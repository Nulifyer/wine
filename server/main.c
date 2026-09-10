/*
 * Server main function
 *
 * Copyright (C) 1998 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif

#include "object.h"
#include "file.h"
#include "thread.h"
#include "process.h"
#include "request.h"
#include "unicode.h"

/* command-line options */
int debug_level = 0;
int foreground = 0;
timeout_t master_socket_timeout = 3 * -TICKS_PER_SEC;  /* master socket timeout, default is 3 seconds */
const char *server_argv0;
static int bootstrap_socket = -1, bootstrap_image = -1, bootstrap_pid;

static void parse_native_bootstrap( const char *arg )
{
#ifdef __linux__
    char extra;
    int type, seals;
    socklen_t len = sizeof(type);
    struct stat st;
    struct sockaddr_storage address;
    socklen_t address_len = sizeof(address);

    if (bootstrap_socket != -1 ||
        sscanf( arg, "%d,%d,%d%c", &bootstrap_socket, &bootstrap_image, &bootstrap_pid, &extra ) != 3 ||
        bootstrap_socket < 3 || bootstrap_image < 3 || bootstrap_socket == bootstrap_image || bootstrap_pid <= 0 ||
        getsockopt( bootstrap_socket, SOL_SOCKET, SO_TYPE, &type, &len ) || type != SOCK_STREAM ||
        getpeername( bootstrap_socket, (struct sockaddr *)&address, &address_len ) || address.ss_family != AF_UNIX ||
        fstat( bootstrap_image, &st ) || !S_ISREG(st.st_mode) ||
        (seals = fcntl( bootstrap_image, F_GET_SEALS )) == -1 ||
        (seals & (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)) !=
                 (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL))
        fatal_error( "invalid native bootstrap descriptors\n" );
    foreground = 1;
    if (fcntl( bootstrap_socket, F_SETFD, FD_CLOEXEC ) == -1 ||
        fcntl( bootstrap_socket, F_SETFL, O_NONBLOCK ) == -1 ||
        fcntl( bootstrap_image, F_SETFD, FD_CLOEXEC ) == -1)
        fatal_error( "could not configure native bootstrap descriptors\n" );
#else
    fatal_error( "native bootstrap requires Linux sealed files\n" );
#endif
}


/* parse-line args */

static void usage( FILE *fh )
{
    fprintf(fh, "Usage: %s [options]\n\n", server_argv0);
    fprintf(fh, "Options:\n");
    fprintf(fh, "         --native-bootstrap=SOCKET,IMAGE,PID  reserve a host-provided initial process\n");
    fprintf(fh, "   -d[n], --debug[=n]       set debug level to n or +1 if n not specified\n");
    fprintf(fh, "   -f,    --foreground      remain in the foreground for debugging\n");
    fprintf(fh, "   -h,    --help            display this help message\n");
    fprintf(fh, "   -k[n], --kill[=n]        kill the current wineserver, optionally with signal n\n");
    fprintf(fh, "   -p[n], --persistent[=n]  make server persistent, optionally for n seconds\n");
    fprintf(fh, "   -v,    --version         display version information and exit\n");
    fprintf(fh, "   -w,    --wait            wait until the current wineserver terminates\n");
    fprintf(fh, "\n");
}

static void option_callback( int optc, char *optarg )
{
    int ret;

    switch (optc)
    {
    case 'd':
        if (optarg && isdigit(*optarg))
            debug_level = atoi( optarg );
        else
            debug_level++;
        break;
    case 'f':
        foreground = 1;
        break;
    case 'h':
        usage(stdout);
        exit(0);
        break;
    case 'k':
        if (optarg && isdigit(*optarg))
            ret = kill_lock_owner( atoi( optarg ) );
        else
            ret = kill_lock_owner(-1);
        exit( !ret );
    case 'p':
        if (optarg && isdigit(*optarg))
            master_socket_timeout = (timeout_t)atoi( optarg ) * -TICKS_PER_SEC;
        else
            master_socket_timeout = TIMEOUT_INFINITE;
        break;
    case 'B':
        parse_native_bootstrap( optarg );
        break;
    case 'v':
        fprintf( stderr, "%s\n", PACKAGE_STRING );
        exit(0);
    case 'w':
        wait_for_lock();
        exit(0);
    }
}

/* command-line option parsing */
/* partly based on the GLibc getopt() implementation */

static struct long_option
{
    const char *name;
    int has_arg;
    int val;
} long_options[] =
{
    {"native-bootstrap", 1, 'B'},
    {"debug",       2, 'd'},
    {"foreground",  0, 'f'},
    {"help",        0, 'h'},
    {"kill",        2, 'k'},
    {"persistent",  2, 'p'},
    {"version",     0, 'v'},
    {"wait",        0, 'w'},
    { NULL }
};

static void parse_options( int argc, char **argv, const char *short_opts,
                           const struct long_option *long_opts, void (*callback)( int, char* ) )
{
    const char *flag;
    char *start, *end;
    int i;

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] != '-' || !argv[i][1])  /* not an option */
            continue;
        if (!strcmp( argv[i], "--" ))
            break;
        start = argv[i] + 1 + (argv[i][1] == '-');

        if (argv[i][1] == '-')
        {
            /* handle long option */
            const struct long_option *opt, *found = NULL;
            int count = 0;

            if (!(end = strchr( start, '=' ))) end = start + strlen(start);
            for (opt = long_opts; opt && opt->name; opt++)
            {
                if (strncmp( opt->name, start, end - start )) continue;
                if (!opt->name[end - start])  /* exact match */
                {
                    found = opt;
                    count = 1;
                    break;
                }
                if (!found)
                {
                    found = opt;
                    count++;
                }
                else if (found->has_arg != opt->has_arg || found->val != opt->val)
                {
                    count++;
                }
            }

            if (count > 1) goto error;

            if (found)
            {
                if (*end)
                {
                    if (!found->has_arg) goto error;
                    end++;  /* skip '=' */
                }
                else if (found->has_arg == 1)
                {
                    if (i == argc - 1) goto error;
                    end = argv[++i];
                }
                else end = NULL;

                callback( found->val, end );
                continue;
            }
            goto error;
        }

        /* handle short option */
        for ( ; *start; start++)
        {
            if (!(flag = strchr( short_opts, *start ))) goto error;
            if (flag[1] == ':')
            {
                end = start + 1;
                if (!*end) end = NULL;
                if (flag[2] != ':' && !end)
                {
                    if (i == argc - 1) goto error;
                    end = argv[++i];
                }
                callback( *start, end );
                break;
            }
            callback( *start, NULL );
        }
    }
    return;

error:
    usage( stderr );
    exit(1);
}

static void sigterm_handler( int signum )
{
    exit(1);  /* make sure atexit functions get called */
}

static void init_limits(void)
{
#ifdef RLIMIT_NOFILE
    struct rlimit rlimit;

    if (!getrlimit( RLIMIT_NOFILE, &rlimit ))
    {
        rlimit.rlim_cur = rlimit.rlim_max;
        if (!setrlimit( RLIMIT_NOFILE, &rlimit )) return;
#ifdef __APPLE__
        {
            /* macOS before Big Sur fails if rlim_max is larger than maxfilesperproc */
            unsigned int nlimit = 0;
            size_t size = sizeof(nlimit);
            sysctlbyname("kern.maxfilesperproc", &nlimit, &size, NULL, 0);
            rlimit.rlim_cur = max( nlimit, OPEN_MAX );
            setrlimit( RLIMIT_NOFILE, &rlimit );
        }
#endif
    }
#endif
}

int main( int argc, char *argv[] )
{
    setvbuf( stderr, NULL, _IOLBF, 0 );
    server_argv0 = argv[0];
    parse_options( argc, argv, "d::fhk::p::vw", long_options, option_callback );

    /* setup temporary handlers before the real signal initialization is done */
    signal( SIGPIPE, SIG_IGN );
    signal( SIGHUP, sigterm_handler );
    signal( SIGINT, sigterm_handler );
    signal( SIGQUIT, sigterm_handler );
    signal( SIGTERM, sigterm_handler );
    signal( SIGABRT, sigterm_handler );
    init_limits();

    sock_init();
    open_master_socket();

    if (debug_level) fprintf( stderr, "wineserver: starting (pid=%ld)\n", (long) getpid() );
    set_current_time();
    init_signals();
    init_memory();
    init_directories( load_intl_file() );
    init_threading();
    init_registry();
    if (bootstrap_socket != -1 && !init_native_bootstrap( bootstrap_socket, bootstrap_image, bootstrap_pid ))
        fatal_error( "could not reserve native bootstrap process\n" );
    main_loop();
    return 0;
}
