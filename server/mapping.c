/*
 * Server-side file mapping management
 *
 * Copyright (C) 1999 Alexandre Julliard
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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef linux
# include <sys/prctl.h>
# include <sys/syscall.h>
#endif
#ifdef HAVE_LINUX_MEMFD_H
# include <linux/memfd.h>
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"

#include "file.h"
#include "handle.h"
#include "thread.h"
#include "process.h"
#include "request.h"
#include "security.h"
#include "image_trust.h"

/* list of memory ranges, used to store committed info */
struct ranges
{
    struct object   obj;             /* object header */
    unsigned int    count;           /* number of used ranges */
    unsigned int    max;             /* number of allocated ranges */
    struct range
    {
        file_pos_t  start;
        file_pos_t  end;
    } *ranges;
};

static void ranges_dump( struct object *obj, int verbose );
static void ranges_destroy( struct object *obj );

static const struct object_ops ranges_ops =
{
    .size    = sizeof(struct ranges),
    .type    = &no_type,
    .dump    = ranges_dump,
    .destroy = ranges_destroy,
};

/* file backing the shared sections of a PE image mapping */
struct shared_map
{
    struct object   obj;             /* object header */
    struct fd      *fd;              /* file descriptor of the mapped PE file */
    struct file    *file;            /* temp file holding the shared data */
    struct list     entry;           /* entry in global shared maps list */
    file_pos_t      image_bytes;     /* bounded prepared shared image backing */
};

static void shared_map_dump( struct object *obj, int verbose );
static void shared_map_destroy( struct object *obj );

static const struct object_ops shared_map_ops =
{
    .size    = sizeof(struct shared_map),
    .type    = &no_type,
    .dump    = shared_map_dump,
    .destroy = shared_map_destroy,
};

static struct list shared_map_list = LIST_INIT( shared_map_list );

/* memory view mapped in client address space */
struct memory_view
{
    struct list     entry;           /* entry in per-process view list */
    struct fd      *fd;              /* fd for mapped file */
    struct ranges  *committed;       /* list of committed ranges in this mapping */
    struct shared_map *shared;       /* temp file for shared PE mapping */
    struct pe_image_info image;      /* image info (for PE image mapping) */
    unsigned int    flags;           /* SEC_* flags */
    client_ptr_t    base;            /* view base address (in process addr space) */
    mem_size_t      size;            /* view size */
    file_pos_t      start;           /* start offset in mapping */
    data_size_t     namelen;
    WCHAR           name[1];         /* filename for .so dll image views */
};


static const WCHAR mapping_name[] = {'S','e','c','t','i','o','n'};

struct type_descr mapping_type =
{
    { mapping_name, sizeof(mapping_name) },   /* name */
    SECTION_ALL_ACCESS | SYNCHRONIZE,         /* valid_access */
    {                                         /* mapping */
        STANDARD_RIGHTS_READ | SECTION_QUERY | SECTION_MAP_READ,
        STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE,
        STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE,
        SECTION_ALL_ACCESS
    },
};

struct mapping
{
    struct object        obj;        /* object header */
    mem_size_t           size;       /* mapping size */
    unsigned int         flags;      /* SEC_* flags */
    struct fd           *fd;         /* fd for mapped file */
    struct fd           *image_fd;   /* immutable native image bytes; fd retains identity/sharing */
    file_pos_t           snapshot_bytes; /* charged retained image backing */
    unsigned int         image_class; /* authenticated bytes, independent of PE markers */
    struct pe_image_info image;      /* image info (for PE image mapping) */
    struct ranges       *committed;  /* list of committed ranges in this mapping */
    struct shared_map   *shared;     /* temp file for shared PE mapping */
    char                *exp_name;   /* export name (for PE image mapping) */
    void                *ver_res;    /* version resource (for PE image mapping) */
    data_size_t          exp_len;    /* length of export name (for PE image mapping) */
    data_size_t          ver_len;    /* length of version resource (for PE image mapping) */
    void                *metadata;  /* sealed worker metadata, owns exp_name/ver_res */
    size_t               metadata_size;
};

struct mapping_init_data
{
    mem_size_t   size;
    unsigned int flags;
    unsigned int file_access;
    struct fd   *fd;
    struct fd   *snapshot;
    file_pos_t   snapshot_bytes;
    bool        *snapshot_consumed;
    const unsigned char *digest;
    const struct pe_image_info *image;
    mem_size_t   image_size;
    struct fd   *metadata;
    data_size_t  exp_len, ver_len;
    struct fd   *shared;
    file_pos_t   shared_size;
};

#define MAX_IMAGE_METADATA_BYTES (1024 * 1024)
#define MAX_SHARED_IMAGE_BYTES (64ULL * 1024 * 1024)
#define MAX_RETAINED_SHARED_IMAGE_BYTES (512ULL * 1024 * 1024)
static file_pos_t retained_shared_image_bytes;
static unsigned int get_image_params( struct mapping *mapping, file_pos_t file_size, int unix_fd,
                                      int *prepared_shared, file_pos_t *shared_size );
static unsigned int install_shared_mapping( struct mapping *mapping, int fd, file_pos_t size );

static void mapping_dump( struct object *obj, int verbose );
static bool mapping_init( struct object *obj, const void *init_data );
static struct fd *mapping_get_fd( struct object *obj );
static void mapping_destroy( struct object *obj );
static enum server_fd_type mapping_get_fd_type( struct fd *fd );

static const struct object_ops mapping_ops =
{
    .size    = sizeof(struct mapping),
    .type    = &mapping_type,
    .dump    = mapping_dump,
    .init    = mapping_init,
    .get_fd  = mapping_get_fd,
    .destroy = mapping_destroy,
};

static const struct fd_ops mapping_fd_ops =
{
    .get_fd_type = mapping_get_fd_type,
};

/* free address ranges for PE image mappings */
struct addr_range
{
    unsigned int count;
    unsigned int size;
    struct
    {
        client_ptr_t base;
        mem_size_t size;
    } *free;
};

static size_t host_page_mask;
static const size_t page_mask = 0xfff;
static const size_t granularity_mask = 0xffff;
static struct addr_range ranges32;
static struct addr_range ranges64;

struct session_block
{
    struct list entry;      /* entry in the session block list */
    const char *data;       /* base pointer for the mmaped data */
    mem_size_t offset;      /* offset of data in the session shared mapping */
    mem_size_t used_size;   /* used size for previously allocated objects  */
    mem_size_t block_size;  /* total size of the block */
};

struct session_object
{
    struct list entry;      /* entry in the session free object list */
    mem_size_t offset;      /* offset of obj in the session shared mapping */
    mem_size_t size;        /* size of obj in the session shared mapping */
    shared_object_t obj;    /* object actually shared with the client */
};

struct session
{
    struct list blocks;
    struct list free_objects;
    object_id_t last_object_id;
};

session_shm_t *shared_session;
static struct mapping *session_mapping;
static struct session session =
{
    .blocks = LIST_INIT(session.blocks),
    .free_objects = LIST_INIT(session.free_objects),
};

static inline mem_size_t round_size( mem_size_t size, mem_size_t mask )
{
    return (size + mask) & ~mask;
}

void init_memory(void)
{
    host_page_mask = sysconf( _SC_PAGESIZE ) - 1;
    free_map_addr( 0x60000000, 0x1c000000 );
    free_map_addr( 0x600000000000, 0x100000000000 );
}

static void ranges_dump( struct object *obj, int verbose )
{
    struct ranges *ranges = (struct ranges *)obj;
    fprintf( stderr, "Memory ranges count=%u\n", ranges->count );
}

static void ranges_destroy( struct object *obj )
{
    struct ranges *ranges = (struct ranges *)obj;
    free( ranges->ranges );
}

static void shared_map_dump( struct object *obj, int verbose )
{
    struct shared_map *shared = (struct shared_map *)obj;
    fprintf( stderr, "Shared mapping fd=%p file=%p\n", shared->fd, shared->file );
}

static void shared_map_destroy( struct object *obj )
{
    struct shared_map *shared = (struct shared_map *)obj;

    retained_shared_image_bytes -= shared->image_bytes;
    release_object( shared->fd );
    release_object( shared->file );
    list_remove( &shared->entry );
}

/* extend a file beyond the current end of file */
int grow_file( int unix_fd, file_pos_t new_size )
{
    static const char zero;
    off_t size = new_size;

    if (sizeof(new_size) > sizeof(size) && size != new_size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return 0;
    }
    /* extend the file one byte beyond the requested size and then truncate it */
    /* this should work around ftruncate implementations that can't extend files */
    if (pwrite( unix_fd, &zero, 1, size ) != -1)
    {
        ftruncate( unix_fd, size );
        return 1;
    }
    file_set_error();
    return 0;
}

/* simplified version of mkstemps() */
static int make_temp_file( char name[16] )
{
    static unsigned int value;
    int i, fd = -1;

    value += (current_time >> 16) + current_time;
    for (i = 0; i < 0x8000 && fd < 0; i++, value += 7777)
    {
        snprintf( name, 16, "tmpmap-%08x", value );
        fd = open( name, O_RDWR | O_CREAT | O_EXCL, 0600 );
    }
    return fd;
}

/* check if the current directory allows exec mappings */
static int check_current_dir_for_exec(void)
{
    int fd;
    char tmpfn[16];
    void *ret = MAP_FAILED;

    fd = make_temp_file( tmpfn );
    if (fd == -1) return 0;
    if (grow_file( fd, 1 ))
    {
        ret = mmap( NULL, get_page_size(), PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0 );
        if (ret != MAP_FAILED) munmap( ret, get_page_size() );
    }
    close( fd );
    unlink( tmpfn );
    return (ret != MAP_FAILED);
}

/* create a temp file for anonymous mappings */
static int create_temp_file( file_pos_t size )
{
    static int temp_dir_fd = -1;
    char tmpfn[16];
    int fd;

#if defined(HAVE_MEMFD_CREATE) && defined(MFD_EXEC)
    if ((fd = memfd_create( "wine-mapping", MFD_EXEC )) != -1)
    {
        if (grow_file( fd, size )) return fd;
        close( fd );
    }
#endif
    if (temp_dir_fd == -1)
    {
        temp_dir_fd = server_dir_fd;
        if (!check_current_dir_for_exec())
        {
            /* the server dir is noexec, try the config dir instead */
            fchdir( config_dir_fd );
            if (check_current_dir_for_exec())
                temp_dir_fd = config_dir_fd;
            else  /* neither works, fall back to server dir */
                fchdir( server_dir_fd );
        }
    }
    else if (temp_dir_fd != server_dir_fd) fchdir( temp_dir_fd );

    fd = make_temp_file( tmpfn );
    if (fd != -1)
    {
        if (!grow_file( fd, size ))
        {
            close( fd );
            fd = -1;
        }
        unlink( tmpfn );
    }
    else file_set_error();

    if (temp_dir_fd != server_dir_fd) fchdir( server_dir_fd );
    return fd;
}

/* Bound retained server copies independently of the offline catalog limits.
 * Client mappings and swap policy remain host-account resource responsibilities. */
#define MAX_RETAINED_IMAGE_BYTES (512ULL * 1024 * 1024)
static file_pos_t retained_image_bytes;

/* Native-machine trust must be checked against the bytes clients will map.
 * Keep the source fd for Windows identity/sharing; return immutable content
 * separately. A mutable source can race this copy, so publisher admission must
 * authenticate the sealed result. Never fall back to a mutable backing. */
static int create_image_snapshot( int source, file_pos_t size )
{
#if defined(HAVE_MEMFD_CREATE) && defined(F_ADD_SEALS)
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    unsigned int flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    char buffer[65536];
    file_pos_t offset = 0;
    int fd, seals;

    if ((seals = fcntl( source, F_GET_SEALS )) != -1 && (seals & required) == required)
    {
        if ((fd = fcntl( source, F_DUPFD_CLOEXEC, 0 )) == -1) file_set_error();
        return fd;
    }
#ifdef MFD_EXEC
    flags |= MFD_EXEC;
#endif
    fd = memfd_create( "wine-native-image", flags );
#ifdef MFD_EXEC
    if (fd == -1 && errno == EINVAL) fd = memfd_create( "wine-native-image", flags & ~MFD_EXEC );
#endif
    if (fd == -1)
    {
        file_set_error();
        return -1;
    }
    while (offset < size)
    {
        ssize_t count, written = 0;
        size_t length = min( sizeof(buffer), size - offset );

        do count = pread( source, buffer, length, offset ); while (count == -1 && errno == EINTR);
        if (!count) errno = EIO;
        if (count <= 0) goto error;
        while (written < count)
        {
            ssize_t ret;
            do ret = pwrite( fd, buffer + written, count - written, offset + written );
            while (ret == -1 && errno == EINTR);
            if (!ret) errno = EIO;
            if (ret <= 0) goto error;
            written += ret;
        }
        offset += count;
    }
    if (fchmod( fd, 0500 ) == -1 || fcntl( fd, F_ADD_SEALS, required ) == -1) goto error;
    return fd;

error:
    file_set_error();
    close( fd );
    return -1;
#else
    set_error( STATUS_NOT_SUPPORTED );
    return -1;
#endif
}

/* Private worker outputs never use the parent's namespace or directory fds. */
static int create_prepared_image_file( const char *name, file_pos_t size, int executable )
{
#if defined(HAVE_MEMFD_CREATE) && defined(F_ADD_SEALS)
    unsigned int flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    int fd;
#ifdef MFD_EXEC
    if (executable) flags |= MFD_EXEC;
#endif
    fd = memfd_create( name, flags );
#ifdef MFD_EXEC
    if (fd == -1 && errno == EINVAL && (flags & MFD_EXEC))
        fd = memfd_create( name, flags & ~MFD_EXEC );
#endif
    if (fd == -1) { file_set_error(); return -1; }
    if (ftruncate( fd, size ))
    {
        file_set_error();
        close( fd );
        return -1;
    }
    return fd;
#else
    set_error( STATUS_NOT_SUPPORTED );
    return -1;
#endif
}

/* Trusted child work is bounded independently of retained section backing.
 * A timed-out/killed job keeps its slot and charge until waitpid reaps it. */
#define MAX_IMAGE_WORKERS 4
#define MAX_IMAGE_JOBS 32
#define IMAGE_WORK_TIMEOUT (30 * -TICKS_PER_SEC)
static unsigned int image_worker_count, image_job_count;
static struct list image_jobs = LIST_INIT(image_jobs);

struct image_job_result
{
    unsigned int phase; /* 0: pin bytes/digest before parsing; 1: prepared metadata */
    unsigned int status;
    unsigned int hashed;
    unsigned char digest[32];
    struct pe_image_info image;
    mem_size_t size;
    data_size_t exp_len, ver_len;
    file_pos_t shared_size;
};

struct image_job
{
    struct object obj;
    struct list entry;
    struct fd *channel;
    struct fd *snapshot;
    struct fd *metadata;
    struct fd *shared;
    struct thread *thread;
    struct token *primary_token, *thread_token;
    struct object_params params;
    struct mapping_init_data data;
    void *attributes;
    struct timeout_user *timeout;
    file_pos_t charge;
    int pid, result_ready;
    int pinned, hashed;
    unsigned char digest[32];
    struct image_job_result result;
};

static void image_job_destroy( struct object *obj );
static int launch_image_worker( struct image_job *job );
static void launch_waiting_image_jobs(void);
static void image_job_drop( struct image_job *job )
{
    list_remove(&job->entry);
    image_job_count--;
    release_object(job);
}
static void image_job_poll( struct fd *fd, int events );
static const struct object_ops image_job_ops =
{
    .size = sizeof(struct image_job),
    .type = &no_type,
    .destroy = image_job_destroy,
};
static const struct fd_ops image_job_fd_ops = { .poll_event = image_job_poll };

static void image_job_cancel( void *private )
{
    struct image_job *job = private;
    struct thread *thread = job->thread;
    job->thread = NULL;
    if (job->pid > 0) kill( job->pid, SIGKILL );
    if (thread) release_object( thread );
    if (job->pid == -1) image_job_drop(job);
}

static void image_job_reply( struct image_job *job, unsigned int status )
{
    union generic_reply reply;
    struct thread *thread = job->thread;
    struct token *saved_primary, *saved_thread;
    bool consumed = false;

    if (!thread) return;
    memset(&reply,0,sizeof(reply));
    if (!status)
    {
        current = thread;
        saved_primary = thread->process->token;
        saved_thread = thread->token;
        thread->process->token = job->primary_token;
        thread->token = job->thread_token;
        job->data.snapshot = job->snapshot;
        job->data.snapshot_bytes = job->charge;
        job->data.snapshot_consumed = &consumed;
        job->data.digest = job->hashed ? job->digest : NULL;
        job->data.image = &job->result.image;
        job->data.image_size = job->result.size;
        job->data.metadata = job->metadata;
        job->data.exp_len = job->result.exp_len;
        job->data.ver_len = job->result.ver_len;
        job->data.shared = job->shared;
        job->data.shared_size = job->result.shared_size;
        clear_error();
        reply.create_mapping_reply.handle = create_named_obj_handle( thread->process, &job->params );
        status = get_error();
        if (consumed) job->charge = 0;
        thread->process->token = saved_primary;
        thread->token = saved_thread;
        current = NULL;
    }
    job->thread = NULL; /* detach before reply errors can kill the requesting thread */
    finish_deferred_reply( thread, &reply, status );
    release_object( thread );
}

static void image_job_timeout( void *private )
{
    struct image_job *job = private;
    job->timeout = NULL;
    if (job->pid > 0) kill( job->pid, SIGKILL );
    image_job_reply( job, STATUS_IO_TIMEOUT );
    if (job->pid == -1) image_job_drop(job);
}

static void image_job_destroy( struct object *obj )
{
    struct image_job *job = (struct image_job *)obj;
    assert( !job->thread && job->pid <= 0 );
    if (job->timeout) remove_timeout_user( job->timeout );
    if (job->channel) release_object( job->channel );
    if (job->snapshot) release_object( job->snapshot );
    if (job->metadata) release_object( job->metadata );
    if (job->shared) release_object( job->shared );
    if (job->data.fd) release_object( job->data.fd );
    if (job->params.root) release_object( job->params.root );
    if (job->primary_token) release_object( job->primary_token );
    if (job->thread_token) release_object( job->thread_token );
    retained_image_bytes -= job->charge;
    free( job->attributes );
}

/* Pin sealed bytes before any PE parsing. Later parser output cannot replace
 * the digest or snapshot used for authority, even if the parser child fails. */
static void image_job_poll( struct fd *fd, int events )
{
    struct image_job *job = get_fd_user( fd );
    struct image_job_result result = {0};
    struct iovec iov = { &result, sizeof(result) };
    union { struct cmsghdr align; char bytes[CMSG_SPACE(3 * sizeof(int))]; } control;
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    int received[3], count = 0, expected, i;
    size_t metadata_size;
    ssize_t ret;

    if (job->result_ready) return;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control);
    ret = recvmsg( get_unix_fd(fd), &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC );
    if (ret == -1 && (errno == EAGAIN || errno == EINTR)) return;
    for (cmsg = CMSG_FIRSTHDR(&msg); ret > 0 && cmsg; cmsg = CMSG_NXTHDR(&msg,cmsg))
    {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(0))
        {
            size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
            int n = bytes / sizeof(int);
            if (n <= 3 - count)
            {
                memcpy( received + count, CMSG_DATA(cmsg), n * sizeof(int) );
                count += n;
            }
        }
    }
    metadata_size = ((size_t)result.exp_len + 3) / 4 * 4 + result.ver_len;
    expected = job->pinned ? !!metadata_size + !!result.shared_size : 1;
    if (ret != sizeof(result) || msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
        result.phase != job->pinned || metadata_size > MAX_IMAGE_METADATA_BYTES ||
        result.shared_size > MAX_SHARED_IMAGE_BYTES || (!result.status && count != expected))
        result.status = STATUS_UNSUCCESSFUL;
    for (i = 0; i < count; i++)
    {
        if (result.status) close( received[i] );
        else
        {
            struct fd **target = !job->pinned ? &job->snapshot :
                                 (metadata_size && !i) ? &job->metadata : &job->shared;
            if (!(*target = create_anonymous_fd( &mapping_fd_ops, received[i], NULL,
                                                FILE_SYNCHRONOUS_IO_NONALERT )))
                result.status = STATUS_NO_MEMORY;
            else allow_fd_caching( *target );
        }
    }
    if (!job->pinned && !result.status)
    {
        struct stat st;
        int snapshot = get_unix_fd(job->snapshot);
        const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        int seals = fcntl(snapshot,F_GET_SEALS);
        if (metadata_size || result.shared_size || seals == -1 || (seals & required) != required ||
            fstat(snapshot,&st) || !S_ISREG(st.st_mode) || st.st_size != job->charge)
        {
            job->result.status = STATUS_UNSUCCESSFUL;
            job->result_ready = 1;
            set_fd_events(fd,-1);
            return;
        }
        job->pinned = 1;
        job->hashed = result.hashed;
        memcpy( job->digest, result.digest, sizeof(job->digest) );
        return;
    }
    job->result = result;
    job->result_ready = 1;
    set_fd_events( fd, -1 );
}

/* Called by the normal server child reaper, including after timeout/cancellation. */
int mapping_worker_exited( int pid, int status )
{
    struct image_job *job;
    LIST_FOR_EACH_ENTRY( job, &image_jobs, struct image_job, entry )
    {
        if (job->pid != pid) continue;
        if (!WIFEXITED(status) && !WIFSIGNALED(status)) return 1;
        job->pid = 0;
        if (!job->result_ready) image_job_poll( job->channel, POLLIN );
        if (!job->result_ready) image_job_poll( job->channel, POLLIN ); /* bounded two-phase drain */
        if (!job->result_ready || !WIFEXITED(status) || WEXITSTATUS(status))
            job->result.status = STATUS_UNSUCCESSFUL;
        image_job_reply( job, job->result.status );
        image_worker_count--;
        image_job_drop(job);
        launch_waiting_image_jobs();
        return 1;
    }
    return 0;
}

static int send_image_job_result( int channel, const struct image_job_result *result,
                                  const int *outputs, unsigned int count )
{
    struct iovec iov = { (void *)result, sizeof(*result) };
    union { struct cmsghdr align; char bytes[CMSG_SPACE(3 * sizeof(int))]; } control;
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (count)
    {
        msg.msg_control = control.bytes;
        msg.msg_controllen = CMSG_SPACE(count * sizeof(int));
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy( CMSG_DATA(cmsg), outputs, count * sizeof(int) );
    }
    return sendmsg(channel,&msg,MSG_NOSIGNAL) == sizeof(*result);
}

static void image_worker( int source, int channel, file_pos_t size, mem_size_t requested_size, int parent )
{
#ifdef linux
    struct image_job_result result = {0};
    sigset_t empty;
    struct mapping prepared = {0};
    int a, b, snapshot, metadata = -1, shared = -1, outputs[3], count = 0;
    size_t metadata_size, ver_offset;
    long max_fd;

    if (prctl( PR_SET_PDEATHSIG, SIGKILL ) || getppid() != parent) _exit(1);
    if ((a = fcntl( source, F_DUPFD_CLOEXEC, 5 )) == -1 ||
        (b = fcntl( channel, F_DUPFD_CLOEXEC, 5 )) == -1) _exit(1);
    if (dup2(a,3) == -1 || dup2(b,4) == -1) _exit(1);
    max_fd = sysconf( _SC_OPEN_MAX );
#ifdef SYS_close_range
    if (syscall( SYS_close_range, 5, ~0U, 0 ))
#endif
        for (a = 5; a < max_fd; ++a) close(a);
    close(0);
    close(1);
    signal( SIGTERM, SIG_DFL );
    signal( SIGABRT, SIG_DFL );
    signal( SIGCHLD, SIG_DFL );
    sigemptyset(&empty);
    sigprocmask( SIG_SETMASK, &empty, NULL );
    clear_error();
    snapshot = create_image_snapshot( 3, size );
    result.status = snapshot == -1 ? get_error() : 0;
    if (!result.status && image_trust_ready())
    {
        result.hashed = hash_image_fd( snapshot, result.digest );
        if (!result.hashed) result.status = STATUS_UNSUCCESSFUL;
    }
    if (!send_image_job_result(4,&result,&snapshot,!result.status)) _exit(1);
    if (result.status) _exit(0);
    result.phase = 1;
    prepared.size = requested_size;
    if (!result.status)
        result.status = get_image_params( &prepared, size, snapshot, &shared, &result.shared_size );
    if (!result.status)
    {
        result.image = prepared.image;
        result.size = prepared.size;
        result.exp_len = prepared.exp_len;
        result.ver_len = prepared.ver_len;
        ver_offset = ((size_t)result.exp_len + 3) / 4 * 4;
        metadata_size = ver_offset + result.ver_len;
        if (metadata_size > MAX_IMAGE_METADATA_BYTES) result.status = STATUS_SECTION_TOO_BIG;
        else if (metadata_size)
        {
            metadata = create_prepared_image_file( "wine-image-metadata", metadata_size, 0 );
            if (metadata == -1 ||
                (result.exp_len && pwrite( metadata, prepared.exp_name, result.exp_len, 0 ) != result.exp_len) ||
                (result.ver_len && pwrite( metadata, prepared.ver_res, result.ver_len, ver_offset ) != result.ver_len) ||
                fcntl( metadata, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL ) == -1)
                result.status = STATUS_UNSUCCESSFUL;
        }
    }
    free( prepared.exp_name );
    free( prepared.ver_res );
    close(3);
    if (!result.status)
    {
        if (metadata != -1) outputs[count++] = metadata;
        if (shared != -1) outputs[count++] = shared;
    }
    if (!send_image_job_result(4,&result,outputs,count)) _exit(1);
    if (snapshot != -1) close(snapshot);
    if (metadata != -1) close(metadata);
    if (shared != -1) close(shared);
    close(4);
    _exit(0);
#else
    _exit(1);
#endif
}

static int launch_image_worker( struct image_job *job )
{
    int sockets[2], pid, source = get_unix_fd(job->data.fd), parent = getpid();
    if (source == -1) return 0;
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sockets)) { file_set_error(); return 0; }
    if (!(job->channel = create_anonymous_fd(&image_job_fd_ops,sockets[0],&job->obj,0)))
    {
        close(sockets[1]);
        return 0;
    }
    pid = fork();
    if (!pid) { close(sockets[0]); image_worker(source,sockets[1],job->data.snapshot_bytes,job->data.size,parent); }
    close(sockets[1]);
    if (pid == -1) { file_set_error(); return 0; }
    job->pid = pid;
    image_worker_count++;
    set_fd_events(job->channel,POLLIN);
    return 1;
}

static void launch_waiting_image_jobs(void)
{
    struct image_job *job, *next;
    LIST_FOR_EACH_ENTRY_SAFE(job,next,&image_jobs,struct image_job,entry)
    {
        if (image_worker_count >= MAX_IMAGE_WORKERS) break;
        if (job->pid != -1) continue;
        if (!launch_image_worker(job))
        {
            unsigned int status = get_error();
            image_job_reply(job,status ? status : STATUS_UNSUCCESSFUL);
            image_job_drop(job);
        }
    }
}

static int start_image_job( const struct object_params *params, const struct mapping_init_data *data )
{
    struct image_job *job;
    struct stat st;
    int source;
    data_size_t attr_size = get_req_data_size();

    if ((source = get_unix_fd(data->fd)) == -1) return 0;
    if (fstat(source,&st)) { file_set_error(); return 0; }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0)
    {
        set_error( STATUS_INVALID_FILE_FOR_SECTION );
        return 0;
    }
    if ((unsigned long long)st.st_size > IMAGE_TRUST_MAX_IMAGE_BYTES)
    {
        set_error( STATUS_SECTION_TOO_BIG );
        return 0;
    }
    if (image_job_count >= MAX_IMAGE_JOBS ||
        (unsigned long long)st.st_size > MAX_RETAINED_IMAGE_BYTES - retained_image_bytes)
    {
        set_error( STATUS_COMMITMENT_LIMIT );
        return 0;
    }
    if (!(job = alloc_object(&image_job_ops))) return 0;
    job->params = *params;
    job->data = *data;
    job->params.init_data = &job->data;
    job->params.root = params->root ? grab_object(params->root) : NULL;
    job->data.fd = (struct fd *)grab_object(data->fd);
    job->channel = job->snapshot = job->metadata = job->shared = NULL;
    job->thread = NULL;
    job->primary_token = job->thread_token = NULL;
    job->attributes = NULL;
    job->timeout = NULL;
    job->charge = 0;
    job->pid = 0;
    job->result_ready = job->pinned = job->hashed = 0;
    memset(&job->result,0,sizeof(job->result));
    if (attr_size)
    {
        if (!(job->attributes = mem_alloc(attr_size))) goto error;
        memcpy(job->attributes,get_req_data(),attr_size);
        job->params.objattr = job->attributes;
        if (params->sd) job->params.sd = (void *)((char *)job->attributes +
                                              ((char *)params->sd - (char *)get_req_data()));
        job->params.name.str = (void *)((char *)job->attributes +
                                      ((char *)params->name.str - (char *)get_req_data()));
    }
    job->data.snapshot_bytes = st.st_size;
    if (!(job->timeout = add_timeout_user(IMAGE_WORK_TIMEOUT,image_job_timeout,job))) goto error;
    if (image_worker_count < MAX_IMAGE_WORKERS)
    {
        if (!launch_image_worker(job)) goto error;
    }
    else job->pid = -1; /* bounded, charged queue; no helper process yet */
    job->charge = st.st_size;
    retained_image_bytes += job->charge;
    image_job_count++;
    list_add_tail(&image_jobs,&job->entry);
    job->primary_token = (struct token *)grab_object(current->process->token);
    if (current->token) job->thread_token = (struct token *)grab_object(current->token);
    job->thread = (struct thread *)grab_object(current);
    defer_reply(image_job_cancel,job);
    return 1;
error:
    release_object(job);
    return 0;
}

/* find a memory view from its base address */
struct memory_view *find_mapped_view( struct process *process, client_ptr_t base )
{
    struct memory_view *view;

    LIST_FOR_EACH_ENTRY( view, &process->views, struct memory_view, entry )
        if (view->base == base) return view;

    set_error( STATUS_NOT_MAPPED_VIEW );
    return NULL;
}

/* find a memory view from any address inside it */
static struct memory_view *find_mapped_addr( struct process *process, client_ptr_t addr )
{
    struct memory_view *view;

    LIST_FOR_EACH_ENTRY( view, &process->views, struct memory_view, entry )
        if (addr >= view->base && addr < view->base + view->size) return view;

    set_error( STATUS_NOT_MAPPED_VIEW );
    return NULL;
}

/* check if an address range is valid for creating a view */
static int is_valid_view_addr( struct process *process, client_ptr_t addr, mem_size_t size )
{
    struct memory_view *view;

    if (!size) return 0;
    if (addr & (process->page_size - 1)) return 0;
    if (addr + size < addr) return 0;  /* overflow */

    /* check for overlapping view */
    LIST_FOR_EACH_ENTRY( view, &process->views, struct memory_view, entry )
    {
        if (view->base + view->size <= addr) continue;
        if (view->base >= addr + size) continue;
        return 0;
    }
    return 1;
}

/* get the main exe memory view */
struct memory_view *get_exe_view( struct process *process )
{
    return LIST_ENTRY( list_head( &process->views ), struct memory_view, entry );
}

static int generate_dll_event( struct thread *thread, int code, struct memory_view *view )
{
    if (!(view->flags & SEC_IMAGE)) return 0;
    generate_debug_event( thread, code, view );
    return 1;
}

static int process_image_has_name( const struct process *process, const char *name )
{
    data_size_t image_len = process->imagelen / sizeof(WCHAR);
    size_t name_len = strlen( name );
    data_size_t start, i;

    if (!name_len || name_len > image_len) return 0;
    start = image_len - name_len;
    if (start && process->image[start - 1] != '\\' && process->image[start - 1] != '/') return 0;

    for (i = 0; i < name_len; i++)
    {
        WCHAR ch = process->image[start + i];
        char expected = name[i];

        if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        if (expected >= 'A' && expected <= 'Z') expected += 'a' - 'A';
        if (ch != expected) return 0;
    }
    return 1;
}

/* add a view to the process list */
/* return 1 if this is the main exe view */
static int add_process_view( struct thread *thread, struct memory_view *view )
{
    static const char services_name[] = "services.exe";
    static const char svchost_name[] = "svchost.exe";
    struct process *process = thread->process;
    const char *delay_main_image;
    struct unicode_str name;
    data_size_t i;

    if (view->flags & SEC_IMAGE)
    {
        if (is_process_init_done( process ))
        {
            generate_dll_event( thread, DbgLoadDllStateChange, view );
        }
        else if (!(view->image.image_charact & IMAGE_FILE_DLL))
        {
            /* main exe */
            free( process->image );
            process->image = NULL;
            if (get_view_nt_name( view, &name ) && (process->image = memdup( name.str, name.len )))
                process->imagelen = name.len;
            if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
            {
                fprintf( stderr, "linuxnt: server main-image winpid=%04x unix=%d image=",
                         process->id, process->unix_pid );
                for (i = 0; i < process->imagelen / sizeof(WCHAR); i++)
                {
                    WCHAR ch = process->image[i];
                    fputc( ch >= 0x20 && ch < 0x7f ? ch : '?', stderr );
                }
                fputc( '\n', stderr );
            }
            if ((delay_main_image = getenv( "LINUXNT_DEBUG_DELAY_MAIN_IMAGE" )) &&
                process_image_has_name( process, delay_main_image ))
            {
                fprintf( stderr, "linuxnt: delaying %s unix=%d before main image reply\n",
                         delay_main_image, process->unix_pid );
                usleep( 30000000 );
            }
            if (getenv( "LINUXNT_DEBUG_DELAY_SERVICES_START" ) &&
                process->imagelen / sizeof(WCHAR) >= sizeof(services_name) - 1)
            {
                data_size_t start = process->imagelen / sizeof(WCHAR) - (sizeof(services_name) - 1);
                for (i = 0; i < sizeof(services_name) - 1; i++)
                {
                    WCHAR ch = process->image[start + i];
                    if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
                    if (ch != services_name[i]) break;
                }
                if (i == sizeof(services_name) - 1)
                {
                    fprintf( stderr, "linuxnt: delaying services.exe unix=%d before main image reply\n",
                             process->unix_pid );
                    usleep( 10000000 );
                }
            }
            if (getenv( "LINUXNT_DEBUG_DELAY_SVCHOST_START" ) &&
                process->imagelen / sizeof(WCHAR) >= sizeof(svchost_name) - 1)
            {
                data_size_t start = process->imagelen / sizeof(WCHAR) - (sizeof(svchost_name) - 1);
                for (i = 0; i < sizeof(svchost_name) - 1; i++)
                {
                    WCHAR ch = process->image[start + i];
                    if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
                    if (ch != svchost_name[i]) break;
                }
                if (i == sizeof(svchost_name) - 1)
                {
                    fprintf( stderr, "linuxnt: delaying svchost.exe unix=%d before main image reply\n",
                             process->unix_pid );
                    usleep( 10000000 );
                }
            }
            process->image_info = view->image;
            list_add_head( &process->views, &view->entry );
            return 1;
        }
    }
    list_add_tail( &process->views, &view->entry );
    return 0;
}

static void free_memory_view( struct memory_view *view )
{
    if (view->fd) release_object( view->fd );
    if (view->committed) release_object( view->committed );
    if (view->shared) release_object( view->shared );
    list_remove( &view->entry );
    free( view );
}

/* free all mapped views at process exit */
void free_mapped_views( struct process *process )
{
    struct list *ptr;

    while ((ptr = list_head( &process->views )))
        free_memory_view( LIST_ENTRY( ptr, struct memory_view, entry ));
}

/* find the shared PE mapping for a given mapping */
static struct shared_map *get_shared_file( struct fd *fd )
{
    struct shared_map *ptr;

    LIST_FOR_EACH_ENTRY( ptr, &shared_map_list, struct shared_map, entry )
        if (is_same_file_fd( ptr->fd, fd ))
            return (struct shared_map *)grab_object( ptr );
    return NULL;
}

/* return the size of the memory mapping and file range of a given section */
static inline void get_section_sizes( const IMAGE_SECTION_HEADER *sec, size_t align_mask,
                                      size_t *map_size, off_t *file_start, size_t *file_size )
{
    static const unsigned int sector_align = 0x1ff;

    if (!sec->Misc.VirtualSize) *map_size = round_size( sec->SizeOfRawData, align_mask );
    else *map_size = round_size( sec->Misc.VirtualSize, align_mask );

    *file_start = sec->PointerToRawData & ~sector_align;
    *file_size = round_size( sec->SizeOfRawData + (sec->PointerToRawData & sector_align), sector_align );
    if (*file_size > *map_size) *file_size = *map_size;
}

/* add a range to the committed list */
static void add_committed_range( struct memory_view *view, file_pos_t start, file_pos_t end )
{
    unsigned int i, j;
    struct ranges *committed = view->committed;
    struct range *ranges;

    if ((start & page_mask) || (end & page_mask) ||
        start >= view->size || end > view->size ||
        start >= end)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }

    if (!committed) return;  /* everything committed already */

    start += view->start;
    end += view->start;

    for (i = 0, ranges = committed->ranges; i < committed->count; i++)
    {
        if (ranges[i].start > end) break;
        if (ranges[i].end < start) continue;
        if (ranges[i].start > start) ranges[i].start = start;   /* extend downwards */
        if (ranges[i].end < end)  /* extend upwards and maybe merge with next */
        {
            for (j = i + 1; j < committed->count; j++)
            {
                if (ranges[j].start > end) break;
                if (ranges[j].end > end) end = ranges[j].end;
            }
            if (j > i + 1)
            {
                memmove( &ranges[i + 1], &ranges[j], (committed->count - j) * sizeof(*ranges) );
                committed->count -= j - (i + 1);
            }
            ranges[i].end = end;
        }
        return;
    }

    /* now add a new range */

    if (committed->count == committed->max)
    {
        unsigned int new_size = committed->max * 2;
        struct range *new_ptr = realloc( committed->ranges, new_size * sizeof(*new_ptr) );
        if (!new_ptr) return;
        committed->max = new_size;
        ranges = committed->ranges = new_ptr;
    }
    memmove( &ranges[i + 1], &ranges[i], (committed->count - i) * sizeof(*ranges) );
    ranges[i].start = start;
    ranges[i].end = end;
    committed->count++;
}

/* find the range containing start and return whether it's committed */
static int find_committed_range( struct memory_view *view, file_pos_t start, mem_size_t *size )
{
    unsigned int i;
    struct ranges *committed = view->committed;
    struct range *ranges;

    if ((start & page_mask) || start >= view->size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return 0;
    }
    if (!committed)  /* everything is committed */
    {
        *size = view->size - start;
        return 1;
    }
    for (i = 0, ranges = committed->ranges; i < committed->count; i++)
    {
        if (ranges[i].start > view->start + start)
        {
            *size = min( ranges[i].start, view->start + view->size ) - (view->start + start);
            return 0;
        }
        if (ranges[i].end > view->start + start)
        {
            *size = min( ranges[i].end, view->start + view->size ) - (view->start + start);
            return 1;
        }
    }
    *size = view->size - start;
    return 0;
}

/* Prepare bytes without publishing cross-process state. The worker and the
 * ordinary path use the same copy mechanism; only the server installs identity. */
static unsigned int copy_shared_mapping( size_t align_mask, int fd, IMAGE_SECTION_HEADER *sec,
                                         unsigned int nb_sec, int isolated, int *output,
                                         file_pos_t *output_size )
{
    unsigned int i;
    mem_size_t total_size = 0;
    size_t file_size, map_size;
    off_t shared_pos, read_pos;
    char buffer[65536];
    int shared_fd;

    *output = -1;
    *output_size = 0;
    for (i = 0; i < nb_sec; i++)
    {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) ||
            !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        get_section_sizes( &sec[i], align_mask, &map_size, &read_pos, &file_size );
        if (isolated && map_size > MAX_SHARED_IMAGE_BYTES - total_size) return STATUS_SECTION_TOO_BIG;
        total_size += map_size;
    }
    if (!total_size) return STATUS_SUCCESS;
    shared_fd = isolated ? create_prepared_image_file( "wine-image-shared", total_size, 1 ) :
                           create_temp_file( total_size );
    if (shared_fd == -1) return STATUS_INVALID_FILE_FOR_SECTION;

    shared_pos = 0;
    for (i = 0; i < nb_sec; i++)
    {
        size_t remaining;
        off_t write_pos;
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) ||
            !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        get_section_sizes( &sec[i], align_mask, &map_size, &read_pos, &file_size );
        write_pos = shared_pos;
        shared_pos += map_size;
        if (!sec[i].PointerToRawData || !file_size) continue;
        remaining = file_size;
        while (remaining)
        {
            size_t written = 0;
            ssize_t res;
            do res = pread( fd, buffer, min(remaining,sizeof(buffer)), read_pos );
            while (res == -1 && errno == EINTR);
            if (!res && remaining < 0x200) break; /* partial sector at EOF */
            if (res <= 0) goto error;
            read_pos += res;
            remaining -= res;
            while (written < res)
            {
                ssize_t ret;
                do ret = pwrite( shared_fd, buffer + written, res - written, write_pos + written );
                while (ret == -1 && errno == EINTR);
                if (ret <= 0) goto error;
                written += ret;
            }
            write_pos += res;
        }
    }
    /* Shared data stays writable, but its bounded extent cannot change. */
    if (isolated && fcntl( shared_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL ) == -1)
        goto error;
    *output = shared_fd;
    *output_size = total_size;
    return STATUS_SUCCESS;
error:
    close( shared_fd );
    return STATUS_INVALID_FILE_FOR_SECTION;
}

static unsigned int install_shared_mapping( struct mapping *mapping, int fd, file_pos_t size )
{
    struct shared_map *shared;
    struct file *file;
    int copy;

    /* Recheck at completion: another job can already have published this file. */
    if ((mapping->shared = get_shared_file( mapping->fd ))) return STATUS_SUCCESS;
    if (size > MAX_RETAINED_SHARED_IMAGE_BYTES - retained_shared_image_bytes)
        return STATUS_COMMITMENT_LIMIT;
    if ((copy = fcntl( fd, F_DUPFD_CLOEXEC, 0 )) == -1) return STATUS_NO_MEMORY;
    if (!(file = create_file_for_fd( copy, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0 )))
        return get_error();
    if (!(shared = alloc_object( &shared_map_ops )))
    {
        release_object( file );
        return STATUS_NO_MEMORY;
    }
    shared->fd = (struct fd *)grab_object( mapping->fd );
    shared->file = file;
    shared->image_bytes = size;
    retained_shared_image_bytes += size;
    list_add_head( &shared_map_list, &shared->entry );
    mapping->shared = shared;
    return STATUS_SUCCESS;
}

static unsigned int build_shared_mapping( struct mapping *mapping, size_t align_mask, int fd,
                                          IMAGE_SECTION_HEADER *sec, unsigned int nb_sec )
{
    unsigned int i, status;
    int shared_fd;
    file_pos_t size;
    size_t file_size, map_size;
    off_t read_pos;

    for (i = 0; i < nb_sec; i++)
    {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) ||
            !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
        get_section_sizes( &sec[i], align_mask, &map_size, &read_pos, &file_size );
        if (map_size) break;
    }
    if (i == nb_sec) return STATUS_SUCCESS;
    if ((mapping->shared = get_shared_file( mapping->fd ))) return STATUS_SUCCESS;
    status = copy_shared_mapping( align_mask, fd, sec, nb_sec, 0, &shared_fd, &size );
    if (status || shared_fd == -1) return status;
    status = install_shared_mapping( mapping, shared_fd, 0 ); /* ordinary path is not image-budgeted */
    close( shared_fd );
    return status;
}

/* load a data directory header from its section */
static int load_data_dir( void *dir, size_t dir_size, size_t va, size_t size, size_t align_mask,
                          int unix_fd, IMAGE_SECTION_HEADER *sec, unsigned int nb_sec )
{
    size_t map_size, file_size;
    off_t file_start;
    unsigned int i;

    if (!va || !size) return 0;

    for (i = 0; i < nb_sec; i++)
    {
        if (va < sec[i].VirtualAddress) continue;
        if (sec[i].Misc.VirtualSize && va - sec[i].VirtualAddress >= sec[i].Misc.VirtualSize) continue;
        get_section_sizes( &sec[i], align_mask, &map_size, &file_start, &file_size );
        if (size >= map_size) continue;
        if (va - sec[i].VirtualAddress >= map_size - size) continue;
        if (size > dir_size) size = dir_size;
        if (size > file_size) size = file_size;
        return pread( unix_fd, dir, size, file_start + va - sec[i].VirtualAddress );
    }
    return 0;
}

/* load EXPORT_DIRECTORY.Name from its section */
static int load_export_name( char **ret_buf, IMAGE_DATA_DIRECTORY *data, size_t align_mask,
                             int unix_fd, IMAGE_SECTION_HEADER *sec, unsigned int nb_sec )
{
    char *end, buffer[1024];
    IMAGE_EXPORT_DIRECTORY exp;
    size_t va = data->VirtualAddress, size = data->Size;
    int ret = load_data_dir( &exp, sizeof(exp), va, size, align_mask, unix_fd, sec, nb_sec );

    if (ret != sizeof(exp)) return 0;
    if (!exp.Name || exp.Name <= va || exp.Name >= va + size) return 0;
    size -= exp.Name - va;
    va = exp.Name;
    ret = load_data_dir( buffer, sizeof(buffer), va, size, align_mask, unix_fd, sec, nb_sec );
    if (ret <= 0) return 0;
    if (!(end = memchr( buffer, 0, ret ))) return 0;
    if (!(*ret_buf = memdup( buffer, end - buffer ))) return 0;
    return end - buffer;
}

/* find a resource entry by id */
static size_t find_resource_id( const IMAGE_RESOURCE_DIRECTORY_ENTRY *entries, unsigned int count,
                                unsigned int id, int want_dir )
{
    for (unsigned int i = 0; i < count; i++)
        if (entries[i].Id == id && !entries[i].DataIsDirectory == !want_dir)
            return entries[i].OffsetToDirectory;
    return 0;
}

/* find a resource entry in a directory */
static size_t find_resource_entry( unsigned int id, IMAGE_DATA_DIRECTORY *data,
                                   size_t offset, size_t align_mask, int unix_fd,
                                   IMAGE_SECTION_HEADER *sec, unsigned int nb_sec )
{
    IMAGE_RESOURCE_DIRECTORY_ENTRY *entries;
    IMAGE_RESOURCE_DIRECTORY res;
    size_t size;
    int ret;

    if (offset >= data->Size) return 0;
    ret = load_data_dir( &res, sizeof(res), data->VirtualAddress + offset, data->Size - offset,
                         align_mask, unix_fd, sec, nb_sec );
    if (ret != sizeof(res)) return 0;
    offset += ret + res.NumberOfNamedEntries * sizeof(*entries);
    if (offset >= data->Size) return 0;
    size = res.NumberOfIdEntries * sizeof(*entries);
    if (!(entries = malloc( size ))) return 0;
    ret = load_data_dir( entries, size, data->VirtualAddress + offset, data->Size - offset,
                         align_mask, unix_fd, sec, nb_sec );
    offset = 0;
    if (ret >= sizeof(*entries))
    {
        unsigned int count = ret / sizeof(*entries);
        if (!id)  /* try various languages */
        {
            if (!(offset = find_resource_id( entries, count, 0x0409, 0 )) &&
                !(offset = find_resource_id( entries, count, 0x0000, 0 )) &&
                !entries[0].DataIsDirectory)
                offset = entries[0].OffsetToData;
        }
        else offset = find_resource_id( entries, count, id, 1 );
    }
    free( entries );
    return offset;
}

/* load the version resource */
static int load_version_resource( void **ret_buf, IMAGE_DATA_DIRECTORY *data, size_t align_mask,
                                  int unix_fd, IMAGE_SECTION_HEADER *sec, unsigned int nb_sec,
                                  size_t limit )
{
    IMAGE_RESOURCE_DATA_ENTRY entry;
    size_t offset;
    int ret;

    if (!(offset = find_resource_entry( RT_VERSION, data, 0, align_mask, unix_fd, sec, nb_sec ))) return 0;
    if (!(offset = find_resource_entry( 1, data, offset, align_mask, unix_fd, sec, nb_sec ))) return 0;
    if (!(offset = find_resource_entry( 0, data, offset, align_mask, unix_fd, sec, nb_sec ))) return 0;
    if (offset >= data->Size) return 0;
    ret = load_data_dir( &entry, sizeof(entry), data->VirtualAddress + offset, data->Size - offset,
                         align_mask, unix_fd, sec, nb_sec );
    if (ret != sizeof(entry)) return 0;
    if (entry.Size > limit) return -1;
    if (!(*ret_buf = malloc( (size_t)entry.Size + 3 ))) return 0;
    if ((ret = load_data_dir( *ret_buf, entry.Size, entry.OffsetToData, entry.Size,
                              align_mask, unix_fd, sec, nb_sec )) > 0)
    {
        if (ret % 4) memset( (char *)*ret_buf + ret, 0, 4 - ret % 4 );
        return (ret + 3) & ~3;
    }
    free( *ret_buf );
    *ret_buf = NULL;
    return 0;
}

/* load the CLR header from its section */
static int load_clr_header( IMAGE_COR20_HEADER *hdr, IMAGE_DATA_DIRECTORY *data, size_t align_mask,
                            int unix_fd, IMAGE_SECTION_HEADER *sec, unsigned int nb_sec )
{
    int ret = load_data_dir( hdr, sizeof(*hdr), data->VirtualAddress, data->Size,
                             align_mask, unix_fd, sec, nb_sec );

    if (ret <= 0) return 0;
    if (ret < sizeof(*hdr)) memset( (char *)hdr + ret, 0, sizeof(*hdr) - ret );
    return (hdr->MajorRuntimeVersion > COR_VERSION_MAJOR_V2 ||
            (hdr->MajorRuntimeVersion == COR_VERSION_MAJOR_V2 &&
             hdr->MinorRuntimeVersion >= COR_VERSION_MINOR));
}

/* load the LOAD_CONFIG header from its section */
static int load_cfg_header( IMAGE_LOAD_CONFIG_DIRECTORY64 *cfg, IMAGE_DATA_DIRECTORY *data, size_t align_mask,
                            int unix_fd, IMAGE_SECTION_HEADER *sec, unsigned int nb_sec )
{
    unsigned int cfg_size;
    int ret = load_data_dir( cfg, sizeof(*cfg), data->VirtualAddress, data->Size,
                             align_mask, unix_fd, sec, nb_sec );

    if (ret <= 0) return 0;
    cfg_size = ret;
    if (cfg_size < offsetof( IMAGE_LOAD_CONFIG_DIRECTORY64, Size ) + sizeof(cfg_size)) return 0;
    if (cfg_size > cfg->Size) cfg_size = cfg->Size;
    if (cfg_size < sizeof(*cfg)) memset( (char *)cfg + cfg_size, 0, sizeof(*cfg) - cfg_size );
    return 1;
}

/* retrieve the mapping parameters for an executable (PE) image */
static unsigned int get_image_params( struct mapping *mapping, file_pos_t file_size, int unix_fd,
                                      int *prepared_shared, file_pos_t *shared_size )
{
    static const char builtin_signature[] = "Wine builtin DLL";
    static const char fakedll_signature[] = "Wine placeholder DLL";

    IMAGE_COR20_HEADER clr;
    IMAGE_SECTION_HEADER *sec;
    struct
    {
        IMAGE_DOS_HEADER dos;
        char buffer[32];
    } mz;
    struct
    {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        union
        {
            IMAGE_OPTIONAL_HEADER32 hdr32;
            IMAGE_OPTIONAL_HEADER64 hdr64;
        } opt;
    } nt;
    union
    {
        IMAGE_LOAD_CONFIG_DIRECTORY32 cfg32;
        IMAGE_LOAD_CONFIG_DIRECTORY64 cfg64;
    } cfg;
    off_t pos;
    int size, has_relocs;
    IMAGE_DATA_DIRECTORY *data_dirs, *exp_dir, *res_dir, *cfg_dir, *clr_dir;
    size_t mz_size, align_mask;
    unsigned int i, ret, nb_data_dirs;

    /* load the headers */

    if (!file_size) return STATUS_INVALID_FILE_FOR_SECTION;
    size = pread( unix_fd, &mz, sizeof(mz), 0 );
    if (size < sizeof(mz.dos)) return STATUS_INVALID_IMAGE_NOT_MZ;
    if (mz.dos.e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_NOT_MZ;
    mz_size = size;
    pos = mz.dos.e_lfanew;

    size = pread( unix_fd, &nt, sizeof(nt), pos );
    if (size < sizeof(nt.Signature) + sizeof(nt.FileHeader)) return STATUS_INVALID_IMAGE_PROTECT;
    if (size < sizeof(nt)) memset( (char *)&nt + size, 0, sizeof(nt) - size );
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        IMAGE_OS2_HEADER *os2 = (IMAGE_OS2_HEADER *)&nt;
        if (os2->ne_magic != IMAGE_OS2_SIGNATURE) return STATUS_INVALID_IMAGE_PROTECT;
        if (os2->ne_exetyp == 2) return STATUS_INVALID_IMAGE_WIN_16;
        if (os2->ne_exetyp == 5) return STATUS_INVALID_IMAGE_PROTECT;
        return STATUS_INVALID_IMAGE_NE_FORMAT;
    }

    switch (nt.opt.hdr32.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        if (!is_machine_32bit( nt.FileHeader.Machine )) return STATUS_INVALID_IMAGE_FORMAT;
        if (!is_machine_supported( nt.FileHeader.Machine )) return STATUS_INVALID_IMAGE_FORMAT;

        if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_I386)  /* non-x86 platforms are more strict */
        {
            if (nt.opt.hdr32.SectionAlignment & page_mask)
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!(nt.opt.hdr32.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!(nt.opt.hdr32.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
                return STATUS_INVALID_IMAGE_FORMAT;
        }
        mapping->image.base            = nt.opt.hdr32.ImageBase;
        mapping->image.entry_point     = nt.opt.hdr32.AddressOfEntryPoint;
        mapping->image.map_size        = nt.opt.hdr32.SizeOfImage;
        mapping->image.alignment       = nt.opt.hdr32.SectionAlignment;
        mapping->image.stack_size      = nt.opt.hdr32.SizeOfStackReserve;
        mapping->image.stack_commit    = nt.opt.hdr32.SizeOfStackCommit;
        mapping->image.subsystem       = nt.opt.hdr32.Subsystem;
        mapping->image.subsystem_minor = nt.opt.hdr32.MinorSubsystemVersion;
        mapping->image.subsystem_major = nt.opt.hdr32.MajorSubsystemVersion;
        mapping->image.osversion_minor = nt.opt.hdr32.MinorOperatingSystemVersion;
        mapping->image.osversion_major = nt.opt.hdr32.MajorOperatingSystemVersion;
        mapping->image.dll_charact     = nt.opt.hdr32.DllCharacteristics;
        mapping->image.contains_code   = (nt.opt.hdr32.SizeOfCode ||
                                          nt.opt.hdr32.AddressOfEntryPoint ||
                                          nt.opt.hdr32.SectionAlignment & page_mask);
        mapping->image.header_size     = nt.opt.hdr32.SizeOfHeaders;
        mapping->image.checksum        = nt.opt.hdr32.CheckSum;
        nb_data_dirs                   = nt.opt.hdr32.NumberOfRvaAndSizes;
        data_dirs                      = nt.opt.hdr32.DataDirectory;
        break;

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (!is_machine_64bit( native_machine )) return STATUS_INVALID_IMAGE_WIN_64;
        if (!is_machine_64bit( nt.FileHeader.Machine )) return STATUS_INVALID_IMAGE_FORMAT;
        if (!is_machine_supported( nt.FileHeader.Machine )) return STATUS_INVALID_IMAGE_FORMAT;

        if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)  /* non-x86 platforms are more strict */
        {
            if (nt.opt.hdr64.SectionAlignment & page_mask)
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!(nt.opt.hdr64.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!(nt.opt.hdr64.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
                return STATUS_INVALID_IMAGE_FORMAT;
        }
        mapping->image.base            = nt.opt.hdr64.ImageBase;
        mapping->image.entry_point     = nt.opt.hdr64.AddressOfEntryPoint;
        mapping->image.map_size        = nt.opt.hdr64.SizeOfImage;
        mapping->image.alignment       = nt.opt.hdr64.SectionAlignment;
        mapping->image.stack_size      = nt.opt.hdr64.SizeOfStackReserve;
        mapping->image.stack_commit    = nt.opt.hdr64.SizeOfStackCommit;
        mapping->image.subsystem       = nt.opt.hdr64.Subsystem;
        mapping->image.subsystem_minor = nt.opt.hdr64.MinorSubsystemVersion;
        mapping->image.subsystem_major = nt.opt.hdr64.MajorSubsystemVersion;
        mapping->image.osversion_minor = nt.opt.hdr64.MinorOperatingSystemVersion;
        mapping->image.osversion_major = nt.opt.hdr64.MajorOperatingSystemVersion;
        mapping->image.dll_charact     = nt.opt.hdr64.DllCharacteristics;
        mapping->image.contains_code   = (nt.opt.hdr64.SizeOfCode ||
                                          nt.opt.hdr64.AddressOfEntryPoint ||
                                          nt.opt.hdr64.SectionAlignment & page_mask);
        mapping->image.header_size     = nt.opt.hdr64.SizeOfHeaders;
        mapping->image.checksum        = nt.opt.hdr64.CheckSum;
        nb_data_dirs                   = nt.opt.hdr64.NumberOfRvaAndSizes;
        data_dirs                      = nt.opt.hdr64.DataDirectory;
        break;

    default:
        return STATUS_INVALID_IMAGE_FORMAT;
    }

#define GET_DATA_DIR(dir) \
    (dir < nb_data_dirs && data_dirs[dir].VirtualAddress && data_dirs[dir].Size ? &data_dirs[dir] : NULL)

    exp_dir = GET_DATA_DIR( IMAGE_DIRECTORY_ENTRY_EXPORT );
    res_dir = GET_DATA_DIR( IMAGE_DIRECTORY_ENTRY_RESOURCE );
    cfg_dir = GET_DATA_DIR( IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG );
    clr_dir = GET_DATA_DIR( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR );
    has_relocs = (GET_DATA_DIR( IMAGE_DIRECTORY_ENTRY_BASERELOC ) &&
                  !(nt.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED));
#undef GET_DATA_DIR

    mapping->image.is_hybrid     = 0;
    mapping->image.padding       = 0;
    mapping->image.map_addr      = mapping->fd ? get_fd_map_address( mapping->fd ) : 0;
    mapping->image.image_charact = nt.FileHeader.Characteristics;
    mapping->image.machine       = nt.FileHeader.Machine;
    mapping->image.dbg_offset    = nt.FileHeader.PointerToSymbolTable;
    mapping->image.dbg_size      = nt.FileHeader.NumberOfSymbols;
    mapping->image.zerobits      = 0; /* FIXME */
    mapping->image.file_size     = file_size;
    mapping->image.image_flags   = 0;
    mapping->image.loader_flags  = !!clr_dir;
    mapping->image.wine_builtin  = (mz_size == sizeof(mz) &&
                                    !memcmp( mz.buffer, builtin_signature, sizeof(builtin_signature) ));
    mapping->image.wine_fakedll  = (mz_size == sizeof(mz) &&
                                    !memcmp( mz.buffer, fakedll_signature, sizeof(fakedll_signature) ));

    if (mapping->image.alignment & page_mask)
        mapping->image.image_flags |= IMAGE_FLAGS_ImageMappedFlat;
    else if ((mapping->image.dll_charact & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) &&
             (has_relocs || mapping->image.contains_code) && !clr_dir)
        mapping->image.image_flags |= IMAGE_FLAGS_ImageDynamicallyRelocated;

    align_mask = max( mapping->image.alignment - 1, page_mask );
    mapping->image.map_size = round_size( mapping->image.map_size, align_mask );

    /* load the section headers */

    pos += sizeof(nt.Signature) + sizeof(nt.FileHeader) + nt.FileHeader.SizeOfOptionalHeader;
    size = sizeof(*sec) * nt.FileHeader.NumberOfSections;
    if (!mapping->size) mapping->size = mapping->image.map_size;
    else if (mapping->size > mapping->image.map_size) return STATUS_SECTION_TOO_BIG;
    if (pos + size > mapping->image.map_size) return STATUS_INVALID_FILE_FOR_SECTION;
    if (pos + size > mapping->image.header_size) mapping->image.header_size = pos + size;
    if (!(sec = malloc( size ))) return STATUS_NO_MEMORY;
    ret = STATUS_INVALID_FILE_FOR_SECTION;
    if (pread( unix_fd, sec, size, pos ) != size) goto done;

    mapping->image.header_map_size = mapping->image.map_size;
    for (i = 0; i < nt.FileHeader.NumberOfSections; i++)
    {
        mapping->image.header_map_size = min( mapping->image.header_map_size, sec[i].VirtualAddress );
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) mapping->image.contains_code = 1;
    }

    if (mapping->image.wine_builtin || mapping->image.wine_fakedll)
    {
        if (exp_dir) mapping->exp_len = load_export_name( &mapping->exp_name, exp_dir, align_mask,
                                                          unix_fd, sec, nt.FileHeader.NumberOfSections );
    }
    else if (res_dir)
    {
        size = load_version_resource( &mapping->ver_res, res_dir, align_mask, unix_fd, sec,
                                      nt.FileHeader.NumberOfSections,
                                      prepared_shared ? MAX_IMAGE_METADATA_BYTES : SIZE_MAX );
        if (size < 0) { ret = STATUS_SECTION_TOO_BIG; goto done; }
        mapping->ver_len = size;
    }

    if (clr_dir &&
        load_clr_header( &clr, clr_dir, align_mask, unix_fd, sec, nt.FileHeader.NumberOfSections ) &&
        (clr.Flags & COMIMAGE_FLAGS_ILONLY))
    {
        mapping->image.image_flags |= IMAGE_FLAGS_ComPlusILOnly;
        if (nt.opt.hdr32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            if (!(clr.Flags & COMIMAGE_FLAGS_32BITREQUIRED))
                mapping->image.image_flags |= IMAGE_FLAGS_ComPlusNativeReady;
            if (clr.Flags & COMIMAGE_FLAGS_32BITPREFERRED)
                mapping->image.image_flags |= IMAGE_FLAGS_ComPlusPrefer32bit;
        }
    }

    if (cfg_dir && load_cfg_header( &cfg.cfg64, cfg_dir, align_mask,
                                    unix_fd, sec, nt.FileHeader.NumberOfSections ))
    {
        if (nt.opt.hdr32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            mapping->image.is_hybrid = !!cfg.cfg32.CHPEMetadataPointer;
        else
            mapping->image.is_hybrid = !!cfg.cfg64.CHPEMetadataPointer;
    }

    ret = prepared_shared ? copy_shared_mapping( align_mask, unix_fd, sec, nt.FileHeader.NumberOfSections,
                                                1, prepared_shared, shared_size ) :
                            build_shared_mapping( mapping, align_mask, unix_fd, sec,
                                                  nt.FileHeader.NumberOfSections );

done:
    free( sec );
    return ret;
}

static struct ranges *create_ranges(void)
{
    struct ranges *ranges = alloc_object( &ranges_ops );

    if (!ranges) return NULL;
    ranges->count = 0;
    ranges->max   = 8;
    if (!(ranges->ranges = mem_alloc( ranges->max * sizeof(*ranges->ranges) )))
    {
        release_object( ranges );
        return NULL;
    }
    return ranges;
}

static unsigned int get_mapping_flags( obj_handle_t handle, unsigned int flags )
{
    switch (flags & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_FILE))
    {
    case SEC_IMAGE:
        if (flags & (SEC_WRITECOMBINE | SEC_LARGE_PAGES)) break;
        if (handle) return SEC_FILE | SEC_IMAGE;
        set_error( STATUS_INVALID_FILE_FOR_SECTION );
        return 0;
    case SEC_COMMIT:
        if (!handle) return flags;
        /* fall through */
    case SEC_RESERVE:
        if (flags & SEC_LARGE_PAGES) break;
        if (handle) return SEC_FILE | (flags & (SEC_NOCACHE | SEC_WRITECOMBINE));
        return flags;
    }
    set_error( STATUS_INVALID_PARAMETER );
    return 0;
}

static bool mapping_init( struct object *obj, const void *init_data )
{
    struct mapping *mapping = (struct mapping *)obj;
    const struct mapping_init_data *data = init_data;
    int unix_fd;
    struct stat st;

    mapping->size        = data->size;
    mapping->flags       = data->flags;
    mapping->fd          = NULL;
    mapping->image_fd    = NULL;
    mapping->snapshot_bytes = data->snapshot ? data->snapshot_bytes : 0;
    if (data->snapshot_consumed) *data->snapshot_consumed = true;
    mapping->image_class = IMAGE_TRUST_UNTRUSTED;
    mapping->shared      = NULL;
    mapping->committed   = NULL;
    mapping->exp_name    = NULL;
    mapping->ver_res     = NULL;
    mapping->exp_len     = 0;
    mapping->ver_len     = 0;
    mapping->metadata    = NULL;
    mapping->metadata_size = 0;

    if (data->fd)
    {
        const unsigned int sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        unsigned int mapping_access = FILE_MAPPING_ACCESS;

        /* file sharing rules for mappings are different so we use magic the access rights */
        if (data->flags & SEC_IMAGE) mapping_access |= FILE_MAPPING_IMAGE;
        else if (data->file_access & FILE_WRITE_DATA) mapping_access |= FILE_MAPPING_WRITE;

        if (!(mapping->fd = get_fd_object_for_mapping( data->fd, mapping_access, sharing )))
        {
            mapping->fd = dup_fd_object( data->fd, mapping_access, sharing, FILE_SYNCHRONOUS_IO_NONALERT );
            if (mapping->fd) set_fd_user( mapping->fd, &mapping_fd_ops, NULL );
        }
        if (!mapping->fd) goto error;

        if ((unix_fd = get_unix_fd( mapping->fd )) == -1) goto error;
        if (fstat( data->snapshot ? get_unix_fd(data->snapshot) : unix_fd, &st ) == -1)
        {
            file_set_error();
            goto error;
        }
        if (data->flags & SEC_IMAGE)
        {
            unsigned int err;

            if (data->snapshot)
            {
                mapping->image_fd = (struct fd *)grab_object(data->snapshot);
                unix_fd = get_unix_fd(mapping->image_fd);
            }
            else if (is_native_machine() || image_trust_ready())
            {
                /* All native/catalog image callers must use the bounded job path. */
                set_error( STATUS_NOT_SUPPORTED );
                goto error;
            }
            if (data->image)
            {
                size_t ver_offset = ((size_t)data->exp_len + 3) / 4 * 4;
                mapping->image = *data->image;
                mapping->image.map_addr = get_fd_map_address( mapping->fd );
                mapping->size = data->image_size;
                mapping->exp_len = data->exp_len;
                mapping->ver_len = data->ver_len;
                mapping->metadata_size = ver_offset + data->ver_len;
                if (mapping->metadata_size)
                {
                    struct stat metadata_stat;
                    int fd = data->metadata ? get_unix_fd(data->metadata) : -1;
                    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
                    int actual_seals = fd == -1 ? -1 : fcntl(fd,F_GET_SEALS);
                    if (mapping->metadata_size > MAX_IMAGE_METADATA_BYTES || fd == -1 ||
                        fstat(fd,&metadata_stat) || metadata_stat.st_size != mapping->metadata_size ||
                        actual_seals == -1 || (actual_seals & seals) != seals)
                    {
                        set_error( STATUS_UNSUCCESSFUL );
                        goto error;
                    }
                    mapping->metadata = mmap( NULL, mapping->metadata_size, PROT_READ, MAP_SHARED, fd, 0 );
                    if (mapping->metadata == MAP_FAILED)
                    {
                        mapping->metadata = NULL;
                        set_error( STATUS_NO_MEMORY );
                        goto error;
                    }
                    if (data->exp_len) mapping->exp_name = mapping->metadata;
                    if (data->ver_len) mapping->ver_res = (char *)mapping->metadata + ver_offset;
                }
                err = STATUS_SUCCESS;
                if (data->shared_size)
                {
                    struct stat shared_stat;
                    int fd = data->shared ? get_unix_fd(data->shared) : -1;
                    const int seals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
                    int actual_seals = fd == -1 ? -1 : fcntl(fd,F_GET_SEALS);
                    if (fd == -1 || data->shared_size > MAX_SHARED_IMAGE_BYTES || fstat(fd,&shared_stat) ||
                        shared_stat.st_size != data->shared_size || actual_seals == -1 ||
                        (actual_seals & seals) != seals)
                        err = STATUS_UNSUCCESSFUL;
                    else err = install_shared_mapping( mapping, fd, data->shared_size );
                }
            }
            else err = get_image_params( mapping, st.st_size, unix_fd, NULL, NULL );
            if (!err)
            {
                mapping->image_class = data->digest ? classify_image_digest( data->digest, st.st_size,
                                                                            mapping->image.machine ) : 0;
                if (debug_level && image_trust_ready())
                    fprintf( stderr, "image-trust: class=%u machine=%04x bytes=%llu\n",
                             mapping->image_class, mapping->image.machine, (unsigned long long)st.st_size );
                return true;
            }
            set_error( err );
            goto error;
        }
        if (!mapping->size)
        {
            if (!(mapping->size = st.st_size))
            {
                set_error( STATUS_MAPPED_FILE_SIZE_ZERO );
                goto error;
            }
        }
        else if (st.st_size < mapping->size)
        {
            if (!(data->file_access & FILE_WRITE_DATA) || mapping->size >> 54 /* ntfs limit */)
            {
                set_error( STATUS_SECTION_TOO_BIG );
                goto error;
            }
            if (!grow_file( unix_fd, mapping->size )) goto error;
        }
    }
    else  /* Anonymous mapping (no associated file) */
    {
        if (!mapping->size)
        {
            set_error( STATUS_INVALID_PARAMETER );
            return false;
        }
        if ((data->flags & SEC_RESERVE) && !(mapping->committed = create_ranges())) return false;
        mapping->size = round_size( mapping->size, page_mask );
        if ((unix_fd = create_temp_file( mapping->size )) == -1) goto error;
        if (!(mapping->fd = create_anonymous_fd( &mapping_fd_ops, unix_fd, &mapping->obj,
                                                 FILE_SYNCHRONOUS_IO_NONALERT ))) goto error;
        allow_fd_caching( mapping->fd );
    }
    return true;

 error:
    if (mapping->fd) release_object( mapping->fd );
    if (mapping->image_fd) release_object( mapping->image_fd );
    retained_image_bytes -= mapping->snapshot_bytes;
    if (mapping->committed) release_object( mapping->committed );
    if (mapping->shared) release_object( mapping->shared );
    if (mapping->metadata) munmap( mapping->metadata, mapping->metadata_size );
    return false;
}

/* create a read-only file mapping for the specified fd */
struct mapping *create_fd_mapping( struct object *root, struct unicode_str name,
                                   struct fd *fd, unsigned int attr, const struct security_descriptor *sd )
{
    struct mapping_init_data data = { .fd = fd, .flags = SEC_FILE, .file_access = FILE_READ_DATA };
    struct object_params params = { .ops = &mapping_ops, .root = root, .name = name,
                                    .attr = attr, .sd = sd, .init_data = &data };

    return create_named_object( &params );
}

static struct mapping *get_mapping_obj( struct process *process, obj_handle_t handle, unsigned int access )
{
    return (struct mapping *)get_handle_obj( process, handle, access, &mapping_ops );
}

/* open a new file for the file descriptor backing the view */
struct file *get_view_file( const struct memory_view *view, unsigned int access, unsigned int sharing )
{
    if (!view->fd) return NULL;
    return create_file_for_fd_obj( view->fd, access, sharing );
}

/* get the image info for a SEC_IMAGE mapped view */
const struct pe_image_info *get_view_image_info( const struct memory_view *view, client_ptr_t *base )
{
    if (!(view->flags & SEC_IMAGE)) return NULL;
    *base = view->base;
    return &view->image;
}

/* get the file name for a mapped view */
int get_view_nt_name( const struct memory_view *view, struct unicode_str *name )
{
    if (view->namelen)  /* .so builtin */
    {
        name->str = view->name;
        name->len = view->namelen;
        return 1;
    }
    if (!view->fd) return 0;
    *name = get_nt_name( view->fd );
    return 1;
}

/* generate all startup events of a given process */
void generate_startup_debug_events( struct process *process )
{
    struct memory_view *view;
    struct list *ptr = list_head( &process->views );
    struct thread *thread, *first_thread = get_process_first_thread( process );

    if (!ptr) return;
    view = LIST_ENTRY( ptr, struct memory_view, entry );
    generate_debug_event( first_thread, DbgCreateProcessStateChange, view );

    /* generate ntdll.dll load event */
    while (ptr && (ptr = list_next( &process->views, ptr )))
    {
        view = LIST_ENTRY( ptr, struct memory_view, entry );
        if (generate_dll_event( first_thread, DbgLoadDllStateChange, view )) break;
    }

    /* generate creation events */
    LIST_FOR_EACH_ENTRY( thread, &process->thread_list, struct thread, proc_entry )
    {
        if (thread->is_system) continue;
        if (thread != first_thread) generate_debug_event( thread, DbgCreateThreadStateChange, NULL );
    }

    /* generate dll events (in loading order) */
    while (ptr && (ptr = list_next( &process->views, ptr )))
    {
        view = LIST_ENTRY( ptr, struct memory_view, entry );
        generate_dll_event( first_thread, DbgLoadDllStateChange, view );
    }
}

static void mapping_dump( struct object *obj, int verbose )
{
    struct mapping *mapping = (struct mapping *)obj;
    assert( obj->ops == &mapping_ops );
    fprintf( stderr, "Mapping size=%08x%08x flags=%08x fd=%p shared=%p\n",
             (unsigned int)(mapping->size >> 32), (unsigned int)mapping->size,
             mapping->flags, mapping->fd, mapping->shared );
}

static struct fd *mapping_get_fd( struct object *obj )
{
    struct mapping *mapping = (struct mapping *)obj;
    return (struct fd *)grab_object( mapping->image_fd ? mapping->image_fd : mapping->fd );
}

static void mapping_destroy( struct object *obj )
{
    struct mapping *mapping = (struct mapping *)obj;
    assert( obj->ops == &mapping_ops );
    if (mapping->fd) release_object( mapping->fd );
    if (mapping->image_fd) release_object( mapping->image_fd );
    retained_image_bytes -= mapping->snapshot_bytes;
    if (mapping->committed) release_object( mapping->committed );
    if (mapping->shared) release_object( mapping->shared );
    if (mapping->metadata) munmap( mapping->metadata, mapping->metadata_size );
    else
    {
        free( mapping->exp_name );
        free( mapping->ver_res );
    }
}

static enum server_fd_type mapping_get_fd_type( struct fd *fd )
{
    return FD_TYPE_FILE;
}

/* assign a mapping address to a PE image mapping */
/* Retain shared data storage only with both mapping rights. Image sections
 * cannot back writable GDI or LPC data views. */
struct object *get_shared_data_section( struct process *process, obj_handle_t handle, mem_size_t *size )
{
    struct mapping *mapping = get_mapping_obj( process, handle, SECTION_MAP_READ | SECTION_MAP_WRITE );
    if (!mapping) return NULL;
    if (mapping->flags & SEC_IMAGE)
    {
        release_object( mapping );
        set_error( STATUS_INVALID_PARAMETER );
        return NULL;
    }
    *size = mapping->size;
    return &mapping->obj;
}

int is_data_section_view( struct process *process, struct object *section,
                          client_ptr_t base, mem_size_t offset, mem_size_t size )
{
    struct mapping *mapping = (struct mapping *)section;
    struct memory_view *view = find_mapped_view( process, base );

    assert( section->ops == &mapping_ops );
    return view && view->base == base && view->fd == mapping->fd &&
           view->start == offset && view->size >= size && !(view->flags & SEC_IMAGE);
}

static client_ptr_t assign_map_address( struct mapping *mapping )
{
    unsigned int i;
    client_ptr_t ret;
    struct addr_range *range = (mapping->image.base >> 32) ? &ranges64 : &ranges32;
    mem_size_t size = round_size( mapping->size, granularity_mask );

    if (!(mapping->image.image_charact & IMAGE_FILE_DLL)) return 0;

    if ((ret = get_fd_map_address( mapping->fd ))) return ret;

    size += granularity_mask + 1;  /* leave some free space between mappings */

    for (i = 0; i < range->count; i++)
    {
        if (range->free[i].size < size) continue;
        range->free[i].size -= size;
        ret = range->free[i].base + range->free[i].size;
        set_fd_map_address( mapping->fd, ret, size );
        return ret;
    }
    return 0;
}

/* free a PE mapping address range when the last mapping is closed */
void free_map_addr( client_ptr_t base, mem_size_t size )
{
    unsigned int i;
    client_ptr_t end = base + size;
    struct addr_range *range = (base >> 32) ? &ranges64 : &ranges32;

    for (i = 0; i < range->count; i++)
    {
        if (range->free[i].base > end) continue;
        if (range->free[i].base + range->free[i].size < base) break;
        if (range->free[i].base == end)
        {
            if (i + 1 < range->count && range->free[i + 1].base + range->free[i + 1].size == base)
            {
                size += range->free[i].size;
                range->count--;
                memmove( &range->free[i], &range->free[i + 1], (range->count - i) * sizeof(*range->free) );
            }
            else range->free[i].base = base;
        }
        range->free[i].size += size;
        return;
    }

    if (range->count == range->size)
    {
        unsigned int new_size = max( 256, range->size * 2 );
        void *new_free = realloc( range->free, new_size * sizeof(*range->free) );
        if (!new_free) return;
        range->size = new_size;
        range->free = new_free;
    }
    memmove( &range->free[i + 1], &range->free[i], (range->count - i) * sizeof(*range->free) );
    range->free[i].base = base;
    range->free[i].size = size;
    range->count++;
}

size_t get_page_size(void)
{
    return host_page_mask + 1;
}

struct mapping *create_anonymous_mapping( mem_size_t size, unsigned int file_access )
{
    struct mapping_init_data data = { .size = round_size( size, host_page_mask ), .flags = SEC_COMMIT,
                                      .file_access = file_access };
    struct object_params params = { .ops = &mapping_ops, .name = empty_str, .init_data = &data };

    return create_named_object( &params );
}

struct mapping *create_session_mapping( struct object *root, struct unicode_str name,
                                        unsigned int attr, const struct security_descriptor *sd )
{
    size_t size = max( sizeof(*shared_session) + sizeof(object_shm_t) * 512, 0x10000 );
    struct mapping_init_data data = { .size = round_size( size, host_page_mask ), .flags = SEC_COMMIT,
                                      .file_access = FILE_READ_DATA | FILE_WRITE_DATA };
    struct object_params params = { .ops = &mapping_ops, .root = root, .name = name,
                                    .attr = attr, .sd = sd, .init_data = &data };

    return create_named_object( &params );
}

void set_session_mapping( struct mapping *mapping )
{
    int unix_fd = get_unix_fd( mapping->fd );
    size_t size = mapping->size;
    struct session_block *block;
    void *tmp;

    if (!(block = mem_alloc( sizeof(*block) ))) return;
    if ((tmp = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, unix_fd, 0 )) == MAP_FAILED)
    {
        free( block );
        return;
    }

    block->data = tmp;
    block->offset = 0;
    block->used_size = sizeof(*shared_session);
    block->block_size = size;

    shared_session = tmp;
    session_mapping = mapping;
    list_add_tail( &session.blocks, &block->entry );
}

static struct session_block *grow_session_mapping( mem_size_t needed )
{
    size_t old_size = session_mapping->size, new_size;
    struct session_block *block;
    int unix_fd;
    void *tmp;

    new_size = max( old_size * 3 / 2, old_size + max( needed, 0x10000 ) );
    new_size = round_size( new_size, host_page_mask );
    assert( new_size > old_size );

    unix_fd = get_unix_fd( session_mapping->fd );
    if (!grow_file( unix_fd, new_size )) return NULL;

    if (!(block = mem_alloc( sizeof(*block) ))) return NULL;
    if ((tmp = mmap( NULL, new_size - old_size, PROT_READ | PROT_WRITE, MAP_SHARED, unix_fd, old_size )) == MAP_FAILED)
    {
        file_set_error();
        free( block );
        return NULL;
    }

    block->data = tmp;
    block->offset = old_size;
    block->used_size = 0;
    block->block_size = new_size - old_size;

    session_mapping->size = new_size;
    list_add_tail( &session.blocks, &block->entry );

    return block;
}

static struct session_block *find_free_session_block( mem_size_t size )
{
    struct session_block *block;

    LIST_FOR_EACH_ENTRY( block, &session.blocks, struct session_block, entry )
        if (size < block->block_size && block->used_size < block->block_size - size) return block;

    return grow_session_mapping( size );
}

static struct session_object *find_free_session_object( mem_size_t size )
{
    struct session_object *object;

    LIST_FOR_EACH_ENTRY( object, &session.free_objects, struct session_object, entry )
    {
        if (size == sizeof(*object) && object->size == size) return object;
        if (size > sizeof(*object) && size <= object->size) return object;
    }

    return NULL;
}

volatile void *alloc_shared_object( mem_size_t shm_size )
{
    struct session_object *object;
    mem_size_t size = sizeof(*object) - sizeof(object_shm_t) + max(shm_size, sizeof(object_shm_t));

    if ((object = find_free_session_object( size )))
        list_remove( &object->entry );
    else
    {
        struct session_block *block;

        if (!(block = find_free_session_block( size ))) return NULL;
        object = (struct session_object *)(block->data + block->used_size);
        object->offset = block->offset + (char *)&object->obj - block->data;
        object->size = size;
        block->used_size += size;
    }

    SHARED_WRITE_BEGIN( &object->obj.shm, object_shm_t )
    {
        /* mark the object data as uninitialized */
        mark_block_uninitialized( (void *)shared, shm_size );
        CONTAINING_RECORD( shared, shared_object_t, shm )->id = ++session.last_object_id;
    }
    SHARED_WRITE_END;

    return &object->obj.shm;
}

void free_shared_object( volatile void *object_shm )
{
    struct session_object *object = CONTAINING_RECORD( object_shm, struct session_object, obj.shm );
    mem_size_t shm_size = object->size - sizeof(*object) + sizeof(object_shm_t);

    SHARED_WRITE_BEGIN( &object->obj.shm, object_shm_t )
    {
        mark_block_noaccess( (void *)shared, shm_size );
        CONTAINING_RECORD( shared, shared_object_t, shm )->id = 0;
    }
    SHARED_WRITE_END;

    list_add_tail( &session.free_objects, &object->entry );
}

/* invalidate client caches for a shared object by giving it a new id */
void invalidate_shared_object( volatile void *object_shm )
{
    struct session_object *object = CONTAINING_RECORD( object_shm, struct session_object, obj.shm );

    SHARED_WRITE_BEGIN( &object->obj.shm, object_shm_t )
    {
        CONTAINING_RECORD( shared, shared_object_t, shm )->id = ++session.last_object_id;
    }
    SHARED_WRITE_END;
}

struct obj_locator get_shared_object_locator( volatile void *object_shm )
{
    struct session_object *object = CONTAINING_RECORD( object_shm, struct session_object, obj.shm );
    struct obj_locator locator = {.offset = object->offset, .id = object->obj.id};
    return locator;
}

struct object *create_user_data_mapping( struct object *root, struct unicode_str name,
                                        unsigned int attr, const struct security_descriptor *sd )
{
    void *ptr;
    struct mapping *mapping;
    struct mapping_init_data data = { .size = sizeof(KUSER_SHARED_DATA), .flags = SEC_COMMIT,
                                      .file_access = FILE_READ_DATA | FILE_WRITE_DATA };
    struct object_params params = { .ops = &mapping_ops, .root = root, .name = name,
                                    .attr = attr, .sd = sd, .init_data = &data };

    if (!(mapping = create_named_object( &params ))) return NULL;
    ptr = mmap( NULL, mapping->size, PROT_WRITE, MAP_SHARED, get_unix_fd( mapping->fd ), 0 );
    if (ptr != MAP_FAILED) user_shared_data = ptr;
    return &mapping->obj;
}

/* create a file mapping */
DECL_HANDLER(create_mapping)
{
    struct file *file = NULL;
    struct mapping_init_data data = { .size = req->size, .file_access = req->file_access };
    struct object_params params = { .ops = &mapping_ops, .access = req->access, .init_data = &data };

    if (!get_req_object_attributes( &params )) return;

    if (!(data.flags = get_mapping_flags( req->file_handle, req->flags )))
    {
        if (params.root) release_object( params.root );
        return;
    }
    if (req->file_handle)
    {
        if (!(file = get_file_obj( current->process, req->file_handle, req->file_access )))
        {
            if (params.root) release_object( params.root );
            return;
        }
        data.fd = get_obj_fd( (struct object *)file );
    }

    if (data.fd && (data.flags & SEC_IMAGE) && (is_native_machine() || image_trust_ready()))
    {
        struct object *existing = NULL;
        if (params.name.len)
        {
            struct object_params lookup = params;
            lookup.ops = NULL;
            existing = open_named_object(&lookup);
        }
        if (existing)
        {
            release_object(existing);
            reply->handle = create_named_obj_handle(current->process,&params);
        }
        else if (params.name.len && get_error() != STATUS_OBJECT_NAME_NOT_FOUND)
            reply->handle = create_named_obj_handle(current->process,&params);
        else
        {
            clear_error();
            start_image_job(&params,&data);
        }
    }
    else reply->handle = create_named_obj_handle( current->process, &params );

    if (file) release_object( file );
    if (data.fd) release_object( data.fd );
    if (params.root) release_object( params.root );
}

/* open a handle to a mapping */
DECL_HANDLER(open_mapping)
{
    reply->handle = open_object( current->process, req->rootdir, req->access,
                                 &mapping_ops, get_req_unicode_str(), req->attributes );
}

/* get a mapping information */
DECL_HANDLER(get_mapping_info)
{
    struct mapping *mapping;

    if (!(mapping = get_mapping_obj( current->process, req->handle, req->access ))) return;

    reply->size    = mapping->size;
    reply->flags   = mapping->flags;

    if (mapping->flags & SEC_IMAGE)
    {
        struct unicode_str name = mapping->fd ? get_nt_name( mapping->fd ) : empty_str;
        data_size_t size;
        void *data;

        size = reply->total = sizeof(struct pe_image_info) + mapping->ver_len + name.len + mapping->exp_len;
        if (size > get_reply_max_size()) size = sizeof(struct pe_image_info) + mapping->ver_len + name.len;
        if (size > get_reply_max_size()) size = sizeof(struct pe_image_info) + mapping->ver_len;
        if (size > get_reply_max_size()) size = sizeof(struct pe_image_info);
        if ((data = set_reply_data_size( size )))
        {
            data = mem_append( data, &mapping->image, min( sizeof(struct pe_image_info), size ));
            if (size >= sizeof(struct pe_image_info) + mapping->ver_len)
            {
                data = mem_append( data, mapping->ver_res, mapping->ver_len );
                reply->ver_len = mapping->ver_len;
            }
            if (size >= sizeof(struct pe_image_info) + mapping->ver_len + name.len)
            {
                data = mem_append( data, name.str, name.len );
                reply->name_len = name.len;
            }
            if (size == reply->total) mem_append( data, mapping->exp_name, mapping->exp_len );
        }
    }

    if (!(req->access & (SECTION_MAP_READ | SECTION_MAP_WRITE)))  /* query only */
    {
        release_object( mapping );
        return;
    }

    if (mapping->shared)
        reply->shared_file = alloc_handle( current->process, mapping->shared->file,
                                           GENERIC_READ|GENERIC_WRITE, 0 );
    release_object( mapping );
}

/* get the address to use to map an image mapping */
DECL_HANDLER(get_image_map_address)
{
    struct mapping *mapping;

    if (!(mapping = get_mapping_obj( current->process, req->handle, SECTION_MAP_READ ))) return;

    if ((mapping->flags & SEC_IMAGE) &&
        (mapping->image.image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated))
    {
        if (!mapping->image.map_addr) mapping->image.map_addr = assign_map_address( mapping );
        reply->addr = mapping->image.map_addr;
    }
    else set_error( STATUS_INVALID_PARAMETER );

    release_object( mapping );
}

/* add a memory view in the current process */
DECL_HANDLER(map_view)
{
    struct mapping *mapping;
    struct memory_view *view;

    if (!is_valid_view_addr( current->process, req->base, req->size ))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }

    if (!(mapping = get_mapping_obj( current->process, req->mapping, req->access ))) return;

    if ((mapping->flags & SEC_IMAGE) ||
        req->start >= mapping->size ||
        req->start + req->size < req->start ||
        req->start + req->size > round_size( mapping->size, page_mask ))
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }

    if ((view = mem_alloc( sizeof(*view) )))
    {
        view->base      = req->base;
        view->size      = req->size;
        view->start     = req->start;
        view->flags     = mapping->flags;
        view->namelen   = 0;
        view->fd        = !is_fd_removable( mapping->fd ) ? (struct fd *)grab_object( mapping->fd ) : NULL;
        view->committed = mapping->committed ? (struct ranges *)grab_object( mapping->committed ) : NULL;
        view->shared    = NULL;
        add_process_view( current, view );
    }

done:
    release_object( mapping );
}

/* add a memory view for an image mapping in the current process */
DECL_HANDLER(map_image_view)
{
    struct mapping *mapping;
    struct memory_view *view;

    if (!is_valid_view_addr( current->process, req->base, req->size ))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }

    if (!(mapping = get_mapping_obj( current->process, req->mapping, SECTION_MAP_READ ))) return;

    if (!(mapping->flags & SEC_IMAGE) || req->size > mapping->image.map_size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }

    if (!(mapping->image.image_charact & IMAGE_FILE_DLL) &&
        !validate_native_bootstrap_image( current->process, get_unix_fd( mapping->fd ))) goto done;

    if ((view = mem_alloc( sizeof(*view) )))
    {
        view->base      = req->base;
        view->size      = req->size;
        view->flags     = mapping->flags;
        view->start     = 0;
        view->namelen   = 0;
        view->fd        = !is_fd_removable( mapping->fd ) ? (struct fd *)grab_object( mapping->fd ) : NULL;
        view->committed = NULL;
        view->shared    = mapping->shared ? (struct shared_map *)grab_object( mapping->shared ) : NULL;
        view->image     = mapping->image;
        if (add_process_view( current, view ))
        {
            if (current->process->native_bootstrap_pid) current->process->native_bootstrap_mapped = 1;
            current->entry_point = view->base + req->entry;
            if (view->image.image_flags & IMAGE_FLAGS_ComPlusNativeReady)
                current->process->machine = is_machine_64bit( native_machine )
                    ? IMAGE_FILE_MACHINE_AMD64 : native_machine;
            else
                current->process->machine = req->machine;
        }

        if (view->base != (mapping->image.map_addr ? mapping->image.map_addr : mapping->image.base) + req->offset)
            set_error( STATUS_IMAGE_NOT_AT_BASE );
        if (req->machine != current->process->machine)
        {
            /* on 32-bit, the native 64-bit machine is allowed */
            if (is_machine_64bit( current->process->machine ) || req->machine != native_machine)
                set_error( STATUS_IMAGE_MACHINE_TYPE_MISMATCH );
        }
    }

done:
    release_object( mapping );
}

/* add a memory view for a builtin dll in the current process */
DECL_HANDLER(map_builtin_view)
{
    struct memory_view *view;
    const struct pe_image_info *image = get_req_data();
    data_size_t namelen = get_req_data_size() - sizeof(*image);

    if (get_req_data_size() < sizeof(*image) ||
        (namelen & (sizeof(WCHAR) - 1)) ||
        !is_valid_view_addr( current->process, image->base, image->map_size ))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }

    if (!(image->image_charact & IMAGE_FILE_DLL) &&
        !validate_native_bootstrap_image( current->process, -1 )) return;

    if ((view = mem_alloc( sizeof(struct memory_view) + namelen )))
    {
        memset( view, 0, sizeof(*view) );
        view->base    = image->base;
        view->size    = image->map_size;
        view->flags   = SEC_IMAGE;
        view->image   = *image;
        view->namelen = namelen;
        memcpy( view->name, image + 1, namelen );
        if (add_process_view( current, view ))
        {
            current->entry_point = view->base + image->entry_point;
            current->process->machine = image->machine;
        }
    }
}

/* unmap a memory view from the current process */
DECL_HANDLER(unmap_view)
{
    struct memory_view *view = find_mapped_view( current->process, req->base );

    if (!view) return;
    generate_dll_event( current, DbgUnloadDllStateChange, view );
    free_memory_view( view );
}

/* get information about a mapped image view */
DECL_HANDLER(get_image_view_info)
{
    struct process *process;
    struct memory_view *view;

    if (!(process = get_process_from_handle( req->process, PROCESS_QUERY_INFORMATION ))) return;

    if ((view = find_mapped_addr( process, req->addr )) && (view->flags & SEC_IMAGE))
    {
        reply->base = view->base;
        reply->size = view->size;
    }

    release_object( process );
}

/* get a range of committed pages in a file mapping */
DECL_HANDLER(get_mapping_committed_range)
{
    struct memory_view *view = find_mapped_view( current->process, req->base );

    if (view) reply->committed = find_committed_range( view, req->offset, &reply->size );
}

/* add a range to the committed pages in a file mapping */
DECL_HANDLER(add_mapping_committed_range)
{
    struct memory_view *view = find_mapped_view( current->process, req->base );

    if (view) add_committed_range( view, req->offset, req->offset + req->size );
}

/* check if two memory maps are for the same file */
DECL_HANDLER(is_same_mapping)
{
    struct memory_view *view1 = find_mapped_view( current->process, req->base1 );
    struct memory_view *view2 = find_mapped_view( current->process, req->base2 );

    if (!view1 || !view2) return;
    if (!view1->fd || !view2->fd || !(view1->flags & SEC_IMAGE) || !is_same_file_fd( view1->fd, view2->fd ))
        set_error( STATUS_NOT_SAME_DEVICE );
}

/* get the filename of a mapping */
DECL_HANDLER(get_mapping_filename)
{
    struct process *process;
    struct memory_view *view;
    struct unicode_str name;

    if (!(process = get_process_from_handle( req->process, PROCESS_QUERY_INFORMATION ))) return;

    if ((view = find_mapped_addr( process, req->addr )) && get_view_nt_name( view, &name ))
    {
        reply->len = name.len;
        if (name.len > get_reply_max_size()) set_error( STATUS_BUFFER_OVERFLOW );
        else if (!name.len) set_error( STATUS_FILE_INVALID );
        else set_reply_data( name.str, name.len );
    }
    else set_error( STATUS_INVALID_ADDRESS );

    release_object( process );
}
