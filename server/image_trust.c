/* Bind sealed mapping bytes to an independently host-pinned offline catalog.
 * This module does no network or Authenticode work in the server event loop. */
#include "config.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef SONAME_LIBGNUTLS
# include <gnutls/crypto.h>
#endif
#include "image_trust.h"

#define HEADER_BYTES 64
#define ENTRY_BYTES 48
#define MAX_ENTRIES 4096

static unsigned char *catalog;
static unsigned int entry_count;
static unsigned long long valid_from, valid_until;
#ifdef SONAME_LIBGNUTLS
static void *crypto_module;
static typeof(gnutls_global_init) *p_global_init;
static typeof(gnutls_hash_init) *p_hash_init;
static typeof(gnutls_hash) *p_hash;
static typeof(gnutls_hash_deinit) *p_hash_deinit;

static int init_hash(void)
{
    if (crypto_module) return 1;
    if (!(crypto_module = dlopen( SONAME_LIBGNUTLS, RTLD_NOW | RTLD_LOCAL ))) return 0;
    if (!(p_global_init = dlsym( crypto_module, "gnutls_global_init" )) ||
        !(p_hash_init = dlsym( crypto_module, "gnutls_hash_init" )) ||
        !(p_hash = dlsym( crypto_module, "gnutls_hash" )) ||
        !(p_hash_deinit = dlsym( crypto_module, "gnutls_hash_deinit" )) || p_global_init() < 0)
    {
        dlclose( crypto_module );
        crypto_module = NULL;
        return 0;
    }
    return 1;
}
#endif

static unsigned int read_u32( const unsigned char *p )
{
    return (unsigned int)p[0] | (unsigned int)p[1] << 8 |
           (unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
}

static unsigned long long read_u64( const unsigned char *p )
{
    return (unsigned long long)read_u32( p ) | (unsigned long long)read_u32( p + 4 ) << 32;
}

static int sealed_size( int fd, unsigned long long maximum, unsigned long long *size )
{
#ifdef F_GET_SEALS
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat st;
    int seals;
    if (fstat( fd, &st ) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (unsigned long long)st.st_size > maximum ||
        (seals = fcntl( fd, F_GET_SEALS )) == -1 || (seals & required) != required) return 0;
    *size = st.st_size;
    return 1;
#else
    return 0;
#endif
}

/* Read only sealed, size-bounded memory files; never hash a mutable source. */
static int hash_fd( int fd, unsigned long long size, unsigned char digest[32], unsigned char *copy )
{
#ifdef SONAME_LIBGNUTLS
    gnutls_hash_hd_t hash;
    unsigned char buffer[65536];
    unsigned long long offset = 0;
    if (!init_hash() || p_hash_init( &hash, GNUTLS_DIG_SHA256 ) < 0) return 0;
    while (offset < size)
    {
        ssize_t count;
        size_t length = size - offset < sizeof(buffer) ? size - offset : sizeof(buffer);
        do count = pread( fd, buffer, length, offset ); while (count == -1 && errno == EINTR);
        if (count <= 0 || p_hash( hash, buffer, count ) < 0)
        {
            p_hash_deinit( hash, NULL );
            return 0;
        }
        if (copy) memcpy( copy + offset, buffer, count );
        offset += count;
    }
    p_hash_deinit( hash, digest );
    return 1;
#else
    return 0;
#endif
}

int image_trust_ready(void)
{
    time_t now = time( NULL );
    return catalog && now >= 0 && (unsigned long long)now >= valid_from &&
           (unsigned long long)now < valid_until;
}

int init_image_trust( int fd, const char *pin )
{
    unsigned long long size, start, end;
    unsigned char digest[32], expected[32], *bytes;
    unsigned int count, i;
    time_t now = time( NULL );

    if (catalog || strlen( pin ) != 64 ||
        !sealed_size( fd, HEADER_BYTES + MAX_ENTRIES * ENTRY_BYTES, &size ) || size < HEADER_BYTES)
        return 0;
    for (i = 0; i < 32; ++i)
    {
        unsigned int j, value = 0;
        for (j = 0; j < 2; ++j)
        {
            unsigned char c = pin[2 * i + j];
            if (c >= '0' && c <= '9') value = value * 16 + c - '0';
            else if (c >= 'a' && c <= 'f') value = value * 16 + c - 'a' + 10;
            else return 0;
        }
        expected[i] = value;
    }
    if (!(bytes = malloc( size ))) return 0;
    if (!hash_fd( fd, size, digest, bytes ) || memcmp( digest, expected, 32 ) ||
        memcmp( bytes, "LNTICT02", 8 ) || read_u32( bytes + 8 ) != 2) goto invalid;
    count = read_u32( bytes + 12 );
    start = read_u64( bytes + 16 );
    end = read_u64( bytes + 24 );
    if (!count || count > MAX_ENTRIES || size != HEADER_BYTES + count * ENTRY_BYTES ||
        now < 0 || start > (unsigned long long)now || (unsigned long long)now >= end) goto invalid;
    for (i = 0; i < count; ++i)
    {
        const unsigned char *entry = bytes + HEADER_BYTES + i * ENTRY_BYTES;
        unsigned long long image_size = read_u64( entry + 32 );
        unsigned int machine = read_u32( entry + 40 ), kind = read_u32( entry + 44 );
        if (!image_size || image_size > IMAGE_TRUST_MAX_IMAGE_BYTES ||
            (machine != 0x14c && machine != 0x8664) ||
            (kind != IMAGE_TRUST_MICROSOFT && kind != IMAGE_TRUST_PLATFORM) ||
            (i && memcmp( entry - ENTRY_BYTES, entry, 32 ) >= 0)) goto invalid;
    }
    catalog = bytes;
    entry_count = count;
    valid_from = start;
    valid_until = end;
    return 1;
invalid:
    free( bytes );
    return 0;
}

int hash_image_fd( int fd, unsigned char digest[32] )
{
    unsigned long long size;
    return sealed_size( fd, IMAGE_TRUST_MAX_IMAGE_BYTES, &size ) && hash_fd( fd, size, digest, NULL );
}

unsigned int classify_image_digest( const unsigned char digest[32], unsigned long long size,
                                   unsigned short machine )
{
    unsigned int low = 0, high = entry_count;
    if (!image_trust_ready()) return IMAGE_TRUST_UNTRUSTED;
    while (low < high)
    {
        unsigned int middle = low + (high - low) / 2;
        const unsigned char *entry = catalog + HEADER_BYTES + middle * ENTRY_BYTES;
        int order = memcmp( digest, entry, 32 );
        if (order < 0) high = middle;
        else if (order > 0) low = middle + 1;
        else return read_u64( entry + 32 ) == size && read_u32( entry + 40 ) == machine ?
                    read_u32( entry + 44 ) : IMAGE_TRUST_UNTRUSTED;
    }
    return IMAGE_TRUST_UNTRUSTED;
}

unsigned int classify_image_fd( int fd, unsigned short machine )
{
    unsigned char digest[32];
    unsigned long long size;
    if (!image_trust_ready() || !sealed_size( fd, IMAGE_TRUST_MAX_IMAGE_BYTES, &size ) ||
        !hash_fd( fd, size, digest, NULL )) return IMAGE_TRUST_UNTRUSTED;
    return classify_image_digest( digest, size, machine );
}
