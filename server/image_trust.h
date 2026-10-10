/* Offline image classification, owned by the server mapping module. */
#ifndef __WINE_SERVER_IMAGE_TRUST_H
#define __WINE_SERVER_IMAGE_TRUST_H

#define IMAGE_TRUST_MAX_IMAGE_BYTES (64ULL * 1024 * 1024)
#define IMAGE_TRUST_UNTRUSTED 0
#define IMAGE_TRUST_MICROSOFT 1
#define IMAGE_TRUST_PLATFORM 2

struct image_trust_info
{
    unsigned int publisher_class;
    unsigned int process_protection; /* exact LinuxNT process grant */
    unsigned int code_grants; /* bits 0..2 authorize code in profiles 41, 51, 61 */
};

/* Called once by the host startup path, before any client request. The digest
 * must come from the trusted host build, independently of the Windows prefix. */
extern int init_image_trust( int fd, const char *digest );
extern int image_trust_ready(void);
/* Classify only sealed full file bytes. Names, markers and client metadata
 * supply no authority. Zero means unknown, unavailable or expired. */
extern unsigned int classify_image_fd( int fd, unsigned short machine );
extern int hash_image_fd( int fd, unsigned char digest[32] );
extern struct image_trust_info classify_image_digest( const unsigned char digest[32], unsigned long long size,
                                                     unsigned short machine );
/* Grants are host policy, independent of publisher class. Legacy, untrusted
 * and expired entries supply no code authority. Recheck validity at mapping. */
extern int image_trust_allows_code( const struct image_trust_info *trust, unsigned int protection );

#endif
