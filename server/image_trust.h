/* Offline image classification, owned by the server mapping module. */
#ifndef __WINE_SERVER_IMAGE_TRUST_H
#define __WINE_SERVER_IMAGE_TRUST_H

#define IMAGE_TRUST_MAX_IMAGE_BYTES (64ULL * 1024 * 1024)
#define IMAGE_TRUST_UNTRUSTED 0
#define IMAGE_TRUST_MICROSOFT 1
#define IMAGE_TRUST_PLATFORM 2

/* Called once by the host startup path, before any client request. The digest
 * must come from the trusted host build, independently of the Windows prefix. */
extern int init_image_trust( int fd, const char *digest );
extern int image_trust_ready(void);
/* Classify only sealed full file bytes. Names, markers and client metadata
 * supply no authority. Zero means unknown, unavailable or expired. */
extern unsigned int classify_image_fd( int fd, unsigned short machine );

#endif
