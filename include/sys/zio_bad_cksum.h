#ifndef _SYS_ZIO_BAD_CKSUM_H
#define _SYS_ZIO_BAD_CKSUM_H

#include <sys/spa.h>

typedef struct zio_bad_cksum {
	zio_cksum_t		zbc_expected;
	zio_cksum_t		zbc_actual;
	const char		*zbc_checksum_name;
	uint8_t			zbc_byteswapped;
	uint8_t			zbc_injected;
	uint8_t			zbc_has_cksum;	/* expected/actual valid */
} zio_bad_cksum_t;

#endif
