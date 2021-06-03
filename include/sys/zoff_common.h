#ifdef ZOFF

#ifndef _ZOFF_COMMON_H
#define	_ZOFF_COMMON_H

#define	ZOFF_OK			0

/* something bad happened not related to missing functionality */
#define	ZOFF_ERROR		1

/* error, fallback to zfs implementation */
#define	ZOFF_FALLBACK   2

#endif

#endif
