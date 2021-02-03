#ifdef ZOFF

#ifndef _ZOFF_COMMON_H
#define _ZOFF_COMMON_H

#include <sys/types.h>
#include <sys/zfs_file.h>

#define ZOFF_OK       0
#define ZOFF_ERROR    1    /* something bad happened not related to missing functionality */
#define ZOFF_FALLBACK 2    /* error, fallback to zfs implementation */

/*
   This struct is normally set with "zfs set zoff_*=on/off" and passed
   around in zio_t.

   The variables are ints instead of boolean_ts to allow for them to
   be distinguished between being set by "zfs set" and being hardcoded
   in the code.
*/
typedef struct zoff_prop {
	int checksum;
	int compress;
	int decompress;
	int raidz1_gen;
	int raidz2_gen;
	int raidz3_gen;
	int raidz1_rec;
	int raidz2_rec;
	int raidz3_rec;
} zoff_prop_t;

#endif

#endif
