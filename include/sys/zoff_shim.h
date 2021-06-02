#ifdef ZOFF

#ifndef _ZOFF_SHIM_H
#define _ZOFF_SHIM_H

#ifdef _KERNEL
#include <linux/types.h>
#else
#include <stdint.h>

struct block_device;
#endif

#include <sys/abd.h>
#include <sys/abd_impl.h>
#include <sys/spa.h>
#include <sys/types.h>
#include <sys/zfs_file.h>
#include <sys/zio.h>
#include <sys/zio_bad_cksum.h>
#include <sys/zio_checksum_enums.h>
#include <sys/zio_compress_enums.h>
#include <sys/zoff_common.h>

typedef struct objset objset_t;
typedef struct raidz_row raidz_row_t;

/*
   This struct is normally set with "zfs set zoff_*=on/off/<value>"
   and passed around in zio_t.

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

/* set up some variables that need to be available before everything else */
extern void zoff_init(void);
extern void zoff_fini(void);

extern void zoff_on(objset_t *os, const char *name);
extern void zoff_off(objset_t *os, const char *name);
extern boolean_t zoff_usable(void);                     /* whether or not ZOFF is usable, if it is enabled */

extern boolean_t zoff_is_offloaded(void *ptr);          /* check if a handle is associated with this pointer */

/* create a mapping between a key and an offloader handle without copying data */
extern int zoff_alloc(void *key, size_t size);
extern int zoff_create_ref(void *ref_key, void *src_key, size_t offset, size_t size);
extern void zoff_free(void *key);

/* additional functions that would normally be defined in abd.h */
extern void abd_free_zoff(abd_t *abd);                  /* deallocate abd's zoff handle without onloading */

/* move data between from the offloader to memory */
/* zoff_offload is not needed for now */
extern int zoff_onload(void *key, void *buf, size_t size);

/* move bp->blk_cksum */
extern int zoff_offload_bp(blkptr_t *bp);
extern int zoff_onload_bp(blkptr_t *bp);

/* calls abd_iterate_func on the abd to copy abd data back and forth */
extern void *zoff_offload_abd(abd_t *abd, size_t size);
extern int zoff_onload_abd(abd_t *abd, size_t size);

/* raidz */
extern void zoff_lock_raidz(void);
extern void zoff_unlock_raidz(void);
extern int zoff_alloc_raidz(zio_t *zio, raidz_row_t *rr);
extern int zoff_cleanup_raidz(zio_t *zio, raidz_row_t *rr);
extern int zoff_onload_raidz(zio_t *zio, raidz_row_t *rr, boolean_t remove);
extern int zoff_free_raidz(raidz_row_t *rr);

/* remap an offloader buffer */
extern int zoff_change_key(void *dst, void *src);

/* fill a buffer with zeros */
extern int zoff_zero_fill(void *key, size_t offset, size_t size);

/* check if the offloader buffer is all zeros */
extern boolean_t zoff_all_zeros(void *key);

extern int zoff_checksum_compute(abd_t *abd, enum zio_checksum alg, zio_byteorder_t order,
    uint64_t size, blkptr_t *bp,
    boolean_t handle_crypt, boolean_t insecure);
extern int zoff_checksum_error(zoff_prop_t *zoff, enum zio_checksum alg, zio_byteorder_t order,
    abd_t *abd, uint64_t size, const blkptr_t *bp,
    int encrypted, int dedup, zio_bad_cksum_t *info);

extern int zoff_compress(enum zio_compress c, abd_t *src,
    void *cbuf, size_t s_len, uint8_t level,
    uint64_t *c_len, uint64_t spa_min_alloc);

// extern int zoff_decompress(zoff_prop_t *zoff, enum zio_compress c,
//     abd_t *src, abd_t *dst,
//     int level,
//     int *status);

extern int zoff_raidz_gen(zio_t *zio, raidz_row_t *rr);

// extern int zoff_raidz_rec(zoff_prop_t *zoff, struct raidz_row *rr,
//     const int *parity_valid, const int *dt, const int nbaddata);

/* vdev_file sometimes writes gangs */
extern int zoff_create_gang(abd_t *gang);

extern int zoff_write_file(zfs_file_t *dst, abd_t *abd, ssize_t size,
    loff_t offset, ssize_t *resid, int *err);
extern int zoff_write_disk(struct block_device *bdev, zio_t *zio,
    size_t io_size, uint64_t io_offset, int rw,
    int failfast, int flags);

#endif

#endif
