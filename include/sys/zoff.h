#ifdef ZOFF

#ifndef _ZOFF_H
#define _ZOFF_H

#include <stddef.h>

#ifdef _KERNEL
#include <linux/types.h>
#else
#include <stdint.h>

struct block_device;
#endif

#include <sys/zfs_file.h>
#include <sys/zio_checksum_enums.h>
#include <sys/zio_compress_enums.h>
#include <sys/zoff_common.h>

/*
   use this struct to copy data to and from offloader memory

   passing explicit offset because handle could be anything
   so ((char *) handle) + offset probably won't make sense
*/
typedef struct zoff_move {
	void *handle;
	size_t offset;
} zmv_t;

/* provider should translate offloader return struct to this struct */
typedef struct zoff_compress_ret {
	size_t c_len;
} zcr_t;

/* signatures of functions that the provider should implement */
typedef struct zoff_functions {
	/*
	   required
	*/

	void *(*alloc)(size_t size);                               /* get a new offloader handle */
	void *(*alloc_ref)(void *src_handle,
	    size_t size, size_t offset);                           /* get a reference to an existing offloader handle */
	void (*free)(void *handle);                                /* free an offloader handle */

	int (*copy_from_mem)(zmv_t *mv, void *buf, size_t size);   /* memory buf -> offloader  */
	int (*copy_to_mem)(zmv_t *mv, void *buf, size_t size);     /* offloader  -> memory buf */
	int (*copy_internal)(zmv_t *dst, zmv_t *src, size_t size); /* offloader  -> offloader  */

	int (*zero_fill)(void *handle, size_t offset, size_t size);
	int (*all_zeros)(void *handle);                            /* whether or not a buffer is all zeros */

	/* used for vdev_file write */
	struct {
		void *(*alloc)(size_t max);
		int (*add)(void *gang_handle, void *new_member_handle);
	} gang;

	/*
	   optional
	*/

	struct {
		int (*compute)(enum zio_checksum alg, zio_byteorder_t order,
		    void *abd, size_t size, void *cksum, int handle_crypt, int insecure);

		int (*error)(enum zio_checksum alg, zio_byteorder_t order,
		    void *abd, void *cksum,
		    int encrypted, int dedup,
		    void *zbc_expected, void *zbc_actual,
		    void *zbc_checksum_name);
	} checksum;

	int (*compress)(enum zio_compress alg,
	    void *src, void *dst,
	    size_t s_len, int level,
	    uint64_t spa_min_alloc, zcr_t *zoff_ret);

	int (*decompress)(enum zio_compress alg,
	    void *src, void *dst,
	    int level);

	struct {
		void *(*alloc)(size_t raidn, size_t acols);
		int (*set_col)(void *raidz, int c, void *col);
		void (*free)(void *raidz);

		/* Erasure Code Generation */
		/* These functions should process an entire row, not individual columns */
		struct {
			int (*z1)(void *handle);
			int (*z2)(void *handle);
			int (*z3)(void *handle);
		} gen;

		/* Erasure Code Reconstruction */
		/* These functions should process an entire row, not individual columns */
		struct {
			int (*z1)(void *ptr);
			int (*z2)(void *ptr);
			int (*z3)(void *ptr);
		} rec;

	} raid;

	struct {
		int (*file)(zfs_file_t *dst, void *handle, size_t size,
		    loff_t offset, ssize_t *resid, int *err);
		int (*disk)(struct block_device *bdev, void *handle,
		    size_t io_size, uint64_t io_offset, int rw,
            int failfast, int flags,
            void *zio);
	} write;
} zoff_functions_t;

/* call in provider's init */
extern int zoff_provider_init(const char *name, const zoff_functions_t *provider);

/* call in provider's exit */
extern void zoff_provider_exit(const char *name);

#ifdef _KERNEL

/* called by offloader's disk write - not implemented by offloader */
extern void zoff_disk_write_completion(void *zio_ptr, int error);

#endif

#endif

#endif
