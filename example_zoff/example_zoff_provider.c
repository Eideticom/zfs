/*
  A ZOFF provider translates ZOFF and offloader data and functions.
  Access to the provider should be presented as a kernel module that
  can be loaded after ZFS. The module's init function should call
  zoff_init to provide a set of functions to ZOFF, and to allow for
  ZOFF to check the sanity of the provided functions. Implementations
  should be able appropriately handle events where the offloader is no
  longer available (e.g. hardware failure) so that ZFS remains
  operational, if in a degraded state.

  This example provider links the "kernel offloader" offloader to
  ZOFF. This provider does not have direct access to the offloader
  memory, but can call the functions the offloader API exposes.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

/* normal ZOFF includes */
#include <kernel_offloader.h> /* provides access to the actual offloader */
#include <sys/zoff.h>         /* the ZOFF API */

static int translate_rc(const int offloader_rc) {
	int zoff_rc = ZOFF_FALLBACK;
	switch (offloader_rc) {
		case KERNEL_OFFLOADER_OK:
			zoff_rc = ZOFF_OK;
			break;
		case KERNEL_OFFLOADER_ERROR:
		case KERNEL_OFFLOADER_BAD_RESULT:
			zoff_rc = ZOFF_ERROR;
			break;
		case KERNEL_OFFLOADER_UNAVAILABLE:
		default:
			zoff_rc = ZOFF_FALLBACK;
			break;
	}
	return zoff_rc;
}

static int example_copy_from_kern(zmv_t *mv, void *buf, size_t size) {
	return kernel_offloader_copy_from_kern(mv->handle, mv->offset, buf, size)?ZOFF_OK:ZOFF_ERROR;
}

static int example_copy_to_kern(zmv_t *mv, void *buf, size_t size) {
	return kernel_offloader_copy_to_kern(mv->handle, mv->offset, buf, size)?ZOFF_OK:ZOFF_ERROR;
}

static int example_copy_internal(zmv_t *dst, zmv_t *src, size_t size) {
	const int rc = kernel_offloader_copy_internal(dst->handle, dst->offset,
	    src->handle, src->offset,
	    size);

	if (rc == KERNEL_OFFLOADER_OK) {
		dst->offset += size;
	}

	return translate_rc(rc);
}

static int example_zero_fill(void *handle, size_t offset, size_t size) {
	return translate_rc(kernel_offloader_zero_fill(handle, offset, size));
}

static int example_all_zeros(void *handle) {
	return translate_rc(kernel_offloader_all_zeros(handle));
}

static int example_gang_add(void *gang_handle, void *new_member_handle) {
	return translate_rc(kernel_offloader_gang_add(gang_handle, new_member_handle));
}

static int example_checksum_compute(enum zio_checksum alg, zio_byteorder_t order,
    void *abd, size_t size, void *cksum, int handle_crypt, int insecure) {
	/* maybe translate alg and order */

	/* trigger offloader to do actual calculation */
	return translate_rc(kernel_offloader_checksum_compute(alg, order, abd, size, cksum, handle_crypt, insecure));
}

static int example_checksum_error(enum zio_checksum alg, zio_byteorder_t order,
    void *abd, void *cksum,
    int encrypted, int dedup,
    void *zbc_expected, void *zbc_actual,
    void *zbc_checksum_name) {
	/* maybe translate alg and order */

	/* trigger offloader to do actual calculation */
	return translate_rc(kernel_offloader_checksum_error(alg, order, abd, cksum,
	    encrypted, dedup,
	    zbc_expected, zbc_actual,
	    zbc_checksum_name));
}

static int example_compress(enum zio_compress alg,
    void *src, void *dst, size_t s_len, int level,
    uint64_t spa_min_alloc, zcr_t *zoff_ret) {
	/* buffer that offloader fills out */
	void *kz_ret_handle = kernel_offloader_alloc(sizeof(kocr_t));

	const int kz_rc = kernel_offloader_compress(alg, src, dst, s_len, level, spa_min_alloc, kz_ret_handle);
	if (kz_rc == KERNEL_OFFLOADER_OK) {
		/* provider doesn't have direct access to the offloader's data */
		kocr_t kz_ret;
		kernel_offloader_copy_to_kern(kz_ret_handle, 0, &kz_ret, sizeof(kz_ret));

		/* translate offloader extra return values to zoff return values */
		zoff_ret->c_len = kz_ret.c_len;
	}

	kernel_offloader_free(kz_ret_handle);

	return translate_rc(kz_rc);
}

static int example_decompress(enum zio_compress alg,
    void *src, void *dst,
    int level) {
	return translate_rc(kernel_offloader_decompress(alg, src, dst, level));
}

int example_raidz_set_col(void *raidz, int c, void *col) {
	return translate_rc(kernel_offloader_set_col(raidz, c, col));
}

int example_raidz1_gen(void *handle) {
	return translate_rc(kernel_offloader_raidz1_gen(handle));
}

int example_raidz2_gen(void *handle) {
	return translate_rc(kernel_offloader_raidz2_gen(handle));
}

int example_raidz3_gen(void *handle) {
	return translate_rc(kernel_offloader_raidz3_gen(handle));
}

int example_write_file(zfs_file_t *fp, void *handle, size_t count,
    loff_t offset, ssize_t *resid, int *err) {
	return translate_rc(kernel_offloader_write_file(fp, handle, count,
	    offset, resid, err));
}

int example_write_disk(struct block_device *bdev, void *handle,
    size_t io_size, uint64_t io_offset, int rw,
    int failfast, int flags, void *zio) {
	return translate_rc(kernel_offloader_write_disk(bdev, handle,
	    io_size, io_offset, rw,
	    failfast, flags, zio));
}

static const char name[] = "example_zoff";
static const zoff_functions_t example_zoff_functions = {
	.alloc                = kernel_offloader_alloc,
	.alloc_ref            = kernel_offloader_alloc_ref,
	.free                 = kernel_offloader_free,
	.copy_from_kern       = example_copy_from_kern,
	.copy_to_kern         = example_copy_to_kern,
	.copy_internal        = example_copy_internal,
	.zero_fill            = example_zero_fill,
	.all_zeros            = example_all_zeros,
	.gang                 = {
	                          .alloc = kernel_offloader_alloc_gang,
	                          .add = example_gang_add,
	                        },
	.checksum             = {
	                          .compute = example_checksum_compute,
	                          .error   = example_checksum_error,
	                        },
	.compress             = example_compress,
	.decompress           = example_decompress,
	.raid                 = {
	                          .alloc     = kernel_offloader_alloc_raidz,
	                          .set_col   = example_raidz_set_col,
	                          .free      = kernel_offloader_free_raidz,
	                          .gen       = {
	                                         .z1 = example_raidz1_gen,
	                                         .z2 = example_raidz2_gen,
	                                         .z3 = example_raidz3_gen,
	                                       },
	                          .rec       = {
	                                         .z1 = NULL,
	                                         .z2 = NULL,
	                                         .z3 = NULL,
	                                       },
	                        },
	.write                = {
	                          .file = example_write_file,
	                          .disk = example_write_disk,
	                        },
};

static int __init example_zoff_init(void) {
	kernel_offloader_init(); /* this should be a separate kernel module, but is here for simplicity */
	return zoff_provider_init(name, &example_zoff_functions);
}

static void __exit example_zoff_exit(void) {
	zoff_provider_exit(name);
}

module_init(example_zoff_init);
module_exit(example_zoff_exit);

MODULE_LICENSE("");
