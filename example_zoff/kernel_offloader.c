#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/zlib.h>

/* Need stuff from zfs_fletcher.h */
#include <zfs_fletcher.h>

/* Not including sys/zio_compresss.h because it would bring in abds */
extern int z_compress_level(void *dest, size_t *destLen, const void *source,
    size_t sourceLen, int level);
extern int z_uncompress(void *dest, size_t *destLen, const void *source,
    size_t sourceLen);

/* Example ZOFF Offloader headers */
#include "disk.h"
#include "kernel_offloader.h"
#include "private.h"
#include "raidz.h"

static const char NAME[] = "KERNEL OFFLOADER";
static const size_t NAME_LEN = sizeof (NAME);

/*
 * value used to swizzle the pointer so that
 * dereferencing the handle will fail
 */
static void *mask = NULL;
void
kernel_offloader_init(void)
{
	get_random_bytes(&mask, sizeof (mask));
	printk("kernel offloader init: %p\n", mask);
}

/* get a starting address of a linear koh_t */
void *
ptr_start(koh_t *koh, size_t offset)
{
	return (void *)(((uintptr_t)LINEAR(koh).ptr) + offset);
}

/*
 * convert the actual pointer to a handle (pretend
 * the data is not accessible from the ZOFF base)
 */
void *
swizzle(void *ptr)
{
	return (ptr?((void *)(((uintptr_t)ptr) ^ ((uintptr_t)mask))):NULL);
}

/* convert the handle to a usable pointer */
void *
unswizzle(void *handle)
{
	return (swizzle(handle));
}

/*
 * not usually needed - buffers should almost
 * always be KOH_REAL or KOH_REFERENCE
 */
int
koh_is_linear(koh_t *koh)
{
	return ((koh->type == KOH_REAL) ||
	    (koh->type == KOH_REFERENCE));
}

int
koh_is_gang(koh_t *koh)
{
	return (koh->type == KOH_GANG);
}

koh_t *
koh_alloc(size_t size)
{
	koh_t *koh = kmalloc(sizeof (koh_t), GFP_KERNEL);
	if (koh) {
		koh->type = KOH_REAL;
		LINEAR(koh).ptr = kmalloc(size, GFP_KERNEL);
		LINEAR(koh).size = size;

		memset(ptr_start(koh, 0), 0, LINEAR(koh).size);
	}

	return (koh);
}

static koh_t *
kernel_offloader_alloc_local_ref(koh_t *src,
    size_t offset, size_t size)
{
	koh_t *ref = NULL;
	if (src) {
		ref = kmalloc(sizeof (koh_t), GFP_KERNEL);
		if (ref) {
			ref->type = KOH_REFERENCE;

			/* same underlying buffer */
			LINEAR(ref).ptr = ptr_start(src, offset);

			/* should probably check offset + size < src->size */
			LINEAR(ref).size = size;
		}
	}

	return (ref);
}

void
koh_free(koh_t *koh)
{
	if (koh) {
		switch (koh->type) {
			case KOH_REAL:
				kfree(LINEAR(koh).ptr);
				break;
			case KOH_REFERENCE:
				break;
			case KOH_GANG:
				kfree(GANG(koh).members);
				break;
			case KOH_INVALID:
			default:
				break;
		}

		kfree(koh);
	}
}

void *
kernel_offloader_alloc(size_t size)
{
	return (swizzle(koh_alloc(size)));
}

void *
kernel_offloader_alloc_ref(void *src_handle, size_t offset, size_t size)
{
	return swizzle(kernel_offloader_alloc_local_ref(unswizzle(src_handle),
	    offset, size));
}

void
kernel_offloader_free(void *handle)
{
	koh_free(unswizzle(handle));
}

void *
kernel_offloader_copy_from_mem(void *handle, size_t offset,
    void *src, size_t size)
{
	koh_t *koh = unswizzle(handle);
	if (!koh) {
		return (NULL);
	}

	if (!koh_is_linear(koh)) {
		return (NULL);
	}

	if ((offset + size) > LINEAR(koh).size) {
		return (NULL);
	}

	return (memcpy(ptr_start(koh, offset), src, size));
}

void *
kernel_offloader_copy_to_mem(void *handle, size_t offset,
    void *dst, size_t size)
{
	koh_t *koh = unswizzle(handle);
	if (!koh) {
		return (NULL);
	}

	if (!koh_is_linear(koh)) {
		return (NULL);
	}

	if ((offset + size) > LINEAR(koh).size) {
		return (NULL);
	}

	return (memcpy(dst, ptr_start(koh, offset), size));
}

int
kernel_offloader_zero_fill(void *handle, size_t offset, size_t size)
{
	koh_t *koh = unswizzle(handle);
	memset(ptr_start(koh, offset), 0, size);
	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_all_zeros(void *handle)
{
	koh_t *koh = unswizzle(handle);
	uint64_t *array = ptr_start(koh, 0);
	size_t i;
	for (i = 0; i < LINEAR(koh).size / sizeof (uint64_t); i++) {
		if (array[i]) {
			return (KERNEL_OFFLOADER_BAD_RESULT);
		}
	}

	return (KERNEL_OFFLOADER_OK);
}

void *
kernel_offloader_alloc_gang(size_t max)
{
	koh_t *koh = kmalloc(sizeof (koh_t), GFP_KERNEL);
	if (koh) {
		koh->type = KOH_GANG;
		GANG(koh).members = (koh_t **)kmalloc(
		    sizeof (koh_t *) * max, GFP_KERNEL);
		GANG(koh).count = 0;
		GANG(koh).max = max;
		GANG(koh).size = 0;
	}
	return (swizzle(koh));
}

int
kernel_offloader_gang_add(void *gang_handle, void *new_member_handle)
{
	koh_t *gang = unswizzle(gang_handle);
	koh_t *new_member = unswizzle(new_member_handle);

	if (GANG(gang).count >= GANG(gang).max) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	/* do not allow gangs in gangs */
	if (new_member->type == KOH_GANG) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	GANG(gang).members[GANG(gang).count] = new_member;
	GANG(gang).count++;
	GANG(gang).size += LINEAR(new_member).size;

	return (KERNEL_OFFLOADER_OK);
}

/* specific implementation */
static int
kernel_offloader_gzip_compress(koh_t *src, koh_t *dst,
    size_t s_len, int level, size_t *c_len)
{
	*c_len = LINEAR(dst).size;

	if (z_compress_level(ptr_start(dst, 0), c_len, ptr_start(src, 0),
	    s_len, level) != Z_OK) {
		if (*c_len != LINEAR(src).size) {
			return (KERNEL_OFFLOADER_ERROR);
		}
		return (KERNEL_OFFLOADER_OK);
	}

	return (KERNEL_OFFLOADER_OK);
}

/* specific implementation */
static int
kernel_offloader_gzip_decompress(koh_t *src, koh_t *dst,
    int level, size_t *c_len)
{
	if (z_uncompress(ptr_start(dst, 0), c_len, ptr_start(src, 0),
	    LINEAR(src).size) != Z_OK) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_compress(enum zio_compress alg,
    void *src, void *dst, size_t s_len, int level,
    uint64_t spa_min_alloc, void *ret)
{
	int status = KERNEL_OFFLOADER_UNAVAILABLE;
	koh_t *src_koh = NULL;
	koh_t *dst_koh = NULL;
	koh_t *ret_koh = NULL;
	kocr_t *ret_kzcr = NULL;
	if (!src || !dst || !ret) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	src_koh = unswizzle(src);
	dst_koh = unswizzle(dst);
	ret_koh = unswizzle(ret);
	ret_kzcr = (kocr_t *)ptr_start(ret_koh, 0);

	if ((ZIO_COMPRESS_GZIP_1 <= alg) &&
	    (alg <= ZIO_COMPRESS_GZIP_9)) {
		status = kernel_offloader_gzip_compress(src_koh, dst_koh, s_len,
		    level, &ret_kzcr->c_len);
	}

	return (status);
}

int
kernel_offloader_decompress(enum zio_compress alg,
    void *src, void *dst, int level)
{
	int status = KERNEL_OFFLOADER_UNAVAILABLE;
	koh_t *src_koh = unswizzle(src);
	koh_t *dst_koh = unswizzle(dst);

	size_t d_len = 0;

	if ((ZIO_COMPRESS_GZIP_1 <= alg) &&
	    (alg <= ZIO_COMPRESS_GZIP_9)) {
		status = kernel_offloader_gzip_decompress(src_koh, dst_koh,
		    level, &d_len);
	}

	return (status);
}

/* copied from module/zcommon/zfs_fletcher.c */
static void
fletcher_4_scalar_native(fletcher_4_ctx_t *ctx, const void *buf,
    uint64_t size)
{
	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;

	a = ctx->scalar.zc_word[0];
	b = ctx->scalar.zc_word[1];
	c = ctx->scalar.zc_word[2];
	d = ctx->scalar.zc_word[3];

	for (; ip < ipend; ip++) {
		a += ip[0];
		b += a;
		c += b;
		d += c;
	}

	ZIO_SET_CHECKSUM(&ctx->scalar, a, b, c, d);
}

/* specific implementation */
static int
kernel_offloader_checksum_native(koh_t *data, size_t size,
    uint64_t *checksum)
{
	/*
	 * treat checksum as fletcher_4_ctx_t since scalar
	 * (zio_cksum_t) is the first member of the struct
	 */
	fletcher_init((zio_cksum_t *)checksum);
	fletcher_4_scalar_native((fletcher_4_ctx_t *)checksum,
	    ptr_start(data, 0), size);
	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_checksum_compute(enum zio_checksum alg,
    zio_byteorder_t order, void *data, size_t size, void *bp_cksum)
{
	koh_t *bp_cksum_koh = unswizzle(bp_cksum);
	koh_t *data_koh = unswizzle(data);
	uint64_t cksum[4];
	uint64_t saved[4];

	/* only fletcher 4 is supported */
	if (alg != ZIO_CHECKSUM_FLETCHER_4) {
		return (KERNEL_OFFLOADER_UNAVAILABLE);
	}

	/* only native byte order is supported */
	if (order != ZIO_CHECKSUM_NATIVE) {
		return (KERNEL_OFFLOADER_UNAVAILABLE);
	}

	/* save old checksum */
	memcpy(saved, ptr_start(bp_cksum_koh, 0), sizeof (saved));

	/* compute checksum */
	if (kernel_offloader_checksum_native(data_koh, size,
	    cksum) != KERNEL_OFFLOADER_OK) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	/* copy checksum into bp */
	memcpy(ptr_start(bp_cksum_koh, 0), cksum, sizeof (cksum));

	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_checksum_error(enum zio_checksum alg,
    zio_byteorder_t order, void *data, void *bp_cksum,
    int encrypted, int dedup, void *zbc_expected,
    void *zbc_actual, void *zbc_checksum_name)
{
	koh_t *bp_cksum_koh = unswizzle(bp_cksum);
	koh_t *data_koh = unswizzle(data);
	koh_t *zbc_expected_koh = unswizzle(zbc_expected);
	koh_t *zbc_actual_koh = unswizzle(zbc_actual);
	koh_t *zbc_checksum_name_koh = unswizzle(zbc_checksum_name);
	uint64_t expected_cksum[4];
	uint64_t actual_cksum[4];

	/* only fletcher 4 is supported */
	if (alg != ZIO_CHECKSUM_FLETCHER_4) {
		return (KERNEL_OFFLOADER_UNAVAILABLE);
	}

	/* only native byte order is supported */
	if (order != ZIO_CHECKSUM_NATIVE) {
		return (KERNEL_OFFLOADER_UNAVAILABLE);
	}

	memcpy(expected_cksum, ptr_start(bp_cksum_koh, 0),
	    sizeof (expected_cksum));

	/* compute checksum */
	/* TODO: LINEAR(data_koh).size is probably wrong */
	if (kernel_offloader_checksum_native(data_koh,
	    LINEAR(data_koh).size, actual_cksum) != KERNEL_OFFLOADER_OK) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	/*
	 * MAC checksums are a special case since half of this checksum will
	 * actually be the encryption MAC. This will be verified by the
	 * decryption process, so we just check the truncated checksum now.
	 * Objset blocks use embedded MACs so we don't truncate the checksum
	 * for them.
	 */
	if (encrypted) {
		if (!dedup) {
			actual_cksum[0] ^= actual_cksum[2];
			actual_cksum[1] ^= actual_cksum[3];
		}

		actual_cksum[2] = 0;
		actual_cksum[3] = 0;
		expected_cksum[2] = 0;
		expected_cksum[3] = 0;
	}

	if (zbc_expected_koh) {
		memcpy(ptr_start(zbc_expected_koh, 0), expected_cksum,
		    sizeof (expected_cksum));
	}

	if (zbc_actual_koh) {
		memcpy(ptr_start(zbc_actual_koh, 0), actual_cksum,
		    sizeof (actual_cksum));
	}

	if (zbc_checksum_name_koh) {
		memcpy(ptr_start(zbc_checksum_name_koh, 0), NAME, NAME_LEN);
	}

	if (memcmp(actual_cksum, expected_cksum, sizeof (expected_cksum))) {
		return (KERNEL_OFFLOADER_BAD_RESULT);
	}

	return (KERNEL_OFFLOADER_OK);
}

/* allocates a korz_t, but doesn't have column information yet */
void *
kernel_offloader_alloc_raidz(size_t raidn, size_t acols)
{
	korz_t *korz = kmalloc(sizeof (korz_t), GFP_KERNEL);
	if (korz) {
		const size_t size = acols * sizeof (koh_t *);
		korz->raidn = raidn;
		korz->acols = acols;
		korz->cols = kmalloc(size, GFP_KERNEL);
		memset(korz->cols, 0, size);
	}

	return (swizzle(korz));
}

/* attaches a (reference) column to the raidz */
int
kernel_offloader_set_col(void *raidz, int c, void *col)
{
	korz_t *korz = (korz_t *)unswizzle(raidz);
	koh_t *koh = (koh_t *)unswizzle(col);

	if (!korz || !koh) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	/* c is too big */
	if (c >= korz->acols) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	/* parity column */
	if (c < korz->raidn) {
		/* needs to be a real allocation */
		if (koh->type != KOH_REAL) {
			return (KERNEL_OFFLOADER_ERROR);
		}
	}
	/* data column */
	else {
		/* needs to be a reference */
		if (koh->type != KOH_REFERENCE) {
			return (KERNEL_OFFLOADER_ERROR);
		}
	}

	korz->cols[c] = koh;

	return (KERNEL_OFFLOADER_OK);
}

void
kernel_offloader_free_raidz(void *raidz)
{
	korz_t *korz = (korz_t *)unswizzle(raidz);
	if (korz) {
		kfree(korz->cols);
		kfree(korz);
	}
}

int
kernel_offloader_raidz1_gen(void *raidz)
{
	vdev_raidz_generate_parity_p(unswizzle(raidz));
	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_raidz2_gen(void *raidz)
{
	vdev_raidz_generate_parity_pq(unswizzle(raidz));
	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_raidz3_gen(void *raidz)
{
	vdev_raidz_generate_parity_pqr(unswizzle(raidz));
	return (KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_write_file(zfs_file_t *fp, void *handle, size_t count,
    loff_t offset, ssize_t *resid, int *err)
{
	koh_t *koh = (koh_t *)unswizzle(handle);
	if (!koh) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	if (!err) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	*err = 0;

	if (koh_is_linear(koh)) {
		*err = zfs_file_pwrite(fp, ptr_start(koh, 0),
		    count, offset, resid);
	} else if (koh->type == KOH_GANG) {
		/*
		 * write abds sequentially instead of serializing
		 * into a single buffer first
		 */
		for (size_t i = 0; !*err && (i < GANG(koh).count); i++) {
			*err = zfs_file_pwrite(fp,
			    ptr_start(GANG(koh).members[i], 0),
			    LINEAR(GANG(koh).members[i]).size,
			    offset, resid);
			offset += LINEAR(GANG(koh).members[i]).size;
		}

		/*
		 * might want to check that the amount
		 * of data written is the same as count
		 */
	}

	return ((*err)?KERNEL_OFFLOADER_BAD_RESULT:KERNEL_OFFLOADER_OK);
}

int
kernel_offloader_write_disk(struct block_device *bdev, void *handle,
    size_t io_size, uint64_t io_offset, int rw, int failfast, int flags,
    void *zio)
{
	koh_t *koh = (koh_t *)unswizzle(handle);
	if (!koh) {
		return (KERNEL_OFFLOADER_ERROR);
	}

	return kernel_offloader_vdev_disk_physio(bdev, koh,
	    io_size, io_offset, rw, failfast, flags, zio);
}
