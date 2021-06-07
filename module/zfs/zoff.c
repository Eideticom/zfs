#ifdef ZOFF

#include <sys/dmu_objset.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_raidz_impl.h>
#include <sys/zoff.h>
#include <sys/zoff_shim.h>

#ifdef _KERNEL
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#endif

#include "zoff_hash.h"

static const size_t BP_SIZE = sizeof (zio_cksum_t);

/* ************************************************************* */
/* initialized by zfs */

/* hash table mapping memory pointers to offloader handles */
/* lifetime is same as zfs */
static zhc_t ZOFF_HANDLES;

void
zoff_init(void)
{
	zoff_hash_context_init(&ZOFF_HANDLES);
}

void
zoff_fini(void)
{
	zoff_hash_context_destroy(&ZOFF_HANDLES);
}
/* ************************************************************* */

/* ************************************************************* */
/* initialized by provider */

/* global offloader functions */
static const zoff_functions_t *zoff_provider = NULL;
/* ************************************************************* */

/* check provider sanity */
static boolean_t
zoff_provider_sane(const zoff_functions_t *provider)
{
	const int required = (
	    provider &&
	    provider->alloc &&
	    provider->free &&
	    provider->copy_from_mem &&
	    provider->copy_to_mem &&
	    provider->copy_internal &&
	    provider->zero_fill &&
	    provider->all_zeros	&&
	    provider->gang.alloc &&
	    provider->gang.add);
	return ((required == 1)?B_TRUE:B_FALSE);
}

int
zoff_provider_init(const char *name, const zoff_functions_t *provider)
{
	if (zoff_provider_sane(provider) != B_TRUE) {
#ifdef _KERNEL
		printk("ZOFF Provider %s does not provide "
		    "a valid set of functions\n", name);
#endif
		return (ZOFF_ERROR);
	}

	zoff_provider = provider;

#ifdef _KERNEL
	printk("ZOFF Provider %s initialized\n", name);
#endif
	return (ZOFF_OK);
}

void
zoff_provider_exit(const char *name)
{
	zoff_provider = NULL;

#ifdef _KERNEL
	printk("ZOFF Provider %s exited\n", name);
#endif
}

void
zoff_on(objset_t *os, const char *name)
{
	os->os_encrypted = B_FALSE;
	os->os_dedup_verify = B_FALSE;
#ifdef _KERNEL
	printk("ZOFF %s enabled. Disabling "
	    "encryption and dedup_verify.\n", name);
#endif
}

void
zoff_off(objset_t *os, const char *name)
{
	memset(&os->os_zoff, 0, sizeof (os->os_zoff));
#ifdef _KERNEL
	printk("ZOFF disabled due to enabling of %s.\n", name);
#endif
}

boolean_t
zoff_usable(void)
{
	return (zoff_provider_sane(zoff_provider));
}

/* create a zhe with an offloader handle */
/* the data is not copied to the offloader */
static zhe_t *
create_zhe(void *key, size_t size)
{
	if (!zoff_provider) {
		return (NULL);
	}

	zhe_t *zhe = zhe_create(&ZOFF_HANDLES, key, B_FALSE);
	if (!zhe) {
		zhe_destroy(zhe);
		return (NULL);
	}

	if (size) {
		zhe->handle = zoff_provider->alloc(size);
	}

	/* do not register */

	return (zhe);
}

/* free both a zhe and an offloader handle */
/* the data is not copied back from the offloader */
static void
destroy_zhe(zhe_t *zhe)
{
	if (!zoff_provider) {
		return;
	}

	if (zhe) {
		/* do not unregister */
		zoff_provider->free(zhe->handle);
		zhe_destroy(zhe);
	}
}

/*
 * create a mapping between a key and an
 *  offloader handle without copying data
 */
int
zoff_alloc(void *key, size_t size)
{
	zoff_hash_context_write_lock(&ZOFF_HANDLES);

	zhe_t *zhe = create_zhe(key, size);
	if (!zhe) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	zoff_hash_register_offload(&ZOFF_HANDLES, zhe);
	zoff_hash_context_write_unlock(&ZOFF_HANDLES);

	return (ZOFF_OK);
}

/* create a new reference zhe and register it */
int
zoff_create_ref(void *ref_key, void *src_key, size_t offset, size_t size)
{
	zoff_hash_context_write_lock(&ZOFF_HANDLES);

	zhe_t *found = zoff_hash_find_mapping(&ZOFF_HANDLES, src_key);
	if (!found) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	/* zoff records this mapping as a reference */
	zhe_t *zhe = zhe_create(&ZOFF_HANDLES, ref_key, B_FALSE);
	if (!zhe) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	/* offloader creates a reference */
	zhe->handle = zoff_provider->alloc_ref(found->handle, offset, size);

	zoff_hash_register_offload(&ZOFF_HANDLES, zhe);

	zoff_hash_context_write_unlock(&ZOFF_HANDLES);
	return (ZOFF_OK);
}

/* find a mapping and free the offloader handle without onloading the data */
static void
zoff_free_private(void *key, boolean_t lock)
{
	if (lock == B_TRUE) {
		zoff_hash_context_write_lock(&ZOFF_HANDLES);
	}

	zhe_t *zhe = zoff_hash_find_and_remove(&ZOFF_HANDLES, key);

	if (lock == B_TRUE) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
	}

	destroy_zhe(zhe);
}

void
zoff_free(void *key)
{
	zoff_free_private(key, B_TRUE);
}

boolean_t
zoff_is_offloaded(void *ptr)
{
	zoff_hash_context_read_lock(&ZOFF_HANDLES);
	zhe_t *found = zoff_hash_find_mapping(&ZOFF_HANDLES, ptr);
	zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	return (found?B_TRUE:B_FALSE);
}

/* move data to the offloader and register the mapping */
static int
zoff_offload(void *key, void *buf, size_t size)
{
	if (!zoff_provider) {
		return (ZOFF_ERROR);
	}

	zoff_hash_context_write_lock(&ZOFF_HANDLES);

	zhe_t *zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, key);
	if (zhe) {
		/* already offloaded */
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_OK);
	}

	zhe = create_zhe(key, size);
	if (!zhe) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	zmv_t mv = { .handle = zhe->handle, .offset = 0 };
	if (zoff_provider->copy_from_mem(&mv, buf, size) != ZOFF_OK) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		destroy_zhe(zhe);
		return (ZOFF_ERROR);
	}

	/* record this mapping */
	zoff_hash_register_offload(&ZOFF_HANDLES, zhe);

	zoff_hash_context_write_unlock(&ZOFF_HANDLES);
	return (ZOFF_OK);
}

/* move data from the offloader and unregister the mapping */
int
zoff_onload(void *key, void *buf, size_t size)
{
	if (!zoff_provider) {
		return (ZOFF_ERROR);
	}

	zoff_hash_context_write_lock(&ZOFF_HANDLES);

	/* remove zhe from hash table, but do not deallocate */
	zhe_t *zhe = zoff_hash_find_and_remove(&ZOFF_HANDLES, key);
	if (!zhe) {
		/*
		 * either already onloaded or missing record
		 * either way can't do anything
		 */
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	zmv_t mv = { .handle = zhe->handle, .offset = 0 };
	const int rc = zoff_provider->copy_to_mem(&mv, buf, size);

	zoff_hash_context_write_unlock(&ZOFF_HANDLES);

	/*
	 * if success, no more need for zhe
	 * if failure, can't do anything with
	 * zhe in any case, so destroy it
	 */
	destroy_zhe(zhe);

	return (rc);
}

/* only offload blk_cksum */
int
zoff_offload_bp(blkptr_t *bp)
{
	return (zoff_offload(bp, &bp->blk_cksum, BP_SIZE));
}

/* only onload blk_cksum */
int
zoff_onload_bp(blkptr_t *bp)
{
	return (zoff_onload(bp, &bp->blk_cksum, BP_SIZE));
}

/* abd_iterate_func callback for moving data to the offloader */
static int
zoff_offload_cb(void *buf, size_t size, void *private)
{
	if (!zoff_provider) {
		return (ZOFF_ERROR);
	}

	if (zoff_provider->copy_from_mem(private, buf, size) != ZOFF_OK) {
		return (ZOFF_ERROR);
	}

	zmv_t *mv = (zmv_t *)private;
	mv->offset += size;
	return (0);
}

/* abd_iterate_func callback for moving data from the offloader */
static int
zoff_onload_cb(void *buf, size_t size, void *private)
{
	if (!zoff_provider) {
		return (ZOFF_ERROR);
	}

	if (zoff_provider->copy_to_mem(private, buf, size) != ZOFF_OK) {
		return (ZOFF_ERROR);
	}

	zmv_t *mv = (zmv_t *)private;
	mv->offset += size;
	return (0);
}

/* record a new abd -> zoff handle mapping */
void *
zoff_offload_abd(abd_t *abd, size_t size)
{
	if (!zoff_provider) {
		return (NULL);
	}

	if (!abd) {
		return (NULL);
	}

	zoff_hash_context_write_lock(&ZOFF_HANDLES);

	zhe_t *zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, abd);
	if (zhe) {
		/* already offloaded */
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (zhe);
	}

	zhe = create_zhe(abd, size);

	/* offload */
	zmv_t mv = { .handle = zhe->handle, .offset = 0 };
	if (abd_iterate_func(abd, 0, size, zoff_offload_cb, &mv) != 0) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		destroy_zhe(zhe);
		return (NULL);
	}

	/* record this mapping */
	zoff_hash_register_offload(&ZOFF_HANDLES, zhe);

	zoff_hash_context_write_unlock(&ZOFF_HANDLES);
	return (zhe);
}

/* move zoff buffer back into abd */
static int
zoff_onload_abd_private(abd_t *abd, size_t size,
    boolean_t lock, boolean_t remove)
{
	if (!zoff_provider) {
		return (ZOFF_FALLBACK);
	}

	if (!abd) {
		return (ZOFF_ERROR);
	}

	if (lock == B_TRUE) {
		zoff_hash_context_write_lock(&ZOFF_HANDLES);
	} else {
		zoff_hash_context_read_lock(&ZOFF_HANDLES);
	}

	zhe_t *zhe = NULL;
	if (remove == B_TRUE) {
		/* remove zhe from hash table, but do not deallocate */
		zhe = zoff_hash_find_and_remove(&ZOFF_HANDLES, abd);
	} else {
		/* find the zhe from hash table only */
		zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, abd);
	}

	if (!zhe) {
		/*
		 * either already onloaded or missing record
		 * either way can't do anything
		 */
		if (lock == B_TRUE) {
			zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		} else {
			zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		}
		return (ZOFF_ERROR);
	}

	/* onload */
	zmv_t mv = { .handle = zhe->handle, .offset = 0 };
	const int rc = abd_iterate_func(abd, 0, size, zoff_onload_cb, &mv);

	if (lock == B_TRUE) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
	} else {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	}

	if (remove) {
		/*
		 * if success, no more need for zhe
		 * if failure, can't do anything with
		 * zhe in any case, so destroy it
		 */
		destroy_zhe(zhe);
	}

	return ((rc == 0)?ZOFF_OK:ZOFF_ERROR);
}

int
zoff_onload_abd(abd_t *abd, size_t size)
{
	return (zoff_onload_abd_private(abd, size, B_TRUE, B_TRUE));
}

int
zoff_change_key(void *dst, void *src)
{
	zoff_hash_context_write_lock(&ZOFF_HANDLES);

	zhe_t *dst_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, dst);
	if (dst_zhe) {
		/* mapping already exists; don't overwrite */
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	/* remove the entry to prevent other threads from finding it */
	zhe_t *src_zhe = zoff_hash_find_and_remove(&ZOFF_HANDLES, src);
	if (!src_zhe) {
		/* previous mapping doesn't exist, so it can't be remapped */
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	/* replace the key */
	src_zhe->ptr = dst;
	zoff_hash_register_offload(&ZOFF_HANDLES, src_zhe);

	zoff_hash_context_write_unlock(&ZOFF_HANDLES);

	return (ZOFF_OK);
}

int
zoff_zero_fill(void *key, size_t offset, size_t size)
{
	if (!zoff_provider) {
		return (ZOFF_ERROR);
	}

	zoff_hash_context_read_lock(&ZOFF_HANDLES);
	zhe_t *zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, key);

	if (!zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_ERROR);
	}

	const int rc = zoff_provider->zero_fill(zhe->handle, offset, size);

	zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	return (rc);
}

static boolean_t
zoff_all_zeros_handle(void *handle)
{
	return ((zoff_provider->all_zeros(handle) == ZOFF_OK)?B_TRUE:B_FALSE);
}

boolean_t
zoff_all_zeros(void *key)
{
	if (!zoff_provider) {
		return (B_FALSE);
	}

	zoff_hash_context_read_lock(&ZOFF_HANDLES);
	zhe_t *zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, key);

	if (!zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (B_FALSE);
	}

	const int rc = zoff_all_zeros_handle(zhe);

	zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	return (rc);
}

/* basically a duplicate of zio_compress_data */
int
zoff_compress(enum zio_compress c, abd_t *src,
    void *cbuf, size_t s_len, uint8_t level,
    uint64_t *c_len, uint64_t spa_min_alloc)
{
	if (!zoff_provider || !zoff_provider->compress) {
		return (ZOFF_FALLBACK);
	}

	if (!c_len) {
		return (ZOFF_FALLBACK);
	}

	zoff_hash_context_read_lock(&ZOFF_HANDLES);

	/* src should already have been offloaded */
	zhe_t *src_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, src);
	if (!src_zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	/* compressed data buffer should have been offloaded */
	zhe_t *cbuf_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, cbuf);
	if (!cbuf_zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	size_t d_len;
	uint8_t complevel;
	zio_compress_info_t *ci = &zio_compress_table[c];

	ASSERT((uint_t)c < ZIO_COMPRESS_FUNCTIONS);
	ASSERT((uint_t)c == ZIO_COMPRESS_EMPTY || ci->ci_compress != NULL);

	/*
	 * If the data is all zeros, we don't even need to allocate
	 * a block for it.  We indicate this by returning zero size.
	 */
	if (zoff_all_zeros_handle(src_zhe->handle) == B_TRUE) {
		*c_len = 0;
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_OK);
	}

	if (c == ZIO_COMPRESS_EMPTY) {
		*c_len = s_len;
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_OK);
	}

	/* Compress at least 12.5% */
	d_len = s_len - (s_len >> 3);

	complevel = ci->ci_level;

	if (c == ZIO_COMPRESS_ZSTD) {
		/* If we don't know the level, we can't compress it */
		if (level == ZIO_COMPLEVEL_INHERIT) {
			*c_len = s_len;
			zoff_hash_context_read_unlock(&ZOFF_HANDLES);
			return (ZOFF_OK);
		}

		if (level == ZIO_COMPLEVEL_DEFAULT)
			complevel = ZIO_ZSTD_LEVEL_DEFAULT;
		else
			complevel = level;

		ASSERT3U(complevel, !=, ZIO_COMPLEVEL_INHERIT);
	}

	zcr_t ret;
	if (zoff_provider->compress(c, src_zhe->handle, cbuf_zhe->handle,
	    s_len, level, spa_min_alloc, &ret) != ZOFF_OK) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	*c_len = ret.c_len;

	if (*c_len > d_len) {
		*c_len = s_len;
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_OK);
	}

	ASSERT3U(*c_len, <=, d_len);

	zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	return (ZOFF_OK);
}

int
zoff_checksum_compute(abd_t *abd, enum zio_checksum alg, zio_byteorder_t order,
    uint64_t size, blkptr_t *bp,
    boolean_t handle_crypt, boolean_t insecure)
{
	if (!zoff_provider || !zoff_provider->checksum.compute) {
		return (ZOFF_FALLBACK);
	}

	zoff_hash_context_read_lock(&ZOFF_HANDLES);

	/* block pointer checksum should have been offloaded already */
	zhe_t *bp_cksum_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, bp);
	if (!bp_cksum_zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	/* abd should have a mapping to [compressed] data */
	zhe_t *abd_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, abd);
	if (!abd_zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	/* trigger checksum operation in provider/offloader */
	const int rc = zoff_provider->checksum.compute(alg, order,
	    abd_zhe->handle, size, bp_cksum_zhe->handle,
	    handle_crypt, insecure);

	zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	return (rc);
}

void
zoff_raidz_lock(void)
{
	zoff_hash_context_write_lock(&ZOFF_HANDLES);
}

void
zoff_raidz_unlock(void)
{
	zoff_hash_context_write_unlock(&ZOFF_HANDLES);
}

static boolean_t
zoff_has_raidz(zoff_prop_t *zoff, int raidn, boolean_t gen, boolean_t rec)
{
	if (!zoff_provider ||
	    !zoff_provider->raid.alloc ||
	    !zoff_provider->raid.set_col ||
	    !zoff_provider->raid.free) {
		return (ZOFF_FALLBACK);
	}

	boolean_t good = B_FALSE;

	if (gen == B_TRUE) {
		switch (raidn) {
			case 1:
				good = (zoff_provider->raid.gen.z1 &&
				    (zoff->raidz1_gen == 1));
				break;
			case 2:
				good = (zoff_provider->raid.gen.z2 &&
				    (zoff->raidz2_gen == 1));
				break;
			case 3:
				good = (zoff_provider->raid.gen.z3 &&
				    (zoff->raidz3_gen == 1));
				break;
			default:
				break;
		}
	}

	if (rec == B_TRUE) {
		switch (raidn) {
			case 1:
				good &= (zoff_provider->raid.rec.z1 &&
				    (zoff->raidz1_rec == 1));
				break;
			case 2:
				good &= (zoff_provider->raid.rec.z2 &&
				    (zoff->raidz2_rec == 1));
				break;
			case 3:
				good &= (zoff_provider->raid.rec.z3 &&
				    (zoff->raidz3_rec == 1));
				break;
			default:
				break;
		}
	}

	return (good);
}

int
zoff_raidz_alloc(zio_t *zio, raidz_row_t *rr)
{
	if (!zio || !rr) {
		return (ZOFF_ERROR);
	}

	if (zoff_has_raidz(&zio->io_prop.zp_zoff, rr->rr_firstdatacol,
	    B_TRUE, B_FALSE) != B_TRUE) {
		return (ZOFF_FALLBACK);
	}

	/* find the source data on the offloader */
	zhe_t *found = zoff_hash_find_mapping(&ZOFF_HANDLES, zio->io_abd);
	if (!found) {
		return (ZOFF_ERROR);
	}

	/*
	 * allocates the rr offloader struct, but
	 * does not fill in the column data
	 */
	void *rr_handle = zoff_provider->raid.alloc(rr->rr_firstdatacol,
	    rr->rr_cols);
	if (!rr_handle) {
		return (ZOFF_ERROR);
	}

	boolean_t good = found?B_TRUE:B_FALSE;

	/* allocate new space for parity */
	for (uint64_t c = 0; (c < rr->rr_firstdatacol) && (good == B_TRUE);
	    c++) {
		zhe_t *zhe = create_zhe(rr->rr_col[c].rc_abd,
		    rr->rr_col[c].rc_size);
		if (!zhe) {
			good = B_FALSE;
			break;
		}

		/* assign this allocation to column c */
		if (zoff_provider->raid.set_col(rr_handle, c,
		    zhe->handle) != ZOFF_OK) {
			good = B_FALSE;
			break;
		}

		zoff_hash_register_offload(&ZOFF_HANDLES, zhe);
	}

	uint64_t off = 0;

	/* create references for column data */
	for (uint64_t c = rr->rr_firstdatacol;
	    (c < rr->rr_cols) && (good == B_TRUE);
	    c++) {
		/* create a new record */
		zhe_t *zhe = zhe_create(&ZOFF_HANDLES, rr->rr_col[c].rc_abd,
		    B_FALSE);
		if (!zhe) {
			good = B_FALSE;
			break;
		}

		/* create an offloader reference */
		zhe->handle = zoff_provider->alloc_ref(found->handle, off,
		    rr->rr_col[c].rc_size);

		/* assign this reference to column c */
		if (zoff_provider->raid.set_col(rr_handle, c,
		    zhe->handle) != ZOFF_OK) {
			good = B_FALSE;
			break;
		}

		zoff_hash_register_offload(&ZOFF_HANDLES, zhe);

		off += rr->rr_col[c].rc_size;
	}

	if (good != B_TRUE) {
		zoff_provider->raid.free(rr_handle);
		return (ZOFF_ERROR);
	}

	zhe_t *rr_zhe = create_zhe(rr, 0);
	if (!rr_zhe) {
		zoff_provider->raid.free(rr_handle);
		return (ZOFF_ERROR);
	}

	rr_zhe->handle = rr_handle;

	zoff_hash_register_offload(&ZOFF_HANDLES, rr_zhe);
	return (ZOFF_OK);
}

int
zoff_raidz_gen(zio_t *zio, raidz_row_t *rr)
{
	if (!rr) {
		return (ZOFF_FALLBACK);
	}

	if (zoff_has_raidz(&zio->io_prop.zp_zoff, rr->rr_firstdatacol,
	    B_TRUE, B_FALSE) != B_TRUE) {
		return (ZOFF_FALLBACK);
	}

	zhe_t *rr_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, rr);
	if (!rr_zhe) {
		return (ZOFF_FALLBACK);
	}

	int rc = ZOFF_ERROR;
	switch (rr->rr_firstdatacol) {
		case 1:
			rc = zoff_provider->raid.gen.z1(rr_zhe->handle);
			break;
		case 2:
			rc = zoff_provider->raid.gen.z2(rr_zhe->handle);
			break;
		case 3:
			rc = zoff_provider->raid.gen.z3(rr_zhe->handle);
			break;
		default:
			break;
	}

	return (rc);
}

/* no onloading happens - onload the zio if the data is needed */
static int
zoff_raidz_free_private(raidz_row_t *rr, boolean_t lock)
{
	if (!rr) {
		return (ZOFF_ERROR);
	}

	if (lock == B_TRUE) {
		zoff_hash_context_write_lock(&ZOFF_HANDLES);
	}

	/* remove zhe from hash table, but do not deallocate */
	zhe_t *rr_zhe = zoff_hash_find_and_remove(&ZOFF_HANDLES, rr);
	if (!rr_zhe) {
		if (lock == B_TRUE) {
			zoff_hash_context_write_unlock(&ZOFF_HANDLES);
		}
		return (ZOFF_FALLBACK);
	}

	/*
	 * no need to check if raidz is working
	 * either raidz is fine, and the rr_zhe->handle
	 * can be deallocated, or raidz is down, and
	 * there's nothing that can be done on the
	 * offloader anyways
	 */
	zoff_provider->raid.free(rr_zhe->handle);

	/*
	 * clean up columns because they are not
	 * removed by zoff_provider->raidz.free
	 */
	for (int c = 0; c < rr->rr_cols; c++) {
		zoff_free_private(rr->rr_col[c].rc_abd, B_FALSE);
	}

	if (lock == B_TRUE) {
		zoff_hash_context_write_unlock(&ZOFF_HANDLES);
	}

	zhe_destroy(rr_zhe);

	return (ZOFF_OK);
}

/* onload abd and delete raidz_row_t stuff */
int
zoff_raidz_cleanup(zio_t *zio, raidz_row_t *rr)
{
	if (!zio || !rr) {
		return (ZOFF_ERROR);
	}

	if (zoff_has_raidz(&zio->io_prop.zp_zoff, rr->rr_firstdatacol,
	    B_TRUE, B_FALSE) != B_TRUE) {
		return (ZOFF_FALLBACK);
	}

	/*
	 * bring data back to zio, which should
	 * place data into parent automatically
	 */
	zoff_onload_abd_private(zio->io_abd, zio->io_abd->abd_size,
	    B_FALSE, B_TRUE);

	/* don't bring parity columns back */
	/* raidz failed, so parity columns will be bad */

	zoff_raidz_free_private(rr, B_FALSE);

	return (ZOFF_OK);
}

int
zoff_raidz_free(raidz_row_t *rr)
{
	return (zoff_raidz_free_private(rr, B_TRUE));
}

int
zoff_create_gang(abd_t *gang)
{
	if (!zoff_provider) {
		return (ZOFF_FALLBACK);
	}

	if (abd_is_gang(gang) != B_TRUE) {
		return (ZOFF_FALLBACK);
	}

	/* count child abds */
	size_t count = 0;
	size_t offloaded = 0;
	for (abd_t *cabd = list_head(&ABD_GANG(gang).abd_gang_chain);
	    cabd != NULL;
	    cabd = list_next(&ABD_GANG(gang).abd_gang_chain, cabd)) {
		count++;
		offloaded += (zoff_is_offloaded(cabd) == B_TRUE);
	}

	/*
	 * if none of the children abds are offloaded,
	 * there's no need to offload the gang
	 */
	if (offloaded == 0) {
		return (ZOFF_ERROR);
	}

	zhe_t *gang_zhe = zhe_create(&ZOFF_HANDLES, gang, B_TRUE);
	if (!gang_zhe) {
		return (ZOFF_ERROR);
	}

	gang_zhe->handle = zoff_provider->gang.alloc(count);
	if (!gang_zhe->handle) {
		destroy_zhe(gang_zhe);
		return (ZOFF_ERROR);
	}

	/* offload each child abd */
	for (abd_t *cabd = list_head(&ABD_GANG(gang).abd_gang_chain);
	    cabd != NULL;
	    cabd = list_next(&ABD_GANG(gang).abd_gang_chain, cabd)) {
		zhe_t *cabd_zhe = zoff_offload_abd(cabd, cabd->abd_size);
		if (!cabd_zhe) {
			/* if offload failed, let abd_free clean up cabd */
			destroy_zhe(gang_zhe);
			return (ZOFF_ERROR);
		}

		zoff_provider->gang.add(gang_zhe->handle, cabd_zhe->handle);
	}

	/* register gang */
	zoff_hash_context_write_lock(&ZOFF_HANDLES);
	zoff_hash_register_offload(&ZOFF_HANDLES, gang_zhe);
	zoff_hash_context_write_unlock(&ZOFF_HANDLES);

	return (ZOFF_OK);
}

int
zoff_write_file(zfs_file_t *dst, abd_t *abd, ssize_t size,
    loff_t offset, ssize_t *resid, int *err)
{
	if (!zoff_provider || !zoff_provider->write.file) {
		return (ZOFF_FALLBACK);
	}

	zoff_hash_context_read_lock(&ZOFF_HANDLES);

	zhe_t *abd_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, abd);
	if (!abd_zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	const int rc = zoff_provider->write.file(dst, abd_zhe->handle,
	    size, offset, resid, err);

	zoff_hash_context_read_unlock(&ZOFF_HANDLES);
	return (rc);
}

int
zoff_write_disk(struct block_device *bdev, zio_t *zio,
    size_t io_size, uint64_t io_offset, int rw,
    int failfast, int flags)
{
#ifdef _KERNEL
	if (!zoff_provider || !zoff_provider->write.disk) {
		return (ZOFF_FALLBACK);
	}

	if (rw != WRITE) {
		return (ZOFF_ERROR);
	}

	zoff_hash_context_read_lock(&ZOFF_HANDLES);

	zhe_t *abd_zhe = zoff_hash_find_mapping(&ZOFF_HANDLES, zio->io_abd);
	if (!abd_zhe) {
		zoff_hash_context_read_unlock(&ZOFF_HANDLES);
		return (ZOFF_FALLBACK);
	}

	const int rc = zoff_provider->write.disk(bdev, abd_zhe->handle,
	    io_size, io_offset, rw, failfast, flags, zio);

	zoff_hash_context_read_unlock(&ZOFF_HANDLES);

	return ((rc == ZOFF_OK)?0:EIO);
#else
	return (ZOFF_FALLBACK);
#endif
}

#ifdef _KERNEL
void
zoff_disk_write_completion(void *zio_ptr, int error)
{
	zio_t *zio = (zio_t *)zio_ptr;
	if (zio) {
		zio->io_error = error;
		ASSERT3S(zio->io_error, >=, 0);
		if (zio->io_error)
			vdev_disk_error(zio);

		zio_delay_interrupt(zio);
	}
}

EXPORT_SYMBOL(zoff_provider_init);
EXPORT_SYMBOL(zoff_provider_exit);
EXPORT_SYMBOL(zoff_disk_write_completion);
#endif

#endif
