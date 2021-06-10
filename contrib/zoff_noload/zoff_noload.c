/*
 * Copyright (c) 2021, Eideticom
 * Use is subject to license terms.
 */

#include <sys/zoff.h>

#include <linux/bio.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/slab.h>

#define	MIN_CMP_SIZE (64 * 1024)
#define	ALGO_ALIGN	512

/* BEGIN CSTYLED */
static bool noload_on_fail_dont_compress = true;
module_param(noload_on_fail_dont_compress, bool, 0644);
MODULE_PARM_DESC(noload_on_fail_dont_compress,
	"when true, don't compress data if the noload fails to "
	"compress; when false, use gzip as a fallback when the "
	"noload fails which can result in excessive CPU usage in "
	"some cases");
/* END CSTYLED */

struct nvme_algo;

int nvme_algo_run(struct nvme_algo *alg, struct bio *src,
    u64 src_len, struct bio *dst, u64 *dst_len);
struct nvme_algo *nvme_algo_find(const char *algo_name, const char *dev_name);
void nvme_algo_put(struct nvme_algo *alg);

static struct nvme_algo *noload_c_alg, *noload_d_alg;
static struct kmem_cache *mem_hdl_cache;

struct mem_hdl {
	struct kref kref;
	struct mem_hdl *ref;
	size_t size;
	void *buf;
};

struct bio_pad_data {
	void *orig, *bounce;
	size_t len;
};

static void
bio_copy_pad_endio(struct bio *bio)
{
	struct bio_pad_data *bpd = bio->bi_private;

	memcpy(bpd->orig, bpd->bounce, bpd->len);

	kfree(bpd->bounce);
	kfree(bpd);
	bio_put(bio);
}

static void
bio_free_pad_endio(struct bio *bio)
{
	kfree(bio->bi_private);
	bio_put(bio);
}

static int
bio_bounce_pad(struct bio *bio, void *data, unsigned int len, bool is_dst)
{
	struct bio_pad_data *bpd;
	void *bounce;

	BUG_ON(bio->bi_private);
	bounce = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		return (-ENOMEM);

	if (is_dst) {
		bpd = kmalloc(sizeof (*bpd), GFP_KERNEL);
		if (!bpd) {
			kfree(bounce);
			return (-ENOMEM);
		}

		bpd->orig = data;
		bpd->bounce = bounce;
		bpd->len = len;

		bio->bi_private = bpd;
		bio->bi_end_io = bio_copy_pad_endio;
	} else {
		memcpy(bounce, data, len);

		bio->bi_private = bounce;
		bio->bi_end_io = bio_free_pad_endio;
	}

	bio_add_page(bio, virt_to_page(bounce), ALIGN(len, ALGO_ALIGN), 0);

	return (0);
}

static int
bio_map_buf(struct bio *bio, void *data, unsigned int len, bool is_dst)
{
	unsigned long kaddr = (unsigned long)data;
	unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = kaddr >> PAGE_SHIFT;

	const int nr_pages = end - start;
	bool is_vmalloc = is_vmalloc_addr(data);
	struct page *page;
	int offset, i;

	offset = offset_in_page(kaddr);

	WARN_ON(!IS_ALIGNED(offset, 512));

	for (i = 0; i < nr_pages; i++) {
		unsigned int bytes = PAGE_SIZE - offset;

		if (len <= 0)
			break;

		if (bytes > len && !IS_ALIGNED(len, ALGO_ALIGN))
			return (bio_bounce_pad(bio, data, len, is_dst));

		if (!is_vmalloc)
			page = virt_to_page(data);
		else
			page = vmalloc_to_page(data);

		bio_add_page(bio, page, min(bytes, len), offset);

		data += bytes;
		len -= bytes;
		offset = 0;
	}

	return (0);
}

static void *
zoff_noload_alloc(size_t size)
{
	struct mem_hdl *hdl;

	hdl = kmem_cache_alloc(mem_hdl_cache, GFP_KERNEL);
	if (!hdl)
		return (NULL);

	hdl->ref = NULL;
	hdl->size = size;
	hdl->buf = kmalloc(size, GFP_KERNEL);
	if (!hdl->buf) {
		kmem_cache_free(mem_hdl_cache, hdl);
		return (NULL);
	}

	kref_init(&hdl->kref);

	return (hdl);
}

static void *
zoff_noload_alloc_ref(void *src_handle, size_t offset, size_t size)
{
	struct mem_hdl *src_hdl = src_handle;
	struct mem_hdl *hdl;

	WARN_ON(size + offset > src_hdl->size);

	hdl = kmem_cache_alloc(mem_hdl_cache, GFP_KERNEL);
	if (!hdl)
		return (NULL);

	hdl->ref = src_hdl;
	hdl->buf = src_hdl->buf + offset;
	hdl->size = size;

	kref_get(&src_hdl->kref);

	return (hdl);
}

static void
zoff_noload_mem_hdl_release(struct kref *kref)
{
	struct mem_hdl *hdl = container_of(kref, struct mem_hdl, kref);

	kfree(hdl->buf);
	kmem_cache_free(mem_hdl_cache, hdl);
}

static void
zoff_noload_free(void *handle)
{
	struct mem_hdl *hdl = handle;

	if (hdl->ref) {
		kref_put(&hdl->ref->kref, zoff_noload_mem_hdl_release);
		kmem_cache_free(mem_hdl_cache, hdl);
	} else {
		kref_put(&hdl->kref, zoff_noload_mem_hdl_release);
	}
}

static int
zoff_noload_copy_from_mem(zmv_t *mv, void *buf, size_t size)
{
	struct mem_hdl *hdl = mv->handle;

	WARN_ON(size + mv->offset > hdl->size);

	memcpy(hdl->buf + mv->offset, buf, size);

	return (0);
}

static int
zoff_noload_copy_to_mem(zmv_t *mv, void *buf, size_t size)
{
	struct mem_hdl *hdl = mv->handle;

	WARN_ON(size + mv->offset > hdl->size);
	memcpy(buf, hdl->buf + mv->offset, size);

	return (0);
}

static int
zoff_noload_zero_fill(void *handle, size_t offset, size_t size)
{
	struct mem_hdl *hdl = handle;

	WARN_ON(size + offset > hdl->size);

	memset(hdl->buf + offset, 0, size);

	return (0);
}

static int
zoff_noload_all_zeros(void *handle)
{
	struct mem_hdl *hdl = handle;
	unsigned long *b = hdl->buf;

	if (b[0] == 0 && !memcmp(b, b + 1, hdl->size - sizeof (*b)))
		return (ZOFF_OK);

	return (ZOFF_ERROR);
}

static void *
zoff_noload_alloc_gang(size_t max)
{
	WARN_ON(1);
	return (NULL);
}

static int
zoff_noload_gang_add(void *handle, void *new_member_handle)
{
	WARN_ON(1);
	return (ZOFF_FALLBACK);
}

static int
noload_run(struct nvme_algo *alg, struct mem_hdl *src, struct mem_hdl *dst,
    size_t s_len, u64 *out_len)
{
	struct bio *bio_src, *bio_dst;
	int ret;

	bio_src = bio_kmalloc(GFP_KERNEL, s_len / PAGE_SIZE + 1);
	if (!bio_src)
		return (ZOFF_ERROR);

	bio_dst = bio_kmalloc(GFP_KERNEL, dst->size / PAGE_SIZE + 1);
	if (!bio_dst) {
		bio_put(bio_src);
		return (ZOFF_ERROR);
	}

	bio_src->bi_end_io = bio_put;
	bio_dst->bi_end_io = bio_put;

	ret = bio_map_buf(bio_src, src->buf, s_len, false);
	if (ret)
		goto exit_bio_put;

	ret = bio_map_buf(bio_dst, dst->buf, dst->size, true);
	if (ret)
		goto exit_src_cleanup;

	ret = nvme_algo_run(alg, bio_src, s_len, bio_dst, out_len);
	if (ret) {
		if (ret == -ENODEV) {
			printk(KERN_WARNING
			    "ZFS: Noload Compression Disabled\n");
			nvme_algo_put(noload_c_alg);
		}

		return (ZOFF_ERROR);
	}

	return (ZOFF_OK);

exit_src_cleanup:
	kfree(bio_src->bi_private);

exit_bio_put:
	bio_put(bio_src);
	bio_put(bio_dst);

	return (ZOFF_ERROR);
}

static int
zoff_noload_compress(enum zio_compress alg, void *src, void *dst, size_t s_len,
    int level, uint64_t spa_min_alloc, zcr_t *zoff_ret)
{
	u64 out_len;
	int ret;

	if (alg < ZIO_COMPRESS_GZIP_1 || alg > ZIO_COMPRESS_GZIP_9)
		return (ZOFF_FALLBACK);

	ret = noload_run(noload_c_alg, src, dst, s_len, &out_len);
	if (ret == ZOFF_OK)
		zoff_ret->c_len = out_len;

	return (ret);
}

static int
zoff_noload_decompress(enum zio_compress alg, void *src, void *dst, int level)
{
	struct mem_hdl *src_hdl = src;

	if (alg < ZIO_COMPRESS_GZIP_1 || alg > ZIO_COMPRESS_GZIP_9)
		return (ZOFF_FALLBACK);

	return (noload_run(noload_d_alg, src, dst, src_hdl->size, NULL));
}

static const zoff_functions_t zoff_noload_functions = {
	.alloc		= zoff_noload_alloc,
	.alloc_ref	= zoff_noload_alloc_ref,
	.free		= zoff_noload_free,
	.copy_from_mem	= zoff_noload_copy_from_mem,
	.copy_to_mem	= zoff_noload_copy_to_mem,
	.zero_fill	= zoff_noload_zero_fill,
	.all_zeros	= zoff_noload_all_zeros,
	.gang.alloc	= zoff_noload_alloc_gang,
	.gang.add	= zoff_noload_gang_add,
	.compress	= zoff_noload_compress,
	.decompress	= zoff_noload_decompress,
};

static int __init
zoff_noload_init(void)
{
	mem_hdl_cache = kmem_cache_create("zoff_noload_mem_hdl_cache",
	    sizeof (struct mem_hdl), 0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (!mem_hdl_cache)
		return (-ENOMEM);

	noload_c_alg = nvme_algo_find("deflate", NULL);
	if (noload_c_alg)
		printk(KERN_NOTICE
		    "ZFS: Using Noload Compression for Zoff Provider\n");

	noload_d_alg = nvme_algo_find("inflate", NULL);
	if (noload_d_alg)
		printk(KERN_NOTICE
		    "ZFS: Using Noload Decompression for Zoff Provider\n");

	return (zoff_provider_init(KBUILD_MODNAME, &zoff_noload_functions));
}

static void __exit
zoff_noload_exit(void)
{
	zoff_provider_exit(KBUILD_MODNAME);
	nvme_algo_put(noload_d_alg);
	nvme_algo_put(noload_c_alg);
	kmem_cache_destroy(mem_hdl_cache);
}

module_init(zoff_noload_init);
module_exit(zoff_noload_exit);

MODULE_LICENSE("Proprietary");
