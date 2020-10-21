/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2019, Eidetic Communications Inc.
 * Use is subject to license terms.
 */

#if defined(_KERNEL) && defined(HAVE_NVME_ALGO)
#include <sys/zfs_context.h>
#include <sys/abd.h>

#define MIN_CMP_SIZE (64 * 1024)
#define ALGO_ALIGN	512

struct nvme_algo;

int nvme_algo_run(struct nvme_algo *alg, struct bio *src,
		  u64 src_len, struct bio *dst, u64 *dst_len);
struct nvme_algo *nvme_algo_find(const char *algo_name, const char *dev_name);
void nvme_algo_put(struct nvme_algo *alg);

struct bio_pad_data {
	void *orig, *bounce;
	size_t len;
};

static struct nvme_algo *noload_c_alg, *noload_d_alg;
static atomic_t req_count;

static void noload_enable(void)
{
	if (noload_c_alg || noload_d_alg)
		return;

	if (!atomic_read(&req_count))
		return;

	noload_c_alg = nvme_algo_find("deflate", NULL);
	noload_d_alg = nvme_algo_find("inflate", NULL);
	printk(KERN_NOTICE "ZFS: Using Noload Compression\n");
}

void noload_disable(void)
{
	printk(KERN_NOTICE "ZFS: Noload Compression Disabled\n");
	nvme_algo_put(noload_c_alg);
	nvme_algo_put(noload_d_alg);
	noload_c_alg = NULL;
	noload_d_alg = NULL;
}

void noload_request(void)
{
	if (atomic_inc_return(&req_count) == 1)
		noload_enable();
}

void noload_release(void)
{
	if (atomic_dec_and_test(&req_count))
		noload_disable();
}

static void bio_copy_pad_endio(struct bio *bio)
{
	struct bio_pad_data *bpd = bio->bi_private;

	memcpy(bpd->orig, bpd->bounce, bpd->len);

	kfree(bpd->bounce);
	kfree(bpd);
	bio->bi_private = NULL;
	bio_put(bio);
}

static void bio_free_pad_endio(struct bio *bio)
{
	kfree(bio->bi_private);
	bio->bi_private = NULL;
	bio_put(bio);
}

static int bio_bounce_pad(struct bio *bio, void *data, unsigned int len,
			  bool is_dst)
{
	struct bio_pad_data *bpd;
	void *bounce;

	BUG_ON(bio->bi_private);
	bounce = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	BUG_ON(len > PAGE_SIZE);

	if (is_dst) {
		bpd = kmalloc(sizeof(*bpd), GFP_KERNEL);
		if (!bpd) {
			kfree(bounce);
			return -ENOMEM;
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

	return 0;
}

static int bio_map_buf(struct bio *bio, void *data, unsigned int len,
		       bool is_dst)
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
			return bio_bounce_pad(bio, data, len, is_dst);

		if (!is_vmalloc)
			page = virt_to_page(data);
		else
			page = vmalloc_to_page(data);

		bio_add_page(bio, page, bytes, offset);

		data += bytes;
		len -= bytes;
		offset = 0;
	}

	return 0;
}

static int abd_to_bio_cb(void *buf, size_t size, void *priv)
{
	struct bio *bio = priv;
	int rc;

	rc = bio_map_buf(bio, buf, size, false);
	if (rc)
		pr_info("bio map failure %d %zu", rc, size);
}

static ssize_t __noload_run(struct nvme_algo *alg, abd_t *src, void *dst,
			    size_t s_len, size_t d_len, int level)
{
	struct bio *bio_src, *bio_dst;
	u64 out_len = d_len;
	int ret;

	if (!alg)
		return -1;

	bio_src = bio_kmalloc(GFP_KERNEL, s_len / PAGE_SIZE + 1);
	if (!src)
		return -1;

	bio_dst = bio_kmalloc(GFP_KERNEL, d_len / PAGE_SIZE + 1);
	if (!dst) {
		bio_put(bio_src);
		return -1;
	}

	bio_src->bi_end_io = bio_put;
	bio_dst->bi_end_io = bio_put;

	ret = abd_iterate_func(src, 0, s_len, abd_to_bio_cb, bio_src);
	if (ret)
		goto exit_bio_put;

	ret = bio_map_buf(bio_dst, dst, d_len, true);
	if (ret)
		goto exit_src_cleanup;

	pr_info("noload_zrun %zu %zu\n", bio_src->bi_iter.bi_size, bio_dst->bi_iter.bi_size);
	ret = nvme_algo_run(alg, bio_src, s_len, bio_dst, &out_len);
	if (ret) {
		if (ret == -ENODEV)
			noload_disable();

		return -1;
	}

	return out_len;

exit_src_cleanup:
	kfree(bio_src->bi_private);

exit_bio_put:
	bio_put(bio_src);
	bio_put(bio_dst);

	return ret;
}

size_t noload_compress(abd_t *src, void *dst, size_t s_len, size_t d_len,
		       int level)
{
	ssize_t ret;

	if (s_len < MIN_CMP_SIZE)
		return s_len;

	ret = __noload_run(noload_c_alg, src, dst, s_len, d_len, level);
	if (ret < 0)
		return s_len;

	return ret;
}

int noload_decompress(abd_t *src, void *dst, size_t s_len, size_t d_len,
		      int level)
{
	ssize_t ret;

	ret = __noload_run(noload_d_alg, src, dst, s_len, d_len, level);
	if (ret < 0)
		return -1;

	return 0;
}

#endif
