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

struct nvme_algo;

struct noload_buffer {
	struct bio *bio;
	off_t pos;
	void *padding;
	bool filled;
};

int nvme_algo_run(struct nvme_algo *alg, struct bio *src,
		  u64 src_len, struct bio *dst, u64 *dst_len);
struct nvme_algo *nvme_algo_find(const char *algo_name, const char *dev_name);
void nvme_algo_put(struct nvme_algo *alg);

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

static void noload_map_buf(struct noload_buffer *nlbuf, void *data,
			   unsigned int len)
{
	unsigned long kaddr = (unsigned long)data;
	unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = kaddr >> PAGE_SHIFT;

	const int nr_pages = end - start;
	bool is_vmalloc = is_vmalloc_addr(data);
	struct page *page;
	int offset, i;

	offset = offset_in_page(kaddr);

	WARN_ON(nlbuf->filled);

	for (i = 0; i < nr_pages; i++) {
		unsigned int bytes = PAGE_SIZE - offset;

		if (len <= 0)
			break;

		//Skip the last page if it would be partial
		if (bytes > len) {
			nlbuf->filled = true;
			break;
		}

		if (bytes > len)
			bytes = len;

		if (!is_vmalloc)
			page = virt_to_page(data);
		else
			page = vmalloc_to_page(data);

		bio_add_page(nlbuf->bio, page, bytes, offset);

		data += bytes;
		len -= bytes;
		offset = 0;
		nlbuf->pos += bytes;
	}
}

static int abd_to_bio_cb(void *buf, size_t size, void *priv)
{
	struct noload_buffer *nlbuf = priv;

	noload_map_buf(nlbuf, buf, size);

	return 0;
}

static ssize_t __noload_run(struct nvme_algo *alg, abd_t *src, void *dst,
			    size_t s_len, size_t d_len, int level)
{
	struct noload_buffer src_buf = {};
	struct noload_buffer dst_buf = {};
	struct bio *bio_src, *bio_dst;
	u64 out_len = d_len;
	int ret;

	if (!alg)
		return -1;

	src_buf.padding = kzalloc(PAGE_SIZE, GFP_KERNEL);
	dst_buf.padding = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!src_buf.padding || !dst_buf.padding)
		goto exit_free_padding;

	src_buf.bio = bio_kmalloc(GFP_KERNEL, s_len / PAGE_SIZE + 1);
	if (!src_buf.bio)
		goto exit_free_padding;

	dst_buf.bio = bio_kmalloc(GFP_KERNEL, d_len / PAGE_SIZE + 1);
	if (!dst_buf.bio) {
		bio_put(src_buf.bio);
		goto exit_free_padding;
	}

	src_buf.bio->bi_end_io = bio_put;
	dst_buf.bio->bi_end_io = bio_put;

	abd_iterate_func(src, 0, s_len, abd_to_bio_cb, &src_buf);
	if (src_buf.pos < s_len) {
		BUG_ON(s_len - src_buf.pos > PAGE_SIZE);
		abd_copy_to_buf_off(src_buf.padding, src,
				    src_buf.pos, s_len - src_buf.pos);
		bio_add_page(src_buf.bio, virt_to_page(src_buf.padding),
			     ALIGN(s_len - src_buf.pos, 512), 0);
	}

	noload_map_buf(&dst_buf, dst, d_len);
	if (dst_buf.pos < d_len) {
		BUG_ON(d_len - dst_buf.pos > PAGE_SIZE);
		bio_add_page(dst_buf.bio, virt_to_page(dst_buf.padding),
			     ALIGN(d_len - dst_buf.pos, 512), 0);
	}

	ret = nvme_algo_run(alg, src_buf.bio, s_len, dst_buf.bio, &out_len);
	if (ret) {
		if (ret == -ENODEV)
			noload_disable();

		goto exit_free_padding;
	}

	if (dst_buf.pos < out_len) {
		BUG_ON(out_len - dst_buf.pos > PAGE_SIZE);
		memcpy(dst + dst_buf.pos, dst_buf.padding,
		       out_len - dst_buf.pos);
	}

	kfree(dst_buf.padding);
	kfree(src_buf.padding);

	return out_len;

exit_free_padding:
	kfree(dst_buf.padding);
	kfree(src_buf.padding);
	return -1;
}

size_t noload_compress(abd_t *src, void *dst, size_t s_len, size_t d_len,
		       int level)
{
	ssize_t ret;

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
