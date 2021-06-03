#include "disk.h"

#include <linux/bio.h>

#include <sys/vdev_disk.h>
#include <sys/zoff.h>

/*
 * copied and modified from
 *   module/os/linux/zfs/abd_os.c
 *   module/os/linux/zfs/vdev_disk.c
 */

#ifndef MIN
#define	MIN(a, b) (((a) < (b))?(a):(b))
#endif

/*
 * bio_nr_pages for ABD.
 * @off is the offset in @abd
 */
static
unsigned long
koh_nr_pages_off(koh_t *koh, unsigned int size, size_t off)
{
	unsigned long pos;

	if (koh_is_gang(koh)) {
		unsigned long count = 0;

		for (size_t i = 0; i < GANG(koh).count; i++) {
			koh_t *ckoh = GANG(koh).members[i];
			int mysize = MIN(size, LINEAR(ckoh).size - off);
			count += koh_nr_pages_off(ckoh, mysize, off);
			size -= mysize;
			off = 0;
		}
		return (count);
	}

	if (koh_is_linear(koh))
		pos = (unsigned long)ptr_start(koh, off);

	return (((pos + size + PAGESIZE - 1) >> PAGE_SHIFT) -
	    (pos >> PAGE_SHIFT));
}

static unsigned int
koh_bio_map(struct bio *bio, void *buf_ptr, unsigned int bio_size)
{
	unsigned int offset, size, i;
	struct page *page;

	offset = offset_in_page(buf_ptr);
	for (i = 0; i < bio->bi_max_vecs; i++) {
		size = PAGE_SIZE - offset;

		if (bio_size <= 0)
			break;

		if (size > bio_size)
			size = bio_size;

		if (is_vmalloc_addr(buf_ptr))
			page = vmalloc_to_page(buf_ptr);
		else
			page = virt_to_page(buf_ptr);

		/*
		 * Some network related block device uses tcp_sendpage, which
		 * doesn't behave well when using 0-count page, this is a
		 * safety net to catch them.
		 */
		ASSERT3S(page_count(page), >, 0);

		if (bio_add_page(bio, page, size, offset) != size)
			break;

		buf_ptr += size;
		bio_size -= size;
		offset = 0;
	}

	return (bio_size);
}

/*
 * Locate the ABD for the supplied offset in the gang ABD.
 * Return a new offset relative to the returned ABD.
 */
static size_t
koh_gang_get_offset(koh_t *koh, size_t *off)
{
	koh_t *ckoh = NULL;
	size_t i = 0;

	ASSERT(koh_is_gang(koh));
	for (i = 0; i < GANG(koh).count; i++) {
		ckoh = GANG(koh).members[i];
		if (*off >= LINEAR(ckoh).size)
			*off -= LINEAR(ckoh).size;
		else
			return (i);
	}
	VERIFY3U(i, <, GANG(koh).count);
	return (i);
}

unsigned int
koh_bio_map_off(struct bio *bio, koh_t *koh,
    unsigned int io_size, size_t off);

/*
 * bio_map for gang ABD.
 */
static unsigned int
koh_gang_bio_map_off(struct bio *bio, koh_t *koh,
    unsigned int io_size, size_t off)
{
	ASSERT(koh_is_gang(koh));

	for (size_t i = koh_gang_get_offset(koh, &off);
	    i < GANG(koh).count; i++) {
		koh_t *ckoh = GANG(koh).members[i];
		ASSERT3U(off, <, LINEAR(ckoh).size);
		int size = MIN(io_size, LINEAR(ckoh).size - off);
		int remainder = koh_bio_map_off(bio, ckoh, size, off);
		io_size -= (size - remainder);
		if (io_size == 0 || remainder > 0)
			return (io_size);
		off = 0;
	}
	ASSERT0(io_size);
	return (io_size);
}

/*
 * bio_map for ABD.
 * @off is the offset in @abd
 * Remaining IO size is returned
 */
unsigned int
koh_bio_map_off(struct bio *bio, koh_t *koh,
    unsigned int io_size, size_t off)
{
	if (koh_is_linear(koh))
		return (koh_bio_map(bio, ptr_start(koh, off), io_size));

	ASSERT(!koh_is_linear(koh));
	ASSERT(koh_is_gang(koh));
	return (koh_gang_bio_map_off(bio, koh, io_size, off));
}

/*
 * Virtual device vector for disks.
 */
typedef struct dio_request {
	zio_t			*dr_zio;	/* Parent ZIO */
	atomic_t		dr_ref;		/* References */
	int			dr_error;	/* Bio error */
	int			dr_bio_count;	/* Count of bio's */
	struct bio		*dr_bio[0];	/* Attached bio's */
} dio_request_t;

static dio_request_t *
vdev_disk_dio_alloc(int bio_count)
{
	dio_request_t *dr = kmem_zalloc(sizeof (dio_request_t) +
	    sizeof (struct bio *) * bio_count, KM_SLEEP);
	atomic_set(&dr->dr_ref, 0);
	dr->dr_bio_count = bio_count;
	dr->dr_error = 0;

	for (int i = 0; i < dr->dr_bio_count; i++)
		dr->dr_bio[i] = NULL;

	return (dr);
}

static void
vdev_disk_dio_free(dio_request_t *dr)
{
	int i;

	for (i = 0; i < dr->dr_bio_count; i++)
		if (dr->dr_bio[i])
			bio_put(dr->dr_bio[i]);

	kmem_free(dr, sizeof (dio_request_t) +
	    sizeof (struct bio *) * dr->dr_bio_count);
}

static void
vdev_disk_dio_get(dio_request_t *dr)
{
	atomic_inc(&dr->dr_ref);
}

static int
vdev_disk_dio_put(dio_request_t *dr)
{
	int rc = atomic_dec_return(&dr->dr_ref);

	/*
	 * Free the dio_request when the last reference is dropped and
	 * ensure zio_interpret is called only once with the correct zio
	 */
	if (rc == 0) {
		zio_t *zio = dr->dr_zio;
		int error = dr->dr_error;

		vdev_disk_dio_free(dr);

		if (zio) {
			zoff_disk_write_completion(zio, error);
		}
	}

	return (rc);
}

BIO_END_IO_PROTO(kernel_offloader_disk_write_completion, bio, error)
{
	dio_request_t *dr = bio->bi_private;
	int rc;

	if (dr->dr_error == 0) {
#ifdef HAVE_1ARG_BIO_END_IO_T
		dr->dr_error = BIO_END_IO_ERROR(bio);
#else
		if (error)
			dr->dr_error = -(error);
		else if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
			dr->dr_error = EIO;
#endif
	}

	/* Drop reference acquired by __vdev_disk_physio */
	rc = atomic_dec_return(&dr->dr_ref);

	/*
	 * Free the dio_request when the last reference is dropped and
	 * ensure zio_interpret is called only once with the correct zio
	 */
	if (rc == 0) {
		zio_t *zio = dr->dr_zio;
		int error = dr->dr_error;

		vdev_disk_dio_free(dr);

		if (zio) {
			zoff_disk_write_completion(zio, error);
		}
	}
}

static inline void
vdev_submit_bio_impl(struct bio *bio)
{
#ifdef HAVE_1ARG_SUBMIT_BIO
	submit_bio(bio);
#else
	submit_bio(0, bio);
#endif
}

#ifdef HAVE_BIO_SET_DEV
#if defined(CONFIG_BLK_CGROUP) && defined(HAVE_BIO_SET_DEV_GPL_ONLY)
/*
 * The Linux 5.5 kernel updated percpu_ref_tryget() which is inlined by
 * blkg_tryget() to use rcu_read_lock() instead of rcu_read_lock_sched().
 * As a side effect the function was converted to GPL-only.  Define our
 * own version when needed which uses rcu_read_lock_sched().
 */
#if defined(HAVE_BLKG_TRYGET_GPL_ONLY)
static inline bool
vdev_blkg_tryget(struct blkcg_gq *blkg)
{
	struct percpu_ref *ref = &blkg->refcnt;
	unsigned long __percpu *count;
	bool rc;

	rcu_read_lock_sched();

	if (__ref_is_percpu(ref, &count)) {
		this_cpu_inc(*count);
		rc = true;
	} else {
#ifdef ZFS_PERCPU_REF_COUNT_IN_DATA
		rc = atomic_long_inc_not_zero(&ref->data->count);
#else
		rc = atomic_long_inc_not_zero(&ref->count);
#endif
	}

	rcu_read_unlock_sched();

	return (rc);
}
#elif defined(HAVE_BLKG_TRYGET)
#define	vdev_blkg_tryget(bg)	blkg_tryget(bg)
#endif
/*
 * The Linux 5.0 kernel updated the bio_set_dev() macro so it calls the
 * GPL-only bio_associate_blkg() symbol thus inadvertently converting
 * the entire macro.  Provide a minimal version which always assigns the
 * request queue's root_blkg to the bio.
 */
static inline void
vdev_bio_associate_blkg(struct bio *bio)
{
#if defined(HAVE_BIO_BDEV_DISK)
	struct request_queue *q = bio->bi_bdev->bd_disk->queue;
#else
	struct request_queue *q = bio->bi_disk->queue;
#endif

	ASSERT3P(q, !=, NULL);
	ASSERT3P(bio->bi_blkg, ==, NULL);

	if (q->root_blkg && vdev_blkg_tryget(q->root_blkg))
		bio->bi_blkg = q->root_blkg;
}
#define	bio_associate_blkg vdev_bio_associate_blkg
#endif
#else
/*
 * Provide a bio_set_dev() helper macro for pre-Linux 4.14 kernels.
 */
static inline void
bio_set_dev(struct bio *bio, struct block_device *bdev)
{
	bio->bi_bdev = bdev;
}
#endif /* HAVE_BIO_SET_DEV */

static inline void
vdev_submit_bio(struct bio *bio)
{
	struct bio_list *bio_list = current->bio_list;
	current->bio_list = NULL;
	vdev_submit_bio_impl(bio);
	current->bio_list = bio_list;
}

int
kernel_offloader_vdev_disk_physio(struct block_device *bdev, koh_t *koh,
    size_t io_size, uint64_t io_offset, int rw, int failfast, int flags,
    void *zio)
{
	dio_request_t *dr;
	uint64_t abd_offset;
	uint64_t bio_offset;
	int bio_size;
	int bio_count = 16;
	int error = 0;
	struct blk_plug plug;

	/*
	 * Accessing outside the block device is never allowed.
	 */
	if (io_offset + io_size > bdev->bd_inode->i_size) {
		return (KERNEL_OFFLOADER_ERROR);
	}

retry:
	dr = vdev_disk_dio_alloc(bio_count);

	if (failfast)
		bio_set_flags_failfast(bdev, &flags);

	dr->dr_zio = zio;

	/*
	 * Since bio's can have up to BIO_MAX_PAGES=256 iovec's, each of which
	 * is at least 512 bytes and at most PAGESIZE (typically 4K), one bio
	 * can cover at least 128KB and at most 1MB.  When the required number
	 * of iovec's exceeds this, we are forced to break the IO in multiple
	 * bio's and wait for them all to complete.  This is likely if the
	 * recordsize property is increased beyond 1MB.  The default
	 * bio_count=16 should typically accommodate the maximum-size zio of
	 * 16MB.
	 */

	abd_offset = 0;
	bio_offset = io_offset;
	bio_size = io_size;
	for (int i = 0; i <= dr->dr_bio_count; i++) {

		/* Finished constructing bio's for given buffer */
		if (bio_size <= 0) {
			break;
		}

		/*
		 * If additional bio's are required, we have to retry, but
		 * this should be rare - see the comment above.
		 */
		if (dr->dr_bio_count == i) {
			vdev_disk_dio_free(dr);
			bio_count *= 2;
			goto retry;
		}

		/* bio_alloc() with __GFP_WAIT never returns NULL */
#ifdef HAVE_BIO_MAX_SEGS
		dr->dr_bio[i] = bio_alloc(GFP_NOIO, bio_max_segs(
		    koh_nr_pages_off(koh, bio_size, abd_offset)));
#else
		dr->dr_bio[i] = bio_alloc(GFP_NOIO,
		    MIN(koh_nr_pages_off(koh, bio_size, abd_offset),
		    BIO_MAX_PAGES));
#endif
		if (unlikely(dr->dr_bio[i] == NULL)) {
			vdev_disk_dio_free(dr);
			return (KERNEL_OFFLOADER_ERROR);
		}

		/* Matching put called by vdev_disk_physio_completion */
		vdev_disk_dio_get(dr);

		bio_set_dev(dr->dr_bio[i], bdev);
		BIO_BI_SECTOR(dr->dr_bio[i]) = bio_offset >> 9;
		dr->dr_bio[i]->bi_end_io =
		    kernel_offloader_disk_write_completion;
		dr->dr_bio[i]->bi_private = dr;
		bio_set_op_attrs(dr->dr_bio[i], rw, flags);

		bio_size = koh_bio_map_off(dr->dr_bio[i], koh,
		    bio_size, abd_offset);

		/* Advance in buffer and construct another bio if needed */
		abd_offset += BIO_BI_SIZE(dr->dr_bio[i]);
		bio_offset += BIO_BI_SIZE(dr->dr_bio[i]);
	}

	/* Extra reference to protect dio_request during vdev_submit_bio */
	vdev_disk_dio_get(dr);

	if (dr->dr_bio_count > 1)
		blk_start_plug(&plug);

	/* Submit all bio's associated with this dio */
	for (int i = 0; i < dr->dr_bio_count; i++) {
		if (dr->dr_bio[i])
			vdev_submit_bio(dr->dr_bio[i]);
	}

	if (dr->dr_bio_count > 1)
		blk_finish_plug(&plug);

	(void) vdev_disk_dio_put(dr);

	return (error);
}
