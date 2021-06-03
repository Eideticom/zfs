#ifndef _KERNEL_OFFLOADER_H
#define _KERNEL_OFFLOADER_H

#include <linux/blk_types.h>
#include <sys/zfs_file.h>     /* zfs_file_t and exporting zfs_file_pwrite */
#include <sys/zio_checksum_enums.h>
#include <sys/zio_compress_enums.h>
#include "kernel_offloader_common.h"

/*
   An offloader implementation should provide an API that can be
   called by the ZOFF provider. ZFS does not require direct access
   to the offloader.

   This file represents the API provided by a vendor to access their
   offloader. The API can be anything the implementor chooses to
   expose. There are no limitations on the function signature or
   name. They just have to be called correctly in the ZOFF provider.

   -------------------------------------------------------------------

   The kernel offloader API provides functions to offload ZFS
   operations from kernel space into "kernel offloader space".  The
   corresponding C file conflates the driver and the physical device
   since both memory spaces are in kernel space and run on the CPU.
   This offloader provides void *s to the provider to represent
   handles to inaccessible memory locations. In order to prevent the
   handle from being dereferenced and used successfully, the handle
   pointer is masked with a random value generated at load-time. Other
   offloaders may choose to present non-void handles.
*/

/* init function - this should be the kernel module init, but kernel_offloader is not compiled as a separate kernel module */
void kernel_offloader_init(void);

/* offloader handle access */
void *kernel_offloader_alloc(size_t size);
void *kernel_offloader_alloc_ref(void *src, size_t offset, size_t size);
void  kernel_offloader_free(void *handle);
void *kernel_offloader_copy_from_mem(void *handle, size_t offset, void *src, size_t size);
void *kernel_offloader_copy_to_mem(void *handle, size_t offset, void *dst, size_t size);
int kernel_offloader_copy_internal(void *dst_handle, size_t dst_offset,
    void *src_handle, size_t src_offset,
    size_t size);
int kernel_offloader_zero_fill(void *handle, size_t offset, size_t size);
int kernel_offloader_all_zeros(void *handle);

/* gang abds are used during vdev_file write */
void *kernel_offloader_alloc_gang(size_t max);
int kernel_offloader_gang_add(void *gang_handle, void *new_member_handle);

/* offloaded operations */
int kernel_offloader_checksum_compute(enum zio_checksum alg, zio_byteorder_t order,
    void *data, size_t size, void *bp_cksum, int handle_crypt, int insecure);

int kernel_offloader_checksum_error(enum zio_checksum alg, zio_byteorder_t order,
    void *data, void *bp_cksum,
    int encrypted, int dedup,
    void *zbc_expected, void *zbc_actual,
    void *zbc_checksum_name);

/* offloader fills this in for the provider to use */
typedef struct kernel_offloader_compress_ret {
    size_t c_len;
} kocr_t;

int kernel_offloader_compress(enum zio_compress alg,
    void *src, void *dst, size_t s_len, int level,
    uint64_t spa_min_alloc, void *ret);

int kernel_offloader_decompress(enum zio_compress alg,
    void *src, void *dst,
    int level);

void *kernel_offloader_alloc_raidz(size_t raidn, size_t acols);
int kernel_offloader_set_col(void *raidz, int c, void *col);
void kernel_offloader_free_raidz(void *raidz);

int kernel_offloader_raidz1_gen(void *raidz);
int kernel_offloader_raidz2_gen(void *raidz);
int kernel_offloader_raidz3_gen(void *raidz);

/* io */
int kernel_offloader_write_file(zfs_file_t *fp, void *handle, size_t count,
    loff_t offset, ssize_t *resid, int *err);
int kernel_offloader_write_disk(struct block_device *bdev, void *handle,
    size_t io_size, uint64_t io_offset, int rw,
    int failfast, int flags,
    void *zio);

#endif
