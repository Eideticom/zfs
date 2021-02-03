#ifndef _KERNEL_OFFLOADER_DISK_H
#define _KERNEL_OFFLOADER_DISK_H

/* copied from module/os/linux/zfs/vdev_disk.c */

#include <sys/debug.h>
#include <sys/types.h>
#include <zfs_config.h> /* this has macros that are used by blkdev_compat.h and needs to come first */
#include <linux/blkdev_compat.h>
#include "private.h"

int
kernel_offloader_vdev_disk_physio(struct block_device *bdev, koh_t *koh,
    size_t io_size, uint64_t io_offset, int rw, int failfast, int flags,
    void *zio);

#endif
