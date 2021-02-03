#ifndef _ZOFF_UTHASH_H
#define _ZOFF_UTHASH_H

#include <sys/zfs_context.h>

#define uthash_malloc(sz)   kmem_alloc(sz, KM_SLEEP)
#define uthash_free(ptr,sz) kmem_free(ptr, sz)
#define uthash_fatal(msg)
#include "uthash.h"

#endif
