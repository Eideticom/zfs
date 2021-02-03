#ifndef _ZOFF_HASH_H
#define _ZOFF_HASH_H

#include <sys/zoff_common.h>

#include "zoff_uthash.h"

/* memory address -> offloader handle */

/* struct for placing into hash table */
typedef struct zoff_hash_entry {
	void *ptr;         /* kernel space pointer */
	void *handle;      /* handle to an offloader record */
	UT_hash_handle hh;
} zhe_t;

/* hash table context */
typedef struct zoff_hash_context {
	krwlock_t rwlock;
	zhe_t *table;
} zhc_t;

extern zhe_t *zhe_create(zhc_t *ctx, void *key);
extern void zhe_destroy(zhe_t *zhe);

extern void zoff_hash_context_init(zhc_t *ctx);
extern void zoff_hash_context_destroy(zhc_t *ctx);

/* locking occurs in zoff.c */
extern void zoff_hash_context_read_lock(zhc_t *ctx);
extern void zoff_hash_context_read_unlock(zhc_t *ctx);
extern void zoff_hash_context_write_lock(zhc_t *ctx);
extern void zoff_hash_context_write_unlock(zhc_t *ctx);

/* find a matching address */
extern zhe_t *zoff_hash_find_mapping(zhc_t *ctx, const void *key);
extern zhe_t *zoff_hash_find_and_remove(zhc_t *ctx, const void *key);

extern void zoff_hash_register_offload(zhc_t *ctx, zhe_t *zhe);
extern void zoff_hash_unregister_offload(zhc_t *ctx, zhe_t *zhe);

#endif
