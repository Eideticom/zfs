#include "zoff_hash.h"

/* allocate and set zhe members only - do not offload or update hash table */
zhe_t *zhe_create(zhc_t *ctx, void *key, boolean_t lock) {
	if (lock == B_TRUE) {
		zoff_hash_context_read_lock(ctx);
	}

	zhe_t *zhe = zoff_hash_find_mapping(ctx, key);

	if (lock == B_TRUE) {
		zoff_hash_context_read_unlock(ctx);
	}

	if (zhe) {
#ifdef _KERNEL
		printk("Existing offloader entry with this "
		    "kernel space address (%p) found. "
		    "Not allocating.\n", key);
		return (zhe);
#endif
	}

	zhe = kmem_alloc(sizeof (zhe_t), KM_SLEEP);
	zhe->ptr = key;
	zhe->handle = NULL;

	return (zhe);
}

/*
 * free zhe only - do not onload, free the
 * offload buffer, or update the hash table
 */
void zhe_destroy(zhe_t *zhe) {
	if (zhe) {
		kmem_free(zhe, sizeof (*zhe));
	}
}

void zoff_hash_context_init(zhc_t *ctx) {
	rw_init(&ctx->rwlock, NULL, RW_DEFAULT, NULL);
	ctx->table = NULL;
}

void zoff_hash_context_destroy(zhc_t *ctx) {
	if (ctx) {
		zoff_hash_context_write_lock(ctx);

#ifdef _KERNEL
		printk("Unfreed Offloader Handles: %u\n",
		    HASH_COUNT(ctx->table));
#endif

		zhe_t *entry = NULL;
		zhe_t *tmp;
		HASH_ITER(hh, ctx->table, entry, tmp) {
			HASH_DEL(ctx->table, entry);
			zhe_destroy(entry);
		}

		zoff_hash_context_write_unlock(ctx);
		rw_destroy(&ctx->rwlock);
	}
}

static
void zoff_hash_context_lock(zhc_t *ctx, krw_t type) {
	rw_enter(&ctx->rwlock, type);
}

static
void zoff_hash_context_unlock(zhc_t *ctx) {
	rw_exit(&ctx->rwlock);
}

void zoff_hash_context_read_lock(zhc_t *ctx) {
	zoff_hash_context_lock(ctx, RW_READER);
}

void zoff_hash_context_read_unlock(zhc_t *ctx) {
	zoff_hash_context_unlock(ctx);
}

void zoff_hash_context_write_lock(zhc_t *ctx) {
	zoff_hash_context_lock(ctx, RW_WRITER);
}

void zoff_hash_context_write_unlock(zhc_t *ctx) {
	zoff_hash_context_unlock(ctx);
}

/* find a matching address */
zhe_t *zoff_hash_find_mapping(zhc_t *ctx, const void *key) {
	zhe_t *found = NULL;
	HASH_FIND_PTR(ctx->table, &key, found);
	return (found);
}

/* find a matching address and remove the entry */
zhe_t *zoff_hash_find_and_remove(zhc_t *ctx, const void *key) {
	zhe_t *found = zoff_hash_find_mapping(ctx, key);
	if (found) {
		HASH_DEL(ctx->table, found);
	}
	return (found);
}

/* add only - do not create */
void zoff_hash_register_offload(zhc_t *ctx, zhe_t *zhe) {
	/*
	 * not checking for duplicates
	 * zoff.c should always be checking before registering
	 */
	HASH_ADD_PTR(ctx->table, ptr, zhe);
}

/* remove only - do not free */
void zoff_hash_unregister_offload(zhc_t *ctx, zhe_t *zhe) {
	HASH_DEL(ctx->table, zhe);
}
