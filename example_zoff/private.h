#ifndef _KERNEL_OFFLOADER_PRIVATE_H
#define	_KERNEL_OFFLOADER_PRIVATE_H

#include <linux/slab.h>
#include <linux/types.h>

#include "kernel_offloader_common.h"

typedef enum kernel_offloader_handle_type {
	/* KOH_REAL and KOH_REFERENCE share the linear struct in the union */
	KOH_REAL, /* default type - convert all data into a single blob */
	KOH_REFERENCE,
	KOH_GANG,

	KOH_INVALID,
} koht_t;

/* the handle structure */
typedef struct kernel_offloader_handle koh_t;
struct kernel_offloader_handle {
	koht_t type;

	union {
		/* analogous to linear abds */
		struct {
			void *ptr;
			size_t size; /* size of the entire buffer */
		} linear;

		/* analogous to gang abds */
		struct {
			koh_t **members;
			size_t count;
			size_t max;
			size_t size;
		} gang;
	} koh_u;
};

int koh_is_linear(koh_t *koh);
int koh_is_gang(koh_t *koh);

#define	LINEAR(koh) (koh)->koh_u.linear
#define	GANG(koh) (koh)->koh_u.gang

koh_t *koh_alloc(size_t size);
void koh_free(koh_t *koh);

/* get a starting address of a linear koh_t */
void *ptr_start(koh_t *koh, size_t offset);

/*
 * convert the actual pointer to a handle (pretend
 * the data is not accessible from the ZOFF base)
 */
void *swizzle(void *ptr);

/* convert the handle to a usable pointer */
void *unswizzle(void *handle);

#endif
