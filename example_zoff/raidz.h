#ifndef _KERNEL_OFFLOADER_RAIDZ_H
#define _KERNEL_OFFLOADER_RAIDZ_H

#include "private.h"

typedef struct kernel_offloader_raidz {
	size_t raidn; /* RAIDZ 1/2/3 */
	size_t acols; /* column count */
	koh_t **cols; /* array of column data - should be references into another buffer */
} korz_t;

void
vdev_raidz_generate_parity_p(korz_t *korz);
void
vdev_raidz_generate_parity_pq(korz_t *korz);
void
vdev_raidz_generate_parity_pqr(korz_t *korz);

#endif
