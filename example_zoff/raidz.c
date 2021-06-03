#include <linux/string.h>
#include <sys/debug.h>	/* ASSERT */

#include "raidz.h"

/* taken from zfs */

/*
 * vdev_raidz interface
 */
#define	VDEV_RAIDZ_P		0
#define	VDEV_RAIDZ_Q		1
#define	VDEV_RAIDZ_R		2

#define	VDEV_RAIDZ_MUL_2(x)	(((x) << 1) ^ (((x) & 0x80) ? 0x1d : 0))
#define	VDEV_RAIDZ_MUL_4(x)	(VDEV_RAIDZ_MUL_2(VDEV_RAIDZ_MUL_2(x)))

/*
 * We provide a mechanism to perform the field multiplication operation on a
 * 64-bit value all at once rather than a byte at a time. This works by
 * creating a mask from the top bit in each byte and using that to
 * conditionally apply the XOR of 0x1d.
 */
#define	VDEV_RAIDZ_64MUL_2(x, mask) \
{ \
	(mask) = (x) & 0x8080808080808080ULL; \
	(mask) = ((mask) << 1) - ((mask) >> 7); \
	(x) = (((x) << 1) & 0xfefefefefefefefeULL) ^ \
	    ((mask) & 0x1d1d1d1d1d1d1d1dULL); \
}

#define	VDEV_RAIDZ_64MUL_4(x, mask) \
{ \
	VDEV_RAIDZ_64MUL_2((x), mask); \
	VDEV_RAIDZ_64MUL_2((x), mask); \
}

struct pqr_struct {
	uint64_t *p;
	uint64_t *q;
	uint64_t *r;
};

static int
vdev_raidz_p_func(void *buf, size_t size, void *private)
{
	struct pqr_struct *pqr = private;
	const uint64_t *src = buf;
	int i, cnt = size / sizeof (src[0]);

	ASSERT(pqr->p && !pqr->q && !pqr->r);

	for (i = 0; i < cnt; i++, src++, pqr->p++)
		*pqr->p ^= *src;

	return (0);
}

static int
vdev_raidz_pq_func(void *buf, size_t size, void *private)
{
	struct pqr_struct *pqr = private;
	const uint64_t *src = buf;
	uint64_t mask;
	int i, cnt = size / sizeof (src[0]);

	ASSERT(pqr->p && pqr->q && !pqr->r);

	for (i = 0; i < cnt; i++, src++, pqr->p++, pqr->q++) {
		*pqr->p ^= *src;
		VDEV_RAIDZ_64MUL_2(*pqr->q, mask);
		*pqr->q ^= *src;
	}

	return (0);
}

static int
vdev_raidz_pqr_func(void *buf, size_t size, void *private)
{
	struct pqr_struct *pqr = private;
	const uint64_t *src = buf;
	uint64_t mask;
	int i, cnt = size / sizeof (src[0]);

	ASSERT(pqr->p && pqr->q && pqr->r);

	for (i = 0; i < cnt; i++, src++, pqr->p++, pqr->q++, pqr->r++) {
		*pqr->p ^= *src;
		VDEV_RAIDZ_64MUL_2(*pqr->q, mask);
		*pqr->q ^= *src;
		VDEV_RAIDZ_64MUL_4(*pqr->r, mask);
		*pqr->r ^= *src;
	}

	return (0);
}

void
vdev_raidz_generate_parity_p(korz_t *korz)
{
	uint64_t *p = LINEAR(korz->cols[VDEV_RAIDZ_P]).ptr;
	int c;

	for (c = korz->raidn; c < korz->acols; c++) {
		koh_t *koh = korz->cols[c];

		if (c == korz->raidn) {
			memcpy(p, LINEAR(koh).ptr, LINEAR(koh).size);
		} else {
			struct pqr_struct pqr = { p, NULL, NULL };
			vdev_raidz_p_func(LINEAR(koh).ptr,
			    LINEAR(koh).size, &pqr);
		}
	}
}

void
vdev_raidz_generate_parity_pq(korz_t *korz)
{
	uint64_t *p = LINEAR(korz->cols[VDEV_RAIDZ_P]).ptr;
	uint64_t *q = LINEAR(korz->cols[VDEV_RAIDZ_Q]).ptr;
	uint64_t pcnt = LINEAR(korz->cols[VDEV_RAIDZ_P]).size / sizeof (p[0]);
	int c;
	uint64_t i;
	ASSERT(LINEAR(korz->cols[VDEV_RAIDZ_P]).size ==
	    LINEAR(korz->cols[VDEV_RAIDZ_Q]).size);

	for (c = korz->raidn; c < korz->acols; c++) {
		koh_t *koh = korz->cols[c];

		uint64_t ccnt = LINEAR(koh).size / sizeof (p[0]);

		if (c == korz->raidn) {
			ASSERT(ccnt == pcnt || ccnt == 0);
			(void) memcpy(p, LINEAR(koh).ptr, LINEAR(koh).size);
			(void) memcpy(q, p, LINEAR(koh).size);

			for (i = ccnt; i < pcnt; i++) {
				p[i] = 0;
				q[i] = 0;
			}
		} else {
			struct pqr_struct pqr = { p, q, NULL };
			uint64_t mask = 0;

			ASSERT(ccnt <= pcnt);
			vdev_raidz_pq_func(LINEAR(koh).ptr,
			    LINEAR(koh).size, &pqr);

			/*
			 * Treat short columns as though they are full of 0s.
			 * Note that there's therefore nothing needed for P.
			 */
			for (i = ccnt; i < pcnt; i++) {
				VDEV_RAIDZ_64MUL_2(q[i], mask);
			}
		}
	}
}

void
vdev_raidz_generate_parity_pqr(korz_t *korz)
{
	uint64_t *p = LINEAR(korz->cols[VDEV_RAIDZ_P]).ptr;
	uint64_t *q = LINEAR(korz->cols[VDEV_RAIDZ_Q]).ptr;
	uint64_t *r = LINEAR(korz->cols[VDEV_RAIDZ_R]).ptr;
	uint64_t pcnt = LINEAR(korz->cols[VDEV_RAIDZ_P]).size / sizeof (p[0]);
	int c;
	uint64_t i;
	ASSERT(LINEAR(korz->cols[VDEV_RAIDZ_P]).size ==
	    LINEAR(korz->cols[VDEV_RAIDZ_Q]).size);
	ASSERT(LINEAR(korz->cols[VDEV_RAIDZ_P]).size ==
	    LINEAR(korz->cols[VDEV_RAIDZ_R]).size);

	for (c = korz->raidn; c < korz->acols; c++) {
		koh_t *koh = korz->cols[c];

		uint64_t ccnt = LINEAR(koh).size / sizeof (p[0]);

		if (c == korz->raidn) {
			ASSERT(ccnt == pcnt || ccnt == 0);
			(void) memcpy(p, LINEAR(koh).ptr, LINEAR(koh).size);
			(void) memcpy(q, p, LINEAR(koh).size);
			(void) memcpy(r, p, LINEAR(koh).size);

			for (i = ccnt; i < pcnt; i++) {
				p[i] = 0;
				q[i] = 0;
				r[i] = 0;
			}
		} else {
			struct pqr_struct pqr = { p, q, r };
			uint64_t mask;

			ASSERT(ccnt <= pcnt);
			vdev_raidz_pqr_func(LINEAR(koh).ptr,
			    LINEAR(koh).size, &pqr);
			/*
			 * Treat short columns as though they are full of 0s.
			 * Note that there's therefore nothing needed for P.
			 */
			for (i = ccnt; i < pcnt; i++) {
				VDEV_RAIDZ_64MUL_2(q[i], mask);
				VDEV_RAIDZ_64MUL_4(r[i], mask);
			}
		}
	}
}
