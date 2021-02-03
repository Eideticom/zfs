#include <linux/string.h>
#include <sys/debug.h>     /* ASSERT */
#include <sys/vdev_raidz_enums.h>

#include "raidz.h"

/* taken from zfs */

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
	uint64_t *p = korz->cols[VDEV_RAIDZ_P]->koh_u.linear.ptr;
	int c;

	for (c = korz->raidn; c < korz->acols; c++) {
		koh_t *koh = korz->cols[c];

		if (c == korz->raidn) {
			memcpy(p, koh->koh_u.linear.ptr, koh->koh_u.linear.size);
		} else {
			struct pqr_struct pqr = { p, NULL, NULL };
			vdev_raidz_p_func(koh->koh_u.linear.ptr, koh->koh_u.linear.size, &pqr);
		}
	}
}

void
vdev_raidz_generate_parity_pq(korz_t *korz)
{
	uint64_t *p = korz->cols[VDEV_RAIDZ_P]->koh_u.linear.ptr;
	uint64_t *q = korz->cols[VDEV_RAIDZ_Q]->koh_u.linear.ptr;
	uint64_t pcnt = korz->cols[VDEV_RAIDZ_P]->koh_u.linear.size / sizeof (p[0]);
	int c;
	uint64_t i;
	ASSERT(korz->cols[VDEV_RAIDZ_P]->koh_u.linear.size ==
	    korz->cols[VDEV_RAIDZ_Q]->koh_u.linear.size);

	for (c = korz->raidn; c < korz->acols; c++) {
		koh_t *koh = korz->cols[c];

		uint64_t ccnt = koh->koh_u.linear.size / sizeof (p[0]);

		if (c == korz->raidn) {
			ASSERT(ccnt == pcnt || ccnt == 0);
			(void) memcpy(p, koh->koh_u.linear.ptr, koh->koh_u.linear.size);
			(void) memcpy(q, p, koh->koh_u.linear.size);

			for (i = ccnt; i < pcnt; i++) {
				p[i] = 0;
				q[i] = 0;
			}
		} else {
			struct pqr_struct pqr = { p, q, NULL };
			uint64_t mask = 0;

			ASSERT(ccnt <= pcnt);
			vdev_raidz_pq_func(koh->koh_u.linear.ptr, koh->koh_u.linear.size, &pqr);

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
	uint64_t *p = korz->cols[VDEV_RAIDZ_P]->koh_u.linear.ptr;
	uint64_t *q = korz->cols[VDEV_RAIDZ_Q]->koh_u.linear.ptr;
	uint64_t *r = korz->cols[VDEV_RAIDZ_R]->koh_u.linear.ptr;
	uint64_t pcnt = korz->cols[VDEV_RAIDZ_P]->koh_u.linear.size / sizeof (p[0]);
	int c;
	uint64_t i;
	ASSERT(korz->cols[VDEV_RAIDZ_P]->koh_u.linear.size ==
	    korz->cols[VDEV_RAIDZ_Q]->koh_u.linear.size);
	ASSERT(korz->cols[VDEV_RAIDZ_P]->koh_u.linear.size ==
	    korz->cols[VDEV_RAIDZ_R]->koh_u.linear.size);

	for (c = korz->raidn; c < korz->acols; c++) {
		koh_t *koh = korz->cols[c];

		uint64_t ccnt = koh->koh_u.linear.size / sizeof (p[0]);

		if (c == korz->raidn) {
			ASSERT(ccnt == pcnt || ccnt == 0);
			(void) memcpy(p, koh->koh_u.linear.ptr, koh->koh_u.linear.size);
			(void) memcpy(q, p, koh->koh_u.linear.size);
			(void) memcpy(r, p, koh->koh_u.linear.size);

			for (i = ccnt; i < pcnt; i++) {
				p[i] = 0;
				q[i] = 0;
				r[i] = 0;
			}
		} else {
			struct pqr_struct pqr = { p, q, r };
			uint64_t mask;

			ASSERT(ccnt <= pcnt);
			vdev_raidz_pqr_func(koh->koh_u.linear.ptr, koh->koh_u.linear.size, &pqr);
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
