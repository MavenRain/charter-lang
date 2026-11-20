/* S7 L1 (the Ligero back end): the radix-2 NTT over BN254 Fr on 2^LOG points.
 * The points of zk_ntt are w^j (j < 2^LOG, w = zk_fr_root(LOG)); the points of
 * zk_coset_ntt are g w^j with the shift g = ZK_NTT_SHIFT. The shift is outside
 * the 2^28 subgroup, so the two point sets have no common point. Each entry of
 * A must be canonical. LOG above 28 is refused: the result is 0 and A is not
 * written. */
#ifndef CHARTER_NTT_H
#define CHARTER_NTT_H

#include "front/fr.h"
#include "front/zk.h"

enum { ZK_NTT_SHIFT = ZK_FR_GENERATOR /* the coset shift g = 5 */ };

/* In place: the coefficients A (low degree first) become the values A(w^j). */
int zk_ntt(ZkFr *a, unsigned log);

/* In place: the values on w^j become the coefficients (the inverse of zk_ntt). */
int zk_intt(ZkFr *a, unsigned log);

/* In place: the coefficients A become the values A(g w^j). */
int zk_coset_ntt(ZkFr *a, unsigned log);

/* In place: the values on g w^j become the coefficients (the inverse of
 * zk_coset_ntt). */
int zk_coset_intt(ZkFr *a, unsigned log);

#endif
