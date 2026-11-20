/* S7 L1 (the Ligero back end): powers, the Fermat inverse and the 2-adic
 * roots of unity of BN254 Fr. r - 1 = 2^28 m with m odd; 5 generates the
 * group of units (test/ligtool.c proves it from the factors of r - 1). */
#ifndef CHARTER_FR_H
#define CHARTER_FR_H

#include <stdint.h>

#include "front/zk.h"

enum {
  ZK_FR_TWO_ADICITY = 28, /* the 2-part of r - 1 */
  ZK_FR_GENERATOR = 5     /* a generator of the units mod r */
};

/* A^E mod r for a canonical A; E is ZK_LIMBS 32-bit limbs, low limb first
 * (any 256-bit value; 0^0 = 1). */
ZkFr zk_fr_pow(const ZkFr *a, const uint32_t e[ZK_LIMBS]);

/* *OUT = A^-1 mod r (Fermat: A^(r - 2)). 1 when ok; 0 when A is 0 or not
 * canonical (then *OUT is not written). */
int zk_fr_inv(const ZkFr *a, ZkFr *out);

/* *OUT = a primitive 2^LOG-th root of unity: w^(2^(28 - LOG)) for
 * w = 5^((r - 1) / 2^28). 1 when ok; 0 when LOG is above 28. */
int zk_fr_root(unsigned log, ZkFr *out);

#endif
