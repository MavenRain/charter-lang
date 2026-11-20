/* S7 L1 (the Ligero back end): Fr powers, the Fermat inverse and the 2-adic
 * roots of unity. See fr.h. */
#include "front/fr.h"

#include <string.h>

ZkFr zk_fr_pow(const ZkFr *a, const uint32_t e[ZK_LIMBS]) {
  ZkFr acc = zk_fr_u64(1);
  unsigned i;
  for (i = ZK_LIMBS * 32; i > 0; i--) {
    acc = zk_fr_mul(&acc, &acc);
    if ((e[(i - 1) / 32] >> ((i - 1) % 32)) & 1u) acc = zk_fr_mul(&acc, a);
  }
  return acc;
}

/* The limbs of r - K for K in [1, r): 0 - K mod r. */
static void r_minus(uint64_t k, uint32_t out[ZK_LIMBS]) {
  const ZkFr zero = zk_fr_u64(0), kk = zk_fr_u64(k);
  const ZkFr d = zk_fr_sub(&zero, &kk);
  memcpy(out, d.limb, sizeof d.limb);
}

int zk_fr_inv(const ZkFr *a, ZkFr *out) {
  const ZkFr zero = zk_fr_u64(0);
  uint32_t e[ZK_LIMBS];
  if (!zk_canonical(a) || memcmp(a->limb, zero.limb, sizeof zero.limb) == 0) return 0;
  r_minus(2, e);
  *out = zk_fr_pow(a, e);
  return 1;
}

int zk_fr_root(unsigned log, ZkFr *out) {
  static ZkFr w; /* 5^((r - 1) / 2^28), made once */
  static int ready;
  uint32_t e[ZK_LIMBS];
  ZkFr x;
  unsigned i;
  if (log > ZK_FR_TWO_ADICITY) return 0;
  if (!ready) {
    const ZkFr g = zk_fr_u64(ZK_FR_GENERATOR);
    r_minus(1, e);
    /* (r - 1) >> 28: e[i + 1] is read before it is shifted. */
    for (i = 0; i < ZK_LIMBS; i++) e[i] = (e[i] >> 28) | (i + 1 < ZK_LIMBS ? e[i + 1] << 4 : 0u);
    w = zk_fr_pow(&g, e);
    ready = 1;
  }
  x = w;
  for (i = log; i < ZK_FR_TWO_ADICITY; i++) x = zk_fr_mul(&x, &x);
  *out = x;
  return 1;
}
