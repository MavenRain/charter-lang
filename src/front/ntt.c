/* S7 L1 (the Ligero back end): the radix-2 NTT over BN254 Fr. See ntt.h. */
#include "front/ntt.h"

static void swap(ZkFr *a, uint32_t i, uint32_t j) {
  const ZkFr t = a[i];
  a[i] = a[j];
  a[j] = t;
}

/* The bit reversal permutation of the 2^LOG entries of A. */
static void reverse_bits(ZkFr *a, unsigned log) {
  const uint32_t n = (uint32_t)1 << log;
  uint32_t i, j;
  unsigned b;
  for (i = 0; i < n; i++) {
    for (j = 0, b = 0; b < log; b++) j |= ((i >> b) & 1u) << (log - 1 - b);
    if (i < j) swap(a, i, j);
  }
}

/* The values A(w^j) of the coefficients A (iterative Cooley-Tukey, decimation
 * in time). Stage S uses zk_fr_root(S) = w^(2^(LOG - S)). LOG is at most 28. */
static void forward(ZkFr *a, unsigned log) {
  const uint32_t n = (uint32_t)1 << log;
  unsigned s;
  reverse_bits(a, log);
  for (s = 1; s <= log; s++) {
    const uint32_t len = (uint32_t)1 << s, half = len >> 1;
    ZkFr step, w = zk_fr_u64(1);
    uint32_t i, j;
    zk_fr_root(s, &step);
    for (j = 0; j < half; j++) {
      for (i = j; i < n; i += len) {
        const ZkFr u = a[i], v = zk_fr_mul(&a[i + half], &w);
        a[i] = zk_fr_add(&u, &v);
        a[i + half] = zk_fr_sub(&u, &v);
      }
      w = zk_fr_mul(&w, &step);
    }
  }
}

/* A_i = A_i S^i for i < N. */
static void scale_powers(ZkFr *a, uint32_t n, const ZkFr *s) {
  ZkFr p = zk_fr_u64(1);
  uint32_t i;
  for (i = 0; i < n; i++) {
    a[i] = zk_fr_mul(&a[i], &p);
    p = zk_fr_mul(&p, s);
  }
}

int zk_ntt(ZkFr *a, unsigned log) {
  if (log > ZK_FR_TWO_ADICITY) return 0;
  forward(a, log);
  return 1;
}

/* The forward transform applied twice gives N c_(-j mod N): reverse the
 * entries 1 .. N - 1, then multiply by 1/N. */
int zk_intt(ZkFr *a, unsigned log) {
  uint32_t n, i;
  ZkFr size, inv;
  if (log > ZK_FR_TWO_ADICITY) return 0;
  n = (uint32_t)1 << log;
  forward(a, log);
  for (i = 1; i < n - i; i++) swap(a, i, n - i);
  size = zk_fr_u64(n);
  zk_fr_inv(&size, &inv); /* N is 2^LOG: not 0 mod r */
  for (i = 0; i < n; i++) a[i] = zk_fr_mul(&a[i], &inv);
  return 1;
}

int zk_coset_ntt(ZkFr *a, unsigned log) {
  const ZkFr g = zk_fr_u64(ZK_NTT_SHIFT);
  if (log > ZK_FR_TWO_ADICITY) return 0;
  scale_powers(a, (uint32_t)1 << log, &g);
  forward(a, log);
  return 1;
}

int zk_coset_intt(ZkFr *a, unsigned log) {
  const ZkFr g = zk_fr_u64(ZK_NTT_SHIFT);
  ZkFr gi;
  if (!zk_intt(a, log)) return 0;
  zk_fr_inv(&g, &gi); /* g is 5: not 0 */
  scale_powers(a, (uint32_t)1 << log, &gi);
  return 1;
}
