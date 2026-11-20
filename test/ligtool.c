/* S7 L1 and L2: the rows of the Ligero back end (fr, ntt, merkle, then the
 * prover and the verifier of lig.c). build/ligtool runs all rows; it exits 1
 * when a row fails. `ligtool prove NAME FILE` writes the proof of the circuit
 * NAME (smoke or gbits) to FILE, and `ligtool verify NAME FILE` checks it: the
 * exit code is 0 when the proof verifies, 1 when it does not, 2 for a bad
 * call. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "front/fr.h"
#include "front/lig.h"
#include "front/merkle.h"
#include "front/ntt.h"
#include "front/zk.h"

static int failed;

static void row(int ok, const char *name) {
  if (!ok) {
    printf("FAIL ligtool: %s\n", name);
    failed = 1;
  }
}

static int fr_eq(const ZkFr *a, const ZkFr *b) { return memcmp(a->limb, b->limb, sizeof a->limb) == 0; }

static int fr_is(const ZkFr *a, uint64_t v) {
  const ZkFr b = zk_fr_u64(v);
  return fr_eq(a, &b);
}

/* r - 1 as an Fr element (0 - 1 mod r). */
static ZkFr fr_minus_one(void) {
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1);
  return zk_fr_sub(&zero, &one);
}

static void exp_u64(uint64_t v, uint32_t e[ZK_LIMBS]) {
  memset(e, 0, ZK_LIMBS * sizeof *e);
  e[0] = (uint32_t)v;
  e[1] = (uint32_t)(v >> 32);
}

/* X^(2^K) by K squarings. */
static ZkFr fr_sq_n(ZkFr x, unsigned k) {
  unsigned i;
  for (i = 0; i < k; i++) x = zk_fr_mul(&x, &x);
  return x;
}

/* ---- 128-bit integers for the primality proofs (no __int128: tcc). ---- */

typedef struct U128 {
  uint64_t hi, lo;
} U128;

static U128 u128(uint64_t hi, uint64_t lo) {
  U128 x;
  x.hi = hi;
  x.lo = lo;
  return x;
}

static int u128_cmp(U128 a, U128 b) {
  if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
  if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
  return 0;
}

static U128 u128_add(U128 a, U128 b) {
  U128 s;
  s.lo = a.lo + b.lo;
  s.hi = a.hi + b.hi + (s.lo < a.lo ? 1u : 0u);
  return s;
}

static U128 u128_sub(U128 a, U128 b) {
  U128 d;
  d.lo = a.lo - b.lo;
  d.hi = a.hi - b.hi - (a.lo < b.lo ? 1u : 0u);
  return d;
}

static U128 u128_shr1(U128 a) { return u128(a.hi >> 1, (a.lo >> 1) | (a.hi << 63)); }

static int u128_bit(U128 a, unsigned i) { return (int)((i < 64 ? a.lo >> i : a.hi >> (i - 64)) & 1u); }

/* A B for 64-bit A and B, by 32-bit halves. */
static U128 mul64(uint64_t a, uint64_t b) {
  const uint64_t al = a & 0xffffffffu, ah = a >> 32, bl = b & 0xffffffffu, bh = b >> 32;
  const uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
  const uint64_t mid = (ll >> 32) + (lh & 0xffffffffu) + (hl & 0xffffffffu);
  return u128(hh + (lh >> 32) + (hl >> 32) + (mid >> 32), (mid << 32) | (ll & 0xffffffffu));
}

/* A + B mod N and A B mod N for A, B < N < 2^127 (double and add). */
static U128 addmod(U128 a, U128 b, U128 n) {
  const U128 s = u128_add(a, b);
  return u128_cmp(s, n) >= 0 ? u128_sub(s, n) : s;
}

static U128 mulmod(U128 a, U128 b, U128 n) {
  U128 acc = u128(0, 0);
  unsigned i;
  for (i = 128; i > 0; i--) {
    acc = addmod(acc, acc, n);
    if (u128_bit(b, i - 1)) acc = addmod(acc, a, n);
  }
  return acc;
}

static U128 powmod(U128 a, U128 e, U128 n) {
  U128 acc = u128(0, 1);
  unsigned i;
  for (i = 128; i > 0; i--) {
    acc = mulmod(acc, acc, n);
    if (u128_bit(e, i - 1)) acc = mulmod(acc, a, n);
  }
  return acc;
}

/* gcd(X, N) for an odd N and 0 < X < N (binary). */
static U128 gcd_odd(U128 x, U128 n) {
  U128 a = x, b = n;
  while (!u128_bit(a, 0)) a = u128_shr1(a);
  while (u128_cmp(a, b) != 0) {
    if (u128_cmp(a, b) > 0) {
      a = u128_sub(a, b);
      while (!u128_bit(a, 0)) a = u128_shr1(a);
    } else {
      b = u128_sub(b, a);
      while (!u128_bit(b, 0)) b = u128_shr1(b);
    }
  }
  return a;
}

/* 1 when N (below 2^64) is prime: strong probable prime to the 12 prime bases
 * 2 .. 37, a proof below 318665857834031151167461 (about 2^78; Sorenson and
 * Webster, Math. Comp. 86 (2017) 985-1003). */
static int prime_mr(U128 n) {
  static const unsigned base[12] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
  const U128 one = u128(0, 1);
  U128 d, nm1;
  unsigned s = 0, i, j;
  int ok = 1;
  if (n.hi != 0 || n.lo < 2) return 0;
  for (i = 0; i < 12; i++)
    if (n.lo == base[i]) return 1;
  for (i = 0; i < 12; i++)
    if (n.lo % base[i] == 0) return 0;
  nm1 = u128_sub(n, one);
  for (d = nm1; !u128_bit(d, 0); d = u128_shr1(d)) s++;
  for (i = 0; ok && i < 12; i++) {
    U128 x = powmod(u128(0, base[i]), d, n);
    int pass = u128_cmp(x, one) == 0 || u128_cmp(x, nm1) == 0;
    for (j = 1; !pass && j < s; j++) {
      x = mulmod(x, x, n);
      pass = u128_cmp(x, nm1) == 0;
    }
    ok = pass;
  }
  return ok;
}

/* The prime factors of r - 1 with their powers. Q (94 bits) is proved by
 * Pocklington (fr_rows); the others by prime_mr. */
static const struct {
  U128 q;
  unsigned power;
} FACTOR[] = {
  {{0, 2u}, 28},
  {{0, 3u}, 2},
  {{0, 13u}, 1},
  {{0, 29u}, 1},
  {{0, 983u}, 1},
  {{0, 11003u}, 1},
  {{0, 237073u}, 1},
  {{0, 405928799u}, 1},
  {{0, 1670836401704629u}, 1},
  {{0x2ca6487cu, 0xfcd795e8729527e1u}, 1} /* 13818364434197438864469338081 */
};
enum { FACTORS = sizeof FACTOR / sizeof FACTOR[0] };

/* ACC = ACC F for 8 limbs of 32 bits; 0 on a carry past 256 bits. */
static int big_mul(uint32_t acc[ZK_LIMBS], U128 f) {
  const uint32_t fl[4] = {(uint32_t)f.lo, (uint32_t)(f.lo >> 32), (uint32_t)f.hi, (uint32_t)(f.hi >> 32)};
  uint32_t t[ZK_LIMBS + 4];
  unsigned i, j;
  int ok = 1;
  memset(t, 0, sizeof t);
  for (i = 0; i < ZK_LIMBS; i++) {
    uint64_t carry = 0;
    for (j = 0; j < 4; j++) {
      const uint64_t s = (uint64_t)t[i + j] + (uint64_t)acc[i] * fl[j] + carry;
      t[i + j] = (uint32_t)s;
      carry = s >> 32;
    }
    t[i + 4] = (uint32_t)carry;
  }
  for (i = ZK_LIMBS; i < ZK_LIMBS + 4; i++) ok = ok && t[i] == 0;
  memcpy(acc, t, ZK_LIMBS * sizeof *acc);
  return ok;
}

/* The product of the factors, with the power of factor SKIP one less
 * (SKIP = FACTORS: all). 0 on overflow. */
static int cofactor(unsigned skip, uint32_t e[ZK_LIMBS]) {
  unsigned i, k;
  int ok = 1;
  exp_u64(1, e);
  for (i = 0; i < FACTORS; i++)
    for (k = 0; k < FACTOR[i].power - (i == skip ? 1u : 0u); k++) ok = ok && big_mul(e, FACTOR[i].q);
  return ok;
}

/* 1 when G^((r - 1) / q) != 1 for each prime q of r - 1. */
static int generates(uint64_t g) {
  const ZkFr gg = zk_fr_u64(g);
  uint32_t e[ZK_LIMBS];
  unsigned i;
  int ok = 1;
  for (i = 0; i < FACTORS; i++) {
    ZkFr x;
    ok = ok && cofactor(i, e);
    x = zk_fr_pow(&gg, e);
    ok = ok && !fr_is(&x, 1);
  }
  return ok;
}

static void fr_rows(void) {
  const ZkFr m1 = fr_minus_one(), zero = zk_fr_u64(0);
  /* 5^((r - 1) / 2^28), from Python 3 pow at RESUME31 (an independent value). */
  static const uint32_t W28[ZK_LIMBS] = {0x725b19f0u, 0x9bd61b6eu, 0x41112ed4u, 0x402d111eu,
                                         0x8ef62abcu, 0x00e0a7ebu, 0xa58a7e85u, 0x2a3c09f0u};
  const U128 Q = FACTOR[FACTORS - 1].q, F = u128(0, 0xea007c3431338fu), C = u128(0, 0x30d8d2ea20u);
  ZkFr sample[7], x, y, w;
  uint32_t e[ZK_LIMBS], e2[ZK_LIMBS];
  unsigned i, log;
  int ok;

  /* The factors: each prime, the product r - 1. */
  for (i = 0, ok = 1; i + 1 < FACTORS; i++) ok = ok && prime_mr(FACTOR[i].q);
  row(ok, "fr factors below 2^64 prime (Miller-Rabin, bases 2 .. 37)");
  /* Pocklington for Q: Q - 1 = F C, F prime, F^2 > Q, 2^(Q-1) = 1, gcd(2^C - 1, Q) = 1. */
  x = zk_fr_u64(0);
  row(prime_mr(F), "fr Pocklington F prime");
  row(u128_cmp(mul64(F.lo, C.lo), u128_sub(Q, u128(0, 1))) == 0, "fr Pocklington Q - 1 = F C");
  row(u128_cmp(mul64(F.lo, F.lo), Q) > 0, "fr Pocklington F^2 > Q");
  row(u128_cmp(powmod(u128(0, 2), u128_sub(Q, u128(0, 1)), Q), u128(0, 1)) == 0, "fr Pocklington 2^(Q-1) = 1");
  {
    const U128 a = powmod(u128(0, 2), C, Q);
    row(a.hi != 0 || a.lo > 1, "fr Pocklington 2^C not 0 or 1");
    row((a.hi != 0 || a.lo > 1) && u128_cmp(gcd_odd(u128_sub(a, u128(0, 1)), Q), u128(0, 1)) == 0,
        "fr Pocklington gcd(2^C - 1, Q) = 1");
  }
  ok = cofactor(FACTORS, e);
  y = zk_fr_u64(0);
  memcpy(y.limb, e, sizeof y.limb);
  row(ok && fr_eq(&y, &m1), "fr product of the factors = r - 1");

  /* The generator: 5 (the pinned one) and 7 both generate. */
  row(generates(ZK_FR_GENERATOR), "fr 5 generates the units mod r");
  row(generates(7), "fr 7 generates the units mod r");
  row(!generates(4), "fr 4 (a square) does not generate");

  /* pow and inv. */
  sample[0] = zk_fr_u64(1);
  sample[1] = zk_fr_u64(2);
  sample[2] = zk_fr_u64(5);
  sample[3] = zk_fr_u64(0x123456789abcdefu);
  sample[4] = m1;
  zk_fr_root(28, &sample[5]);
  sample[6] = zk_fr_sub(&m1, &sample[3]);
  for (i = 0, ok = 1; i < 7; i++) {
    ZkFr inv, t;
    ok = ok && zk_fr_inv(&sample[i], &inv);
    t = zk_fr_mul(&sample[i], &inv);
    ok = ok && fr_is(&t, 1);
    memcpy(e, m1.limb, sizeof e);
    t = zk_fr_pow(&sample[i], e);
    ok = ok && fr_is(&t, 1);
    exp_u64(0, e);
    t = zk_fr_pow(&sample[i], e);
    ok = ok && fr_is(&t, 1);
    exp_u64(1, e);
    t = zk_fr_pow(&sample[i], e);
    ok = ok && fr_eq(&t, &sample[i]);
    exp_u64(3, e);
    t = zk_fr_pow(&sample[i], e);
    x = zk_fr_mul(&sample[i], &sample[i]);
    x = zk_fr_mul(&x, &sample[i]);
    ok = ok && fr_eq(&t, &x);
    /* a^12345 a^67890 = a^80235 */
    exp_u64(12345, e);
    exp_u64(67890, e2);
    t = zk_fr_pow(&sample[i], e);
    x = zk_fr_pow(&sample[i], e2);
    t = zk_fr_mul(&t, &x);
    exp_u64(80235, e);
    x = zk_fr_pow(&sample[i], e);
    ok = ok && fr_eq(&t, &x);
  }
  row(ok, "fr pow and inv on 7 samples (a a^-1 = 1, a^(r-1) = 1, a^0, a^1, a^3, a^(e1+e2))");
  row(!zk_fr_inv(&zero, &x), "fr inv(0) refused");
  for (i = 0, x = zero; i < ZK_LIMBS; i++) x.limb[i] = 0xffffffffu;
  row(!zk_fr_inv(&x, &y), "fr inv(non-canonical) refused");

  /* The roots of unity. */
  ok = zk_fr_root(28, &w);
  row(ok && memcmp(w.limb, W28, sizeof W28) == 0, "fr root 2^28 = 5^((r-1)/2^28) (the Python value)");
  for (log = 0, ok = 1; log <= ZK_FR_TWO_ADICITY; log++) {
    ok = ok && zk_fr_root(log, &x);
    y = fr_sq_n(x, log);
    ok = ok && fr_is(&y, 1);
    if (log > 0) {
      y = fr_sq_n(x, log - 1);
      ok = ok && fr_eq(&y, &m1);
    }
  }
  row(ok, "fr root 2^k has order exactly 2^k for k = 0 .. 28");
  row(!zk_fr_root(29, &x), "fr root 2^29 refused");
  x = zk_fr_u64(ZK_FR_GENERATOR);
  x = fr_sq_n(x, ZK_FR_TWO_ADICITY);
  row(!fr_is(&x, 1), "fr 5 is outside the 2^28 subgroup (the coset shift)");
  if (!failed) printf("fr rows: passed\n");
}

/* ---- ntt rows ---- */

/* splitmix64: the fixed samples of the ntt and merkle rows. */
static uint64_t mix_state = 0x2545f4914f6cdd1du;

static uint64_t mix64(void) {
  uint64_t z = (mix_state += 0x9e3779b97f4a7c15u);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9u;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebu;
  return z ^ (z >> 31);
}

/* A sample over all of Fr: ((a 2^64 + b) 2^64 + c) 2^64 + d mod r. */
static ZkFr fr_sample(void) {
  const ZkFr two32 = zk_fr_u64((uint64_t)1 << 32);
  const ZkFr two64 = zk_fr_mul(&two32, &two32);
  ZkFr x = zk_fr_u64(mix64());
  unsigned i;
  for (i = 0; i < 3; i++) {
    const ZkFr d = zk_fr_u64(mix64());
    x = zk_fr_mul(&x, &two64);
    x = zk_fr_add(&x, &d);
  }
  return x;
}

/* C(X) by Horner: TERMS coefficients, low degree first. */
static ZkFr horner(const ZkFr *c, uint32_t terms, const ZkFr *x) {
  ZkFr y = zk_fr_u64(0);
  uint32_t i;
  for (i = terms; i > 0; i--) {
    y = zk_fr_mul(&y, x);
    y = zk_fr_add(&y, &c[i - 1]);
  }
  return y;
}

/* 1 when A_j = C(S w^j) for each j < 2^LOG, w = zk_fr_root(LOG): the naive
 * O(n^2) evaluation. */
static int naive_agrees(const ZkFr *a, const ZkFr *c, uint32_t terms, unsigned log, const ZkFr *s) {
  ZkFr w, x = *s;
  uint32_t j;
  int ok = zk_fr_root(log, &w);
  for (j = 0; j < (uint32_t)1 << log; j++) {
    const ZkFr y = horner(c, terms, &x);
    ok = ok && fr_eq(&a[j], &y);
    x = zk_fr_mul(&x, &w);
  }
  return ok;
}

static void ntt_rows(void) {
  enum { NAIVE = 6, TRIP = 12, H_LOG = 3, L_LOG = 5 };
  static ZkFr c[1 << TRIP], a[1 << TRIP], keep[1 << TRIP];
  static const uint32_t SPOT[] = {0, 1, 2047, 4095};
  const ZkFr one = zk_fr_u64(1), zero = zk_fr_u64(0), g = zk_fr_u64(ZK_NTT_SHIFT);
  const uint32_t big = (uint32_t)1 << TRIP, hn = (uint32_t)1 << H_LOG, ln = (uint32_t)1 << L_LOG;
  uint32_t n, j, e[ZK_LIMBS];
  unsigned log;
  int fwd = 1, inv = 1, cfwd = 1, cinv = 1, ok;
  ZkFr w, x, y;

  for (log = 0; log <= NAIVE; log++) {
    n = (uint32_t)1 << log;
    for (j = 0; j < n; j++) c[j] = fr_sample();
    memcpy(a, c, n * sizeof *a);
    ok = zk_ntt(a, log);
    fwd = fwd && ok && naive_agrees(a, c, n, log, &one);
    ok = zk_intt(a, log);
    inv = inv && ok && memcmp(a, c, n * sizeof *a) == 0;
    memcpy(a, c, n * sizeof *a);
    ok = zk_coset_ntt(a, log);
    cfwd = cfwd && ok && naive_agrees(a, c, n, log, &g);
    ok = zk_coset_intt(a, log);
    cinv = cinv && ok && memcmp(a, c, n * sizeof *a) == 0;
  }
  row(fwd, "ntt on 2^a points = the naive evaluation at w^j (a = 0 .. 6)");
  row(inv, "ntt intt(ntt(c)) = c (a = 0 .. 6)");
  row(cfwd, "ntt coset on 2^a points = the naive evaluation at 5 w^j (a = 0 .. 6)");
  row(cinv, "ntt coset_intt(coset_ntt(c)) = c (a = 0 .. 6)");

  /* 2^12: four naive points, then the round trips. */
  for (j = 0; j < big; j++) c[j] = fr_sample();
  memcpy(a, c, sizeof a);
  ok = zk_ntt(a, TRIP) && zk_fr_root(TRIP, &w);
  for (j = 0; j < sizeof SPOT / sizeof *SPOT; j++) {
    exp_u64(SPOT[j], e);
    x = zk_fr_pow(&w, e);
    y = horner(c, big, &x);
    ok = ok && fr_eq(&a[SPOT[j]], &y);
  }
  row(ok, "ntt at 2^12 = the naive evaluation at w^0, w^1, w^2047, w^4095");
  ok = zk_intt(a, TRIP) && memcmp(a, c, sizeof a) == 0;
  ok = ok && zk_coset_ntt(a, TRIP) && memcmp(a, c, sizeof a) != 0;
  ok = ok && zk_coset_intt(a, TRIP) && memcmp(a, c, sizeof a) == 0;
  row(ok, "ntt round trips at 2^12 (plain and coset)");

  /* The low-degree extension of the prover: 2^3 values on H = <w_8>, their
   * interpolant (degree < 8), its values on the coset 5 <w_32>. */
  for (j = 0; j < hn; j++) c[j] = fr_sample();
  memcpy(a, c, hn * sizeof *a);
  ok = zk_intt(a, H_LOG) && naive_agrees(c, a, hn, H_LOG, &one);
  memcpy(keep, a, hn * sizeof *a);
  for (j = hn; j < ln; j++) a[j] = zero;
  ok = ok && zk_coset_ntt(a, L_LOG) && naive_agrees(a, keep, hn, L_LOG, &g);
  row(ok, "ntt low-degree extension: 2^3 values on H, their interpolant on the coset 5 <w_32>");

  memcpy(keep, a, ln * sizeof *a);
  ok = !zk_ntt(a, 29) && !zk_intt(a, 29) && !zk_coset_ntt(a, 29) && !zk_coset_intt(a, 29);
  row(ok && memcmp(a, keep, ln * sizeof *a) == 0, "ntt 2^29 refused, the entries not written");
  if (!failed) printf("ntt rows: passed\n");
}

/* ---- merkle rows ---- */

/* Known answers from hashlib (W/s7-u6-r32-merkle-kat.py, an independent
 * SHA-512): H(0 || 1 || 2), H(0), the node of the leaves of the columns (0)
 * and (1), and the root over the leaves of the columns (0) .. (3). An Fr
 * element is 32 bytes, low byte first. */
static const uint8_t KAT_LEAF12[32] = {0xc8, 0x8e, 0xff, 0xe4, 0x15, 0x98, 0x2e, 0x4e, 0x17, 0xb5, 0xcb,
                                       0xd3, 0x9f, 0xe5, 0xbd, 0x2a, 0xb8, 0x14, 0x5b, 0x9e, 0x1b, 0x25,
                                       0xfc, 0x49, 0x7e, 0x9e, 0x7d, 0x8b, 0xdc, 0x35, 0x6f, 0xbe};
static const uint8_t KAT_NODE01[32] = {0x31, 0xa1, 0xc5, 0x61, 0x72, 0x70, 0x96, 0xbc, 0x3e, 0xad, 0x13,
                                       0x36, 0xd5, 0x71, 0x91, 0x93, 0xa3, 0x68, 0x50, 0x77, 0x85, 0x07,
                                       0x52, 0x76, 0x0d, 0x3c, 0x43, 0xbf, 0x32, 0xa7, 0x2d, 0x05};
static const uint8_t KAT_ROOT4[32] = {0xc8, 0x0a, 0x75, 0x76, 0x7b, 0x34, 0x61, 0x82, 0xcd, 0x6c, 0x30,
                                      0xe6, 0x87, 0x8c, 0xbd, 0x67, 0x4a, 0xb3, 0xa7, 0xb4, 0xd7, 0x57,
                                      0xb3, 0xd9, 0x84, 0xc3, 0xe1, 0x2b, 0xb0, 0x17, 0x3c, 0x3b};
static const uint8_t KAT_EMPTY[32] = {0xb8, 0x24, 0x4d, 0x02, 0x89, 0x81, 0xd6, 0x93, 0xaf, 0x7b, 0x45,
                                      0x6a, 0xf8, 0xef, 0xa4, 0xca, 0xd6, 0x3d, 0x28, 0x2e, 0x19, 0xff,
                                      0x14, 0x94, 0x2c, 0x24, 0x6e, 0x50, 0xd9, 0x35, 0x1d, 0x22};

/* The 32 bytes of A, low byte first. */
static void fr_bytes(const ZkFr *a, uint8_t out[32]) {
  unsigned k;
  for (k = 0; k < 32; k++) out[k] = (uint8_t)(a->limb[k / 4] >> (8 * (k % 4)));
}

/* OUT = the leaf hashes of LEAF at the COUNT indices IDX. */
static void gather(const uint8_t *leaf, const uint32_t *idx, size_t count, uint8_t *out) {
  size_t i;
  for (i = 0; i < count; i++)
    memcpy(out + i * ZK_MERKLE_BYTES, leaf + (size_t)idx[i] * ZK_MERKLE_BYTES, ZK_MERKLE_BYTES);
}

static void merkle_rows(void) {
  enum { HB = ZK_MERKLE_BYTES, LOG = 4, N = 1 << LOG, BIG = 10, OPEN = 309, STRIDE = 389 };
  static uint8_t leaf[(1 << BIG) * HB], sib[OPEN * BIG * HB + HB], lv[OPEN * HB], mark[1 << BIG];
  static const uint32_t SET[] = {1, 2, 9, 15}, NEAR[] = {1, 2, 9, 14}, ONE[] = {5};
  static const uint32_t DESC[] = {2, 1}, DUP[] = {1, 1}, PAST[] = {N};
  uint32_t idx[OPEN], all[N], j;
  uint8_t h[HB], h2[HB], b0[HB], b1[HB], path[LOG * HB];
  const uint8_t *root;
  ZkFr col[2];
  ZkMerkle t;
  size_t hashes = 0, i, count;
  unsigned b;
  int ok, good, bad;

  /* The definition, against hashlib. */
  col[0] = zk_fr_u64(1);
  col[1] = zk_fr_u64(2);
  zk_merkle_leaf(col, 2, h);
  row(memcmp(h, KAT_LEAF12, HB) == 0, "merkle leaf of the column (1, 2) = H(0 || 1 || 2) (hashlib)");
  zk_merkle_leaf(col, 0, h);
  row(memcmp(h, KAT_EMPTY, HB) == 0, "merkle leaf of the empty column = H(0) (hashlib)");
  for (j = 0; j < 4; j++) {
    col[0] = zk_fr_u64(j);
    zk_merkle_leaf(col, 1, leaf + j * HB);
  }
  zk_merkle_node(leaf, leaf + HB, h);
  row(memcmp(h, KAT_NODE01, HB) == 0, "merkle node of the leaves (0) and (1) = H(1 || l0 || l1) (hashlib)");
  ok = zk_merkle_build(&t, 2, leaf) == ZK_OK && memcmp(zk_merkle_root(&t), KAT_ROOT4, HB) == 0;
  zk_merkle_free(&t);
  row(ok, "merkle root over the leaves (0) .. (3) (hashlib)");
  col[0] = fr_sample();
  col[1] = fr_sample();
  fr_bytes(&col[0], b0);
  fr_bytes(&col[1], b1);
  zk_merkle_leaf(col, 2, h);
  zk_merkle_node(b0, b1, h2);
  row(memcmp(h, h2, HB) != 0, "merkle the leaf tag and the node tag give different hashes of the same 64 bytes");
  row(zk_merkle_build(&t, ZK_MERKLE_LOG_MAX + 1, leaf) == ZK_ERR_COUNT && t.node == NULL,
      "merkle build over 2^29 leaves refused");

  /* A tree over 2^4 leaves: the paths. */
  for (j = 0; j < N; j++) {
    col[0] = fr_sample();
    col[1] = fr_sample();
    zk_merkle_leaf(col, 2, leaf + j * HB);
  }
  ok = zk_merkle_build(&t, LOG, leaf) == ZK_OK;
  row(ok, "merkle build over 2^4 leaves");
  if (!ok) return;
  root = zk_merkle_root(&t);
  for (j = 0, good = 1, bad = 1; j < N; j++) {
    const uint8_t *lj = leaf + j * HB;
    good = good && zk_merkle_path(&t, j, path) && zk_merkle_path_check(root, LOG, j, lj, path);
    memcpy(h, lj, HB);
    h[j % HB] ^= 1u;
    bad = bad && !zk_merkle_path_check(root, LOG, j, h, path);
    for (b = 0; b < LOG; b++) {
      path[b * HB + 7] ^= 0x80u;
      bad = bad && !zk_merkle_path_check(root, LOG, j, lj, path);
      path[b * HB + 7] ^= 0x80u;
    }
    bad = bad && !zk_merkle_path_check(root, LOG, j ^ 1u, lj, path);
  }
  row(good, "merkle the path of each of the 16 leaves verifies");
  row(bad, "merkle a path refuses a changed leaf, a changed sibling (each level) and the index j ^ 1");
  row(!zk_merkle_path(&t, N, path) && !zk_merkle_path_check(root, LOG, N, leaf, path) &&
          !zk_merkle_path_check(root, ZK_MERKLE_LOG_MAX + 1, 0, leaf, path),
      "merkle a path at index 2^4, a check at index 2^4 or at log 29 refused");

  /* The multi-open. Leaves 1, 2, 9, 15: 4 hashes at the leaf level, 2 at
   * level 1, 1 at level 2, 0 at level 3. */
  gather(leaf, SET, 4, lv);
  ok = zk_merkle_open(&t, SET, 4, sib, &hashes) == ZK_OK && hashes == 7 &&
       zk_merkle_check(root, LOG, SET, 4, lv, sib, hashes);
  row(ok, "merkle multi-open of the leaves 1, 2, 9, 15 of 16: 7 hashes, verifies");
  for (i = 0, bad = 1; i < 4; i++) {
    lv[i * HB + 3] ^= 1u;
    bad = bad && !zk_merkle_check(root, LOG, SET, 4, lv, sib, hashes);
    lv[i * HB + 3] ^= 1u;
  }
  for (i = 0; i < hashes; i++) {
    sib[i * HB + 11] ^= 1u;
    bad = bad && !zk_merkle_check(root, LOG, SET, 4, lv, sib, hashes);
    sib[i * HB + 11] ^= 1u;
  }
  bad = bad && !zk_merkle_check(root, LOG, SET, 4, lv, sib, hashes - 1);
  bad = bad && !zk_merkle_check(root, LOG, SET, 4, lv, sib, hashes + 1);
  bad = bad && !zk_merkle_check(root, LOG, NEAR, 4, lv, sib, hashes);
  row(bad, "merkle multi-open refuses a changed leaf, a changed hash (each), a missing hash, an extra hash and "
           "the indices 1, 2, 9, 14");
  ok = zk_merkle_open(&t, DESC, 2, sib, &hashes) == ZK_ERR_MAP && zk_merkle_open(&t, DUP, 2, sib, &hashes) == ZK_ERR_MAP &&
       zk_merkle_open(&t, PAST, 1, sib, &hashes) == ZK_ERR_MAP && zk_merkle_open(&t, SET, 0, sib, &hashes) == ZK_ERR_MAP;
  ok = ok && !zk_merkle_check(root, LOG, DESC, 2, lv, sib, 0) && !zk_merkle_check(root, LOG, DUP, 2, lv, sib, 0) &&
       !zk_merkle_check(root, LOG, PAST, 1, lv, sib, 0) && !zk_merkle_check(root, LOG, SET, 0, lv, sib, 0);
  row(ok, "merkle multi-open and check refuse a decreasing, a repeated, an out-of-range and an empty index set");
  ok = zk_merkle_open(&t, ONE, 1, sib, &hashes) == ZK_OK && hashes == LOG && zk_merkle_path(&t, ONE[0], path) &&
       memcmp(sib, path, LOG * HB) == 0;
  row(ok, "merkle multi-open of one leaf = its path");
  for (j = 0; j < N; j++) all[j] = j;
  ok = zk_merkle_open(&t, all, N, sib, &hashes) == ZK_OK && hashes == 0 && zk_merkle_check(root, LOG, all, N, leaf, sib, 0);
  row(ok, "merkle multi-open of all 16 leaves: 0 hashes, verifies");
  zk_merkle_free(&t);

  /* 309 of 2^10 leaves (the t of Q-L1): j 389 mod 2^10 for j < 309 (389 is
   * odd, so the indices are distinct), in increasing order. */
  for (i = 0; i < sizeof leaf; i++) leaf[i] = (uint8_t)mix64();
  for (j = 0; j < OPEN; j++) mark[(j * STRIDE) % (1u << BIG)] = 1;
  for (j = 0, count = 0; j < 1u << BIG; j++)
    if (mark[j]) idx[count++] = j;
  ok = count == OPEN && zk_merkle_build(&t, BIG, leaf) == ZK_OK;
  row(ok, "merkle build over 2^10 leaves, 309 distinct indices");
  if (!ok) return;
  root = zk_merkle_root(&t);
  gather(leaf, idx, count, lv);
  ok = zk_merkle_open(&t, idx, count, sib, &hashes) == ZK_OK && hashes > 0 && hashes < count * BIG &&
       zk_merkle_check(root, BIG, idx, count, lv, sib, hashes);
  lv[100 * HB] ^= 1u;
  ok = ok && !zk_merkle_check(root, BIG, idx, count, lv, sib, hashes);
  zk_merkle_free(&t);
  row(ok, "merkle multi-open of 309 of 2^10 leaves: fewer than 3090 hashes, verifies; a changed leaf refused");
  if (!failed) printf("merkle rows: passed (309 of 2^10 leaves: %zu hashes)\n", hashes);
}

/* ---- S7 L2: the prover and the verifier (lig.c). ---- */

enum {
  FIX_BITS = 64,
  ROW_TEXT = 200,
  P_ROOT = 16,    /* the proof byte offsets (lig.h): the root */
  P_Q = 48,       /* q0 */
  P_FR = 32       /* the bytes of one element */
};

/* One circuit with its witness. The witness points into the fixture, so a
 * fixture is not copied. */
typedef struct Fixture {
  ZkCircuit c;
  ZkFr input[2], weight[FIX_BITS], output[1];
  ZkMatrix matrix;
  uint32_t map;
  ZkWitness w;
  uint32_t mul; /* fix_dangling: the value of the mul */
} Fixture;

static void fix_wire(Fixture *f) {
  f->matrix.rows = 1;
  f->matrix.cols = f->c.weights;
  f->matrix.entry = f->weight;
  f->map = 0;
  f->w.inputs = f->c.inputs;
  f->w.input = f->input;
  f->w.matrices = 1;
  f->w.matrix = &f->matrix;
  f->w.maps = 1;
  f->w.map = &f->map;
  f->w.outputs = f->c.outputs;
  f->w.output = f->output;
}

/* The smoke circuit of zktool: x w = y for the inputs x, y and the weight w,
 * and the output 0 is the const 1. */
static void fix_smoke(Fixture *f, uint64_t x, uint64_t y, uint64_t w) {
  const ZkFr one = zk_fr_u64(1);
  uint32_t p, k;
  memset(f, 0, sizeof *f);
  zk_init(&f->c, 2, 1, 1);
  p = zk_mul(&f->c, zk_input(&f->c, 0), zk_weight(&f->c, 0));
  zk_eq(&f->c, p, zk_input(&f->c, 1));
  k = zk_const(&f->c, &one);
  (void)zk_out(&f->c, 0, k);
  f->input[0] = zk_fr_u64(x);
  f->input[1] = zk_fr_u64(y);
  f->weight[0] = zk_fr_u64(w);
  f->output[0] = one;
  fix_wire(f);
}

/* The gbits circuit of zktool: the 64 weights are the bits of the input x. */
static void fix_gbits(Fixture *f, uint64_t x) {
  memset(f, 0, sizeof *f);
  zk_init(&f->c, 1, FIX_BITS, 0);
  zk_bits(&f->c, zk_input(&f->c, 0), 0, FIX_BITS);
  f->input[0] = zk_fr_u64(x);
  zk_bits_fill(f->weight, &f->input[0], FIX_BITS);
  fix_wire(f);
}

/* One mul of the input 3 and the weight 5 that no eq uses: only the
 * quadratic test sees a wrong product. */
static void fix_dangling(Fixture *f) {
  memset(f, 0, sizeof *f);
  zk_init(&f->c, 1, 1, 0);
  f->mul = zk_mul(&f->c, zk_input(&f->c, 0), zk_weight(&f->c, 0));
  f->input[0] = zk_fr_u64(3);
  f->weight[0] = zk_fr_u64(5);
  fix_wire(f);
}

static LigErr fix_verify(const Fixture *f, const ZkFr *input, const ZkFr *output, const LigProof *p) {
  return lig_verify(&f->c, input, f->c.inputs, output, f->c.outputs, p->byte, p->count);
}

static LigErr own_verify(const Fixture *f, const LigProof *p) { return fix_verify(f, f->input, f->output, p); }

/* 1 when the proof P of F does not verify (the Merkle check: the public
 * values are in the seed of the open columns) for each public value plus 1. */
static int publics_bound(const Fixture *f, const LigProof *p) {
  const ZkFr one = zk_fr_u64(1);
  uint32_t i;
  int ok = 1;
  for (i = 0; i < f->c.inputs + f->c.outputs; i++) {
    ZkFr in[2], out[1], *t;
    memcpy(in, f->input, sizeof in);
    memcpy(out, f->output, sizeof out);
    t = i < f->c.inputs ? &in[i] : &out[i - f->c.inputs];
    *t = zk_fr_add(t, &one);
    ok = ok && fix_verify(f, in, out, p) == LIG_ERR_MERKLE;
  }
  return ok;
}

static void named_row(int ok, const char *name, const char *what) {
  char text[ROW_TEXT];
  snprintf(text, sizeof text, "lig %s %s", name, what);
  row(ok, text);
}

/* The two fixed seeds of the rows. A proof is a function of the seed, the
 * circuit, the public values and the witness, so a row gives the same bytes
 * on each run. The prove mode takes its seed from /dev/urandom. */
static const uint8_t SEED_A[LIG_SEED_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t SEED_B[LIG_SEED_BYTES] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f, 0x00};

/* The 32-bit word (low byte first) at the byte AT of P. AT + 4 is not after
 * the end of P. */
static uint32_t proof_word(const LigProof *p, size_t at) {
  const uint8_t *b = p->byte + at;
  return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

/* The byte offset of the count of Merkle hashes in a proof of the sizes S. */
static size_t cnt_at(const LigParams *s) {
  return P_Q + (size_t)5 * s->k * P_FR + (size_t)LIG_COLUMNS * (s->rows + LIG_COL_EXTRA) * P_FR;
}

/* 1 when P has the L3 layout for the sizes S: version 2, and the count of
 * Merkle hashes at the L2 offset plus 39552 (LIG_COLUMNS x 4 elements: u0,
 * m1, m2 and the salt of each open column), with the proof size that the
 * count gives. The size is not a fixed number: the open columns, and with
 * them the hash count, change with the seed. */
static int layout_ok(const LigParams *s, const LigProof *p) {
  size_t l2 = P_Q + (size_t)5 * s->k * P_FR + (size_t)LIG_COLUMNS * s->rows * P_FR;
  size_t cnt = cnt_at(s);
  if (cnt != l2 + 39552 || p->count < cnt + 4 || proof_word(p, 0) != 2) return 0;
  return p->count == cnt + 4 + (size_t)proof_word(p, cnt) * ZK_MERKLE_BYTES;
}

/* 1 when the COUNT elements at the byte AT are not the same in P and in Q. */
static int part_differs(const LigProof *p, const LigProof *q, size_t at, size_t count) {
  size_t bytes = count * P_FR;
  return at + bytes <= p->count && at + bytes <= q->count && memcmp(p->byte + at, q->byte + at, bytes) != 0;
}

/* 1 when the prover refuses the false witness of BAD, and the forced proof
 * fails the linear sum. */
static int refused(const Fixture *bad) {
  LigProof p = {NULL, 0};
  int ok = lig_prove(&bad->c, &bad->w, SEED_A, &p) == LIG_ERR_UNSAT && p.byte == NULL && p.count == 0;
  ok = ok && lig_prove_forced(&bad->c, &bad->w, SEED_A, NULL, 0, &p) == LIG_OK && p.count > 0;
  ok = ok && own_verify(bad, &p) == LIG_ERR_LINEAR_SUM;
  lig_proof_free(&p);
  return ok;
}

/* The four case families: the true instance A, a second true instance B and
 * the false witness BAD for the public values of A; then the layout and the
 * seed rows of L3. *KEEP = the proof of A. */
static void family_rows(const char *name, const Fixture *a, const Fixture *b, const Fixture *bad, LigProof *keep) {
  LigProof pa = {NULL, 0}, pb = {NULL, 0}, again = {NULL, 0}, other = {NULL, 0};
  LigParams s;
  int va = lig_prove(&a->c, &a->w, SEED_A, &pa) == LIG_OK && pa.count > 0 && own_verify(a, &pa) == LIG_OK;
  int vb = lig_prove(&b->c, &b->w, SEED_A, &pb) == LIG_OK && pb.count > 0 && own_verify(b, &pb) == LIG_OK;
  int ok;
  named_row(va, name, "accepts: the proof of the true witness verifies");
  named_row(vb, name, "proves: the proof of a second instance verifies");
  named_row(refused(bad), name, "refuses: the prover refuses the false witness; the forced proof fails the linear sum");
  ok = pa.count > 0 && pb.count > 0 && own_verify(b, &pa) == LIG_ERR_MERKLE && own_verify(a, &pb) == LIG_ERR_MERKLE;
  named_row(ok && publics_bound(a, &pa), name, "instance_refused: a changed public value fails the verify");
  ok = va && vb && lig_params(&a->c, &s) == LIG_OK;
  named_row(ok && layout_ok(&s, &pa) && layout_ok(&s, &pb), name,
            "layout: version 2; the hash count is 39552 bytes after its L2 place and gives the proof size");
  named_row(ok && lig_prove(&a->c, &a->w, SEED_A, &again) == LIG_OK && again.count == pa.count &&
                memcmp(again.byte, pa.byte, pa.count) == 0,
            name, "seed: one seed gives the same proof bytes two times");
  named_row(ok && lig_prove(&a->c, &a->w, SEED_B, &other) == LIG_OK && own_verify(a, &other) == LIG_OK &&
                part_differs(&pa, &other, P_ROOT, 1) && part_differs(&pa, &other, P_Q, s.k) &&
                part_differs(&pa, &other, P_Q + (size_t)s.k * P_FR, (size_t)2 * s.k) &&
                part_differs(&pa, &other, P_Q + (size_t)3 * s.k * P_FR, (size_t)2 * s.k),
            name, "seed: a second seed gives another root, q0, q1 and q2 for the same witness; the proof verifies");
  named_row(ok && part_differs(&pa, &pb, P_Q, s.k), name,
            "seed: one seed with a second witness gives another q0; the two proofs verify");
  lig_proof_free(&again);
  lig_proof_free(&other);
  lig_proof_free(&pb);
  *keep = pa;
}

/* The verify result for the proof P of F with bit 0 of the byte AT changed. */
static LigErr flip(const Fixture *f, const LigProof *p, size_t at) {
  LigErr e;
  if (at >= p->count) return LIG_OK;
  p->byte[at] ^= 1u;
  e = own_verify(f, p);
  p->byte[at] ^= 1u;
  return e;
}

/* The verify result with the element at the byte AT set to 2^256 - 1. */
static LigErr not_canonical(const Fixture *f, const LigProof *p, size_t at) {
  uint8_t keep[P_FR];
  LigErr e;
  if (at + P_FR > p->count) return LIG_OK;
  memcpy(keep, p->byte + at, P_FR);
  memset(p->byte + at, 0xff, P_FR);
  e = own_verify(f, p);
  memcpy(p->byte + at, keep, P_FR);
  return e;
}

/* The changed proof bytes of the true proof P of F: each site with the error
 * of the check that finds it. */
static void tamper_rows(const Fixture *f, const LigProof *p) {
  LigParams s;
  size_t col, cnt, mask;
  uint8_t *big;
  if (lig_params(&f->c, &s) != LIG_OK || p->count == 0) {
    row(0, "lig tamper: the true proof is there");
    return;
  }
  col = P_Q + (size_t)5 * s.k * P_FR;
  cnt = col + (size_t)LIG_COLUMNS * (s.rows + LIG_COL_EXTRA) * P_FR;
  mask = col + (size_t)s.rows * P_FR; /* u0, m1, m2 and the salt of the first open column */
  row(p->count > cnt + 4 + ZK_MERKLE_BYTES, "lig tamper: the proof has the columns and one Merkle hash at least");
  row(flip(f, p, P_ROOT) == LIG_ERR_MERKLE, "lig tamper: a changed root fails the Merkle check");
  row(flip(f, p, P_Q) == LIG_ERR_MERKLE, "lig tamper: a changed q0 gives other open columns");
  row(flip(f, p, P_Q + (size_t)s.k * P_FR) == LIG_ERR_MERKLE, "lig tamper: a changed q1 gives other open columns");
  row(flip(f, p, P_Q + (size_t)3 * s.k * P_FR) == LIG_ERR_MERKLE, "lig tamper: a changed q2 gives other open columns");
  row(flip(f, p, col) == LIG_ERR_MERKLE, "lig tamper: a changed open column value fails the Merkle check");
  row(flip(f, p, mask) == LIG_ERR_MERKLE, "lig tamper: a changed u0 value of an open column fails the Merkle check");
  row(flip(f, p, mask + P_FR) == LIG_ERR_MERKLE,
      "lig tamper: a changed m1 value of an open column fails the Merkle check");
  row(flip(f, p, mask + 2 * P_FR) == LIG_ERR_MERKLE,
      "lig tamper: a changed m2 value of an open column fails the Merkle check");
  row(flip(f, p, mask + 3 * P_FR) == LIG_ERR_MERKLE,
      "lig tamper: a changed salt of an open column fails the Merkle check");
  row(flip(f, p, cnt - P_FR) == LIG_ERR_MERKLE,
      "lig tamper: a changed salt of the last open column fails the Merkle check");
  row(flip(f, p, p->count - 1) == LIG_ERR_MERKLE, "lig tamper: a changed last Merkle hash fails the Merkle check");
  row(flip(f, p, cnt + 4) == LIG_ERR_MERKLE, "lig tamper: a changed Merkle hash fails the Merkle check");
  row(flip(f, p, 0) == LIG_ERR_FORMAT, "lig tamper: a changed version word is a format error");
  row(flip(f, p, 4) == LIG_ERR_FORMAT, "lig tamper: a changed log k word is a format error");
  row(flip(f, p, 8) == LIG_ERR_FORMAT, "lig tamper: a changed rows word is a format error");
  row(flip(f, p, 12) == LIG_ERR_FORMAT, "lig tamper: a changed columns word is a format error");
  row(flip(f, p, cnt) == LIG_ERR_FORMAT, "lig tamper: a changed hash count is a format error");
  row(not_canonical(f, p, P_Q) == LIG_ERR_FORMAT, "lig tamper: a q0 element that is not canonical is a format error");
  row(not_canonical(f, p, col) == LIG_ERR_FORMAT, "lig tamper: a column element that is not canonical is a format error");
  row(not_canonical(f, p, mask) == LIG_ERR_FORMAT, "lig tamper: a mask value that is not canonical is a format error");
  row(not_canonical(f, p, mask + 3 * P_FR) == LIG_ERR_FORMAT,
      "lig tamper: a salt that is not canonical is a format error");
  row(lig_verify(&f->c, f->input, f->c.inputs, f->output, f->c.outputs, p->byte, p->count - 1) == LIG_ERR_FORMAT,
      "lig tamper: a proof without its last byte is a format error");
  row(lig_verify(&f->c, f->input, f->c.inputs, f->output, f->c.outputs, p->byte, cnt) == LIG_ERR_FORMAT,
      "lig tamper: a proof cut before the hash count is a format error");
  big = calloc(p->count + 1, 1);
  if (big != NULL) memcpy(big, p->byte, p->count);
  row(big != NULL &&
          lig_verify(&f->c, f->input, f->c.inputs, f->output, f->c.outputs, big, p->count + 1) == LIG_ERR_FORMAT,
      "lig tamper: a proof with one more byte is a format error");
  free(big);
}

/* The calls that the prover and the verifier refuse before the tests. */
static void refusal_rows(const Fixture *f, const LigProof *p) {
  ZkFr big = zk_fr_u64(0), in[sizeof f->input / sizeof f->input[0]];
  ZkWitness w = f->w;
  ZkCircuit c;
  LigParams s;
  LigProof q = {NULL, 0};
  uint64_t far;
  int ok = lig_params(&f->c, &s) == LIG_OK;
  row(ok && s.log_k == 9 && s.k == 512 && s.l == 203 && s.n == 2048 && s.muls == 1 && s.vrows == 1 && s.trows == 1 &&
          s.rows == 4,
      "lig params of smoke: k 512, l 203, n 2048, one v row and one row for each of x, y, z");
  row(ok && cnt_at(&s) == 161072, "lig layout of smoke: the hash count is at byte 161072 (the L2 byte 121520 + 39552)");
  row(lig_verify(&f->c, f->input, f->c.inputs - 1, f->output, f->c.outputs, p->byte, p->count) == LIG_ERR_INSTANCE,
      "lig verify: a wrong input count is an instance error");
  row(lig_verify(&f->c, f->input, f->c.inputs, f->output, f->c.outputs + 1, p->byte, p->count) == LIG_ERR_INSTANCE,
      "lig verify: a wrong output count is an instance error");
  memset(big.limb, 0xff, sizeof big.limb);
  row(lig_verify(&f->c, f->input, f->c.inputs, &big, f->c.outputs, p->byte, p->count) == LIG_ERR_INSTANCE,
      "lig verify: a public value that is not canonical is an instance error");
  memcpy(in, f->input, sizeof in);
  in[0] = big;
  row(lig_verify(&f->c, in, f->c.inputs, f->output, f->c.outputs, p->byte, p->count) == LIG_ERR_INSTANCE,
      "lig verify: an input of 2^256 - 1 is an instance error");
  far = (uint64_t)s.rows * s.l;
  row(ok && lig_prove_forced(&f->c, &f->w, SEED_A, &far, 1, &q) == LIG_ERR_WITNESS && q.byte == NULL && q.count == 0,
      "lig prove: a tweak position after the last row is a witness error");
  w.inputs = f->c.inputs - 1;
  row(lig_prove(&f->c, &w, SEED_A, &q) == LIG_ERR_WITNESS && q.byte == NULL,
      "lig prove: a witness with a wrong input count is a witness error");
  zk_init(&c, 1, 1, 0);
  zk_refuse(&c);
  row(lig_params(&c, &s) == LIG_ERR_REFUSED && lig_prove(&c, &f->w, SEED_A, &q) == LIG_ERR_REFUSED && q.byte == NULL &&
          lig_verify(&c, f->input, 1, f->output, 0, p->byte, p->count) == LIG_ERR_REFUSED,
      "lig refused circuit: the sizes, the prover and the verifier give the refused error");
  zk_free(&c);
}

/* The mul that no eq uses: the product is wrong in z and in v (the linear
 * rows hold), then in z only. */
static void dangling_rows(void) {
  Fixture d;
  LigParams s;
  LigProof p = {NULL, 0};
  uint64_t tw[2] = {0, 0};
  int ok;
  fix_dangling(&d);
  ok = lig_params(&d.c, &s) == LIG_OK;
  tw[0] = lig_at_z(&s, 0);
  tw[1] = lig_at_value(&s, d.mul);
  row(ok && lig_prove(&d.c, &d.w, SEED_A, &p) == LIG_OK && own_verify(&d, &p) == LIG_OK,
      "lig dangling accepts: the proof of the true product verifies");
  lig_proof_free(&p);
  row(ok && lig_prove_forced(&d.c, &d.w, SEED_A, tw, 2, &p) == LIG_OK && own_verify(&d, &p) == LIG_ERR_QUAD_ZERO,
      "lig dangling refuses: a wrong product in z and v fails the quadratic test on H");
  lig_proof_free(&p);
  row(ok && lig_prove_forced(&d.c, &d.w, SEED_A, tw, 1, &p) == LIG_OK && own_verify(&d, &p) == LIG_ERR_LINEAR_SUM,
      "lig dangling refuses: a wrong z only fails the linear sum");
  lig_proof_free(&p);
  zk_free(&d.c);
}

/* The verifier result for the forced proof of F with the witness tweaks TW
 * and the change M1 of the mask m1 (NULL for none); the prover error when the
 * prover refuses. */
static LigErr tweaked(const Fixture *f, const uint64_t *tw, size_t tws, const ZkFr *m1) {
  LigBend b;
  LigProof p = {NULL, 0};
  LigErr e;
  memset(&b, 0, sizeof b);
  b.m1_add = m1;
  e = lig_prove_bent(&f->c, &f->w, SEED_A, tw, tws, &b, &p);
  if (e == LIG_OK) e = own_verify(f, &p);
  lig_proof_free(&p);
  return e;
}

/* Row c of the linear test has the power sigma^(c+1). The 12 tweaks make the
 * dangling witness of the input 4 (the value 0 and x are 4, z and the product
 * are 20) for the public input 3: the row 0 (the value 0 is the input 0) is
 * the only false row, and its error is 1. The sum over H less the right side
 * is then sigma + k M1. With M1 = -1/k that is sigma - 1, so the verifier
 * refuses. With powers from sigma^0 it is 1 + k M1 = 0 for each sigma: the
 * mask hides the false row. */
static void sigma_rows(void) {
  const ZkFr zero = zk_fr_u64(0), minus = fr_minus_one();
  Fixture d;
  LigParams s;
  uint64_t tw[12];
  ZkFr kk, inv, m1, km;
  size_t i;
  int ok;
  fix_dangling(&d);
  memset(&s, 0, sizeof s);
  ok = lig_params(&d.c, &s) == LIG_OK;
  tw[0] = lig_at_value(&s, 0);
  tw[1] = lig_at_x(&s, 0);
  for (i = 0; i < 5; i++) {
    tw[2 + i] = lig_at_z(&s, 0);
    tw[7 + i] = lig_at_value(&s, d.mul);
  }
  kk = zk_fr_u64(s.k);
  inv = zero;
  ok = ok && zk_fr_inv(&kk, &inv);
  m1 = zk_fr_sub(&zero, &inv);
  km = zk_fr_mul(&kk, &m1);
  ok = ok && fr_eq(&km, &minus);
  row(ok && tweaked(&d, tw, 12, NULL) == LIG_ERR_LINEAR_SUM,
      "lig sigma: the witness of the input 4 fails the linear sum for the public input 3");
  row(ok && tweaked(&d, tw, 12, &m1) == LIG_ERR_LINEAR_SUM,
      "lig sigma: a mask m1 with the sum -1 does not hide the false row 0 (the powers start at sigma^1)");
  zk_free(&d.c);
}

/* The prover-side rows (D107 Open (a)): no verifier sees a prover with masks,
 * free values or salts of 0, so these rows read the view of lig_prove_view. */
static int fr_cmp(const void *a, const void *b) {
  const ZkFr *x = a, *y = b;
  return memcmp(x->limb, y->limb, sizeof x->limb);
}

/* The count of the COUNT values A that are 0 or equal to the value before
 * them in the sorted order (A is sorted in place). */
static size_t weak(ZkFr *a, size_t count) {
  const ZkFr zero = zk_fr_u64(0);
  size_t i, bad = 0;
  qsort(a, count, sizeof *a, fr_cmp);
  for (i = 0; i < count; i++) bad += (size_t)(fr_eq(&a[i], &zero) || (i > 0 && fr_eq(&a[i], &a[i - 1])));
  return bad;
}

typedef struct Rand {
  ZkFr *v;      /* the random values by family: free, u0, m1, m2 free, m2 b, salt */
  size_t at[7]; /* the start of each family, then the count of all */
  int shape;    /* 1 when m1 has the sum 0 over H and m2 is 0 on the witness points */
} Rand;

/* *O = the random values of the view VW; 0 when an allocation fails. The free
 * values of a polynomial are its values on the last k - l points of H. m1:
 * each coefficient but the one at k (it is minus the one at 0). m2 = a +
 * (X^k - 1) b: a is the sum of the low half and the high half, b is the high
 * half. */
static int rand_of(const LigParams *s, const LigView *vw, Rand *o) {
  const size_t k = s->k, open = s->k - s->l;
  const size_t size[6] = {s->rows * open, k, 2 * k - 1, open, k, s->n};
  const ZkFr zero = zk_fr_u64(0);
  const ZkFr *m1 = vw->mask + k, *m2 = m1 + 2 * k;
  ZkFr *buf = malloc(k * sizeof *buf), *v, sum;
  size_t r, j;
  for (j = 0, o->at[0] = 0; j < 6; j++) o->at[j + 1] = o->at[j] + size[j];
  o->v = v = malloc(o->at[6] * sizeof *v);
  o->shape = 0;
  if (buf == NULL || v == NULL) {
    free(buf);
    return 0;
  }
  for (r = 0; r < s->rows; r++) {
    memcpy(buf, vw->poly + r * k, k * sizeof *buf);
    (void)zk_ntt(buf, s->log_k);
    memcpy(v + r * open, buf + s->l, open * sizeof *v);
  }
  memcpy(v + o->at[1], vw->mask, k * sizeof *v);
  memcpy(v + o->at[2], m1, k * sizeof *v);
  memcpy(v + o->at[2] + k, m1 + k + 1, (k - 1) * sizeof *v);
  for (j = 0; j < k; j++) buf[j] = zk_fr_add(&m2[j], &m2[k + j]);
  (void)zk_ntt(buf, s->log_k);
  sum = zk_fr_add(&m1[0], &m1[k]);
  o->shape = fr_eq(&sum, &zero);
  for (j = 0; j < s->l; j++) o->shape = o->shape && fr_eq(&buf[j], &zero);
  memcpy(v + o->at[3], buf + s->l, open * sizeof *v);
  memcpy(v + o->at[4], m2 + k, k * sizeof *v);
  memcpy(v + o->at[5], vw->salt, s->n * sizeof *v);
  free(buf);
  return 1;
}

/* The count of the values that are not 0 and occur in X and in Y (X and Y
 * are sorted in place). */
static size_t shared(Rand *x, Rand *y) {
  const size_t nx = x->at[6], ny = y->at[6];
  ZkFr *all = malloc((nx + ny) * sizeof *all);
  size_t both;
  if (all == NULL) return nx + ny;
  memcpy(all, x->v, nx * sizeof *all);
  memcpy(all + nx, y->v, ny * sizeof *all);
  both = weak(all, nx + ny) - weak(x->v, nx) - weak(y->v, ny);
  free(all);
  return both;
}

/* 1 when the arrays of VW give the root in the proof P: the codeword of each
 * row polynomial and of each mask, then a leaf for each column, as in the
 * prover. */
static int view_root(const LigParams *s, const LigView *vw, const LigProof *p) {
  const unsigned log_n = s->log_k + LIG_RATE_LOG;
  const size_t k = s->k, n = s->n, rows = s->rows, len = rows + LIG_COL_EXTRA;
  ZkFr *code = calloc((rows + 3) * n, sizeof *code), *col = malloc(len * sizeof *col);
  uint8_t *leaf = malloc(n * ZK_MERKLE_BYTES);
  ZkMerkle t;
  size_t r, j;
  int ok = code != NULL && col != NULL && leaf != NULL;
  if (ok) {
    for (r = 0; r < rows; r++) memcpy(code + r * n, vw->poly + r * k, k * sizeof *code);
    memcpy(code + rows * n, vw->mask, k * sizeof *code);
    memcpy(code + (rows + 1) * n, vw->mask + k, 2 * k * sizeof *code);
    memcpy(code + (rows + 2) * n, vw->mask + 3 * k, 2 * k * sizeof *code);
    for (r = 0; r < rows + 3; r++) (void)zk_coset_ntt(code + r * n, log_n);
    for (j = 0; j < n; j++) {
      for (r = 0; r < rows + 3; r++) col[r] = code[r * n + j];
      col[len - 1] = vw->salt[j];
      zk_merkle_leaf(col, len, leaf + j * ZK_MERKLE_BYTES);
    }
    ok = zk_merkle_build(&t, log_n, leaf) == ZK_OK;
  }
  if (ok) {
    ok = memcmp(zk_merkle_root(&t), p->byte + P_ROOT, ZK_MERKLE_BYTES) == 0;
    zk_merkle_free(&t);
  }
  free(code);
  free(col);
  free(leaf);
  return ok;
}

/* 1 when the honest prover gives the proof P and the view V of F under SEED,
 * the verifier accepts P, and *O = the random values of V. */
static int viewed(const Fixture *f, const uint8_t *seed, const LigParams *s, LigView *v, LigProof *p, Rand *o) {
  return lig_prove_view(&f->c, &f->w, seed, v, p) == LIG_OK && own_verify(f, p) == LIG_OK && rand_of(s, v, o);
}

static void view_drop(LigView *v, LigProof *p, Rand *o) {
  lig_view_free(v);
  lig_proof_free(p);
  free(o->v);
}

/* The view rows of the fixture F. A family row counts the values of one
 * family that are 0 or occur two times in it; the two-families row counts
 * only a value that is in more than one family. */
static void view_rows(const char *name, const Fixture *f) {
  static const char *const what[6] = {"view: no free value of a witness row is 0 and no two are equal",
                                      "view: no coefficient of u0 is 0 and no two are equal",
                                      "view: no coefficient of m1 but the one at k is 0 and no two are equal",
                                      "view: no free value of m2 is 0 and no two are equal",
                                      "view: no b coefficient of m2 is 0 and no two are equal",
                                      "view: no salt is 0 and no two are equal"};
  LigParams s;
  LigView va = {NULL, NULL, NULL, {0}}, vb = {NULL, NULL, NULL, {0}};
  LigProof pa = {NULL, 0}, pb = {NULL, 0}, plain = {NULL, 0};
  Rand ra = {NULL, {0}, 0}, rb = {NULL, {0}, 0};
  size_t i, in = 0;
  int ok;
  memset(&s, 0, sizeof s);
  ok = lig_params(&f->c, &s) == LIG_OK && viewed(f, SEED_A, &s, &va, &pa, &ra) &&
       viewed(f, SEED_B, &s, &vb, &pb, &rb) && lig_prove(&f->c, &f->w, SEED_A, &plain) == LIG_OK;
  named_row(ok && pa.count == plain.count && memcmp(pa.byte, plain.byte, pa.count) == 0, name,
            "view: lig_prove_view gives the proof bytes of lig_prove");
  named_row(ok && view_root(&s, &va, &pa), name, "view: the arrays of the view give the root of the proof");
  named_row(ok && ra.shape, name, "view: m1 has the sum 0 over H, and m2 is 0 on the witness points of H");
  for (i = 0; i < 6; i++) {
    const size_t bad = ok ? weak(ra.v + ra.at[i], ra.at[i + 1] - ra.at[i]) : 1;
    in += bad;
    named_row(bad == 0, name, what[i]);
  }
  named_row(ok && weak(ra.v, ra.at[6]) == in, name, "view: no random value is in two families");
  named_row(ok && shared(&ra, &rb) == 0, name, "view: a second seed changes each random value");
  named_row(ok && memcmp(pa.byte + P_ROOT, pb.byte + P_ROOT, ZK_MERKLE_BYTES) != 0 &&
                memcmp(va.root_seed, vb.root_seed, sizeof va.root_seed) != 0,
            name, "view: two proofs with different roots have different root seeds");
  view_drop(&va, &pa, &ra);
  view_drop(&vb, &pb, &rb);
  lig_proof_free(&plain);
}

/* The random values depend on the witness (the hedge against a seed that
 * comes two times). The smoke witnesses with the weights 5 and 6 have the
 * same public values (0 times a weight is 0), so only the witness rows
 * differ: with one seed the two views share no random value. */
static void hedge_row(void) {
  Fixture a, b;
  LigParams s;
  LigView va = {NULL, NULL, NULL, {0}}, vb = {NULL, NULL, NULL, {0}};
  LigProof pa = {NULL, 0}, pb = {NULL, 0};
  Rand ra = {NULL, {0}, 0}, rb = {NULL, {0}, 0};
  int ok;
  fix_smoke(&a, 0, 0, 5);
  fix_smoke(&b, 0, 0, 6);
  memset(&s, 0, sizeof s);
  ok = lig_params(&a.c, &s) == LIG_OK && viewed(&a, SEED_A, &s, &va, &pa, &ra) &&
       viewed(&b, SEED_A, &s, &vb, &pb, &rb);
  row(ok && shared(&ra, &rb) == 0,
      "lig view: a second witness with the same public values and seed changes each random value");
  view_drop(&va, &pa, &ra);
  view_drop(&vb, &pb, &rb);
  zk_free(&a.c);
  zk_free(&b.c);
}

/* The verifier result for the proof of the forced prover with the changes
 * (AT, ADD, ADDS) of q and M1 of the mask m1; the prover error when the
 * prover refuses. */
static LigErr bent(const Fixture *f, const uint32_t *at, const ZkFr *add, size_t adds, const ZkFr *m1) {
  LigBend b;
  LigProof p = {NULL, 0};
  LigErr e;
  b.q_at = at;
  b.q_add = add;
  b.q_adds = adds;
  b.m1_add = m1;
  e = lig_prove_bent(&f->c, &f->w, SEED_A, NULL, 0, &b, &p);
  if (e == LIG_OK) e = own_verify(f, &p);
  lig_proof_free(&p);
  return e;
}

/* The forced prover changes q0, q1 or q2 after the masks and before the
 * column hash: the open columns give the root, so each row shows one verifier
 * check alone. The sum of x^j over H is 0 for 0 < j < k, and x^k - 1 is 0 on
 * H. P is the honest proof of F under SEED_A. */
static void bend_rows(const char *name, const Fixture *f, const LigProof *p) {
  const ZkFr one = zk_fr_u64(1), zero = zk_fr_u64(0);
  ZkFr pair[2];
  LigParams s;
  LigBend none;
  LigProof q = {NULL, 0};
  uint32_t at[2] = {0, 0};
  const int ok = lig_params(&f->c, &s) == LIG_OK;
  const uint32_t k = ok ? s.k : 0;
  pair[0] = zk_fr_sub(&zero, &one);
  pair[1] = one;
  memset(&none, 0, sizeof none);
  named_row(ok && lig_prove_bent(&f->c, &f->w, SEED_A, NULL, 0, &none, &q) == LIG_OK && q.count == p->count &&
                memcmp(q.byte, p->byte, p->count) == 0,
            name, "bend: no change gives the bytes of the honest proof");
  lig_proof_free(&q);
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_PROXIMITY, name, "bend: q0 + 1 fails the proximity test");
  at[0] = k - 1;
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_PROXIMITY, name,
            "bend: q0 + x^(k-1) fails the proximity test");
  at[0] = k;
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_LINEAR_SUM, name, "bend: q1 + 1 fails the linear sum");
  at[0] = 2 * k;
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_LINEAR_SUM, name, "bend: q1 + x^k fails the linear sum");
  at[0] = k + 1;
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_LINEAR, name,
            "bend: q1 + x keeps the sum over H and fails the linear test at an open column");
  at[0] = k;
  at[1] = 2 * k;
  named_row(ok && bent(f, at, pair, 2, NULL) == LIG_ERR_LINEAR, name,
            "bend: q1 + x^k - 1 keeps the sum over H and fails the linear test at an open column");
  at[0] = 3 * k;
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_QUAD_ZERO, name, "bend: q2 + 1 is not 0 on H");
  at[1] = 4 * k;
  named_row(ok && bent(f, at, pair, 2, NULL) == LIG_ERR_QUAD, name,
            "bend: q2 + x^k - 1 stays 0 on H and fails the quadratic test at an open column");
  at[0] = 5 * k;
  named_row(ok && bent(f, at, &one, 1, NULL) == LIG_ERR_WITNESS, name,
            "bend: the prover refuses the q position 5 k");
  named_row(ok && bent(f, NULL, NULL, 0, &one) == LIG_ERR_LINEAR_SUM, name,
            "bend: a mask m1 with a sum over H that is not 0 fails the linear sum");
}

static void lig_rows(void) {
  Fixture a, b, bad;
  LigProof smoke = {NULL, 0}, gbits = {NULL, 0};
  fix_smoke(&a, 3, 15, 5);
  fix_smoke(&b, 4, 28, 7);
  fix_smoke(&bad, 3, 15, 6);
  family_rows("smoke", &a, &b, &bad, &smoke);
  tamper_rows(&a, &smoke);
  refusal_rows(&a, &smoke);
  bend_rows("smoke", &a, &smoke);
  view_rows("smoke", &a);
  zk_free(&a.c);
  zk_free(&b.c);
  zk_free(&bad.c);
  fix_gbits(&a, UINT64_MAX);
  fix_gbits(&b, 12345);
  fix_gbits(&bad, UINT64_MAX);
  bad.weight[0] = zk_fr_u64(0); /* the sum of the bits is not x */
  family_rows("gbits", &a, &b, &bad, &gbits);
  bend_rows("gbits", &a, &gbits);
  view_rows("gbits", &a);
  bad.weight[0] = zk_fr_u64(3); /* the sum is x again (3 + 0 for 1 + 2), but 3 is not a bit */
  bad.weight[1] = zk_fr_u64(0);
  named_row(refused(&bad), "gbits", "refuses: the prover refuses a weight 3 with the right sum; the forced proof fails");
  dangling_rows();
  sigma_rows();
  hedge_row();
  if (!failed) printf("lig rows: passed (proof bytes: smoke %zu, gbits %zu)\n", smoke.count, gbits.count);
  lig_proof_free(&smoke);
  lig_proof_free(&gbits);
  zk_free(&a.c);
  zk_free(&b.c);
  zk_free(&bad.c);
}

/* The circuit NAME of the prove and verify modes. 0 when there is no such
 * name. */
static int fix_named(const char *name, Fixture *f) {
  if (strcmp(name, "smoke") == 0) {
    fix_smoke(f, 3, 15, 5);
    return 1;
  }
  if (strcmp(name, "gbits") == 0) {
    fix_gbits(f, UINT64_MAX);
    return 1;
  }
  fprintf(stderr, "ligtool: no circuit %s (smoke, gbits)\n", name);
  return 0;
}

/* SEED = LIG_SEED_BYTES bytes of /dev/urandom. 0 when the read fails. */
static int random_seed(uint8_t seed[LIG_SEED_BYTES]) {
  FILE *in = fopen("/dev/urandom", "rb");
  int ok;
  if (in == NULL) return 0;
  setvbuf(in, NULL, _IONBF, 0);
  ok = fread(seed, 1, (size_t)LIG_SEED_BYTES, in) == (size_t)LIG_SEED_BYTES;
  fclose(in);
  return ok;
}

static int prove_mode(const char *name, const char *path) {
  uint8_t seed[LIG_SEED_BYTES];
  Fixture f;
  LigProof p = {NULL, 0};
  FILE *out;
  LigErr e;
  int ok;
  if (!fix_named(name, &f)) return 2;
  if (!random_seed(seed)) {
    zk_free(&f.c);
    fprintf(stderr, "ligtool: cannot read a seed from /dev/urandom\n");
    return 2;
  }
  e = lig_prove(&f.c, &f.w, seed, &p);
  zk_free(&f.c);
  if (e != LIG_OK) {
    fprintf(stderr, "ligtool: prove %s: %s\n", name, lig_err_text(e));
    return 1;
  }
  out = fopen(path, "wb");
  ok = out != NULL && fwrite(p.byte, 1, p.count, out) == p.count;
  if (out != NULL) ok = fclose(out) == 0 && ok;
  if (ok) printf("%s: %zu proof bytes\n", name, p.count);
  if (!ok) fprintf(stderr, "ligtool: cannot write %s\n", path);
  lig_proof_free(&p);
  return ok ? 0 : 2;
}

static int verify_mode(const char *name, const char *path) {
  Fixture f;
  FILE *in;
  uint8_t *byte = NULL;
  long size = -1;
  size_t got = 0;
  LigErr e;
  if (!fix_named(name, &f)) return 2;
  in = fopen(path, "rb");
  if (in != NULL && fseek(in, 0, SEEK_END) == 0) size = ftell(in);
  if (size >= 0 && fseek(in, 0, SEEK_SET) == 0) byte = malloc((size_t)size + 1);
  if (byte != NULL) got = fread(byte, 1, (size_t)size, in);
  if (in != NULL) fclose(in);
  if (byte == NULL || got != (size_t)size) {
    fprintf(stderr, "ligtool: cannot read %s\n", path);
    free(byte);
    zk_free(&f.c);
    return 2;
  }
  e = lig_verify(&f.c, f.input, f.c.inputs, f.output, f.c.outputs, byte, got);
  free(byte);
  zk_free(&f.c);
  printf("%s: %s\n", name, lig_err_text(e));
  return e == LIG_OK ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "prove") == 0) return prove_mode(argv[2], argv[3]);
  if (argc == 4 && strcmp(argv[1], "verify") == 0) return verify_mode(argv[2], argv[3]);
  if (argc != 1) {
    fprintf(stderr, "use: ligtool [prove NAME FILE | verify NAME FILE]\n");
    return 2;
  }
  fr_rows();
  ntt_rows();
  merkle_rows();
  lig_rows();
  return failed ? 1 : 0;
}
