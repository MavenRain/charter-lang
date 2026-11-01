/* Threshold decryption of a squash LWE: see front/tdec.h. The products of a
 * mask word (2 words) and a share (3 words) use 32-bit halves (C99 has no
 * 128-bit integer). The sum of the 4096 products is below 2^332, so it fits
 * in 6 words and one tshare_reduce gives the value mod p. */
#include "front/tdec.h"

#define MASK32 0xffffffffu

/* (p - 1) / 2, low word first: a value above it is the integer V - p. */
static const TshareFe half = {{0xfffffffffff67000u, 0xffffffffffffffffu, 0x7fffffffffffffffu}};

/* The 128-bit product of A and B as HI and LO. */
static void mul_64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
  uint64_t a0 = a & MASK32, a1 = a >> 32, b0 = b & MASK32, b1 = b >> 32;
  uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
  uint64_t mid = (p00 >> 32) + (p01 & MASK32) + (p10 & MASK32);
  *lo = (mid << 32) | (p00 & MASK32);
  *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

/* ACC + X 2^(64 K): the carry goes up to the top word. */
static void add_at(uint64_t acc[2 * TSHARE_LIMBS], unsigned k, uint64_t x) {
  for (; k < 2 * TSHARE_LIMBS && x != 0; k++) {
    acc[k] += x;
    x = acc[k] < x;
  }
}

/* 1 when V is above (p - 1) / 2. */
static int above_half(TshareFe v) {
  unsigned i = TSHARE_LIMBS;
  while (i > 1 && v.w[i - 1] == half.w[i - 1]) i--;
  return v.w[i - 1] > half.w[i - 1];
}

TshareFe tdec_mask_product(const TshareFe share[SQUASH_BIG_N], const Squash128 mask[SQUASH_BIG_N]) {
  uint64_t acc[2 * TSHARE_LIMBS] = {0}, a[2], hi, lo;
  unsigned j, u, v;
  for (j = 0; j < SQUASH_BIG_N; j++) {
    a[0] = mask[j].lo;
    a[1] = mask[j].hi;
    for (u = 0; u < 2; u++)
      for (v = 0; v < TSHARE_LIMBS; v++) {
        mul_64(a[u], share[j].w[v], &hi, &lo);
        add_at(acc, u + v, lo);
        add_at(acc, u + v + 1, hi);
      }
  }
  return tshare_reduce(acc);
}

void tdec_flood(TshareFe noise[TSHARE_PARTIES], TfheDrbg *d) {
  Squash128 u, e;
  TshareFe lift = {{0, 0, 0}};
  u.lo = tfhe_uniform(d);
  u.hi = tfhe_uniform(d) & ((1ull << (TDEC_FLOOD_LOG + 1 - 64)) - 1u);
  e = squash_sub(u, squash_shl(squash_from_u64(1), TDEC_FLOOD_LOG));
  if (e.hi >> 63) {
    Squash128 m = squash_neg(e);
    lift.w[0] = m.lo;
    lift.w[1] = m.hi;
    lift = tshare_sub(tshare_from_u64(0), lift);
  } else {
    lift.w[0] = e.lo;
    lift.w[1] = e.hi;
  }
  tshare_share(noise, &lift, 1, d);
}

TshareFe tdec_partial(const TshareFe share[SQUASH_BIG_N], const Squash128 mask[SQUASH_BIG_N], const TshareFe *noise,
                      unsigned dealers, unsigned party) {
  TshareFe v = tdec_mask_product(share, mask);
  unsigned j;
  for (j = 0; j < dealers; j++) v = tshare_add(v, noise[j * TSHARE_PARTIES + party - 1]);
  return v;
}

/* The value at 0 of the polynomial of degree t through the partials at the
 * t + 1 positions POS. Returns 0 for a bad subset. */
static int value_at_0(TshareFe *v, const TshareFe *partial, const unsigned *subset,
                      const unsigned pos[TSHARE_THRESHOLD + 1]) {
  TshareFe lambda[TSHARE_THRESHOLD + 1];
  unsigned points[TSHARE_THRESHOLD + 1], i;
  for (i = 0; i <= TSHARE_THRESHOLD; i++) points[i] = subset[pos[i]];
  if (!tshare_lagrange(lambda, points, TSHARE_THRESHOLD + 1)) return 0;
  *v = tshare_from_u64(0);
  for (i = 0; i <= TSHARE_THRESHOLD; i++) *v = tshare_add(*v, tshare_mul(lambda[i], partial[pos[i]]));
  return 1;
}

/* V0 is the value at 0 over the positions 0 to t. For each extra position k,
 * Vk is the value at 0 over the positions 1 to t and k. For the t + 2 points
 * of the positions 0 to t and k, the two values are the same only when the
 * points are on one polynomial of degree t (W/S6-NOTES.md "The U3 design"),
 * so one changed partial gives no phase. */
int tdec_combine(Squash128 *phase, Squash128 body, const TshareFe *partial, const unsigned *subset, unsigned m) {
  TshareFe lambda[TSHARE_PARTIES], v0, vk;
  Squash128 lift;
  unsigned pos[TSHARE_THRESHOLD + 1], i, k;
  if (m <= TSHARE_THRESHOLD || !tshare_lagrange(lambda, subset, m)) return 0;
  for (i = 0; i <= TSHARE_THRESHOLD; i++) pos[i] = i;
  if (!value_at_0(&v0, partial, subset, pos)) return 0;
  for (k = TSHARE_THRESHOLD + 1; k < m; k++) {
    for (i = 0; i < TSHARE_THRESHOLD; i++) pos[i] = i + 1;
    pos[TSHARE_THRESHOLD] = k;
    if (!value_at_0(&vk, partial, subset, pos) || !tshare_eq(vk, v0)) return 0;
  }
  /* The integer V0 - p for V0 above (p - 1) / 2: V0 - p = V0 + 2^192 - p
   * mod 2^128. */
  lift.lo = v0.w[0];
  lift.hi = v0.w[1];
  if (above_half(v0)) lift = squash_add(lift, squash_from_u64(TSHARE_FOLD));
  *phase = squash_sub(body, lift);
  return 1;
}

unsigned tdec_decode(Squash128 phase) {
  return (unsigned)(squash_shr(squash_add(phase, squash_shl(squash_from_u64(1), SQUASH_DELTA_LOG - 1)),
                               SQUASH_DELTA_LOG)
                        .lo &
                    31u);
}
