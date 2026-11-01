/* 128-bit words and the products over Z/2^128: see front/squash.h. The
 * 64-bit products use 32-bit halves (C99 has no 128-bit integer). */
#include "front/squash.h"

#include <stdlib.h>
#include <string.h>

#define MASK32 0xffffffffu
#define MASK16 0xffffu

/* The 128-bit product of A and B as HI and LO. */
static void mul_64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
  uint64_t a0 = a & MASK32, a1 = a >> 32, b0 = b & MASK32, b1 = b >> 32;
  uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
  uint64_t mid = (p00 >> 32) + (p01 & MASK32) + (p10 & MASK32);
  *lo = (mid << 32) | (p00 & MASK32);
  *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

Squash128 squash_from_u64(uint64_t x) {
  Squash128 r;
  r.lo = x;
  r.hi = 0;
  return r;
}

Squash128 squash_from_i64(int64_t x) {
  Squash128 r;
  r.lo = (uint64_t)x;
  r.hi = x < 0 ? ~(uint64_t)0 : 0;
  return r;
}

int squash_eq(Squash128 a, Squash128 b) { return a.lo == b.lo && a.hi == b.hi; }

Squash128 squash_add(Squash128 a, Squash128 b) {
  Squash128 r;
  r.lo = a.lo + b.lo;
  r.hi = a.hi + b.hi + (r.lo < a.lo);
  return r;
}

Squash128 squash_sub(Squash128 a, Squash128 b) {
  Squash128 r;
  r.lo = a.lo - b.lo;
  r.hi = a.hi - b.hi - (a.lo < b.lo);
  return r;
}

Squash128 squash_neg(Squash128 a) { return squash_sub(squash_from_u64(0), a); }

Squash128 squash_mul(Squash128 a, Squash128 b) {
  Squash128 r;
  mul_64(a.lo, b.lo, &r.hi, &r.lo);
  r.hi += a.lo * b.hi + a.hi * b.lo;
  return r;
}

Squash128 squash_shl(Squash128 a, unsigned s) {
  Squash128 r;
  if (s == 0) return a;
  if (s >= 64) {
    r.hi = a.lo << (s - 64);
    r.lo = 0;
    return r;
  }
  r.hi = (a.hi << s) | (a.lo >> (64 - s));
  r.lo = a.lo << s;
  return r;
}

Squash128 squash_shr(Squash128 a, unsigned s) {
  Squash128 r;
  if (s == 0) return a;
  if (s >= 64) {
    r.lo = a.hi >> (s - 64);
    r.hi = 0;
    return r;
  }
  r.lo = (a.lo >> s) | (a.hi << (64 - s));
  r.hi = a.hi >> s;
  return r;
}

Squash128 squash_uniform(TfheDrbg *d) {
  Squash128 r;
  r.lo = tfhe_uniform(d);
  r.hi = tfhe_uniform(d);
  return r;
}

Squash128 squash_tuniform(TfheDrbg *d, unsigned bound_log) {
  return squash_from_i64((int64_t)tfhe_tuniform(d, bound_log));
}

void squash_poly_mul_exact(Squash128 out[SQUASH_POLY_N], const Squash128 a[SQUASH_POLY_N],
                           const int64_t b[SQUASH_POLY_N]) {
  unsigned i, j;
  for (j = 0; j < SQUASH_POLY_N; j++) out[j] = squash_from_u64(0);
  for (i = 0; i < SQUASH_POLY_N; i++) {
    Squash128 bi = squash_from_i64(b[i]);
    if (b[i] != 0) {
      /* X^i X^j = -X^(i + j - N) when i + j is N or more. */
      for (j = 0; j < SQUASH_POLY_N - i; j++) out[i + j] = squash_add(out[i + j], squash_mul(a[j], bi));
      for (j = SQUASH_POLY_N - i; j < SQUASH_POLY_N; j++)
        out[i + j - SQUASH_POLY_N] = squash_sub(out[i + j - SQUASH_POLY_N], squash_mul(a[j], bi));
    }
  }
}

/* The balanced 16-bit limbs of A: A = sum limb[i] 2^(16 i) mod 2^128, each
 * limb in [-2^15, 2^15). The carry out of limb 7 is 2^128, that is 0. */
static void limbs_16(int64_t limb[SQUASH_LIMBS], Squash128 a) {
  unsigned i;
  int64_t carry = 0;
  for (i = 0; i < SQUASH_LIMBS; i++) {
    uint64_t word = i < SQUASH_LIMBS / 2 ? a.lo : a.hi;
    int64_t v = (int64_t)((word >> (16 * (i % (SQUASH_LIMBS / 2)))) & MASK16) + carry;
    carry = v >= 32768;
    limb[i] = v - 65536 * carry;
  }
}

/* The 8 limbs of the words A: WORD[0] to WORD[7], then IN[0] to IN[7]. */
static void word_limbs_forward(const TfheFft *f, SquashFftWork *w, const Squash128 a[SQUASH_POLY_N]) {
  unsigned i, j;
  for (j = 0; j < SQUASH_POLY_N; j++) {
    int64_t limb[SQUASH_LIMBS];
    limbs_16(limb, a[j]);
    for (i = 0; i < SQUASH_LIMBS; i++) w->word[i][j] = (uint64_t)limb[i];
  }
  for (i = 0; i < SQUASH_LIMBS; i++) tfhe_fft_forward(f, &w->in[i], w->word[i]);
}

/* The 2 limbs of the values B, b = b0 + b1 2^16 with b0 in [-2^15, 2^15):
 * WORD[8] and WORD[9], then IN[8] and IN[9]. */
static void digit_limbs_forward(const TfheFft *f, SquashFftWork *w, const int64_t b[SQUASH_POLY_N]) {
  unsigned j;
  for (j = 0; j < SQUASH_POLY_N; j++) {
    int64_t b0 = (int64_t)(((uint64_t)b[j] + 32768u) & MASK16) - 32768;
    w->word[SQUASH_LIMBS][j] = (uint64_t)b0;
    w->word[SQUASH_LIMBS + 1][j] = (uint64_t)((b[j] - b0) / 65536);
  }
  tfhe_fft_forward(f, &w->in[SQUASH_LIMBS], w->word[SQUASH_LIMBS]);
  tfhe_fft_forward(f, &w->in[SQUASH_LIMBS + 1], w->word[SQUASH_LIMBS + 1]);
}

/* ACC[k] += limb sum k = A_k b0 + A_(k - 1) b1. */
static void limb_sums_add(TfheFourier acc[SQUASH_LIMBS], const SquashFftWork *w) {
  unsigned i;
  for (i = 0; i < SQUASH_LIMBS; i++) {
    tfhe_fourier_mul_add(&acc[i], &w->in[i], w->in[SQUASH_LIMBS].re, w->in[SQUASH_LIMBS].im);
    if (i > 0) tfhe_fourier_mul_add(&acc[i], &w->in[i - 1], w->in[SQUASH_LIMBS + 1].re, w->in[SQUASH_LIMBS + 1].im);
  }
}

/* OUT = the sum of the inverse of ACC[k] times 2^(16 k), mod 2^128. ACC is
 * changed. */
static void limb_sums_back(const TfheFft *f, SquashFftWork *w, Squash128 out[SQUASH_POLY_N],
                           TfheFourier acc[SQUASH_LIMBS]) {
  unsigned i, j;
  for (j = 0; j < SQUASH_POLY_N; j++) out[j] = squash_from_u64(0);
  for (i = 0; i < SQUASH_LIMBS; i++) {
    memset(w->word[0], 0, sizeof w->word[0]);
    tfhe_fft_backward_add(f, w->word[0], &acc[i]);
    for (j = 0; j < SQUASH_POLY_N; j++)
      out[j] = squash_add(out[j], squash_shl(squash_from_i64((int64_t)w->word[0][j]), 16 * i));
  }
}

void squash_poly_mul_fft(const TfheFft *f, SquashFftWork *w, Squash128 out[SQUASH_POLY_N],
                         const Squash128 a[SQUASH_POLY_N], const int64_t b[SQUASH_POLY_N]) {
  word_limbs_forward(f, w, a);
  digit_limbs_forward(f, w, b);
  memset(w->acc, 0, sizeof w->acc);
  limb_sums_add(w->acc, w);
  limb_sums_back(f, w, out, w->acc);
}

void squash_key_generate(SquashKey *k, TfheDrbg *d) {
  unsigned i, j;
  for (i = 0; i < SQUASH_GLWE_K; i++)
    for (j = 0; j < SQUASH_POLY_N; j++) k->s[i][j] = (int64_t)(tfhe_drbg_bytes(d, 1) & 1u);
}

void squash_glwe_encrypt(const TfheFft *f, SquashFftWork *w, Squash128 ct[SQUASH_GLWE_WORDS], const SquashKey *k,
                         const Squash128 *m, TfheDrbg *d) {
  Squash128 *body = ct + SQUASH_GLWE_K * SQUASH_POLY_N;
  unsigned i, j;
  for (j = 0; j < SQUASH_GLWE_K * SQUASH_POLY_N; j++) ct[j] = squash_uniform(d);
  for (j = 0; j < SQUASH_POLY_N; j++) body[j] = m != NULL ? m[j] : squash_from_u64(0);
  for (i = 0; i < SQUASH_GLWE_K; i++) {
    squash_poly_mul_fft(f, w, w->prod, ct + i * SQUASH_POLY_N, k->s[i]);
    for (j = 0; j < SQUASH_POLY_N; j++) body[j] = squash_add(body[j], w->prod[j]);
  }
  for (j = 0; j < SQUASH_POLY_N; j++) body[j] = squash_add(body[j], squash_tuniform(d, SQUASH_NOISE));
}

void squash_glwe_phase(const TfheFft *f, SquashFftWork *w, Squash128 out[SQUASH_POLY_N],
                       const Squash128 ct[SQUASH_GLWE_WORDS], const SquashKey *k) {
  unsigned i, j;
  for (j = 0; j < SQUASH_POLY_N; j++) out[j] = ct[SQUASH_GLWE_K * SQUASH_POLY_N + j];
  for (i = 0; i < SQUASH_GLWE_K; i++) {
    squash_poly_mul_fft(f, w, w->prod, ct + i * SQUASH_POLY_N, k->s[i]);
    for (j = 0; j < SQUASH_POLY_N; j++) out[j] = squash_sub(out[j], w->prod[j]);
  }
}

/* A >> S with copies of the sign bit (S below 64): the complement of the
 * logical shift of the complement for a negative A. */
static Squash128 sar_128(Squash128 a, unsigned s) {
  Squash128 r;
  if (!(a.hi >> 63)) return squash_shr(a, s);
  a.lo = ~a.lo;
  a.hi = ~a.hi;
  r = squash_shr(a, s);
  r.lo = ~r.lo;
  r.hi = ~r.hi;
  return r;
}

void squash_decompose(int64_t digits[SQUASH_LEVEL], Squash128 x) {
  const unsigned rep = SQUASH_BASE_LOG * SQUASH_LEVEL; /* 72 bits: 56 bits are not representable */
  const uint64_t base_mask = ((uint64_t)1 << SQUASH_BASE_LOG) - 1u;
  Squash128 state = squash_shr(x, 128u - rep - 1u);
  uint64_t rounding_bit = state.lo & 1u, need_balance, low_less_one;
  unsigned l;
  /* init_decomposer_state: add the half interval, drop the rounding bit, keep
   * the low 72 bits, then take 2^72 off when the state is above 2^71 (or at
   * 2^71 with the rounding bit set). Bit 71 is bit 7 of the high word. */
  state = squash_shr(squash_add(state, squash_from_u64(1)), 1);
  state.hi &= ((uint64_t)1 << (rep - 64u)) - 1u;
  low_less_one = state.hi - (state.lo == 0);
  need_balance = ((low_less_one | (rounding_bit << (rep - 65u))) & state.hi) >> (rep - 65u);
  state = squash_sub(state, squash_shl(squash_from_u64(need_balance), rep));
  /* decompose_one_level, the least significant level first: the carry is 1
   * when the digit is above 2^23, or at 2^23 with bit 23 of the next state set. */
  for (l = SQUASH_LEVEL; l > 0; l--) {
    uint64_t res = state.lo & base_mask, carry;
    state = sar_128(state, SQUASH_BASE_LOG);
    carry = (((res - 1u) | state.lo) & res) >> (SQUASH_BASE_LOG - 1u);
    state = squash_add(state, squash_from_u64(carry));
    digits[l - 1u] = (int64_t)res - (int64_t)(carry << SQUASH_BASE_LOG);
  }
}

void squash_ggsw_encrypt(const TfheFft *f, SquashFftWork *w, Squash128 *ggsw, const SquashKey *k, int64_t m,
                         TfheDrbg *d) {
  unsigned l, i, j;
  for (l = 1; l <= SQUASH_LEVEL; l++) {
    Squash128 delta_m = squash_mul(squash_from_i64(m), squash_shl(squash_from_u64(1), 128u - SQUASH_BASE_LOG * l));
    for (i = 0; i <= SQUASH_GLWE_K; i++) {
      Squash128 *ct = ggsw + ((size_t)(l - 1u) * (SQUASH_GLWE_K + 1) + i) * SQUASH_GLWE_WORDS;
      Squash128 *body = ct + SQUASH_GLWE_K * SQUASH_POLY_N;
      squash_glwe_encrypt(f, w, ct, k, NULL, d);
      if (i == SQUASH_GLWE_K) {
        body[0] = squash_add(body[0], delta_m);
      } else {
        for (j = 0; j < SQUASH_POLY_N; j++)
          if (k->s[i][j] != 0) body[j] = squash_sub(body[j], delta_m);
      }
    }
  }
}

void squash_external_product(const TfheFft *f, SquashExtWork *w, Squash128 out[SQUASH_GLWE_WORDS],
                             const Squash128 *ggsw, const Squash128 glwe[SQUASH_GLWE_WORDS]) {
  int64_t digits[SQUASH_LEVEL];
  unsigned l, i, t, j, row;
  /* Level l + 1 of poly i multiplies row l (K + 1) + i. */
  for (i = 0; i <= SQUASH_GLWE_K; i++)
    for (j = 0; j < SQUASH_POLY_N; j++) {
      squash_decompose(digits, glwe[i * SQUASH_POLY_N + j]);
      for (l = 0; l < SQUASH_LEVEL; l++) w->digit[l * (SQUASH_GLWE_K + 1) + i][j] = digits[l];
    }
  memset(w->acc, 0, sizeof w->acc);
  for (row = 0; row < SQUASH_GGSW_ROWS; row++) {
    digit_limbs_forward(f, &w->mul, w->digit[row]);
    for (t = 0; t <= SQUASH_GLWE_K; t++) {
      word_limbs_forward(f, &w->mul, ggsw + ((size_t)row * (SQUASH_GLWE_K + 1) + t) * SQUASH_POLY_N);
      limb_sums_add(w->acc[t], &w->mul);
    }
  }
  for (t = 0; t <= SQUASH_GLWE_K; t++) limb_sums_back(f, &w->mul, out + t * SQUASH_POLY_N, w->acc[t]);
}

int squash_bsk_generate(SquashBsk *b, const TfheFft *f, SquashFftWork *w, const SquashKey *k,
                        const uint64_t lwe_key[TFHE_LWE_N], TfheDrbg *d) {
  unsigned i;
  b->ggsw = malloc((size_t)SQUASH_BSK_WORDS * sizeof b->ggsw[0]);
  if (b->ggsw == NULL) return 0;
  for (i = 0; i < TFHE_LWE_N; i++)
    squash_ggsw_encrypt(f, w, b->ggsw + (size_t)i * SQUASH_GGSW_WORDS, k, (int64_t)lwe_key[i], d);
  return 1;
}

void squash_bsk_release(SquashBsk *b) {
  free(b->ggsw);
  b->ggsw = NULL;
}

void squash_lut(Squash128 lut[SQUASH_POLY_N]) {
  const unsigned box = SQUASH_POLY_N / TFHE_PLAIN, half = box / 2u;
  unsigned j;
  for (j = 0; j < SQUASH_POLY_N; j++) {
    unsigned src = j + half;
    if (src < SQUASH_POLY_N) lut[j] = squash_shl(squash_from_u64(src / box), SQUASH_DELTA_LOG);
    else lut[j] = squash_neg(squash_shl(squash_from_u64((src - SQUASH_POLY_N) / box), SQUASH_DELTA_LOG));
  }
}

/* OUT = X^POWER IN mod (X^N + 1), POWER < 2N (the S5 poly_monomial_mul). */
static void monomial_mul(Squash128 *out, const Squash128 *in, unsigned power) {
  unsigned j;
  for (j = 0; j < SQUASH_POLY_N; j++) {
    unsigned k = j + power;
    if (k >= 2u * SQUASH_POLY_N) k -= 2u * SQUASH_POLY_N;
    if (k < SQUASH_POLY_N) out[k] = in[j];
    else out[k - SQUASH_POLY_N] = squash_neg(in[j]);
  }
}

void squash_blind_rotate(const TfheFft *f, SquashPbsWork *w, const uint64_t switched[TFHE_LWE_N + 1],
                         const Squash128 lut[SQUASH_POLY_N], const SquashBsk *b) {
  Squash128 *body = w->acc + SQUASH_GLWE_K * SQUASH_POLY_N;
  unsigned i, j, p, b_body = (unsigned)switched[TFHE_LWE_N];
  for (j = 0; j < SQUASH_GLWE_K * SQUASH_POLY_N; j++) w->acc[j] = squash_from_u64(0);
  monomial_mul(body, lut, b_body == 0 ? 0u : 2u * SQUASH_POLY_N - b_body);
  for (i = 0; i < TFHE_LWE_N; i++) {
    unsigned a = (unsigned)switched[i];
    if (a == 0) continue;
    for (p = 0; p <= SQUASH_GLWE_K; p++) monomial_mul(w->diff + p * SQUASH_POLY_N, w->acc + p * SQUASH_POLY_N, a);
    for (j = 0; j < SQUASH_GLWE_WORDS; j++) w->diff[j] = squash_sub(w->diff[j], w->acc[j]);
    squash_external_product(f, &w->ext, w->prod, b->ggsw + (size_t)i * SQUASH_GGSW_WORDS, w->diff);
    for (j = 0; j < SQUASH_GLWE_WORDS; j++) w->acc[j] = squash_add(w->acc[j], w->prod[j]);
  }
}

void squash_sample_extract(Squash128 out[SQUASH_BIG_N + 1], const Squash128 acc[SQUASH_GLWE_WORDS]) {
  unsigned i, j;
  for (i = 0; i < SQUASH_GLWE_K; i++) {
    const Squash128 *mask = acc + i * SQUASH_POLY_N;
    out[i * SQUASH_POLY_N] = mask[0];
    for (j = 1; j < SQUASH_POLY_N; j++) out[i * SQUASH_POLY_N + j] = squash_neg(mask[SQUASH_POLY_N - j]);
  }
  out[SQUASH_BIG_N] = acc[SQUASH_GLWE_K * SQUASH_POLY_N];
}

void squash_pbs(const TfheFft *f, SquashPbsWork *w, Squash128 out[SQUASH_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1],
                const uint64_t *ksk, const SquashBsk *b) {
  uint64_t small[TFHE_LWE_N + 1], switched[TFHE_LWE_N + 1];
  tfhe_keyswitch(small, in, ksk);
  tfhe_modulus_switch(switched, small);
  squash_lut(w->lut);
  squash_blind_rotate(f, w, switched, w->lut, b);
  squash_sample_extract(out, w->acc);
}

void squash_poly_mul_ntt(const TshareNtt *t, SquashNttWork *w, Squash128 out[SQUASH_POLY_N],
                         const Squash128 a[SQUASH_POLY_N], const int64_t b[SQUASH_POLY_N]) {
  unsigned j;
  for (j = 0; j < SQUASH_POLY_N; j++) {
    w->a[j].w[0] = a[j].lo;
    w->a[j].w[1] = a[j].hi;
    w->a[j].w[2] = 0;
    w->b[j] = tshare_from_i64(b[j]);
  }
  tshare_poly_mul(t, w->c, w->a, w->b);
  /* A value R of 2^191 or more is the negative integer R - p, and
   * R - p = R + (2^192 - p) mod 2^128. */
  for (j = 0; j < SQUASH_POLY_N; j++) {
    Squash128 r;
    r.lo = w->c[j].w[0];
    r.hi = w->c[j].w[1];
    out[j] = w->c[j].w[2] >> 63 ? squash_add(r, squash_from_u64(TSHARE_FOLD)) : r;
  }
}
