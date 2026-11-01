/* Threshold sharing over F_p: see front/tshare.h. The 64-bit products use
 * 32-bit halves (C99 has no 128-bit integer). The reduction uses the form of
 * p: 2^192 = K mod p with K = TSHARE_FOLD. */
#include "front/tshare.h"

#include <string.h>

#define MASK32 0xffffffffu

/* p, the 2^13-th root z^c of the Tonelli-Shanks step (z = 3, a non-square)
 * and w = z^(2c), the root of order 4096 (W/S6-NOTES.md "Session U1"). */
static const TshareFe modulus = {{0xffffffffffece001u, 0xffffffffffffffffu, 0xffffffffffffffffu}};
static const TshareFe root_2_13 = {{0x55c366db82a45ac4u, 0x7ca1c6e387f18d80u, 0x41293630fa2fe3c1u}};
static const TshareFe root_4096 = {{0xe75d52229f54f707u, 0x0e0c65eb40ea8eb7u, 0x685087336483cf4fu}};

/* The 128-bit product of A and B as HI and LO. */
static void mul_64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
  uint64_t a0 = a & MASK32, a1 = a >> 32, b0 = b & MASK32, b1 = b >> 32;
  uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
  uint64_t mid = (p00 >> 32) + (p01 & MASK32) + (p10 & MASK32);
  *lo = (mid << 32) | (p00 & MASK32);
  *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

/* T + K. Returns the carry out of 2^192: 1 when T is p or more, and then OUT
 * is T - p. */
static unsigned add_fold(uint64_t out[TSHARE_LIMBS], const uint64_t t[TSHARE_LIMBS]) {
  uint64_t carry;
  out[0] = t[0] + TSHARE_FOLD;
  carry = out[0] < TSHARE_FOLD;
  out[1] = t[1] + carry;
  carry = out[1] < carry;
  out[2] = t[2] + carry;
  return out[2] < carry;
}

/* A value T below 2^192 to a field element: T - p when T is p or more. */
static TshareFe canonical(const uint64_t t[TSHARE_LIMBS]) {
  TshareFe r;
  uint64_t u[TSHARE_LIMBS];
  if (add_fold(u, t)) {
    memcpy(r.w, u, sizeof r.w);
  } else {
    memcpy(r.w, t, sizeof r.w);
  }
  return r;
}

TshareFe tshare_from_u64(uint64_t x) {
  TshareFe r = {{x, 0, 0}};
  return r;
}

TshareFe tshare_from_i64(int64_t x) {
  if (x >= 0) return tshare_from_u64((uint64_t)x);
  return tshare_sub(tshare_from_u64(0), tshare_from_u64(0u - (uint64_t)x));
}

TshareFe tshare_root(void) {
  return root_4096;
}

int tshare_eq(TshareFe a, TshareFe b) {
  return a.w[0] == b.w[0] && a.w[1] == b.w[1] && a.w[2] == b.w[2];
}

/* A + B is below 2p. On a carry out of 2^192, the sum less p is the low 192
 * bits plus K, below p. */
TshareFe tshare_add(TshareFe a, TshareFe b) {
  uint64_t t[TSHARE_LIMBS], carry = 0, s;
  unsigned i;
  for (i = 0; i < TSHARE_LIMBS; i++) {
    s = a.w[i] + carry;
    carry = s < carry;
    t[i] = s + b.w[i];
    carry += t[i] < s;
  }
  if (carry) {
    TshareFe r;
    add_fold(r.w, t);
    return r;
  }
  return canonical(t);
}

/* On a borrow, the difference plus p is the low 192 bits less K. */
TshareFe tshare_sub(TshareFe a, TshareFe b) {
  TshareFe r;
  uint64_t borrow = 0, d;
  unsigned i;
  for (i = 0; i < TSHARE_LIMBS; i++) {
    d = a.w[i] - borrow;
    borrow = a.w[i] < borrow;
    r.w[i] = d - b.w[i];
    borrow += d < b.w[i];
  }
  if (borrow) {
    borrow = r.w[0] < TSHARE_FOLD;
    r.w[0] -= TSHARE_FOLD;
    d = r.w[1] < borrow;
    r.w[1] -= borrow;
    r.w[2] -= d;
  }
  return r;
}

void tshare_mul_wide(uint64_t out[2 * TSHARE_LIMBS], TshareFe a, TshareFe b) {
  unsigned i, j;
  for (i = 0; i < 2 * TSHARE_LIMBS; i++) out[i] = 0;
  for (i = 0; i < TSHARE_LIMBS; i++) {
    uint64_t carry = 0;
    for (j = 0; j < TSHARE_LIMBS; j++) {
      uint64_t hi, lo;
      mul_64(a.w[i], b.w[j], &hi, &lo);
      lo += carry;
      hi += lo < carry;
      lo += out[i + j];
      hi += lo < out[i + j];
      out[i + j] = lo;
      carry = hi;
    }
    out[i + TSHARE_LIMBS] = carry;
  }
}

/* X = H 2^192 + L = H K + L mod p. The first fold gives a value below 2^214,
 * the second a value below 2^192 + 2^43. A last carry out of 2^192 leaves low
 * bits below 2^43, so the sum with K has no carry. */
TshareFe tshare_reduce(const uint64_t x[2 * TSHARE_LIMBS]) {
  uint64_t t[TSHARE_LIMBS], carry = 0, hi, lo;
  unsigned i;
  for (i = 0; i < TSHARE_LIMBS; i++) {
    mul_64(x[i + TSHARE_LIMBS], TSHARE_FOLD, &hi, &lo);
    lo += carry;
    hi += lo < carry;
    lo += x[i];
    hi += lo < x[i];
    t[i] = lo;
    carry = hi;
  }
  lo = carry * TSHARE_FOLD;
  t[0] += lo;
  carry = t[0] < lo;
  for (i = 1; i < TSHARE_LIMBS; i++) {
    t[i] += carry;
    carry = t[i] < carry;
  }
  t[0] += carry * TSHARE_FOLD;
  return canonical(t);
}

TshareFe tshare_mul(TshareFe a, TshareFe b) {
  uint64_t x[2 * TSHARE_LIMBS];
  tshare_mul_wide(x, a, b);
  return tshare_reduce(x);
}

TshareFe tshare_pow(TshareFe a, const uint64_t e[TSHARE_LIMBS]) {
  TshareFe r = tshare_from_u64(1);
  int bit;
  for (bit = 64 * TSHARE_LIMBS - 1; bit >= 0; bit--) {
    r = tshare_mul(r, r);
    if ((e[bit / 64] >> (bit % 64)) & 1u) r = tshare_mul(r, a);
  }
  return r;
}

TshareFe tshare_inverse(TshareFe a) {
  uint64_t e[TSHARE_LIMBS];
  memcpy(e, modulus.w, sizeof e);
  e[0] -= 2;
  return tshare_pow(a, e);
}

/* p - 1 = q 2^13 with q odd. Each step finds the least i with t^(2^i) = 1;
 * when no i below m has it, A is not a square. */
int tshare_sqrt(TshareFe *root, TshareFe a) {
  const TshareFe one = tshare_from_u64(1);
  uint64_t q[TSHARE_LIMBS], half[TSHARE_LIMBS];
  TshareFe c = root_2_13, t, r;
  unsigned m = TSHARE_TWO_ADICITY, i, j;
  if (tshare_eq(a, tshare_from_u64(0))) {
    *root = a;
    return 1;
  }
  for (i = 0; i < TSHARE_LIMBS; i++) {
    uint64_t next = i + 1 < TSHARE_LIMBS ? modulus.w[i + 1] : 0;
    q[i] = (modulus.w[i] >> TSHARE_TWO_ADICITY) | (next << (64 - TSHARE_TWO_ADICITY));
  }
  for (i = 0; i < TSHARE_LIMBS; i++) {
    uint64_t next = i + 1 < TSHARE_LIMBS ? q[i + 1] : 0;
    half[i] = (q[i] >> 1) | (next << 63);
  }
  half[0] += 1; /* q = 2h + 1, so (q + 1) / 2 = h + 1 */
  t = tshare_pow(a, q);
  r = tshare_pow(a, half);
  while (!tshare_eq(t, one)) {
    TshareFe u = t, b = c;
    for (i = 1; i < m; i++) {
      u = tshare_mul(u, u);
      if (tshare_eq(u, one)) break;
    }
    if (i == m) return 0;
    for (j = 0; j + i + 1 < m; j++) b = tshare_mul(b, b);
    m = i;
    c = tshare_mul(b, b);
    t = tshare_mul(t, c);
    r = tshare_mul(r, b);
  }
  *root = r;
  return 1;
}

TshareFe tshare_random(TfheDrbg *d) {
  for (;;) {
    TshareFe r;
    uint64_t u[TSHARE_LIMBS];
    unsigned i;
    for (i = 0; i < TSHARE_LIMBS; i++) r.w[i] = tfhe_uniform(d);
    if (!add_fold(u, r.w)) return r;
  }
}

void tshare_bytes(uint8_t out[TSHARE_BYTES], TshareFe a) {
  unsigned i;
  for (i = 0; i < TSHARE_BYTES; i++) out[i] = (uint8_t)(a.w[i / 8] >> (8u * (i % 8)));
}

static unsigned bit_reverse(unsigned k) {
  unsigned r = 0, i;
  for (i = 0; i < TSHARE_LOG_N; i++) r |= ((k >> i) & 1u) << (TSHARE_LOG_N - 1 - i);
  return r;
}

/* w^-x = -w^(N - x) for 0 < x < N, as w^N = -1. */
void tshare_ntt_init(TshareNtt *t) {
  TshareFe power[TSHARE_N];
  unsigned k;
  power[0] = tshare_from_u64(1);
  for (k = 1; k < TSHARE_N; k++) power[k] = tshare_mul(power[k - 1], root_4096);
  for (k = 0; k < TSHARE_N; k++) {
    unsigned x = bit_reverse(k);
    t->zeta[k] = power[x];
    t->zeta_inv[k] = x == 0 ? power[0] : tshare_sub(tshare_from_u64(0), power[TSHARE_N - x]);
  }
  t->n_inv = tshare_inverse(tshare_from_u64(TSHARE_N));
}

/* The stage with half size LEN has N / (2 LEN) blocks; block b starts at
 * 2 LEN b and uses zeta[blocks + b]. */
void tshare_ntt_forward(const TshareNtt *t, TshareFe a[TSHARE_N]) {
  unsigned len, b, j;
  for (len = TSHARE_N / 2; len > 0; len >>= 1) {
    unsigned blocks = TSHARE_N / (2 * len);
    for (b = 0; b < blocks; b++) {
      TshareFe zeta = t->zeta[blocks + b];
      for (j = 2 * len * b; j < 2 * len * b + len; j++) {
        TshareFe u = a[j], v = tshare_mul(zeta, a[j + len]);
        a[j] = tshare_add(u, v);
        a[j + len] = tshare_sub(u, v);
      }
    }
  }
}

void tshare_ntt_inverse(const TshareNtt *t, TshareFe a[TSHARE_N]) {
  unsigned len, b, j;
  for (len = 1; len < TSHARE_N; len <<= 1) {
    unsigned blocks = TSHARE_N / (2 * len);
    for (b = 0; b < blocks; b++) {
      TshareFe zeta = t->zeta_inv[blocks + b];
      for (j = 2 * len * b; j < 2 * len * b + len; j++) {
        TshareFe u = a[j], v = a[j + len];
        a[j] = tshare_add(u, v);
        a[j + len] = tshare_mul(zeta, tshare_sub(u, v));
      }
    }
  }
  for (j = 0; j < TSHARE_N; j++) a[j] = tshare_mul(a[j], t->n_inv);
}

void tshare_poly_mul(const TshareNtt *t, TshareFe out[TSHARE_N], const TshareFe a[TSHARE_N],
                     const TshareFe b[TSHARE_N]) {
  TshareFe tmp[TSHARE_N];
  unsigned j;
  memcpy(tmp, b, sizeof tmp);
  if (out != a) memcpy(out, a, sizeof tmp);
  tshare_ntt_forward(t, out);
  tshare_ntt_forward(t, tmp);
  for (j = 0; j < TSHARE_N; j++) out[j] = tshare_mul(out[j], tmp[j]);
  tshare_ntt_inverse(t, out);
}

void tshare_share(TshareFe *shares, const TshareFe *secret, size_t count, TfheDrbg *d) {
  size_t j;
  unsigned i, e;
  for (j = 0; j < count; j++) {
    TshareFe coef[TSHARE_THRESHOLD + 1];
    coef[0] = secret[j];
    for (e = 1; e <= TSHARE_THRESHOLD; e++) coef[e] = tshare_random(d);
    for (i = 0; i < TSHARE_PARTIES; i++) {
      TshareFe x = tshare_from_u64(i + 1), y = coef[TSHARE_THRESHOLD];
      for (e = TSHARE_THRESHOLD; e > 0; e--) y = tshare_add(tshare_mul(y, x), coef[e - 1]);
      shares[i * count + j] = y;
    }
  }
}

void tshare_commit(uint8_t digest[SHA512_BYTES], unsigned party, const TshareFe *share, size_t count) {
  Sha512 s;
  uint8_t bytes[TSHARE_BYTES];
  size_t j;
  unsigned i;
  for (i = 0; i < 4; i++) bytes[i] = (uint8_t)(party >> (8u * i));
  sha512_init(&s);
  sha512_update(&s, bytes, 4);
  for (j = 0; j < count; j++) {
    tshare_bytes(bytes, share[j]);
    sha512_update(&s, bytes, TSHARE_BYTES);
  }
  sha512_final(&s, digest);
}

/* lambda_i = prod over j != i of x_j / (x_j - x_i). */
int tshare_lagrange(TshareFe *lambda, const unsigned *subset, unsigned m) {
  unsigned i, j;
  if (m == 0 || m > TSHARE_PARTIES) return 0;
  for (i = 0; i < m; i++) {
    if (subset[i] < 1 || subset[i] > TSHARE_PARTIES) return 0;
    for (j = 0; j < i; j++) {
      if (subset[j] == subset[i]) return 0;
    }
  }
  for (i = 0; i < m; i++) {
    TshareFe num = tshare_from_u64(1), den = tshare_from_u64(1);
    for (j = 0; j < m; j++) {
      if (j == i) continue;
      num = tshare_mul(num, tshare_from_u64(subset[j]));
      den = tshare_mul(den, tshare_sub(tshare_from_u64(subset[j]), tshare_from_u64(subset[i])));
    }
    lambda[i] = tshare_mul(num, tshare_inverse(den));
  }
  return 1;
}

int tshare_combine(TshareFe *out, const TshareFe *shares, size_t count, const unsigned *subset, unsigned m,
                   const uint8_t commits[TSHARE_PARTIES][SHA512_BYTES]) {
  TshareFe lambda[TSHARE_PARTIES];
  uint8_t digest[SHA512_BYTES];
  size_t j;
  unsigned i;
  if (m <= TSHARE_THRESHOLD || !tshare_lagrange(lambda, subset, m)) return 0;
  for (i = 0; i < m; i++) {
    tshare_commit(digest, subset[i], shares + (size_t)(subset[i] - 1) * count, count);
    if (memcmp(digest, commits[subset[i] - 1], SHA512_BYTES) != 0) return 0;
  }
  for (j = 0; j < count; j++) {
    TshareFe acc = tshare_from_u64(0);
    for (i = 0; i < m; i++) acc = tshare_add(acc, tshare_mul(lambda[i], shares[(size_t)(subset[i] - 1) * count + j]));
    out[j] = acc;
  }
  return 1;
}
