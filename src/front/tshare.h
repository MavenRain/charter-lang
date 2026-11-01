/* Threshold sharing over a prime field for the S6 key ceremony (docs/PLAN.md
 * 11 Q-S6-2 (b), Q-S6-4 (b), Q-S6-8 (b), Q-S6-9 (b)). The prime is
 * p = c 2^13 + 1 with c = 2^179 - 153, so p = 2^192 - 1253375 and 2^13
 * exactly divides p - 1 (the search is in W/S6-NOTES.md "Session U1"). An
 * element is 3 words of 64 bits, low word first, always below p. The
 * negacyclic NTT of size 2048 uses w, a root of order 4096. Shamir sharing:
 * 5 parties at the points 1 to 5 and a polynomial of degree 2, so 3 shares
 * give the secret and 2 shares do not. Each share vector has a SHA-512
 * commitment, and the combine checks it. The randomness is the S5 test DRBG
 * (front/tfhe.h). */
#ifndef LANG_TSHARE_H
#define LANG_TSHARE_H
#include <stddef.h>
#include <stdint.h>

#include "front/sha512.h"
#include "front/tfhe.h"

enum {
  TSHARE_LIMBS = 3,
  TSHARE_BYTES = 24,
  TSHARE_TWO_ADICITY = 13, /* 2^13 divides p - 1, 2^14 does not */
  TSHARE_FOLD = 1253375,   /* 2^192 - p */
  TSHARE_N = 2048,         /* the NTT size, TFHE_POLY_N */
  TSHARE_LOG_N = 11,
  TSHARE_PARTIES = 5,
  TSHARE_THRESHOLD = 2 /* the degree t: t + 1 shares give the secret */
};

/* An element of F_p: the words of a value below p, low word first. */
typedef struct TshareFe {
  uint64_t w[TSHARE_LIMBS];
} TshareFe;

/* The NTT tables from tshare_ntt_init. Block k (1 to N - 1, in the order of
 * the forward transform) uses zeta[k] = w^brv(k), with brv the 11-bit
 * reversal; zeta_inv[k] is its inverse. */
typedef struct TshareNtt {
  TshareFe zeta[TSHARE_N];
  TshareFe zeta_inv[TSHARE_N];
  TshareFe n_inv;
} TshareNtt;

TshareFe tshare_from_u64(uint64_t x);

/* X mod p: -1 gives p - 1. */
TshareFe tshare_from_i64(int64_t x);

/* W, the root of order 4096 (w^2048 = -1). */
TshareFe tshare_root(void);

int tshare_eq(TshareFe a, TshareFe b);
TshareFe tshare_add(TshareFe a, TshareFe b);
TshareFe tshare_sub(TshareFe a, TshareFe b);

/* The full product of A and B (6 words, low word first, below p^2). */
void tshare_mul_wide(uint64_t out[2 * TSHARE_LIMBS], TshareFe a, TshareFe b);

/* X mod p for a value X below 2^384. */
TshareFe tshare_reduce(const uint64_t x[2 * TSHARE_LIMBS]);

TshareFe tshare_mul(TshareFe a, TshareFe b);

/* A^E for an exponent of 3 words, low word first. */
TshareFe tshare_pow(TshareFe a, const uint64_t e[TSHARE_LIMBS]);

/* A^(p - 2): the inverse of A, and 0 for 0. */
TshareFe tshare_inverse(TshareFe a);

/* Tonelli-Shanks: when A is a square, writes a root R (R^2 = A) and returns
 * 1. Returns 0 when A is not a square. */
int tshare_sqrt(TshareFe *root, TshareFe a);

/* A uniform element: 3 words from D, again while the value is p or more. */
TshareFe tshare_random(TfheDrbg *d);

/* The 24 bytes of A, low byte first. */
void tshare_bytes(uint8_t out[TSHARE_BYTES], TshareFe a);

void tshare_ntt_init(TshareNtt *t);

/* The negacyclic NTT in place (Cooley-Tukey, the output in bit-reversed
 * order) and its inverse (Gentleman-Sande, then the product by 1/N). */
void tshare_ntt_forward(const TshareNtt *t, TshareFe a[TSHARE_N]);
void tshare_ntt_inverse(const TshareNtt *t, TshareFe a[TSHARE_N]);

/* OUT = A B mod (X^N + 1), exact over F_p. OUT may equal A or B. */
void tshare_poly_mul(const TshareNtt *t, TshareFe out[TSHARE_N], const TshareFe a[TSHARE_N],
                     const TshareFe b[TSHARE_N]);

/* Shares COUNT secrets: for each secret j a new polynomial f of degree t with
 * f(0) = secret[j] and random coefficients from D. Party i (1 to 5) gets
 * shares[(i - 1) count + j] = f(i). */
void tshare_share(TshareFe *shares, const TshareFe *secret, size_t count, TfheDrbg *d);

/* The commitment to the share vector of PARTY: SHA-512 of the party number
 * (4 bytes, low byte first), then the bytes of each share. */
void tshare_commit(uint8_t digest[SHA512_BYTES], unsigned party, const TshareFe *share, size_t count);

/* The Lagrange coefficients at 0 for the M points in SUBSET (party numbers,
 * 1 to 5, all different). Returns 1, or 0 for a bad subset. */
int tshare_lagrange(TshareFe *lambda, const unsigned *subset, unsigned m);

/* Combines the share vectors (the layout of tshare_share) of the M parties in
 * SUBSET: out[j] = sum of lambda_i shares[(subset[i] - 1) count + j]. Returns
 * 0 and writes no output when M is t or less, when the subset is bad, or when
 * a share vector does not match its commitment commits[party - 1]. */
int tshare_combine(TshareFe *out, const TshareFe *shares, size_t count, const unsigned *subset, unsigned m,
                   const uint8_t commits[TSHARE_PARTIES][SHA512_BYTES]);
#endif
