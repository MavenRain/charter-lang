/* 128-bit words for the S6 noise squashing (docs/PLAN.md 11 Q-S6-1 (a)): the
 * tfhe-rs 1.8.0 set NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
 * (W/S6-NOTES.md "Session U2a"). A word of Z/2^128 is 2 words of 64 bits (C99
 * has no 128-bit integer). The negacyclic product of a polynomial of words and
 * a polynomial of small signed values has 3 forms: the schoolbook rule (the
 * reference), the S5 f64 FFT on balanced 16-bit limbs, and the NTT over the
 * S6 prime p of front/tshare.h. */
#ifndef LANG_SQUASH_H
#define LANG_SQUASH_H
#include <stdint.h>

#include "front/tfhe.h"
#include "front/tshare.h"

enum {
  SQUASH_GLWE_K = 2,     /* glwe_dimension */
  SQUASH_POLY_N = 2048,  /* polynomial_size, TFHE_POLY_N and TSHARE_N */
  SQUASH_BIG_N = 4096,   /* kN, the LWE dimension after sample extract */
  SQUASH_NOISE = 30,     /* TUniform(30) under the squash GLWE key */
  SQUASH_BASE_LOG = 24,  /* decomp_base_log */
  SQUASH_LEVEL = 3,      /* decomp_level_count */
  SQUASH_DELTA_LOG = 123, /* Delta = 2^128 / (2 x 16) */
  SQUASH_SMALL_LOG = 23, /* the products are exact for |b| <= 2^23 */
  SQUASH_LIMBS = 8       /* 16-bit limbs of a word in the FFT form */
};

/* A word of Z/2^128: LO is bits 0 to 63, HI is bits 64 to 127. */
typedef struct Squash128 {
  uint64_t lo;
  uint64_t hi;
} Squash128;

enum {
  SQUASH_GLWE_WORDS = (SQUASH_GLWE_K + 1) * SQUASH_POLY_N,  /* K mask polys, then the body */
  SQUASH_GGSW_ROWS = SQUASH_LEVEL * (SQUASH_GLWE_K + 1),     /* level 1 first; rows 0 to K in a level */
  SQUASH_GGSW_WORDS = SQUASH_GGSW_ROWS * SQUASH_GLWE_WORDS
};

/* The work memory of squash_poly_mul_fft (about 480 KB): the caller gives it.
 * PROD is the product in squash_glwe_encrypt and squash_glwe_phase. */
typedef struct SquashFftWork {
  uint64_t word[SQUASH_LIMBS + 2][SQUASH_POLY_N];
  TfheFourier in[SQUASH_LIMBS + 2];
  TfheFourier acc[SQUASH_LIMBS];
  Squash128 prod[SQUASH_POLY_N];
} SquashFftWork;

/* The squash GLWE key: K polynomials of bits. */
typedef struct SquashKey {
  int64_t s[SQUASH_GLWE_K][SQUASH_POLY_N];
} SquashKey;

/* The work memory of squash_external_product (about 1 MB). After the call,
 * DIGIT[row] holds the digit polynomial that multiplies GGSW row ROW. */
typedef struct SquashExtWork {
  SquashFftWork mul;
  int64_t digit[SQUASH_GGSW_ROWS][SQUASH_POLY_N];
  TfheFourier acc[SQUASH_GLWE_K + 1][SQUASH_LIMBS];
} SquashExtWork;

/* The work memory of squash_poly_mul_ntt (about 150 KB). */
typedef struct SquashNttWork {
  TshareFe a[SQUASH_POLY_N];
  TshareFe b[SQUASH_POLY_N];
  TshareFe c[SQUASH_POLY_N];
} SquashNttWork;

Squash128 squash_from_u64(uint64_t x);

/* X mod 2^128: the sign of X fills the high word. */
Squash128 squash_from_i64(int64_t x);

int squash_eq(Squash128 a, Squash128 b);
Squash128 squash_add(Squash128 a, Squash128 b);
Squash128 squash_sub(Squash128 a, Squash128 b);
Squash128 squash_neg(Squash128 a);

/* The low 128 bits of the product A B. */
Squash128 squash_mul(Squash128 a, Squash128 b);

/* A 2^S and the floor of A / 2^S, for S below 128. */
Squash128 squash_shl(Squash128 a, unsigned s);
Squash128 squash_shr(Squash128 a, unsigned s);

/* A uniform word, and a TUniform(B) value mod 2^128 (B <= 62). */
Squash128 squash_uniform(TfheDrbg *d);
Squash128 squash_tuniform(TfheDrbg *d, unsigned bound_log);

/* OUT = A B mod (X^N + 1) over Z/2^128 for |b[j]| <= 2^23. OUT must not be A.
 * The schoolbook rule: N^2 products of words. */
void squash_poly_mul_exact(Squash128 out[SQUASH_POLY_N], const Squash128 a[SQUASH_POLY_N],
                           const int64_t b[SQUASH_POLY_N]);

/* The same product by the S5 FFT. Each word of A is 8 balanced limbs of 16
 * bits and each b[j] is 2 balanced limbs b0 + b1 2^16. Limb sum k (the limb
 * products with the shift 2^(16 k)) has coefficients below 2^42, so the f64
 * error stays far below 1/2; sum 8 (shift 2^128) is 0 mod 2^128. 10 forward
 * and 8 inverse transforms. */
void squash_poly_mul_fft(const TfheFft *f, SquashFftWork *w, Squash128 out[SQUASH_POLY_N],
                         const Squash128 a[SQUASH_POLY_N], const int64_t b[SQUASH_POLY_N]);

/* The same product by the NTT over F_p: A in [0, 2^128) and b[j] lift to F_p,
 * and each coefficient of the integer product has a magnitude of 2^162 or
 * less (N 2^128 2^23), below p / 2, so it is exact. 3 transforms. */
void squash_poly_mul_ntt(const TshareNtt *t, SquashNttWork *w, Squash128 out[SQUASH_POLY_N],
                         const Squash128 a[SQUASH_POLY_N], const int64_t b[SQUASH_POLY_N]);

/* The key bits from D, one byte for each bit (the S5 form): poly 0, then 1. */
void squash_key_generate(SquashKey *k, TfheDrbg *d);

/* CT = a GLWE of M under K (M NULL is 0): the uniform masks from D (poly 0,
 * then 1), then body = sum mask_i s_i + m + e, e from TUniform(30) for each
 * coefficient. */
void squash_glwe_encrypt(const TfheFft *f, SquashFftWork *w, Squash128 ct[SQUASH_GLWE_WORDS], const SquashKey *k,
                         const Squash128 *m, TfheDrbg *d);

/* OUT = body - sum mask_i s_i. */
void squash_glwe_phase(const TfheFft *f, SquashFftWork *w, Squash128 out[SQUASH_POLY_N],
                       const Squash128 ct[SQUASH_GLWE_WORDS], const SquashKey *k);

/* The tfhe-rs 1.8.0 SignedDecomposer of X (base 2^24, 3 levels): X rounds to
 * the closest multiple of 2^56 (balanced: init_decomposer_state), then each
 * level gives a digit in [-2^23, 2^23] (decompose_one_level). DIGITS[l] is
 * level l + 1, weight 2^(104 - 24 l). */
void squash_decompose(int64_t digits[SQUASH_LEVEL], Squash128 x);

/* GGSW (SQUASH_GGSW_WORDS words) = a GGSW of the small M under K: row
 * (l, i), l from 1 to 3 and i from 0 to K, is a GLWE of 0 plus m Delta_l
 * (-s_i) for i < K and m Delta_l for i = K, Delta_l = 2^(128 - 24 l). */
void squash_ggsw_encrypt(const TfheFft *f, SquashFftWork *w, Squash128 *ggsw, const SquashKey *k, int64_t m,
                         TfheDrbg *d);

/* OUT = GGSW x GLWE: the sum over the rows of the digit polynomial of the row
 * times the row, by the f64 form (Q-S6-12 (c)): each CMux transforms the 27
 * row polynomials (8 limbs each) and the 9 digit polynomials (2 limbs each),
 * and the 9 products add in the Fourier domain (limb sums below 2^44.2). */
void squash_external_product(const TfheFft *f, SquashExtWork *w, Squash128 out[SQUASH_GLWE_WORDS],
                             const Squash128 *ggsw, const Squash128 glwe[SQUASH_GLWE_WORDS]);

/* S6 U2b: the squash PBS. The squash BSK holds a GGSW of each bit of the S5
 * small key under the squash GLWE key, in the standard form (Q-S6-12 (c)):
 * 918 x 27 x 2048 words of 16 bytes, about 812 MB. */
enum { SQUASH_BSK_WORDS = TFHE_LWE_N * SQUASH_GGSW_WORDS };

/* The pointer belongs to squash_bsk_generate; squash_bsk_release frees it. */
typedef struct SquashBsk {
  Squash128 *ggsw;
} SquashBsk;

/* The work memory of squash_pbs (about 1.4 MB). */
typedef struct SquashPbsWork {
  SquashExtWork ext;
  Squash128 lut[SQUASH_POLY_N];
  Squash128 acc[SQUASH_GLWE_WORDS];
  Squash128 diff[SQUASH_GLWE_WORDS];
  Squash128 prod[SQUASH_GLWE_WORDS];
} SquashPbsWork;

/* BSK GGSW i = a GGSW of LWE_KEY[i] (0 or 1) under K, from D in the order of
 * i. Returns 1, or 0 when the allocation fails (then no memory stays
 * allocated). */
int squash_bsk_generate(SquashBsk *b, const TfheFft *f, SquashFftWork *w, const SquashKey *k,
                        const uint64_t lwe_key[TFHE_LWE_N], TfheDrbg *d);
void squash_bsk_release(SquashBsk *b);

/* The identity LUT polynomial (the tfhe_lut form): box m (128 coefficients)
 * holds m Delta_128 for m from 0 to 15, then the polynomial is multiplied by
 * X^(-64) (half a box). */
void squash_lut(Squash128 lut[SQUASH_POLY_N]);

/* W->ACC = the blind rotation of the trivial GLWE of LUT by the S5 switched
 * LWE (words in [0, 2N)): X^(-b) LUT, then for each i with a_i not 0 a CMux,
 * acc += GGSW_i x (X^(a_i) acc - acc). */
void squash_blind_rotate(const TfheFft *f, SquashPbsWork *w, const uint64_t switched[TFHE_LWE_N + 1],
                         const Squash128 lut[SQUASH_POLY_N], const SquashBsk *b);

/* OUT (mask, then body) = the LWE of coefficient 0 of ACC. The LWE key is
 * poly 0 of the squash key, then poly 1. */
void squash_sample_extract(Squash128 out[SQUASH_BIG_N + 1], const Squash128 acc[SQUASH_GLWE_WORDS]);

/* The squash of IN (an S5 LWE under the big key, v Delta with v < 16): the
 * S5 key switch with KSK, the S5 modulus switch to 2N, the blind rotation
 * with the identity LUT, the sample extract. OUT is an LWE of v Delta_128
 * over Z/2^128 under the squash key. */
void squash_pbs(const TfheFft *f, SquashPbsWork *w, Squash128 out[SQUASH_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1],
                const uint64_t *ksk, const SquashBsk *b);
#endif
