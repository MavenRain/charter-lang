/* TFHE (CGGI) over the torus Z/2^64 for the S5 runtime (docs/PLAN.md 11 Q-C2,
 * Q-S5-1 (a), Q-S5-2 (a)): the tfhe-rs 1.8.0 set
 * V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128. A block has 2 message
 * bits, 2 carry bits and one padding bit. Big-key encryption: a fresh or a PBS
 * output ciphertext is an LWE under the GLWE key read as kN = 2048 bits. The
 * PBS order is key switch, modulus switch to 2N with the centered mean, blind
 * rotation, sample extract. The negacyclic product is an f64 FFT on N/2
 * complex points. The test DRBG is SHA-512 in counter mode: it is for fixed
 * test keys only, not for keys in use (key generation at enact is S6). */
#ifndef LANG_TFHE_H
#define LANG_TFHE_H
#include <stddef.h>
#include <stdint.h>

#include "front/sha512.h"

enum {
  TFHE_LWE_N = 918,       /* lwe_dimension, the small key */
  TFHE_POLY_N = 2048,     /* polynomial_size; glwe_dimension k = 1 */
  TFHE_BIG_N = 2048,      /* kN, the LWE dimension of the big key */
  TFHE_FFT_M = 1024,      /* N / 2 complex points */
  TFHE_LOG_2N = 12,       /* the modulus switch goes to 2N = 2^12 */
  TFHE_LWE_NOISE = 45,    /* TUniform(45) under the small key (the KSK) */
  TFHE_GLWE_NOISE = 17,   /* TUniform(17) under the GLWE key (the BSK, fresh inputs) */
  TFHE_PBS_BASE_LOG = 23,
  TFHE_PBS_LEVEL = 1,
  TFHE_KS_BASE_LOG = 4,
  TFHE_KS_LEVEL = 4,
  TFHE_PLAIN = 16,        /* message modulus 4 x carry modulus 4 */
  TFHE_DELTA_LOG = 59,    /* Delta = 2^64 / (2 x 16) */
  TFHE_BOX = 128,         /* N / 16 LUT coefficients for each plaintext */
  TFHE_SEED_BYTES = 32
};

/* Word counts of the keys. KSK: for each big-key bit j and level l (1 to 4),
 * an LWE of S_j 2^(64 - 4l) under the small key. BSK: for each small-key bit
 * i, a GGSW of s_i: row 0 (mask row) and row 1 (body row), each a GLWE of 2
 * polynomials. The Fourier BSK holds each polynomial as M real parts, then M
 * imaginary parts. */
enum {
  TFHE_KSK_WORDS = TFHE_BIG_N * TFHE_KS_LEVEL * (TFHE_LWE_N + 1),
  TFHE_BSK_WORDS = TFHE_LWE_N * 2 * TFHE_PBS_LEVEL * 2 * TFHE_POLY_N,
  TFHE_BSK_FOURIER_DOUBLES = TFHE_LWE_N * 2 * TFHE_PBS_LEVEL * 2 * 2 * TFHE_FFT_M
};

/* The test DRBG: block c is SHA-512(seed || c as 8 bytes, low byte first). */
typedef struct TfheDrbg {
  uint8_t seed[TFHE_SEED_BYTES];
  uint64_t counter;
  uint8_t block[SHA512_BYTES];
  unsigned used;
} TfheDrbg;

/* The FFT tables, computed once by tfhe_fft_init from libm cos and sin: the
 * twist w^j = exp(i pi j / N) for j < M, and the roots exp(-2 pi i j / M) for
 * j < M / 2. */
typedef struct TfheFft {
  double twist_re[TFHE_FFT_M];
  double twist_im[TFHE_FFT_M];
  double root_re[TFHE_FFT_M / 2];
  double root_im[TFHE_FFT_M / 2];
} TfheFft;

/* A polynomial in the Fourier domain, in the bit-reversed order of the
 * forward transform. */
typedef struct TfheFourier {
  double re[TFHE_FFT_M];
  double im[TFHE_FFT_M];
} TfheFourier;

/* The secret keys (one bit in each word) and the server keys. The pointers
 * belong to tfhe_keys_generate; tfhe_keys_release frees them. */
typedef struct TfheKeys {
  uint64_t lwe_key[TFHE_LWE_N];
  uint64_t glwe_key[TFHE_POLY_N];
  TfheFourier glwe_key_fourier;
  uint64_t *ksk;
  uint64_t *bsk;
  double *bsk_fourier;
} TfheKeys;

void tfhe_drbg_init(TfheDrbg *d, const uint8_t seed[TFHE_SEED_BYTES]);

/* The next N bytes (n <= 8) as a word, low byte first. */
uint64_t tfhe_drbg_bytes(TfheDrbg *d, unsigned n);

/* A uniform word. */
uint64_t tfhe_uniform(TfheDrbg *d);

/* A TUniform(B) value in [-2^b, 2^b] as a torus word (b <= 62), in the
 * tfhe-rs 1.8.0 form: b + 2 bits r, then (r >> 1) + (r & 1) - 2^b. */
uint64_t tfhe_tuniform(TfheDrbg *d, unsigned bound_log);

void tfhe_fft_init(TfheFft *f);

/* The forward transform of POLY, each word read as a signed 64-bit value. */
void tfhe_fft_forward(const TfheFft *f, TfheFourier *out, const uint64_t poly[TFHE_POLY_N]);

/* ACC += A * (B_RE, B_IM), point by point. */
void tfhe_fourier_mul_add(TfheFourier *acc, const TfheFourier *a, const double *b_re, const double *b_im);

/* POLY += the inverse transform of IN, each value rounded (ties to even) and
 * taken mod 2^64. IN is changed. */
void tfhe_fft_backward_add(const TfheFft *f, uint64_t poly[TFHE_POLY_N], TfheFourier *in);

/* OUT = A * B mod (X^N + 1): by the FFT (A and B signed), exact mod 2^64 by
 * the schoolbook rule, and exact for a key in the Fourier domain with 0 or 1
 * coefficients (three 22-bit limbs of A, each product below 2^33). */
void tfhe_poly_mul_fft(const TfheFft *f, uint64_t out[TFHE_POLY_N], const uint64_t a[TFHE_POLY_N],
                       const uint64_t b[TFHE_POLY_N]);
void tfhe_poly_mul_exact(uint64_t out[TFHE_POLY_N], const uint64_t a[TFHE_POLY_N], const uint64_t b[TFHE_POLY_N]);
void tfhe_poly_mul_key(const TfheFft *f, uint64_t out[TFHE_POLY_N], const uint64_t a[TFHE_POLY_N],
                       const TfheFourier *key);

/* m Delta, and the nearest m (0 to 31, the padding bit included) to a phase. */
uint64_t tfhe_encode(unsigned m);
unsigned tfhe_decode(uint64_t phase);

/* CT (N + 1 words: mask, then body) = an LWE of PLAIN under KEY with
 * TUniform(NOISE_LOG) noise: body = <mask, key> + plain + e. */
void tfhe_lwe_encrypt(uint64_t *ct, const uint64_t *key, size_t n, uint64_t plain, unsigned noise_log,
                      TfheDrbg *d);

/* body - <mask, key>. */
uint64_t tfhe_lwe_phase(const uint64_t *ct, const uint64_t *key, size_t n);

/* Makes the keys: the small key, the GLWE key, the KSK and the BSK (both
 * forms), from D in this order. Returns 1, or 0 when an allocation fails
 * (then no memory stays allocated). */
int tfhe_keys_generate(TfheKeys *k, const TfheFft *f, TfheDrbg *d);
void tfhe_keys_release(TfheKeys *k);

/* An LWE under the big key to an LWE under the small key (base 2^4, 4
 * levels, balanced digits). */
void tfhe_keyswitch(uint64_t out[TFHE_LWE_N + 1], const uint64_t in[TFHE_BIG_N + 1], const uint64_t *ksk);

/* The centered binary modulus switch to 2N (tfhe-rs 1.8.0
 * centered_binary_ms_body_correction_to_add): each word goes to [0, 2N);
 * the body takes sum(mask rounding error / 2) - 2^51 before it rounds. */
void tfhe_modulus_switch(uint64_t out[TFHE_LWE_N + 1], const uint64_t in[TFHE_LWE_N + 1]);

/* The LUT polynomial of TABLE (each entry mod 16): box m holds table[m]
 * Delta, then the polynomial is multiplied by X^(-64) (half a box). */
void tfhe_lut(uint64_t lut[TFHE_POLY_N], const uint8_t table[TFHE_PLAIN]);

/* ACC (mask, then body) = the blind rotation of the trivial GLWE of LUT by
 * the switched LWE, X^(-b) LUT, then a CMux with X^(a_i) for each i. */
void tfhe_blind_rotate(const TfheFft *f, uint64_t acc[2 * TFHE_POLY_N], const uint64_t switched[TFHE_LWE_N + 1],
                       const uint64_t lut[TFHE_POLY_N], const double *bsk_fourier);

/* The LWE under the big key of coefficient 0 of ACC. */
void tfhe_sample_extract(uint64_t out[TFHE_BIG_N + 1], const uint64_t acc[2 * TFHE_POLY_N]);

/* The PBS of IN (big key) with LUT: key switch, modulus switch, blind
 * rotation, sample extract. OUT is under the big key. */
void tfhe_pbs(const TfheFft *f, uint64_t out[TFHE_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1], const TfheKeys *k,
              const uint64_t lut[TFHE_POLY_N]);

/* As tfhe_pbs, with KSK in place of the KSK of K. */
void tfhe_pbs_ksk(const TfheFft *f, uint64_t out[TFHE_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1],
                  const uint64_t *ksk, const TfheKeys *k, const uint64_t lut[TFHE_POLY_N]);

/* S5 U5: the public-key encryption of ballots (Q-S5-8 (a), Q-S5-9 (a)), the
 * tfhe-rs 1.8.0 sets PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 (the
 * compact public key) and PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
 * (the cast). KEY is a new binary key of 2048 bits. pk_b = pk_a phi_1(key) + e
 * mod (X^N + 1), with phi_1 the reversed vector and e TUniform(17). CKSK is the
 * casting KSK from KEY to the small key, in the KSK form (base 2^4, 4 levels,
 * TUniform(45)). The pointer belongs to tfhe_pke_generate; tfhe_pke_release
 * frees it. */
enum { TFHE_PKE_NOISE = 17 };

typedef struct TfhePke {
  uint64_t key[TFHE_BIG_N];
  uint64_t pk_a[TFHE_POLY_N];
  uint64_t pk_b[TFHE_POLY_N];
  uint64_t *cksk;
} TfhePke;

/* Makes KEY, pk_a, pk_b and the casting KSK to the small key of K, from D in
 * this order. Returns 1, or 0 when the allocation fails. */
int tfhe_pke_generate(TfhePke *p, const TfheKeys *k, TfheDrbg *d);
void tfhe_pke_release(TfhePke *p);

/* One chunk of COUNT plaintexts M (COUNT <= N, each m below 16). Draws r
 * (binary), e1 and e2 (TUniform(17)) from D in this order. MASK = pk_a
 * phi_1(r) + e1; body j = c[N - 1 - j] + e2_j + m_j Delta, with c = pk_b
 * phi_1(r). */
void tfhe_pke_encrypt(uint64_t mask[TFHE_POLY_N], uint64_t *body, const TfhePke *p, const uint8_t *m, size_t count,
                      TfheDrbg *d);

/* The LWE under KEY of entry J (J < N) of a chunk: the mask X^J MASK mod
 * (X^N + 1), then BODY. */
void tfhe_pke_expand(uint64_t out[TFHE_BIG_N + 1], const uint64_t mask[TFHE_POLY_N], uint64_t body, size_t j);

/* The cast of an LWE under KEY to an LWE under the big key: the key switch
 * with the casting KSK, then the PBS of the identity LUT. */
void tfhe_pke_cast(const TfheFft *f, uint64_t out[TFHE_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1], const TfhePke *p,
                   const TfheKeys *k);

/* S5 U3: the radix layer. A radix holds a u64 as 32 blocks of 2 bits, the
 * low block first. A block is an LWE under the big key of v Delta, with v = 4
 * carry + message and v < 16. Clean = each block holds its digit and carry 0.
 * A PBS input block must have v < 16 and a noise level of 5 or less (tfhe-rs
 * max_noise_level 5): a fresh or a PBS output block has level 1, a trivial
 * block has level 0, a block add sums the levels, and a scale by c
 * multiplies the level by c. The PBS counts are static. */
enum {
  TFHE_BLOCK_WORDS = TFHE_BIG_N + 1,
  TFHE_RADIX_BLOCKS = 32,
  TFHE_MSG_MOD = 4,                               /* the message modulus of a block */
  TFHE_PROPAGATE_PBS = 2 * TFHE_RADIX_BLOCKS - 1, /* 31 CARRY + 32 MSG */
  TFHE_LE_PBS = 2 * TFHE_RADIX_BLOCKS - 1         /* 32 CMP + 30 MERGE + 1 LE */
};

/* The radix LUTs. MSG: v mod 4. CARRY: v / 4. CMP (4x + y, x and y
 * messages): LT, EQ or GT. MERGE (4h + l, h and l CMP values): l when h = EQ,
 * else h (the high block wins). LE (4h + l): 1 when the MERGE value is not
 * GT, else 0. All 16 entries have a value; the radix functions use only the
 * valid inputs. */
enum { TFHE_LUT_MSG, TFHE_LUT_CARRY, TFHE_LUT_CMP, TFHE_LUT_MERGE, TFHE_LUT_LE, TFHE_LUTS };
enum { TFHE_CMP_LT, TFHE_CMP_EQ, TFHE_CMP_GT };

/* 512 KiB: keep a radix in static storage. */
typedef struct TfheRadix {
  uint64_t block[TFHE_RADIX_BLOCKS][TFHE_BLOCK_WORDS];
} TfheRadix;

/* The LUT polynomial of each radix LUT, in the enum order (5 x 16 KiB). */
typedef struct TfheRadixLuts {
  uint64_t lut[TFHE_LUTS][TFHE_POLY_N];
} TfheRadixLuts;

void tfhe_radix_luts(TfheRadixLuts *l);

/* DST += A, each word mod 2^64: the values add and the levels add. 0 PBS. */
void tfhe_block_add(uint64_t dst[TFHE_BLOCK_WORDS], const uint64_t a[TFHE_BLOCK_WORDS]);

/* DST *= C, each word mod 2^64: the value and the level are multiplied by
 * C. 0 PBS. */
void tfhe_block_scale(uint64_t dst[TFHE_BLOCK_WORDS], uint64_t c);

/* R = X under the big key: block i is a fresh LWE of digit i with
 * TUniform(17) noise (level 1), i from 0 to 31 in this DRBG order. For the
 * client only. 0 PBS. */
void tfhe_radix_encrypt(TfheRadix *r, const TfheKeys *k, uint64_t x, TfheDrbg *d);

/* R = the trivial radix of X: mask 0, body = digit i Delta (level 0). No
 * DRBG. 0 PBS. */
void tfhe_radix_trivial(TfheRadix *r, uint64_t x);

/* The sum of (decode (phase of block i) mod 4) 4^i: the carry of a block
 * that is not clean is lost. 0 PBS. */
uint64_t tfhe_radix_decrypt(const TfheRadix *r, const TfheKeys *k);

/* Carry propagation from the low block to the high block. For i = 0 to 30:
 * carry = PBS (b_i, CARRY), b_i = PBS (b_i, MSG), b_(i+1) += carry. Then
 * b_31 = PBS (b_31, MSG): the carry of block 31 goes out of the u64 (mod
 * 2^64). 63 PBS. Bound: each block, with its carry-in, has v < 16 and a
 * level of 5 or less. R is then clean, level 1. */
void tfhe_radix_propagate(const TfheFft *f, TfheRadix *r, const TfheKeys *k, const TfheRadixLuts *l);

/* OUT = X + Y mod 2^64: the block adds, then one propagation (the n = 2
 * case of tfhe_radix_sum). 63 PBS. Bound: X and Y clean, level 1 or less,
 * so a block is at most 3 + 3 + carry-in 1 = 7, level 3. OUT is not an
 * input. */
void tfhe_radix_add(const TfheFft *f, TfheRadix *out, const TfheRadix *x, const TfheRadix *y, const TfheKeys *k,
                    const TfheRadixLuts *l);

/* OUT = BIT * A (docs/PLAN.md 4.3): BIT is a block of 0 or 1 and A is a
 * clear u64. Block i = BIT scaled by digit i of A; a digit 0 gives a trivial
 * zero block. 0 PBS. Bound: each block is at most 1 x 3 = 3 (clean, no
 * propagation), level 3 x the level of BIT or less. Two outputs go into an
 * add only after a refresh (S5 U4). */
void tfhe_radix_scalar_mul(TfheRadix *out, const uint64_t bit[TFHE_BLOCK_WORDS], uint64_t a);

/* OUT = one block, 1 when X <= Y, else 0. From the high block: acc = PBS
 * (4 x_31 + y_31, CMP); for i = 30 down to 1, acc = PBS (4 acc + PBS (4 x_i
 * + y_i, CMP), MERGE); OUT = PBS (4 acc + PBS (4 x_0 + y_0, CMP), LE). 63
 * PBS. Bound: X and Y clean, level 1 or less, so each PBS input is at most
 * 4 x 3 + 3 = 15, level 4 + 1 = 5. OUT is clean, level 1. */
void tfhe_radix_le(const TfheFft *f, uint64_t out[TFHE_BLOCK_WORDS], const TfheRadix *x, const TfheRadix *y,
                   const TfheKeys *k, const TfheRadixLuts *l);

/* OUT = XS[0] + ... + XS[N - 1] mod 2^64, N >= 1. OUT = XS[0]; then for
 * each group of up to 3 more inputs, the block adds and one propagation.
 * 63 x ceil ((N - 1) / 3) PBS (N = 1: 0 PBS). Bound: XS clean, level 1 or
 * less, so 4 terms give a block of at most 12 + carry-in 3 = 15 (its carry
 * is 3 again), level 4 + 1 = 5. A fifth term goes over both. OUT is not in
 * XS. */
void tfhe_radix_sum(const TfheFft *f, TfheRadix *out, const TfheRadix *xs, size_t n, const TfheKeys *k,
                    const TfheRadixLuts *l);
#endif
