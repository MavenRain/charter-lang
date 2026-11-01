/* TFHE (CGGI) over the torus Z/2^64: see front/tfhe.h. The forms of the
 * TUniform sampler and of the centered modulus switch are the tfhe-rs 1.8.0
 * ones (git ab8ba567, W/S5-NOTES.md "Session r1"). */
#include "front/tfhe.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define TWO_POW_63 9223372036854775808.0
#define TWO_POW_64 18446744073709551616.0

void tfhe_drbg_init(TfheDrbg *d, const uint8_t seed[TFHE_SEED_BYTES]) {
  memcpy(d->seed, seed, TFHE_SEED_BYTES);
  d->counter = 0;
  d->used = SHA512_BYTES;
}

static uint8_t drbg_byte(TfheDrbg *d) {
  if (d->used == SHA512_BYTES) {
    uint8_t input[TFHE_SEED_BYTES + 8];
    unsigned i;
    memcpy(input, d->seed, TFHE_SEED_BYTES);
    for (i = 0; i < 8; i++) input[TFHE_SEED_BYTES + i] = (uint8_t)(d->counter >> (8u * i));
    sha512(input, sizeof input, d->block);
    d->counter++;
    d->used = 0;
  }
  return d->block[d->used++];
}

uint64_t tfhe_drbg_bytes(TfheDrbg *d, unsigned n) {
  uint64_t w = 0;
  unsigned i;
  for (i = 0; i < n && i < 8; i++) w |= (uint64_t)drbg_byte(d) << (8u * i);
  return w;
}

uint64_t tfhe_uniform(TfheDrbg *d) {
  return tfhe_drbg_bytes(d, 8);
}

uint64_t tfhe_tuniform(TfheDrbg *d, unsigned bound_log) {
  unsigned bits = bound_log + 2u;
  uint64_t mask = UINT64_MAX >> (64u - bits);
  uint64_t r = tfhe_drbg_bytes(d, (bits + 7u) / 8u) & mask;
  uint64_t low = r & 1u;
  r >>= 1;
  r += low;
  return r - ((uint64_t)1 << bound_log);
}

void tfhe_fft_init(TfheFft *f) {
  const double pi = 3.14159265358979323846;
  unsigned j;
  for (j = 0; j < TFHE_FFT_M; j++) {
    double angle = pi * (double)j / (double)TFHE_POLY_N;
    f->twist_re[j] = cos(angle);
    f->twist_im[j] = sin(angle);
  }
  for (j = 0; j < TFHE_FFT_M / 2; j++) {
    double angle = -2.0 * pi * (double)j / (double)TFHE_FFT_M;
    f->root_re[j] = cos(angle);
    f->root_im[j] = sin(angle);
  }
}

/* Decimation in frequency: natural order in, bit-reversed order out. */
static void fft_dif(const TfheFft *f, double *re, double *im) {
  unsigned len;
  for (len = TFHE_FFT_M; len >= 2; len >>= 1) {
    unsigned half = len / 2u, step = TFHE_FFT_M / len, start, j;
    for (start = 0; start < TFHE_FFT_M; start += len) {
      for (j = 0; j < half; j++) {
        unsigned a = start + j, b = a + half;
        double wr = f->root_re[j * step], wi = f->root_im[j * step];
        double dr = re[a] - re[b], di = im[a] - im[b];
        re[a] += re[b];
        im[a] += im[b];
        re[b] = dr * wr - di * wi;
        im[b] = dr * wi + di * wr;
      }
    }
  }
}

/* Decimation in time with the conjugate roots: bit-reversed order in,
 * natural order out, not scaled. It undoes fft_dif up to the factor M. */
static void fft_dit_inverse(const TfheFft *f, double *re, double *im) {
  unsigned len;
  for (len = 2; len <= TFHE_FFT_M; len <<= 1) {
    unsigned half = len / 2u, step = TFHE_FFT_M / len, start, j;
    for (start = 0; start < TFHE_FFT_M; start += len) {
      for (j = 0; j < half; j++) {
        unsigned a = start + j, b = a + half;
        double wr = f->root_re[j * step], wi = -f->root_im[j * step];
        double vr = re[b] * wr - im[b] * wi, vi = re[b] * wi + im[b] * wr;
        re[b] = re[a] - vr;
        im[b] = im[a] - vi;
        re[a] += vr;
        im[a] += vi;
      }
    }
  }
}

/* Coefficients j and j + M fold into one complex point, times the twist. */
void tfhe_fft_forward(const TfheFft *f, TfheFourier *out, const uint64_t poly[TFHE_POLY_N]) {
  unsigned j;
  for (j = 0; j < TFHE_FFT_M; j++) {
    double x = (double)(int64_t)poly[j], y = (double)(int64_t)poly[j + TFHE_FFT_M];
    out->re[j] = x * f->twist_re[j] - y * f->twist_im[j];
    out->im[j] = x * f->twist_im[j] + y * f->twist_re[j];
  }
  fft_dif(f, out->re, out->im);
}

void tfhe_fourier_mul_add(TfheFourier *acc, const TfheFourier *a, const double *b_re, const double *b_im) {
  unsigned j;
  for (j = 0; j < TFHE_FFT_M; j++) {
    acc->re[j] += a->re[j] * b_re[j] - a->im[j] * b_im[j];
    acc->im[j] += a->re[j] * b_im[j] + a->im[j] * b_re[j];
  }
}

/* The nearest integer to X (ties to even), mod 2^64. The steps are exact
 * for |x| < 2^116 and use only the f64 operations that Wasm has (nearest,
 * floor, the signed truncation in range). */
static uint64_t torus_from_double(double x) {
  double r = rint(x);
  if (r >= -TWO_POW_63 && r < TWO_POW_63) return (uint64_t)(int64_t)r;
  r -= floor(r * (1.0 / TWO_POW_64) + 0.5) * TWO_POW_64;
  if (r >= TWO_POW_63) r -= TWO_POW_64;
  return (uint64_t)(int64_t)r;
}

void tfhe_fft_backward_add(const TfheFft *f, uint64_t poly[TFHE_POLY_N], TfheFourier *in) {
  const double scale = 1.0 / (double)TFHE_FFT_M;
  unsigned j;
  fft_dit_inverse(f, in->re, in->im);
  for (j = 0; j < TFHE_FFT_M; j++) {
    double xr = in->re[j] * scale, xi = in->im[j] * scale;
    double cr = xr * f->twist_re[j] + xi * f->twist_im[j];
    double ci = xi * f->twist_re[j] - xr * f->twist_im[j];
    poly[j] += torus_from_double(cr);
    poly[j + TFHE_FFT_M] += torus_from_double(ci);
  }
}

static void fourier_zero(TfheFourier *x) {
  memset(x->re, 0, sizeof x->re);
  memset(x->im, 0, sizeof x->im);
}

void tfhe_poly_mul_fft(const TfheFft *f, uint64_t out[TFHE_POLY_N], const uint64_t a[TFHE_POLY_N],
                       const uint64_t b[TFHE_POLY_N]) {
  TfheFourier fa, fb, acc;
  tfhe_fft_forward(f, &fa, a);
  tfhe_fft_forward(f, &fb, b);
  fourier_zero(&acc);
  tfhe_fourier_mul_add(&acc, &fa, fb.re, fb.im);
  memset(out, 0, TFHE_POLY_N * sizeof out[0]);
  tfhe_fft_backward_add(f, out, &acc);
}

void tfhe_poly_mul_exact(uint64_t out[TFHE_POLY_N], const uint64_t a[TFHE_POLY_N], const uint64_t b[TFHE_POLY_N]) {
  unsigned i, j;
  memset(out, 0, TFHE_POLY_N * sizeof out[0]);
  for (i = 0; i < TFHE_POLY_N; i++) {
    for (j = 0; j < TFHE_POLY_N; j++) {
      unsigned k = i + j;
      if (k < TFHE_POLY_N) out[k] += a[i] * b[j];
      else out[k - TFHE_POLY_N] -= a[i] * b[j];
    }
  }
}

enum { KEY_LIMB_BITS = 22, KEY_LIMBS = 3 };

void tfhe_poly_mul_key(const TfheFft *f, uint64_t out[TFHE_POLY_N], const uint64_t a[TFHE_POLY_N],
                       const TfheFourier *key) {
  uint64_t limb[TFHE_POLY_N], part[TFHE_POLY_N];
  const uint64_t mask = ((uint64_t)1 << KEY_LIMB_BITS) - 1u;
  TfheFourier fa, acc;
  unsigned l, j;
  memset(out, 0, TFHE_POLY_N * sizeof out[0]);
  for (l = 0; l < KEY_LIMBS; l++) {
    unsigned shift = KEY_LIMB_BITS * l;
    for (j = 0; j < TFHE_POLY_N; j++) limb[j] = (a[j] >> shift) & mask;
    tfhe_fft_forward(f, &fa, limb);
    fourier_zero(&acc);
    tfhe_fourier_mul_add(&acc, &fa, key->re, key->im);
    memset(part, 0, sizeof part);
    tfhe_fft_backward_add(f, part, &acc);
    for (j = 0; j < TFHE_POLY_N; j++) out[j] += part[j] << shift;
  }
}

uint64_t tfhe_encode(unsigned m) {
  return (uint64_t)m << TFHE_DELTA_LOG;
}

unsigned tfhe_decode(uint64_t phase) {
  return (unsigned)((phase + ((uint64_t)1 << (TFHE_DELTA_LOG - 1))) >> TFHE_DELTA_LOG);
}

void tfhe_lwe_encrypt(uint64_t *ct, const uint64_t *key, size_t n, uint64_t plain, unsigned noise_log,
                      TfheDrbg *d) {
  uint64_t body = plain;
  size_t i;
  for (i = 0; i < n; i++) {
    ct[i] = tfhe_uniform(d);
    body += ct[i] * key[i];
  }
  ct[n] = body + tfhe_tuniform(d, noise_log);
}

uint64_t tfhe_lwe_phase(const uint64_t *ct, const uint64_t *key, size_t n) {
  uint64_t body = ct[n];
  size_t i;
  for (i = 0; i < n; i++) body -= ct[i] * key[i];
  return body;
}

/* CT (mask, then body) = a GLWE of 0 under the GLWE key, TUniform(17). */
static void glwe_encrypt_zero(const TfheFft *f, uint64_t ct[2 * TFHE_POLY_N], const TfheKeys *k, TfheDrbg *d) {
  unsigned j;
  for (j = 0; j < TFHE_POLY_N; j++) ct[j] = tfhe_uniform(d);
  tfhe_poly_mul_key(f, ct + TFHE_POLY_N, ct, &k->glwe_key_fourier);
  for (j = 0; j < TFHE_POLY_N; j++) ct[TFHE_POLY_N + j] += tfhe_tuniform(d, TFHE_GLWE_NOISE);
}

void tfhe_keys_release(TfheKeys *k) {
  free(k->ksk);
  free(k->bsk);
  free(k->bsk_fourier);
  k->ksk = NULL;
  k->bsk = NULL;
  k->bsk_fourier = NULL;
}

/* KSK: for each bit j of IN_KEY and level l (0 to 3), an LWE under LWE_KEY
 * of in_key[j] 2^(64 - 4 (l + 1)), from D in this order. */
static void ksk_generate(uint64_t *ksk, const uint64_t in_key[TFHE_BIG_N], const uint64_t lwe_key[TFHE_LWE_N],
                         TfheDrbg *d) {
  unsigned j, l;
  for (j = 0; j < TFHE_BIG_N; j++) {
    for (l = 0; l < TFHE_KS_LEVEL; l++) {
      uint64_t *ct = ksk + ((size_t)j * TFHE_KS_LEVEL + l) * (TFHE_LWE_N + 1);
      uint64_t plain = in_key[j] << (64u - TFHE_KS_BASE_LOG * (l + 1u));
      tfhe_lwe_encrypt(ct, lwe_key, TFHE_LWE_N, plain, TFHE_LWE_NOISE, d);
    }
  }
}

int tfhe_keys_generate(TfheKeys *k, const TfheFft *f, TfheDrbg *d) {
  TfheFourier poly;
  unsigned i, j, row, p;
  k->ksk = malloc((size_t)TFHE_KSK_WORDS * sizeof k->ksk[0]);
  k->bsk = malloc((size_t)TFHE_BSK_WORDS * sizeof k->bsk[0]);
  k->bsk_fourier = malloc((size_t)TFHE_BSK_FOURIER_DOUBLES * sizeof k->bsk_fourier[0]);
  if (k->ksk == NULL || k->bsk == NULL || k->bsk_fourier == NULL) {
    tfhe_keys_release(k);
    return 0;
  }
  for (i = 0; i < TFHE_LWE_N; i++) k->lwe_key[i] = tfhe_drbg_bytes(d, 1) & 1u;
  for (j = 0; j < TFHE_POLY_N; j++) k->glwe_key[j] = tfhe_drbg_bytes(d, 1) & 1u;
  tfhe_fft_forward(f, &k->glwe_key_fourier, k->glwe_key);
  ksk_generate(k->ksk, k->glwe_key, k->lwe_key, d);
  for (i = 0; i < TFHE_LWE_N; i++) {
    for (row = 0; row < 2; row++) {
      uint64_t *ct = k->bsk + ((size_t)i * 2 + row) * 2 * TFHE_POLY_N;
      glwe_encrypt_zero(f, ct, k, d);
      ct[row * TFHE_POLY_N] += k->lwe_key[i] << (64u - TFHE_PBS_BASE_LOG);
      for (p = 0; p < 2; p++) {
        double *out = k->bsk_fourier + (((size_t)i * 2 + row) * 2 + p) * 2 * TFHE_FFT_M;
        tfhe_fft_forward(f, &poly, ct + p * TFHE_POLY_N);
        memcpy(out, poly.re, sizeof poly.re);
        memcpy(out + TFHE_FFT_M, poly.im, sizeof poly.im);
      }
    }
  }
  return 1;
}

/* The balanced digits of the closest multiple of 2^(64 - base_log level) to
 * X: digit l (0 is the most significant) has weight 2^(64 - base_log (l + 1))
 * and is in [-2^(base_log - 1), 2^(base_log - 1)). */
static void decompose(int64_t *digits, uint64_t x, unsigned base_log, unsigned level) {
  unsigned total = base_log * level, l;
  uint64_t base = (uint64_t)1 << base_log;
  uint64_t state = (x + ((uint64_t)1 << (63u - total))) >> (64u - total);
  for (l = level; l > 0; l--) {
    uint64_t digit = state & (base - 1u);
    state >>= base_log;
    if (digit >= base / 2u) {
      digits[l - 1u] = (int64_t)digit - (int64_t)base;
      state += 1u;
    } else {
      digits[l - 1u] = (int64_t)digit;
    }
  }
}

void tfhe_keyswitch(uint64_t out[TFHE_LWE_N + 1], const uint64_t in[TFHE_BIG_N + 1], const uint64_t *ksk) {
  int64_t digits[TFHE_KS_LEVEL];
  unsigned i, j, l;
  memset(out, 0, TFHE_LWE_N * sizeof out[0]);
  out[TFHE_LWE_N] = in[TFHE_BIG_N];
  for (j = 0; j < TFHE_BIG_N; j++) {
    decompose(digits, in[j], TFHE_KS_BASE_LOG, TFHE_KS_LEVEL);
    for (l = 0; l < TFHE_KS_LEVEL; l++) {
      const uint64_t *row = ksk + ((size_t)j * TFHE_KS_LEVEL + l) * (TFHE_LWE_N + 1);
      uint64_t digit = (uint64_t)digits[l];
      if (digit == 0) continue;
      for (i = 0; i <= TFHE_LWE_N; i++) out[i] -= digit * row[i];
    }
  }
}

void tfhe_modulus_switch(uint64_t out[TFHE_LWE_N + 1], const uint64_t in[TFHE_LWE_N + 1]) {
  const unsigned shift = 64u - TFHE_LOG_2N;
  const uint64_t half_case = (uint64_t)1 << (shift - 1u);
  uint64_t sum_half = 0;
  int64_t sum_halving_doubled = 0;
  unsigned i;
  for (i = 0; i < TFHE_LWE_N; i++) {
    uint64_t switched = (in[i] + half_case) >> shift;
    int64_t error = (int64_t)((switched << shift) - in[i]);
    int64_t half = error / 2;
    sum_halving_doubled += 2 * half - error;
    sum_half += (uint64_t)half;
    out[i] = switched;
  }
  sum_half -= (uint64_t)(sum_halving_doubled / 2);
  out[TFHE_LWE_N] = (in[TFHE_LWE_N] + (sum_half - half_case) + half_case) >> shift;
}

void tfhe_lut(uint64_t lut[TFHE_POLY_N], const uint8_t table[TFHE_PLAIN]) {
  const unsigned half = TFHE_BOX / 2u;
  unsigned j;
  for (j = 0; j < TFHE_POLY_N; j++) {
    unsigned src = j + half;
    if (src < TFHE_POLY_N) lut[j] = tfhe_encode(table[src / TFHE_BOX] % TFHE_PLAIN);
    else lut[j] = 0u - tfhe_encode(table[(src - TFHE_POLY_N) / TFHE_BOX] % TFHE_PLAIN);
  }
}

/* OUT = X^POWER IN mod (X^N + 1), POWER < 2N. */
static void poly_monomial_mul(uint64_t *out, const uint64_t *in, unsigned power) {
  unsigned j;
  for (j = 0; j < TFHE_POLY_N; j++) {
    unsigned k = j + power;
    if (k >= 2u * TFHE_POLY_N) k -= 2u * TFHE_POLY_N;
    if (k < TFHE_POLY_N) out[k] = in[j];
    else out[k - TFHE_POLY_N] = 0u - in[j];
  }
}

void tfhe_blind_rotate(const TfheFft *f, uint64_t acc[2 * TFHE_POLY_N], const uint64_t switched[TFHE_LWE_N + 1],
                       const uint64_t lut[TFHE_POLY_N], const double *bsk_fourier) {
  uint64_t diff[2 * TFHE_POLY_N];
  int64_t digit[TFHE_PBS_LEVEL];
  TfheFourier fd[2], out;
  unsigned i, j, p, t;
  unsigned body = (unsigned)switched[TFHE_LWE_N];
  memset(acc, 0, TFHE_POLY_N * sizeof acc[0]);
  poly_monomial_mul(acc + TFHE_POLY_N, lut, body == 0 ? 0u : 2u * TFHE_POLY_N - body);
  for (i = 0; i < TFHE_LWE_N; i++) {
    unsigned a = (unsigned)switched[i];
    if (a == 0) continue;
    for (p = 0; p < 2; p++) {
      poly_monomial_mul(diff + p * TFHE_POLY_N, acc + p * TFHE_POLY_N, a);
      for (j = 0; j < TFHE_POLY_N; j++) {
        decompose(digit, diff[p * TFHE_POLY_N + j] - acc[p * TFHE_POLY_N + j], TFHE_PBS_BASE_LOG, TFHE_PBS_LEVEL);
        diff[p * TFHE_POLY_N + j] = (uint64_t)digit[0];
      }
      tfhe_fft_forward(f, &fd[p], diff + p * TFHE_POLY_N);
    }
    for (t = 0; t < 2; t++) {
      fourier_zero(&out);
      for (p = 0; p < 2; p++) {
        const double *row = bsk_fourier + (((size_t)i * 2 + p) * 2 + t) * 2 * TFHE_FFT_M;
        tfhe_fourier_mul_add(&out, &fd[p], row, row + TFHE_FFT_M);
      }
      tfhe_fft_backward_add(f, acc + t * TFHE_POLY_N, &out);
    }
  }
}

void tfhe_sample_extract(uint64_t out[TFHE_BIG_N + 1], const uint64_t acc[2 * TFHE_POLY_N]) {
  unsigned j;
  out[0] = acc[0];
  for (j = 1; j < TFHE_POLY_N; j++) out[j] = 0u - acc[TFHE_POLY_N - j];
  out[TFHE_BIG_N] = acc[TFHE_POLY_N];
}

void tfhe_pbs_ksk(const TfheFft *f, uint64_t out[TFHE_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1],
                  const uint64_t *ksk, const TfheKeys *k, const uint64_t lut[TFHE_POLY_N]) {
  uint64_t small[TFHE_LWE_N + 1], switched[TFHE_LWE_N + 1], acc[2 * TFHE_POLY_N];
  tfhe_keyswitch(small, in, ksk);
  tfhe_modulus_switch(switched, small);
  tfhe_blind_rotate(f, acc, switched, lut, k->bsk_fourier);
  tfhe_sample_extract(out, acc);
}

void tfhe_pbs(const TfheFft *f, uint64_t out[TFHE_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1], const TfheKeys *k,
              const uint64_t lut[TFHE_POLY_N]) {
  tfhe_pbs_ksk(f, out, in, k->ksk, k, lut);
}

/* phi_1(IN) = (in_{N-1}, .., in_0), the reversed vector. */
static void pke_reverse(uint64_t out[TFHE_POLY_N], const uint64_t in[TFHE_POLY_N]) {
  unsigned j;
  for (j = 0; j < TFHE_POLY_N; j++) out[j] = in[TFHE_POLY_N - 1u - j];
}

int tfhe_pke_generate(TfhePke *p, const TfheKeys *k, TfheDrbg *d) {
  uint64_t rev[TFHE_POLY_N];
  unsigned j;
  p->cksk = malloc((size_t)TFHE_KSK_WORDS * sizeof p->cksk[0]);
  if (p->cksk == NULL) return 0;
  for (j = 0; j < TFHE_BIG_N; j++) p->key[j] = tfhe_drbg_bytes(d, 1) & 1u;
  for (j = 0; j < TFHE_POLY_N; j++) p->pk_a[j] = tfhe_uniform(d);
  pke_reverse(rev, p->key);
  tfhe_poly_mul_exact(p->pk_b, p->pk_a, rev);
  for (j = 0; j < TFHE_POLY_N; j++) p->pk_b[j] += tfhe_tuniform(d, TFHE_PKE_NOISE);
  ksk_generate(p->cksk, p->key, k->lwe_key, d);
  return 1;
}

void tfhe_pke_release(TfhePke *p) {
  free(p->cksk);
  p->cksk = NULL;
}

void tfhe_pke_encrypt(uint64_t mask[TFHE_POLY_N], uint64_t *body, const TfhePke *p, const uint8_t *m, size_t count,
                      TfheDrbg *d) {
  uint64_t r[TFHE_POLY_N], rev[TFHE_POLY_N], c[TFHE_POLY_N];
  size_t j;
  for (j = 0; j < TFHE_POLY_N; j++) r[j] = tfhe_drbg_bytes(d, 1) & 1u;
  pke_reverse(rev, r);
  tfhe_poly_mul_exact(mask, p->pk_a, rev);
  for (j = 0; j < TFHE_POLY_N; j++) mask[j] += tfhe_tuniform(d, TFHE_PKE_NOISE);
  tfhe_poly_mul_exact(c, p->pk_b, rev);
  for (j = 0; j < count && j < TFHE_POLY_N; j++) {
    body[j] = c[TFHE_POLY_N - 1u - j] + tfhe_tuniform(d, TFHE_PKE_NOISE) + tfhe_encode(m[j]);
  }
}

void tfhe_pke_expand(uint64_t out[TFHE_BIG_N + 1], const uint64_t mask[TFHE_POLY_N], uint64_t body, size_t j) {
  poly_monomial_mul(out, mask, (unsigned)j);
  out[TFHE_BIG_N] = body;
}

void tfhe_pke_cast(const TfheFft *f, uint64_t out[TFHE_BIG_N + 1], const uint64_t in[TFHE_BIG_N + 1], const TfhePke *p,
                   const TfheKeys *k) {
  uint64_t lut[TFHE_POLY_N];
  uint8_t table[TFHE_PLAIN];
  unsigned x;
  for (x = 0; x < TFHE_PLAIN; x++) table[x] = (uint8_t)x;
  tfhe_lut(lut, table);
  tfhe_pbs_ksk(f, out, in, p->cksk, k, lut);
}

void tfhe_radix_luts(TfheRadixLuts *l) {
  uint8_t table[TFHE_LUTS][TFHE_PLAIN];
  unsigned v, id;
  for (v = 0; v < TFHE_PLAIN; v++) {
    unsigned h = v / TFHE_MSG_MOD, lo = v % TFHE_MSG_MOD;
    unsigned merge = h == TFHE_CMP_EQ ? lo : h;
    table[TFHE_LUT_MSG][v] = (uint8_t)lo;
    table[TFHE_LUT_CARRY][v] = (uint8_t)h;
    table[TFHE_LUT_CMP][v] = (uint8_t)((h >= lo) + (h > lo)); /* LT 0, EQ 1, GT 2 */
    table[TFHE_LUT_MERGE][v] = (uint8_t)merge;
    table[TFHE_LUT_LE][v] = (uint8_t)(merge != TFHE_CMP_GT);
  }
  for (id = 0; id < TFHE_LUTS; id++) tfhe_lut(l->lut[id], table[id]);
}

void tfhe_block_add(uint64_t dst[TFHE_BLOCK_WORDS], const uint64_t a[TFHE_BLOCK_WORDS]) {
  unsigned j;
  for (j = 0; j < TFHE_BLOCK_WORDS; j++) dst[j] += a[j];
}

void tfhe_block_scale(uint64_t dst[TFHE_BLOCK_WORDS], uint64_t c) {
  unsigned j;
  for (j = 0; j < TFHE_BLOCK_WORDS; j++) dst[j] *= c;
}

/* Digit I (2 bits) of X. */
static unsigned radix_digit(uint64_t x, unsigned i) {
  return (unsigned)(x >> (2u * i)) & (TFHE_MSG_MOD - 1u);
}

void tfhe_radix_encrypt(TfheRadix *r, const TfheKeys *k, uint64_t x, TfheDrbg *d) {
  unsigned i;
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) {
    tfhe_lwe_encrypt(r->block[i], k->glwe_key, TFHE_BIG_N, tfhe_encode(radix_digit(x, i)), TFHE_GLWE_NOISE, d);
  }
}

void tfhe_radix_trivial(TfheRadix *r, uint64_t x) {
  unsigned i;
  memset(r, 0, sizeof *r);
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) r->block[i][TFHE_BIG_N] = tfhe_encode(radix_digit(x, i));
}

uint64_t tfhe_radix_decrypt(const TfheRadix *r, const TfheKeys *k) {
  uint64_t x = 0;
  unsigned i;
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) {
    unsigned v = tfhe_decode(tfhe_lwe_phase(r->block[i], k->glwe_key, TFHE_BIG_N));
    x |= (uint64_t)(v % TFHE_MSG_MOD) << (2u * i);
  }
  return x;
}

void tfhe_radix_propagate(const TfheFft *f, TfheRadix *r, const TfheKeys *k, const TfheRadixLuts *l) {
  uint64_t carry[TFHE_BLOCK_WORDS], msg[TFHE_BLOCK_WORDS];
  unsigned i;
  for (i = 0; i + 1u < TFHE_RADIX_BLOCKS; i++) {
    tfhe_pbs(f, carry, r->block[i], k, l->lut[TFHE_LUT_CARRY]);
    tfhe_pbs(f, msg, r->block[i], k, l->lut[TFHE_LUT_MSG]);
    memcpy(r->block[i], msg, sizeof msg);
    tfhe_block_add(r->block[i + 1u], carry);
  }
  tfhe_pbs(f, msg, r->block[TFHE_RADIX_BLOCKS - 1], k, l->lut[TFHE_LUT_MSG]);
  memcpy(r->block[TFHE_RADIX_BLOCKS - 1], msg, sizeof msg);
}

/* OUT += Y, block by block. */
static void radix_add_blocks(TfheRadix *out, const TfheRadix *y) {
  unsigned i;
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) tfhe_block_add(out->block[i], y->block[i]);
}

void tfhe_radix_add(const TfheFft *f, TfheRadix *out, const TfheRadix *x, const TfheRadix *y, const TfheKeys *k,
                    const TfheRadixLuts *l) {
  memcpy(out, x, sizeof *out);
  radix_add_blocks(out, y);
  tfhe_radix_propagate(f, out, k, l);
}

void tfhe_radix_scalar_mul(TfheRadix *out, const uint64_t bit[TFHE_BLOCK_WORDS], uint64_t a) {
  unsigned i;
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) {
    memcpy(out->block[i], bit, sizeof out->block[i]);
    tfhe_block_scale(out->block[i], radix_digit(a, i));
  }
}

/* OUT = 4 H + L, the PBS input of a block pair. */
static void block_pair(uint64_t out[TFHE_BLOCK_WORDS], const uint64_t h[TFHE_BLOCK_WORDS],
                       const uint64_t l[TFHE_BLOCK_WORDS]) {
  memcpy(out, h, TFHE_BLOCK_WORDS * sizeof out[0]);
  tfhe_block_scale(out, TFHE_MSG_MOD);
  tfhe_block_add(out, l);
}

void tfhe_radix_le(const TfheFft *f, uint64_t out[TFHE_BLOCK_WORDS], const TfheRadix *x, const TfheRadix *y,
                   const TfheKeys *k, const TfheRadixLuts *l) {
  uint64_t in[TFHE_BLOCK_WORDS], cmp[TFHE_BLOCK_WORDS], acc[TFHE_BLOCK_WORDS];
  unsigned i;
  block_pair(in, x->block[TFHE_RADIX_BLOCKS - 1], y->block[TFHE_RADIX_BLOCKS - 1]);
  tfhe_pbs(f, acc, in, k, l->lut[TFHE_LUT_CMP]);
  /* Block i - 1 goes into ACC; block 0 takes LE in place of MERGE. */
  for (i = TFHE_RADIX_BLOCKS - 1; i > 0; i--) {
    block_pair(in, x->block[i - 1u], y->block[i - 1u]);
    tfhe_pbs(f, cmp, in, k, l->lut[TFHE_LUT_CMP]);
    block_pair(in, acc, cmp);
    tfhe_pbs(f, acc, in, k, l->lut[i > 1u ? TFHE_LUT_MERGE : TFHE_LUT_LE]);
  }
  memcpy(out, acc, sizeof acc);
}

void tfhe_radix_sum(const TfheFft *f, TfheRadix *out, const TfheRadix *xs, size_t n, const TfheKeys *k,
                    const TfheRadixLuts *l) {
  size_t i;
  memcpy(out, &xs[0], sizeof *out);
  for (i = 1; i < n; i++) {
    radix_add_blocks(out, &xs[i]);
    if (i % 3u == 0 || i + 1u == n) tfhe_radix_propagate(f, out, k, l);
  }
}
