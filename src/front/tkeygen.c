/* The MPC key generation base: see front/tkeygen.h. */
#include "front/tkeygen.h"

#include <stdlib.h>
#include <string.h>

/* (p + 1) / 2, low word first: the inverse of 2. */
static const TshareFe half = {{0xfffffffffff67001u, 0xffffffffffffffffu, 0x7fffffffffffffffu}};

unsigned tkeygen_degree(TkeygenDegree degree) {
  switch (degree) {
  case TKEYGEN_DEGREE_T:
    return TSHARE_THRESHOLD;
  case TKEYGEN_DEGREE_2T:
    return 2 * TSHARE_THRESHOLD;
  }
  return TSHARE_THRESHOLD;
}

/* SHA-512(party || seed), the party number as 4 bytes, low byte first. */
static void commit(uint8_t digest[SHA512_BYTES], unsigned party, const uint8_t seed[TKEYGEN_SEED_BYTES]) {
  Sha512 s;
  uint8_t number[4];
  unsigned i;
  for (i = 0; i < 4; i++) number[i] = (uint8_t)(party >> (8u * i));
  sha512_init(&s);
  sha512_update(&s, number, 4);
  sha512_update(&s, seed, TKEYGEN_SEED_BYTES);
  sha512_final(&s, digest);
}

int tkeygen_toss_draw(TkeygenToss *toss, unsigned party, TfheDrbg *d) {
  unsigned i;
  if (party < 1 || party > TSHARE_PARTIES) return 0;
  for (i = 0; i < TKEYGEN_SEED_BYTES; i++) toss->seed[party - 1][i] = (uint8_t)tfhe_drbg_bytes(d, 1);
  commit(toss->commit[party - 1], party, toss->seed[party - 1]);
  return 1;
}

int tkeygen_toss_check(const TkeygenToss *toss) {
  uint8_t digest[SHA512_BYTES];
  unsigned j;
  int ok = 1;
  for (j = 0; j < TSHARE_PARTIES; j++) {
    commit(digest, j + 1, toss->seed[j]);
    ok &= memcmp(digest, toss->commit[j], SHA512_BYTES) == 0;
  }
  return ok;
}

int tkeygen_toss_joint(uint8_t joint[SHA512_BYTES], TfheDrbg *masks, const TkeygenToss *toss) {
  Sha512 s;
  unsigned j;
  if (!tkeygen_toss_check(toss)) return 0;
  sha512_init(&s);
  for (j = 0; j < TSHARE_PARTIES; j++) sha512_update(&s, toss->seed[j], TKEYGEN_SEED_BYTES);
  sha512_final(&s, joint);
  tfhe_drbg_init(masks, joint);
  return 1;
}

void tkeygen_deal(TshareFe *shares, const TshareFe *secret, size_t count, TkeygenDegree degree, TfheDrbg *d) {
  TshareFe coef[2 * TSHARE_THRESHOLD + 1];
  unsigned top = tkeygen_degree(degree), i, e;
  size_t j;
  for (j = 0; j < count; j++) {
    coef[0] = secret[j];
    for (e = 1; e <= top; e++) coef[e] = tshare_random(d);
    for (i = 0; i < TSHARE_PARTIES; i++) {
      TshareFe x = tshare_from_u64(i + 1), y = coef[top];
      for (e = top; e > 0; e--) y = tshare_add(tshare_mul(y, x), coef[e - 1]);
      shares[i * count + j] = y;
    }
  }
}

void tkeygen_add(TshareFe *out, const TshareFe *one, size_t count) {
  size_t k;
  for (k = 0; k < TSHARE_PARTIES * count; k++) out[k] = tshare_add(out[k], one[k]);
}

void tkeygen_zero(TshareFe *zero, size_t count, TfheDrbg party[TSHARE_PARTIES]) {
  const TshareFe nil = tshare_from_u64(0);
  TshareFe deal[TSHARE_PARTIES];
  size_t k;
  unsigned i, j;
  for (k = 0; k < TSHARE_PARTIES * count; k++) zero[k] = nil;
  for (k = 0; k < count; k++)
    for (j = 0; j < TSHARE_PARTIES; j++) {
      tkeygen_deal(deal, &nil, 1, TKEYGEN_DEGREE_2T, &party[j]);
      for (i = 0; i < TSHARE_PARTIES; i++) zero[i * count + k] = tshare_add(zero[i * count + k], deal[i]);
    }
}

/* The value at 0 of the degree-2t polynomial through the 5 shares: the
 * Lagrange coefficients at 0 for the points 1 to 5 are 5, -10, 10, -5, 1. */
static TshareFe open_all(const TshareFe v[TSHARE_PARTIES]) {
  static const int64_t lambda[TSHARE_PARTIES] = {5, -10, 10, -5, 1};
  TshareFe sum = tshare_from_u64(0);
  unsigned i;
  for (i = 0; i < TSHARE_PARTIES; i++) sum = tshare_add(sum, tshare_mul(tshare_from_i64(lambda[i]), v[i]));
  return sum;
}

int tkeygen_bit_try(TkeygenBit *b, TfheDrbg party[TSHARE_PARTIES]) {
  TshareFe deal[TSHARE_PARTIES], zero[TSHARE_PARTIES], r, root, inv;
  unsigned i, j;
  for (i = 0; i < TSHARE_PARTIES; i++) b->r[i] = tshare_from_u64(0);
  for (j = 0; j < TSHARE_PARTIES; j++) {
    r = tshare_random(&party[j]);
    tkeygen_deal(deal, &r, 1, TKEYGEN_DEGREE_T, &party[j]);
    tkeygen_add(b->r, deal, 1);
  }
  tkeygen_zero(zero, 1, party);
  for (i = 0; i < TSHARE_PARTIES; i++) b->opened[i] = tshare_add(tshare_mul(b->r[i], b->r[i]), zero[i]);
  b->square = open_all(b->opened);
  if (tshare_eq(b->square, tshare_from_u64(0)) || !tshare_sqrt(&root, b->square)) return 0;
  inv = tshare_inverse(root);
  for (i = 0; i < TSHARE_PARTIES; i++)
    b->bit[i] = tshare_mul(tshare_add(tshare_mul(b->r[i], inv), tshare_from_u64(1)), half);
  return 1;
}

void tkeygen_bits(TshareFe *bits, size_t count, TfheDrbg party[TSHARE_PARTIES]) {
  TkeygenBit b;
  size_t j;
  unsigned i;
  for (j = 0; j < count; j++) {
    int done = 0;
    while (!done) done = tkeygen_bit_try(&b, party);
    for (i = 0; i < TSHARE_PARTIES; i++) bits[i * count + j] = b.bit[i];
  }
}

TshareFe tkeygen_lift(uint64_t e) {
  if (e >> 63) return tshare_sub(tshare_from_u64(0), tshare_from_u64(0u - e));
  return tshare_from_u64(e);
}

void tkeygen_noise(TshareFe *shares, uint64_t *e, size_t count, unsigned set_log, TkeygenDegree degree,
                   TfheDrbg *d) {
  TshareFe lift, deal[TSHARE_PARTIES];
  size_t k;
  unsigned i;
  for (k = 0; k < count; k++) {
    e[k] = tfhe_tuniform(d, set_log - 1u);
    lift = tkeygen_lift(e[k]);
    tkeygen_deal(deal, &lift, 1, degree, d);
    for (i = 0; i < TSHARE_PARTIES; i++) shares[i * count + k] = deal[i];
  }
}

/* 1 when V >= (p + 1) / 2: then V is the lift of the negative value V - p. */
static int at_least_half(TshareFe v) {
  unsigned k = TSHARE_LIMBS;
  while (k > 0) {
    k--;
    if (v.w[k] != half.w[k]) return v.w[k] > half.w[k];
  }
  return 1;
}

uint64_t tkeygen_word64(TshareFe v) {
  TshareFe n;
  if (!at_least_half(v)) return v.w[0];
  n = tshare_sub(tshare_from_u64(0), v);
  return 0u - n.w[0];
}

Squash128 tkeygen_word128(TshareFe v) {
  Squash128 r;
  TshareFe n;
  if (!at_least_half(v)) {
    r.lo = v.w[0];
    r.hi = v.w[1];
    return r;
  }
  n = tshare_sub(tshare_from_u64(0), v);
  r.lo = n.w[0];
  r.hi = n.w[1];
  return squash_neg(r);
}

void tkeygen_shares(TkeygenShares *s, TfheDrbg party[TSHARE_PARTIES]) {
  tkeygen_bits(&s->lwe[0][0], TFHE_LWE_N, party);
  tkeygen_bits(&s->glwe[0][0], TFHE_POLY_N, party);
  tkeygen_bits(&s->pke[0][0], TFHE_BIG_N, party);
  tkeygen_bits(&s->squash[0][0], SQUASH_BIG_N, party);
}

void tkeygen_work_init(TkeygenWork *w) {
  tshare_ntt_init(&w->ntt);
  w->key_count = 0;
}

void tkeygen_load(TkeygenWork *w, const TkeygenShares *s, TkeygenKey key) {
  unsigned i, k;
  size_t c;
  switch (key) {
  case TKEYGEN_KEY_GLWE:
    w->key_count = 1;
    for (i = 0; i < TSHARE_PARTIES; i++) memcpy(w->key[i][0], s->glwe[i], sizeof w->key[i][0]);
    break;
  case TKEYGEN_KEY_PKE:
    w->key_count = 1;
    for (i = 0; i < TSHARE_PARTIES; i++)
      for (c = 0; c < TSHARE_N; c++) w->key[i][0][c] = s->pke[i][TFHE_BIG_N - 1 - c];
    break;
  case TKEYGEN_KEY_SQUASH:
    w->key_count = SQUASH_GLWE_K;
    for (i = 0; i < TSHARE_PARTIES; i++)
      for (k = 0; k < SQUASH_GLWE_K; k++) memcpy(w->key[i][k], &s->squash[i][k * TSHARE_N], sizeof w->key[i][k]);
    break;
  }
  for (i = 0; i < TSHARE_PARTIES; i++)
    for (k = 0; k < w->key_count; k++) tshare_ntt_forward(&w->ntt, w->key[i][k]);
}

/* 2^(WORD_LOG - BASE_LOG LEVEL): the gadget value of LEVEL (level 1 is the
 * most significant). */
static TshareFe gadget(unsigned word_log, unsigned base_log, unsigned level) {
  const unsigned e = word_log - base_log * level;
  TshareFe g = tshare_from_u64(0);
  g.w[e / 64u] = (uint64_t)1 << (e % 64u);
  return g;
}

/* The plaintext shares of a product row: -g s_i S_i[c] (degree 2t). BIT and
 * POLY: the shares of party i at bit[i STRIDE] and poly[i POLY_STRIDE + c]. */
static void plain_product(TkeygenWork *w, const TshareFe *bit, size_t stride, const TshareFe *poly,
                          size_t poly_stride, TshareFe g) {
  const TshareFe nil = tshare_from_u64(0);
  unsigned i;
  size_t c;
  for (i = 0; i < TSHARE_PARTIES; i++) {
    TshareFe gs = tshare_mul(g, bit[i * stride]);
    for (c = 0; c < TSHARE_N; c++) w->share[i][c] = tshare_sub(nil, tshare_mul(gs, poly[i * poly_stride + c]));
  }
}

/* The plaintext shares of a linear row: g s_i at coefficient 0 (degree t). */
static void plain_const(TkeygenWork *w, const TshareFe *bit, size_t stride, TshareFe g) {
  const TshareFe nil = tshare_from_u64(0);
  unsigned i;
  size_t c;
  for (i = 0; i < TSHARE_PARTIES; i++) {
    for (c = 0; c < TSHARE_N; c++) w->share[i][c] = nil;
    w->share[i][0] = tshare_mul(g, bit[i * stride]);
  }
}

/* One GLWE opening: w->mask has the K masks and w->share the plaintext
 * shares. Party i adds sum_k A_k S_k,i (in the NTT form: one inverse NTT for
 * each party) and the noise of the 5 dealers; then each coefficient is
 * opened into w->open. ESUM: the noise sum. */
static void glwe_row(TkeygenWork *w, uint64_t esum[TSHARE_N], unsigned set_log, TkeygenDegree degree,
                     TfheDrbg party[TSHARE_PARTIES]) {
  TshareFe v[TSHARE_PARTIES];
  unsigned i, j, k;
  size_t c;
  for (k = 0; k < w->key_count; k++) tshare_ntt_forward(&w->ntt, w->mask[k]);
  for (i = 0; i < TSHARE_PARTIES; i++) {
    for (c = 0; c < TSHARE_N; c++) {
      TshareFe sum = tshare_from_u64(0);
      for (k = 0; k < w->key_count; k++) sum = tshare_add(sum, tshare_mul(w->mask[k][c], w->key[i][k][c]));
      w->acc[c] = sum;
    }
    tshare_ntt_inverse(&w->ntt, w->acc);
    for (c = 0; c < TSHARE_N; c++) w->share[i][c] = tshare_add(w->share[i][c], w->acc[c]);
  }
  for (c = 0; c < TSHARE_N; c++) esum[c] = 0;
  for (j = 0; j < TSHARE_PARTIES; j++) {
    tkeygen_noise(w->deal, w->e, TSHARE_N, set_log, degree, &party[j]);
    for (c = 0; c < TSHARE_N; c++) esum[c] += w->e[c];
    tkeygen_add(&w->share[0][0], w->deal, TSHARE_N);
  }
  for (c = 0; c < TSHARE_N; c++) {
    for (i = 0; i < TSHARE_PARTIES; i++) v[i] = w->share[i][c];
    w->open[c] = open_all(v);
  }
}

/* One TFHE GLWE opening: N mask words from MASKS into MASK, the body into
 * BODY (w->share has the plaintext shares). */
static void tfhe_row(TkeygenWork *w, uint64_t *mask, uint64_t *body, uint64_t esum[TSHARE_N], unsigned set_log,
                     TkeygenDegree degree, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]) {
  size_t c;
  for (c = 0; c < TFHE_POLY_N; c++) {
    mask[c] = tfhe_uniform(masks);
    w->mask[0][c] = tshare_from_u64(mask[c]);
  }
  glwe_row(w, esum, set_log, degree, party);
  for (c = 0; c < TFHE_POLY_N; c++) body[c] = tkeygen_word64(w->open[c]);
}

void tkeygen_lwe_row(uint64_t *ct, uint64_t *esum, const TshareFe *key, size_t n, const TshareFe plain[TSHARE_PARTIES],
                     unsigned set_log, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]) {
  TshareFe share[TSHARE_PARTIES], deal[TSHARE_PARTIES], a;
  uint64_t e;
  size_t k;
  unsigned i, j;
  for (i = 0; i < TSHARE_PARTIES; i++) share[i] = plain[i];
  for (k = 0; k < n; k++) {
    ct[k] = tfhe_uniform(masks);
    a = tshare_from_u64(ct[k]);
    for (i = 0; i < TSHARE_PARTIES; i++) share[i] = tshare_add(share[i], tshare_mul(a, key[i * n + k]));
  }
  *esum = 0;
  for (j = 0; j < TSHARE_PARTIES; j++) {
    tkeygen_noise(deal, &e, 1, set_log, TKEYGEN_DEGREE_T, &party[j]);
    *esum += e;
    tkeygen_add(share, deal, 1);
  }
  ct[n] = tkeygen_word64(open_all(share));
}

void tkeygen_ksk(uint64_t *ksk, const TshareFe *in, const TkeygenShares *s, TfheDrbg *masks,
                 TfheDrbg party[TSHARE_PARTIES]) {
  TshareFe plain[TSHARE_PARTIES];
  uint64_t e;
  size_t j;
  unsigned i, l;
  for (j = 0; j < TFHE_BIG_N; j++)
    for (l = 0; l < TFHE_KS_LEVEL; l++) {
      TshareFe g = gadget(64, TFHE_KS_BASE_LOG, l + 1u);
      for (i = 0; i < TSHARE_PARTIES; i++) plain[i] = tshare_mul(g, in[i * TFHE_BIG_N + j]);
      tkeygen_lwe_row(ksk + (j * TFHE_KS_LEVEL + l) * (TFHE_LWE_N + 1), &e, &s->lwe[0][0], TFHE_LWE_N, plain,
                      TFHE_LWE_NOISE, masks, party);
    }
}

void tkeygen_bsk_ggsw(TkeygenWork *w, uint64_t *ct, size_t i, const TkeygenShares *s, TfheDrbg *masks,
                      TfheDrbg party[TSHARE_PARTIES]) {
  const TshareFe g = gadget(64, TFHE_PBS_BASE_LOG, 1);
  plain_product(w, &s->lwe[0][i], TFHE_LWE_N, &s->glwe[0][0], TFHE_POLY_N, g);
  tfhe_row(w, ct, ct + TFHE_POLY_N, w->esum[0], TFHE_GLWE_NOISE, TKEYGEN_DEGREE_2T, masks, party);
  plain_const(w, &s->lwe[0][i], TFHE_LWE_N, g);
  tfhe_row(w, ct + 2 * TFHE_POLY_N, ct + 3 * TFHE_POLY_N, w->esum[1], TFHE_GLWE_NOISE, TKEYGEN_DEGREE_T, masks, party);
}

void tkeygen_squash_row(TkeygenWork *w, Squash128 *ct, size_t i, unsigned level, unsigned row,
                        const TkeygenShares *s, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]) {
  const TshareFe g = gadget(128, SQUASH_BASE_LOG, level);
  TkeygenDegree degree = TKEYGEN_DEGREE_T;
  unsigned k;
  size_t c;
  if (row < SQUASH_GLWE_K) {
    plain_product(w, &s->lwe[0][i], TFHE_LWE_N, &s->squash[0][(size_t)row * SQUASH_POLY_N], SQUASH_BIG_N, g);
    degree = TKEYGEN_DEGREE_2T;
  } else {
    plain_const(w, &s->lwe[0][i], TFHE_LWE_N, g);
  }
  for (k = 0; k < SQUASH_GLWE_K; k++)
    for (c = 0; c < SQUASH_POLY_N; c++) {
      Squash128 a = squash_uniform(masks);
      ct[k * SQUASH_POLY_N + c] = a;
      w->mask[k][c] = tshare_from_u64(a.lo);
      w->mask[k][c].w[1] = a.hi;
    }
  glwe_row(w, w->esum[(level - 1u) * (SQUASH_GLWE_K + 1u) + row], SQUASH_NOISE, degree, party);
  for (c = 0; c < SQUASH_POLY_N; c++) ct[SQUASH_GLWE_K * SQUASH_POLY_N + c] = tkeygen_word128(w->open[c]);
}

void tkeygen_pk(TkeygenWork *w, TfhePke *p, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]) {
  const TshareFe nil = tshare_from_u64(0);
  unsigned i;
  size_t c;
  for (i = 0; i < TSHARE_PARTIES; i++)
    for (c = 0; c < TSHARE_N; c++) w->share[i][c] = nil;
  tfhe_row(w, p->pk_a, p->pk_b, w->esum[0], TFHE_PKE_NOISE, TKEYGEN_DEGREE_T, masks, party);
}

int tkeygen_keys(TfheKeys *k, TfhePke *p, SquashBsk *b, const TkeygenShares *s, const TfheFft *f, TfheDrbg *masks,
                 TfheDrbg party[TSHARE_PARTIES]) {
  TkeygenWork *w = malloc(sizeof *w);
  TfheFourier poly;
  size_t i;
  unsigned q, level, row;
  memset(k, 0, sizeof *k);
  memset(p, 0, sizeof *p);
  k->ksk = malloc((size_t)TFHE_KSK_WORDS * sizeof k->ksk[0]);
  k->bsk = malloc((size_t)TFHE_BSK_WORDS * sizeof k->bsk[0]);
  k->bsk_fourier = malloc((size_t)TFHE_BSK_FOURIER_DOUBLES * sizeof k->bsk_fourier[0]);
  p->cksk = malloc((size_t)TFHE_KSK_WORDS * sizeof p->cksk[0]);
  b->ggsw = malloc((size_t)SQUASH_BSK_WORDS * sizeof b->ggsw[0]);
  if (w == NULL || k->ksk == NULL || k->bsk == NULL || k->bsk_fourier == NULL || p->cksk == NULL || b->ggsw == NULL) {
    free(w);
    tfhe_keys_release(k);
    tfhe_pke_release(p);
    squash_bsk_release(b);
    return 0;
  }
  tkeygen_work_init(w);
  tkeygen_ksk(k->ksk, &s->glwe[0][0], s, masks, party);
  tkeygen_load(w, s, TKEYGEN_KEY_GLWE);
  for (i = 0; i < TFHE_LWE_N; i++) {
    uint64_t *ct = k->bsk + i * 4 * TFHE_POLY_N;
    tkeygen_bsk_ggsw(w, ct, i, s, masks, party);
    for (q = 0; q < 4; q++) {
      double *out = k->bsk_fourier + (i * 4 + q) * 2 * TFHE_FFT_M;
      tfhe_fft_forward(f, &poly, ct + q * TFHE_POLY_N);
      memcpy(out, poly.re, sizeof poly.re);
      memcpy(out + TFHE_FFT_M, poly.im, sizeof poly.im);
    }
  }
  tkeygen_load(w, s, TKEYGEN_KEY_PKE);
  tkeygen_pk(w, p, masks, party);
  tkeygen_ksk(p->cksk, &s->pke[0][0], s, masks, party);
  tkeygen_load(w, s, TKEYGEN_KEY_SQUASH);
  for (i = 0; i < TFHE_LWE_N; i++)
    for (level = 1; level <= SQUASH_LEVEL; level++)
      for (row = 0; row <= SQUASH_GLWE_K; row++)
        tkeygen_squash_row(w, b->ggsw + i * SQUASH_GGSW_WORDS + ((level - 1u) * (SQUASH_GLWE_K + 1u) + row) * SQUASH_GLWE_WORDS,
                           i, level, row, s, masks, party);
  free(w);
  return 1;
}
