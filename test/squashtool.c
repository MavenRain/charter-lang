/* The squash PBS rows (S6 U2b, Q-S6-13 (a)): `make check-squash` builds this
 * tool with cc -O2. It is not in `make check`: the squash BSK is 812 MB and
 * takes about 7 s at cc -O2 (45 s on tcc), and each squash PBS takes about
 * 1.9 s (15 s on tcc). Each input is an S5 PBS output, as a chain output: the
 * messages 0 to 15, then the 32 blocks of the credit plan value
 * p = 0x123456789ABCDEF0 (chain_stage in test/checktool.c; its blocks hold
 * the 2-bit digits 0 to 3). Each output must decode under the squash key with
 * Delta_128 = 2^123. The noise B must be below 2^82: then 2^40 B is below
 * Delta_128 / 2 = 2^122. The tdec rows (S6 U3, Q-S6-14 (a)): a test dealer
 * shares the squash key to the 5 parties; each output must decode after the
 * threshold decryption by S = {1, ..., 5} and by S = {3, 4, 5}, and the
 * blocks must give p for each set. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "front/squash.h"
#include "front/tdec.h"

static TfheKeys keys;
static TfheRadix radix;
static TshareFe shares[TSHARE_PARTIES * SQUASH_BIG_N];
static int fails;
static int tdec_ok = 1;

/* Prints the first 5 FAIL lines and counts all of them. */
static void check(int ok, const char *what, unsigned m) {
  if (!ok) {
    if (fails < 5) printf("FAIL squash pbs %s %u\n", what, m);
    fails++;
  }
}

/* body - <mask, key> under the squash LWE key (poly 0, then poly 1). */
static Squash128 phase(const Squash128 *ct, const SquashKey *k) {
  Squash128 p = ct[SQUASH_BIG_N];
  unsigned i, j;
  for (i = 0; i < SQUASH_GLWE_K; i++)
    for (j = 0; j < SQUASH_POLY_N; j++)
      if (k->s[i][j] != 0) p = squash_sub(p, ct[i * SQUASH_POLY_N + j]);
  return p;
}

/* Prints the first tdec FAIL line and clears tdec_ok. */
static void tdec_check(int ok, const char *what, unsigned m) {
  if (!ok && tdec_ok) printf("FAIL tdec squash %s %u\n", what, m);
  tdec_ok &= ok;
}

/* Threshold decryption of (MASK, BODY) by the M parties in SUBSET (U3; a
 * copy of tdec_run in test/checktool.c). The test dealer gave the key shares
 * SHARES (party i holds the 4096 values at (i - 1) 4096); each party in
 * SUBSET also deals a flood noise. */
static int tdec_run(Squash128 *phase, TshareFe *partial, const TshareFe *shares, const Squash128 *mask, Squash128 body,
                    const unsigned *subset, unsigned m, TfheDrbg *d) {
  static TshareFe noise[TSHARE_PARTIES * TSHARE_PARTIES];
  unsigned i;
  for (i = 0; i < m; i++) tdec_flood(noise + i * TSHARE_PARTIES, d);
  for (i = 0; i < m; i++)
    partial[i] = tdec_partial(shares + (size_t)(subset[i] - 1) * SQUASH_BIG_N, mask, noise, m, subset[i]);
  return tdec_combine(phase, body, partial, subset, m);
}

/* The decode of the threshold decryption of the squash LWE CT by the M
 * parties in SUBSET, or 32 when the combine gives no phase. */
static unsigned tdec_value(const Squash128 *ct, const unsigned *subset, unsigned m, TfheDrbg *d) {
  TshareFe partial[TSHARE_PARTIES];
  Squash128 ph;
  return tdec_run(&ph, partial, shares, ct, ct[SQUASH_BIG_N], subset, m, d) ? tdec_decode(ph) : 32u;
}

/* The bit length of |P - V Delta_128|. */
static unsigned noise_bits(Squash128 p, unsigned v) {
  Squash128 e = squash_sub(p, squash_shl(squash_from_u64(v), SQUASH_DELTA_LOG));
  unsigned b = 0;
  if (e.hi >> 63) e = squash_neg(e);
  while (b < 128 && !squash_eq(squash_shr(e, b), squash_from_u64(0))) b++;
  return b;
}

int main(void) {
  static TfheFft f;
  static uint64_t lut[TFHE_POLY_N], ct[TFHE_BIG_N + 1], pbs[TFHE_BIG_N + 1];
  static Squash128 out[SQUASH_BIG_N + 1];
  static uint8_t table[TFHE_PLAIN];
  static TshareFe key[SQUASH_BIG_N];
  static const unsigned all[TSHARE_PARTIES] = {1, 2, 3, 4, 5};
  static const unsigned three[3] = {3, 4, 5};
  SquashKey *k = malloc(sizeof *k);
  SquashFftWork *w = malloc(sizeof *w);
  SquashPbsWork *pw = malloc(sizeof *pw);
  uint8_t seed[TFHE_SEED_BYTES], tseed[TFHE_SEED_BYTES];
  const uint64_t p = 0x123456789ABCDEF0u;
  uint64_t got = 0, got5 = 0, got3 = 0;
  SquashBsk bsk;
  Squash128 ph;
  TfheDrbg d, td;
  unsigned m, i, v5, v3, worst = 0;
  memset(seed, 0, sizeof seed);
  memcpy(seed, "charter-lang S6 U2b squash seed!", 32);
  tfhe_drbg_init(&d, seed);
  tfhe_fft_init(&f);
  if (k == NULL || w == NULL || pw == NULL || !tfhe_keys_generate(&keys, &f, &d)) {
    puts("FAIL squash pbs keys");
    return 1;
  }
  squash_key_generate(k, &d);
  if (!squash_bsk_generate(&bsk, &f, w, k, keys.lwe_key, &d)) {
    puts("FAIL squash pbs bsk allocation");
    return 1;
  }
  for (i = 0; i < TFHE_PLAIN; i++) table[i] = (uint8_t)i;
  tfhe_lut(lut, table);
  /* The test dealer of the tdec rows. It has its own DRBG, so the U2b rows
   * do not change. */
  memset(tseed, 0, sizeof tseed);
  memcpy(tseed, "charter-lang S6 U3 tdec squash!!", 32);
  tfhe_drbg_init(&td, tseed);
  for (i = 0; i < SQUASH_BIG_N; i++) key[i] = tshare_from_u64((uint64_t)k->s[i / SQUASH_POLY_N][i % SQUASH_POLY_N]);
  tshare_share(shares, key, SQUASH_BIG_N, &td);

  /* The messages 0 to 15: an S5 PBS output of m, then the squash. */
  for (m = 0; m < TFHE_PLAIN; m++) {
    tfhe_lwe_encrypt(ct, keys.glwe_key, TFHE_BIG_N, tfhe_encode(m), TFHE_GLWE_NOISE, &d);
    tfhe_pbs(&f, pbs, ct, &keys, lut);
    check(tfhe_decode(tfhe_lwe_phase(pbs, keys.glwe_key, TFHE_BIG_N)) == m, "S5 pbs of m", m);
    squash_pbs(&f, pw, out, pbs, keys.ksk, &bsk);
    ph = phase(out, k);
    check(tdec_decode(ph) == m, "decode of m", m);
    if (noise_bits(ph, m) > worst) worst = noise_bits(ph, m);
    tdec_check(tdec_value(out, all, TSHARE_PARTIES, &td) == m, "of m, S = {1, ..., 5}, m", m);
    tdec_check(tdec_value(out, three, 3, &td) == m, "of m, S = {3, 4, 5}, m", m);
  }

  /* The credit plan value p: 32 blocks of 2 bits, the low block first. */
  tfhe_radix_encrypt(&radix, &keys, p, &d);
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) {
    unsigned digit = (unsigned)(p >> (2u * i)) & 3u;
    tfhe_pbs(&f, pbs, radix.block[i], &keys, lut);
    squash_pbs(&f, pw, out, pbs, keys.ksk, &bsk);
    ph = phase(out, k);
    check(tdec_decode(ph) == digit, "decode of block", i);
    if (noise_bits(ph, digit) > worst) worst = noise_bits(ph, digit);
    got |= (uint64_t)(tdec_decode(ph) & 3u) << (2u * i);
    v5 = tdec_value(out, all, TSHARE_PARTIES, &td);
    v3 = tdec_value(out, three, 3, &td);
    tdec_check(v5 == digit, "of a block, S = {1, ..., 5}, block", i);
    tdec_check(v3 == digit, "of a block, S = {3, 4, 5}, block", i);
    got5 |= (uint64_t)(v5 & 3u) << (2u * i);
    got3 |= (uint64_t)(v3 & 3u) << (2u * i);
  }
  check(got == p, "value of p", 0);
  tdec_check(got5 == p, "value of p, S = {1, ..., 5},", 0);
  tdec_check(got3 == p, "value of p, S = {3, 4, 5},", 0);
  check(worst + 40u < 122u, "flooding margin, noise bits", worst);
  printf("squash pbs noise: B below 2^%u, 2^40 B below 2^%u, Delta_128 / 2 = 2^122\n", worst, worst + 40u);
  if (fails == 0) puts("squash pbs rows: passed");
  if (tdec_ok) puts("tdec squash rows: passed");
  squash_bsk_release(&bsk);
  tfhe_keys_release(&keys);
  free(k);
  free(w);
  free(pw);
  return fails != 0 || !tdec_ok;
}
