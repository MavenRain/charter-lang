/* The MPC key set rows (S6b U4b, Q-S6-17 (a)): `make check-mpc` builds this
 * tool with cc -O2. It is not in `make check`: the 5 parties make the full
 * key set (the KSK, the BSK, pk, the cast KSK and the 812 MB squash BSK) in
 * about 190 s at cc -O2. A coin toss gives the masks DRBG, tkeygen_shares
 * deals the key bits and tkeygen_keys makes the public keys from the
 * shares. The check keys are the clear keys from the shares of all 5 parties
 * (the Lagrange combine at 0). Each row uses an MPC key: the key switch, the
 * PBS, the pk encryption and the cast, and the squash PBS must give the
 * clear value. The squash GGSW row opens one row of the MPC squash BSK and
 * checks its noise bound. U4c (Q-S6-18 (a)): the S5 chain through fhe_eval
 * under the MPC keys, and the threshold decryption of the squash PBS outputs
 * with the MPC squash key shares. U5 (Q-S6-6 (c), Q-S6-19 (b), Q-S6-20 (a)): a
 * second MPC key set (epoch e+1) and the masked re-encryption of 4 blocks of m
 * and the 32 blocks of the credit q2 from epoch e to epoch e+1. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "front/fhe.h"
#include "front/tdec.h"
#include "front/tkeygen.h"

static TfheFft f;
static TkeygenShares s;
static TkeygenToss toss;
static TfheKeys k, clear;
static TfhePke p, pc;
static SquashKey sk;
static int fails;

/* Prints the first 5 FAIL lines and counts all of them. */
static void check(int ok, const char *what, unsigned m) {
  if (!ok) {
    if (fails < 5) printf("FAIL mpc %s %u\n", what, m);
    fails++;
  }
}

static double since(clock_t c0) {
  return (double)(clock() - c0) / CLOCKS_PER_SEC;
}

/* The clear key bits from the shares of the 5 parties (SHARES[(i - 1) N +
 * j], the Lagrange coefficients LAMBDA of {1, ..., 5}). Each bit must be 0
 * or 1. Returns the count of the bad bits. */
static unsigned open_key(uint64_t *bit, const TshareFe *shares, size_t n, const TshareFe lambda[TSHARE_PARTIES]) {
  unsigned bad = 0, i;
  size_t j;
  for (j = 0; j < n; j++) {
    TshareFe v = tshare_from_u64(0);
    for (i = 0; i < TSHARE_PARTIES; i++) v = tshare_add(v, tshare_mul(lambda[i], shares[i * n + j]));
    bit[j] = tshare_eq(v, tshare_from_u64(1)) ? 1u : 0u;
    if (!tshare_eq(v, tshare_from_u64(bit[j]))) bad++;
  }
  return bad;
}

/* body - <mask, key> under the squash LWE key (poly 0, then poly 1). */
static Squash128 phase(const Squash128 *ct, const SquashKey *key) {
  Squash128 v = ct[SQUASH_BIG_N];
  unsigned i, j;
  for (i = 0; i < SQUASH_GLWE_K; i++)
    for (j = 0; j < SQUASH_POLY_N; j++)
      if (key->s[i][j] != 0) v = squash_sub(v, ct[i * SQUASH_POLY_N + j]);
  return v;
}

/* Threshold decryption of (MASK, BODY) by the M parties in SUBSET (the form
 * of checktool.c tdec_run): party i holds the shares at (i - 1) 4096; each
 * party in SUBSET also deals a flood noise. */
static int tdec_run(Squash128 *phase, TshareFe *partial, const TshareFe *shares, const Squash128 *mask, Squash128 body,
                    const unsigned *subset, unsigned m, TfheDrbg *d) {
  static TshareFe noise[TSHARE_PARTIES * TSHARE_PARTIES];
  unsigned i;
  for (i = 0; i < m; i++) tdec_flood(noise + i * TSHARE_PARTIES, d);
  for (i = 0; i < m; i++)
    partial[i] = tdec_partial(shares + (size_t)(subset[i] - 1) * SQUASH_BIG_N, mask, noise, m, subset[i]);
  return tdec_combine(phase, body, partial, subset, m);
}

/* The S5 chain under the MPC keys (checktool.c fhe_chain_rows, no node and no
 * Wasm): the C pk encryption of the 18 client lines, the C cast of the 113
 * used slots with the MPC cast KSK, then tally4, tally3 (run A), theta, amd,
 * settle, credit and withdraw (runs B to E) through fhe_eval with the MPC KSK
 * and BSK. Each input decrypts to the S5 plan; each output decrypts to f of
 * the decrypted inputs and to the plan. */
enum { CHAIN_LINES = 18, CHAIN_CASTS = 113, CHAIN_DEC = 0, CHAIN_BALLOT = 28, CHAIN_Q = 49, CHAIN_P = 81 };
static const unsigned chain_dec[7] = {0, 0, 0, 1, 1, 2, 3};
static const unsigned chain_ballot[7] = {0, 0, 0, 0, 1, 1, 2};
static const uint64_t chain_radix[2] = {0x00000000FFFFFFFFu, 0x123456789ABCDEF0u};
typedef struct ChainStage {
  FheKind kind;
  unsigned ni, no;
  const char *name[7];
  uint64_t plan[7];
} ChainStage;
static const ChainStage chain_stage[5] = {
  {FHE_THETA, 3, 1, {"cRel", "cRef", "t", "d"}, {3, 2, 3, 0}},
  {FHE_AMD, 4, 1, {"cAdopt", "cReject", "tA", "slack", "code"}, {4, 2, 4, 3, 0}},
  {FHE_SETTLE, 1, 3, {"d", "r", "rf", "z"}, {0, 1, 0, 1}},
  {FHE_CREDIT, 5, 2, {"q", "p", "r", "rf", "amount", "q2", "p2"},
   {0x00000000FFFFFFFFu, 0x123456789ABCDEF0u, 1, 0, 1, 0x0000000100000000u, 0x123456789ABCDEF0u}},
  {FHE_WITHDRAW, 2, 2, {"a", "amount", "ok", "a2"}, {0x0000000100000000u, 0x00000000FFFFFFFFu, 1, 1}}};
static FheEval ev;
static FheLuts luts;
static TfheRadixLuts radix_luts;
static FheCircuit circ;
static TfheRadix rin[2], count[7], chain_out[5][3];
static uint64_t bin[FHE_INPUTS][TFHE_BLOCK_WORDS], param[FHE_INPUTS];
static uint64_t chain_cast[CHAIN_CASTS][TFHE_BLOCK_WORDS];
static unsigned chain_pbs;

/* The used slots of client line LINE: 4 (DecE), 3 (BallotA) or 16 (q, p). */
static unsigned chain_width(unsigned line) {
  return line < 7u ? 4u : line < 14u ? 3u : (unsigned)TFHE_PLAIN;
}

/* The 16 messages of client line LINE: a ballot has 1 at its choice; lines 14
 * to 17 are the 2-bit digits of q and p, low digit first. */
static void chain_list(uint8_t m[TFHE_PLAIN], unsigned line) {
  const unsigned w = chain_width(line), half = line < 14u ? 0u : line - 14u;
  const unsigned choice = line < 7u ? chain_dec[line] : line < 14u ? chain_ballot[line - 7u] : 0u;
  unsigned j;
  for (j = 0; j < TFHE_PLAIN; j++)
    m[j] = (uint8_t)(line < 14u ? (uint64_t)(j < w && j == choice)
                                : (chain_radix[half / 2u] >> (2u * (16u * (half % 2u) + j))) & 3u);
}

/* Output I of stage KIND on the decrypted inputs V (the stream order). */
static uint64_t chain_f(FheKind kind, const uint64_t *v, unsigned i) {
  const uint64_t settle[3] = {v[0] == 0u, v[0] == 1u, v[0] <= 1u};
  return kind == FHE_THETA    ? (v[2] <= v[0] ? 0u : v[2] <= v[1] ? 1u : 2u)
         : kind == FHE_AMD    ? (v[2] <= v[0] ? 0u : v[3] < v[1] ? 1u : 2u)
         : kind == FHE_SETTLE ? settle[i % 3u]
         : kind == FHE_CREDIT ? v[i % 2u] + v[2u + i % 2u] * v[4]
         : i == 0             ? (uint64_t)(v[1] <= v[0])
                              : v[1] <= v[0] ? v[0] - v[1] : v[0];
}

/* The decode of block B under the opened big key. */
static uint64_t value(const uint64_t *b) {
  return tfhe_decode(tfhe_lwe_phase(b, clear.glwe_key, TFHE_BIG_N));
}

/* One chain row of circuit circ: value NAME I (TAG " (1.1)": against f). */
static void chain_check(int ok, const char *name, unsigned i, const char *tag, uint64_t got, uint64_t want) {
  if (!ok && fails < 5)
    printf("FAIL mpc chain %s: %s %u%s = 0x%llx, want 0x%llx\n", circ.name, name, i, tag, (unsigned long long)got,
           (unsigned long long)want);
  fails += !ok;
}

/* Output I of the last fhe_eval of circ (a block output goes to block 0). */
static void chain_get(TfheRadix *r, unsigned i) {
  if (circ.out[i].slot == FHE_RADIX_REG)
    *r = ev.radix[circ.out[i].index];
  else
    memcpy(r->block[0], ev.block[circ.out[i].index], sizeof r->block[0]);
}

/* The C pk encryption of each line under the MPC pk, then the expand and the
 * MPC cast of each used slot: each cast decrypts to its slot. */
static void chain_casts(TfheDrbg *d) {
  static uint64_t mask[TFHE_POLY_N], body[TFHE_PLAIN], ct[TFHE_BIG_N + 1];
  uint8_t m[TFHE_PLAIN];
  unsigned line, j, n = 0;
  for (line = 0; line < CHAIN_LINES; line++) {
    chain_list(m, line);
    tfhe_pke_encrypt(mask, body, &p, m, TFHE_PLAIN, d);
    for (j = 0; j < chain_width(line); j++, n++) {
      tfhe_pke_expand(ct, mask, body[j], j);
      tfhe_pke_cast(&f, chain_cast[n], ct, &p, &clear);
      check(value(chain_cast[n]) == m[j], "chain cast of slot", n);
    }
  }
}

/* Run A, tally T (0 tally4, 1 tally3) on the cast ballot blocks: count j
 * decrypts to the sum of the decrypted bits j and to the plan. */
static void chain_tally(unsigned t) {
  const unsigned options = t == 0 ? 4u : 3u, base = t == 0 ? CHAIN_DEC : CHAIN_BALLOT;
  TfheRadix *out = count + (t == 0 ? 0u : 4u);
  uint64_t sum[4] = {0}, plan[4] = {0}, got;
  unsigned i, j;
  int ok = fhe_build(&circ, t == 0 ? FHE_TALLY4 : FHE_TALLY3, 7) && circ.outs == options;
  check(ok, "chain tally build", t);
  if (!ok) return;
  ev.bin = (const uint64_t(*)[TFHE_BLOCK_WORDS])(chain_cast + base);
  fhe_eval(&ev, &circ);
  ev.bin = (const uint64_t(*)[TFHE_BLOCK_WORDS])bin;
  chain_pbs += ev.pbs;
  for (i = 0; i < 7u; i++) {
    plan[t == 0 ? chain_dec[i] : chain_ballot[i]]++;
    for (j = 0; j < options; j++) sum[j] += value(chain_cast[base + i * options + j]);
  }
  for (j = 0; j < options; j++) {
    chain_get(out + j, j);
    got = tfhe_radix_decrypt(out + j, &clear);
    chain_check(got == sum[j], "count", j, " (1.1)", got, sum[j]);
    chain_check(got == plan[j], "count", j, "", got, plan[j]);
  }
}

/* Stage S on rin and bin: the params from the plan, the decrypted inputs in
 * V (radixes, blocks, params), fhe_eval, the outputs in chain_out[S]. */
static void chain_stage_row(unsigned s) {
  const ChainStage *st = &chain_stage[s];
  uint64_t v[7], f_v;
  unsigned i, n = 0;
  int ok = fhe_build(&circ, st->kind, 7) && circ.radix_ins + circ.block_ins + circ.params == st->ni &&
           circ.radix_ins <= 2u && circ.outs == st->no;
  check(ok, "chain stage build", s);
  if (!ok) return;
  for (i = 0; i < circ.params; i++) param[i] = st->plan[st->ni - circ.params + i];
  for (i = 0; i < circ.radix_ins; i++) v[n++] = tfhe_radix_decrypt(&rin[i], &clear);
  for (i = 0; i < circ.block_ins; i++) v[n++] = value(bin[i]);
  for (i = 0; i < circ.params; i++) v[n++] = param[i];
  for (i = 0; i < st->ni; i++) chain_check(v[i] == st->plan[i], st->name[i], i, "", v[i], st->plan[i]);
  fhe_eval(&ev, &circ);
  chain_pbs += ev.pbs;
  for (i = 0; i < st->no; i++) {
    chain_get(&chain_out[s][i], i);
    v[st->ni + i] = circ.out[i].slot == FHE_RADIX_REG ? tfhe_radix_decrypt(&chain_out[s][i], &clear)
                                                      : value(chain_out[s][i].block[0]);
  }
  for (i = 0; i < st->no; i++) {
    f_v = chain_f(st->kind, v, i);
    chain_check(v[st->ni + i] == f_v, st->name[st->ni + i], i, " (1.1)", v[st->ni + i], f_v);
    chain_check(v[st->ni + i] == st->plan[st->ni + i], st->name[st->ni + i], i, "", v[st->ni + i],
                st->plan[st->ni + i]);
  }
}

/* The casts, run A, then runs B to E in the checktool.c chain_stage_rows
 * order (which output feeds which input). */
static void chain_rows(TfheDrbg *d) {
  unsigned c;
  tfhe_radix_luts(&radix_luts);
  fhe_luts(&luts);
  ev.f = &f;
  ev.k = &clear;
  ev.rl = &radix_luts;
  ev.l = &luts;
  ev.rin = rin;
  ev.bin = (const uint64_t(*)[TFHE_BLOCK_WORDS])bin;
  ev.param = param;
  chain_casts(d);
  chain_tally(0);
  chain_tally(1);
  rin[0] = count[0];
  rin[1] = count[1];
  chain_stage_row(0);
  rin[0] = count[4];
  rin[1] = count[5];
  chain_stage_row(1);
  memcpy(bin[0], chain_out[0][0].block[0], sizeof bin[0]);
  chain_stage_row(2);
  for (c = 0; c < TFHE_RADIX_BLOCKS; c++) {
    memcpy(rin[0].block[c], chain_cast[CHAIN_Q + c], sizeof rin[0].block[c]);
    memcpy(rin[1].block[c], chain_cast[CHAIN_P + c], sizeof rin[1].block[c]);
  }
  memcpy(bin[0], chain_out[2][0].block[0], sizeof bin[0]);
  memcpy(bin[1], chain_out[2][1].block[0], sizeof bin[1]);
  chain_stage_row(3);
  rin[0] = chain_out[3][0];
  chain_stage_row(4);
}

/* The masked re-encryption at enact (S6b U5, Q-S6-6 (c)): blocks 0 to 3 are
 * Enc_{pk_e}(m) for m = 0 to 3 (cast), blocks 4 to 35 are the credit output
 * q2 of the chain (Q-S6-20 (a); stage 3, plan entry 5). Member j (party j + 1
 * of epoch e) draws a mask r_j in 0 to 3 and a 32-byte salt for each block
 * from its DRBG and commits sha512 (j + 1, block, r_j, salt) before the e+1
 * keygen. */
enum { REENC_M = 4, REENC_BLOCKS = REENC_M + TFHE_RADIX_BLOCKS, REENC_SALT = 32, REENC_CREDIT = 3, REENC_Q2 = 5 };
static TkeygenShares s_next;
static TkeygenToss toss_next;
static TfheKeys k_next;
static TfhePke p_next;
static uint8_t reenc_r[TSHARE_PARTIES][REENC_BLOCKS], reenc_salt[TSHARE_PARTIES][REENC_BLOCKS][REENC_SALT];
static uint8_t reenc_commit[TSHARE_PARTIES][REENC_BLOCKS][SHA512_BYTES];
static uint8_t reenc_clear[REENC_BLOCKS], reenc_open[REENC_BLOCKS];
static uint64_t reenc_acc[REENC_BLOCKS][TFHE_BLOCK_WORDS], reenc_lut[TFHE_POLY_N];
static uint64_t reenc_mask[TFHE_POLY_N], reenc_body[REENC_BLOCKS];

/* sha512 (j + 1, B, R, the salt of member J and block B). */
static void reenc_digest(uint8_t digest[SHA512_BYTES], unsigned j, unsigned b, uint8_t r) {
  uint8_t in[3 + REENC_SALT];
  in[0] = (uint8_t)(j + 1u);
  in[1] = (uint8_t)b;
  in[2] = r;
  memcpy(in + 3, reenc_salt[j][b], REENC_SALT);
  sha512(in, sizeof in, digest);
}

/* The masks, the salts and the commitments of the 5 members. */
static void reenc_masks(TfheDrbg party[TSHARE_PARTIES]) {
  unsigned j, b, i;
  for (j = 0; j < TSHARE_PARTIES; j++)
    for (b = 0; b < REENC_BLOCKS; b++) {
      reenc_r[j][b] = (uint8_t)(tfhe_drbg_bytes(&party[j], 1) % TFHE_MSG_MOD);
      for (i = 0; i < REENC_SALT; i++) reenc_salt[j][b][i] = (uint8_t)tfhe_drbg_bytes(&party[j], 1);
      reenc_digest(reenc_commit[j][b], j, b, reenc_r[j][b]);
    }
}

/* OUT = the cast of entry B of the pk chunk (reenc_mask, reenc_body) under PK
 * to the big key of K. */
static void reenc_cast(uint64_t out[TFHE_BLOCK_WORDS], const TfhePke *pk, const TfheKeys *k, unsigned b) {
  static uint64_t ct[TFHE_BLOCK_WORDS];
  tfhe_pke_expand(ct, reenc_mask, reenc_body[b], b);
  tfhe_pke_cast(&f, out, ct, pk, k);
}

/* Member J adds its masks to the blocks (SUB 0, epoch e) or takes them away
 * (SUB 1, epoch e+1, with a trivial 4): its pk chunk under PK (DRBG D), the
 * cast to the big key of K, the add, then a PBS mod 4 under K (Q-S6-19 (b)).
 * Each PBS input is 3 + 3 = 6 (e) or 3 + 4 = 7 (e+1) or less, level 2. */
static void reenc_member(const TfhePke *pk, const TfheKeys *k, unsigned j, int sub, TfheDrbg *d) {
  static uint64_t out[TFHE_BLOCK_WORDS], pbs[TFHE_BLOCK_WORDS];
  unsigned b;
  tfhe_pke_encrypt(reenc_mask, reenc_body, pk, reenc_r[j], REENC_BLOCKS, d);
  for (b = 0; b < REENC_BLOCKS; b++) {
    reenc_cast(out, pk, k, b);
    if (sub) {
      tfhe_block_scale(out, UINT64_MAX);
      out[TFHE_BIG_N] += tfhe_encode(TFHE_MSG_MOD);
    }
    tfhe_block_add(reenc_acc[b], out);
    tfhe_pbs(&f, pbs, reenc_acc[b], k, reenc_lut);
    memcpy(reenc_acc[b], pbs, sizeof pbs);
  }
}

/* Epoch e: the blocks (each must decrypt to its clear value), the masks of
 * the 5 members, the squash (the e KSK and BSK), then the tdec by {1, 3, 5}
 * or {2, 4, 5} with the e squash shares: the value is (m + r) mod 4, r = sum
 * r_j. The values go to reenc_open. */
static void reenc_rows_e(SquashPbsWork *pw, const SquashBsk *bsk, const unsigned (*subset)[3],
                         TfheDrbg party[TSHARE_PARTIES], TfheDrbg *d) {
  static const uint8_t m[REENC_M] = {0, 1, 2, 3};
  static Squash128 sq[SQUASH_BIG_N + 1];
  const uint64_t q2 = chain_stage[REENC_CREDIT].plan[REENC_Q2];
  TshareFe partial[TSHARE_PARTIES];
  Squash128 tph;
  unsigned b, j, r;
  int ok;
  tfhe_pke_encrypt(reenc_mask, reenc_body, &p, m, REENC_M, d);
  for (b = 0; b < REENC_BLOCKS; b++) {
    if (b < REENC_M) {
      reenc_cast(reenc_acc[b], &p, &clear, b);
      reenc_clear[b] = m[b];
    } else {
      memcpy(reenc_acc[b], chain_out[REENC_CREDIT][0].block[b - REENC_M], sizeof reenc_acc[b]);
      reenc_clear[b] = (uint8_t)((q2 >> (2u * (b - REENC_M))) & 3u);
    }
    check(value(reenc_acc[b]) == reenc_clear[b], "reenc e block", b);
  }
  for (j = 0; j < TSHARE_PARTIES; j++) reenc_member(&p, &clear, j, 0, &party[j]);
  for (b = 0; b < REENC_BLOCKS; b++) {
    for (r = reenc_clear[b], j = 0; j < TSHARE_PARTIES; j++) r += reenc_r[j][b];
    squash_pbs(&f, pw, sq, reenc_acc[b], k.ksk, bsk);
    ok = tdec_run(&tph, partial, &s.squash[0][0], sq, sq[SQUASH_BIG_N], subset[b % 2u], 3, d);
    reenc_open[b] = (uint8_t)tdec_decode(tph);
    check(ok && reenc_open[b] == r % TFHE_MSG_MOD, "reenc e tdec of block", b);
  }
}

/* Epoch e+1: the r_j of each member opens its commitment (r_j + 1 mod 4 does
 * not); Enc_{pk'}(reenc_open) under PK (DRBG D), the cast to the big key of
 * KN, the 5 members take their masks away, the squash (KN and BSK), then the
 * tdec by {1, 3, 5} and {2, 4, 5} with SHARES (the e+1 squash shares): each
 * value is the clear value, and the values of blocks 4 to 35 give q2. */
static void reenc_rows_next(SquashPbsWork *pw, const TfhePke *pk, const TfheKeys *kn, const SquashBsk *bsk,
                            const TshareFe *shares, const unsigned (*subset)[3], TfheDrbg party[TSHARE_PARTIES],
                            TfheDrbg *d) {
  static Squash128 sq[SQUASH_BIG_N + 1];
  uint8_t digest[SHA512_BYTES], wrong[SHA512_BYTES];
  TshareFe partial[TSHARE_PARTIES];
  Squash128 tph;
  uint64_t q2 = 0;
  unsigned b, j, i, v = 0;
  int ok;
  for (j = 0; j < TSHARE_PARTIES; j++)
    for (b = 0; b < REENC_BLOCKS; b++) {
      reenc_digest(digest, j, b, reenc_r[j][b]);
      reenc_digest(wrong, j, b, (uint8_t)((reenc_r[j][b] + 1u) % TFHE_MSG_MOD));
      ok = memcmp(digest, reenc_commit[j][b], SHA512_BYTES) == 0;
      check(ok && memcmp(wrong, reenc_commit[j][b], SHA512_BYTES) != 0, "reenc reveal of block", b);
    }
  tfhe_pke_encrypt(reenc_mask, reenc_body, pk, reenc_open, REENC_BLOCKS, d);
  for (b = 0; b < REENC_BLOCKS; b++) reenc_cast(reenc_acc[b], pk, kn, b);
  for (j = 0; j < TSHARE_PARTIES; j++) reenc_member(pk, kn, j, 1, &party[j]);
  for (b = 0; b < REENC_BLOCKS; b++) {
    squash_pbs(&f, pw, sq, reenc_acc[b], kn->ksk, bsk);
    for (i = 0; i < 2u; i++) {
      ok = tdec_run(&tph, partial, shares, sq, sq[SQUASH_BIG_N], subset[i], 3, d);
      v = tdec_decode(tph);
      check(ok && v == reenc_clear[b], "reenc e+1 tdec of block", b);
    }
    if (b >= REENC_M) q2 |= (uint64_t)(v % TFHE_MSG_MOD) << (2u * (b - REENC_M));
  }
  check(q2 == chain_stage[REENC_CREDIT].plan[REENC_Q2], "reenc e+1 credit q2", 0);
}

int main(void) {
  static uint64_t lut[TFHE_POLY_N], ct[TFHE_BIG_N + 1], out[TFHE_BIG_N + 1], small[TFHE_LWE_N + 1];
  static uint64_t pbs[TFHE_BIG_N + 1], bits[SQUASH_BIG_N], mask[TFHE_POLY_N], body[TFHE_PLAIN];
  static Squash128 sq[SQUASH_BIG_N + 1], ph[SQUASH_POLY_N], sqm[4][SQUASH_BIG_N + 1];
  static const unsigned all[TSHARE_PARTIES] = {1, 2, 3, 4, 5}, subset[2][3] = {{1, 3, 5}, {2, 4, 5}};
  TshareFe partial[TSHARE_PARTIES];
  Squash128 tph;
  static uint8_t table[TFHE_PLAIN], msg[TFHE_PLAIN], seed[TFHE_SEED_BYTES], joint[SHA512_BYTES];
  SquashPbsWork *pw = malloc(sizeof *pw);
  SquashFftWork *sw = malloc(sizeof *sw);
  TfheDrbg party[TSHARE_PARTIES], masks, d, party_next[TSHARE_PARTIES], masks_next;
  TshareFe lambda[TSHARE_PARTIES];
  SquashBsk bsk, bsk_next;
  uint64_t zero = 0;
  clock_t c0;
  double reenc_time;
  unsigned i, m, bad;
  size_t j, i0 = TFHE_LWE_N;
  int ok = 1;
  if (pw == NULL || sw == NULL) {
    free(pw);
    free(sw);
    puts("FAIL mpc work allocation");
    return 1;
  }
  tfhe_fft_init(&f);
  memcpy(seed, "charter-lang S6b U4b mpc party 1", 32);
  for (i = 0; i < TSHARE_PARTIES; i++) {
    seed[31] = (uint8_t)('1' + i);
    tfhe_drbg_init(&party[i], seed);
  }
  for (i = 1; i <= TSHARE_PARTIES; i++) ok &= tkeygen_toss_draw(&toss, i, &party[i - 1]);
  ok &= tkeygen_toss_check(&toss) && tkeygen_toss_joint(joint, &masks, &toss);
  tkeygen_shares(&s, party);
  c0 = clock();
  if (!ok || !tkeygen_keys(&k, &p, &bsk, &s, &f, &masks, party)) {
    puts("FAIL mpc coin toss or keys");
    return 1;
  }
  printf("mpc keys: tkeygen_keys %.1f s\n", since(c0));

  /* The secret key fields stay 0; the clear keys come from all 5 parties. */
  for (j = 0; j < TFHE_LWE_N; j++) zero |= k.lwe_key[j];
  for (j = 0; j < TFHE_POLY_N; j++) zero |= k.glwe_key[j];
  for (j = 0; j < TFHE_BIG_N; j++) zero |= p.key[j];
  check(zero == 0, "secret key fields are 0", 0);
  check(tshare_lagrange(lambda, all, TSHARE_PARTIES), "lagrange", 0);
  clear = k;
  pc = p;
  bad = open_key(clear.lwe_key, &s.lwe[0][0], TFHE_LWE_N, lambda);
  bad += open_key(clear.glwe_key, &s.glwe[0][0], TFHE_POLY_N, lambda);
  bad += open_key(pc.key, &s.pke[0][0], TFHE_BIG_N, lambda);
  bad += open_key(bits, &s.squash[0][0], SQUASH_BIG_N, lambda);
  for (j = 0; j < SQUASH_BIG_N; j++) sk.s[j / SQUASH_POLY_N][j % SQUASH_POLY_N] = (int64_t)bits[j];
  tfhe_fft_forward(&f, &clear.glwe_key_fourier, clear.glwe_key);
  check(bad == 0, "clear keys, bad bits", bad);
  for (i = 0; i < TFHE_PLAIN; i++) table[i] = (uint8_t)i;
  tfhe_lut(lut, table);
  tfhe_drbg_init(&d, (const uint8_t *)"charter-lang S6b U4b mpc tests!!");

  /* The MPC KSK: m under the big key, then the key switch to the small key. */
  c0 = clock();
  for (m = 0; m < TFHE_PLAIN; m++) {
    tfhe_lwe_encrypt(ct, clear.glwe_key, TFHE_BIG_N, tfhe_encode(m), TFHE_GLWE_NOISE, &d);
    tfhe_keyswitch(small, ct, k.ksk);
    check(tfhe_decode(tfhe_lwe_phase(small, clear.lwe_key, TFHE_LWE_N)) == m, "key switch of m", m);
  }
  printf("mpc ksk rows: %.2f s\n", since(c0));

  /* The MPC KSK and BSK: one PBS of the identity LUT per m. */
  c0 = clock();
  for (m = 0; m < TFHE_PLAIN; m++) {
    tfhe_lwe_encrypt(ct, clear.glwe_key, TFHE_BIG_N, tfhe_encode(m), TFHE_GLWE_NOISE, &d);
    tfhe_pbs(&f, pbs, ct, &clear, lut);
    check(tfhe_decode(tfhe_lwe_phase(pbs, clear.glwe_key, TFHE_BIG_N)) == m, "pbs of m", m);
  }
  printf("mpc pbs rows: %.2f s\n", since(c0));

  /* The MPC pk: one chunk of the 16 messages 15 to 0, then the MPC cast KSK. */
  c0 = clock();
  for (m = 0; m < TFHE_PLAIN; m++) msg[m] = (uint8_t)(TFHE_PLAIN - 1u - m);
  tfhe_pke_encrypt(mask, body, &p, msg, TFHE_PLAIN, &d);
  for (m = 0; m < TFHE_PLAIN; m++) {
    tfhe_pke_expand(ct, mask, body[m], m);
    check(tfhe_decode(tfhe_lwe_phase(ct, pc.key, TFHE_BIG_N)) == msg[m], "pk encryption of entry", m);
    tfhe_pke_cast(&f, out, ct, &p, &clear);
    check(tfhe_decode(tfhe_lwe_phase(out, clear.glwe_key, TFHE_BIG_N)) == msg[m], "cast of entry", m);
  }
  printf("mpc pk and cast rows: %.2f s\n", since(c0));

  /* The S5 chain under the MPC keys (Q-S6-18 (a)). */
  c0 = clock();
  chain_rows(&d);
  printf("mpc chain rows: %.2f s, %u PBS\n", since(c0), chain_pbs);

  /* The MPC squash BSK: the squash PBS of an S5 PBS output of m. */
  c0 = clock();
  for (m = 0; m < TFHE_PLAIN; m += 5) {
    tfhe_lwe_encrypt(ct, clear.glwe_key, TFHE_BIG_N, tfhe_encode(m), TFHE_GLWE_NOISE, &d);
    tfhe_pbs(&f, pbs, ct, &clear, lut);
    squash_pbs(&f, pw, sq, pbs, k.ksk, &bsk);
    check(tdec_decode(phase(sq, &sk)) == m, "squash pbs of m", m);
    memcpy(sqm[m / 5u], sq, sizeof sq);
  }
  printf("mpc squash pbs rows: %.2f s\n", since(c0));

  /* Threshold decryption (Q-C7) of the squash PBS outputs of m = 0, 5, 10, 15
   * with the MPC squash key shares, by the subsets {1, 3, 5} and {2, 4, 5}. */
  c0 = clock();
  for (m = 0; m < 4u; m++)
    for (i = 0; i < 2u; i++)
      check(tdec_run(&tph, partial, &s.squash[0][0], sqm[m], sqm[m][SQUASH_BIG_N], subset[i], 3, &d) &&
                tdec_decode(tph) == 5u * m,
            "tdec of m", 5u * m);
  printf("mpc tdec rows: %.2f s\n", since(c0));

  /* The MPC squash BSK, the GGSW of the first LWE key bit 1 (I0): level 2,
   * row 0 (level 2 starts at row K + 1) has the phase e - g_2 S_0 under the
   * squash key (g_2 = 2^80), with |e| <= 5 2^29 (the sum of 5 party noises). */
  c0 = clock();
  for (j = TFHE_LWE_N; j > 0; j--)
    if (clear.lwe_key[j - 1] == 1) i0 = j - 1;
  check(i0 < TFHE_LWE_N, "squash ggsw, no lwe key bit 1", 0);
  if (i0 < TFHE_LWE_N) {
    const Squash128 g2 = squash_shl(squash_from_u64(1), 80), b = squash_from_u64((uint64_t)5 << 29);
    squash_glwe_phase(&f, sw, ph, bsk.ggsw + i0 * SQUASH_GGSW_WORDS + (size_t)(SQUASH_GLWE_K + 1) * SQUASH_GLWE_WORDS, &sk);
    for (j = 0; j < SQUASH_POLY_N; j++) {
      /* v + b in [0, 2 b] is v in [-b, b]. */
      Squash128 v = squash_add(ph[j], b);
      if (sk.s[0][j] != 0) v = squash_add(v, g2);
      check(v.hi == 0 && v.lo <= 2u * b.lo, "squash ggsw level 2 row 0 coefficient", (unsigned)j);
    }
  }
  printf("mpc squash ggsw row: %.2f s\n", since(c0));

  /* S6b U5: the masked re-encryption from epoch e to epoch e+1. The masks and
   * the commitments come before the e+1 keygen, and the e squash BSK goes
   * before it (peak about 1.2 GB). The e+1 key set: new party seeds, a new
   * coin toss, tkeygen_shares and tkeygen_keys. */
  c0 = clock();
  for (i = 0; i < TFHE_PLAIN; i++) table[i] = (uint8_t)(i % TFHE_MSG_MOD);
  tfhe_lut(reenc_lut, table);
  reenc_masks(party);
  reenc_rows_e(pw, &bsk, subset, party, &d);
  reenc_time = since(c0);
  squash_bsk_release(&bsk);
  memcpy(seed, "charter-lang S6b U5 epoch2 pty 1", 32);
  for (i = 0; i < TSHARE_PARTIES; i++) {
    seed[31] = (uint8_t)('1' + i);
    tfhe_drbg_init(&party_next[i], seed);
  }
  for (i = 1; i <= TSHARE_PARTIES; i++) ok &= tkeygen_toss_draw(&toss_next, i, &party_next[i - 1]);
  ok &= tkeygen_toss_check(&toss_next) && tkeygen_toss_joint(joint, &masks_next, &toss_next);
  tkeygen_shares(&s_next, party_next);
  c0 = clock();
  if (!ok || !tkeygen_keys(&k_next, &p_next, &bsk_next, &s_next, &f, &masks_next, party_next)) {
    puts("FAIL mpc e+1 coin toss or keys");
    return 1;
  }
  printf("mpc keys e+1: tkeygen_keys %.1f s\n", since(c0));
  c0 = clock();
  reenc_rows_next(pw, &p_next, &k_next, &bsk_next, &s_next.squash[0][0], subset, party, &d);
  printf("mpc reenc rows: %.2f s\n", reenc_time + since(c0));
  if (fails == 0) puts("mpc key set rows: passed");
  squash_bsk_release(&bsk_next);
  tfhe_pke_release(&p_next);
  tfhe_keys_release(&k_next);
  tfhe_pke_release(&p);
  tfhe_keys_release(&k);
  free(pw);
  free(sw);
  return fails != 0;
}
