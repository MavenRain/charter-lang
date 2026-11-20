/* S7 U7 D142, D145, D146: the native reader of the client witness words
 * (front/zkread.h). The word tables are D139 (vote) and D140 (motion). */
#include "front/zkread.h"
#include "front/poseidon2.h"

#include <string.h>

/* D139 vote block, without the count word. */
enum {
  ZR_V_ROOT = 0,
  ZR_V_NF = 4,
  ZR_V_E = 8,
  ZR_V_U = 9,
  ZR_V_W = 10,
  ZR_V_MASK = 11,
  ZR_V_BODY = ZR_V_MASK + ZK_PKE_N,
  ZR_V_KEY = ZR_V_BODY + ZK_PKE_SLOTS,
  ZR_V_IDX = ZR_V_KEY + 4,
  ZR_V_PATH = ZR_V_IDX + 1,
  ZR_V_M = ZR_V_PATH + ZR_PATH_WORDS,
  ZR_V_R = ZR_V_M + ZK_PKE_SLOTS,
  ZR_V_E1 = ZR_V_R + ZK_PKE_N / 64,
  ZR_V_E2 = ZR_V_E1 + ZK_PKE_N,
  ZR_V_END = ZR_V_E2 + ZK_PKE_SLOTS
};

/* D140 motion block, without the count word. */
enum {
  ZR_M_ROOT = 0,
  ZR_M_MT = 4,
  ZR_M_E = 8,
  ZR_M_CTX = 9,
  ZR_M_KEY = 13,
  ZR_M_IDX = 17,
  ZR_M_PATH = 18,
  ZR_M_END = ZR_M_PATH + ZR_PATH_WORDS
};

/* The build fails when a table end is not the block size of zkread.h. */
typedef char zr_vote_layout[ZR_V_END == ZR_VOTE_WORDS ? 1 : -1];
typedef char zr_motion_layout[ZR_M_END == ZR_MOTION_WORDS ? 1 : -1];

/* The R3 recompute area: one gballot, one gmask slice and one gmotion fill. */
static ZkFr zr_gb[ZK_GB_WEIGHTS];
static ZkFr zr_gm[ZK_GMASK_WEIGHTS];
static ZkFr zr_mo[ZK_GMOTION_WEIGHTS];

const char *zr_err_text(ZrErr e) {
  switch (e) {
  case ZR_OK:
    return "ok";
  case ZR_ERR_COUNT:
    return "R1 count: the word count is not exact";
  case ZR_ERR_LIMB:
    return "R2 limb: a word is outside its range";
  case ZR_ERR_REF:
    return "R3 reference: a recomputed value differs from the words";
  case ZR_ERR_CONTEXT:
    return "R4 context: a public value differs from the verifier context";
  }
  return "unknown code";
}

/* 1 when the N Digests at W (4 words each, low word first) are canonical. */
static int zr_digests_ok(const uint64_t *w, size_t n) {
  Fr f;
  size_t i;
  int ok = 1;
  for (i = 0; i < n; i++) ok = ok && fr_from_words(&f, w + 4 * i);
  return ok;
}

/* 1 when the two's complement word X is in -2^17 .. 2^17 (TUniform(17));
 * writes the value to OUT. */
static int zr_noise(int64_t *out, uint64_t x) {
  uint64_t s = x + ((uint64_t)1 << ZK_PKE_NOISE);
  int ok = s <= ((uint64_t)1 << (ZK_PKE_NOISE + 1));
  *out = ok ? (int64_t)s - ((int64_t)1 << ZK_PKE_NOISE) : 0;
  return ok;
}

static int zr_same(const uint64_t *a, const uint64_t *b, size_t n) {
  return memcmp(a, b, n * sizeof *a) == 0;
}

/* A' = X^-o pk_a mod (X^N + 1, 2^64), as pke_shift of test/zktool.c. */
static void zr_shift(const uint64_t *pk_a, uint32_t o, uint64_t *ap) {
  uint32_t t;
  for (t = 0; t < ZK_PKE_N; t++) ap[t] = t + o < ZK_PKE_N ? pk_a[t + o] : 0u - pk_a[t + o - ZK_PKE_N];
}

ZrErr zr_read_vote(ZrVote *out, const uint64_t *words, size_t n, const ZrContext *ctx) {
  uint64_t root[4], nf[4], cr[4], body[ZK_PKE_SLOTS], ap[ZK_PKE_N], slice[ZK_GMASK_SPAN];
  uint32_t j, o, ones = 0, at = ZK_PKE_SLOTS;
  int ok;
  if (n != ZR_VOTE_WORDS) return ZR_ERR_COUNT;
  /* R2 limb. */
  ok = zr_digests_ok(words + ZR_V_ROOT, 2) && zr_digests_ok(words + ZR_V_KEY, 1) &&
       zr_digests_ok(words + ZR_V_PATH, ZK_MERKLE_LEVELS);
  ok = ok && (words[ZR_V_W] == 3 || words[ZR_V_W] == 4) && words[ZR_V_IDX] < ZR_IDX_LIMIT;
  for (j = 0; j < ZK_PKE_SLOTS; j++) {
    ok = ok && words[ZR_V_M + j] <= 1;
    out->m[j] = (uint8_t)(words[ZR_V_M + j] & 1u);
    ones += out->m[j];
    at = out->m[j] ? j : at;
  }
  ok = ok && ones == 1 && at < words[ZR_V_W];
  for (j = 0; j < ZK_PKE_N; j++) ok = ok && zr_noise(&out->e1[j], words[ZR_V_E1 + j]);
  for (j = 0; j < ZK_PKE_SLOTS; j++) ok = ok && zr_noise(&out->e2[j], words[ZR_V_E2 + j]);
  if (!ok) return ZR_ERR_LIMB;
  memcpy(out->root, words + ZR_V_ROOT, sizeof out->root);
  memcpy(out->nf, words + ZR_V_NF, sizeof out->nf);
  out->e = words[ZR_V_E];
  out->u = words[ZR_V_U];
  out->w = (uint32_t)words[ZR_V_W];
  memcpy(out->mask, words + ZR_V_MASK, sizeof out->mask);
  memcpy(out->body, words + ZR_V_BODY, sizeof out->body);
  memcpy(out->key, words + ZR_V_KEY, sizeof out->key);
  out->idx = (uint32_t)words[ZR_V_IDX];
  memcpy(out->sib, words + ZR_V_PATH, sizeof out->sib);
  for (j = 0; j < ZK_PKE_N; j++) out->r[j] = (uint8_t)((words[ZR_V_R + j / 64] >> (j % 64)) & 1u);
  /* R3 reference: root, nf and the bodies, then the mask one slice at a time. */
  zk_gballot_fill(zr_gb, out->key, out->e, out->u, out->sib, out->idx, ctx->pk_b, out->r, out->m, out->e2, root, nf,
                  cr, body);
  ok = zr_same(root, out->root, 4) && zr_same(nf, out->nf, 4) && zr_same(body, out->body, ZK_PKE_SLOTS);
  for (o = 0; ok && o < ZK_PKE_N; o += ZK_GMASK_SPAN) {
    zr_shift(ctx->pk_a, o, ap);
    zk_gmask_fill(zr_gm, ap, out->r, out->e1 + o, slice, cr);
    ok = zr_same(slice, out->mask + o, ZK_GMASK_SPAN);
  }
  if (!ok) return ZR_ERR_REF;
  /* R4 context. */
  if (!zr_same(out->root, ctx->root, 4) || out->e != ctx->e) return ZR_ERR_CONTEXT;
  return ZR_OK;
}

ZrErr zr_read_motion(ZrMotion *out, const uint64_t *words, size_t n, const ZrContext *ctx) {
  uint64_t root[4], mt[4];
  int ok;
  if (n != ZR_MOTION_WORDS) return ZR_ERR_COUNT;
  /* R2 limb: root, mt, ctx and K are 4 Digests in a row. */
  ok = zr_digests_ok(words + ZR_M_ROOT, 2) && zr_digests_ok(words + ZR_M_CTX, 2) &&
       zr_digests_ok(words + ZR_M_PATH, ZK_MERKLE_LEVELS) && words[ZR_M_IDX] < ZR_IDX_LIMIT;
  if (!ok) return ZR_ERR_LIMB;
  memcpy(out->root, words + ZR_M_ROOT, sizeof out->root);
  memcpy(out->mt, words + ZR_M_MT, sizeof out->mt);
  out->e = words[ZR_M_E];
  memcpy(out->ctx, words + ZR_M_CTX, sizeof out->ctx);
  memcpy(out->key, words + ZR_M_KEY, sizeof out->key);
  out->idx = (uint32_t)words[ZR_M_IDX];
  memcpy(out->sib, words + ZR_M_PATH, sizeof out->sib);
  /* R3 reference. */
  zk_gmotion_fill(zr_mo, out->key, out->e, out->ctx, out->sib, out->idx, root, mt);
  if (!zr_same(root, out->root, 4) || !zr_same(mt, out->mt, 4)) return ZR_ERR_REF;
  /* R4 context. */
  if (!zr_same(out->root, ctx->root, 4) || out->e != ctx->e || !zr_same(out->ctx, ctx->ctx, 4)) return ZR_ERR_CONTEXT;
  return ZR_OK;
}
