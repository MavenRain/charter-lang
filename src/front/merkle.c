/* S7 L1 (the Ligero back end): the Merkle tree of the column commitment. See
 * merkle.h. */
#include "front/merkle.h"

#include <stdlib.h>
#include <string.h>

#include "front/sha512.h"

enum { HB = ZK_MERKLE_BYTES };

void zk_merkle_leaf(const ZkFr *col, size_t count, uint8_t out[ZK_MERKLE_BYTES]) {
  const uint8_t tag = ZK_MERKLE_LEAF_TAG;
  uint8_t d[SHA512_BYTES], e[ZK_LIMBS * 4];
  Sha512 s;
  size_t i;
  unsigned k;
  sha512_init(&s);
  sha512_update(&s, &tag, 1);
  for (i = 0; i < count; i++) {
    for (k = 0; k < ZK_LIMBS * 4; k++) e[k] = (uint8_t)(col[i].limb[k / 4] >> (8 * (k % 4)));
    sha512_update(&s, e, sizeof e);
  }
  sha512_final(&s, d);
  memcpy(out, d, HB);
}

void zk_merkle_node(const uint8_t left[ZK_MERKLE_BYTES], const uint8_t right[ZK_MERKLE_BYTES],
                    uint8_t out[ZK_MERKLE_BYTES]) {
  const uint8_t tag = ZK_MERKLE_NODE_TAG;
  uint8_t d[SHA512_BYTES];
  Sha512 s;
  sha512_init(&s);
  sha512_update(&s, &tag, 1);
  sha512_update(&s, left, HB);
  sha512_update(&s, right, HB);
  sha512_final(&s, d); /* LEFT and RIGHT are read before OUT is written */
  memcpy(out, d, HB);
}

ZkErr zk_merkle_build(ZkMerkle *t, unsigned log, const uint8_t *leaf) {
  size_t n, i;
  t->node = NULL;
  t->log = log;
  if (log > ZK_MERKLE_LOG_MAX) return ZK_ERR_COUNT;
  n = (size_t)1 << log;
  t->node = malloc(2 * n * HB);
  if (!t->node) return ZK_ERR_MEMORY;
  memcpy(t->node + n * HB, leaf, n * HB);
  for (i = n - 1; i > 0; i--) zk_merkle_node(t->node + 2 * i * HB, t->node + (2 * i + 1) * HB, t->node + i * HB);
  /* one leaf (LOG 0): the root is node 1, the leaf itself */
  return ZK_OK;
}

void zk_merkle_free(ZkMerkle *t) {
  free(t->node);
  t->node = NULL;
}

const uint8_t *zk_merkle_root(const ZkMerkle *t) { return t->node + HB; }

int zk_merkle_path(const ZkMerkle *t, uint32_t j, uint8_t *path) {
  size_t v;
  unsigned b;
  if (j >= (uint32_t)1 << t->log) return 0;
  for (v = ((size_t)1 << t->log) + j, b = 0; b < t->log; b++, v >>= 1) memcpy(path + b * HB, t->node + (v ^ 1) * HB, HB);
  return 1;
}

int zk_merkle_path_check(const uint8_t root[ZK_MERKLE_BYTES], unsigned log, uint32_t j,
                         const uint8_t leaf[ZK_MERKLE_BYTES], const uint8_t *path) {
  uint8_t h[HB];
  unsigned b;
  if (log > ZK_MERKLE_LOG_MAX || j >= (uint32_t)1 << log) return 0;
  memcpy(h, leaf, HB);
  for (b = 0; b < log; b++) {
    const uint8_t *sib = path + b * HB;
    if ((j >> b) & 1u)
      zk_merkle_node(sib, h, h);
    else
      zk_merkle_node(h, sib, h);
  }
  return memcmp(h, root, HB) == 0;
}

/* 1 when IDX has COUNT entries (at least 1), strictly increasing, below 2^LOG. */
static int good_idx(unsigned log, const uint32_t *idx, size_t count) {
  size_t i;
  if (log > ZK_MERKLE_LOG_MAX || count == 0 || idx[count - 1] >= (uint32_t)1 << log) return 0;
  for (i = 1; i < count; i++)
    if (idx[i - 1] >= idx[i]) return 0;
  return 1;
}

/* The two walks share one level step. CUR holds *LEN node numbers, strictly
 * increasing, all on one level. A node whose sibling is the next entry pairs
 * with it; any other node takes its sibling from the outside (OPEN writes it
 * from the tree, CHECK reads it from SIB). The parents replace CUR in place
 * (entry k <= i is written after entry i is read). */

ZkErr zk_merkle_open(const ZkMerkle *t, const uint32_t *idx, size_t count, uint8_t *out, size_t *hashes) {
  uint32_t *cur;
  size_t len, i, k, w = 0;
  unsigned b;
  if (!good_idx(t->log, idx, count)) return ZK_ERR_MAP;
  cur = malloc(count * sizeof *cur);
  if (!cur) return ZK_ERR_MEMORY;
  for (i = 0; i < count; i++) cur[i] = ((uint32_t)1 << t->log) + idx[i];
  for (b = 0, len = count; b < t->log; b++, len = k) {
    for (i = 0, k = 0; i < len; k++) {
      const uint32_t v = cur[i];
      const int paired = (v & 1u) == 0 && i + 1 < len && cur[i + 1] == v + 1;
      if (!paired) memcpy(out + w++ * HB, t->node + (size_t)(v ^ 1u) * HB, HB);
      i += paired ? 2 : 1;
      cur[k] = v >> 1;
    }
  }
  free(cur);
  *hashes = w;
  return ZK_OK;
}

int zk_merkle_check(const uint8_t root[ZK_MERKLE_BYTES], unsigned log, const uint32_t *idx, size_t count,
                    const uint8_t *leaf, const uint8_t *sib, size_t hashes) {
  uint32_t *cur;
  uint8_t *h;
  size_t len, i, k, r = 0;
  unsigned b;
  int ok = 1;
  if (!good_idx(log, idx, count)) return 0;
  cur = malloc(count * sizeof *cur);
  h = malloc(count * HB);
  if (!cur || !h) {
    free(cur);
    free(h);
    return 0;
  }
  memcpy(h, leaf, count * HB);
  for (i = 0; i < count; i++) cur[i] = ((uint32_t)1 << log) + idx[i];
  for (b = 0, len = count; ok && b < log; b++, len = k) {
    for (i = 0, k = 0; ok && i < len; k++) {
      const uint32_t v = cur[i];
      const int paired = (v & 1u) == 0 && i + 1 < len && cur[i + 1] == v + 1;
      const uint8_t *other = NULL; /* SIB + R is made only when R < HASHES */
      ok = paired || r < hashes;
      if (paired) other = h + (i + 1) * HB;
      if (!paired && ok) other = sib + r * HB;
      if (ok && (v & 1u))
        zk_merkle_node(other, h + i * HB, h + k * HB);
      if (ok && !(v & 1u))
        zk_merkle_node(h + i * HB, other, h + k * HB);
      r += !paired;
      i += paired ? 2 : 1;
      cur[k] = v >> 1;
    }
  }
  ok = ok && r == hashes && memcmp(h, root, HB) == 0;
  free(cur);
  free(h);
  return ok;
}
