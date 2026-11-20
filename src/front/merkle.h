/* S7 L1 (the Ligero back end): a binary Merkle tree over 2^LOG leaves for the
 * column commitment. H is SHA-512 cut to its first 32 bytes. A leaf hash is
 * H(0 || bytes) and a node hash is H(1 || left || right): the tag byte keeps a
 * leaf hash apart from a node hash of the same bytes. */
#ifndef CHARTER_MERKLE_H
#define CHARTER_MERKLE_H

#include <stddef.h>
#include <stdint.h>

#include "front/zk.h"

enum {
  ZK_MERKLE_BYTES = 32,   /* one hash: the first 32 bytes of SHA-512 */
  ZK_MERKLE_LEAF_TAG = 0, /* the first byte of a leaf hash input */
  ZK_MERKLE_NODE_TAG = 1, /* the first byte of a node hash input */
  ZK_MERKLE_LOG_MAX = 28  /* the most levels (the NTT domain has 2^28 points at most) */
};

/* The tree over 2^log leaves. node holds 2^(log + 1) hashes: node 1 is the
 * root, the nodes 2^log .. 2^(log + 1) - 1 are the leaves 0 .. 2^log - 1, and
 * node i has the children 2i and 2i + 1. Node 0 is not used. */
typedef struct ZkMerkle {
  uint8_t *node;
  unsigned log;
} ZkMerkle;

/* OUT = H(0 || the COUNT elements of COL), each element as 32 bytes, low byte
 * first (the limbs low limb first, each limb low byte first). */
void zk_merkle_leaf(const ZkFr *col, size_t count, uint8_t out[ZK_MERKLE_BYTES]);

/* OUT = H(1 || LEFT || RIGHT). OUT can be LEFT or RIGHT. */
void zk_merkle_node(const uint8_t left[ZK_MERKLE_BYTES], const uint8_t right[ZK_MERKLE_BYTES],
                    uint8_t out[ZK_MERKLE_BYTES]);

/* *T = the tree over the 2^LOG leaf hashes LEAF (32 bytes each, leaf 0
 * first). ZK_OK; ZK_ERR_COUNT when LOG is above ZK_MERKLE_LOG_MAX;
 * ZK_ERR_MEMORY. On an error T->node is NULL. */
ZkErr zk_merkle_build(ZkMerkle *t, unsigned log, const uint8_t *leaf);
void zk_merkle_free(ZkMerkle *t);

/* The root: 32 bytes. */
const uint8_t *zk_merkle_root(const ZkMerkle *t);

/* PATH = the LOG sibling hashes of leaf J, from the leaf level up. 1 when ok;
 * 0 when J is not below 2^LOG (then PATH is not written). */
int zk_merkle_path(const ZkMerkle *t, uint32_t j, uint8_t *path);

/* 1 when the leaf hash LEAF at J and the LOG hashes PATH give ROOT; 0 else
 * (also when LOG is above ZK_MERKLE_LOG_MAX or J is not below 2^LOG). */
int zk_merkle_path_check(const uint8_t root[ZK_MERKLE_BYTES], unsigned log, uint32_t j,
                         const uint8_t leaf[ZK_MERKLE_BYTES], const uint8_t *path);

/* The multi-open of the COUNT leaves IDX (COUNT at least 1, IDX strictly
 * increasing and below 2^log): the sibling hashes that the open leaves do not
 * give, level by level from the leaves up, each level in increasing node
 * order. OUT has room for COUNT * log hashes; *HASHES gets the count written.
 * For one leaf the result is its path. ZK_OK; ZK_ERR_MAP for a bad IDX;
 * ZK_ERR_MEMORY. */
ZkErr zk_merkle_open(const ZkMerkle *t, const uint32_t *idx, size_t count, uint8_t *out, size_t *hashes);

/* 1 when the COUNT leaf hashes LEAF at IDX and the HASHES hashes SIB (in the
 * order of zk_merkle_open) give ROOT, and each hash of SIB is used; 0 else
 * (also for a bad IDX or LOG, and when memory runs out). */
int zk_merkle_check(const uint8_t root[ZK_MERKLE_BYTES], unsigned log, const uint32_t *idx, size_t count,
                    const uint8_t *leaf, const uint8_t *sib, size_t hashes);

#endif
