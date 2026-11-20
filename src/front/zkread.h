/* S7 U7 D142, D145, D146: the native reader of the client witness words.
 * It parses the vote block (D139, 4256 words) and the motion block (D140, 82
 * words) that the client Wasm module writes, without the count word. It
 * checks the four refusal classes of D133 in the order R1 to R4 and returns
 * the first refusal. It calls no prover: a caller that gets a refusal makes
 * no proof. It does not abort and does not assert.
 *
 * R1 count: the word count is not exact.
 * R2 limb: a Digest word group is not a canonical Fr (root, nf or mt, K, each
 *   sibling, the motion ctx); w is not 3 or 4; idx is not below 2^16; an m
 *   slot is not 0 or 1, or m is not one-hot in slots 0 .. w - 1; an e1 or e2
 *   word is outside the TUniform(17) support -2^17 .. 2^17 (two's complement).
 * R3 reference: the root through the path, nf = H(4, K ++ e ++ u, 6), mt =
 *   H(6, K ++ e ++ ctx, 9), the 16 bodies (zk_gballot_fill from r, m, e2
 *   under the context pk_b) or the 2048 mask words (zk_gmask_fill from r, e1
 *   under the context pk_a, one slice of 64 at a time) differ from the words.
 * R4 context: the root, e or the motion ctx of the words differ from the
 *   verifier context.
 *
 * D146: the D139 block carries no pk word and the path carries no direction
 * word. Thus a changed context pk word shows only in the recomputed
 * ciphertext (R3), and a changed idx below 2^16 shows only in the root
 * through the path (R3). */
#ifndef CHARTER_ZKREAD_H
#define CHARTER_ZKREAD_H

#include <stddef.h>
#include <stdint.h>

#include "front/zk.h"

typedef enum { ZR_OK = 0, ZR_ERR_COUNT = 1, ZR_ERR_LIMB = 2, ZR_ERR_REF = 3, ZR_ERR_CONTEXT = 4 } ZrErr;

/* The text of a code, for the tool output. */
const char *zr_err_text(ZrErr e);

enum {
  ZR_VOTE_WORDS = 4256,
  ZR_MOTION_WORDS = 82,
  ZR_PATH_WORDS = ZK_MERKLE_LEVELS * 4,
  ZR_IDX_LIMIT = 1 << 16
};

/* The verifier context. The vote reader uses root, e, pk_a and pk_b (each
 * ZK_PKE_N words, not NULL); the motion reader uses root, e and ctx. */
typedef struct ZrContext {
  uint64_t root[4];
  uint64_t e;
  const uint64_t *pk_a;
  const uint64_t *pk_b;
  uint64_t ctx[4];
} ZrContext;

/* The typed vote witness (D139). r holds the 2048 bits, bit i of word i / 64
 * at bit i mod 64. */
typedef struct ZrVote {
  uint64_t root[4];
  uint64_t nf[4];
  uint64_t e;
  uint64_t u;
  uint32_t w;
  uint64_t mask[ZK_PKE_N];
  uint64_t body[ZK_PKE_SLOTS];
  uint64_t key[4];
  uint32_t idx;
  uint64_t sib[ZR_PATH_WORDS];
  uint8_t m[ZK_PKE_SLOTS];
  uint8_t r[ZK_PKE_N];
  int64_t e1[ZK_PKE_N];
  int64_t e2[ZK_PKE_SLOTS];
} ZrVote;

/* The typed motion witness (D140). */
typedef struct ZrMotion {
  uint64_t root[4];
  uint64_t mt[4];
  uint64_t e;
  uint64_t ctx[4];
  uint64_t key[4];
  uint32_t idx;
  uint64_t sib[ZR_PATH_WORDS];
} ZrMotion;

/* Reads N words into OUT and checks R1 to R4 against CTX. OUT is complete
 * only when the result is ZR_OK. Not reentrant: the R3 recompute uses one
 * static weight area. */
ZrErr zr_read_vote(ZrVote *out, const uint64_t *words, size_t n, const ZrContext *ctx);
ZrErr zr_read_motion(ZrMotion *out, const uint64_t *words, size_t n, const ZrContext *ctx);

#endif
