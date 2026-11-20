/* S7 U1: the ZK Circuit IR writer (docs/PLAN.md 5.2, Q-S7-1, Q-S7-4). A
 * circuit is the BN254 arithmetic entry of the zkml-lang printer
 * `build/halo2print` (968dce4 src/halo2.c). Its value numbers are the public
 * inputs 0 .. n-1, the private weights n .. n+m-1, then one value for each
 * instruction that is not eq, in emit order. The numbering, the constants and
 * the eq wiring depend only on the builder calls, never on witness values.
 *
 * The printer gives an out row a free witness that only the instance binds,
 * so zk_out also emits eq (out value, source): an output is constrained to
 * the value that it names. An arithmetic result is constrained to another
 * value only by zk_eq.
 *
 * Each builder call checks its operands. The first error is kept and later
 * calls do nothing, so a caller checks once, at zk_words. zk_words writes the
 * four printer blocks only when the circuit and the witness are both valid;
 * otherwise the output stays empty. */
#ifndef CHARTER_ZK_H
#define CHARTER_ZK_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum {
  ZK_LIMBS = 8,        /* 32-bit limbs of one Fr element, low limb first */
  ZK_FIELD_BN254 = 2,  /* the printer field id */
  ZK_VERSION = 1,      /* the circuit and the witness version */
  ZK_HEADER_WORDS = 7, /* version, field, size, n, m, q, instruction count */
  /* The value count limit: 2^28 rows (the 2-adicity of the BN254 Fr) minus
   * the 6 rows that the printer keeps for blinding (UNUSABLE_ROWS). */
  ZK_VALUES_MAX = (1 << 28) - 6
};

/* The printer instruction tags (src/halo2.c TAG_*). */
typedef enum { ZK_CONST = 1, ZK_ADD = 2, ZK_SUB = 3, ZK_MUL = 4, ZK_OUT = 5, ZK_EQ = 6, ZK_REFUSE = 7 } ZkTag;

typedef enum {
  ZK_OK,
  ZK_ERR_MEMORY,       /* an allocation failed */
  ZK_ERR_COUNT,        /* a count is above its limit, or a size overflows */
  ZK_ERR_NONCANONICAL, /* an element is not below the BN254 Fr modulus r */
  ZK_ERR_REF,          /* a value is not defined yet, or an out value is an operand of an op that is not eq */
  ZK_ERR_OUTPUT,       /* an output number is not below q, or it is written twice, or not written */
  ZK_ERR_WITNESS,      /* a witness count does not agree with the circuit */
  ZK_ERR_MAP,          /* a matrix index is not below the matrix count, or the mapped entries are not m */
  ZK_ERR_REFUSED,      /* zk_refuse: the relation needs a gadget that the writer does not have */
  ZK_ERR_UNSAT         /* zk_check: an eq does not hold for the witness */
} ZkErr;

/* One canonical Fr element: 8 limbs of 32 bits, low limb first, below r. */
typedef struct ZkFr {
  uint32_t limb[ZK_LIMBS];
} ZkFr;

/* A word stream. count words are valid; the stream owns word. */
typedef struct ZkWords {
  uint32_t *word;
  size_t count;
  size_t cap;
} ZkWords;

typedef struct ZkCircuit {
  uint32_t inputs;  /* n: public */
  uint32_t weights; /* m: private */
  uint32_t outputs; /* q: public, after the inputs in the instance */
  uint32_t vals;    /* the value numbers defined so far */
  uint32_t instrs;
  ZkWords code;          /* the instructions: tag, then operands */
  unsigned char *is_out; /* one byte for each result value: 1 for an out value */
  size_t is_out_cap;
  unsigned char *written; /* one byte for each output */
  ZkErr err;              /* the first error */
} ZkCircuit;

/* A rank-2 witness matrix: rows x cols entries in row-major order. */
typedef struct ZkMatrix {
  uint32_t rows;
  uint32_t cols;
  const ZkFr *entry;
} ZkMatrix;

/* The witness blocks. The map gives the matrix of each weight group in
 * weight order: weight n + j is entry j of the mapped matrices, each in
 * row-major order. The final trace stage holds the q public outputs. */
typedef struct ZkWitness {
  uint32_t inputs;
  const ZkFr *input;
  uint32_t matrices;
  const ZkMatrix *matrix;
  uint32_t maps;
  const uint32_t *map;
  uint32_t outputs;
  const ZkFr *output;
} ZkWitness;

ZkFr zk_fr_u64(uint64_t v);

/* 1 when the limbs of K are below r. */
int zk_canonical(const ZkFr *k);

const char *zk_err_text(ZkErr e);

/* Starts a circuit with N inputs, M weights and Q outputs. A count above
 * the limits is ZK_ERR_COUNT. */
void zk_init(ZkCircuit *c, uint32_t n, uint32_t m, uint32_t q);
void zk_free(ZkCircuit *c);

/* The value number of input I and of weight J. */
uint32_t zk_input(ZkCircuit *c, uint32_t i);
uint32_t zk_weight(ZkCircuit *c, uint32_t j);

/* Each returns the new value number (0 after an error). */
uint32_t zk_const(ZkCircuit *c, const ZkFr *k);
uint32_t zk_add(ZkCircuit *c, uint32_t a, uint32_t b);
uint32_t zk_sub(ZkCircuit *c, uint32_t a, uint32_t b);
uint32_t zk_mul(ZkCircuit *c, uint32_t a, uint32_t b);

/* Writes value V to output O and constrains the out value to V. */
uint32_t zk_out(ZkCircuit *c, uint32_t o, uint32_t v);

/* A copy constraint: value A equals value B. */
void zk_eq(ZkCircuit *c, uint32_t a, uint32_t b);

/* Refuses the circuit (ZK_ERR_REFUSED): no words are written for it. */
void zk_refuse(ZkCircuit *c);

/* Writes the four printer blocks of C with witness W to OUT (empty on entry).
 * On an error OUT stays empty. */
ZkErr zk_words(const ZkCircuit *c, const ZkWitness *w, ZkWords *out);
void zk_words_free(ZkWords *w);

/* Prints the words on one line. 1 when ok; 0 when a write fails. */
int zk_print(const ZkWords *w, FILE *out);

/* S7 U2: Fr arithmetic mod r on canonical elements. */
ZkFr zk_fr_add(const ZkFr *a, const ZkFr *b);
ZkFr zk_fr_sub(const ZkFr *a, const ZkFr *b);
ZkFr zk_fr_mul(const ZkFr *a, const ZkFr *b);

/* D1: evaluates C with witness W over Fr; an out value is its instance
 * output. ZK_OK only when every eq holds, ZK_ERR_UNSAT when one does not.
 * The checks before the evaluation are those of zk_words. */
ZkErr zk_check(const ZkCircuit *c, const ZkWitness *w);

/* The gadgets. A gadget constrains the caller weights W0 .. W0 + k - 1 and
 * emits every constraint. The matching fill writes those k entries (WT is the
 * entry of weight W0) from the operand values. Every value in a relation is
 * below 2^253 < r, so an Fr equality is an integer equality. */
enum { ZK_BITS_MAX = 252 };

/* D2: weights W0 .. W0 + N - 1 are bits (b (b - 1) = 0). Returns the value
 * sum b_i 2^i. N of 0 or above ZK_BITS_MAX is ZK_ERR_COUNT. */
uint32_t zk_word(ZkCircuit *c, uint32_t w0, uint32_t n);

/* X equals the word of the N bits at W0. */
void zk_bits(ZkCircuit *c, uint32_t x, uint32_t w0, uint32_t n);

/* Bits 0 .. N - 1 of X. */
void zk_bits_fill(ZkFr *wt, const ZkFr *x, uint32_t n);

/* D3: X is in [0, B] for a constant B below 2^ZK_BITS_MAX. With n the bit
 * length of B: the n bits of X, and when B is not 2^n - 1 also the n bits of
 * B - X (the two words add to B). B = 0: X equals 0, with no weight.
 * zk_range_weights is the weight count (0 for a B that is too large). */
uint32_t zk_range_weights(const ZkFr *b);
void zk_range(ZkCircuit *c, uint32_t x, const ZkFr *b, uint32_t w0);
void zk_range_fill(ZkFr *wt, const ZkFr *x, const ZkFr *b);

/* D3: X is in [-2^(N-1), 2^(N-1)) (a negative X is r - |X|): the N bits of
 * X + 2^(N-1). */
void zk_signed(ZkCircuit *c, uint32_t x, uint32_t w0, uint32_t n);
void zk_signed_fill(ZkFr *wt, const ZkFr *x, uint32_t n);

/* D4: X = hi 2^LO + lo, with lo the LO bits at W0, hi the weight W0 + LO and
 * hi in [0, HI] (zk_range at W0 + LO + 1). Returns lo and writes hi to *HIV.
 * LO of 0, or LO plus the bit length of HI above ZK_BITS_MAX, is
 * ZK_ERR_COUNT: then hi 2^LO + lo is below 2^252 and the Fr relation is an
 * integer relation. zk_split_weights is LO + 1 plus the range weights of HI
 * (0 for a shape that is not allowed). */
uint32_t zk_split_weights(uint32_t lo, const ZkFr *hi);
uint32_t zk_split(ZkCircuit *c, uint32_t x, uint32_t lo, const ZkFr *hi, uint32_t w0, uint32_t *hiv);
void zk_split_fill(ZkFr *wt, const ZkFr *x, uint32_t lo, const ZkFr *hi);

/* D4 mod 2^64 and mod 2^128. Each operand is a 64-bit limb that the caller
 * has already put in [0, 2^64); each result limb is in [0, 2^64). A 2^128
 * value is two limbs, low limb first. */
enum {
  ZK_ADD64_WEIGHTS = 66,     /* split(64, 1) */
  ZK_MULADD64_WEIGHTS = 129, /* split(64, 2^64 - 1) */
  ZK_ADD128_WEIGHTS = 132,   /* split(64, 1), two times */
  ZK_MUL128_WEIGHTS = 388    /* split(64, 2^64 - 2), then split(64, 2^65 - 3) */
};

/* A + B = carry 2^64 + r: returns r and writes the carry bit to *CARRY. */
uint32_t zk_add64(ZkCircuit *c, uint32_t a, uint32_t b, uint32_t w0, uint32_t *carry);
void zk_add64_fill(ZkFr *wt, const ZkFr *a, const ZkFr *b);

/* A B + C = hi 2^64 + lo: returns lo and writes hi to *HI. */
uint32_t zk_muladd64(ZkCircuit *c, uint32_t a, uint32_t b, uint32_t cc, uint32_t w0, uint32_t *hi);
void zk_muladd64_fill(ZkFr *wt, const ZkFr *a, const ZkFr *b, const ZkFr *cc);

/* R = A + B and R = A B mod 2^128. The add has a carry bit for each limb (the
 * top carry is dropped). The mul has lo = a0 b0 = q0 2^64 + r0 with q0 in
 * [0, 2^64 - 2] and a0 b1 + a1 b0 + q0 = q1 2^64 + r1 with q1 in
 * [0, 2^65 - 3]; the a1 b1 term is a multiple of 2^128. */
void zk_add128(ZkCircuit *c, const uint32_t a[2], const uint32_t b[2], uint32_t w0, uint32_t r[2]);
void zk_add128_fill(ZkFr *wt, const ZkFr a[2], const ZkFr b[2]);
void zk_mul128(ZkCircuit *c, const uint32_t a[2], const uint32_t b[2], uint32_t w0, uint32_t r[2]);
void zk_mul128_fill(ZkFr *wt, const ZkFr a[2], const ZkFr b[2]);

/* D5 mod p, p = 2^192 - 1253375 (src/front/tshare.h). An element is three
 * 64-bit limbs, low limb first, of a value in [0, p - 1]. zk_fp makes one from
 * the ZK_FP_WEIGHTS weights at W0: zk_range of the value with B = p - 1, and
 * the limbs are the bit words 0-63, 64-127 and 128-191. It writes the limbs
 * to X and returns the value. zk_fp_bind makes one and binds its limbs to A.
 * zk_fp_fill takes the limbs, each below 2^64. */
enum {
  ZK_FP_WEIGHTS = 384,   /* 192 bits and 192 complement bits */
  ZK_ADDP_WEIGHTS = 385, /* q, then r */
  ZK_MULP_WEIGHTS = 1040 /* q, r, then 4 carries of 68 bits */
};
uint32_t zk_fp(ZkCircuit *c, uint32_t w0, uint32_t x[3]);
void zk_fp_bind(ZkCircuit *c, const uint32_t a[3], uint32_t w0);
void zk_fp_fill(ZkFr *wt, const ZkFr x[3]);

/* R = A + B mod p for elements A and B: a + b = q p + r with q the bit at W0
 * and r the element at W0 + 1. Every value is below 2^194. */
void zk_addp(ZkCircuit *c, const uint32_t a[3], const uint32_t b[3], uint32_t w0, uint32_t r[3]);
void zk_addp_fill(ZkFr *wt, const ZkFr a[3], const ZkFr b[3]);

/* R = A B mod p: a b = q p + r with q the element at W0 and r the element at
 * W0 + ZK_FP_WEIGHTS. The 384-bit identity has 6 limb columns of 64 bits.
 * Column k (k < 5) is sum a_i b_j + c_(k-1) = sum q_i p_j + r_k + c_k 2^64
 * over i + j = k, with r_k = 0 for k > 2 and c_(-1) = 0; c_k + 2^67 is the 68
 * bits at W0 + 2 ZK_FP_WEIGHTS + 68 k for k < 4, and c_4 = 0 (the limb 5
 * column is 0). Each column is below 2^132 in absolute value, so each Fr
 * relation is an integer relation. The fill finds q and r by long division. */
void zk_mulp(ZkCircuit *c, const uint32_t a[3], const uint32_t b[3], uint32_t w0, uint32_t r[3]);
void zk_mulp_fill(ZkFr *wt, const ZkFr a[3], const ZkFr b[3]);

/* D6: Poseidon2 over Fr (front/poseidon2.h: width 3, x^5). Round constant K
 * (below POSEIDON2_CONSTANTS, in permutation order) as a canonical element. */
ZkFr zk_poseidon2_constant(uint32_t k);
/* The permutation of the values S, in place, as constants, ADD and MUL: x^5
 * is 3 MUL, each linear layer is ADD only. */
void zk_poseidon2_permute(ZkCircuit *c, uint32_t s[3]);
/* H(TAG, words, N) of poseidon2_hash: word i is the 64 bits at
 * W0 + ZK_POSEIDON2_WORD_BITS i (zk_word, so each word is below 2^64). The
 * capacity starts at the constant TAG 2^64 + N. Returns the digest value
 * (element 0 of the state). */
enum { ZK_POSEIDON2_WORD_BITS = 64 };
uint32_t zk_poseidon2_hash(ZkCircuit *c, uint64_t tag, uint32_t n, uint32_t w0);
void zk_poseidon2_hash_fill(ZkFr *wt, const uint64_t *words, uint32_t n);
/* S7 U3 D10: H(TAG, words, N) over the word values X[0 .. N - 1], each of
 * which the caller has put below 2^64. The sponge and the emit order are those
 * of zk_poseidon2_hash, with X[i] in place of the zk_word of word i. */
uint32_t zk_poseidon2_hash_values(ZkCircuit *c, uint64_t tag, uint32_t n, const uint32_t *x);

/* D11: the 4 word values X (each below 2^64, word 0 low) are a value below r.
 * Y = (r - 1) - X is the 4 words of 64 bits at W0 and c_1 .. c_3 are the bits
 * at W0 + 256: x_i + y_i + c_i = R_i + 2^64 c_(i+1) with R_i word i of r - 1
 * and c_0 = c_4 = 0. Each side is below 2^66, so each EQ is an integer one.
 * zk_recompose returns sum x_i 2^(64 i). zk_digest makes a Digest: the 4
 * words at W0 (zk_word), then zk_canon at W0 + 256; it writes the words to X.
 * A fill takes the 4 words, word 0 low. */
enum { ZK_DIGEST_WORDS = 4, ZK_CANON_WEIGHTS = 259, ZK_DIGEST_WEIGHTS = 256 + ZK_CANON_WEIGHTS };
void zk_canon(ZkCircuit *c, const uint32_t x[4], uint32_t w0);
void zk_canon_fill(ZkFr *wt, const uint64_t x[4]);
uint32_t zk_recompose(ZkCircuit *c, const uint32_t x[4]);
void zk_digest(ZkCircuit *c, uint32_t w0, uint32_t x[4]);
void zk_digest_fill(ZkFr *wt, const uint64_t x[4]);

/* D12: one Merkle level (Q-S4-3, Q-S4-6) over the value CUR. The left child
 * L is the Digest at W0, the right child R the Digest at W0 + ZK_DIGEST_WEIGHTS
 * and the direction b the bit after them: cur = A + b (B - A) for the values
 * A of L and B of R, so b = 0 puts cur on the left. Returns H(3, L ++ R, 8).
 * zk_path is the 16 levels from CUR, level d at W0 + d ZK_NODE_WEIGHTS, and
 * returns the root. zk_member is zk_path from the leaf commit k = H(2, K, 4)
 * of the key words K. A fill takes the leaf (or the key), the 16 siblings
 * (level 0 first) and the leaf index IDX (bit d is the direction of level d),
 * and writes the root words to ROOT. SIB is 16 x 4 words, level 0 first. */
enum { ZK_NODE_WEIGHTS = 2 * ZK_DIGEST_WEIGHTS + 1, ZK_MERKLE_LEVELS = 16 };
uint32_t zk_node(ZkCircuit *c, uint32_t cur, uint32_t w0);
uint32_t zk_path(ZkCircuit *c, uint32_t cur, uint32_t w0);
void zk_path_fill(ZkFr *wt, const uint64_t leaf[4], const uint64_t *sib, uint32_t idx,
                  uint64_t root[4]);
uint32_t zk_member(ZkCircuit *c, const uint32_t k[4], uint32_t w0);
void zk_member_fill(ZkFr *wt, const uint64_t key[4], const uint64_t *sib, uint32_t idx,
                    uint64_t root[4]);

/* D13: the vote relation (membership and nullifier). zk_gvote starts C with
 * inputs e (0) and u (1), outputs root (0) and nf (1) = H(4, K ++ e ++ u, 6).
 * Weights: the key Digest K at 0, the 64-bit words e and u after it (each
 * EQ its input), then zk_member of K. */
enum { ZK_GVOTE_WEIGHTS = ZK_DIGEST_WEIGHTS + 128 + ZK_MERKLE_LEVELS * ZK_NODE_WEIGHTS };
void zk_gvote(ZkCircuit *c);
void zk_gvote_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, uint64_t u, const uint64_t *sib,
                   uint32_t idx, uint64_t root[4], uint64_t nf[4]);

/* D14: the motion relation (Q-S7-U3-1 (a)). zk_gmotion starts C with inputs
 * e (0) and ctx (1, one Fr), outputs root (0) and mt (1) = H(6, K ++ e ++
 * ctx, 9). Weights: the key Digest K at 0, the 64-bit word e (EQ input 0),
 * the ctx Digest (its value EQ input 1), then zk_member of K. */
enum { ZK_GMOTION_WEIGHTS = 2 * ZK_DIGEST_WEIGHTS + 64 + ZK_MERKLE_LEVELS * ZK_NODE_WEIGHTS };
void zk_gmotion(ZkCircuit *c);
void zk_gmotion_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, const uint64_t ctx[4],
                     const uint64_t *sib, uint32_t idx, uint64_t root[4], uint64_t mt[4]);

/* S7 U4 D21 to D23: the PKE ballot relation of tfhe_pke_encrypt
 * (src/front/tfhe.c). The constants are those of tfhe.h (TFHE_POLY_N,
 * TFHE_PLAIN, TFHE_PKE_NOISE, TFHE_DELTA_LOG); test/zktool.c checks them. */
enum {
  ZK_PKE_N = 2048,
  ZK_PKE_SLOTS = 16,
  ZK_PKE_NOISE = 17,
  ZK_PKE_DELTA_LOG = 59,
  ZK_LWE_RANGE_WEIGHTS = 38, /* zk_range of e + 2^17 in [0, 2^18]: 2 x 19 bits */
  ZK_LWE_Q_BITS = 13,        /* q in [-2^12, 2^12) */
  ZK_LWE_WEIGHTS = 2 + ZK_LWE_RANGE_WEIGHTS + ZK_LWE_Q_BITS
};

/* D21: S_k = sum over i of s_i P[i] rev[(k - i) mod N] for the N values P and
 * the N bit values R (rev[t] = R[N - 1 - t]), with s_i = +1 for i <= K (ADD)
 * and -1 for i > K (SUB): coefficient K of P phi_1(r) over the integers,
 * before the mod 2^64 wrap. |S_k| < N 2^64 < 2^75. One MUL and one ADD or
 * SUB for each term. K not below N is ZK_ERR_COUNT. */
uint32_t zk_negacyclic(ZkCircuit *c, const uint32_t *p, const uint32_t *r, uint32_t k);

/* D22: S + e + M = W + 2^64 q for the public word W (below 2^64: a verifier
 * requirement), the message term M (none when M is NULL), the error e (the
 * weight W0) with e + 2^17 in [0, 2^18] (zk_range at W0 + 1) and the quotient q
 * (the weight W0 + 1 + ZK_LWE_RANGE_WEIGHTS) in [-2^12, 2^12) (zk_signed after
 * it). Every term is below 2^77, so W = (S + e + M) mod 2^64, the C uint64
 * wrap. The fill takes e and q. */
void zk_lwe_word(ZkCircuit *c, uint32_t s, const uint32_t *m, uint32_t w, uint32_t w0);
void zk_lwe_word_fill(ZkFr *wt, int64_t e, int64_t q);

/* D23: the one-hot ballot (Q-S5-12, chain_list). The 16 weights at W0 are
 * bits m_j that add to 1, m_j = 0 for j >= 4, and the public width W has
 * (w - 3) (w - 4) = 0 and m_3 (4 - w) = 0: one 1 in slots 0 .. w - 1. Writes
 * the bit values to M. */
void zk_onehot(ZkCircuit *c, uint32_t w, uint32_t w0, uint32_t m[ZK_PKE_SLOTS]);

/* D19: the complete ballot relation as one circuit. Inputs e (0), u (1), w
 * (2), pk_a, pk_b, the mask, then the 16 bodies; outputs root (0) and nf (1).
 * Weights: gvote at 0 (zk_gvote), r (32 zk_word of 64 bits: weight
 * ZK_GBALLOT_R + t is r[t]), the 16 ballot bits, then the ZK_LWE_WEIGHTS of each
 * mask coefficient k (zk_lwe_word of zk_negacyclic(pk_a, r, k) with e1_k) and
 * of each body j (zk_negacyclic(pk_b, r, N - 1 - j) with e2_j and m_j 2^59).
 * The fill takes the gvote values, the bits R and M, and the errors E1 and E2;
 * it computes each quotient from the integer sums and writes the mask and
 * the 16 bodies (mod 2^64) to WORDS. */
enum {
  ZK_GBALLOT_IN_PKA = 3,
  ZK_GBALLOT_IN_PKB = ZK_GBALLOT_IN_PKA + ZK_PKE_N,
  ZK_GBALLOT_IN_MASK = ZK_GBALLOT_IN_PKB + ZK_PKE_N,
  ZK_GBALLOT_IN_BODY = ZK_GBALLOT_IN_MASK + ZK_PKE_N,
  ZK_GBALLOT_INPUTS = ZK_GBALLOT_IN_BODY + ZK_PKE_SLOTS,
  ZK_GBALLOT_R = ZK_GVOTE_WEIGHTS,
  ZK_GBALLOT_M = ZK_GBALLOT_R + ZK_PKE_N,
  ZK_GBALLOT_LWE = ZK_GBALLOT_M + ZK_PKE_SLOTS,
  ZK_GBALLOTFULL_WEIGHTS = ZK_GBALLOT_LWE + (ZK_PKE_N + ZK_PKE_SLOTS) * ZK_LWE_WEIGHTS
};
void zk_gballotfull(ZkCircuit *c);
void zk_gballotfull_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, uint64_t u, const uint64_t *sib, uint32_t idx,
                         const uint64_t *pk_a, const uint64_t *pk_b, const uint8_t *r, const uint8_t *m,
                         const int64_t *e1, const int64_t *e2, uint64_t root[4], uint64_t nf[4], uint64_t *words);

/* S7 U4 D20 (Q-S7-U4-1 (a), slices + Cr): the randomness commitment Cr =
 * H(7, the 32 words of r, 32), word w being sum r[64 w + t] 2^t (the zk_word
 * of 64 bits at ZK_GBALLOT_R + 64 w in gballot, at 64 w in gmask). Every slice
 * proof has Cr as a public output, so the 33 proofs of one ballot share one r.
 * zk_pke_commit is the C value (4 words, word 0 low). */
enum { ZK_CR_TAG = 7, ZK_CR_WORDS = ZK_PKE_N / ZK_POSEIDON2_WORD_BITS };
void zk_pke_commit(const uint8_t *r, uint64_t cr[4]);

/* D20 gmask, one shape for each offset o = 0, 64, .., N - 64. Inputs
 * A'[0 .. N - 1] (A' = X^-o pk_a mod (X^N + 1, 2^64), the caller's input)
 * and the slice mask[o .. o + 63]; output Cr (0). Weights: r (32 zk_word of
 * 64 bits at 0), then the ZK_LWE_WEIGHTS of slice coefficient t (zk_lwe_word
 * of zk_negacyclic(A', r, t) with e1[o + t]): coefficient t of X^-o (pk_a
 * phi_1(r)) is mask coefficient o + t, as o + t < N. The fill takes A', the
 * bits R and the 64 errors E1 of the slice; it writes the 64 mask words to
 * WORDS and Cr to CR. */
enum {
  ZK_GMASK_SPAN = 64,
  ZK_GMASK_IN_MASK = ZK_PKE_N,
  ZK_GMASK_INPUTS = ZK_GMASK_IN_MASK + ZK_GMASK_SPAN,
  ZK_GMASK_LWE = ZK_PKE_N,
  ZK_GMASK_WEIGHTS = ZK_GMASK_LWE + ZK_GMASK_SPAN * ZK_LWE_WEIGHTS
};
void zk_gmask(ZkCircuit *c);
void zk_gmask_fill(ZkFr *wt, const uint64_t *ap, const uint8_t *r, const int64_t *e1, uint64_t *words, uint64_t cr[4]);

/* D20, D24 gballot: gvote and the 16 bodies under pk_b in one witness.
 * Inputs e (0), u (1), w (2), pk_b, then the 16 bodies; outputs root (0), nf
 * (1) and Cr (2). Weights as zk_gballotfull without the mask: gvote at 0, r at
 * ZK_GBALLOT_R, the 16 ballot bits at ZK_GBALLOT_M (zk_onehot of w), then the
 * ZK_LWE_WEIGHTS of each body j at ZK_GBALLOT_LWE. The fill writes the 16 body
 * words to WORDS and Cr to CR. */
enum {
  ZK_GB_IN_PKB = 3,
  ZK_GB_IN_BODY = ZK_GB_IN_PKB + ZK_PKE_N,
  ZK_GB_INPUTS = ZK_GB_IN_BODY + ZK_PKE_SLOTS,
  ZK_GB_WEIGHTS = ZK_GBALLOT_LWE + ZK_PKE_SLOTS * ZK_LWE_WEIGHTS
};
void zk_gballot(ZkCircuit *c);
void zk_gballot_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, uint64_t u, const uint64_t *sib, uint32_t idx,
                     const uint64_t *pk_b, const uint8_t *r, const uint8_t *m, const int64_t *e2, uint64_t root[4],
                     uint64_t nf[4], uint64_t cr[4], uint64_t *words);

/* D7: SHA-512 (front/sha512.h, FIPS 180-4) of N private bytes. Byte p is the
 * 8 bits at W0 + 8 p (zk_word, low bit first). The padding comes from the
 * public N, so the shape does not depend on the bytes. A word is 64 bit
 * values: xor is a + b - 2 a b, ch is g + e (f - g), maj is a b + c (a xor b),
 * ROTR and SHR are bit rewiring, and an add of k words mod 2^64 is
 * zk_split(64, k - 1), the exact carry bound. After the bytes, each block has
 * the 64 schedule words, then e and a of each of the 80 rounds, then the 8
 * chaining adds. DIGEST gets the 8 digest words (each below 2^64, word 0
 * first: load_be of the digest bytes). zk_sha512_weights is the weight count
 * (0 for N above ZK_SHA512_BYTES_MAX). */
enum { ZK_SHA512_BYTES_MAX = 1 << 20 };
uint32_t zk_sha512_weights(uint32_t n);
void zk_sha512(ZkCircuit *c, uint32_t n, uint32_t w0, uint32_t digest[8]);
void zk_sha512_fill(ZkFr *wt, const uint8_t *bytes, uint32_t n);

/* S7 U5 L1: SHA-512 blocks B0 .. B0 + NB - 1 of the padded message of N
 * bytes (one chunk of a chained proof). The weights at W0 are the chunk
 * message bytes (bytes 128 B0 .. min(N, 128 (B0 + NB)) - 1, in order, each a
 * zk_word of 8 bits), then the 8 input chaining words (a zk_word of 64 bits
 * each; word i EQ HIN[i], the caller's public values), then the block
 * weights of zk_sha512. The padding comes from the public N only. HOUT gets
 * the 8 chaining words after the last block (each below 2^64); the caller
 * binds them (zk_out). BYTE, when not NULL, gets the chunk byte values in
 * order (S7 U5 D49). zk_sha512_chunk_weights is the weight count (0 for a
 * bad shape). The fill reads BYTES at the message offsets (the whole message)
 * and writes the chaining words after the last block to HOUT. */
uint32_t zk_sha512_chunk_weights(uint32_t n, uint32_t b0, uint32_t nb);
void zk_sha512_chunk(ZkCircuit *c, uint32_t n, uint32_t b0, uint32_t nb, uint32_t w0, const uint32_t hin[8],
                     uint32_t hout[8], uint32_t *byte);
void zk_sha512_chunk_fill(ZkFr *wt, const uint8_t *bytes, uint32_t n, uint32_t b0, uint32_t nb, const uint64_t hin[8],
                          uint64_t hout[8]);

/* S7 U5 D37 to D39: the partial of one party (src/front/tdec.h). */
enum {
  ZK_TDEC_PARTIES = 5,
  ZK_TDEC_COORDS_MAX = 4096,
  ZK_TDEC_Q_BITS = 142,    /* Q < (2^332 + 5 2^192) / p < 2^142 */
  ZK_TDEC_CARRY_BITS = 80, /* c_k + 2^79, |c_k| < 2^78 */
  ZK_TDEC_WEIGHTS = ZK_FP_WEIGHTS + ZK_TDEC_Q_BITS + 4 * ZK_TDEC_CARRY_BITS,
  ZK_CN_TAG = 8 /* D39; tag 5 stays unused */
};
/* D37: (P - 1)(P - 2)(P - 3)(P - 4)(P - 5) EQ 0 (4 MUL). */
void zk_party(ZkCircuit *c, uint32_t p);
/* D38: V = sum_i m_i s_i + sum_d b_d n_d mod p over N coordinates (N at
 * most ZK_TDEC_COORDS_MAX). S has the 3 N share limbs (s_(i,b) at S[3 i + b]),
 * M the 2 N mask words (m_(i,0) lo at M[2 i], m_(i,1) hi at M[2 i + 1]; the
 * verifier supplies them below 2^64), B the 5 subset bits (the caller emits
 * b (b - 1) EQ 0), NL the 3 limbs of each n_d (NL[3 (d - 1) + k], below 2^64:
 * zk_fp). Columns C_k = sum_(a + b = k) m_(i,a) s_(i,b) (k = 0 to 3; 6 MUL
 * and 6 ADD for each coordinate) and N_k = sum_d b_d n_(d,k) (k = 0 to 2).
 * The weights at W0 are V (zk_fp), Q (64, 64 and 14 bits) and the carries
 * c_k + 2^79 (80 bits each, k = 0 to 3). Column k (k = 0 to 4) is
 * C_k + N_k + c_(k-1) = V_k + sum_(i + j = k) q_i p_j + c_k 2^64, with
 * c_(-1) = 0, c_4 = 0, C_4 = 0, N_k = 0 for k > 2 and V_k = 0 for k > 2. Each
 * column is below 2^142 in absolute value, so each Fr relation is an integer
 * relation. V gets the limbs; the caller binds them. The fill takes the share
 * limbs, the mask words, the bits, the noise limbs and V (each below 2^64) and
 * finds Q by long division. */
void zk_tdec_reduce(ZkCircuit *c, uint32_t n, const uint32_t *s, const uint32_t *m, const uint32_t b[5],
                    const uint32_t nl[15], uint32_t w0, uint32_t v[3]);
void zk_tdec_reduce_fill(ZkFr *wt, uint32_t n, const uint64_t *s, const uint64_t *m, const uint64_t b[5],
                         const uint64_t nl[15], const uint64_t v[3]);
/* S7 U5 D52, D53 (gap 3): the split form of zk_tdec_reduce. zk_tdec_cols adds
 * the product columns C_0 to C_3 of N coordinates (S and M as above) into
 * COL. zk_tdec_reduce_from is zk_tdec_reduce with the columns started from A0
 * (NULL: zero; slice 15 gives the accumulator A_(14,c)) before the products of
 * its own N coordinates; zk_tdec_reduce is zk_tdec_reduce_from with A0 NULL
 * and makes the same circuit as before the split. zk_tdec_cols_fill adds the
 * columns of N coordinates into COL (3 words each, low word first). */
void zk_tdec_cols(ZkCircuit *c, uint32_t n, const uint32_t *s, const uint32_t *m, uint32_t col[4]);
void zk_tdec_reduce_from(ZkCircuit *c, const uint32_t a0[4], uint32_t n, const uint32_t *s, const uint32_t *m,
                         const uint32_t b[5], const uint32_t nl[15], uint32_t w0, uint32_t v[3]);
void zk_tdec_cols_fill(uint64_t col[][3], uint32_t n, const uint64_t *s, const uint64_t *m);
/* D39 (a stub until U6): Cn_d = H(ZK_CN_TAG, [P, D, n_(d,0), n_(d,1),
 * n_(d,2)], 5) over the values P (zk_party), the constant D and NL (zk_fp
 * limbs). */
uint32_t zk_noise_commit(ZkCircuit *c, uint32_t p, uint32_t d, const uint32_t nl[3]);

/* S7 U5 D48 to D54 (Q-S7-U5-1 (a), Q-S7-U5-3 (a)): chunk proof K of the split
 * share commitment. The message is LE32 P, then the 4096 x 24 share bytes
 * (tshare_commit): 98308 bytes, 769 blocks. Chunk K (0 to 255) is blocks
 * 3 K .. 3 K + 2 (bytes 384 K .. 384 K + 383); chunk 256 is block 768 (bytes
 * 98304 .. 98307 and the padding). Inputs: P (0), K (1) and, for K > 0,
 * Ch_(K-1) (2). Outputs: Cs_K (0); for K < 256 Ch_K (1); for K = 256 the 8
 * words of Dg (1 to 8). The weights are those of zk_sha512_chunk (at 0),
 * then for K > 0 the 8 private H_in words, then sigma_K, then rho_K
 * (K < 256), then rho_(K-1) (K > 0). A piece is the integer of its bytes, low
 * byte first (tshare_bytes): chunk bytes 0 to 3 are the bytes of P (K = 0:
 * EQ P, not a piece) or the last half of a cut group (K > 0); for K < 256,
 * bytes 4 + 8 t .. 11 + 8 t (t = 0 to 46) are whole groups and bytes 380 to
 * 383 the first half of a cut group. Cs_K = H(9, [sigma_K, P, K, pieces]),
 * Ch_K = H(10, [rho_K, P, K, H_out]), and H(10, [rho_(K-1), P, K - 1, H_in])
 * EQ Ch_(K-1); chunk 0 starts from the IV. Every chunk has zk_party. The
 * circuit is the same for K = 1 to 255. zk_gchunk_weights is the weight count
 * (0 for K above 256). The fill takes the whole message, H_in (the IV for
 * K = 0) and SALT = (sigma_K, rho_K, rho_(K-1)); HOUT gets H_out. */
enum {
  ZK_SPLIT_BYTES = 98308, /* 4 + 24 x 4096 */
  ZK_SPLIT_CHUNKS = 257,
  ZK_SPLIT_CHUNK_BYTES = 384,
  ZK_CS_TAG = 9,
  ZK_CH_TAG = 10,
  ZK_CA_TAG = 11
};
uint32_t zk_gchunk_weights(uint32_t k);
void zk_gchunk(ZkCircuit *c, uint32_t k);
void zk_gchunk_fill(ZkFr *wt, const uint8_t *msg, uint32_t k, const uint64_t hin[8], const ZkFr salt[3],
                    uint64_t hout[8]);

/* S7 U5 D52 to D54: the slice proof J (0 to 15) of one party. Inputs: P (0),
 * J (1), Cs_k for k = 16 J + t (2 + t, t = 0 to 16), Ca_(J-1) (19, J > 0),
 * the 512 mask words of coordinates 256 J to 256 J + 255 (lo, hi), then for
 * J = 15 b_1 to b_5 and V (3 words). Outputs: Ca_J (0) for J < 15, Cn_1 to
 * Cn_5 (0 to 4) for J = 15. Weights: for t = 0 to 16, sigma_k and then the
 * pieces of chunk k in the zk_gchunk order (48 for k = 0, 1 for k = 256, else
 * 49); then salt_(J-1) and A_(J-1,0) to A_(J-1,3) (J > 0); then salt_J
 * (J < 15) or the tail (J = 15): the 5 noise values (zk_fp, ZK_FP_WEIGHTS
 * each) and the zk_tdec_reduce_from weights. Each Cs_k is opened (EQ); the
 * neighbour pieces and sigma_k have no other use. The 768 limbs are the 752
 * whole pieces and the 16 cut limbs (first + 2^32 last). The columns start
 * from the opened A_(J-1) (J = 0: zero) and add the 256 products; Ca_J =
 * H(11, [salt_J, P, J, A_J]). Slice 15 does the D38 reduction and the D39
 * noise terms. Every slice has zk_party. The circuit is the same for J = 1 to
 * 14. zk_gslice_fill fills all weights but the J = 15 tail (at
 * zk_gslice_weights(15) - 5 ZK_FP_WEIGHTS - ZK_TDEC_WEIGHTS: zk_fp_fill of
 * the noise values, then zk_tdec_reduce_fill over all 4096 coordinates).
 * SIGMA has the 17 sigma_k, SALT = (salt_(J-1), salt_J), A0 = A_(J-1). */
enum { ZK_SPLIT_SLICES = 16, ZK_SPLIT_SLICE_CHUNKS = 16, ZK_SPLIT_SLICE_COORDS = 256 };
uint32_t zk_gslice_weights(uint32_t j);
void zk_gslice(ZkCircuit *c, uint32_t j);
void zk_gslice_fill(ZkFr *wt, const uint8_t *msg, uint32_t j, const ZkFr sigma[ZK_SPLIT_SLICE_CHUNKS + 1],
                    const ZkFr salt[2], const ZkFr a0[4]);

/* S7 U6 D61, D73: the tags of the U6 commitments (K, the dealt share C_(d,i),
 * the bit share vector). */
enum { ZK_K_TAG = 12, ZK_CD_TAG = 13, ZK_CB_TAG = 14 };
/* D62 G1 gtoss. FORM 0 (the commitment of one party): inputs P (0), commit_P
 * (1 .. 8) and seed_P (9 .. 16), each word load_be of 8 bytes; no output; the
 * relation is commit_P = SHA-512(LE32 P || seed_P) (68 bytes). FORM 1 (the
 * joint seed): inputs seed_1 .. seed_5 (word k of seed d at 8 (d - 1) + k), J
 * (40 .. 47) and e (48); output 0 is K = H(ZK_K_TAG, [J_0 .. J_7, e], 9); the
 * relation is J = SHA-512(seed_1 || .. || seed_5) (320 bytes). All inputs are
 * public; the weights are those of zk_sha512 over the message (zk_gtoss_fill:
 * MSG is the message). The verifier puts e below 2^64. zk_gtoss_weights is 0
 * for a FORM above 1. */
uint32_t zk_gtoss_weights(uint32_t form);
void zk_gtoss(ZkCircuit *c, uint32_t form);
void zk_gtoss_fill(ZkFr *wt, uint32_t form, const uint8_t *msg);

/* D63 G2 gdeal (one dealer d, M secrets of one row, degree TOP = 2 (t) or 4
 * (2t)). Inputs K (0), I (1) and d (2); output i - 1 (i = 1 .. 5) is
 * C_(d,i) = H(ZK_CD_TAG, [sigma_i, K, I, d, i, y_(i,1) .. y_(i,M) limbs],
 * 5 + 3 M) with y_(i,k) = x_k + sum_e c_(k,e) i^e mod p (one integer sum and
 * one ranged quotient for each share; x_k, c_(k,e), y_(i,k) canonical by
 * zk_fp). CLASS: ZK_GDEAL_NOISE (x = e mod p, e in [-2^(B-1), 2^(B-1)]:
 * u = e + 2^(B-1) in [0, 2^B] and x + 2^(B-1) = u + q p with q a bit, the
 * tkeygen_lift rule; B in 1 .. 62), ZK_GDEAL_R (x canonical, no range) or
 * ZK_GDEAL_ZERO (x = 0, TOP 4). The salts sigma_1 .. sigma_5 are the last 5
 * weights (no range). zk_gdeal_fill: X the 3 M limbs of the secrets (zeros
 * for ZK_GDEAL_ZERO), E the M noise values (ZK_GDEAL_NOISE only), COEF the
 * limbs of c_(k,e) at 3 (k TOP + e - 1), Y the limbs of y_(i,k) at
 * 3 ((i - 1) M + k) (the tshare_share layout), SALT the 5 salts.
 * zk_gdeal_weights is 0 for a shape it refuses. */
enum { ZK_GDEAL_NOISE, ZK_GDEAL_R, ZK_GDEAL_ZERO, ZK_GDEAL_MAX = 64, ZK_GDEAL_PARTIES = 5 };
uint32_t zk_gdeal_weights(uint32_t cls, uint32_t top, uint32_t m, uint32_t b);
void zk_gdeal(ZkCircuit *c, uint32_t cls, uint32_t top, uint32_t m, uint32_t b);
void zk_gdeal_fill(ZkFr *wt, uint32_t cls, uint32_t top, uint32_t m, uint32_t b, const ZkFr *x, const int64_t *e,
                   const ZkFr *coef, const ZkFr *y, const ZkFr salt[ZK_GDEAL_PARTIES]);

/* D63 G2 gflood (the D39 producer: one dealer d deals one flood noise e,
 * uniform in [-2^106, 2^106), as tdec_flood, degree t). Input d (0, the
 * dealer, zk_party); output P - 1 (P = 1 .. 5) is Cn_(d,P) = H(ZK_CN_TAG,
 * [P, d, y_P limbs], 5), unsalted, the zk_noise_commit form of U5.
 * u = e + 2^106 is in [0, 2^107 - 1] and x + 2^106 = u + q p with q a bit
 * (the tdec_flood lift); y_P = x + c_1 P + c_2 P^2 mod p (one integer sum
 * and one ranged quotient for each share; x, c_1, c_2 and y_P canonical by
 * zk_fp). zk_gflood_fill: U the 2 words of u (low first), X the limbs of x,
 * COEF the limbs of c_1 then c_2, Y the limbs of y_1 .. y_5. */
enum { ZK_GFLOOD_LOG = 106 };
uint32_t zk_gflood_weights(void);
void zk_gflood(ZkCircuit *c);
void zk_gflood_fill(ZkFr *wt, const uint64_t u[2], const ZkFr x[3], const ZkFr coef[6], const ZkFr y[15]);

/* D66 G5 gword (the opening of one key word from its 5 public shares; no
 * private input). Inputs 0 .. 14 are the limbs of share_1 .. share_5 (low
 * limb first), each canonical by zk_fp_bind; v = 5 s_1 - 10 s_2 + 10 s_3 -
 * 5 s_4 + s_5 mod p (one integer identity with a quotient Q in [0, 31]);
 * h = [v >= (p + 1) / 2] (a bit and the range of d, the at_least_half edge);
 * output k (k < WORDS) is W_k with v - h p = W + q 2^(64 WORDS), W = W_0 +
 * W_1 2^64 and each W_k below 2^64: tkeygen_word64 for WORDS 1,
 * tkeygen_word128 (lo, hi) for WORDS 2 (squash). zk_gword_fill: SH the 15
 * share limbs, V the 3 words of v (low first). */
enum { ZK_GWORD_SHIFT = 191 };
uint32_t zk_gword_weights(uint32_t words);
void zk_gword(ZkCircuit *c, uint32_t words);
void zk_gword_fill(ZkFr *wt, uint32_t words, const ZkFr sh[15], const uint64_t v[3]);

/* D64 G3 gbit (one party i, one bit j of tkeygen_bit_try). Inputs: K (0),
 * j (1), i (2, zk_party), w (3 .. 5), o_i (6 .. 8), low limb first, and the
 * key-vector id vid (9; C7, Q-S7-U6-4: 0 lwe, 1 glwe, 2 pke, 3 and 4 the
 * squash polys 0 and 1). The
 * weights hold r_(d,i) and z_(d,i) for d = 1 .. 5 (zk_fp), r_i = sum_d
 * r_(d,i) and z_i = sum_d z_(d,i) (4 zk_addp each), w (zk_fp_bind), o_i =
 * r_i^2 + z_i mod p (zk_mulp, zk_addp, 3 zk_eq to the inputs), b_i = r_i w +
 * (p + 1) / 2 mod p (zk_mulp, zk_addp) and 11 salts (full Fr, no range).
 * w = (2c)^-1 mod p with c^2 = v is formed by the verifier. With I_F = F 2^40
 * + j 2^20: output d - 1 is C^r_(d,i) = H(ZK_CD_TAG, [sr_d, K, I_7, d, i,
 * r_(d,i)], 8), output 5 + d - 1 is C^z_(d,i) = H(ZK_CD_TAG, [sz_d, K, I_8,
 * d, i, z_(d,i)], 8) and output 10 is Cb_(i,j) = H(ZK_CB_TAG, [sb, K, I_6 + vid,
 * i, b_i], 7). zk_gbit_fill: RS the limbs of r_(d,i) at 3 (d - 1), ZS the
 * limbs of z_(d,i) at 3 (d - 1), W the limbs of w, SALT the r salts 0 .. 4,
 * the zero salts 5 .. 9 and the bit salt 10. */
uint32_t zk_gbit_weights(void);
void zk_gbit(ZkCircuit *c);
void zk_gbit_fill(ZkFr *wt, const ZkFr rs[15], const ZkFr zs[15], const ZkFr w[3], const ZkFr salt[11]);

/* D65 G4 gopen (one party i, one opened share of one KSK or cast KSK row (j,
 * l); the GLWE families follow below; any other FAM gives weights 0 and
 * ZK_ERR_COUNT). share_i = g_l x_i + sum_k a_k S_i[k] + sum_d N_d(i) mod p,
 * g_l = 2^(64 - 4 l), l = 1 .. 4. Inputs: K (0), j (1), i (2, zk_party),
 * share_i (3 .. 5, low limb first) and a_0 .. a_917 (6 .. 923; the verifier
 * ranges them). The weights hold S_i (918 x 3 limbs, not ranged: C5), x_i
 * (3), the 5 noise shares N_d(i) (3 each), the zk_tdec_reduce block (919
 * coordinates: the 918 mask terms, then g_l x_i as one more term with mask
 * g_l and hi limb 0; b_d = 1), the 5 noise salts and, keys 1 only, the 919
 * key salts. The reduced V is bound to share_i by 3 EQ. With I = F 2^40 +
 * (l - 1) 2^20 + j 2^22 (F 1 KSK, 4 cast; R = 4 j + l - 1), output d - 1 is
 * C_(d,i) = H(ZK_CD_TAG, [sigma_d, K, I, d, i, N_d(i) limbs], 8). Keys 1
 * adds output 5 + k, Cb_(i,k) = H(ZK_CB_TAG, [sb_k, K, 6 2^40 + k 2^20, i,
 * S_i[k] limbs], 7), and output 923, the Cb of x_i with the index 6 2^40 +
 * j 2^20 + v (v 1 KSK glwe_i[j], v 2 cast pke_i[j]). The fill takes the mask
 * words A, the limbs S, X and NZ (N_d(i) at 3 (d - 1)), the limbs V of
 * share_i and the salts (5, then keys 1 the 919 key salts). */
/* RESUME13 adds the GLWE families BSK row 0, BSK row 1 and pk (keys 0
 * only, C6). L is then the coefficient C (0 .. 2047, a shape constant,
 * C4) and share_i = M_i + sum_(t <= C) a_t S_i[C - t] - sum_(t > C) a_t
 * S_i[C - t + N] + sum_d N_d(i) mod p, N = 2048. Inputs: K (0), g (1, the
 * GGSW index; 0 for pk), i (2, zk_party), share_i (3 .. 5) and a_0 ..
 * a_2047 (6 .. 2053). The weights hold S_i (2048 x 3; the GLWE key for
 * BSK, the reversed pke key for pk), x = lwe_i[g] (3, BSK only), N_d(i)
 * (15), the zk_mulp block (BSK row 0 only, r = x S_i[C] mod p), the 2
 * zk_tdec_reduce blocks U (t <= C and the noise, b_d = 1) and W (t > C,
 * b_d = 0), the zk_addp block (share_i + W = U mod p, 3 EQ) and the 5
 * noise salts. U and W each end with one M slot of mask 2^41 or 0: U
 * holds 2^41 x for BSK row 1 at C = 0, W holds 2^41 r for BSK row 0 (C3).
 * I = F 2^40 + (2 g + row) 2^20 + C (F 2 BSK, 3 pk; row 0 for pk). The
 * fill takes V as the limbs of share_i, U, W and (BSK row 0) r, 3 each. */
/* Squash GGSW rows 0, 1 and 2 (RESUME14): L = (level - 1) ZK_GOPEN_GN + C. */
enum { ZK_GOPEN_KSK, ZK_GOPEN_CAST, ZK_GOPEN_BSK0, ZK_GOPEN_BSK1, ZK_GOPEN_PK, ZK_GOPEN_SQ0, ZK_GOPEN_SQ1, ZK_GOPEN_SQ2 };
enum { ZK_GOPEN_N = 918, ZK_GOPEN_GN = 2048 };
uint32_t zk_gopen_weights(uint32_t fam, uint32_t l, uint32_t keys);
void zk_gopen(ZkCircuit *c, uint32_t fam, uint32_t l, uint32_t keys);
void zk_gopen_fill(ZkFr *wt, uint32_t fam, uint32_t l, uint32_t keys, const uint64_t *a, const uint64_t *s,
                   const uint64_t x[3], const uint64_t nz[15], const uint64_t *v, const ZkFr *salt);

#endif
