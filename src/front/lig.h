/* S7 L2 (the Ligero back end): the prover and the verifier for one ZkCircuit
 * (Ligero: Ames, Hazay, Ishai and Venkitasubramaniam, CCS 2017), with the
 * parameters of docs/PLAN.md Q-L1: rate 1/4 and LIG_COLUMNS open columns.
 *
 * The constraints come from one pass over the circuit code. The witness is
 * each value v, then one triple (x, y, z) for each mul. The linear rows are
 *   input i: v_i = in_i          const k: v_j = k
 *   add: v_j - v_a - v_b = 0     sub: v_j - v_a + v_b = 0
 *   mul t: x_t - v_a = 0, y_t - v_b = 0, z_t - v_j = 0
 *   out o: v_j = out_o           eq: v_a - v_b = 0
 * and the quadratic rows are x_t y_t = z_t. The public inputs and outputs are
 * only on the right side b of the linear rows, so another instance gives
 * another b.
 *
 * The witness goes into rows of l values: the v rows, then the x, y and z
 * rows. A row is the first l values of a polynomial of degree below k on
 * H = <w_k> (k = l + LIG_COLUMNS; the other k - l values are random). Its
 * codeword is the n = 4 k values on L = g <w_n>. Three mask rows follow the
 * witness rows: u0 (degree below k), m1 (degree below 2 k, the sum 0 over H)
 * and m2 (degree below 2 k, 0 on the first l points of H). A Merkle tree
 * commits to the n columns; a column is the values of the witness rows, the
 * three mask values and one random salt.
 *
 * The challenges come from SHA-512 over the circuit, the public values and
 * the root (Fiat-Shamir):
 *   q0 = u0 + sum r_i p_i (degree below k), r_i one element for each row;
 *   q1 = m1 + sum R_i p_i (degree below 2 k), R_i the row i of s^T A as a
 *        polynomial that is 0 on the free points, s_c = sigma^(c + 1) for
 *        linear row c (from 0): the sum of q1 over H is s^T b;
 *   q2 = m2 + sum rho_i (px_i py_i - pz_i) (degree below 2 k): q2 is 0 on
 *        the first l points of H.
 * The open columns come from the hash of q0, q1 and q2. The verifier checks
 * the Merkle multi-open, then each of q0, q1 and q2 against each open column.
 *
 * Soundness (Q-L1, Q-L5): (3/4)^309 + at most (C + 2) n / r + (C + 1) / r for
 * C linear rows (BCIKS20 Theorem 3.1 for q0 and q2, Theorem 1.6 for q1). The
 * powers of sigma start at sigma^1: a mask with a sum that is not 0 hides a
 * false row with the weight sigma^0.
 *
 * Zero knowledge (L3: Q-L4, Q-L5, Q-L6): the random free values hide the
 * open column values of the witness rows, and the masks hide q0, q1 and q2.
 * The salt stops a test of a witness guess against the hash of a column that
 * is not open. The random values come from SHA-512 over a caller seed of
 * LIG_SEED_BYTES bytes, the circuit, the public values and the witness. */
#ifndef CHARTER_LIG_H
#define CHARTER_LIG_H

#include <stddef.h>
#include <stdint.h>

#include "front/zk.h"

enum {
  LIG_VERSION = 2,     /* the first word of a proof (2: the masks and the salts of L3) */
  LIG_COLUMNS = 309,   /* t: the open columns (Q-L1) */
  LIG_RATE_LOG = 2,    /* n = 4 k */
  LIG_LOG_K_MIN = 9,   /* k = 512: the smallest power of 2 above t */
  LIG_LOG_K_MAX = 26,  /* n = 4 k is at most 2^28, the 2-part of r - 1 */
  LIG_SEED_BYTES = 32, /* the caller seed of the prover (Q-L4) */
  LIG_ROOT_SEED_BYTES = 64, /* the root seed (SHA-512) in the view of the tests */
  LIG_COL_EXTRA = 4    /* the column elements after the witness rows: u0, m1, m2, the salt */
};

typedef enum {
  LIG_OK,
  LIG_ERR_MEMORY,     /* an allocation failed */
  LIG_ERR_CIRCUIT,    /* the circuit holds a builder error, has no value, or its code is not valid */
  LIG_ERR_REFUSED,    /* the circuit is refused (zk_refuse) */
  LIG_ERR_WITNESS,    /* the witness does not agree with the circuit, or a tweak is out of range */
  LIG_ERR_UNSAT,      /* the prover refuses: an eq does not hold for the witness */
  LIG_ERR_INSTANCE,   /* a public value count is wrong, or a public value is not canonical */
  LIG_ERR_FORMAT,     /* the proof bytes: the length, the header or an element that is not canonical */
  LIG_ERR_MERKLE,     /* the open columns do not give the root */
  LIG_ERR_PROXIMITY,  /* q0 does not agree with an open column */
  LIG_ERR_LINEAR_SUM, /* the sum of q1 over H is not s^T b */
  LIG_ERR_LINEAR,     /* q1 does not agree with an open column */
  LIG_ERR_QUAD_ZERO,  /* q2 is not 0 on one of the first l points of H */
  LIG_ERR_QUAD        /* q2 does not agree with an open column */
} LigErr;

/* The sizes for one circuit. They depend only on the value count and the mul
 * count, so the prover and the verifier get the same sizes. */
typedef struct LigParams {
  unsigned log_k;
  uint32_t k;     /* the points of H */
  uint32_t l;     /* the witness values in a row: k - LIG_COLUMNS */
  uint32_t n;     /* the points of L, the columns: 4 k */
  uint32_t muls;  /* the mul count */
  uint32_t vrows; /* the rows of v */
  uint32_t trows; /* the rows of each of x, y and z */
  uint32_t rows;  /* vrows + 3 trows */
} LigParams;

/* The proof bytes: the words version, log k, rows and columns (low byte
 * first), the root, then q0 (k elements), q1 and q2 (2 k elements each), the
 * open columns in increasing column order (rows + LIG_COL_EXTRA elements
 * each: the witness rows, u0, m1, m2, the salt), the count of Merkle hashes,
 * and the hashes. An element is 32 bytes, low byte first. The proof owns
 * byte. */
typedef struct LigProof {
  uint8_t *byte;
  size_t count;
} LigProof;

const char *lig_err_text(LigErr e);

/* *P = the sizes for C. The k is the power of 2 in [2^9, 2^26] with the
 * smallest 5 k + LIG_COLUMNS rows (the element count of q0, q1, q2 and the
 * open columns); the smaller k wins a tie. */
LigErr lig_params(const ZkCircuit *c, LigParams *p);

/* The witness row position of value V, and of the x, y and z of mul T (for a
 * tweak of lig_prove_forced). */
uint64_t lig_at_value(const LigParams *p, uint32_t v);
uint64_t lig_at_x(const LigParams *p, uint32_t t);
uint64_t lig_at_y(const LigParams *p, uint32_t t);
uint64_t lig_at_z(const LigParams *p, uint32_t t);

/* The honest prover: *OUT = a proof that C holds for the witness W (OUT is
 * empty on entry and stays empty on an error). LIG_ERR_UNSAT when an eq does
 * not hold. SEED is LIG_SEED_BYTES bytes from the random source of the
 * caller: new for each proof, and secret. The proof bytes are a function of
 * SEED, C and W; the random values depend on W too (a hedge against a seed
 * that comes two times). */
LigErr lig_prove(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES], LigProof *out);

/* For the false-witness rows of the tests only: the same steps as
 * lig_prove, but an eq that does not hold does not stop the prover, and 1 is
 * added to each of the TWEAKS witness row positions TWEAK after the fill. */
LigErr lig_prove_forced(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES],
                        const uint64_t *tweak, size_t tweaks, LigProof *out);

/* The changes of lig_prove_bent. A position Q_AT is a coefficient of q: q0
 * is at 0, q1 at k and q2 at 3 k (5 k positions). */
typedef struct LigBend {
  const uint32_t *q_at; /* Q_ADDS positions */
  const ZkFr *q_add;    /* Q_ADDS values */
  size_t q_adds;
  const ZkFr *m1_add;   /* NULL, or a value for coefficient 0 of the mask m1 */
} LigBend;

/* For the verifier-check rows of the tests only: the steps of
 * lig_prove_forced with the changes B. M1_ADD is added to coefficient 0 of
 * the mask m1 before the column commitment, so the sum of m1 over H is k
 * times M1_ADD. Q_ADD[i] is added to coefficient Q_AT[i] of q after the
 * masks and before the column hash, so the open columns agree with the root
 * and only the test of that q can refuse. LIG_ERR_WITNESS when a position is
 * 5 k or more. */
LigErr lig_prove_bent(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES],
                      const uint64_t *tweak, size_t tweaks, const LigBend *b, LigProof *out);

/* The secret random values of one proof, for the prover-side rows of the
 * tests only: the arrays that the prover commits to. POLY: the coefficients
 * of the witness row polynomials (rows x k; the values of a row on H are its
 * l witness values, then its k - l free values). MASK: the coefficients of
 * u0 (k), m1 (2 k) and m2 (2 k). SALT: the salt of each column (n). ROOT_SEED:
 * the root seed (the hash of the circuit, the public values and the root) that
 * gives the challenges. The view owns the arrays. */
typedef struct LigView {
  ZkFr *poly;
  ZkFr *mask;
  ZkFr *salt;
  uint8_t root_seed[LIG_ROOT_SEED_BYTES];
} LigView;

/* For the prover-side rows of the tests only: the steps of lig_prove (the
 * same proof bytes for the same SEED, C and W), and *VIEW = the committed
 * arrays (VIEW is empty on an error). No verifier sees these values, and a
 * caller must not show them: they open the witness. */
LigErr lig_prove_view(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES], LigView *view,
                      LigProof *out);

void lig_view_free(LigView *v);

void lig_proof_free(LigProof *p);

/* LIG_OK when the COUNT bytes PROOF show that C holds for the public values
 * INPUT and OUTPUT. The verifier uses Fr arithmetic and SHA-512 only. */
LigErr lig_verify(const ZkCircuit *c, const ZkFr *input, uint32_t inputs, const ZkFr *output, uint32_t outputs,
                  const uint8_t *proof, size_t count);

#endif
