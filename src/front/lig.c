/* S7 L2 (the Ligero back end): the constraints of a ZkCircuit, the prover, the
 * verifier and the proof bytes. lig.h gives the protocol. */
#include "front/lig.h"

#include <stdlib.h>
#include <string.h>

#include "front/fr.h"
#include "front/merkle.h"
#include "front/ntt.h"
#include "front/sha512.h"

enum {
  FR_BYTES = 32,
  HEAD_BYTES = 16,           /* the words version, log k, rows, columns */
  Q_PARTS = 5,               /* q0 has k coefficients; q1 and q2 have 2 k each */
  MASKS = LIG_COL_EXTRA - 1, /* the mask rows u0, m1 and m2 of a column; the salt is the last element */
  STREAM_BYTES = 9,
  DOM_PROX = 0, /* the challenge streams under the root seed */
  DOM_LIN = 1,
  DOM_QUAD = 2,
  DOM_COL = 3,  /* the column stream under the column seed */
  DOM_FREE = 4, /* the prover streams under the random key: the free values of the witness rows */
  DOM_U0 = 5,   /* the coefficients of the q0 mask */
  DOM_M1 = 6,   /* the coefficients of the q1 mask */
  DOM_M2 = 7,   /* the free values, then the b coefficients, of the q2 mask */
  DOM_SALT = 8  /* the salt of each column */
};

/* The transcript tags. The hash takes the final 0 byte too. */
static const char TAG_ROOT[] = "charter-lang ligero 1 root";
static const char TAG_COLS[] = "charter-lang ligero 1 columns";
static const char TAG_RAND[] = "charter-lig-rand";

const char *lig_err_text(LigErr e) {
  switch (e) {
    case LIG_OK: return "ok";
    case LIG_ERR_MEMORY: return "an allocation failed";
    case LIG_ERR_CIRCUIT: return "the circuit is not valid";
    case LIG_ERR_REFUSED: return "the circuit is refused";
    case LIG_ERR_WITNESS: return "the witness does not agree with the circuit";
    case LIG_ERR_UNSAT: return "an eq does not hold for the witness";
    case LIG_ERR_INSTANCE: return "the public values do not agree with the circuit";
    case LIG_ERR_FORMAT: return "the proof bytes are not valid";
    case LIG_ERR_MERKLE: return "the open columns do not give the root";
    case LIG_ERR_PROXIMITY: return "the proximity test fails at an open column";
    case LIG_ERR_LINEAR_SUM: return "the linear test sum is wrong";
    case LIG_ERR_LINEAR: return "the linear test fails at an open column";
    case LIG_ERR_QUAD_ZERO: return "the quadratic test polynomial is not 0 on H";
    case LIG_ERR_QUAD: return "the quadratic test fails at an open column";
  }
  return "an unknown error";
}

static void u32_put(uint32_t v, uint8_t *out) {
  out[0] = (uint8_t)v;
  out[1] = (uint8_t)(v >> 8);
  out[2] = (uint8_t)(v >> 16);
  out[3] = (uint8_t)(v >> 24);
}

static uint32_t u32_get(const uint8_t *in) {
  return (uint32_t)in[0] | (uint32_t)in[1] << 8 | (uint32_t)in[2] << 16 | (uint32_t)in[3] << 24;
}

static void fr_put(const ZkFr *a, uint8_t *out) {
  unsigned i;
  for (i = 0; i < ZK_LIMBS; i++) u32_put(a->limb[i], out + 4 * i);
}

/* *A = the 32 bytes IN. 1 when the element is canonical. */
static int fr_get(const uint8_t *in, ZkFr *a) {
  unsigned i;
  for (i = 0; i < ZK_LIMBS; i++) a->limb[i] = u32_get(in + 4 * i);
  return zk_canonical(a);
}

static int fr_eq(const ZkFr *a, const ZkFr *b) { return memcmp(a->limb, b->limb, sizeof a->limb) == 0; }

static void add_to(ZkFr *a, const ZkFr *s) { *a = zk_fr_add(a, s); }

static void sub_from(ZkFr *a, const ZkFr *s) { *a = zk_fr_sub(a, s); }

/* *ACC += S V. */
static void add_scaled(ZkFr *acc, const ZkFr *s, const ZkFr *v) {
  const ZkFr t = zk_fr_mul(s, v);
  *acc = zk_fr_add(acc, &t);
}

static void hash_u32(Sha512 *s, uint32_t v) {
  uint8_t b[4];
  u32_put(v, b);
  sha512_update(s, b, sizeof b);
}

static void hash_frs(Sha512 *s, const ZkFr *a, uint32_t count) {
  uint8_t b[FR_BYTES];
  uint32_t i;
  for (i = 0; i < count; i++) {
    fr_put(&a[i], b);
    sha512_update(s, b, sizeof b);
  }
}

/* D = SHA-512(SEED || DOM || AT), AT as 8 bytes, low byte first. */
static void stream(const uint8_t seed[SHA512_BYTES], uint8_t dom, uint64_t at, uint8_t d[SHA512_BYTES]) {
  uint8_t in[STREAM_BYTES];
  unsigned i;
  Sha512 s;
  in[0] = dom;
  for (i = 0; i < 8; i++) in[1 + i] = (uint8_t)(at >> (8 * i));
  sha512_init(&s);
  sha512_update(&s, seed, SHA512_BYTES);
  sha512_update(&s, in, sizeof in);
  sha512_final(&s, d);
}

/* Element AT of stream DOM: the 64 hash bytes as one integer (low byte first)
 * mod r, from its four 128-bit parts (each part is canonical). The bias is
 * below 2^-250. */
static ZkFr challenge(const uint8_t seed[SHA512_BYTES], uint8_t dom, uint64_t at) {
  uint8_t d[SHA512_BYTES];
  ZkFr base = zk_fr_u64(0), acc = zk_fr_u64(0);
  unsigned part, i;
  stream(seed, dom, at, d);
  base.limb[4] = 1; /* 2^128 */
  for (part = 4; part > 0; part--) {
    ZkFr c = zk_fr_u64(0);
    for (i = 0; i < 4; i++) c.limb[i] = u32_get(d + 16 * (part - 1) + 4 * i);
    acc = zk_fr_mul(&acc, &base);
    acc = zk_fr_add(&acc, &c);
  }
  return acc;
}

/* One instruction. */
typedef struct Step {
  uint32_t tag;
  uint32_t a, b;
  const uint32_t *konst; /* the ZK_LIMBS words of a const */
} Step;

/* Reads the instruction at *PC into S and moves *PC after it. AT is the count
 * of the values before the instruction. 0 when the code is not valid. */
static int step(const ZkCircuit *c, size_t *pc, uint32_t at, Step *s) {
  const uint32_t *code = c->code.word;
  size_t len = 3;
  if (*pc >= c->code.count) return 0;
  s->tag = code[*pc];
  if (s->tag == ZK_CONST) len = 1 + ZK_LIMBS;
  if (c->code.count - *pc < len) return 0;
  s->konst = &code[*pc + 1];
  s->a = code[*pc + 1];
  s->b = code[*pc + 2];
  *pc += len;
  switch (s->tag) {
    case ZK_CONST:
    case ZK_REFUSE:
      return 1;
    case ZK_ADD:
    case ZK_SUB:
    case ZK_MUL:
    case ZK_EQ:
      return s->a < at && s->b < at;
    case ZK_OUT:
      return s->a < c->outputs;
  }
  return 0;
}

LigErr lig_params(const ZkCircuit *c, LigParams *p) {
  size_t pc = 0;
  uint64_t best = UINT64_MAX;
  uint32_t at, i, muls = 0;
  unsigned log;
  Step s;
  memset(p, 0, sizeof *p);
  if (c->err == ZK_ERR_REFUSED) return LIG_ERR_REFUSED;
  if (c->err != ZK_OK || c->vals == 0 || c->vals > ZK_VALUES_MAX) return LIG_ERR_CIRCUIT;
  if ((uint64_t)c->inputs + c->weights > c->vals) return LIG_ERR_CIRCUIT;
  at = c->inputs + c->weights;
  for (i = 0; i < c->instrs; i++) {
    if (!step(c, &pc, at, &s)) return LIG_ERR_CIRCUIT;
    if (s.tag == ZK_REFUSE) return LIG_ERR_REFUSED;
    if (s.tag == ZK_CONST) {
      ZkFr k;
      memcpy(k.limb, s.konst, sizeof k.limb);
      if (!zk_canonical(&k)) return LIG_ERR_CIRCUIT;
    }
    if (s.tag == ZK_MUL) muls++;
    if (s.tag != ZK_EQ) {
      if (at == c->vals) return LIG_ERR_CIRCUIT;
      at++;
    }
  }
  if (pc != c->code.count || at != c->vals) return LIG_ERR_CIRCUIT;
  for (log = LIG_LOG_K_MIN; log <= LIG_LOG_K_MAX; log++) {
    const uint64_t k = (uint64_t)1 << log, l = k - LIG_COLUMNS;
    const uint64_t vr = (c->vals + l - 1) / l, tr = (muls + l - 1) / l;
    const uint64_t cost = Q_PARTS * k + LIG_COLUMNS * (vr + 3 * tr);
    if (cost < best) {
      best = cost;
      p->log_k = log;
      p->k = (uint32_t)k;
      p->l = (uint32_t)l;
      p->n = (uint32_t)(k << LIG_RATE_LOG);
      p->muls = muls;
      p->vrows = (uint32_t)vr;
      p->trows = (uint32_t)tr;
      p->rows = (uint32_t)(vr + 3 * tr);
    }
  }
  return LIG_OK;
}

uint64_t lig_at_value(const LigParams *p, uint32_t v) {
  (void)p;
  return v;
}

uint64_t lig_at_x(const LigParams *p, uint32_t t) { return (uint64_t)p->vrows * p->l + t; }

uint64_t lig_at_y(const LigParams *p, uint32_t t) { return (uint64_t)(p->vrows + p->trows) * p->l + t; }

uint64_t lig_at_z(const LigParams *p, uint32_t t) { return ((uint64_t)p->vrows + 2 * (uint64_t)p->trows) * p->l + t; }

/* A x B zeroed items of SIZE bytes; NULL when the size overflows. */
static void *alloc(uint64_t a, uint64_t b, size_t size) {
  if (a == 0 || b == 0) return calloc(1, size);
  if (a > SIZE_MAX / b || a * b > SIZE_MAX / size) return NULL;
  return calloc((size_t)(a * b), size);
}

/* E (rows x l, zero on entry) = the witness rows of C and W: each value, then
 * the x, y and z of each mul. lig_params and zk_check come first, so the code
 * and the witness counts are valid. */
static void fill(const ZkCircuit *c, const ZkWitness *w, const LigParams *p, ZkFr *e) {
  ZkFr *x = e + lig_at_x(p, 0), *y = e + lig_at_y(p, 0), *z = e + lig_at_z(p, 0);
  size_t pc = 0;
  uint32_t at = 0, i, t = 0;
  Step s;
  for (i = 0; i < c->inputs; i++) e[at++] = w->input[i];
  for (i = 0; i < w->maps; i++) {
    const ZkMatrix *m = &w->matrix[w->map[i]];
    const uint64_t entries = (uint64_t)m->rows * m->cols;
    uint64_t j;
    for (j = 0; j < entries; j++) e[at++] = m->entry[j];
  }
  for (i = 0; i < c->instrs; i++) {
    if (!step(c, &pc, at, &s)) return;
    switch (s.tag) {
      case ZK_CONST:
        memcpy(e[at].limb, s.konst, sizeof e[at].limb);
        break;
      case ZK_ADD:
        e[at] = zk_fr_add(&e[s.a], &e[s.b]);
        break;
      case ZK_SUB:
        e[at] = zk_fr_sub(&e[s.a], &e[s.b]);
        break;
      case ZK_MUL:
        e[at] = zk_fr_mul(&e[s.a], &e[s.b]);
        x[t] = e[s.a];
        y[t] = e[s.b];
        z[t] = e[at];
        t++;
        break;
      case ZK_OUT:
        e[at] = w->output[s.a];
        break;
    }
    if (s.tag != ZK_EQ) at++;
  }
}

/* R (rows x l, zero on entry) = s^T A and *RHS = s^T b for s_c =
 * SIGMA^(c + 1), c the number of the linear row from 0. The powers start at
 * SIGMA^1: q1 has a mask, and a mask with a sum over H that is not 0 hides a
 * false row with the weight SIGMA^0. The rows, in order: one for each input,
 * then for each instruction one row (three for a mul: x, y, z). */
static void linear(const ZkCircuit *c, const LigParams *p, const ZkFr *input, const ZkFr *output, const ZkFr *sigma,
                   ZkFr *r, ZkFr *rhs) {
  ZkFr *x = r + lig_at_x(p, 0), *y = r + lig_at_y(p, 0), *z = r + lig_at_z(p, 0);
  ZkFr s = *sigma, k;
  size_t pc = 0;
  uint32_t at = 0, i, t = 0;
  Step st;
  *rhs = zk_fr_u64(0);
  for (i = 0; i < c->inputs; i++) {
    add_to(&r[at], &s);
    add_scaled(rhs, &s, &input[i]);
    s = zk_fr_mul(&s, sigma);
    at++;
  }
  at += c->weights;
  for (i = 0; i < c->instrs; i++) {
    if (!step(c, &pc, at, &st)) return;
    switch (st.tag) {
      case ZK_CONST:
        memcpy(k.limb, st.konst, sizeof k.limb);
        add_to(&r[at], &s);
        add_scaled(rhs, &s, &k);
        break;
      case ZK_ADD:
        add_to(&r[at], &s);
        sub_from(&r[st.a], &s);
        sub_from(&r[st.b], &s);
        break;
      case ZK_SUB:
        add_to(&r[at], &s);
        sub_from(&r[st.a], &s);
        add_to(&r[st.b], &s);
        break;
      case ZK_MUL:
        add_to(&x[t], &s);
        sub_from(&r[st.a], &s);
        s = zk_fr_mul(&s, sigma);
        add_to(&y[t], &s);
        sub_from(&r[st.b], &s);
        s = zk_fr_mul(&s, sigma);
        add_to(&z[t], &s);
        sub_from(&r[at], &s);
        t++;
        break;
      case ZK_OUT:
        add_to(&r[at], &s);
        add_scaled(rhs, &s, &output[st.a]);
        break;
      case ZK_EQ:
        add_to(&r[st.a], &s);
        sub_from(&r[st.b], &s);
        break;
    }
    s = zk_fr_mul(&s, sigma);
    if (st.tag != ZK_EQ) at++;
  }
}

static void circuit_digest(const ZkCircuit *c, uint8_t d[SHA512_BYTES]) {
  size_t i;
  Sha512 s;
  sha512_init(&s);
  hash_u32(&s, c->inputs);
  hash_u32(&s, c->weights);
  hash_u32(&s, c->outputs);
  hash_u32(&s, c->vals);
  hash_u32(&s, c->instrs);
  for (i = 0; i < c->code.count; i++) hash_u32(&s, c->code.word[i]);
  sha512_final(&s, d);
}

/* SEED = the hash of the tag, the sizes, the circuit, the public values and
 * the root: the seed of the r, sigma and rho challenges. */
/* The view copies the root seed: its size in lig.h is the SHA-512 size. */
typedef char lig_root_seed_size[LIG_ROOT_SEED_BYTES == SHA512_BYTES ? 1 : -1];

static void seed_root(const ZkCircuit *c, const LigParams *p, const ZkFr *input, const ZkFr *output,
                      const uint8_t *root, uint8_t seed[SHA512_BYTES]) {
  uint8_t d[SHA512_BYTES];
  Sha512 s;
  circuit_digest(c, d);
  sha512_init(&s);
  sha512_update(&s, (const uint8_t *)TAG_ROOT, sizeof TAG_ROOT);
  hash_u32(&s, LIG_VERSION);
  hash_u32(&s, p->log_k);
  hash_u32(&s, p->l);
  hash_u32(&s, p->n);
  hash_u32(&s, p->vrows);
  hash_u32(&s, p->trows);
  hash_u32(&s, LIG_COLUMNS);
  sha512_update(&s, d, sizeof d);
  hash_u32(&s, c->inputs);
  hash_frs(&s, input, c->inputs);
  hash_u32(&s, c->outputs);
  hash_frs(&s, output, c->outputs);
  sha512_update(&s, root, ZK_MERKLE_BYTES);
  sha512_final(&s, seed);
}

/* SEED = the hash of the tag, the root seed and the bytes of q0, q1 and q2:
 * the seed of the open columns. */
static void seed_cols(const uint8_t root_seed[SHA512_BYTES], const uint8_t *q, size_t bytes,
                      uint8_t seed[SHA512_BYTES]) {
  Sha512 s;
  sha512_init(&s);
  sha512_update(&s, (const uint8_t *)TAG_COLS, sizeof TAG_COLS);
  sha512_update(&s, root_seed, SHA512_BYTES);
  sha512_update(&s, q, bytes);
  sha512_final(&s, seed);
}

/* KEY = the hash of the tag, the caller seed ENTROPY, the circuit, the public
 * values and each witness row value EXT: the key of the random values of the
 * prover (Q-L4). The witness is in the hash, so one seed with two witnesses
 * gives two streams. */
static void seed_rand(const ZkCircuit *c, const LigParams *p, const ZkWitness *w, const uint8_t *entropy,
                      const ZkFr *ext, uint8_t key[SHA512_BYTES]) {
  uint8_t d[SHA512_BYTES];
  uint32_t r;
  Sha512 s;
  circuit_digest(c, d);
  sha512_init(&s);
  sha512_update(&s, (const uint8_t *)TAG_RAND, sizeof TAG_RAND);
  sha512_update(&s, entropy, LIG_SEED_BYTES);
  sha512_update(&s, d, sizeof d);
  hash_frs(&s, w->input, c->inputs);
  hash_frs(&s, w->output, c->outputs);
  for (r = 0; r < p->rows; r++) hash_frs(&s, ext + (size_t)r * p->l, p->l);
  sha512_final(&s, key);
}

/* IDX = LIG_COLUMNS different columns below n, in increasing order: the
 * 32-bit words of the column stream mod n (n is a power of 2), a column that
 * is there already is skipped. */
static LigErr columns(const uint8_t seed[SHA512_BYTES], const LigParams *p, uint32_t *idx) {
  unsigned char *seen = calloc(p->n, 1);
  uint8_t d[SHA512_BYTES];
  uint64_t at = 0;
  uint32_t count = 0, j;
  unsigned i;
  if (seen == NULL) return LIG_ERR_MEMORY;
  while (count < LIG_COLUMNS) {
    stream(seed, DOM_COL, at++, d);
    for (i = 0; i < SHA512_BYTES / 4 && count < LIG_COLUMNS; i++) {
      j = u32_get(d + 4 * i) & (p->n - 1);
      count += !seen[j];
      seen[j] = 1;
    }
  }
  count = 0;
  for (j = 0; j < p->n; j++) {
    if (seen[j]) idx[count++] = j;
  }
  free(seen);
  return LIG_OK;
}

/* The byte offsets in a proof: q0, the open columns, the hash count, the hashes. */
typedef struct Layout {
  size_t q, col, cnt, sib;
} Layout;

static Layout layout(const LigParams *p) {
  Layout a;
  a.q = HEAD_BYTES + ZK_MERKLE_BYTES;
  a.col = a.q + (size_t)Q_PARTS * p->k * FR_BYTES;
  a.cnt = a.col + (size_t)LIG_COLUMNS * ((size_t)p->rows + LIG_COL_EXTRA) * FR_BYTES;
  a.sib = a.cnt + 4;
  return a;
}

/* BUF (k entries) = the coefficients of the polynomial with the l values ROW,
 * then 0, on H. */
static void row_poly(const ZkFr *row, const LigParams *p, ZkFr *buf) {
  memcpy(buf, row, p->l * sizeof *buf);
  memset(buf + p->l, 0, (p->k - p->l) * sizeof *buf);
  (void)zk_intt(buf, p->log_k);
}

/* BUF (k entries) = the coefficients of the polynomial with the l values ROW,
 * then the k - l random free values of witness row R under KEY, on H. */
static void wit_poly(const ZkFr *row, const LigParams *p, const uint8_t *key, uint32_t r, ZkFr *buf) {
  const uint32_t open = p->k - p->l;
  uint32_t i;
  memcpy(buf, row, p->l * sizeof *buf);
  for (i = 0; i < open; i++) buf[p->l + i] = challenge(key, DOM_FREE, (uint64_t)r * open + i);
  (void)zk_intt(buf, p->log_k);
}

/* MASK (5 k coefficients, in the layout of q0, q1 and q2) = the three mask
 * polynomials under KEY (Q-L5). u0: k random coefficients. m1: 2 k random
 * coefficients, then coefficient k = -(coefficient 0), so the sum over H,
 * k (c_0 + c_k), is 0. m2 = a + (X^k - 1) b: a is 0 on the first l points of
 * H and random on the free points, and b has k random coefficients; m2 is 0
 * on the first l points of H (the low k coefficients are a - b, the high k
 * are b). */
static void mask_polys(const LigParams *p, const uint8_t *key, ZkFr *mask) {
  const size_t k = p->k, k2 = 2 * k, open = p->k - p->l;
  const ZkFr zero = zk_fr_u64(0);
  ZkFr *u0 = mask, *m1 = u0 + k, *m2 = m1 + k2;
  size_t j;
  for (j = 0; j < k; j++) u0[j] = challenge(key, DOM_U0, j);
  for (j = 0; j < k2; j++) m1[j] = challenge(key, DOM_M1, j);
  m1[k] = zk_fr_sub(&zero, &m1[0]);
  memset(m2, 0, p->l * sizeof *m2);
  for (j = 0; j < open; j++) m2[p->l + j] = challenge(key, DOM_M2, j);
  (void)zk_intt(m2, p->log_k);
  for (j = 0; j < k; j++) {
    const ZkFr b = challenge(key, DOM_M2, open + j);
    m2[k + j] = b;
    sub_from(&m2[j], &b);
  }
}

/* DST (2 k entries) = the values of the k coefficients SRC on the 2 k-th
 * roots of unity. */
static void eval2k(const ZkFr *src, const LigParams *p, ZkFr *dst) {
  memcpy(dst, src, p->k * sizeof *dst);
  memset(dst + p->k, 0, p->k * sizeof *dst);
  (void)zk_ntt(dst, p->log_k + 1);
}

typedef struct Prover {
  ZkFr *ext;   /* rows x l: the witness rows */
  ZkFr *poly;  /* rows x k: the row polynomials */
  ZkFr *code;  /* rows x n: the codewords */
  ZkFr *lin;   /* rows x l: s^T A */
  ZkFr *q;     /* 5 k: q0, q1, q2 */
  ZkFr *mask;  /* 5 k: the coefficients of u0, m1, m2 */
  ZkFr *mcode; /* 3 x n: the mask codewords */
  ZkFr *salt;  /* n: the salt of each column */
  ZkFr *tmp;   /* 3 x 2 k */
  ZkFr *col;   /* rows + 4: one column */
  uint8_t *leaf;
  uint32_t *idx;
  uint8_t *out;
  ZkMerkle tree;
} Prover;

static void prover_free(Prover *st) {
  free(st->ext);
  free(st->poly);
  free(st->code);
  free(st->lin);
  free(st->q);
  free(st->mask);
  free(st->mcode);
  free(st->salt);
  free(st->tmp);
  free(st->col);
  free(st->leaf);
  free(st->idx);
  free(st->out);
  if (st->tree.node != NULL) zk_merkle_free(&st->tree);
}

/* Q = q0 (k coefficients), q1 and q2 (2 k each) under the root seed SEED,
 * each with its mask: q0 += u0, q1 += m1, q2 += m2 (coefficients). */
static void test_polys(const ZkCircuit *c, const ZkWitness *w, const LigParams *p, Prover *st, const uint8_t *seed) {
  const size_t k = p->k, k2 = 2 * k;
  const ZkFr sigma = challenge(seed, DOM_LIN, 0);
  ZkFr *q0 = st->q, *q1 = q0 + k, *q2 = q1 + k2;
  ZkFr *a = st->tmp, *b = a + k2, *z = b + k2;
  ZkFr rhs;
  size_t j;
  uint32_t i;
  for (i = 0; i < p->rows; i++) {
    const ZkFr r = challenge(seed, DOM_PROX, i);
    const ZkFr *pi = st->poly + (size_t)i * k;
    for (j = 0; j < k; j++) add_scaled(&q0[j], &r, &pi[j]);
  }
  linear(c, p, w->input, w->output, &sigma, st->lin, &rhs);
  for (i = 0; i < p->rows; i++) {
    row_poly(st->lin + (size_t)i * p->l, p, z);
    eval2k(z, p, a);
    eval2k(st->poly + (size_t)i * k, p, b);
    for (j = 0; j < k2; j++) add_scaled(&q1[j], &a[j], &b[j]);
  }
  (void)zk_intt(q1, p->log_k + 1);
  for (i = 0; i < p->trows; i++) {
    const ZkFr rho = challenge(seed, DOM_QUAD, i);
    eval2k(st->poly + (size_t)(p->vrows + i) * k, p, a);
    eval2k(st->poly + (size_t)(p->vrows + p->trows + i) * k, p, b);
    eval2k(st->poly + (size_t)(p->vrows + 2 * p->trows + i) * k, p, z);
    for (j = 0; j < k2; j++) {
      ZkFr t = zk_fr_mul(&a[j], &b[j]);
      t = zk_fr_sub(&t, &z[j]);
      add_scaled(&q2[j], &rho, &t);
    }
  }
  (void)zk_intt(q2, p->log_k + 1);
  for (j = 0; j < Q_PARTS * k; j++) add_to(&st->q[j], &st->mask[j]);
}

static LigErr prove_run(const ZkCircuit *c, const ZkWitness *w, const LigParams *p, const uint8_t *entropy,
                        const uint64_t *tweak, size_t tweaks, const LigBend *b, Prover *st, LigView *view,
                        LigProof *out) {
  const Layout at = layout(p);
  const unsigned log_n = p->log_k + LIG_RATE_LOG;
  const size_t k = p->k, n = p->n, cells = (size_t)p->rows * p->l, len = (size_t)p->rows + LIG_COL_EXTRA;
  const ZkFr one = zk_fr_u64(1);
  uint8_t seed[SHA512_BYTES], seed2[SHA512_BYTES], rkey[SHA512_BYTES];
  size_t hashes = 0, i, j;
  uint32_t r;
  LigErr e;
  st->ext = alloc(p->rows, p->l, sizeof *st->ext);
  st->poly = alloc(p->rows, k, sizeof *st->poly);
  st->code = alloc(p->rows, n, sizeof *st->code);
  st->lin = alloc(p->rows, p->l, sizeof *st->lin);
  st->q = alloc(Q_PARTS, k, sizeof *st->q);
  st->tmp = alloc(6, k, sizeof *st->tmp);
  st->mask = alloc(Q_PARTS, k, sizeof *st->mask);
  st->mcode = alloc(MASKS, n, sizeof *st->mcode);
  st->salt = alloc(n, 1, sizeof *st->salt);
  st->col = alloc(len, 1, sizeof *st->col);
  st->leaf = alloc(n, ZK_MERKLE_BYTES, 1);
  st->idx = alloc(LIG_COLUMNS, 1, sizeof *st->idx);
  st->out = alloc(at.sib + (size_t)LIG_COLUMNS * log_n * ZK_MERKLE_BYTES, 1, 1);
  if (st->ext == NULL || st->poly == NULL || st->code == NULL || st->lin == NULL || st->q == NULL) return LIG_ERR_MEMORY;
  if (st->tmp == NULL || st->col == NULL || st->leaf == NULL || st->idx == NULL || st->out == NULL) return LIG_ERR_MEMORY;
  if (st->mask == NULL || st->mcode == NULL || st->salt == NULL) return LIG_ERR_MEMORY;
  fill(c, w, p, st->ext);
  for (i = 0; i < tweaks; i++) {
    if (tweak[i] >= cells) return LIG_ERR_WITNESS;
    add_to(&st->ext[tweak[i]], &one);
  }
  seed_rand(c, p, w, entropy, st->ext, rkey);
  /* The row polynomials and the codewords. */
  for (r = 0; r < p->rows; r++) {
    ZkFr *pr = st->poly + (size_t)r * k, *ur = st->code + (size_t)r * n;
    wit_poly(st->ext + (size_t)r * p->l, p, rkey, r, pr);
    memcpy(ur, pr, k * sizeof *ur);
    (void)zk_coset_ntt(ur, log_n);
  }
  /* The mask polynomials and their codewords: u0 has k coefficients, m1 and
   * m2 have 2 k each (n = 4 k). */
  mask_polys(p, rkey, st->mask);
  if (b != NULL && b->m1_add != NULL) add_to(&st->mask[k], b->m1_add);
  memcpy(st->mcode, st->mask, k * sizeof *st->mcode);
  memcpy(st->mcode + n, st->mask + k, 2 * k * sizeof *st->mcode);
  memcpy(st->mcode + 2 * n, st->mask + 3 * k, 2 * k * sizeof *st->mcode);
  for (i = 0; i < MASKS; i++) (void)zk_coset_ntt(st->mcode + i * n, log_n);
  /* The column commitment: the witness rows, the masks, then the salt. */
  for (j = 0; j < n; j++) {
    for (r = 0; r < p->rows; r++) st->col[r] = st->code[(size_t)r * n + j];
    for (i = 0; i < MASKS; i++) st->col[p->rows + i] = st->mcode[i * n + j];
    st->salt[j] = challenge(rkey, DOM_SALT, j);
    st->col[len - 1] = st->salt[j];
    zk_merkle_leaf(st->col, p->rows + LIG_COL_EXTRA, st->leaf + j * ZK_MERKLE_BYTES);
  }
  if (zk_merkle_build(&st->tree, log_n, st->leaf) != ZK_OK) {
    st->tree.node = NULL;
    return LIG_ERR_MEMORY;
  }
  seed_root(c, p, w->input, w->output, zk_merkle_root(&st->tree), seed);
  test_polys(c, w, p, st, seed);
  for (i = 0; b != NULL && i < b->q_adds; i++) {
    if (b->q_at[i] >= Q_PARTS * k) return LIG_ERR_WITNESS;
    add_to(&st->q[b->q_at[i]], &b->q_add[i]);
  }
  /* The proof bytes. */
  u32_put(LIG_VERSION, st->out);
  u32_put(p->log_k, st->out + 4);
  u32_put(p->rows, st->out + 8);
  u32_put(LIG_COLUMNS, st->out + 12);
  memcpy(st->out + HEAD_BYTES, zk_merkle_root(&st->tree), ZK_MERKLE_BYTES);
  for (i = 0; i < Q_PARTS * k; i++) fr_put(&st->q[i], st->out + at.q + i * FR_BYTES);
  seed_cols(seed, st->out + at.q, at.col - at.q, seed2);
  e = columns(seed2, p, st->idx);
  if (e != LIG_OK) return e;
  for (i = 0; i < LIG_COLUMNS; i++) {
    uint8_t *oc = st->out + at.col + i * len * FR_BYTES;
    for (r = 0; r < p->rows; r++) fr_put(&st->code[(size_t)r * n + st->idx[i]], oc + (size_t)r * FR_BYTES);
    for (j = 0; j < MASKS; j++) fr_put(&st->mcode[j * n + st->idx[i]], oc + (p->rows + j) * FR_BYTES);
    fr_put(&st->salt[st->idx[i]], oc + (len - 1) * FR_BYTES);
  }
  if (zk_merkle_open(&st->tree, st->idx, LIG_COLUMNS, st->out + at.sib, &hashes) != ZK_OK) return LIG_ERR_MEMORY;
  u32_put((uint32_t)hashes, st->out + at.cnt);
  out->byte = st->out;
  out->count = at.sib + hashes * ZK_MERKLE_BYTES;
  st->out = NULL;
  /* The view gets the committed arrays (test_polys does not change them) and
   * the root seed. */
  if (view != NULL) {
    view->poly = st->poly;
    view->mask = st->mask;
    view->salt = st->salt;
    memcpy(view->root_seed, seed, sizeof view->root_seed);
    st->poly = NULL;
    st->mask = NULL;
    st->salt = NULL;
  }
  return LIG_OK;
}

/* The prover error for the zk_check result ZE. */
static LigErr witness_err(ZkErr ze, int forced) {
  switch (ze) {
    case ZK_OK: return LIG_OK;
    case ZK_ERR_UNSAT: return forced ? LIG_OK : LIG_ERR_UNSAT;
    case ZK_ERR_MEMORY: return LIG_ERR_MEMORY;
    case ZK_ERR_REFUSED: return LIG_ERR_REFUSED;
    case ZK_ERR_COUNT:
    case ZK_ERR_NONCANONICAL:
    case ZK_ERR_REF:
    case ZK_ERR_OUTPUT:
    case ZK_ERR_WITNESS:
    case ZK_ERR_MAP:
      return LIG_ERR_WITNESS;
  }
  return LIG_ERR_WITNESS;
}

static LigErr prove(const ZkCircuit *c, const ZkWitness *w, const uint8_t *entropy, int forced, const uint64_t *tweak,
                    size_t tweaks, const LigBend *b, LigView *view, LigProof *out) {
  LigParams p;
  Prover st;
  LigErr e = lig_params(c, &p);
  out->byte = NULL;
  out->count = 0;
  if (view != NULL) memset(view, 0, sizeof *view);
  if (e == LIG_OK) e = witness_err(zk_check(c, w), forced);
  if (e != LIG_OK) return e;
  memset(&st, 0, sizeof st);
  e = prove_run(c, w, &p, entropy, tweak, tweaks, b, &st, view, out);
  prover_free(&st);
  return e;
}

LigErr lig_prove(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES], LigProof *out) {
  return prove(c, w, seed, 0, NULL, 0, NULL, NULL, out);
}

LigErr lig_prove_forced(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES],
                        const uint64_t *tweak, size_t tweaks, LigProof *out) {
  return prove(c, w, seed, 1, tweak, tweaks, NULL, NULL, out);
}

LigErr lig_prove_bent(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES],
                      const uint64_t *tweak, size_t tweaks, const LigBend *b, LigProof *out) {
  return prove(c, w, seed, 1, tweak, tweaks, b, NULL, out);
}

LigErr lig_prove_view(const ZkCircuit *c, const ZkWitness *w, const uint8_t seed[LIG_SEED_BYTES], LigView *view,
                      LigProof *out) {
  return prove(c, w, seed, 0, NULL, 0, NULL, view, out);
}

void lig_view_free(LigView *v) {
  free(v->poly);
  free(v->mask);
  free(v->salt);
  v->poly = NULL;
  v->mask = NULL;
  v->salt = NULL;
  memset(v->root_seed, 0, sizeof v->root_seed);
}

void lig_proof_free(LigProof *p) {
  free(p->byte);
  p->byte = NULL;
  p->count = 0;
}

/* The value of the TERMS coefficients C (low degree first) at X. */
static ZkFr horner(const ZkFr *c, size_t terms, const ZkFr *x) {
  ZkFr acc = zk_fr_u64(0);
  size_t i;
  for (i = terms; i > 0; i--) {
    acc = zk_fr_mul(&acc, x);
    acc = zk_fr_add(&acc, &c[i - 1]);
  }
  return acc;
}

typedef struct Verifier {
  ZkFr *q;   /* 5 k: q0, q1, q2 */
  ZkFr *col; /* LIG_COLUMNS x (rows + 4): the open columns */
  ZkFr *lin; /* rows x l: s^T A */
  ZkFr *buf; /* n */
  ZkFr *eta; /* LIG_COLUMNS: the points of the open columns */
  ZkFr *acc; /* LIG_COLUMNS */
  uint8_t *leaf;
  uint32_t *idx;
} Verifier;

static void verifier_free(Verifier *v) {
  free(v->q);
  free(v->col);
  free(v->lin);
  free(v->buf);
  free(v->eta);
  free(v->acc);
  free(v->leaf);
  free(v->idx);
}

/* 1 when the TERMS coefficients Q give ACC[j] at each open point. */
static int agrees(const ZkFr *q, size_t terms, const Verifier *v) {
  uint32_t j;
  for (j = 0; j < LIG_COLUMNS; j++) {
    const ZkFr lhs = horner(q, terms, &v->eta[j]);
    if (!fr_eq(&lhs, &v->acc[j])) return 0;
  }
  return 1;
}

/* ACC[j] = the element AT of open column j: the open value of one mask. */
static void acc_start(const LigParams *p, Verifier *v, size_t at) {
  const size_t len = (size_t)p->rows + LIG_COL_EXTRA;
  uint32_t j;
  for (j = 0; j < LIG_COLUMNS; j++) v->acc[j] = v->col[(size_t)j * len + at];
}

/* q0 at each open point is U0_j + sum r_i U_ij (U0 is the u0 row). */
static LigErr check_prox(const LigParams *p, Verifier *v, const uint8_t *seed) {
  const size_t len = (size_t)p->rows + LIG_COL_EXTRA;
  uint32_t r, j;
  acc_start(p, v, p->rows);
  for (r = 0; r < p->rows; r++) {
    const ZkFr ch = challenge(seed, DOM_PROX, r);
    for (j = 0; j < LIG_COLUMNS; j++) add_scaled(&v->acc[j], &ch, &v->col[(size_t)j * len + r]);
  }
  return agrees(v->q, p->k, v) ? LIG_OK : LIG_ERR_PROXIMITY;
}

/* The sum of q1 over H is s^T b (the m1 row has the sum 0), and q1 at each
 * open point is M1_j + sum R_i U_ij. q1 has degree below 2 k, so its sum over
 * H is k (c_0 + c_k). */
static LigErr check_linear(const ZkCircuit *c, const LigParams *p, const ZkFr *input, const ZkFr *output,
                           Verifier *v, const uint8_t *seed) {
  const unsigned log_n = p->log_k + LIG_RATE_LOG;
  const ZkFr sigma = challenge(seed, DOM_LIN, 0), kk = zk_fr_u64(p->k);
  const ZkFr *q1 = v->q + p->k;
  const size_t len = (size_t)p->rows + LIG_COL_EXTRA;
  ZkFr rhs, sum;
  uint32_t r, j;
  linear(c, p, input, output, &sigma, v->lin, &rhs);
  sum = zk_fr_add(&q1[0], &q1[p->k]);
  sum = zk_fr_mul(&sum, &kk);
  if (!fr_eq(&sum, &rhs)) return LIG_ERR_LINEAR_SUM;
  acc_start(p, v, (size_t)p->rows + 1);
  for (r = 0; r < p->rows; r++) {
    memset(v->buf, 0, p->n * sizeof *v->buf);
    row_poly(v->lin + (size_t)r * p->l, p, v->buf);
    (void)zk_coset_ntt(v->buf, log_n);
    for (j = 0; j < LIG_COLUMNS; j++) add_scaled(&v->acc[j], &v->buf[v->idx[j]], &v->col[(size_t)j * len + r]);
  }
  return agrees(q1, 2 * (size_t)p->k, v) ? LIG_OK : LIG_ERR_LINEAR;
}

/* q2 is 0 on the first l points of H (the m2 row is 0 there), and q2 at each
 * open point is M2_j + sum rho_i (Ux_ij Uy_ij - Uz_ij). The values of q2 on H
 * are those of q2 mod X^k - 1. */
static LigErr check_quad(const LigParams *p, Verifier *v, const uint8_t *seed) {
  const ZkFr zero = zk_fr_u64(0);
  const ZkFr *q2 = v->q + 3 * (size_t)p->k;
  const size_t len = (size_t)p->rows + LIG_COL_EXTRA;
  uint32_t r, j, i;
  for (i = 0; i < p->k; i++) v->buf[i] = zk_fr_add(&q2[i], &q2[i + p->k]);
  (void)zk_ntt(v->buf, p->log_k);
  for (i = 0; i < p->l; i++) {
    if (!fr_eq(&v->buf[i], &zero)) return LIG_ERR_QUAD_ZERO;
  }
  acc_start(p, v, (size_t)p->rows + 2);
  for (r = 0; r < p->trows; r++) {
    const ZkFr rho = challenge(seed, DOM_QUAD, r);
    for (j = 0; j < LIG_COLUMNS; j++) {
      const ZkFr *cj = v->col + (size_t)j * len + p->vrows + r;
      ZkFr t = zk_fr_mul(&cj[0], &cj[p->trows]);
      t = zk_fr_sub(&t, &cj[2 * (size_t)p->trows]);
      add_scaled(&v->acc[j], &rho, &t);
    }
  }
  return agrees(q2, 2 * (size_t)p->k, v) ? LIG_OK : LIG_ERR_QUAD;
}

static LigErr verify_run(const ZkCircuit *c, const LigParams *p, const ZkFr *input, const ZkFr *output,
                         const uint8_t *proof, size_t count, Verifier *v) {
  const Layout at = layout(p);
  const unsigned log_n = p->log_k + LIG_RATE_LOG;
  const uint8_t *root = proof + HEAD_BYTES;
  const size_t len = (size_t)p->rows + LIG_COL_EXTRA, cells = (size_t)LIG_COLUMNS * len;
  const ZkFr shift = zk_fr_u64(ZK_NTT_SHIFT);
  uint8_t seed[SHA512_BYTES], seed2[SHA512_BYTES];
  uint32_t e[ZK_LIMBS] = {0};
  size_t hashes, i;
  ZkFr w;
  LigErr err;
  if (count < at.sib) return LIG_ERR_FORMAT;
  if (u32_get(proof) != LIG_VERSION || u32_get(proof + 4) != p->log_k) return LIG_ERR_FORMAT;
  if (u32_get(proof + 8) != p->rows || u32_get(proof + 12) != LIG_COLUMNS) return LIG_ERR_FORMAT;
  hashes = u32_get(proof + at.cnt);
  if (hashes > (size_t)LIG_COLUMNS * log_n || count - at.sib != hashes * ZK_MERKLE_BYTES) return LIG_ERR_FORMAT;
  v->q = alloc(Q_PARTS, p->k, sizeof *v->q);
  v->col = alloc(LIG_COLUMNS, len, sizeof *v->col);
  v->lin = alloc(p->rows, p->l, sizeof *v->lin);
  v->buf = alloc(p->n, 1, sizeof *v->buf);
  v->eta = alloc(LIG_COLUMNS, 1, sizeof *v->eta);
  v->acc = alloc(LIG_COLUMNS, 1, sizeof *v->acc);
  v->leaf = alloc(LIG_COLUMNS, ZK_MERKLE_BYTES, 1);
  v->idx = alloc(LIG_COLUMNS, 1, sizeof *v->idx);
  if (v->q == NULL || v->col == NULL || v->lin == NULL || v->buf == NULL) return LIG_ERR_MEMORY;
  if (v->eta == NULL || v->acc == NULL || v->leaf == NULL || v->idx == NULL) return LIG_ERR_MEMORY;
  for (i = 0; i < (size_t)Q_PARTS * p->k; i++) {
    if (!fr_get(proof + at.q + i * FR_BYTES, &v->q[i])) return LIG_ERR_FORMAT;
  }
  for (i = 0; i < cells; i++) {
    if (!fr_get(proof + at.col + i * FR_BYTES, &v->col[i])) return LIG_ERR_FORMAT;
  }
  seed_root(c, p, input, output, root, seed);
  seed_cols(seed, proof + at.q, at.col - at.q, seed2);
  err = columns(seed2, p, v->idx);
  if (err != LIG_OK) return err;
  for (i = 0; i < LIG_COLUMNS; i++)
    zk_merkle_leaf(v->col + i * len, p->rows + LIG_COL_EXTRA, v->leaf + i * ZK_MERKLE_BYTES);
  if (!zk_merkle_check(root, log_n, v->idx, LIG_COLUMNS, v->leaf, proof + at.sib, hashes)) return LIG_ERR_MERKLE;
  /* The point of column j is g w_n^j. */
  if (!zk_fr_root(log_n, &w)) return LIG_ERR_CIRCUIT;
  for (i = 0; i < LIG_COLUMNS; i++) {
    e[0] = v->idx[i];
    v->eta[i] = zk_fr_pow(&w, e);
    v->eta[i] = zk_fr_mul(&v->eta[i], &shift);
  }
  err = check_prox(p, v, seed);
  if (err == LIG_OK) err = check_linear(c, p, input, output, v, seed);
  if (err == LIG_OK) err = check_quad(p, v, seed);
  return err;
}

LigErr lig_verify(const ZkCircuit *c, const ZkFr *input, uint32_t inputs, const ZkFr *output, uint32_t outputs,
                  const uint8_t *proof, size_t count) {
  LigParams p;
  Verifier v;
  uint32_t i;
  LigErr e = lig_params(c, &p);
  if (e != LIG_OK) return e;
  if (inputs != c->inputs || outputs != c->outputs) return LIG_ERR_INSTANCE;
  for (i = 0; i < inputs; i++) {
    if (!zk_canonical(&input[i])) return LIG_ERR_INSTANCE;
  }
  for (i = 0; i < outputs; i++) {
    if (!zk_canonical(&output[i])) return LIG_ERR_INSTANCE;
  }
  memset(&v, 0, sizeof v);
  e = verify_run(c, &p, input, output, proof, count, &v);
  verifier_free(&v);
  return e;
}
