/* S7 U1: the ZK Circuit IR writer (front/zk.h). The checks follow the
 * printer reader (zkml-lang 968dce4 src/halo2.c: below, operand, walk,
 * mapped, stages), so an entry that zk_words writes is one that the printer
 * reads. The donor writer (zkpolicy-lang 1d263fb src/zkml.c) gives the
 * discipline: an exhaustive switch on each tag, and a refusal with no
 * partial output. */
#include "front/zk.h"
#include "front/poseidon2.h"
#include "front/sha512.h"

#include <stdlib.h>
#include <string.h>

/* The BN254 scalar field modulus r, low limb first (src/halo2.c BN254_R). */
static const uint32_t ZK_R[ZK_LIMBS] = {4026531841u, 1138881939u, 2042196113u, 674490440u,
                                        2172737629u, 3092268470u, 3778125865u, 811880050u};

ZkFr zk_fr_u64(uint64_t v) {
  ZkFr k;
  memset(&k, 0, sizeof k);
  k.limb[0] = (uint32_t)v;
  k.limb[1] = (uint32_t)(v >> 32);
  return k;
}

int zk_canonical(const ZkFr *k) {
  unsigned i;
  for (i = ZK_LIMBS; i > 0; i--)
    if (k->limb[i - 1] != ZK_R[i - 1]) return k->limb[i - 1] < ZK_R[i - 1];
  return 0;
}

const char *zk_err_text(ZkErr e) {
  switch (e) {
    case ZK_OK:
      return "ok";
    case ZK_ERR_MEMORY:
      return "no memory";
    case ZK_ERR_COUNT:
      return "a count is above its limit";
    case ZK_ERR_NONCANONICAL:
      return "an element is not below the field modulus";
    case ZK_ERR_REF:
      return "a value is not defined, or an out value is an operand of an op that is not eq";
    case ZK_ERR_OUTPUT:
      return "an output number is not below the output count, or it is written twice or not written";
    case ZK_ERR_WITNESS:
      return "a witness count does not agree with the circuit";
    case ZK_ERR_MAP:
      return "a matrix index is not below the matrix count, or the mapped entries are not the weight count";
    case ZK_ERR_REFUSED:
      return "the relation is refused";
    case ZK_ERR_UNSAT:
      return "an eq does not hold for the witness";
  }
  return "the error is not known";
}

/* Appends N words. 0 when there is no memory. */
static int push(ZkWords *w, const uint32_t *v, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (w->count == w->cap) {
      uint32_t *grown;
      size_t cap = w->cap == 0 ? 64 : w->cap * 2;
      if (w->cap > SIZE_MAX / (2 * sizeof *grown)) return 0;
      grown = realloc(w->word, cap * sizeof *grown);
      if (grown == NULL) return 0;
      w->word = grown;
      w->cap = cap;
    }
    w->word[w->count++] = v[i];
  }
  return 1;
}

static int push1(ZkWords *w, uint32_t v) { return push(w, &v, 1); }

static void fail(ZkCircuit *c, ZkErr e) {
  if (c->err == ZK_OK) c->err = e;
}

void zk_init(ZkCircuit *c, uint32_t n, uint32_t m, uint32_t q) {
  memset(c, 0, sizeof *c);
  c->inputs = n;
  c->weights = m;
  c->outputs = q;
  if (n > ZK_VALUES_MAX || m > ZK_VALUES_MAX - n || q > ZK_VALUES_MAX) {
    c->err = ZK_ERR_COUNT;
    return;
  }
  c->vals = n + m;
  c->written = calloc((size_t)q + 1, 1);
  if (c->written == NULL) c->err = ZK_ERR_MEMORY;
}

void zk_free(ZkCircuit *c) {
  free(c->code.word);
  free(c->is_out);
  free(c->written);
  memset(c, 0, sizeof *c);
}

uint32_t zk_input(ZkCircuit *c, uint32_t i) {
  if (i >= c->inputs) fail(c, ZK_ERR_REF);
  return c->err == ZK_OK ? i : 0;
}

uint32_t zk_weight(ZkCircuit *c, uint32_t j) {
  if (j >= c->weights) fail(c, ZK_ERR_REF);
  return c->err == ZK_OK ? c->inputs + j : 0;
}

/* 1 when V is defined and, unless ANY (an eq operand), not an out value
 * (src/halo2.c operand). */
static int operand_ok(const ZkCircuit *c, uint32_t v, int any) {
  const uint32_t base = c->inputs + c->weights;
  if (v >= c->vals) return 0;
  return any || v < base || !c->is_out[v - base];
}

/* Appends one instruction. 0 after an error. */
static int put(ZkCircuit *c, ZkTag tag, const uint32_t *op, size_t n) {
  if (c->instrs == UINT32_MAX) {
    fail(c, ZK_ERR_COUNT);
    return 0;
  }
  if (!push1(&c->code, (uint32_t)tag) || !push(&c->code, op, n)) {
    fail(c, ZK_ERR_MEMORY);
    return 0;
  }
  c->instrs++;
  return 1;
}

/* Appends an instruction that defines a value (OUT: an out value). */
static uint32_t value_op(ZkCircuit *c, ZkTag tag, const uint32_t *op, size_t n, int out) {
  const size_t r = c->vals - (c->inputs + c->weights);
  if (c->vals >= ZK_VALUES_MAX) {
    fail(c, ZK_ERR_COUNT);
    return 0;
  }
  if (r == c->is_out_cap) {
    size_t cap = c->is_out_cap == 0 ? 64 : c->is_out_cap * 2;
    unsigned char *grown = realloc(c->is_out, cap);
    if (grown == NULL) {
      fail(c, ZK_ERR_MEMORY);
      return 0;
    }
    c->is_out = grown;
    c->is_out_cap = cap;
  }
  if (!put(c, tag, op, n)) return 0;
  c->is_out[r] = (unsigned char)out;
  return c->vals++;
}

uint32_t zk_const(ZkCircuit *c, const ZkFr *k) {
  if (c->err != ZK_OK) return 0;
  if (!zk_canonical(k)) {
    fail(c, ZK_ERR_NONCANONICAL);
    return 0;
  }
  return value_op(c, ZK_CONST, k->limb, ZK_LIMBS, 0);
}

static uint32_t binary(ZkCircuit *c, ZkTag tag, uint32_t a, uint32_t b) {
  const uint32_t op[2] = {a, b};
  if (c->err != ZK_OK) return 0;
  if (!operand_ok(c, a, 0) || !operand_ok(c, b, 0)) {
    fail(c, ZK_ERR_REF);
    return 0;
  }
  return value_op(c, tag, op, 2, 0);
}

uint32_t zk_add(ZkCircuit *c, uint32_t a, uint32_t b) { return binary(c, ZK_ADD, a, b); }
uint32_t zk_sub(ZkCircuit *c, uint32_t a, uint32_t b) { return binary(c, ZK_SUB, a, b); }
uint32_t zk_mul(ZkCircuit *c, uint32_t a, uint32_t b) { return binary(c, ZK_MUL, a, b); }

uint32_t zk_out(ZkCircuit *c, uint32_t o, uint32_t v) {
  const uint32_t op[2] = {o, v};
  uint32_t u;
  if (c->err != ZK_OK) return 0;
  if (o >= c->outputs || c->written[o]) {
    fail(c, ZK_ERR_OUTPUT);
    return 0;
  }
  if (!operand_ok(c, v, 0)) {
    fail(c, ZK_ERR_REF);
    return 0;
  }
  u = value_op(c, ZK_OUT, op, 2, 1);
  if (c->err != ZK_OK) return 0;
  c->written[o] = 1;
  zk_eq(c, u, v);
  return u;
}

void zk_eq(ZkCircuit *c, uint32_t a, uint32_t b) {
  const uint32_t op[2] = {a, b};
  if (c->err != ZK_OK) return;
  if (!operand_ok(c, a, 1) || !operand_ok(c, b, 1)) {
    fail(c, ZK_ERR_REF);
    return;
  }
  put(c, ZK_EQ, op, 2);
}

void zk_refuse(ZkCircuit *c) { fail(c, ZK_ERR_REFUSED); }

/* Checks that the COUNT elements are canonical. */
static int all_canonical(const ZkFr *k, uint64_t count) {
  uint64_t i;
  for (i = 0; i < count; i++)
    if (!zk_canonical(&k[i])) return 0;
  return 1;
}

static int push_fr(ZkWords *w, const ZkFr *k, uint64_t count) {
  uint64_t i;
  for (i = 0; i < count; i++)
    if (!push(w, k[i].limb, ZK_LIMBS)) return 0;
  return 1;
}

/* The checks of zk_words before any word is written. */
static ZkErr check_witness(const ZkCircuit *c, const ZkWitness *w) {
  uint64_t mapped = 0;
  uint32_t i;
  if (c->err != ZK_OK) return c->err;
  for (i = 0; i < c->outputs; i++)
    if (!c->written[i]) return ZK_ERR_OUTPUT;
  if (w->inputs != c->inputs || w->outputs != c->outputs) return ZK_ERR_WITNESS;
  for (i = 0; i < w->matrices; i++) {
    const uint64_t entries = (uint64_t)w->matrix[i].rows * w->matrix[i].cols;
    if (entries > ZK_VALUES_MAX) return ZK_ERR_COUNT;
    if (!all_canonical(w->matrix[i].entry, entries)) return ZK_ERR_NONCANONICAL;
  }
  for (i = 0; i < w->maps; i++) {
    if (w->map[i] >= w->matrices) return ZK_ERR_MAP;
    mapped += (uint64_t)w->matrix[w->map[i]].rows * w->matrix[w->map[i]].cols;
  }
  if (mapped != c->weights) return ZK_ERR_MAP;
  if (!all_canonical(w->input, w->inputs) || !all_canonical(w->output, w->outputs)) return ZK_ERR_NONCANONICAL;
  return ZK_OK;
}

ZkErr zk_words(const ZkCircuit *c, const ZkWitness *w, ZkWords *out) {
  const uint32_t header[ZK_HEADER_WORDS] = {ZK_VERSION, ZK_FIELD_BN254, ZK_LIMBS, c->inputs,
                                            c->weights, c->outputs,     c->instrs};
  const uint32_t witness[4] = {ZK_VERSION, ZK_FIELD_BN254, ZK_LIMBS, w->matrices};
  /* One stage: rank 1, the dim q, the aux word 0. */
  const uint32_t stage[4] = {1, 1, c->outputs, 0};
  ZkWords t = {NULL, 0, 0};
  int ok;
  uint32_t i;
  ZkErr e = check_witness(c, w);
  if (e != ZK_OK) return e;
  ok = push(&t, header, ZK_HEADER_WORDS) && push(&t, c->code.word, c->code.count);
  ok = ok && push1(&t, w->maps) && push(&t, w->map, w->maps);
  ok = ok && push1(&t, w->inputs) && push_fr(&t, w->input, w->inputs);
  ok = ok && push(&t, witness, 4);
  for (i = 0; ok && i < w->matrices; i++) {
    const ZkMatrix *m = &w->matrix[i];
    const uint32_t head[3] = {2, m->rows, m->cols};
    ok = push(&t, head, 3) && push_fr(&t, m->entry, (uint64_t)m->rows * m->cols);
  }
  ok = ok && push(&t, stage, 4) && push_fr(&t, w->output, w->outputs);
  if (!ok) {
    free(t.word);
    return ZK_ERR_MEMORY;
  }
  *out = t;
  return ZK_OK;
}

void zk_words_free(ZkWords *w) {
  free(w->word);
  memset(w, 0, sizeof *w);
}

int zk_print(const ZkWords *w, FILE *out) {
  size_t i;
  int ok = 1;
  for (i = 0; ok && i < w->count; i++) ok = fprintf(out, i == 0 ? "%lu" : " %lu", (unsigned long)w->word[i]) > 0;
  return ok && fputc('\n', out) != EOF && fflush(out) == 0;
}

/* -r^-1 mod 2^32 (r = 1 mod 2^28), for the Montgomery product. */
#define ZK_R_INV 0xefffffffu

/* K - r in place, for K in [r, 2r). */
static void sub_r(ZkFr *k) {
  uint64_t borrow = 0;
  unsigned i;
  for (i = 0; i < ZK_LIMBS; i++) {
    const uint64_t d = (uint64_t)k->limb[i] - ZK_R[i] - borrow;
    k->limb[i] = (uint32_t)d;
    borrow = d >> 63;
  }
}

ZkFr zk_fr_add(const ZkFr *a, const ZkFr *b) {
  ZkFr s;
  uint64_t carry = 0;
  unsigned i;
  for (i = 0; i < ZK_LIMBS; i++) {
    carry += (uint64_t)a->limb[i] + b->limb[i];
    s.limb[i] = (uint32_t)carry;
    carry >>= 32;
  }
  if (!zk_canonical(&s)) sub_r(&s);
  return s;
}

ZkFr zk_fr_sub(const ZkFr *a, const ZkFr *b) {
  ZkFr d;
  uint64_t borrow = 0, carry = 0;
  unsigned i;
  for (i = 0; i < ZK_LIMBS; i++) {
    const uint64_t t = (uint64_t)a->limb[i] - b->limb[i] - borrow;
    d.limb[i] = (uint32_t)t;
    borrow = t >> 63;
  }
  for (i = 0; borrow != 0 && i < ZK_LIMBS; i++) {
    carry += (uint64_t)d.limb[i] + ZK_R[i];
    d.limb[i] = (uint32_t)carry;
    carry >>= 32;
  }
  return d;
}

/* A B 2^-256 mod r (CIOS with 32-bit limbs; A and B below r). */
static ZkFr mont(const ZkFr *a, const ZkFr *b) {
  uint32_t t[ZK_LIMBS + 2];
  ZkFr out;
  unsigned i, j;
  memset(t, 0, sizeof t);
  for (i = 0; i < ZK_LIMBS; i++) {
    uint64_t carry = 0;
    uint32_t m;
    for (j = 0; j < ZK_LIMBS; j++) {
      const uint64_t s = (uint64_t)t[j] + (uint64_t)a->limb[j] * b->limb[i] + carry;
      t[j] = (uint32_t)s;
      carry = s >> 32;
    }
    carry += t[ZK_LIMBS];
    t[ZK_LIMBS] = (uint32_t)carry;
    t[ZK_LIMBS + 1] = (uint32_t)(carry >> 32);
    m = t[0] * ZK_R_INV;
    carry = ((uint64_t)t[0] + (uint64_t)m * ZK_R[0]) >> 32;
    for (j = 1; j < ZK_LIMBS; j++) {
      const uint64_t s = (uint64_t)t[j] + (uint64_t)m * ZK_R[j] + carry;
      t[j - 1] = (uint32_t)s;
      carry = s >> 32;
    }
    carry += t[ZK_LIMBS];
    t[ZK_LIMBS - 1] = (uint32_t)carry;
    t[ZK_LIMBS] = t[ZK_LIMBS + 1] + (uint32_t)(carry >> 32);
  }
  memcpy(out.limb, t, sizeof out.limb);
  if (t[ZK_LIMBS] != 0 || !zk_canonical(&out)) sub_r(&out);
  return out;
}

/* A when A is 0 or 1, else 2: zk_fr_mul skips both Montgomery steps for a bit operand. */
static unsigned fr_bit(const ZkFr *a) {
  uint32_t high = 0;
  unsigned i;
  for (i = 1; i < ZK_LIMBS; i++) high |= a->limb[i];
  return high == 0 && a->limb[0] <= 1 ? a->limb[0] : 2;
}

ZkFr zk_fr_mul(const ZkFr *a, const ZkFr *b) {
  static ZkFr r2; /* 2^512 mod r, made once by doubling */
  static int ready;
  const unsigned ba = fr_bit(a), bb = fr_bit(b);
  ZkFr t;
  unsigned i;
  if (ba == 0 || bb == 0) return zk_fr_u64(0);
  if (ba == 1 && zk_canonical(b)) return *b;
  if (bb == 1 && zk_canonical(a)) return *a;
  if (!ready) {
    r2 = zk_fr_u64(1);
    for (i = 0; i < 512; i++) r2 = zk_fr_add(&r2, &r2);
    ready = 1;
  }
  t = mont(a, b);
  return mont(&t, &r2);
}

/* The value of the instruction at CODE into V[*AT]; *LEN gets its words. */
static ZkErr eval(const ZkWitness *w, ZkFr *v, uint32_t *at, const uint32_t *code, size_t *len) {
  const ZkTag tag = (ZkTag)code[0];
  *len = 3;
  switch (tag) {
    case ZK_CONST:
      memcpy(v[*at].limb, &code[1], sizeof v[*at].limb);
      ++*at;
      *len = 1 + ZK_LIMBS;
      return ZK_OK;
    case ZK_ADD:
      v[*at] = zk_fr_add(&v[code[1]], &v[code[2]]);
      ++*at;
      return ZK_OK;
    case ZK_SUB:
      v[*at] = zk_fr_sub(&v[code[1]], &v[code[2]]);
      ++*at;
      return ZK_OK;
    case ZK_MUL:
      v[*at] = zk_fr_mul(&v[code[1]], &v[code[2]]);
      ++*at;
      return ZK_OK;
    case ZK_OUT:
      v[*at] = w->output[code[1]];
      ++*at;
      return ZK_OK;
    case ZK_EQ:
      return memcmp(&v[code[1]], &v[code[2]], sizeof v[0]) == 0 ? ZK_OK : ZK_ERR_UNSAT;
    case ZK_REFUSE:
      return ZK_ERR_REFUSED;
  }
  return ZK_ERR_REFUSED;
}

ZkErr zk_check(const ZkCircuit *c, const ZkWitness *w) {
  ZkFr *v;
  size_t pc = 0, len = 0;
  uint32_t i, at = 0;
  ZkErr e = check_witness(c, w);
  if (e != ZK_OK) return e;
  v = malloc(((size_t)c->vals + 1) * sizeof *v);
  if (v == NULL) return ZK_ERR_MEMORY;
  for (i = 0; i < c->inputs; i++) v[at++] = w->input[i];
  for (i = 0; i < w->maps; i++) {
    const ZkMatrix *m = &w->matrix[w->map[i]];
    const uint64_t entries = (uint64_t)m->rows * m->cols;
    uint64_t j;
    for (j = 0; j < entries; j++) v[at++] = m->entry[j];
  }
  for (i = 0; e == ZK_OK && i < c->instrs; i++) {
    e = eval(w, v, &at, &c->code.word[pc], &len);
    pc += len;
  }
  free(v);
  return e;
}

static ZkFr pow2(uint32_t e) {
  ZkFr k;
  memset(&k, 0, sizeof k);
  k.limb[e / 32] = 1u << (e % 32);
  return k;
}

static int bit(const ZkFr *x, uint32_t i) { return (int)((x->limb[i / 32] >> (i % 32)) & 1u); }

static uint32_t bit_length(const ZkFr *k) {
  uint32_t n = ZK_LIMBS * 32;
  while (n > 0 && !bit(k, n - 1)) n--;
  return n;
}

/* 1 when the N low bits of K are all 1 (K = 2^N - 1 when N is its length). */
static int all_ones(const ZkFr *k, uint32_t n) {
  uint32_t i;
  for (i = 0; i < n; i++)
    if (!bit(k, i)) return 0;
  return 1;
}

uint32_t zk_word(ZkCircuit *c, uint32_t w0, uint32_t n) {
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1);
  uint32_t z, u, acc = 0, i;
  if (c->err != ZK_OK) return 0;
  if (n == 0 || n > ZK_BITS_MAX) {
    fail(c, ZK_ERR_COUNT);
    return 0;
  }
  if (w0 > c->weights || n > c->weights - w0) {
    fail(c, ZK_ERR_REF);
    return 0;
  }
  z = zk_const(c, &zero);
  u = zk_const(c, &one);
  /* Horner from the top bit: acc = 2 acc + b. */
  for (i = n; i > 0; i--) {
    const uint32_t b = zk_weight(c, w0 + i - 1);
    const uint32_t bm1 = zk_sub(c, b, u);
    zk_eq(c, zk_mul(c, b, bm1), z);
    if (i == n)
      acc = b;
    else {
      const uint32_t twice = zk_add(c, acc, acc);
      acc = zk_add(c, twice, b);
    }
  }
  return c->err == ZK_OK ? acc : 0;
}

void zk_bits(ZkCircuit *c, uint32_t x, uint32_t w0, uint32_t n) {
  const uint32_t v = zk_word(c, w0, n);
  zk_eq(c, v, x);
}

void zk_bits_fill(ZkFr *wt, const ZkFr *x, uint32_t n) {
  uint32_t i;
  for (i = 0; i < n && i < ZK_LIMBS * 32; i++) wt[i] = zk_fr_u64((uint64_t)bit(x, i));
}

uint32_t zk_range_weights(const ZkFr *b) {
  const uint32_t n = bit_length(b);
  if (n > ZK_BITS_MAX) return 0;
  return all_ones(b, n) ? n : 2 * n;
}

void zk_range(ZkCircuit *c, uint32_t x, const ZkFr *b, uint32_t w0) {
  const uint32_t n = bit_length(b);
  uint32_t d, sum, k;
  if (c->err != ZK_OK) return;
  if (n > ZK_BITS_MAX) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (n == 0) {
    zk_eq(c, x, zk_const(c, b));
    return;
  }
  zk_bits(c, x, w0, n);
  if (all_ones(b, n)) return;
  d = zk_word(c, w0 + n, n);
  sum = zk_add(c, x, d);
  k = zk_const(c, b);
  zk_eq(c, sum, k);
}

void zk_range_fill(ZkFr *wt, const ZkFr *x, const ZkFr *b) {
  const uint32_t n = bit_length(b);
  ZkFr d;
  if (n == 0 || n > ZK_BITS_MAX) return;
  zk_bits_fill(wt, x, n);
  if (all_ones(b, n)) return;
  d = zk_fr_sub(b, x);
  zk_bits_fill(wt + n, &d, n);
}

void zk_signed(ZkCircuit *c, uint32_t x, uint32_t w0, uint32_t n) {
  ZkFr h;
  uint32_t k;
  if (c->err != ZK_OK) return;
  if (n == 0 || n > ZK_BITS_MAX) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  h = pow2(n - 1);
  k = zk_const(c, &h);
  zk_bits(c, zk_add(c, x, k), w0, n);
}

void zk_signed_fill(ZkFr *wt, const ZkFr *x, uint32_t n) {
  ZkFr h, s;
  if (n == 0 || n > ZK_BITS_MAX) return;
  h = pow2(n - 1);
  s = zk_fr_add(x, &h);
  zk_bits_fill(wt, &s, n);
}

static ZkFr pow2_minus(uint32_t e, uint64_t d) {
  const ZkFr k = pow2(e), dd = zk_fr_u64(d);
  return zk_fr_sub(&k, &dd);
}

uint32_t zk_split_weights(uint32_t lo, const ZkFr *hi) {
  const uint32_t n = bit_length(hi);
  if (lo == 0 || lo > ZK_BITS_MAX || n > ZK_BITS_MAX - lo) return 0;
  return lo + 1 + zk_range_weights(hi);
}

uint32_t zk_split(ZkCircuit *c, uint32_t x, uint32_t lo, const ZkFr *hi, uint32_t w0, uint32_t *hiv) {
  ZkFr s;
  uint32_t l, h, k, t, sum;
  *hiv = 0;
  if (c->err != ZK_OK) return 0;
  if (zk_split_weights(lo, hi) == 0) {
    fail(c, ZK_ERR_COUNT);
    return 0;
  }
  l = zk_word(c, w0, lo);
  h = zk_weight(c, w0 + lo);
  zk_range(c, h, hi, w0 + lo + 1);
  s = pow2(lo);
  k = zk_const(c, &s);
  t = zk_mul(c, h, k);
  sum = zk_add(c, t, l);
  zk_eq(c, sum, x);
  if (c->err != ZK_OK) return 0;
  *hiv = h;
  return l;
}

void zk_split_fill(ZkFr *wt, const ZkFr *x, uint32_t lo, const ZkFr *hi) {
  ZkFr h;
  uint32_t i;
  if (zk_split_weights(lo, hi) == 0) return;
  memset(&h, 0, sizeof h);
  for (i = lo; i < ZK_LIMBS * 32; i++)
    if (bit(x, i)) h.limb[(i - lo) / 32] |= 1u << ((i - lo) % 32);
  zk_bits_fill(wt, x, lo);
  wt[lo] = h;
  zk_range_fill(wt + lo + 1, &h, hi);
}

uint32_t zk_add64(ZkCircuit *c, uint32_t a, uint32_t b, uint32_t w0, uint32_t *carry) {
  const ZkFr one = zk_fr_u64(1);
  const uint32_t s = zk_add(c, a, b);
  return zk_split(c, s, 64, &one, w0, carry);
}

void zk_add64_fill(ZkFr *wt, const ZkFr *a, const ZkFr *b) {
  const ZkFr one = zk_fr_u64(1), s = zk_fr_add(a, b);
  zk_split_fill(wt, &s, 64, &one);
}

uint32_t zk_muladd64(ZkCircuit *c, uint32_t a, uint32_t b, uint32_t cc, uint32_t w0, uint32_t *hi) {
  const ZkFr max = pow2_minus(64, 1);
  const uint32_t p = zk_mul(c, a, b);
  const uint32_t s = zk_add(c, p, cc);
  return zk_split(c, s, 64, &max, w0, hi);
}

void zk_muladd64_fill(ZkFr *wt, const ZkFr *a, const ZkFr *b, const ZkFr *cc) {
  const ZkFr max = pow2_minus(64, 1), p = zk_fr_mul(a, b), s = zk_fr_add(&p, cc);
  zk_split_fill(wt, &s, 64, &max);
}

void zk_add128(ZkCircuit *c, const uint32_t a[2], const uint32_t b[2], uint32_t w0, uint32_t r[2]) {
  const ZkFr one = zk_fr_u64(1);
  uint32_t k0, k1, s0, t, s1;
  s0 = zk_add(c, a[0], b[0]);
  r[0] = zk_split(c, s0, 64, &one, w0, &k0);
  t = zk_add(c, a[1], b[1]);
  s1 = zk_add(c, t, k0);
  r[1] = zk_split(c, s1, 64, &one, w0 + ZK_ADD64_WEIGHTS, &k1);
}

void zk_add128_fill(ZkFr *wt, const ZkFr a[2], const ZkFr b[2]) {
  const ZkFr one = zk_fr_u64(1), s0 = zk_fr_add(&a[0], &b[0]), t = zk_fr_add(&a[1], &b[1]);
  ZkFr s1;
  zk_split_fill(wt, &s0, 64, &one);
  s1 = zk_fr_add(&t, &wt[64]);
  zk_split_fill(wt + ZK_ADD64_WEIGHTS, &s1, 64, &one);
}

/* The weights of the low split of zk_mul128: 64 + 1 + 2 64 (2^64 - 2 is not
 * 2^64 - 1, so its range has the complement word). */
enum { MUL128_LO_WEIGHTS = 193 };

void zk_mul128(ZkCircuit *c, const uint32_t a[2], const uint32_t b[2], uint32_t w0, uint32_t r[2]) {
  const ZkFr q0max = pow2_minus(64, 2), q1max = pow2_minus(65, 3);
  uint32_t p0, q0, q1, m0, m1, m, s;
  p0 = zk_mul(c, a[0], b[0]);
  r[0] = zk_split(c, p0, 64, &q0max, w0, &q0);
  m0 = zk_mul(c, a[0], b[1]);
  m1 = zk_mul(c, a[1], b[0]);
  m = zk_add(c, m0, m1);
  s = zk_add(c, m, q0);
  r[1] = zk_split(c, s, 64, &q1max, w0 + MUL128_LO_WEIGHTS, &q1);
}

void zk_mul128_fill(ZkFr *wt, const ZkFr a[2], const ZkFr b[2]) {
  const ZkFr q0max = pow2_minus(64, 2), q1max = pow2_minus(65, 3);
  const ZkFr p0 = zk_fr_mul(&a[0], &b[0]), m0 = zk_fr_mul(&a[0], &b[1]), m1 = zk_fr_mul(&a[1], &b[0]);
  ZkFr m, s;
  zk_split_fill(wt, &p0, 64, &q0max);
  m = zk_fr_add(&m0, &m1);
  s = zk_fr_add(&m, &wt[64]);
  zk_split_fill(wt + MUL128_LO_WEIGHTS, &s, 64, &q1max);
}

/* D5: p = 2^192 - 1253375 in 32-bit limbs, and the mulp carry shape. */
static const uint32_t P32[6] = {0xffece001u, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu};
enum { FP_CARRY_BITS = 68, FP_CARRIES = 4 };

/* p - D for D of 0 or 1. */
static ZkFr fp_const(uint32_t d) {
  ZkFr k;
  memset(&k, 0, sizeof k);
  memcpy(k.limb, P32, sizeof P32);
  k.limb[0] -= d;
  return k;
}

/* The 64-bit limb K of X. */
static ZkFr fp_limb(const ZkFr *x, uint32_t k) {
  ZkFr l;
  memset(&l, 0, sizeof l);
  l.limb[0] = x->limb[2 * k];
  l.limb[1] = x->limb[2 * k + 1];
  return l;
}

/* x0 + x1 2^64 + x2 2^128 for limbs below 2^64. */
static ZkFr fp_compose(const ZkFr x[3]) {
  ZkFr v;
  uint32_t k;
  memset(&v, 0, sizeof v);
  for (k = 0; k < 3; k++) {
    v.limb[2 * k] = x[k].limb[0];
    v.limb[2 * k + 1] = x[k].limb[1];
  }
  return v;
}

/* The Horner word of the N weights at W0, which the caller constrains to bits. */
static uint32_t word_of(ZkCircuit *c, uint32_t w0, uint32_t n) {
  uint32_t acc = 0, i;
  if (c->err != ZK_OK) return 0;
  if (n == 0 || w0 > c->weights || n > c->weights - w0) {
    fail(c, ZK_ERR_REF);
    return 0;
  }
  for (i = n; i > 0; i--) {
    const uint32_t b = zk_weight(c, w0 + i - 1);
    if (i == n)
      acc = b;
    else {
      const uint32_t twice = zk_add(c, acc, acc);
      acc = zk_add(c, twice, b);
    }
  }
  return c->err == ZK_OK ? acc : 0;
}

/* The value x0 + x1 2^64 + x2 2^128 of the limbs X. */
static uint32_t fp_value(ZkCircuit *c, const uint32_t x[3]) {
  const ZkFr k64 = pow2(64), k128 = pow2(128);
  uint32_t s64, s128, t1, t2, v0;
  s64 = zk_const(c, &k64);
  s128 = zk_const(c, &k128);
  t1 = zk_mul(c, x[1], s64);
  t2 = zk_mul(c, x[2], s128);
  v0 = zk_add(c, x[0], t1);
  return zk_add(c, v0, t2);
}

uint32_t zk_fp(ZkCircuit *c, uint32_t w0, uint32_t x[3]) {
  const ZkFr pm1 = fp_const(1);
  uint32_t i, v;
  for (i = 0; i < 3; i++) x[i] = word_of(c, w0 + 64 * i, 64);
  v = fp_value(c, x);
  zk_range(c, v, &pm1, w0);
  if (c->err == ZK_OK) return v;
  for (i = 0; i < 3; i++) x[i] = 0;
  return 0;
}

void zk_fp_bind(ZkCircuit *c, const uint32_t a[3], uint32_t w0) {
  uint32_t x[3], i;
  zk_fp(c, w0, x);
  for (i = 0; i < 3; i++) zk_eq(c, x[i], a[i]);
}

static void fp_fill_value(ZkFr *wt, const ZkFr *v) {
  const ZkFr pm1 = fp_const(1);
  zk_range_fill(wt, v, &pm1);
}

void zk_fp_fill(ZkFr *wt, const ZkFr x[3]) {
  const ZkFr v = fp_compose(x);
  fp_fill_value(wt, &v);
}

void zk_addp(ZkCircuit *c, const uint32_t a[3], const uint32_t b[3], uint32_t w0, uint32_t r[3]) {
  const ZkFr p = fp_const(0);
  uint32_t q, vr, va, vb, k, s, t, u;
  q = zk_word(c, w0, 1);
  vr = zk_fp(c, w0 + 1, r);
  va = fp_value(c, a);
  vb = fp_value(c, b);
  k = zk_const(c, &p);
  s = zk_add(c, va, vb);
  t = zk_mul(c, q, k);
  u = zk_add(c, t, vr);
  zk_eq(c, s, u);
}

/* 1 when X is below Y. */
static int fr_below(const ZkFr *x, const ZkFr *y) {
  uint32_t i;
  for (i = ZK_LIMBS; i > 0; i--)
    if (x->limb[i - 1] != y->limb[i - 1]) return x->limb[i - 1] < y->limb[i - 1];
  return 0;
}

void zk_addp_fill(ZkFr *wt, const ZkFr a[3], const ZkFr b[3]) {
  const ZkFr p = fp_const(0), va = fp_compose(a), vb = fp_compose(b), s = zk_fr_add(&va, &vb);
  const int over = !fr_below(&s, &p);
  const ZkFr r = over ? zk_fr_sub(&s, &p) : s;
  wt[0] = zk_fr_u64((uint64_t)over);
  fp_fill_value(wt + 1, &r);
}

void zk_mulp(ZkCircuit *c, const uint32_t a[3], const uint32_t b[3], uint32_t w0, uint32_t r[3]) {
  const ZkFr p = fp_const(0), zero = zk_fr_u64(0), k64 = pow2(64), off = pow2(67);
  uint32_t q[3], pl[3], z, s64, so, carry = 0, col, i;
  zk_fp(c, w0, q);
  zk_fp(c, w0 + ZK_FP_WEIGHTS, r);
  for (i = 0; i < 3; i++) {
    const ZkFr l = fp_limb(&p, i);
    pl[i] = zk_const(c, &l);
  }
  z = zk_const(c, &zero);
  s64 = zk_const(c, &k64);
  so = zk_const(c, &off);
  for (col = 0; col < 5; col++) {
    uint32_t lhs = col == 0 ? z : carry, rhs = col < 3 ? r[col] : z;
    for (i = 0; i < 3; i++)
      if (col >= i && col - i <= 2) {
        const uint32_t ab = zk_mul(c, a[i], b[col - i]);
        const uint32_t qp = zk_mul(c, q[i], pl[col - i]);
        lhs = zk_add(c, lhs, ab);
        rhs = zk_add(c, rhs, qp);
      }
    if (col < FP_CARRIES) {
      const uint32_t w = zk_word(c, w0 + 2 * ZK_FP_WEIGHTS + FP_CARRY_BITS * col, FP_CARRY_BITS);
      const uint32_t ck = zk_sub(c, w, so);
      const uint32_t t = zk_mul(c, ck, s64);
      rhs = zk_add(c, rhs, t);
      carry = ck;
    }
    zk_eq(c, lhs, rhs);
  }
}

/* X (7 limbs) at least p. */
static int fp_at_least_p(const uint32_t x[7]) {
  uint32_t i;
  if (x[6] != 0) return 1;
  for (i = 6; i > 0; i--)
    if (x[i - 1] != P32[i - 1]) return x[i - 1] > P32[i - 1];
  return 1;
}

static void fp_sub_p(uint32_t x[7]) {
  uint64_t borrow = 0;
  uint32_t i;
  for (i = 0; i < 7; i++) {
    const uint64_t d = (uint64_t)x[i] - (i < 6 ? P32[i] : 0u) - borrow;
    x[i] = (uint32_t)d;
    borrow = d >> 63;
  }
}

/* The value of X shifted right by 64 bits. */
static ZkFr fr_shr64(const ZkFr *x) {
  ZkFr y;
  uint32_t i;
  memset(&y, 0, sizeof y);
  for (i = 2; i < ZK_LIMBS; i++) y.limb[i - 2] = x->limb[i];
  return y;
}

void zk_mulp_fill(ZkFr *wt, const ZkFr a[3], const ZkFr b[3]) {
  const ZkFr p = fp_const(0), va = fp_compose(a), vb = fp_compose(b), shift = pow2(131), base = pow2(67);
  uint32_t t[12], rem[7], i, j, col;
  ZkFr q, r, ql[3], rl[3], pl[3], carry;
  /* T = A B in 32-bit limbs. */
  memset(t, 0, sizeof t);
  for (i = 0; i < 6; i++) {
    uint64_t cy = 0;
    for (j = 0; j < 6; j++) {
      const uint64_t s = (uint64_t)va.limb[i] * vb.limb[j] + t[i + j] + cy;
      t[i + j] = (uint32_t)s;
      cy = s >> 32;
    }
    t[i + 6] = (uint32_t)cy;
  }
  /* Q = T / p and R = T mod p, shift-subtract from the top bit of T. */
  memset(rem, 0, sizeof rem);
  memset(&q, 0, sizeof q);
  memset(&r, 0, sizeof r);
  for (i = 384; i > 0; i--) {
    uint32_t cy = (t[(i - 1) / 32] >> ((i - 1) % 32)) & 1u;
    for (j = 0; j < 7; j++) {
      const uint32_t hi = rem[j] >> 31;
      rem[j] = (rem[j] << 1) | cy;
      cy = hi;
    }
    if (fp_at_least_p(rem)) {
      fp_sub_p(rem);
      if (i - 1 < ZK_LIMBS * 32) q.limb[(i - 1) / 32] |= 1u << ((i - 1) % 32);
    }
  }
  for (i = 0; i < 6; i++) r.limb[i] = rem[i];
  fp_fill_value(wt, &q);
  fp_fill_value(wt + ZK_FP_WEIGHTS, &r);
  /* c_k + 2^67 = (column k + 2^131) / 2^64: the column is above -2^131. */
  for (i = 0; i < 3; i++) {
    ql[i] = fp_limb(&q, i);
    rl[i] = fp_limb(&r, i);
    pl[i] = fp_limb(&p, i);
  }
  carry = zk_fr_u64(0);
  for (col = 0; col < FP_CARRIES; col++) {
    ZkFr s = carry, w;
    for (i = 0; i < 3; i++)
      if (col >= i && col - i <= 2) {
        const ZkFr ab = zk_fr_mul(&a[i], &b[col - i]), qp = zk_fr_mul(&ql[i], &pl[col - i]);
        const ZkFr s1 = zk_fr_add(&s, &ab);
        s = zk_fr_sub(&s1, &qp);
      }
    if (col < 3) {
      const ZkFr s1 = zk_fr_sub(&s, &rl[col]);
      s = s1;
    }
    {
      const ZkFr s1 = zk_fr_add(&s, &shift);
      w = fr_shr64(&s1);
    }
    zk_bits_fill(wt + 2 * ZK_FP_WEIGHTS + FP_CARRY_BITS * col, &w, FP_CARRY_BITS);
    carry = zk_fr_sub(&w, &base);
  }
}

/* D6: Poseidon2. poseidon2_round_constant gives K 2^256 mod r (the
 * Montgomery form over 8 limbs of 32 bits); 256 halvings mod r give K. */
ZkFr zk_poseidon2_constant(uint32_t k) {
  const Fr m = poseidon2_round_constant(k), r = fr_modulus();
  uint64_t t[FR_LIMBS + 1];
  ZkFr out;
  uint32_t i, s;
  for (i = 0; i < FR_LIMBS; i++) t[i] = m.limb[i];
  t[FR_LIMBS] = 0;
  for (s = 0; s < 256; s++) {
    if (t[0] & 1u) {
      uint64_t carry = 0;
      for (i = 0; i < FR_LIMBS; i++) {
        const uint64_t v = t[i] + r.limb[i] + carry;
        t[i] = v & 0xffffffffu;
        carry = v >> 32;
      }
      t[FR_LIMBS] += carry;
    }
    for (i = 0; i < FR_LIMBS; i++) t[i] = (t[i] >> 1) | ((t[i + 1] & 1u) << 31);
    t[FR_LIMBS] >>= 1;
  }
  for (i = 0; i < ZK_LIMBS; i++) out.limb[i] = (uint32_t)t[i];
  return out;
}

static uint32_t p2_sbox(ZkCircuit *c, uint32_t x) {
  const uint32_t x2 = zk_mul(c, x, x);
  const uint32_t x4 = zk_mul(c, x2, x2);
  return zk_mul(c, x, x4);
}

/* The external matrix circ(2, 1, 1): each element adds the sum. The internal
 * matrix (diag 2, 2, 3 + sum) adds s_2 once more first. */
static void p2_linear(ZkCircuit *c, uint32_t s[3], int internal) {
  const uint32_t s01 = zk_add(c, s[0], s[1]);
  const uint32_t sum = zk_add(c, s01, s[2]);
  uint32_t i;
  if (internal) s[2] = zk_add(c, s[2], s[2]);
  for (i = 0; i < POSEIDON2_T; i++) s[i] = zk_add(c, s[i], sum);
}

/* X becomes (X + constant K)^5. */
static void p2_round(ZkCircuit *c, uint32_t *x, uint32_t k) {
  const ZkFr rc = zk_poseidon2_constant(k);
  const uint32_t kv = zk_const(c, &rc);
  const uint32_t a = zk_add(c, *x, kv);
  *x = p2_sbox(c, a);
}

static void p2_external_rounds(ZkCircuit *c, uint32_t s[3], uint32_t k0) {
  uint32_t r, i;
  for (r = 0; r < POSEIDON2_HALF_F; r++) {
    for (i = 0; i < POSEIDON2_T; i++) p2_round(c, &s[i], k0 + POSEIDON2_T * r + i);
    p2_linear(c, s, 0);
  }
}

void zk_poseidon2_permute(ZkCircuit *c, uint32_t s[3]) {
  uint32_t r;
  p2_linear(c, s, 0);
  p2_external_rounds(c, s, 0);
  for (r = 0; r < POSEIDON2_ROUNDS_P; r++) {
    p2_round(c, &s[0], POSEIDON2_HALF_F * POSEIDON2_T + r);
    p2_linear(c, s, 1);
  }
  p2_external_rounds(c, s, POSEIDON2_HALF_F * POSEIDON2_T + POSEIDON2_ROUNDS_P);
}

/* The sponge of zk_poseidon2_hash. Word i is X[i], or the zk_word at
 * W0 + ZK_POSEIDON2_WORD_BITS i when X is NULL. */
static uint32_t p2_sponge(ZkCircuit *c, uint64_t tag, uint32_t n, uint32_t w0, const uint32_t *x);

uint32_t zk_poseidon2_hash(ZkCircuit *c, uint64_t tag, uint32_t n, uint32_t w0) {
  if (c->err != ZK_OK) return 0;
  if (n > (UINT32_MAX - w0) / ZK_POSEIDON2_WORD_BITS) {
    fail(c, ZK_ERR_COUNT);
    return 0;
  }
  return p2_sponge(c, tag, n, w0, NULL);
}

uint32_t zk_poseidon2_hash_values(ZkCircuit *c, uint64_t tag, uint32_t n, const uint32_t *x) {
  if (c->err != ZK_OK) return 0;
  return p2_sponge(c, tag, n, 0, x);
}

static uint32_t p2_sponge(ZkCircuit *c, uint64_t tag, uint32_t n, uint32_t w0, const uint32_t *x) {
  const ZkFr zero = zk_fr_u64(0);
  const uint32_t blocks = n == 0 ? 1 : n / 2 + n % 2;
  ZkFr cap = zk_fr_u64(n);
  uint32_t s[POSEIDON2_T], b, i;
  cap.limb[2] = (uint32_t)tag;
  cap.limb[3] = (uint32_t)(tag >> 32);
  s[0] = zk_const(c, &zero);
  s[1] = zk_const(c, &zero);
  s[2] = zk_const(c, &cap);
  for (b = 0; b < blocks; b++) {
    for (i = 0; i < 2; i++)
      if (2 * b + i < n) {
        const uint32_t v =
            x != NULL ? x[2 * b + i] : zk_word(c, w0 + ZK_POSEIDON2_WORD_BITS * (2 * b + i), ZK_POSEIDON2_WORD_BITS);
        s[i] = zk_add(c, s[i], v);
      }
    zk_poseidon2_permute(c, s);
  }
  return c->err == ZK_OK ? s[0] : 0;
}

void zk_poseidon2_hash_fill(ZkFr *wt, const uint64_t *words, uint32_t n) {
  uint32_t i;
  for (i = 0; i < n; i++) {
    const ZkFr x = zk_fr_u64(words[i]);
    zk_bits_fill(wt + ZK_POSEIDON2_WORD_BITS * i, &x, ZK_POSEIDON2_WORD_BITS);
  }
}

/* S7 U3 D11 to D14: Digest words, the Merkle level, membership, the vote and
 * motion relations. */

/* 2^(64 K) for K below 4. */
static ZkFr dg_pow64(uint32_t k) {
  ZkFr x = zk_fr_u64(0);
  x.limb[2 * k] = 1;
  return x;
}

/* The 4 words of r - 1, word 0 low (r is odd). */
static void dg_r1(uint64_t w[4]) {
  const Fr r = fr_modulus();
  uint32_t i;
  for (i = 0; i < ZK_DIGEST_WORDS; i++) w[i] = r.limb[2 * i] | r.limb[2 * i + 1] << 32;
  w[0]--;
}

void zk_canon(ZkCircuit *c, const uint32_t x[4], uint32_t w0) {
  const ZkFr k64 = dg_pow64(1);
  const uint32_t k = zk_const(c, &k64);
  uint64_t r1[ZK_DIGEST_WORDS];
  uint32_t carry = 0, i;
  dg_r1(r1);
  for (i = 0; i < ZK_DIGEST_WORDS; i++) {
    const ZkFr ri = zk_fr_u64(r1[i]);
    const uint32_t y = zk_word(c, w0 + ZK_POSEIDON2_WORD_BITS * i, ZK_POSEIDON2_WORD_BITS);
    const uint32_t xy = zk_add(c, x[i], y);
    const uint32_t lhs = i == 0 ? xy : zk_add(c, xy, carry);
    uint32_t rhs = zk_const(c, &ri);
    if (i + 1 < ZK_DIGEST_WORDS) {
      carry = zk_word(c, w0 + ZK_POSEIDON2_WORD_BITS * ZK_DIGEST_WORDS + i, 1);
      rhs = zk_add(c, rhs, zk_mul(c, k, carry));
    }
    zk_eq(c, lhs, rhs);
  }
}

/* Y = (r - 1) - X with the borrows; a word X at or above r leaves a final
 * borrow that the circuit does not have. */
void zk_canon_fill(ZkFr *wt, const uint64_t x[4]) {
  uint64_t r1[ZK_DIGEST_WORDS];
  uint32_t borrow = 0, i;
  dg_r1(r1);
  for (i = 0; i < ZK_DIGEST_WORDS; i++) {
    const uint64_t d = r1[i] - x[i];
    const ZkFr y = zk_fr_u64(d - borrow);
    borrow = (r1[i] < x[i]) | (d < borrow);
    zk_bits_fill(wt + ZK_POSEIDON2_WORD_BITS * i, &y, ZK_POSEIDON2_WORD_BITS);
    if (i + 1 < ZK_DIGEST_WORDS) wt[ZK_POSEIDON2_WORD_BITS * ZK_DIGEST_WORDS + i] = zk_fr_u64(borrow);
  }
}

uint32_t zk_recompose(ZkCircuit *c, const uint32_t x[4]) {
  uint32_t v = x[0], i;
  for (i = 1; i < ZK_DIGEST_WORDS; i++) {
    const ZkFr k = dg_pow64(i);
    v = zk_add(c, v, zk_mul(c, zk_const(c, &k), x[i]));
  }
  return v;
}

void zk_digest(ZkCircuit *c, uint32_t w0, uint32_t x[4]) {
  uint32_t i;
  for (i = 0; i < ZK_DIGEST_WORDS; i++) x[i] = zk_word(c, w0 + ZK_POSEIDON2_WORD_BITS * i, ZK_POSEIDON2_WORD_BITS);
  zk_canon(c, x, w0 + ZK_POSEIDON2_WORD_BITS * ZK_DIGEST_WORDS);
}

void zk_digest_fill(ZkFr *wt, const uint64_t x[4]) {
  zk_poseidon2_hash_fill(wt, x, ZK_DIGEST_WORDS);
  zk_canon_fill(wt + ZK_POSEIDON2_WORD_BITS * ZK_DIGEST_WORDS, x);
}

uint32_t zk_node(ZkCircuit *c, uint32_t cur, uint32_t w0) {
  uint32_t lr[2 * ZK_DIGEST_WORDS];
  uint32_t a, b, d;
  zk_digest(c, w0, lr);
  zk_digest(c, w0 + ZK_DIGEST_WEIGHTS, lr + ZK_DIGEST_WORDS);
  d = zk_word(c, w0 + 2 * ZK_DIGEST_WEIGHTS, 1);
  a = zk_recompose(c, lr);
  b = zk_recompose(c, lr + ZK_DIGEST_WORDS);
  zk_eq(c, cur, zk_add(c, a, zk_mul(c, d, zk_sub(c, b, a))));
  return zk_poseidon2_hash_values(c, 3, 2 * ZK_DIGEST_WORDS, lr);
}

uint32_t zk_path(ZkCircuit *c, uint32_t cur, uint32_t w0) {
  uint32_t d;
  for (d = 0; d < ZK_MERKLE_LEVELS; d++) cur = zk_node(c, cur, w0 + ZK_NODE_WEIGHTS * d);
  return cur;
}

void zk_path_fill(ZkFr *wt, const uint64_t leaf[4], const uint64_t *sib, uint32_t idx,
                  uint64_t root[4]) {
  uint64_t lr[2 * ZK_DIGEST_WORDS];
  uint32_t d;
  Fr parent;
  memcpy(root, leaf, ZK_DIGEST_WORDS * sizeof lr[0]);
  for (d = 0; d < ZK_MERKLE_LEVELS; d++) {
    const uint32_t b = idx >> d & 1u;
    ZkFr *at = wt + ZK_NODE_WEIGHTS * d;
    memcpy(lr + ZK_DIGEST_WORDS * b, root, ZK_DIGEST_WORDS * sizeof lr[0]);
    memcpy(lr + ZK_DIGEST_WORDS * (1u - b), sib + ZK_DIGEST_WORDS * d, ZK_DIGEST_WORDS * sizeof lr[0]);
    zk_digest_fill(at, lr);
    zk_digest_fill(at + ZK_DIGEST_WEIGHTS, lr + ZK_DIGEST_WORDS);
    at[2 * ZK_DIGEST_WEIGHTS] = zk_fr_u64(b);
    poseidon2_hash(3, lr, 2 * ZK_DIGEST_WORDS, &parent);
    fr_to_words(&parent, root);
  }
}

uint32_t zk_member(ZkCircuit *c, const uint32_t k[4], uint32_t w0) {
  return zk_path(c, zk_poseidon2_hash_values(c, 2, ZK_DIGEST_WORDS, k), w0);
}

void zk_member_fill(ZkFr *wt, const uint64_t key[4], const uint64_t *sib, uint32_t idx,
                    uint64_t root[4]) {
  uint64_t leaf[ZK_DIGEST_WORDS];
  Fr d;
  poseidon2_hash(2, key, ZK_DIGEST_WORDS, &d);
  fr_to_words(&d, leaf);
  zk_path_fill(wt, leaf, sib, idx, root);
}

/* The D13 body. zk_gballotfull (U4 D19) uses it with the same weights,
 * inputs and outputs. */
static void gvote_body(ZkCircuit *c) {
  uint32_t v[ZK_DIGEST_WORDS + 2], i;
  zk_digest(c, 0, v);
  for (i = 0; i < 2; i++) {
    v[ZK_DIGEST_WORDS + i] = zk_word(c, ZK_DIGEST_WEIGHTS + ZK_POSEIDON2_WORD_BITS * i, ZK_POSEIDON2_WORD_BITS);
    zk_eq(c, v[ZK_DIGEST_WORDS + i], zk_input(c, i));
  }
  zk_out(c, 0, zk_member(c, v, ZK_DIGEST_WEIGHTS + 2 * ZK_POSEIDON2_WORD_BITS));
  zk_out(c, 1, zk_poseidon2_hash_values(c, 4, ZK_DIGEST_WORDS + 2, v));
}

void zk_gvote(ZkCircuit *c) {
  zk_init(c, 2, ZK_GVOTE_WEIGHTS, 2);
  gvote_body(c);
}

static uint32_t add_or_sub(ZkCircuit *c, uint32_t a, uint32_t b, int add) {
  return add ? zk_add(c, a, b) : zk_sub(c, a, b);
}

uint32_t zk_negacyclic(ZkCircuit *c, const uint32_t *p, const uint32_t *r, uint32_t k) {
  uint32_t acc = 0, i;
  if (c->err != ZK_OK) return 0;
  if (k >= ZK_PKE_N) {
    fail(c, ZK_ERR_COUNT);
    return 0;
  }
  for (i = 0; i < ZK_PKE_N; i++) {
    const uint32_t term = zk_mul(c, p[i], r[ZK_PKE_N - 1u - (k + ZK_PKE_N - i) % ZK_PKE_N]);
    acc = i == 0 ? term : add_or_sub(c, acc, term, i <= k);
  }
  return c->err == ZK_OK ? acc : 0;
}

/* V as an Fr element: a negative V is r - |V|. */
static ZkFr fr_i64(int64_t v) {
  const ZkFr zero = zk_fr_u64(0), mag = zk_fr_u64(v < 0 ? 0u - (uint64_t)v : (uint64_t)v);
  return v < 0 ? zk_fr_sub(&zero, &mag) : mag;
}

void zk_lwe_word(ZkCircuit *c, uint32_t s, const uint32_t *m, uint32_t w, uint32_t w0) {
  const ZkFr h = pow2(ZK_PKE_NOISE), b = pow2(ZK_PKE_NOISE + 1), t64 = pow2(64);
  const uint32_t e = zk_weight(c, w0), q = zk_weight(c, w0 + 1 + ZK_LWE_RANGE_WEIGHTS);
  uint32_t x, lhs, rhs;
  x = zk_add(c, e, zk_const(c, &h));
  zk_range(c, x, &b, w0 + 1);
  zk_signed(c, q, w0 + 2 + ZK_LWE_RANGE_WEIGHTS, ZK_LWE_Q_BITS);
  lhs = zk_add(c, s, e);
  if (m != NULL) lhs = zk_add(c, lhs, *m);
  rhs = zk_add(c, w, zk_mul(c, zk_const(c, &t64), q));
  zk_eq(c, lhs, rhs);
}

void zk_lwe_word_fill(ZkFr *wt, int64_t e, int64_t q) {
  const ZkFr h = pow2(ZK_PKE_NOISE), b = pow2(ZK_PKE_NOISE + 1), ef = fr_i64(e);
  const ZkFr x = zk_fr_add(&ef, &h);
  wt[0] = ef;
  zk_range_fill(wt + 1, &x, &b);
  wt[1 + ZK_LWE_RANGE_WEIGHTS] = fr_i64(q);
  zk_signed_fill(wt + 2 + ZK_LWE_RANGE_WEIGHTS, &wt[1 + ZK_LWE_RANGE_WEIGHTS], ZK_LWE_Q_BITS);
}

void zk_onehot(ZkCircuit *c, uint32_t w, uint32_t w0, uint32_t m[ZK_PKE_SLOTS]) {
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1), three = zk_fr_u64(3), four = zk_fr_u64(4);
  uint32_t z, u, k3, k4, sum = 0, a, b, j;
  z = zk_const(c, &zero);
  u = zk_const(c, &one);
  k3 = zk_const(c, &three);
  k4 = zk_const(c, &four);
  for (j = 0; j < ZK_PKE_SLOTS; j++) {
    m[j] = zk_weight(c, w0 + j);
    zk_eq(c, zk_mul(c, m[j], m[j]), m[j]);
    sum = j == 0 ? m[j] : zk_add(c, sum, m[j]);
    if (j >= 4) zk_eq(c, m[j], z);
  }
  zk_eq(c, sum, u);
  a = zk_sub(c, w, k3);
  b = zk_sub(c, w, k4);
  zk_eq(c, zk_mul(c, a, b), z);
  a = zk_sub(c, k4, w);
  zk_eq(c, zk_mul(c, m[3], a), z);
}

void zk_gballotfull(ZkCircuit *c) {
  const ZkFr delta = pow2(ZK_PKE_DELTA_LOG);
  uint32_t pa[ZK_PKE_N], pb[ZK_PKE_N], r[ZK_PKE_N], m[ZK_PKE_SLOTS], dl, s, t, w, i;
  zk_init(c, ZK_GBALLOT_INPUTS, ZK_GBALLOTFULL_WEIGHTS, 2);
  gvote_body(c);
  for (i = 0; i < ZK_PKE_N / ZK_POSEIDON2_WORD_BITS; i++)
    (void)zk_word(c, ZK_GBALLOT_R + ZK_POSEIDON2_WORD_BITS * i, ZK_POSEIDON2_WORD_BITS);
  for (i = 0; i < ZK_PKE_N; i++) {
    r[i] = zk_weight(c, ZK_GBALLOT_R + i);
    pa[i] = zk_input(c, ZK_GBALLOT_IN_PKA + i);
    pb[i] = zk_input(c, ZK_GBALLOT_IN_PKB + i);
  }
  zk_onehot(c, zk_input(c, 2), ZK_GBALLOT_M, m);
  for (i = 0; i < ZK_PKE_N; i++) {
    s = zk_negacyclic(c, pa, r, i);
    w = zk_input(c, ZK_GBALLOT_IN_MASK + i);
    zk_lwe_word(c, s, NULL, w, ZK_GBALLOT_LWE + ZK_LWE_WEIGHTS * i);
  }
  dl = zk_const(c, &delta);
  for (i = 0; i < ZK_PKE_SLOTS; i++) {
    s = zk_negacyclic(c, pb, r, ZK_PKE_N - 1u - i);
    t = zk_mul(c, m[i], dl);
    w = zk_input(c, ZK_GBALLOT_IN_BODY + i);
    zk_lwe_word(c, s, &t, w, ZK_GBALLOT_LWE + ZK_LWE_WEIGHTS * (ZK_PKE_N + i));
  }
}

/* LO + 2^64 HI plus A (ADD 1) or minus A. */
static void wide_add(uint64_t *lo, int64_t *hi, uint64_t a, int add) {
  const uint64_t old = *lo;
  if (add) {
    *lo = old + a;
    *hi += *lo < old;
  } else {
    *lo = old - a;
    *hi -= *lo > old;
  }
}

/* The D22 weights of coefficient K of P phi_1(R) with error E and message
 * term M: the word (S + e + M) mod 2^64 is the return value, the quotient the
 * high part. */
static uint64_t lwe_fill(ZkFr *wt, const uint64_t *p, const uint8_t *r, uint32_t k, int64_t e, uint64_t m) {
  uint64_t lo = 0;
  int64_t hi = 0;
  uint32_t i;
  for (i = 0; i < ZK_PKE_N; i++)
    if (r[ZK_PKE_N - 1u - (k + ZK_PKE_N - i) % ZK_PKE_N]) wide_add(&lo, &hi, p[i], i <= k);
  wide_add(&lo, &hi, e < 0 ? 0u - (uint64_t)e : (uint64_t)e, e >= 0);
  wide_add(&lo, &hi, m, 1);
  zk_lwe_word_fill(wt, e, hi);
  return lo;
}

void zk_gballotfull_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, uint64_t u, const uint64_t *sib, uint32_t idx,
                         const uint64_t *pk_a, const uint64_t *pk_b, const uint8_t *r, const uint8_t *m,
                         const int64_t *e1, const int64_t *e2, uint64_t root[4], uint64_t nf[4], uint64_t *words) {
  uint32_t i;
  zk_gvote_fill(wt, key, e, u, sib, idx, root, nf);
  for (i = 0; i < ZK_PKE_N; i++) wt[ZK_GBALLOT_R + i] = zk_fr_u64(r[i]);
  for (i = 0; i < ZK_PKE_SLOTS; i++) wt[ZK_GBALLOT_M + i] = zk_fr_u64(m[i]);
  for (i = 0; i < ZK_PKE_N; i++) words[i] = lwe_fill(wt + ZK_GBALLOT_LWE + ZK_LWE_WEIGHTS * i, pk_a, r, i, e1[i], 0);
  for (i = 0; i < ZK_PKE_SLOTS; i++)
    words[ZK_PKE_N + i] = lwe_fill(wt + ZK_GBALLOT_LWE + ZK_LWE_WEIGHTS * (ZK_PKE_N + i), pk_b, r, ZK_PKE_N - 1u - i,
                                   e2[i], (uint64_t)m[i] << ZK_PKE_DELTA_LOG);
}

/* The 32 zk_word of r at W0 (their values to RW) and the bit values to R. */
static void r_words(ZkCircuit *c, uint32_t w0, uint32_t rw[ZK_CR_WORDS], uint32_t r[ZK_PKE_N]) {
  uint32_t i;
  for (i = 0; i < ZK_CR_WORDS; i++) rw[i] = zk_word(c, w0 + ZK_POSEIDON2_WORD_BITS * i, ZK_POSEIDON2_WORD_BITS);
  for (i = 0; i < ZK_PKE_N; i++) r[i] = zk_weight(c, w0 + i);
}

void zk_gmask(ZkCircuit *c) {
  uint32_t ap[ZK_PKE_N], r[ZK_PKE_N], rw[ZK_CR_WORDS], s, w, t;
  zk_init(c, ZK_GMASK_INPUTS, ZK_GMASK_WEIGHTS, 1);
  r_words(c, 0, rw, r);
  for (t = 0; t < ZK_PKE_N; t++) ap[t] = zk_input(c, t);
  for (t = 0; t < ZK_GMASK_SPAN; t++) {
    s = zk_negacyclic(c, ap, r, t);
    w = zk_input(c, ZK_GMASK_IN_MASK + t);
    zk_lwe_word(c, s, NULL, w, ZK_GMASK_LWE + ZK_LWE_WEIGHTS * t);
  }
  zk_out(c, 0, zk_poseidon2_hash_values(c, ZK_CR_TAG, ZK_CR_WORDS, rw));
}

void zk_gballot(ZkCircuit *c) {
  const ZkFr delta = pow2(ZK_PKE_DELTA_LOG);
  uint32_t pb[ZK_PKE_N], r[ZK_PKE_N], rw[ZK_CR_WORDS], m[ZK_PKE_SLOTS], dl, s, t, w, i;
  zk_init(c, ZK_GB_INPUTS, ZK_GB_WEIGHTS, 3);
  gvote_body(c);
  r_words(c, ZK_GBALLOT_R, rw, r);
  for (i = 0; i < ZK_PKE_N; i++) pb[i] = zk_input(c, ZK_GB_IN_PKB + i);
  zk_onehot(c, zk_input(c, 2), ZK_GBALLOT_M, m);
  dl = zk_const(c, &delta);
  for (i = 0; i < ZK_PKE_SLOTS; i++) {
    s = zk_negacyclic(c, pb, r, ZK_PKE_N - 1u - i);
    t = zk_mul(c, m[i], dl);
    w = zk_input(c, ZK_GB_IN_BODY + i);
    zk_lwe_word(c, s, &t, w, ZK_GBALLOT_LWE + ZK_LWE_WEIGHTS * i);
  }
  zk_out(c, 2, zk_poseidon2_hash_values(c, ZK_CR_TAG, ZK_CR_WORDS, rw));
}

void zk_pke_commit(const uint8_t *r, uint64_t cr[4]) {
  uint64_t rw[ZK_CR_WORDS];
  uint32_t i;
  Fr d;
  memset(rw, 0, sizeof rw);
  for (i = 0; i < ZK_PKE_N; i++)
    rw[i / ZK_POSEIDON2_WORD_BITS] |= (uint64_t)(r[i] & 1u) << (i % ZK_POSEIDON2_WORD_BITS);
  poseidon2_hash(ZK_CR_TAG, rw, ZK_CR_WORDS, &d);
  fr_to_words(&d, cr);
}

void zk_gmask_fill(ZkFr *wt, const uint64_t *ap, const uint8_t *r, const int64_t *e1, uint64_t *words, uint64_t cr[4]) {
  uint32_t i;
  for (i = 0; i < ZK_PKE_N; i++) wt[i] = zk_fr_u64(r[i]);
  for (i = 0; i < ZK_GMASK_SPAN; i++) words[i] = lwe_fill(wt + ZK_GMASK_LWE + ZK_LWE_WEIGHTS * i, ap, r, i, e1[i], 0);
  zk_pke_commit(r, cr);
}

void zk_gballot_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, uint64_t u, const uint64_t *sib, uint32_t idx,
                     const uint64_t *pk_b, const uint8_t *r, const uint8_t *m, const int64_t *e2, uint64_t root[4],
                     uint64_t nf[4], uint64_t cr[4], uint64_t *words) {
  uint32_t i;
  zk_gvote_fill(wt, key, e, u, sib, idx, root, nf);
  for (i = 0; i < ZK_PKE_N; i++) wt[ZK_GBALLOT_R + i] = zk_fr_u64(r[i]);
  for (i = 0; i < ZK_PKE_SLOTS; i++) wt[ZK_GBALLOT_M + i] = zk_fr_u64(m[i]);
  for (i = 0; i < ZK_PKE_SLOTS; i++)
    words[i] = lwe_fill(wt + ZK_GBALLOT_LWE + ZK_LWE_WEIGHTS * i, pk_b, r, ZK_PKE_N - 1u - i, e2[i],
                        (uint64_t)m[i] << ZK_PKE_DELTA_LOG);
  zk_pke_commit(r, cr);
}

void zk_gvote_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, uint64_t u, const uint64_t *sib,
                   uint32_t idx, uint64_t root[4], uint64_t nf[4]) {
  uint64_t v[ZK_DIGEST_WORDS + 2];
  Fr d;
  memcpy(v, key, ZK_DIGEST_WORDS * sizeof v[0]);
  v[ZK_DIGEST_WORDS] = e;
  v[ZK_DIGEST_WORDS + 1] = u;
  zk_digest_fill(wt, key);
  zk_poseidon2_hash_fill(wt + ZK_DIGEST_WEIGHTS, v + ZK_DIGEST_WORDS, 2);
  zk_member_fill(wt + ZK_DIGEST_WEIGHTS + 2 * ZK_POSEIDON2_WORD_BITS, key, sib, idx, root);
  poseidon2_hash(4, v, ZK_DIGEST_WORDS + 2, &d);
  fr_to_words(&d, nf);
}

void zk_gmotion(ZkCircuit *c) {
  uint32_t v[2 * ZK_DIGEST_WORDS + 1];
  zk_init(c, 2, ZK_GMOTION_WEIGHTS, 2);
  zk_digest(c, 0, v);
  v[ZK_DIGEST_WORDS] = zk_word(c, ZK_DIGEST_WEIGHTS, ZK_POSEIDON2_WORD_BITS);
  zk_eq(c, v[ZK_DIGEST_WORDS], zk_input(c, 0));
  zk_digest(c, ZK_DIGEST_WEIGHTS + ZK_POSEIDON2_WORD_BITS, v + ZK_DIGEST_WORDS + 1);
  zk_eq(c, zk_recompose(c, v + ZK_DIGEST_WORDS + 1), zk_input(c, 1));
  zk_out(c, 0, zk_member(c, v, 2 * ZK_DIGEST_WEIGHTS + ZK_POSEIDON2_WORD_BITS));
  zk_out(c, 1, zk_poseidon2_hash_values(c, 6, 2 * ZK_DIGEST_WORDS + 1, v));
}

void zk_gmotion_fill(ZkFr *wt, const uint64_t key[4], uint64_t e, const uint64_t ctx[4],
                     const uint64_t *sib, uint32_t idx, uint64_t root[4], uint64_t mt[4]) {
  uint64_t v[2 * ZK_DIGEST_WORDS + 1];
  Fr d;
  memcpy(v, key, ZK_DIGEST_WORDS * sizeof v[0]);
  v[ZK_DIGEST_WORDS] = e;
  memcpy(v + ZK_DIGEST_WORDS + 1, ctx, ZK_DIGEST_WORDS * sizeof v[0]);
  zk_digest_fill(wt, key);
  zk_poseidon2_hash_fill(wt + ZK_DIGEST_WEIGHTS, &e, 1);
  zk_digest_fill(wt + ZK_DIGEST_WEIGHTS + ZK_POSEIDON2_WORD_BITS, ctx);
  zk_member_fill(wt + 2 * ZK_DIGEST_WEIGHTS + ZK_POSEIDON2_WORD_BITS, key, sib, idx, root);
  poseidon2_hash(6, v, 2 * ZK_DIGEST_WORDS + 1, &d);
  fr_to_words(&d, mt);
}

/* D7: SHA-512. A word is its 64 bit values (bit 0 low) and its value. */
typedef struct ShaWord {
  uint32_t bit[64];
  uint32_t value;
} ShaWord;

/* The circuit, the constants 0 and 1, and the next weight. */
typedef struct Sha {
  ZkCircuit *c;
  uint32_t zero;
  uint32_t one;
  uint32_t w;
} Sha;

static uint32_t sha_blocks(uint32_t n) { return (n + 16) / 128 + 1; }

/* Byte P of the padded message of LEN bytes (FIPS 180-4 5.1.2): the N
 * bytes, 0x80, zeros, then the bit length 8 N in the last 8 bytes. */
static uint8_t sha_pad(const uint8_t *bytes, uint32_t n, uint32_t len, uint32_t p) {
  if (p < n) return bytes[p];
  if (p == n) return 0x80u;
  if (p + 8 >= len) return (uint8_t)(((uint64_t)n << 3) >> (8 * (len - 1 - p)));
  return 0;
}

static uint32_t sha_split_weights(uint32_t k) {
  const ZkFr hi = zk_fr_u64(k - 1);
  return zk_split_weights(64, &hi);
}

/* Horner from bit 63 down: acc = 2 acc + b. */
static uint32_t sha_horner(Sha *s, uint32_t acc, uint32_t b, uint32_t k) {
  uint32_t twice;
  if (k == 63) return b;
  twice = zk_add(s->c, acc, acc);
  return zk_add(s->c, twice, b);
}

/* A xor B = a + b - 2 a b; *AB gets a b. */
static uint32_t sha_xor(Sha *s, uint32_t a, uint32_t b, uint32_t *ab) {
  uint32_t t, u;
  *ab = zk_mul(s->c, a, b);
  t = zk_add(s->c, a, b);
  u = zk_sub(s->c, t, *ab);
  return zk_sub(s->c, u, *ab);
}

static uint32_t sha_value(Sha *s, const ShaWord *x) {
  uint32_t acc = 0, i;
  for (i = 64; i > 0; i--)
    acc = sha_horner(s, acc, x->bit[i - 1], i - 1);
  return acc;
}

static void sha_const_word(Sha *s, uint64_t v, ShaWord *r) {
  const ZkFr k = zk_fr_u64(v);
  uint32_t i;
  for (i = 0; i < 64; i++)
    r->bit[i] = ((v >> i) & 1u) ? s->one : s->zero;
  r->value = zk_const(s->c, &k);
}

/* ROTR^R0 ^ ROTR^R1 ^ (SHR^R2 when SHR, else ROTR^R2) of X, as a value. */
static uint32_t sha_sigma(Sha *s, const ShaWord *x, uint32_t r0, uint32_t r1, uint32_t r2, int shr) {
  uint32_t acc = 0, ab, u, i, k;
  for (i = 64; i > 0; i--) {
    k = i - 1;
    u = sha_xor(s, x->bit[(k + r0) % 64], x->bit[(k + r1) % 64], &ab);
    if (!shr || k + r2 < 64) u = sha_xor(s, u, x->bit[(k + r2) % 64], &ab);
    acc = sha_horner(s, acc, u, k);
  }
  return acc;
}

/* Ch(e, f, g) = G + sum 2^k e_k (f_k - g_k). */
static uint32_t sha_ch(Sha *s, const ShaWord *e, const ShaWord *f, const ShaWord *g) {
  uint32_t acc = 0, d, m, i;
  for (i = 64; i > 0; i--) {
    d = zk_sub(s->c, f->bit[i - 1], g->bit[i - 1]);
    m = zk_mul(s->c, e->bit[i - 1], d);
    acc = sha_horner(s, acc, m, i - 1);
  }
  return zk_add(s->c, g->value, acc);
}

/* Maj(a, b, x) bit k = a_k b_k + x_k (a_k xor b_k). */
static uint32_t sha_maj(Sha *s, const ShaWord *a, const ShaWord *b, const ShaWord *x) {
  uint32_t acc = 0, ab, u, m, t, i;
  for (i = 64; i > 0; i--) {
    u = sha_xor(s, a->bit[i - 1], b->bit[i - 1], &ab);
    m = zk_mul(s->c, x->bit[i - 1], u);
    t = zk_add(s->c, ab, m);
    acc = sha_horner(s, acc, t, i - 1);
  }
  return acc;
}

/* SUM of K words = carry 2^64 + r with carry in [0, K - 1]; R gets r. */
static void sha_split(Sha *s, uint32_t sum, uint32_t k, ShaWord *r) {
  const ZkFr hi = zk_fr_u64(k - 1);
  uint32_t hiv, i;
  r->value = zk_split(s->c, sum, 64, &hi, s->w, &hiv);
  for (i = 0; i < 64; i++)
    r->bit[i] = zk_weight(s->c, s->w + i);
  s->w += zk_split_weights(64, &hi);
}

/* FIPS 180-4 6.4.2 on block B of the padded message of LEN bytes. */
static void sha_block(Sha *s, ShaWord h[8], uint32_t n, uint32_t len, uint32_t w0, uint32_t b) {
  ShaWord w[80], v[8], ne, na;
  ZkFr kt;
  uint32_t t, i, p, j, k, s0, s1, chv, mj, t1, es, as, sum;
  for (t = 0; t < 16; t++) {
    for (i = 0; i < 64; i++) {
      p = 128 * b + 8 * t + 7 - i / 8;
      j = i % 8;
      if (p < n)
        w[t].bit[i] = zk_weight(s->c, w0 + 8 * p + j);
      else
        w[t].bit[i] = ((sha_pad(NULL, n, len, p) >> j) & 1u) ? s->one : s->zero;
    }
    w[t].value = sha_value(s, &w[t]);
  }
  for (t = 16; t < 80; t++) {
    s1 = sha_sigma(s, &w[t - 2], 19, 61, 6, 1);
    s0 = sha_sigma(s, &w[t - 15], 1, 8, 7, 1);
    sum = zk_add(s->c, s1, w[t - 7].value);
    sum = zk_add(s->c, sum, s0);
    sum = zk_add(s->c, sum, w[t - 16].value);
    sha_split(s, sum, 4, &w[t]);
  }
  memcpy(v, h, sizeof v);
  for (t = 0; t < 80; t++) {
    kt = zk_fr_u64(sha512_round_constant(t));
    s1 = sha_sigma(s, &v[4], 14, 18, 41, 0);
    chv = sha_ch(s, &v[4], &v[5], &v[6]);
    k = zk_const(s->c, &kt);
    t1 = zk_add(s->c, v[7].value, s1);
    t1 = zk_add(s->c, t1, chv);
    t1 = zk_add(s->c, t1, k);
    t1 = zk_add(s->c, t1, w[t].value);
    s0 = sha_sigma(s, &v[0], 28, 34, 39, 0);
    mj = sha_maj(s, &v[0], &v[1], &v[2]);
    es = zk_add(s->c, v[3].value, t1);
    as = zk_add(s->c, t1, s0);
    as = zk_add(s->c, as, mj);
    sha_split(s, es, 6, &ne);
    sha_split(s, as, 7, &na);
    memmove(&v[1], &v[0], 7 * sizeof v[0]);
    v[0] = na;
    v[4] = ne;
  }
  for (i = 0; i < 8; i++) {
    sum = zk_add(s->c, h[i].value, v[i].value);
    sha_split(s, sum, 2, &h[i]);
  }
}

/* The weights of one block: the schedule, the rounds, the chaining adds. */
static uint32_t sha_block_weights(void) {
  return 64 * sha_split_weights(4) + 80 * (sha_split_weights(6) + sha_split_weights(7)) + 8 * sha_split_weights(2);
}

uint32_t zk_sha512_weights(uint32_t n) {
  if (n > ZK_SHA512_BYTES_MAX) return 0;
  return 8 * n + sha_blocks(n) * sha_block_weights();
}

void zk_sha512(ZkCircuit *c, uint32_t n, uint32_t w0, uint32_t digest[8]) {
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1);
  const uint32_t m = zk_sha512_weights(n);
  ShaWord h[8];
  Sha s;
  uint32_t b, p, i;
  memset(digest, 0, 8 * sizeof digest[0]);
  if (c->err != ZK_OK) return;
  if (m == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (w0 > c->weights || m > c->weights - w0) {
    fail(c, ZK_ERR_REF);
    return;
  }
  s.c = c;
  s.zero = zk_const(c, &zero);
  s.one = zk_const(c, &one);
  s.w = w0 + 8 * n;
  for (p = 0; p < n; p++)
    (void)zk_word(c, w0 + 8 * p, 8);
  for (i = 0; i < 8; i++)
    sha_const_word(&s, sha512_initial_hash(i), &h[i]);
  for (b = 0; b < sha_blocks(n); b++)
    sha_block(&s, h, n, 128 * sha_blocks(n), w0, b);
  if (c->err != ZK_OK) return;
  for (i = 0; i < 8; i++)
    digest[i] = h[i].value;
}

static uint64_t sha_rotr(uint64_t x, uint32_t n) { return (x >> n) | (x << (64u - n)); }

static uint64_t sha_sigma64(uint64_t x, uint32_t r0, uint32_t r1, uint32_t r2, int shr) {
  return sha_rotr(x, r0) ^ sha_rotr(x, r1) ^ (shr ? x >> r2 : sha_rotr(x, r2));
}

static uint64_t sha_ch64(uint64_t e, uint64_t f, uint64_t g) { return (e & f) ^ (~e & g); }

static uint64_t sha_maj64(uint64_t a, uint64_t b, uint64_t x) { return (a & b) ^ (a & x) ^ (b & x); }

/* The zk_split fill of the sum of the K words T; R gets the sum mod 2^64.
 * Returns the weight count. */
static uint32_t sha_fill_split(ZkFr *wt, const uint64_t *t, uint32_t k, uint64_t *r) {
  const ZkFr hi = zk_fr_u64(k - 1);
  ZkFr sum = zk_fr_u64(t[0]), x;
  uint64_t acc = t[0];
  uint32_t i;
  for (i = 1; i < k; i++) {
    x = zk_fr_u64(t[i]);
    sum = zk_fr_add(&sum, &x);
    acc += t[i];
  }
  zk_split_fill(wt, &sum, 64, &hi);
  *r = acc;
  return zk_split_weights(64, &hi);
}

/* The weights of block B of the padded message of LEN bytes from the chaining
 * words H; H gets the chaining words after the block. Returns the count. */
static uint32_t sha_fill_block(ZkFr *wt, uint64_t h[8], const uint8_t *bytes, uint32_t n, uint32_t len, uint32_t b) {
  uint64_t w[80], v[8], te[6], ta[7], t4[4], t2[2], ne, na;
  uint32_t t, i, j, off = 0;
  for (t = 0; t < 16; t++) {
    w[t] = 0;
    for (j = 0; j < 8; j++)
      w[t] = (w[t] << 8) | sha_pad(bytes, n, len, 128 * b + 8 * t + j);
  }
  for (t = 16; t < 80; t++) {
    t4[0] = sha_sigma64(w[t - 2], 19, 61, 6, 1);
    t4[1] = w[t - 7];
    t4[2] = sha_sigma64(w[t - 15], 1, 8, 7, 1);
    t4[3] = w[t - 16];
    off += sha_fill_split(wt + off, t4, 4, &w[t]);
  }
  memcpy(v, h, sizeof v);
  for (t = 0; t < 80; t++) {
    ta[0] = v[7];
    ta[1] = sha_sigma64(v[4], 14, 18, 41, 0);
    ta[2] = sha_ch64(v[4], v[5], v[6]);
    ta[3] = sha512_round_constant(t);
    ta[4] = w[t];
    ta[5] = sha_sigma64(v[0], 28, 34, 39, 0);
    ta[6] = sha_maj64(v[0], v[1], v[2]);
    te[0] = v[3];
    memcpy(te + 1, ta, 5 * sizeof ta[0]);
    off += sha_fill_split(wt + off, te, 6, &ne);
    off += sha_fill_split(wt + off, ta, 7, &na);
    memmove(v + 1, v, 7 * sizeof v[0]);
    v[0] = na;
    v[4] = ne;
  }
  for (i = 0; i < 8; i++) {
    t2[0] = h[i];
    t2[1] = v[i];
    off += sha_fill_split(wt + off, t2, 2, &h[i]);
  }
  return off;
}

void zk_sha512_fill(ZkFr *wt, const uint8_t *bytes, uint32_t n) {
  const uint32_t len = 128 * sha_blocks(n);
  uint64_t h[8];
  uint32_t p, b, i, off;
  ZkFr x;
  if (n > ZK_SHA512_BYTES_MAX) return;
  for (p = 0; p < n; p++) {
    x = zk_fr_u64(bytes[p]);
    zk_bits_fill(wt + 8 * p, &x, 8);
  }
  off = 8 * n;
  for (i = 0; i < 8; i++)
    h[i] = sha512_initial_hash(i);
  for (b = 0; b < sha_blocks(n); b++)
    off += sha_fill_block(wt + off, h, bytes, n, len, b);
}

/* S7 U5 L1. The message bytes of blocks B0 .. B0 + NB - 1. */
static uint32_t sha_chunk_bytes(uint32_t n, uint32_t b0, uint32_t nb) {
  const uint32_t lo = 128 * b0, hi = 128 * (b0 + nb) < n ? 128 * (b0 + nb) : n;
  return hi > lo ? hi - lo : 0;
}

uint32_t zk_sha512_chunk_weights(uint32_t n, uint32_t b0, uint32_t nb) {
  if (n > ZK_SHA512_BYTES_MAX || nb == 0 || b0 >= sha_blocks(n) || nb > sha_blocks(n) - b0) return 0;
  return 8 * sha_chunk_bytes(n, b0, nb) + 8 * 64 + nb * sha_block_weights();
}

void zk_sha512_chunk(ZkCircuit *c, uint32_t n, uint32_t b0, uint32_t nb, uint32_t w0, const uint32_t hin[8],
                     uint32_t hout[8], uint32_t *byte) {
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1);
  const uint32_t m = zk_sha512_chunk_weights(n, b0, nb), nm = sha_chunk_bytes(n, b0, nb);
  ShaWord h[8];
  Sha s;
  uint32_t b, p, i, j, hw;
  memset(hout, 0, 8 * sizeof hout[0]);
  if (c->err != ZK_OK) return;
  if (m == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (w0 > c->weights || m > c->weights - w0) {
    fail(c, ZK_ERR_REF);
    return;
  }
  s.c = c;
  s.zero = zk_const(c, &zero);
  s.one = zk_const(c, &one);
  hw = w0 + 8 * nm;
  s.w = hw + 8 * 64;
  for (p = 0; p < nm; p++) {
    const uint32_t v = zk_word(c, w0 + 8 * p, 8);
    if (byte != NULL) byte[p] = v;
  }
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 64; j++)
      h[i].bit[j] = zk_weight(c, hw + 64 * i + j);
    h[i].value = zk_word(c, hw + 64 * i, 64);
    zk_eq(c, h[i].value, hin[i]);
  }
  /* Byte p of block b reads weight base + 8 p with base = W0 - 1024 B0: a
   * uint32_t wrap (defined in C99) that puts byte 128 B0 at W0. */
  for (b = b0; b < b0 + nb; b++)
    sha_block(&s, h, n, 128 * sha_blocks(n), w0 - 1024 * b0, b);
  if (c->err != ZK_OK) return;
  for (i = 0; i < 8; i++)
    hout[i] = h[i].value;
}

void zk_sha512_chunk_fill(ZkFr *wt, const uint8_t *bytes, uint32_t n, uint32_t b0, uint32_t nb, const uint64_t hin[8],
                          uint64_t hout[8]) {
  const uint32_t len = 128 * sha_blocks(n), nm = sha_chunk_bytes(n, b0, nb);
  uint32_t p, b, i, off;
  ZkFr x;
  memmove(hout, hin, 8 * sizeof hout[0]);
  if (zk_sha512_chunk_weights(n, b0, nb) == 0) return;
  for (p = 0; p < nm; p++) {
    x = zk_fr_u64(bytes[128 * b0 + p]);
    zk_bits_fill(wt + 8 * p, &x, 8);
  }
  off = 8 * nm;
  for (i = 0; i < 8; i++) {
    x = zk_fr_u64(hin[i]);
    zk_bits_fill(wt + off + 64 * i, &x, 64);
  }
  off += 8 * 64;
  for (b = b0; b < b0 + nb; b++)
    off += sha_fill_block(wt + off, hout, bytes, n, len, b);
}

/* S7 U5 D37. */
void zk_party(ZkCircuit *c, uint32_t p) {
  const ZkFr zero = zk_fr_u64(0);
  uint32_t d, f, acc = 0;
  for (d = 1; d <= ZK_TDEC_PARTIES; d++) {
    const ZkFr k = zk_fr_u64(d);
    f = zk_sub(c, p, zk_const(c, &k));
    acc = d == 1 ? f : zk_mul(c, acc, f);
  }
  zk_eq(c, acc, zk_const(c, &zero));
}

/* S7 U5 D39. */
uint32_t zk_noise_commit(ZkCircuit *c, uint32_t p, uint32_t d, const uint32_t nl[3]) {
  const ZkFr k = zk_fr_u64(d);
  uint32_t x[5];
  x[0] = p;
  x[1] = zk_const(c, &k);
  memcpy(x + 2, nl, 3 * sizeof x[0]);
  return zk_poseidon2_hash_values(c, ZK_CN_TAG, 5, x);
}

/* S7 U5 D49: the integer of the L bytes at BYTE + O, low byte first (Horner
 * with the constant 256 at T8: L - 1 MUL and L - 1 ADD). */
static uint32_t split_piece(ZkCircuit *c, const uint32_t *byte, uint32_t o, uint32_t l, uint32_t t8) {
  uint32_t acc = byte[o + l - 1], t;
  for (t = l - 1; t > 0; t--)
    acc = zk_add(c, zk_mul(c, acc, t8), byte[o + t - 1]);
  return acc;
}

/* S7 U5 D48 to D54. */
uint32_t zk_gchunk_weights(uint32_t k) {
  const uint32_t ms =
      k < ZK_SPLIT_CHUNKS ? zk_sha512_chunk_weights(ZK_SPLIT_BYTES, 3 * k, k + 1 < ZK_SPLIT_CHUNKS ? 3 : 1) : 0;
  return ms == 0 ? 0 : ms + 1 + (k + 1 < ZK_SPLIT_CHUNKS ? 1 : 0) + (k > 0 ? 9 : 0);
}

void zk_gchunk(ZkCircuit *c, uint32_t k) {
  const ZkFr one = zk_fr_u64(1), t8 = zk_fr_u64(256);
  const int last = k + 1 == ZK_SPLIT_CHUNKS;
  const uint32_t m = zk_gchunk_weights(k);
  const uint32_t ms = m == 0 ? 0 : zk_sha512_chunk_weights(ZK_SPLIT_BYTES, 3 * k, last ? 1 : 3);
  const uint32_t ws = ms + (k > 0 ? 8 : 0);
  uint32_t byte[ZK_SPLIT_CHUNK_BYTES], x[52], hin[8], hout[8], h[11], p, kv, t8v, n, i;
  if (c->err != ZK_OK) return;
  if (m == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (m > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  p = zk_input(c, 0);
  kv = zk_input(c, 1);
  zk_party(c, p);
  for (i = 0; i < 8; i++) {
    const ZkFr iv = zk_fr_u64(sha512_initial_hash(i));
    hin[i] = k > 0 ? zk_weight(c, ms + i) : zk_const(c, &iv);
  }
  zk_sha512_chunk(c, ZK_SPLIT_BYTES, 3 * k, last ? 1 : 3, 0, hin, hout, byte);
  if (c->err != ZK_OK) return;
  t8v = zk_const(c, &t8);
  x[0] = zk_weight(c, ws);
  x[1] = p;
  x[2] = kv;
  n = 3;
  if (k == 0)
    zk_eq(c, split_piece(c, byte, 0, 4, t8v), p);
  else
    x[n++] = split_piece(c, byte, 0, 4, t8v);
  if (!last) {
    for (i = 0; i < 47; i++)
      x[n++] = split_piece(c, byte, 4 + 8 * i, 8, t8v);
    x[n++] = split_piece(c, byte, 380, 4, t8v);
  }
  zk_out(c, 0, zk_poseidon2_hash_values(c, ZK_CS_TAG, n, x));
  h[1] = p;
  if (k > 0) {
    h[0] = zk_weight(c, ws + (last ? 1 : 2));
    h[2] = zk_sub(c, kv, zk_const(c, &one));
    memcpy(h + 3, hin, sizeof hin);
    zk_eq(c, zk_poseidon2_hash_values(c, ZK_CH_TAG, 11, h), zk_input(c, 2));
  }
  if (last) {
    for (i = 0; i < 8; i++)
      zk_out(c, 1 + i, hout[i]);
  } else {
    h[0] = zk_weight(c, ws + 1);
    h[2] = kv;
    memcpy(h + 3, hout, sizeof hout);
    zk_out(c, 1, zk_poseidon2_hash_values(c, ZK_CH_TAG, 11, h));
  }
}

void zk_gchunk_fill(ZkFr *wt, const uint8_t *msg, uint32_t k, const uint64_t hin[8], const ZkFr salt[3],
                    uint64_t hout[8]) {
  const int last = k + 1 == ZK_SPLIT_CHUNKS;
  uint32_t off, i;
  if (zk_gchunk_weights(k) == 0) {
    memmove(hout, hin, 8 * sizeof hout[0]);
    return;
  }
  zk_sha512_chunk_fill(wt, msg, ZK_SPLIT_BYTES, 3 * k, last ? 1 : 3, hin, hout);
  off = zk_sha512_chunk_weights(ZK_SPLIT_BYTES, 3 * k, last ? 1 : 3);
  if (k > 0)
    for (i = 0; i < 8; i++)
      wt[off++] = zk_fr_u64(hin[i]);
  wt[off++] = salt[0];
  if (!last) wt[off++] = salt[1];
  if (k > 0) wt[off] = salt[2];
}

/* S7 U5 D51, D52: the piece count of chunk K and the native piece (the
 * integer of the L bytes at B, low byte first). */
static uint32_t gslice_pieces(uint32_t k) {
  return k == 0 ? 48 : k + 1 < ZK_SPLIT_CHUNKS ? 49 : 1;
}

static uint64_t gslice_piece_u64(const uint8_t *b, uint32_t l) {
  uint64_t v = 0;
  uint32_t t;
  for (t = l; t > 0; t--)
    v = v << 8 | b[t - 1];
  return v;
}

/* S7 U5 D52 to D54. */
uint32_t zk_gslice_weights(uint32_t j) {
  uint32_t m = 0, t;
  if (j >= ZK_SPLIT_SLICES) return 0;
  for (t = 0; t <= ZK_SPLIT_SLICE_CHUNKS; t++)
    m += 1 + gslice_pieces(ZK_SPLIT_SLICE_CHUNKS * j + t);
  return m + (j > 0 ? 5 : 0) + (j + 1 < ZK_SPLIT_SLICES ? 1 : 5 * ZK_FP_WEIGHTS + ZK_TDEC_WEIGHTS);
}

void zk_gslice(ZkCircuit *c, uint32_t j) {
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1), t16 = zk_fr_u64(ZK_SPLIT_SLICE_CHUNKS), t32 = pow2(32);
  const int last = j + 1 == ZK_SPLIT_SLICES;
  const uint32_t m = zk_gslice_weights(j), mi = 3 + ZK_SPLIT_SLICE_CHUNKS + (j > 0 ? 1 : 0);
  uint32_t s[3 * ZK_SPLIT_SLICE_COORDS], mw[2 * ZK_SPLIT_SLICE_COORDS], x[52], h[7], col[4], b[5], nl[15], v[3];
  uint32_t p, jv, kv = 0, zv, onev, t16v, t32v, lo = 0, w = 0, n, f, t, i;
  if (c->err != ZK_OK) return;
  if (m == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (m > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  p = zk_input(c, 0);
  jv = zk_input(c, 1);
  zk_party(c, p);
  for (i = 0; i < 2 * ZK_SPLIT_SLICE_COORDS; i++)
    mw[i] = zk_input(c, mi + i);
  zv = zk_const(c, &zero);
  onev = zk_const(c, &one);
  t16v = zk_const(c, &t16);
  t32v = zk_const(c, &t32);
  x[1] = p;
  for (t = 0; t <= ZK_SPLIT_SLICE_CHUNKS; t++) {
    const uint32_t k = ZK_SPLIT_SLICE_CHUNKS * j + t;
    n = gslice_pieces(k);
    f = k > 0 ? 4 : 3;
    kv = t == 0 ? zk_mul(c, jv, t16v) : zk_add(c, kv, onev);
    x[0] = zk_weight(c, w);
    x[2] = kv;
    for (i = 0; i < n; i++)
      x[3 + i] = zk_weight(c, w + 1 + i);
    w += 1 + n;
    zk_eq(c, zk_poseidon2_hash_values(c, ZK_CS_TAG, 3 + n, x), zk_input(c, 2 + t));
    if (t > 0) s[48 * t - 1] = zk_add(c, lo, zk_mul(c, x[3], t32v));
    if (t < ZK_SPLIT_SLICE_CHUNKS) {
      for (i = 0; i < 47; i++)
        s[48 * t + i] = x[f + i];
      lo = x[f + 47];
    }
  }
  if (c->err != ZK_OK) return;
  h[1] = p;
  if (j > 0) {
    h[0] = zk_weight(c, w);
    h[2] = zk_sub(c, jv, onev);
    for (i = 0; i < 4; i++)
      h[3 + i] = col[i] = zk_weight(c, w + 1 + i);
    w += 5;
    zk_eq(c, zk_poseidon2_hash_values(c, ZK_CA_TAG, 7, h), zk_input(c, 3 + ZK_SPLIT_SLICE_CHUNKS));
  } else {
    for (i = 0; i < 4; i++)
      col[i] = zv;
  }
  if (!last) {
    zk_tdec_cols(c, ZK_SPLIT_SLICE_COORDS, s, mw, col);
    h[0] = zk_weight(c, w);
    h[2] = jv;
    memcpy(h + 3, col, sizeof col);
    zk_out(c, 0, zk_poseidon2_hash_values(c, ZK_CA_TAG, 7, h));
    return;
  }
  for (i = 0; i < ZK_TDEC_PARTIES; i++) {
    b[i] = zk_input(c, mi + 2 * ZK_SPLIT_SLICE_COORDS + i);
    zk_eq(c, zk_mul(c, b[i], zk_sub(c, b[i], onev)), zv);
  }
  for (i = 0; i < ZK_TDEC_PARTIES; i++)
    (void)zk_fp(c, w + ZK_FP_WEIGHTS * i, nl + 3 * i);
  zk_tdec_reduce_from(c, col, ZK_SPLIT_SLICE_COORDS, s, mw, b, nl, w + ZK_TDEC_PARTIES * ZK_FP_WEIGHTS, v);
  for (i = 0; i < 3; i++)
    zk_eq(c, v[i], zk_input(c, mi + 2 * ZK_SPLIT_SLICE_COORDS + ZK_TDEC_PARTIES + i));
  for (i = 0; i < ZK_TDEC_PARTIES; i++)
    zk_out(c, i, zk_noise_commit(c, p, i + 1, nl + 3 * i));
}

void zk_gslice_fill(ZkFr *wt, const uint8_t *msg, uint32_t j, const ZkFr sigma[ZK_SPLIT_SLICE_CHUNKS + 1],
                    const ZkFr salt[2], const ZkFr a0[4]) {
  uint32_t w = 0, t, i;
  if (zk_gslice_weights(j) == 0) return;
  for (t = 0; t <= ZK_SPLIT_SLICE_CHUNKS; t++) {
    const uint32_t k = ZK_SPLIT_SLICE_CHUNKS * j + t;
    const uint8_t *cb = msg + ZK_SPLIT_CHUNK_BYTES * k;
    wt[w++] = sigma[t];
    if (k > 0) wt[w++] = zk_fr_u64(gslice_piece_u64(cb, 4));
    if (k + 1 < ZK_SPLIT_CHUNKS) {
      for (i = 0; i < 47; i++)
        wt[w++] = zk_fr_u64(gslice_piece_u64(cb + 4 + 8 * i, 8));
      wt[w++] = zk_fr_u64(gslice_piece_u64(cb + 380, 4));
    }
  }
  if (j > 0) {
    wt[w++] = salt[0];
    for (i = 0; i < 4; i++)
      wt[w++] = a0[i];
  }
  if (j + 1 < ZK_SPLIT_SLICES) wt[w] = salt[1];
}

/* S7 U5 D38 (L2): the product columns of N coordinates added into COL (6 MUL
 * and 6 ADD for each coordinate). */
static void tdec_cols(ZkCircuit *c, uint32_t n, const uint32_t *s, const uint32_t *m, uint32_t col[4]) {
  uint32_t i, a, j;
  for (i = 0; i < n; i++)
    for (a = 0; a < 2; a++)
      for (j = 0; j < 3; j++)
        col[a + j] = zk_add(c, col[a + j], zk_mul(c, m[2 * i + a], s[3 * i + j]));
}

/* S7 U5 D52, D53 (gap 3). */
void zk_tdec_cols(ZkCircuit *c, uint32_t n, const uint32_t *s, const uint32_t *m, uint32_t col[4]) {
  if (c->err != ZK_OK) return;
  if (n == 0 || n > ZK_TDEC_COORDS_MAX) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  tdec_cols(c, n, s, m, col);
}

/* S7 U5 D38 (L2). */
void zk_tdec_reduce(ZkCircuit *c, uint32_t n, const uint32_t *s, const uint32_t *m, const uint32_t b[5],
                    const uint32_t nl[15], uint32_t w0, uint32_t v[3]) {
  zk_tdec_reduce_from(c, NULL, n, s, m, b, nl, w0, v);
}

void zk_tdec_reduce_from(ZkCircuit *c, const uint32_t a0[4], uint32_t n, const uint32_t *s, const uint32_t *m,
                         const uint32_t b[5], const uint32_t nl[15], uint32_t w0, uint32_t v[3]) {
  const ZkFr zero = zk_fr_u64(0), t64 = pow2(64), off = pow2(ZK_TDEC_CARRY_BITS - 1), p = fp_const(0);
  const uint32_t wq = w0 + ZK_FP_WEIGHTS, wc = wq + ZK_TDEC_Q_BITS;
  uint32_t col[5], q[3], cy[4], pk[3], i, k, zv, t64v, offv, lhs, rhs;
  ZkFr pl;
  memset(v, 0, 3 * sizeof v[0]);
  if (c->err != ZK_OK) return;
  if (n == 0 || n > ZK_TDEC_COORDS_MAX) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (w0 > c->weights || ZK_TDEC_WEIGHTS > c->weights - w0) {
    fail(c, ZK_ERR_REF);
    return;
  }
  (void)zk_fp(c, w0, v);
  q[0] = zk_word(c, wq, 64);
  q[1] = zk_word(c, wq + 64, 64);
  q[2] = zk_word(c, wq + 128, ZK_TDEC_Q_BITS - 128);
  zv = zk_const(c, &zero);
  t64v = zk_const(c, &t64);
  offv = zk_const(c, &off);
  for (k = 0; k < 4; k++)
    cy[k] = zk_sub(c, zk_word(c, wc + ZK_TDEC_CARRY_BITS * k, ZK_TDEC_CARRY_BITS), offv);
  for (k = 0; k < 3; k++) {
    pl = fp_limb(&p, k);
    pk[k] = zk_const(c, &pl);
  }
  for (k = 0; k < 5; k++)
    col[k] = a0 != NULL && k < 4 ? a0[k] : zv;
  tdec_cols(c, n, s, m, col);
  for (i = 0; i < ZK_TDEC_PARTIES; i++)
    for (k = 0; k < 3; k++)
      col[k] = zk_add(c, col[k], zk_mul(c, b[i], nl[3 * i + k]));
  for (k = 0; k < 5; k++) {
    lhs = k > 0 ? zk_add(c, col[k], cy[k - 1]) : col[k];
    rhs = k < 3 ? v[k] : zv;
    for (i = 0; i < 3; i++)
      if (k >= i && k - i < 3) rhs = zk_add(c, rhs, zk_mul(c, q[i], pk[k - i]));
    if (k < 4) rhs = zk_add(c, rhs, zk_mul(c, cy[k], t64v));
    zk_eq(c, lhs, rhs);
  }
}

/* R = A B, low word first (32-bit halves: C99 has no 128-bit type). */
static void td_mul64(uint64_t a, uint64_t b, uint64_t r[2]) {
  const uint64_t al = a & 0xffffffffu, ah = a >> 32, bl = b & 0xffffffffu, bh = b >> 32;
  const uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
  const uint64_t mid = (ll >> 32) + (lh & 0xffffffffu) + (hl & 0xffffffffu);
  r[0] = (ll & 0xffffffffu) | (mid << 32);
  r[1] = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

/* X += Y mod 2^(64 K) (Y has N words, zero above). */
static void td_add(uint64_t *x, uint32_t k, const uint64_t *y, uint32_t n) {
  uint64_t cy = 0, t;
  uint32_t i;
  for (i = 0; i < k; i++) {
    t = x[i] + cy;
    cy = t < cy;
    x[i] = t + (i < n ? y[i] : 0);
    cy += x[i] < t;
  }
}

/* X -= Y mod 2^(64 K) (Y has N words, zero above). */
static void td_sub(uint64_t *x, uint32_t k, const uint64_t *y, uint32_t n) {
  uint64_t bw = 0, t, yi, nb;
  uint32_t i;
  for (i = 0; i < k; i++) {
    yi = i < n ? y[i] : 0;
    t = x[i] - yi;
    nb = x[i] < yi;
    x[i] = t - bw;
    nb |= t < bw;
    bw = nb;
  }
}

/* The 3 words of p, low first. */
static void td_p_words(uint64_t pw[3]) {
  const ZkFr p = fp_const(0);
  uint32_t j;
  for (j = 0; j < 3; j++)
    pw[j] = (uint64_t)p.limb[2 * j] | ((uint64_t)p.limb[2 * j + 1] << 32);
}

/* Q = X / p and X = X mod p by binary long division (X < p 2^142). */
static void td_divp(uint64_t x[6], uint64_t q[3]) {
  uint64_t pw[3], d[6];
  uint32_t e, j, sh;
  int ge;
  td_p_words(pw);
  memset(q, 0, 3 * sizeof q[0]);
  for (e = ZK_TDEC_Q_BITS; e-- > 0;) {
    memset(d, 0, sizeof d);
    sh = e % 64;
    for (j = 0; j < 3; j++) {
      d[j + e / 64] |= pw[j] << sh;
      if (sh != 0) d[j + e / 64 + 1] |= pw[j] >> (64 - sh);
    }
    ge = 1;
    for (j = 6; j-- > 0;)
      if (x[j] != d[j]) {
        ge = x[j] > d[j];
        break;
      }
    if (ge) {
      td_sub(x, 6, d, 6);
      q[e / 64] |= (uint64_t)1 << sh;
    }
  }
}

void zk_tdec_cols_fill(uint64_t col[][3], uint32_t n, const uint64_t *s, const uint64_t *m) {
  uint64_t r[2];
  uint32_t i, a, j;
  for (i = 0; i < n; i++)
    for (a = 0; a < 2; a++)
      for (j = 0; j < 3; j++) {
        td_mul64(m[2 * i + a], s[3 * i + j], r);
        td_add(col[a + j], 3, r, 2);
      }
}

void zk_tdec_reduce_fill(ZkFr *wt, uint32_t n, const uint64_t *s, const uint64_t *m, const uint64_t b[5],
                         const uint64_t nl[15], const uint64_t v[3]) {
  static const uint64_t off[2] = {0, (uint64_t)1 << (ZK_TDEC_CARRY_BITS - 1 - 64)};
  uint64_t col[5][3], x[6], q[3], pw[3], t[3], cp[3], r[2], vk;
  uint32_t i, k;
  ZkFr f[3], e;
  if (n == 0 || n > ZK_TDEC_COORDS_MAX) return;
  memset(col, 0, sizeof col);
  zk_tdec_cols_fill(col, n, s, m);
  for (i = 0; i < ZK_TDEC_PARTIES; i++)
    for (k = 0; k < 3; k++)
      if (b[i] != 0) td_add(col[k], 3, &nl[3 * i + k], 1);
  memset(x, 0, sizeof x);
  for (k = 0; k < 5; k++)
    td_add(x + k, 6 - k, col[k], 3);
  td_divp(x, q);
  td_p_words(pw);
  for (k = 0; k < 3; k++)
    f[k] = zk_fr_u64(v[k]);
  zk_fp_fill(wt, f);
  for (k = 0; k < 3; k++) {
    e = zk_fr_u64(q[k]);
    zk_bits_fill(wt + ZK_FP_WEIGHTS + 64 * k, &e, k < 2 ? 64 : ZK_TDEC_Q_BITS - 128);
  }
  /* Column k: t = C_k + N_k + c_(k-1) - V_k - sum q_i p_j = c_k 2^64 (3-word
   * two's complement), so c_k is t shifted down one word, sign kept. */
  memset(cp, 0, sizeof cp);
  for (k = 0; k < 4; k++) {
    memcpy(t, col[k], sizeof t);
    td_add(t, 3, cp, 3);
    vk = k < 3 ? v[k] : 0;
    td_sub(t, 3, &vk, 1);
    for (i = 0; i < 3; i++)
      if (k >= i && k - i < 3) {
        td_mul64(q[i], pw[k - i], r);
        td_sub(t, 3, r, 2);
      }
    cp[0] = t[1];
    cp[1] = t[2];
    cp[2] = t[2] >> 63 ? ~(uint64_t)0 : 0;
    memcpy(t, cp, sizeof t);
    td_add(t, 3, off, 2);
    memset(&e, 0, sizeof e);
    e.limb[0] = (uint32_t)t[0];
    e.limb[1] = (uint32_t)(t[0] >> 32);
    e.limb[2] = (uint32_t)t[1];
    e.limb[3] = (uint32_t)(t[1] >> 32);
    zk_bits_fill(wt + ZK_FP_WEIGHTS + ZK_TDEC_Q_BITS + ZK_TDEC_CARRY_BITS * k, &e, ZK_TDEC_CARRY_BITS);
  }
}

/* S7 U6 D62 (G1 gtoss). */
static uint32_t gtoss_bytes(uint32_t form) {
  return form == 0 ? 4 + 64 : 5 * 64;
}

uint32_t zk_gtoss_weights(uint32_t form) {
  return form > 1 ? 0 : zk_sha512_weights(gtoss_bytes(form));
}

/* The value of the N message bytes at bit weight W (low bit first): byte q
 * has the place q (LE) or N - 1 - q (load_be). */
static uint32_t gtoss_pack(ZkCircuit *c, const uint32_t k2[64], uint32_t w, uint32_t n, int le) {
  uint32_t v = 0, q, t, term;
  for (q = 0; q < n; q++)
    for (t = 0; t < 8; t++) {
      term = zk_mul(c, zk_weight(c, w + 8 * q + t), k2[8 * (le ? q : n - 1 - q) + t]);
      v = q == 0 && t == 0 ? term : zk_add(c, v, term);
    }
  return v;
}

void zk_gtoss(ZkCircuit *c, uint32_t form) {
  const uint32_t m = zk_gtoss_weights(form), s0 = form == 0 ? 4 : 0, ns = form == 0 ? 8 : 40;
  const uint32_t si = form == 0 ? 9 : 0, di = form == 0 ? 1 : 40;
  uint32_t k2[64], d[8], x[9], p, i;
  ZkFr t;
  if (c->err != ZK_OK) return;
  if (m == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (m > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  for (i = 0; i < 64; i++) {
    t = pow2(i);
    k2[i] = zk_const(c, &t);
  }
  if (form == 0) {
    p = zk_input(c, 0);
    zk_party(c, p);
    zk_eq(c, gtoss_pack(c, k2, 0, 4, 1), p);
  }
  for (i = 0; i < ns; i++)
    zk_eq(c, gtoss_pack(c, k2, 8 * (s0 + 8 * i), 8, 0), zk_input(c, si + i));
  zk_sha512(c, gtoss_bytes(form), 0, d);
  for (i = 0; i < 8; i++)
    zk_eq(c, d[i], zk_input(c, di + i));
  if (form == 0) return;
  memcpy(x, d, sizeof d);
  x[8] = zk_input(c, 48);
  zk_out(c, 0, zk_poseidon2_hash_values(c, ZK_K_TAG, 9, x));
}

void zk_gtoss_fill(ZkFr *wt, uint32_t form, const uint8_t *msg) {
  if (zk_gtoss_weights(form) == 0) return;
  zk_sha512_fill(wt, msg, gtoss_bytes(form));
}

/* S7 U6 D63 (G2 gdeal). */
static uint32_t gdeal_noise_weights(uint32_t b) {
  const ZkFr bound = pow2(b);
  return 2 + zk_range_weights(&bound);
}

static uint32_t gdeal_secret_weights(uint32_t cls, uint32_t b) {
  return cls == ZK_GDEAL_NOISE ? gdeal_noise_weights(b) + ZK_FP_WEIGHTS : cls == ZK_GDEAL_R ? ZK_FP_WEIGHTS : 0;
}

/* The bound of the quotient of share I: the sum over e <= TOP of I^e, less 1. */
static ZkFr gdeal_qbound(uint32_t i, uint32_t top) {
  uint64_t s = 0, t = 1;
  uint32_t e;
  for (e = 0; e <= top; e++) {
    s += t;
    t *= i;
  }
  return zk_fr_u64(s - 1);
}

static uint64_t gdeal_ipow(uint32_t i, uint32_t e) {
  uint64_t t = 1;
  uint32_t k;
  for (k = 0; k < e; k++)
    t *= i;
  return t;
}

static uint32_t gdeal_share_weights(uint32_t i, uint32_t top) {
  const ZkFr bound = gdeal_qbound(i, top);
  return ZK_FP_WEIGHTS + 1 + zk_range_weights(&bound);
}

static uint32_t gdeal_block(uint32_t cls, uint32_t top, uint32_t b) {
  uint32_t i, n = gdeal_secret_weights(cls, b) + top * ZK_FP_WEIGHTS;
  for (i = 1; i <= ZK_GDEAL_PARTIES; i++)
    n += gdeal_share_weights(i, top);
  return n;
}

uint32_t zk_gdeal_weights(uint32_t cls, uint32_t top, uint32_t m, uint32_t b) {
  const int noise_ok = cls != ZK_GDEAL_NOISE || (b >= 1 && b <= 62);
  const int shape_ok = cls <= ZK_GDEAL_ZERO && (top == 2 || top == 4) && (cls != ZK_GDEAL_ZERO || top == 4);
  return noise_ok && shape_ok && m >= 1 && m <= ZK_GDEAL_MAX ? m * gdeal_block(cls, top, b) + ZK_GDEAL_PARTIES : 0;
}

/* The noise secret at W0: u, the range of u, q, then x. */
static uint32_t gdeal_noise(ZkCircuit *c, uint32_t w0, uint32_t b, uint32_t pk) {
  const ZkFr bound = pow2(b), half = pow2(b - 1);
  const uint32_t rw = zk_range_weights(&bound), u = zk_weight(c, w0), q = zk_weight(c, w0 + 1 + rw);
  uint32_t l[3], x;
  zk_range(c, u, &bound, w0 + 1);
  zk_eq(c, zk_mul(c, q, q), q);
  x = zk_fp(c, w0 + 2 + rw, l);
  zk_eq(c, zk_add(c, x, zk_const(c, &half)), zk_add(c, u, zk_mul(c, q, pk)));
  return x;
}

static uint32_t gdeal_secret(ZkCircuit *c, uint32_t cls, uint32_t w0, uint32_t b, uint32_t pk) {
  const ZkFr zero = zk_fr_u64(0);
  uint32_t l[3];
  switch (cls) {
  case ZK_GDEAL_NOISE:
    return gdeal_noise(c, w0, b, pk);
  case ZK_GDEAL_R:
    return zk_fp(c, w0, l);
  case ZK_GDEAL_ZERO:
    return zk_const(c, &zero);
  }
  return zk_const(c, &zero);
}

void zk_gdeal(ZkCircuit *c, uint32_t cls, uint32_t top, uint32_t m, uint32_t b) {
  const uint32_t n = zk_gdeal_weights(cls, top, m, b);
  const ZkFr p = fp_const(0);
  uint32_t x[ZK_GDEAL_PARTIES][5 + 3 * ZK_GDEAL_MAX], cf[4], l[3], k, i, e, w, s, sum, y, q, rw, pk;
  ZkFr t, bound;
  if (c->err != ZK_OK) return;
  if (n == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (n > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  pk = zk_const(c, &p);
  for (i = 0; i < ZK_GDEAL_PARTIES; i++) {
    t = zk_fr_u64(i + 1);
    x[i][0] = zk_weight(c, n - ZK_GDEAL_PARTIES + i);
    x[i][1] = zk_input(c, 0);
    x[i][2] = zk_input(c, 1);
    x[i][3] = zk_input(c, 2);
    x[i][4] = zk_const(c, &t);
  }
  zk_party(c, x[0][3]);
  for (k = 0; k < m; k++) {
    w = k * gdeal_block(cls, top, b);
    s = gdeal_secret(c, cls, w, b, pk);
    w += gdeal_secret_weights(cls, b);
    for (e = 0; e < top; e++)
      cf[e] = zk_fp(c, w + e * ZK_FP_WEIGHTS, l);
    w += top * ZK_FP_WEIGHTS;
    for (i = 1; i <= ZK_GDEAL_PARTIES; i++) {
      sum = s;
      for (e = 1; e <= top; e++) {
        t = zk_fr_u64(gdeal_ipow(i, e));
        sum = zk_add(c, sum, zk_mul(c, cf[e - 1], zk_const(c, &t)));
      }
      bound = gdeal_qbound(i, top);
      rw = zk_range_weights(&bound);
      y = zk_fp(c, w, x[i - 1] + 5 + 3 * k);
      q = zk_weight(c, w + ZK_FP_WEIGHTS);
      zk_range(c, q, &bound, w + ZK_FP_WEIGHTS + 1);
      zk_eq(c, sum, zk_add(c, y, zk_mul(c, q, pk)));
      w += ZK_FP_WEIGHTS + 1 + rw;
    }
  }
  for (i = 0; i < ZK_GDEAL_PARTIES; i++)
    zk_out(c, i, zk_poseidon2_hash_values(c, ZK_CD_TAG, 5 + 3 * m, x[i]));
}

/* The value of 3 limbs of 64 bits. */
static ZkFr gdeal_val(const ZkFr l[3]) {
  const ZkFr k64 = pow2(64), k128 = pow2(128);
  const ZkFr a = zk_fr_mul(&l[1], &k64), b = zk_fr_mul(&l[2], &k128), v = zk_fr_add(&l[0], &a);
  return zk_fr_add(&v, &b);
}

/* The quotient q with y + q p = S (QMAX when there is none: zk_check refuses). */
static uint64_t gdeal_quot(const ZkFr *s, const ZkFr *y, uint64_t qmax) {
  const ZkFr p = fp_const(0);
  ZkFr t = *y;
  uint64_t q = 0;
  while (q < qmax && memcmp(&t, s, sizeof t) != 0) {
    t = zk_fr_add(&t, &p);
    q++;
  }
  return q;
}

void zk_gdeal_fill(ZkFr *wt, uint32_t cls, uint32_t top, uint32_t m, uint32_t b, const ZkFr *x, const int64_t *e,
                   const ZkFr *coef, const ZkFr *y, const ZkFr salt[ZK_GDEAL_PARTIES]) {
  const uint32_t n = zk_gdeal_weights(cls, top, m, b);
  ZkFr s, t, a, cv[4], bound, u, yv;
  uint32_t k, i, j, w, rw;
  uint64_t q;
  if (n == 0) return;
  for (k = 0; k < m; k++) {
    w = k * gdeal_block(cls, top, b);
    if (cls == ZK_GDEAL_NOISE) {
      bound = pow2(b);
      rw = zk_range_weights(&bound);
      u = zk_fr_u64((uint64_t)(e[k] + ((int64_t)1 << (b - 1))));
      wt[w] = u;
      zk_range_fill(wt + w + 1, &u, &bound);
      wt[w + 1 + rw] = zk_fr_u64(e[k] < 0 ? 1 : 0);
      zk_fp_fill(wt + w + 2 + rw, x + 3 * k);
    }
    if (cls == ZK_GDEAL_R) zk_fp_fill(wt + w, x + 3 * k);
    w += gdeal_secret_weights(cls, b);
    for (j = 0; j < top; j++) {
      cv[j] = gdeal_val(coef + 3 * (k * top + j));
      zk_fp_fill(wt + w, coef + 3 * (k * top + j));
      w += ZK_FP_WEIGHTS;
    }
    for (i = 1; i <= ZK_GDEAL_PARTIES; i++) {
      s = gdeal_val(x + 3 * k);
      for (j = 1; j <= top; j++) {
        t = zk_fr_u64(gdeal_ipow(i, j));
        a = zk_fr_mul(&cv[j - 1], &t);
        s = zk_fr_add(&s, &a);
      }
      bound = gdeal_qbound(i, top);
      rw = zk_range_weights(&bound);
      yv = gdeal_val(y + 3 * ((i - 1) * m + k));
      zk_fp_fill(wt + w, y + 3 * ((i - 1) * m + k));
      q = gdeal_quot(&s, &yv, gdeal_ipow(i, 0) + (uint64_t)bound.limb[0]);
      wt[w + ZK_FP_WEIGHTS] = zk_fr_u64(q);
      zk_range_fill(wt + w + ZK_FP_WEIGHTS + 1, &wt[w + ZK_FP_WEIGHTS], &bound);
      w += ZK_FP_WEIGHTS + 1 + rw;
    }
  }
  for (i = 0; i < ZK_GDEAL_PARTIES; i++)
    wt[n - ZK_GDEAL_PARTIES + i] = salt[i];
}

/* S7 U6 D63 (G2 gflood, the D39 producer). */
static ZkFr gflood_bound(void) {
  return pow2_minus(ZK_GFLOOD_LOG + 1, 1);
}

/* u, the range of u, q, x, c_1 and c_2: the shares start here. */
static uint32_t gflood_head(void) {
  const ZkFr bound = gflood_bound();
  return 2 + zk_range_weights(&bound) + 3 * ZK_FP_WEIGHTS;
}

uint32_t zk_gflood_weights(void) {
  uint32_t i, n = gflood_head();
  for (i = 1; i <= ZK_GDEAL_PARTIES; i++)
    n += gdeal_share_weights(i, 2);
  return n;
}

void zk_gflood(ZkCircuit *c) {
  const uint32_t n = zk_gflood_weights();
  const ZkFr p = fp_const(0), bound = gflood_bound(), half = pow2(ZK_GFLOOD_LOG);
  const uint32_t rw = zk_range_weights(&bound);
  uint32_t x[ZK_GDEAL_PARTIES][5], cf[2], l[3], u, q, s, sum, y, qi, w, i, e, pk, qr;
  ZkFr t, qb;
  if (c->err != ZK_OK) return;
  if (n > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  pk = zk_const(c, &p);
  zk_party(c, zk_input(c, 0));
  u = zk_weight(c, 0);
  q = zk_weight(c, 1 + rw);
  zk_range(c, u, &bound, 1);
  zk_eq(c, zk_mul(c, q, q), q);
  s = zk_fp(c, 2 + rw, l);
  zk_eq(c, zk_add(c, s, zk_const(c, &half)), zk_add(c, u, zk_mul(c, q, pk)));
  for (e = 0; e < 2; e++)
    cf[e] = zk_fp(c, 2 + rw + (e + 1) * ZK_FP_WEIGHTS, l);
  w = gflood_head();
  for (i = 1; i <= ZK_GDEAL_PARTIES; i++) {
    t = zk_fr_u64(i);
    x[i - 1][0] = zk_const(c, &t);
    x[i - 1][1] = zk_input(c, 0);
    sum = s;
    for (e = 1; e <= 2; e++) {
      t = zk_fr_u64(gdeal_ipow(i, e));
      sum = zk_add(c, sum, zk_mul(c, cf[e - 1], zk_const(c, &t)));
    }
    qb = gdeal_qbound(i, 2);
    qr = zk_range_weights(&qb);
    y = zk_fp(c, w, x[i - 1] + 2);
    qi = zk_weight(c, w + ZK_FP_WEIGHTS);
    zk_range(c, qi, &qb, w + ZK_FP_WEIGHTS + 1);
    zk_eq(c, sum, zk_add(c, y, zk_mul(c, qi, pk)));
    w += ZK_FP_WEIGHTS + 1 + qr;
  }
  for (i = 0; i < ZK_GDEAL_PARTIES; i++)
    zk_out(c, i, zk_poseidon2_hash_values(c, ZK_CN_TAG, 5, x[i]));
}

void zk_gflood_fill(ZkFr *wt, const uint64_t u[2], const ZkFr x[3], const ZkFr coef[6], const ZkFr y[15]) {
  const ZkFr bound = gflood_bound(), k64 = pow2(64), hi = zk_fr_u64(u[1]), lo = zk_fr_u64(u[0]);
  const uint32_t rw = zk_range_weights(&bound);
  ZkFr s, t, a, cv[2], qb, yv, uv;
  uint32_t i, j, w;
  uint64_t q;
  uv = zk_fr_mul(&hi, &k64);
  uv = zk_fr_add(&uv, &lo);
  wt[0] = uv;
  zk_range_fill(wt + 1, &uv, &bound);
  wt[1 + rw] = zk_fr_u64(u[1] >> (ZK_GFLOOD_LOG - 64) ? 0 : 1);
  zk_fp_fill(wt + 2 + rw, x);
  for (j = 0; j < 2; j++) {
    cv[j] = gdeal_val(coef + 3 * j);
    zk_fp_fill(wt + 2 + rw + (j + 1) * ZK_FP_WEIGHTS, coef + 3 * j);
  }
  w = gflood_head();
  for (i = 1; i <= ZK_GDEAL_PARTIES; i++) {
    s = gdeal_val(x);
    for (j = 1; j <= 2; j++) {
      t = zk_fr_u64(gdeal_ipow(i, j));
      a = zk_fr_mul(&cv[j - 1], &t);
      s = zk_fr_add(&s, &a);
    }
    qb = gdeal_qbound(i, 2);
    yv = gdeal_val(y + 3 * (i - 1));
    zk_fp_fill(wt + w, y + 3 * (i - 1));
    q = gdeal_quot(&s, &yv, 1 + (uint64_t)qb.limb[0]);
    wt[w + ZK_FP_WEIGHTS] = zk_fr_u64(q);
    zk_range_fill(wt + w + ZK_FP_WEIGHTS + 1, &wt[w + ZK_FP_WEIGHTS], &qb);
    w += ZK_FP_WEIGHTS + 1 + zk_range_weights(&qb);
  }
}

/* S7 U6 D66 (G5 gword, the opening of one key word). |lambda_i| of the
 * Lagrange coefficients at 0 (5, -10, 10, -5, 1): the shares 1, 3 and 5 go
 * to the left side, 2 and 4 to the right. */
static const uint64_t gword_lambda[ZK_GDEAL_PARTIES] = {5, 10, 10, 5, 1};

/* 1 when V >= (p + 1) / 2 (at_least_half of tkeygen.c: V lifts to V - p). */
static uint32_t gword_half(const uint64_t v[3]) {
  static const uint64_t half[3] = {0xfffffffffff67001u, 0xffffffffffffffffu, 0x7fffffffffffffffu};
  uint32_t k = 3;
  while (k > 0) {
    k--;
    if (v[k] != half[k]) return v[k] > half[k];
  }
  return 1;
}

/* (p - 1) / 2, the bound of d. */
static ZkFr gword_dbound(void) {
  return pow2_minus(ZK_GWORD_SHIFT, 626688);
}

/* 2^(192 - 64 WORDS) - 1, the bound of u (WORDS 1 or 2). */
static ZkFr gword_ubound(uint32_t words) {
  return pow2_minus(192 - 64 * words, 1);
}

/* The 5 shares, v, Q and its range, h and the range of d: the words start here. */
static uint32_t gword_head(void) {
  const ZkFr qb = zk_fr_u64(31), db = gword_dbound();
  return (ZK_GDEAL_PARTIES + 1) * ZK_FP_WEIGHTS + 2 + zk_range_weights(&qb) + zk_range_weights(&db);
}

uint32_t zk_gword_weights(uint32_t words) {
  const ZkFr wb = pow2_minus(64, 1);
  ZkFr ub;
  if (words != 1 && words != 2) return 0;
  ub = gword_ubound(words);
  return gword_head() + words * (1 + zk_range_weights(&wb)) + 1 + zk_range_weights(&ub);
}

void zk_gword(ZkCircuit *c, uint32_t words) {
  const ZkFr p = fp_const(0), one = zk_fr_u64(1), qb = zk_fr_u64(31), db = gword_dbound();
  const ZkFr half = pow2_minus(ZK_GWORD_SHIFT, 626687), shift = pow2(ZK_GWORD_SHIFT), wb = pow2_minus(64, 1);
  const uint32_t rw = zk_range_weights(&wb);
  uint32_t a[3], l[3], s[ZK_GDEAL_PARTIES], lhs, rhs, term, pk, oc, v, q, h, d, x, u, w, wu, i, k;
  ZkFr t, ub;
  if (c->err != ZK_OK) return;
  if (words != 1 && words != 2) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (zk_gword_weights(words) > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  ub = gword_ubound(words);
  pk = zk_const(c, &p);
  oc = zk_const(c, &one);
  for (i = 0; i < ZK_GDEAL_PARTIES; i++) {
    for (k = 0; k < 3; k++)
      a[k] = zk_input(c, 3 * i + k);
    zk_fp_bind(c, a, ZK_FP_WEIGHTS * i);
    s[i] = fp_value(c, a);
  }
  w = ZK_GDEAL_PARTIES * ZK_FP_WEIGHTS;
  v = zk_fp(c, w, l);
  w += ZK_FP_WEIGHTS;
  /* 5 s_1 + 10 s_3 + s_5 + 16 p = 10 s_2 + 5 s_4 + V + Q p: both sides below 2^198, no wrap. */
  q = zk_weight(c, w);
  zk_range(c, q, &qb, w + 1);
  w += 1 + zk_range_weights(&qb);
  t = zk_fr_u64(16);
  t = zk_fr_mul(&t, &p);
  lhs = zk_const(c, &t);
  rhs = zk_add(c, v, zk_mul(c, q, pk));
  for (i = 0; i < ZK_GDEAL_PARTIES; i++) {
    t = zk_fr_u64(gword_lambda[i]);
    term = zk_mul(c, s[i], zk_const(c, &t));
    if (i % 2 == 0)
      lhs = zk_add(c, lhs, term);
    else
      rhs = zk_add(c, rhs, term);
  }
  zk_eq(c, lhs, rhs);
  /* h = [V >= (p + 1) / 2]: d = (2 h - 1)(V - (p + 1) / 2) + h - 1 in [0, (p - 1) / 2]. */
  h = zk_weight(c, w);
  zk_eq(c, zk_mul(c, h, h), h);
  d = zk_mul(c, zk_sub(c, zk_add(c, h, h), oc), zk_sub(c, v, zk_const(c, &half)));
  d = zk_add(c, d, zk_sub(c, h, oc));
  zk_range(c, d, &db, w + 1);
  w += 1 + zk_range_weights(&db);
  /* V - h p + 2^191 = W_0 + W_1 2^64 + u 2^(64 WORDS), below 2^192: W = (V - h p) mod 2^(64 WORDS). */
  wu = w + words * (1 + rw);
  u = zk_weight(c, wu);
  zk_range(c, u, &ub, wu + 1);
  t = pow2(64 * words);
  rhs = zk_mul(c, u, zk_const(c, &t));
  for (k = 0; k < words; k++) {
    x = zk_weight(c, w + k * (1 + rw));
    zk_range(c, x, &wb, w + k * (1 + rw) + 1);
    t = pow2(64 * k);
    rhs = zk_add(c, rhs, zk_mul(c, x, zk_const(c, &t)));
    zk_out(c, k, x);
  }
  lhs = zk_add(c, zk_sub(c, v, zk_mul(c, h, pk)), zk_const(c, &shift));
  zk_eq(c, lhs, rhs);
}

void zk_gword_fill(ZkFr *wt, uint32_t words, const ZkFr sh[15], const uint64_t v[3]) {
  const ZkFr p = fp_const(0), one = zk_fr_u64(1), qb = zk_fr_u64(31), db = gword_dbound();
  const ZkFr half = pow2_minus(ZK_GWORD_SHIFT, 626687), wb = pow2_minus(64, 1), k64 = pow2(64);
  const uint32_t rw = zk_range_weights(&wb);
  ZkFr vl[3], vv, lhs, rhs, a, t, hv, d, u, ub;
  uint64_t s[3], c0, c1;
  uint32_t h, w, i, k;
  if (words != 1 && words != 2) return;
  ub = gword_ubound(words);
  for (i = 0; i < ZK_GDEAL_PARTIES; i++)
    zk_fp_fill(wt + ZK_FP_WEIGHTS * i, sh + 3 * i);
  for (k = 0; k < 3; k++)
    vl[k] = zk_fr_u64(v[k]);
  w = ZK_GDEAL_PARTIES * ZK_FP_WEIGHTS;
  zk_fp_fill(wt + w, vl);
  w += ZK_FP_WEIGHTS;
  vv = gdeal_val(vl);
  t = zk_fr_u64(16);
  lhs = zk_fr_mul(&t, &p);
  rhs = vv;
  for (i = 0; i < ZK_GDEAL_PARTIES; i++) {
    t = zk_fr_u64(gword_lambda[i]);
    a = gdeal_val(sh + 3 * i);
    a = zk_fr_mul(&t, &a);
    if (i % 2 == 0)
      lhs = zk_fr_add(&lhs, &a);
    else
      rhs = zk_fr_add(&rhs, &a);
  }
  wt[w] = zk_fr_u64(gdeal_quot(&lhs, &rhs, 32));
  zk_range_fill(wt + w + 1, &wt[w], &qb);
  w += 1 + zk_range_weights(&qb);
  h = gword_half(v);
  hv = zk_fr_u64(h);
  wt[w] = hv;
  t = zk_fr_add(&hv, &hv);
  t = zk_fr_sub(&t, &one);
  a = zk_fr_sub(&vv, &half);
  d = zk_fr_mul(&t, &a);
  a = zk_fr_sub(&hv, &one);
  d = zk_fr_add(&d, &a);
  zk_range_fill(wt + w + 1, &d, &db);
  w += 1 + zk_range_weights(&db);
  /* S = V - h p + 2^191 by words (h 1: V + (2^192 - p) - 2^191, bit 191 of V + 1253375 set). */
  memcpy(s, v, sizeof s);
  if (h) {
    s[0] = v[0] + 1253375u;
    c0 = s[0] < v[0];
    s[1] = v[1] + c0;
    c1 = c0 && s[1] == 0;
    s[2] = v[2] + c1;
  }
  s[2] ^= 1ull << 63;
  for (k = 0; k < words; k++) {
    wt[w] = zk_fr_u64(s[k]);
    zk_range_fill(wt + w + 1, &wt[w], &wb);
    w += 1 + rw;
  }
  u = zk_fr_u64(0);
  for (k = 3; k > words; k--) {
    u = zk_fr_mul(&u, &k64);
    t = zk_fr_u64(s[k - 1]);
    u = zk_fr_add(&u, &t);
  }
  wt[w] = u;
  zk_range_fill(wt + w + 1, &u, &ub);
}

/* S7 U6 D64 (G3 gbit, one party and one bit). The weight offsets. */
enum {
  GBIT_Z = ZK_GDEAL_PARTIES * ZK_FP_WEIGHTS,         /* z_(d,i) */
  GBIT_RSUM = 2 * ZK_GDEAL_PARTIES * ZK_FP_WEIGHTS,  /* 4 zk_addp for r_i */
  GBIT_ZSUM = GBIT_RSUM + 4 * ZK_ADDP_WEIGHTS,       /* 4 zk_addp for z_i */
  GBIT_W = GBIT_ZSUM + 4 * ZK_ADDP_WEIGHTS,          /* zk_fp_bind of w */
  GBIT_SQ = GBIT_W + ZK_FP_WEIGHTS,                  /* r_i^2 */
  GBIT_O = GBIT_SQ + ZK_MULP_WEIGHTS,                /* o_i = r_i^2 + z_i */
  GBIT_T = GBIT_O + ZK_ADDP_WEIGHTS,                 /* r_i w */
  GBIT_B = GBIT_T + ZK_MULP_WEIGHTS,                 /* b_i = r_i w + (p + 1) / 2 */
  GBIT_SALT = GBIT_B + ZK_ADDP_WEIGHTS,              /* the 11 salts */
  GBIT_SALTS = 11
};

/* The 3 limbs of the element at WT (192 bit weights, each 0 or 1). */
static void gbit_limbs(ZkFr r[3], const ZkFr *wt) {
  uint64_t v;
  uint32_t k, i;
  for (k = 0; k < 3; k++) {
    v = 0;
    for (i = 0; i < 64; i++)
      v |= (uint64_t)wt[64 * k + i].limb[0] << i;
    r[k] = zk_fr_u64(v);
  }
}

/* R = X_1 + .. + X_5 mod p by 4 zk_addp at W0. */
static void gbit_sum(ZkCircuit *c, uint32_t x[ZK_GDEAL_PARTIES][3], uint32_t w0, uint32_t r[3]) {
  uint32_t a[3], k, d;
  for (k = 0; k < 3; k++)
    r[k] = x[0][k];
  for (d = 1; d < ZK_GDEAL_PARTIES; d++) {
    for (k = 0; k < 3; k++)
      a[k] = r[k];
    zk_addp(c, a, x[d], w0 + ZK_ADDP_WEIGHTS * (d - 1), r);
  }
}

/* The fill of gbit_sum: X the 15 limbs; the limbs of each sum are read back. */
static void gbit_sum_fill(ZkFr *wt, const ZkFr x[15], ZkFr r[3]) {
  ZkFr a[3];
  uint32_t d;
  memcpy(r, x, sizeof a);
  for (d = 1; d < ZK_GDEAL_PARTIES; d++) {
    memcpy(a, r, sizeof a);
    zk_addp_fill(wt + ZK_ADDP_WEIGHTS * (d - 1), a, x + 3 * d);
    gbit_limbs(r, wt + ZK_ADDP_WEIGHTS * (d - 1) + 1);
  }
}

uint32_t zk_gbit_weights(void) {
  return GBIT_SALT + GBIT_SALTS;
}

void zk_gbit(ZkCircuit *c) {
  const ZkFr half = pow2_minus(ZK_GWORD_SHIFT, 626687), k20 = zk_fr_u64((uint64_t)1 << 20);
  uint32_t rl[ZK_GDEAL_PARTIES][3], zl[ZK_GDEAL_PARTIES][3], xr[ZK_GDEAL_PARTIES][8], xz[ZK_GDEAL_PARTIES][8], xb[7];
  uint32_t ri[3], zi[3], wi[3], o[3], s[3], t[3], b[3], hl[3], idx[3], kk, j, i, vid, jw, dc, k, d;
  ZkFr f;
  if (c->err != ZK_OK) return;
  if (zk_gbit_weights() > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  kk = zk_input(c, 0);
  j = zk_input(c, 1);
  i = zk_input(c, 2);
  zk_party(c, i);
  for (k = 0; k < 3; k++)
    wi[k] = zk_input(c, 3 + k);
  vid = zk_input(c, 9);
  /* I_F = F 2^40 + j 2^20 for F = 6 (the bit), 7 (the r dealings), 8 (the zero dealings).
   * C7 (Q-S7-U6-4): the bit index is I_6 + vid, vid the public key-vector id. */
  jw = zk_mul(c, j, zk_const(c, &k20));
  for (k = 0; k < 3; k++) {
    f = zk_fr_u64((uint64_t)(6 + k) << 40);
    idx[k] = zk_add(c, zk_const(c, &f), jw);
  }
  idx[0] = zk_add(c, idx[0], vid);
  for (d = 0; d < ZK_GDEAL_PARTIES; d++) {
    zk_fp(c, ZK_FP_WEIGHTS * d, rl[d]);
    zk_fp(c, GBIT_Z + ZK_FP_WEIGHTS * d, zl[d]);
  }
  gbit_sum(c, rl, GBIT_RSUM, ri);
  gbit_sum(c, zl, GBIT_ZSUM, zi);
  zk_fp_bind(c, wi, GBIT_W);
  zk_mulp(c, ri, ri, GBIT_SQ, s);
  zk_addp(c, s, zi, GBIT_O, o);
  for (k = 0; k < 3; k++)
    zk_eq(c, o[k], zk_input(c, 6 + k));
  zk_mulp(c, ri, wi, GBIT_T, t);
  for (k = 0; k < 3; k++) {
    f = fp_limb(&half, k);
    hl[k] = zk_const(c, &f);
  }
  zk_addp(c, t, hl, GBIT_B, b);
  for (d = 0; d < ZK_GDEAL_PARTIES; d++) {
    f = zk_fr_u64(d + 1);
    dc = zk_const(c, &f);
    xr[d][0] = zk_weight(c, GBIT_SALT + d);
    xz[d][0] = zk_weight(c, GBIT_SALT + ZK_GDEAL_PARTIES + d);
    xr[d][1] = kk;
    xz[d][1] = kk;
    xr[d][2] = idx[1];
    xz[d][2] = idx[2];
    xr[d][3] = dc;
    xz[d][3] = dc;
    xr[d][4] = i;
    xz[d][4] = i;
    for (k = 0; k < 3; k++) {
      xr[d][5 + k] = rl[d][k];
      xz[d][5 + k] = zl[d][k];
    }
  }
  xb[0] = zk_weight(c, GBIT_SALT + 2 * ZK_GDEAL_PARTIES);
  xb[1] = kk;
  xb[2] = idx[0];
  xb[3] = i;
  for (k = 0; k < 3; k++)
    xb[4 + k] = b[k];
  for (d = 0; d < ZK_GDEAL_PARTIES; d++) {
    zk_out(c, d, zk_poseidon2_hash_values(c, ZK_CD_TAG, 8, xr[d]));
    zk_out(c, ZK_GDEAL_PARTIES + d, zk_poseidon2_hash_values(c, ZK_CD_TAG, 8, xz[d]));
  }
  zk_out(c, 2 * ZK_GDEAL_PARTIES, zk_poseidon2_hash_values(c, ZK_CB_TAG, 7, xb));
}

void zk_gbit_fill(ZkFr *wt, const ZkFr rs[15], const ZkFr zs[15], const ZkFr w[3], const ZkFr salt[11]) {
  const ZkFr half = pow2_minus(ZK_GWORD_SHIFT, 626687);
  ZkFr ri[3], zi[3], s[3], t[3], hl[3];
  uint32_t d, k;
  for (d = 0; d < ZK_GDEAL_PARTIES; d++) {
    zk_fp_fill(wt + ZK_FP_WEIGHTS * d, rs + 3 * d);
    zk_fp_fill(wt + GBIT_Z + ZK_FP_WEIGHTS * d, zs + 3 * d);
  }
  gbit_sum_fill(wt + GBIT_RSUM, rs, ri);
  gbit_sum_fill(wt + GBIT_ZSUM, zs, zi);
  zk_fp_fill(wt + GBIT_W, w);
  zk_mulp_fill(wt + GBIT_SQ, ri, ri);
  gbit_limbs(s, wt + GBIT_SQ + ZK_FP_WEIGHTS);
  zk_addp_fill(wt + GBIT_O, s, zi);
  zk_mulp_fill(wt + GBIT_T, ri, w);
  gbit_limbs(t, wt + GBIT_T + ZK_FP_WEIGHTS);
  for (k = 0; k < 3; k++)
    hl[k] = fp_limb(&half, k);
  zk_addp_fill(wt + GBIT_B, t, hl);
  for (k = 0; k < GBIT_SALTS; k++)
    wt[GBIT_SALT + k] = salt[k];
}

/* S7 U6 D65 (G4 gopen, KSK and cast KSK). The weight offsets. */
enum {
  GOPEN_COORDS = ZK_GOPEN_N + 1,               /* the mask terms, then g_l x_i */
  GOPEN_X = 3 * ZK_GOPEN_N,                    /* x_i */
  GOPEN_NZ = GOPEN_X + 3,                      /* N_d(i), d = 1 .. 5 */
  GOPEN_RED = GOPEN_NZ + 3 * ZK_TDEC_PARTIES,  /* zk_tdec_reduce of 919 coordinates */
  GOPEN_SALT = GOPEN_RED + ZK_TDEC_WEIGHTS     /* the 5 noise salts, then the 919 key salts */
};

static uint32_t gopen_const(ZkCircuit *c, uint64_t x) {
  const ZkFr f = zk_fr_u64(x);
  return zk_const(c, &f);
}

/* The GLWE weight offsets (RESUME13; squash RESUME14): S_i at 0 (1 key
 * polynomial, 2 for squash), x at 3 K N (BSK and squash), then N_d(i), the
 * zk_mulp block (BSK row 0, squash rows 0 and 1), U, W, the zk_addp block and
 * the 5 noise salts. */
static uint32_t gopen_keys(uint32_t fam) {
  return fam >= ZK_GOPEN_SQ0 ? 2 : 1;
}

static int gopen_prod(uint32_t fam) {
  return fam == ZK_GOPEN_BSK0 || fam == ZK_GOPEN_SQ0 || fam == ZK_GOPEN_SQ1;
}

static uint32_t gopen_nz(uint32_t fam) {
  return 3 * ZK_GOPEN_GN * gopen_keys(fam) + (fam == ZK_GOPEN_PK ? 0 : 3);
}

static uint32_t gopen_red(uint32_t fam) {
  return gopen_nz(fam) + 3 * ZK_TDEC_PARTIES + (gopen_prod(fam) ? ZK_MULP_WEIGHTS : 0);
}

/* The M slot mask exponent (C3), 0 for a zero mask: 41 in U (side 0) for BSK
 * row 1 at C = 0 and in W (side 1) for BSK row 0; the squash gadget 128 - 24
 * level in W for squash rows 0 and 1 and in U for squash row 2 at C = 0. L
 * carries C (and for squash the level: L = (level - 1) N + C). */
static uint32_t gopen_mslot(uint32_t fam, uint32_t l, uint32_t side) {
  const uint32_t cc = l % ZK_GOPEN_GN, e = fam >= ZK_GOPEN_SQ0 ? 128 - 24 * (l / ZK_GOPEN_GN + 1) : 41;
  const int on = side == 0 ? (fam == ZK_GOPEN_BSK1 || fam == ZK_GOPEN_SQ2) && cc == 0 : gopen_prod(fam);
  return on ? e : 0;
}

/* Limb K (0 lo, 1 hi) of the M slot mask 2^E (E 0: the zero mask). */
static uint64_t gopen_mlimb(uint32_t e, uint32_t k) {
  return e == 0 || e / 64 != k ? 0 : (uint64_t)1 << (e % 64);
}

/* A side carries its M slot when the mask is not 0 or the side has no term (W
 * at C = N - 1); BSK and pk carry both (the RESUME13 shape). Squash U at
 * C = N - 1 has 2 N terms, so its zero slot stays out (n <= 4096). */
static int gopen_slot(uint32_t fam, uint32_t l, uint32_t side) {
  return fam < ZK_GOPEN_SQ0 || gopen_mslot(fam, l, side) != 0 || (side == 1 && l % ZK_GOPEN_GN == ZK_GOPEN_GN - 1);
}

/* The GLWE families (C3): U = P mod p over the terms t <= C of each key
 * polynomial, the noise and the U M slot; W = Nn mod p over the terms t > C
 * and the W M slot; then share_i + W = U mod p. The key index of term t is
 * (C - t) mod N. A squash mask word has 2 limbs (inputs 6 + 2 (k N + t) and
 * the next); the other masks 1 (input 6 + t). */
static void gopen_glwe(ZkCircuit *c, uint32_t fam, uint32_t l) {
  const uint32_t nz = gopen_nz(fam), red = gopen_red(fam), wa = red + 2 * ZK_TDEC_WEIGHTS, kn = gopen_keys(fam);
  const uint32_t cc = l % ZK_GOPEN_GN, xw = 3 * ZK_GOPEN_GN * kn, sq = fam >= ZK_GOPEN_SQ0;
  const uint32_t ki = sq ? (fam - ZK_GOPEN_SQ0) * ZK_GOPEN_GN + cc : cc;
  uint32_t s[3 * ZK_TDEC_COORDS_MAX], m[2 * ZK_TDEC_COORDS_MAX], nl[3 * ZK_TDEC_PARTIES], b[ZK_TDEC_PARTIES];
  uint32_t mk[3], key[3], u[3], w[3], v[3], r[3], x[8];
  uint32_t kk, g, i, zv, one, idx, side, lo, hi, n, t, k, d, p, e;
  uint64_t f;
  kk = zk_input(c, 0);
  g = zk_input(c, 1);
  i = zk_input(c, 2);
  zk_party(c, i);
  zv = gopen_const(c, 0);
  one = gopen_const(c, 1);
  for (k = 0; k < 3; k++)
    mk[k] = fam == ZK_GOPEN_PK ? zv : zk_weight(c, xw + k);
  if (gopen_prod(fam)) {
    for (k = 0; k < 3; k++)
      key[k] = zk_weight(c, 3 * ki + k);
    zk_mulp(c, mk, key, nz + 3 * ZK_TDEC_PARTIES, r);
    memcpy(mk, r, sizeof mk);
  }
  for (k = 0; k < 3 * ZK_TDEC_PARTIES; k++)
    nl[k] = zk_weight(c, nz + k);
  for (side = 0; side < 2; side++) {
    lo = side == 0 ? 0 : cc + 1;
    hi = side == 0 ? cc + 1 : ZK_GOPEN_GN;
    n = 0;
    for (p = 0; p < kn; p++)
      for (t = lo; t < hi; t++, n++) {
        for (k = 0; k < 3; k++)
          s[3 * n + k] = zk_weight(c, 3 * (p * ZK_GOPEN_GN + (cc + ZK_GOPEN_GN - t) % ZK_GOPEN_GN) + k);
        m[2 * n] = zk_input(c, sq ? 6 + 2 * (p * ZK_GOPEN_GN + t) : 6 + t);
        m[2 * n + 1] = sq ? zk_input(c, 7 + 2 * (p * ZK_GOPEN_GN + t)) : zv;
      }
    if (gopen_slot(fam, l, side)) {
      e = gopen_mslot(fam, l, side);
      for (k = 0; k < 3; k++)
        s[3 * n + k] = mk[k];
      m[2 * n] = gopen_const(c, gopen_mlimb(e, 0));
      m[2 * n + 1] = gopen_mlimb(e, 1) == 0 ? zv : gopen_const(c, gopen_mlimb(e, 1));
      n++;
    }
    for (d = 0; d < ZK_TDEC_PARTIES; d++)
      b[d] = side == 0 ? one : zv;
    zk_tdec_reduce(c, n, s, m, b, nl, red + side * ZK_TDEC_WEIGHTS, side == 0 ? u : w);
  }
  for (k = 0; k < 3; k++)
    v[k] = zk_input(c, 3 + k);
  zk_addp(c, v, w, wa, r);
  for (k = 0; k < 3; k++)
    zk_eq(c, r[k], u[k]);
  /* I = F 2^40 + R 2^20 + C (C8, C9): F 2 BSK, 3 pk, R = 2 g + row; F 5
   * squash, R = 16 g + 4 (level - 1) + row. */
  f = sq ? (uint64_t)5 << 40 | (uint64_t)(4 * (l / ZK_GOPEN_GN) + fam - ZK_GOPEN_SQ0) << 20 | cc
         : (fam == ZK_GOPEN_PK ? (uint64_t)3 : (uint64_t)2) << 40 | (uint64_t)(fam == ZK_GOPEN_BSK1) << 20 | cc;
  idx = zk_add(c, gopen_const(c, f), zk_mul(c, g, gopen_const(c, (uint64_t)1 << (sq ? 24 : 21))));
  for (d = 0; d < ZK_TDEC_PARTIES; d++) {
    x[0] = zk_weight(c, wa + ZK_ADDP_WEIGHTS + d);
    x[1] = kk;
    x[2] = idx;
    x[3] = gopen_const(c, d + 1);
    x[4] = i;
    for (k = 0; k < 3; k++)
      x[5 + k] = nl[3 * d + k];
    zk_out(c, d, zk_poseidon2_hash_values(c, ZK_CD_TAG, 8, x));
  }
}

/* V holds the limbs of share_i, U, W and (BSK row 0, squash rows 0 and 1) r.
 * A holds N mask words, or for squash 2 N (lo, hi) pairs, word k N + t at
 * 2 (k N + t). */
static void gopen_glwe_fill(ZkFr *wt, uint32_t fam, uint32_t l, const uint64_t *a, const uint64_t *s,
                            const uint64_t x[3], const uint64_t nz[15], const uint64_t *v, const ZkFr *salt) {
  static const uint64_t b[2][ZK_TDEC_PARTIES] = {{1, 1, 1, 1, 1}, {0, 0, 0, 0, 0}};
  static const uint64_t zero[3] = {0, 0, 0};
  const uint32_t nzw = gopen_nz(fam), red = gopen_red(fam), wa = red + 2 * ZK_TDEC_WEIGHTS, kn = gopen_keys(fam);
  const uint32_t cc = l % ZK_GOPEN_GN, xw = 3 * ZK_GOPEN_GN * kn, sq = fam >= ZK_GOPEN_SQ0;
  const uint32_t ki = sq ? (fam - ZK_GOPEN_SQ0) * ZK_GOPEN_GN + cc : cc;
  const uint64_t *mk = fam == ZK_GOPEN_PK ? zero : gopen_prod(fam) ? v + 9 : x;
  uint64_t sx[3 * ZK_TDEC_COORDS_MAX], m[2 * ZK_TDEC_COORDS_MAX];
  ZkFr fa[3], fb[3];
  uint32_t side, lo, hi, n, t, k, p, e;
  for (k = 0; k < xw; k++)
    wt[k] = zk_fr_u64(s[k]);
  /* x: 3 limbs for BSK and squash, none for pk. */
  for (k = 0; k < nzw - xw; k++)
    wt[xw + k] = zk_fr_u64(x[k]);
  for (k = 0; k < 3 * ZK_TDEC_PARTIES; k++)
    wt[nzw + k] = zk_fr_u64(nz[k]);
  if (gopen_prod(fam)) {
    for (k = 0; k < 3; k++) {
      fa[k] = zk_fr_u64(x[k]);
      fb[k] = zk_fr_u64(s[3 * ki + k]);
    }
    zk_mulp_fill(wt + nzw + 3 * ZK_TDEC_PARTIES, fa, fb);
  }
  for (side = 0; side < 2; side++) {
    lo = side == 0 ? 0 : cc + 1;
    hi = side == 0 ? cc + 1 : ZK_GOPEN_GN;
    n = 0;
    for (p = 0; p < kn; p++)
      for (t = lo; t < hi; t++, n++) {
        memcpy(sx + 3 * n, s + 3 * (p * ZK_GOPEN_GN + (cc + ZK_GOPEN_GN - t) % ZK_GOPEN_GN), 3 * sizeof sx[0]);
        m[2 * n] = sq ? a[2 * (p * ZK_GOPEN_GN + t)] : a[t];
        m[2 * n + 1] = sq ? a[2 * (p * ZK_GOPEN_GN + t) + 1] : 0;
      }
    if (gopen_slot(fam, l, side)) {
      e = gopen_mslot(fam, l, side);
      memcpy(sx + 3 * n, mk, 3 * sizeof sx[0]);
      m[2 * n] = gopen_mlimb(e, 0);
      m[2 * n + 1] = gopen_mlimb(e, 1);
      n++;
    }
    zk_tdec_reduce_fill(wt + red + side * ZK_TDEC_WEIGHTS, n, sx, m, b[side], nz, v + 3 + 3 * side);
  }
  for (k = 0; k < 3; k++) {
    fa[k] = zk_fr_u64(v[k]);
    fb[k] = zk_fr_u64(v[6 + k]);
  }
  zk_addp_fill(wt + wa, fa, fb);
  for (k = 0; k < ZK_TDEC_PARTIES; k++)
    wt[wa + ZK_ADDP_WEIGHTS + k] = salt[k];
}

uint32_t zk_gopen_weights(uint32_t fam, uint32_t l, uint32_t keys) {
  if (fam > ZK_GOPEN_SQ2 || keys > 1) return 0;
  if (fam > ZK_GOPEN_CAST)
    return l < ZK_GOPEN_GN * (fam >= ZK_GOPEN_SQ0 ? 3 : 1) && keys == 0
               ? gopen_red(fam) + 2 * ZK_TDEC_WEIGHTS + ZK_ADDP_WEIGHTS + ZK_TDEC_PARTIES
               : 0;
  if (l < 1 || l > 4) return 0;
  return GOPEN_SALT + ZK_TDEC_PARTIES + keys * GOPEN_COORDS;
}

void zk_gopen(ZkCircuit *c, uint32_t fam, uint32_t l, uint32_t keys) {
  uint32_t s[3 * GOPEN_COORDS], m[2 * GOPEN_COORDS], nl[3 * ZK_TDEC_PARTIES], b[ZK_TDEC_PARTIES], v[3], x[8];
  uint32_t kk, j, i, zv, one, idx, jw, k, d;
  uint64_t f;
  if (c->err != ZK_OK) return;
  if (zk_gopen_weights(fam, l, keys) == 0) {
    fail(c, ZK_ERR_COUNT);
    return;
  }
  if (zk_gopen_weights(fam, l, keys) > c->weights) {
    fail(c, ZK_ERR_REF);
    return;
  }
  if (fam > ZK_GOPEN_CAST) {
    gopen_glwe(c, fam, l);
    return;
  }
  kk = zk_input(c, 0);
  j = zk_input(c, 1);
  i = zk_input(c, 2);
  zk_party(c, i);
  zv = gopen_const(c, 0);
  one = gopen_const(c, 1);
  for (k = 0; k < 3 * GOPEN_COORDS; k++)
    s[k] = zk_weight(c, k);
  for (k = 0; k < ZK_GOPEN_N; k++) {
    m[2 * k] = zk_input(c, 6 + k);
    m[2 * k + 1] = zv;
  }
  m[2 * ZK_GOPEN_N] = gopen_const(c, (uint64_t)1 << (64 - 4 * l));
  m[2 * ZK_GOPEN_N + 1] = zv;
  for (d = 0; d < ZK_TDEC_PARTIES; d++)
    b[d] = one;
  for (k = 0; k < 3 * ZK_TDEC_PARTIES; k++)
    nl[k] = zk_weight(c, GOPEN_NZ + k);
  zk_tdec_reduce(c, GOPEN_COORDS, s, m, b, nl, GOPEN_RED, v);
  for (k = 0; k < 3; k++)
    zk_eq(c, v[k], zk_input(c, 3 + k));
  /* I = F 2^40 + (l - 1) 2^20 + j 2^22 (C9). */
  f = (fam == ZK_GOPEN_KSK ? (uint64_t)1 : (uint64_t)4) << 40 | (uint64_t)(l - 1) << 20;
  idx = zk_add(c, gopen_const(c, f), zk_mul(c, j, gopen_const(c, (uint64_t)1 << 22)));
  for (d = 0; d < ZK_TDEC_PARTIES; d++) {
    x[0] = zk_weight(c, GOPEN_SALT + d);
    x[1] = kk;
    x[2] = idx;
    x[3] = gopen_const(c, d + 1);
    x[4] = i;
    for (k = 0; k < 3; k++)
      x[5 + k] = nl[3 * d + k];
    zk_out(c, d, zk_poseidon2_hash_values(c, ZK_CD_TAG, 8, x));
  }
  if (keys == 0) return;
  /* The x_i index 6 2^40 + j 2^20 + v (C7). */
  f = (uint64_t)6 << 40 | (fam == ZK_GOPEN_KSK ? (uint64_t)1 : (uint64_t)2);
  jw = zk_add(c, gopen_const(c, f), zk_mul(c, j, gopen_const(c, (uint64_t)1 << 20)));
  x[1] = kk;
  x[3] = i;
  for (k = 0; k < GOPEN_COORDS; k++) {
    x[0] = zk_weight(c, GOPEN_SALT + ZK_TDEC_PARTIES + k);
    x[2] = k < ZK_GOPEN_N ? gopen_const(c, (uint64_t)6 << 40 | (uint64_t)k << 20) : jw;
    for (d = 0; d < 3; d++)
      x[4 + d] = s[3 * k + d];
    zk_out(c, ZK_TDEC_PARTIES + k, zk_poseidon2_hash_values(c, ZK_CB_TAG, 7, x));
  }
}

void zk_gopen_fill(ZkFr *wt, uint32_t fam, uint32_t l, uint32_t keys, const uint64_t *a, const uint64_t *s,
                   const uint64_t x[3], const uint64_t nz[15], const uint64_t *v, const ZkFr *salt) {
  static const uint64_t b[ZK_TDEC_PARTIES] = {1, 1, 1, 1, 1};
  uint64_t sx[3 * GOPEN_COORDS], m[2 * GOPEN_COORDS];
  uint32_t k;
  if (zk_gopen_weights(fam, l, keys) == 0) return;
  if (fam > ZK_GOPEN_CAST) {
    gopen_glwe_fill(wt, fam, l, a, s, x, nz, v, salt);
    return;
  }
  memcpy(sx, s, 3 * ZK_GOPEN_N * sizeof sx[0]);
  memcpy(sx + GOPEN_X, x, 3 * sizeof sx[0]);
  for (k = 0; k < ZK_GOPEN_N; k++) {
    m[2 * k] = a[k];
    m[2 * k + 1] = 0;
  }
  m[2 * ZK_GOPEN_N] = (uint64_t)1 << (64 - 4 * l);
  m[2 * ZK_GOPEN_N + 1] = 0;
  for (k = 0; k < 3 * GOPEN_COORDS; k++)
    wt[k] = zk_fr_u64(sx[k]);
  for (k = 0; k < 3 * ZK_TDEC_PARTIES; k++)
    wt[GOPEN_NZ + k] = zk_fr_u64(nz[k]);
  zk_tdec_reduce_fill(wt + GOPEN_RED, GOPEN_COORDS, sx, m, b, nz, v);
  for (k = 0; k < ZK_TDEC_PARTIES + keys * GOPEN_COORDS; k++)
    wt[GOPEN_SALT + k] = salt[k];
}
