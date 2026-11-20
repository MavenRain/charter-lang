/* The ZK writer rows (S7 U1, front/zk.h). `build/zktool` runs the rows of
 * the Circuit IR writer and is part of make check. `build/zktool smoke X Y W`
 * prints the words of the smoke relation: public inputs x and y, the private
 * weight w in a 1x1 mapped matrix, x * w = y, and the constant 1 as output 0.
 * `build/zktool bad KIND` prints the smoke words for (3, 15, 5) with one
 * reader defect, for the printer refusal rows of check-zk (removed in L0). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "front/squash.h"
#include "front/poseidon2.h"
#include "front/sha512.h"
#include "front/tfhe.h"
#include "front/tkeygen.h"
#include "front/tdec.h"
#include "front/tshare.h"
#include "front/zk.h"
#include "front/zkread.h"
#ifdef ZK_LIG
#include "front/lig.h"
#endif

static int fails;

static void check(int ok, const char *what) {
  if (ok) return;
  if (fails < 10) printf("FAIL zk writer %s\n", what);
  fails++;
}

/* The BN254 scalar field modulus r, low limb first (as src/front/zk.c). */
static const ZkFr ZK_R_FR = {{4026531841u, 1138881939u, 2042196113u, 674490440u, 2172737629u, 3092268470u,
                              3778125865u, 811880050u}};

static ZkFr r_minus_1(void) {
  ZkFr k = ZK_R_FR;
  k.limb[0]--;
  return k;
}

static ZkFr all_ones(void) {
  ZkFr k;
  memset(&k, 0xff, sizeof k);
  return k;
}

/* The smoke circuit: x = 0, y = 1, w = 2; 3 = mul x w; eq 3 y; 4 = const 1;
 * 5 = out 0 4; eq 5 4 (zk_out). */
static void smoke_circuit(ZkCircuit *c) {
  const ZkFr one = zk_fr_u64(1);
  zk_init(c, 2, 1, 1);
  zk_eq(c, zk_mul(c, zk_input(c, 0), zk_weight(c, 0)), zk_input(c, 1));
  zk_out(c, 0, zk_const(c, &one));
}

/* The smoke witness. The arrays belong to the caller. */
typedef struct Smoke {
  ZkFr input[2];
  ZkFr weight[1];
  ZkFr output[1];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkWitness w;
} Smoke;

static void smoke_witness(Smoke *s, ZkFr x, ZkFr y, ZkFr w) {
  s->input[0] = x;
  s->input[1] = y;
  s->weight[0] = w;
  s->output[0] = zk_fr_u64(1);
  s->matrix[0].rows = 1;
  s->matrix[0].cols = 1;
  s->matrix[0].entry = s->weight;
  s->map[0] = 0;
  s->w.inputs = 2;
  s->w.input = s->input;
  s->w.matrices = 1;
  s->w.matrix = s->matrix;
  s->w.maps = 1;
  s->w.map = s->map;
  s->w.outputs = 1;
  s->w.output = s->output;
}

static ZkErr smoke_words(uint64_t x, uint64_t y, uint64_t w, ZkWords *out) {
  ZkCircuit c;
  Smoke s;
  ZkErr e;
  smoke_circuit(&c);
  smoke_witness(&s, zk_fr_u64(x), zk_fr_u64(y), zk_fr_u64(w));
  e = zk_words(&c, &s.w, out);
  zk_free(&c);
  return e;
}

/* The smoke words for (3, 15, 5): 74 words. */
static const uint32_t SMOKE_3_15_5[] = {
    /* block 1: header, mul 0 2, eq 3 1, const 1, out 0 4, eq 5 4 */
    1, 2, 8, 2, 1, 1, 5, 4, 0, 2, 6, 3, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 6, 5, 4,
    /* block 2: one map, matrix 0 */
    1, 0,
    /* block 3: 2 inputs, 3 and 15 */
    2, 3, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0,
    /* block 4: header, the 1x1 matrix of w = 5, one rank 1 stage of dim 1, aux 0, the output 1 */
    1, 2, 8, 1, 2, 1, 1, 5, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0};
enum { SMOKE_WORDS = sizeof SMOKE_3_15_5 / sizeof SMOKE_3_15_5[0], SMOKE_BLOCK1 = 28 };

/* Checks that zk_words of C and W returns WANT and leaves OUT empty. */
static void expect_err(const ZkCircuit *c, const ZkWitness *w, ZkErr want, const char *what) {
  ZkWords out = {NULL, 0, 0};
  const ZkErr e = zk_words(c, w, &out);
  check(e == want, what);
  check(out.word == NULL && out.count == 0, what);
  zk_words_free(&out);
}

static void expect_ok(const ZkCircuit *c, const ZkWitness *w, const char *what) {
  ZkWords out = {NULL, 0, 0};
  check(zk_words(c, w, &out) == ZK_OK && out.count > 0, what);
  zk_words_free(&out);
}

static void rows_smoke(void) {
  ZkWords a = {NULL, 0, 0};
  ZkWords b = {NULL, 0, 0};
  check(smoke_words(3, 15, 5, &a) == ZK_OK, "smoke (3, 15, 5) is written");
  check(a.count == SMOKE_WORDS && memcmp(a.word, SMOKE_3_15_5, sizeof SMOKE_3_15_5) == 0,
        "smoke (3, 15, 5) word vector");
  check(smoke_words(3, 18, 6, &b) == ZK_OK, "smoke (3, 18, 6) is written");
  check(b.count == SMOKE_WORDS && memcmp(a.word, b.word, SMOKE_BLOCK1 * sizeof *a.word) == 0,
        "block 1 is the same for (3, 15, 5) and (3, 18, 6)");
  zk_words_free(&a);
  zk_words_free(&b);
}

static void rows_empty(void) {
  static const uint32_t want[] = {1, 2, 8, 0, 0, 0, 0, 0, 0, 1, 2, 8, 0, 1, 1, 0, 0};
  ZkCircuit c;
  ZkWitness w;
  ZkWords out = {NULL, 0, 0};
  memset(&w, 0, sizeof w);
  zk_init(&c, 0, 0, 0);
  check(zk_words(&c, &w, &out) == ZK_OK, "the empty 0/0/0 circuit is written");
  check(out.count == sizeof want / sizeof want[0] && memcmp(out.word, want, sizeof want) == 0,
        "the empty 0/0/0 circuit word vector");
  zk_words_free(&out);
  zk_free(&c);
}

/* r is refused and r - 1 is accepted for a const, an input, a weight and an output. */
static void rows_canonical(void) {
  const ZkFr r = ZK_R_FR;
  const ZkFr rm1 = r_minus_1();
  const ZkFr ones = all_ones();
  const ZkFr k[3] = {r, rm1, ones};
  const ZkErr want[3] = {ZK_ERR_NONCANONICAL, ZK_OK, ZK_ERR_NONCANONICAL};
  static const char *const name[3] = {"r", "r - 1", "2^256 - 1"};
  char what[96];
  unsigned i;
  check(!zk_canonical(&r) && zk_canonical(&rm1) && !zk_canonical(&ones), "zk_canonical of r, r - 1, 2^256 - 1");
  for (i = 0; i < 3; i++) {
    ZkCircuit c;
    Smoke s;
    const ZkFr three = zk_fr_u64(3);
    const ZkFr five = zk_fr_u64(5);
    const ZkFr fifteen = zk_fr_u64(15);
    /* const */
    zk_init(&c, 0, 0, 1);
    zk_out(&c, 0, zk_const(&c, &k[i]));
    smoke_witness(&s, three, fifteen, five);
    s.w.inputs = 0;
    s.w.matrices = 0;
    s.w.maps = 0;
    snprintf(what, sizeof what, "const %s", name[i]);
    if (want[i] == ZK_OK)
      expect_ok(&c, &s.w, what);
    else
      expect_err(&c, &s.w, want[i], what);
    zk_free(&c);
    /* input, weight, output */
    smoke_circuit(&c);
    smoke_witness(&s, k[i], fifteen, five);
    snprintf(what, sizeof what, "input %s", name[i]);
    if (want[i] == ZK_OK)
      expect_ok(&c, &s.w, what);
    else
      expect_err(&c, &s.w, want[i], what);
    smoke_witness(&s, three, fifteen, k[i]);
    snprintf(what, sizeof what, "weight %s", name[i]);
    if (want[i] == ZK_OK)
      expect_ok(&c, &s.w, what);
    else
      expect_err(&c, &s.w, want[i], what);
    smoke_witness(&s, three, fifteen, five);
    s.output[0] = k[i];
    snprintf(what, sizeof what, "output %s", name[i]);
    if (want[i] == ZK_OK)
      expect_ok(&c, &s.w, what);
    else
      expect_err(&c, &s.w, want[i], what);
    zk_free(&c);
  }
}

static void rows_refs(void) {
  ZkCircuit c;
  Smoke s;
  uint32_t u;
  const ZkFr one = zk_fr_u64(1);
  smoke_witness(&s, zk_fr_u64(3), zk_fr_u64(15), zk_fr_u64(5));
  /* an undefined operand */
  zk_init(&c, 2, 1, 1);
  check(zk_mul(&c, 0, 3) == 0 && c.err == ZK_ERR_REF, "mul of an undefined value");
  expect_err(&c, &s.w, ZK_ERR_REF, "mul of an undefined value");
  zk_free(&c);
  zk_init(&c, 2, 1, 1);
  zk_eq(&c, 0, 99);
  expect_err(&c, &s.w, ZK_ERR_REF, "eq of an undefined value");
  zk_free(&c);
  zk_init(&c, 2, 1, 1);
  zk_input(&c, 2);
  expect_err(&c, &s.w, ZK_ERR_REF, "input number 2 of 2");
  zk_free(&c);
  zk_init(&c, 2, 1, 1);
  zk_weight(&c, 1);
  expect_err(&c, &s.w, ZK_ERR_REF, "weight number 1 of 1");
  zk_free(&c);
  /* an out value as an add operand; an eq operand is allowed */
  zk_init(&c, 2, 1, 1);
  u = zk_out(&c, 0, zk_const(&c, &one));
  zk_eq(&c, u, 0);
  check(c.err == ZK_OK, "an out value as an eq operand");
  zk_add(&c, u, 0);
  check(c.err == ZK_ERR_REF, "an out value as an add operand");
  expect_err(&c, &s.w, ZK_ERR_REF, "an out value as an add operand");
  /* the first error is kept and later calls do nothing */
  u = (uint32_t)c.code.count;
  check(zk_const(&c, &one) == 0 && c.code.count == u && c.err == ZK_ERR_REF, "a call after an error");
  zk_free(&c);
}

static void rows_outputs(void) {
  ZkCircuit c;
  Smoke s;
  const ZkFr one = zk_fr_u64(1);
  smoke_witness(&s, zk_fr_u64(3), zk_fr_u64(15), zk_fr_u64(5));
  zk_init(&c, 2, 1, 1);
  zk_out(&c, 1, zk_const(&c, &one));
  expect_err(&c, &s.w, ZK_ERR_OUTPUT, "output number 1 of 1");
  zk_free(&c);
  zk_init(&c, 2, 1, 1);
  zk_out(&c, 0, zk_const(&c, &one));
  zk_out(&c, 0, 0);
  expect_err(&c, &s.w, ZK_ERR_OUTPUT, "output 0 written twice");
  zk_free(&c);
  zk_init(&c, 2, 1, 1);
  zk_eq(&c, zk_mul(&c, 0, 2), 1);
  expect_err(&c, &s.w, ZK_ERR_OUTPUT, "output 0 not written");
  zk_free(&c);
}

static void rows_witness(void) {
  ZkCircuit c;
  Smoke s;
  ZkFr two[2];
  ZkMatrix wide = {1, 2, NULL};
  ZkMatrix huge = {65536, 65536, NULL};
  two[0] = zk_fr_u64(5);
  two[1] = zk_fr_u64(5);
  wide.entry = two;
  smoke_circuit(&c);
  smoke_witness(&s, zk_fr_u64(3), zk_fr_u64(15), zk_fr_u64(5));
  s.w.inputs = 1;
  expect_err(&c, &s.w, ZK_ERR_WITNESS, "witness input count 1, circuit 2");
  s.w.inputs = 2;
  s.w.outputs = 0;
  expect_err(&c, &s.w, ZK_ERR_WITNESS, "witness output count 0, circuit 1");
  s.w.outputs = 1;
  s.map[0] = 1;
  expect_err(&c, &s.w, ZK_ERR_MAP, "map index 1 of 1 matrix");
  s.map[0] = 0;
  s.w.maps = 0;
  expect_err(&c, &s.w, ZK_ERR_MAP, "no map: mapped entries 0, weights 1");
  s.w.maps = 1;
  s.w.matrix = &wide;
  expect_err(&c, &s.w, ZK_ERR_MAP, "mapped entries 2, weights 1");
  s.w.matrix = &huge;
  expect_err(&c, &s.w, ZK_ERR_COUNT, "matrix entries 2^32 above the limit");
  s.w.matrix = s.matrix;
  expect_ok(&c, &s.w, "the restored smoke witness");
  zk_refuse(&c);
  expect_err(&c, &s.w, ZK_ERR_REFUSED, "refuse");
  zk_free(&c);
}

static void rows_init(void) {
  ZkCircuit c;
  ZkWitness w;
  memset(&w, 0, sizeof w);
  zk_init(&c, ZK_VALUES_MAX, 1, 0);
  expect_err(&c, &w, ZK_ERR_COUNT, "zk_init n + m above the limit");
  zk_free(&c);
  zk_init(&c, 1, UINT32_MAX, 0);
  expect_err(&c, &w, ZK_ERR_COUNT, "zk_init m = 2^32 - 1");
  zk_free(&c);
  zk_init(&c, UINT32_MAX, 0, 0);
  expect_err(&c, &w, ZK_ERR_COUNT, "zk_init n = 2^32 - 1");
  zk_free(&c);
  zk_init(&c, 0, 0, ZK_VALUES_MAX + 1u);
  expect_err(&c, &w, ZK_ERR_COUNT, "zk_init q above the limit");
  zk_free(&c);
  zk_init(&c, ZK_VALUES_MAX - 1u, 1, 0);
  check(c.err == ZK_OK, "zk_init n + m at the limit");
  zk_free(&c);
}

static void rows_text(void) {
  static const ZkErr all[] = {ZK_OK,        ZK_ERR_MEMORY,  ZK_ERR_COUNT, ZK_ERR_NONCANONICAL, ZK_ERR_REF,
                              ZK_ERR_OUTPUT, ZK_ERR_WITNESS, ZK_ERR_MAP,   ZK_ERR_REFUSED,      ZK_ERR_UNSAT};
  unsigned i;
  for (i = 0; i < sizeof all / sizeof all[0]; i++)
    check(strcmp(zk_err_text(all[i]), "the error is not known") != 0, "zk_err_text of each error");
}

/* S7 U2 D1: zk_check accepts the smoke witness and refuses a changed weight
 * or a changed output; Fr products agree with small integer products. */
static void rows_check(void) {
  ZkCircuit c;
  Smoke s;
  const ZkFr a = zk_fr_u64(4294967295u), b = zk_fr_u64(4294967297u), m1 = r_minus_1();
  const ZkFr ab = zk_fr_mul(&a, &b), one = zk_fr_u64(1), sq = zk_fr_mul(&m1, &m1);
  smoke_circuit(&c);
  smoke_witness(&s, zk_fr_u64(3), zk_fr_u64(15), zk_fr_u64(5));
  check(zk_check(&c, &s.w) == ZK_OK, "zk_check smoke (3, 15, 5)");
  s.weight[0] = zk_fr_u64(6);
  check(zk_check(&c, &s.w) == ZK_ERR_UNSAT, "zk_check smoke changed weight");
  smoke_witness(&s, zk_fr_u64(3), zk_fr_u64(15), zk_fr_u64(5));
  s.output[0] = zk_fr_u64(2);
  check(zk_check(&c, &s.w) == ZK_ERR_UNSAT, "zk_check smoke changed output");
  s.output[0] = ZK_R_FR;
  check(zk_check(&c, &s.w) == ZK_ERR_NONCANONICAL, "zk_check smoke noncanonical output");
  zk_free(&c);
  check(ab.limb[0] == 4294967295u && ab.limb[1] == 4294967295u && ab.limb[2] == 0, "Fr (2^32 - 1)(2^32 + 1) = 2^64 - 1");
  check(memcmp(&sq, &one, sizeof one) == 0, "Fr (r - 1)^2 = 1");
}

/* A gadget case: one public input, the weights in one 1 x m matrix, no
 * output. */
enum { CASE_WEIGHTS = 512 };
typedef enum { G_BITS, G_RANGE, G_SIGNED } Gadget;

typedef struct Case {
  ZkFr input[1];
  ZkFr weight[CASE_WEIGHTS];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkWitness w;
} Case;

static ZkFr fr_pow2_minus(uint32_t e, uint64_t d) {
  ZkFr k;
  const ZkFr dd = zk_fr_u64(d);
  memset(&k, 0, sizeof k);
  k.limb[e / 32] = 1u << (e % 32);
  return zk_fr_sub(&k, &dd);
}

static ZkFr fr_i64(int64_t v) {
  const ZkFr zero = zk_fr_u64(0);
  const ZkFr mag = zk_fr_u64(v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v);
  return v < 0 ? zk_fr_sub(&zero, &mag) : mag;
}

/* Circuit mode (zktool circuit NAME): finish prints the words of a satisfied
 * circuit and its witness to stdout (the check-zk crates; removed in L0). */
static int print_words;

/* zktool case (S7 U4 D31): the zk_check verdict, then the inputs, the weights
 * and the outputs of W, each value as 4 hex u64 limbs, the low limb first. */
static int print_case;
/* The cases mode (RESUME47): case_print records the first verdict of a case
 * and prints nothing when case_quiet. */
static int case_quiet, case_seen;
static ZkErr case_first = ZK_OK;

/* The S7 U6 rows (rows_u6, keygen_rows): timed_finish prints no line and
 * returns the zk_check verdict without the second check of finish. */
static int quiet_rows;

static void case_values(const char *what, const ZkFr *v, uint32_t n) {
  uint32_t i, j;
  printf("%s %u\n", what, (unsigned)n);
  for (i = 0; i < n; i++)
    for (j = 0; j < 4; j++)
      printf("%016llx%c", (unsigned long long)v[i].limb[2 * j] | (unsigned long long)v[i].limb[2 * j + 1] << 32,
             j == 3 ? '\n' : ' ');
}

static ZkErr case_print(ZkErr e, const ZkWitness *w) {
  if (case_seen++ == 0) case_first = e;
  if (case_quiet) return ZK_OK;
  printf("check %s\n", e == ZK_OK ? "accept" : "refuse");
  case_values("inputs", w->input, w->inputs);
  case_values("weights", w->matrix[0].entry, w->matrix[0].rows * w->matrix[0].cols);
  case_values("outputs", w->output, w->outputs);
  return ZK_OK;
}

#ifdef ZK_LIG
/* The Ligero rows of the second build (build/ligzk, make check-lig; S7 L4,
 * Q-CL-1). After zk_check of each gadget gave E: for ZK_OK, lig_prove and
 * lig_verify give LIG_OK and the first public value plus 1 does not verify;
 * for ZK_ERR_UNSAT, lig_prove gives LIG_ERR_UNSAT and a forced proof (no
 * tweak) does not verify. Any other E is a builder or an API refusal: no
 * Ligero row. One row on stdout for each call; a false row is a FAIL row. */
static uint32_t lig_count;

/* 1 when the proof P of C does not verify for the public values of W with
 * the first one plus 1 (or when C has no public value). */
static int lig_bound(const ZkCircuit *c, const ZkWitness *w, const LigProof *p) {
  const ZkFr one = zk_fr_u64(1);
  const uint32_t n = c->inputs + c->outputs;
  ZkFr *v = malloc(sizeof(ZkFr) * ((size_t)n + 1));
  int ok;
  if (v == NULL) return 0;
  if (n == 0) {
    free(v);
    return 1;
  }
  if (c->inputs != 0) memcpy(v, w->input, sizeof(ZkFr) * c->inputs);
  if (c->outputs != 0) memcpy(v + c->inputs, w->output, sizeof(ZkFr) * c->outputs);
  v[0] = zk_fr_add(&v[0], &one);
  ok = lig_verify(c, v, c->inputs, v + c->inputs, c->outputs, p->byte, p->count) != LIG_OK;
  free(v);
  return ok;
}

static ZkErr lig_hook(const char *what, const ZkCircuit *c, const ZkWitness *w, ZkErr e) {
  const int sat = e == ZK_OK;
  uint8_t seed[LIG_SEED_BYTES];
  LigParams p;
  LigProof pr = {NULL, 0};
  LigErr a, f, v;
  clock_t t0, t1, t2;
  uint32_t lk = 0;
  int ok;
  lig_count++;
  if (e != ZK_OK && e != ZK_ERR_UNSAT) {
    printf("lig %u %s no row: %s\n", (unsigned)lig_count, what, zk_err_text(e));
    return e;
  }
  memset(seed, 0, sizeof seed);
  memcpy(seed, &lig_count, sizeof lig_count);
  memset(&p, 0, sizeof p);
  check(lig_params(c, &p) == LIG_OK, "lig_params of a gadget");
  while (lk < 31 && (1u << lk) < p.k) lk++;
  t0 = clock();
  a = lig_prove(c, w, seed, &pr);
  f = (sat || a == LIG_OK) ? a : lig_prove_forced(c, w, seed, NULL, 0, &pr);
  t1 = clock();
  v = lig_verify(c, w->input, c->inputs, w->output, c->outputs, pr.byte, pr.count);
  t2 = clock();
  ok = sat ? a == LIG_OK && f == LIG_OK && v == LIG_OK && lig_bound(c, w, &pr)
           : a == LIG_ERR_UNSAT && f == LIG_OK && v != LIG_OK;
  printf("lig %u %s values %u muls %u log k %u rows %u proof bytes %lu prove %.3f s verify %.3f s %s %s\n",
         (unsigned)lig_count, what, (unsigned)c->vals, (unsigned)p.muls, (unsigned)lk, (unsigned)p.rows,
         (unsigned long)pr.count, (double)(t1 - t0) / CLOCKS_PER_SEC, (double)(t2 - t1) / CLOCKS_PER_SEC,
         sat ? "accept" : "refuse", ok ? "ok" : "FAIL");
  check(ok, "lig row of a gadget");
  lig_proof_free(&pr);
  return e;
}
#else
#define lig_hook(what, c, w, e) (e)
#endif

/* The tail of finish after zk_check gave E: case_print in the case mode, then
 * the words when print_words. */
static ZkErr finish_words(const ZkCircuit *c, const ZkWitness *w, ZkErr e) {
  ZkWords out = {NULL, 0, 0};
  if (print_case) return case_print(e, w);
  if (e != ZK_OK || !print_words) return e;
  e = zk_words(c, w, &out);
  check(e != ZK_OK || zk_print(&out, stdout), "circuit words printed");
  zk_words_free(&out);
  return e;
}

static ZkErr finish(const ZkCircuit *c, const ZkWitness *w) {
  const ZkErr e = zk_check(c, w);
  return finish_words(c, w, lig_hook("finish", c, w, e));
}

/* zk_check of gadget G on public X: N bits, the range [0, B] or N-bit signed.
 * The first NT weights become TAMPER after the fill. */
static ZkErr gadget_check(Gadget g, const ZkFr *x, uint32_t n, const ZkFr *b, const ZkFr *tamper, uint32_t nt) {
  static Case k;
  ZkCircuit c;
  ZkErr e;
  uint32_t m = n, i;
  if (g == G_RANGE) m = zk_range_weights(b);
  if (m > CASE_WEIGHTS) return ZK_ERR_COUNT;
  memset(&k, 0, sizeof k);
  k.input[0] = *x;
  k.matrix[0].rows = 1;
  k.matrix[0].cols = m;
  k.matrix[0].entry = k.weight;
  k.w.inputs = 1;
  k.w.input = k.input;
  k.w.matrices = 1;
  k.w.matrix = k.matrix;
  k.w.maps = 1;
  k.w.map = k.map;
  zk_init(&c, 1, m, 0);
  switch (g) {
    case G_BITS:
      zk_bits(&c, zk_input(&c, 0), 0, n);
      zk_bits_fill(k.weight, x, n);
      break;
    case G_RANGE:
      zk_range(&c, zk_input(&c, 0), b, 0);
      zk_range_fill(k.weight, x, b);
      break;
    case G_SIGNED:
      zk_signed(&c, zk_input(&c, 0), 0, n);
      zk_signed_fill(k.weight, x, n);
      break;
  }
  for (i = 0; i < nt && i < m; i++) k.weight[i] = tamper[i];
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

/* 1 when X <= B as integers (the C predicate of the range gadget). */
static int le(const ZkFr *x, const ZkFr *b) {
  unsigned i;
  for (i = ZK_LIMBS; i > 0; i--)
    if (x->limb[i - 1] != b->limb[i - 1]) return x->limb[i - 1] < b->limb[i - 1];
  return 1;
}

/* S7 U2 D2 and D3 boundary rows; D8 non-boolean bit and value above bound. */
static void rows_gadgets(void) {
  static const uint32_t nbits[4] = {1, 2, 64, 252};
  /* p = 2^192 - 1253375 (src/front/tshare.h). */
  const ZkFr bound[7] = {zk_fr_u64(0),          zk_fr_u64(1),
                         fr_pow2_minus(64, 1),  fr_pow2_minus(64, 2),
                         fr_pow2_minus(128, 1), fr_pow2_minus(192, 1253376),
                         fr_pow2_minus(252, 1)};
  static const char *const bname[7] = {"0", "1", "2^64 - 1", "2^64 - 2", "2^128 - 1", "p - 1", "2^252 - 1"};
  static const int64_t sv[6] = {INT64_MIN, -1, 0, 1, INT64_MAX - 1, INT64_MAX};
  const ZkFr one = zk_fr_u64(1), two = zk_fr_u64(2), zero = zk_fr_u64(0);
  const ZkFr nonbool[2] = {two, zero};
  char what[96];
  unsigned i;
  for (i = 0; i < 4; i++) {
    const ZkFr max = fr_pow2_minus(nbits[i], 1), over = fr_pow2_minus(nbits[i], 0);
    snprintf(what, sizeof what, "bits n %u: 0, 1, max accepted; max + 1 refused", (unsigned)nbits[i]);
    check(gadget_check(G_BITS, &zero, nbits[i], NULL, NULL, 0) == ZK_OK, what);
    check(gadget_check(G_BITS, &one, nbits[i], NULL, NULL, 0) == ZK_OK, what);
    check(gadget_check(G_BITS, &max, nbits[i], NULL, NULL, 0) == ZK_OK, what);
    check(gadget_check(G_BITS, &over, nbits[i], NULL, NULL, 0) == ZK_ERR_UNSAT, what);
  }
  check(gadget_check(G_BITS, &two, 2, NULL, nonbool, 2) == ZK_ERR_UNSAT, "bits: x = 2 as bits (2, 0) refused");
  check(gadget_check(G_BITS, &two, 2, NULL, NULL, 0) == ZK_OK, "bits: x = 2 as bits (0, 1) accepted");
  check(gadget_check(G_BITS, &zero, 0, NULL, NULL, 0) == ZK_ERR_COUNT, "bits n 0 is ZK_ERR_COUNT");
  check(gadget_check(G_BITS, &zero, ZK_BITS_MAX + 1, NULL, NULL, 0) == ZK_ERR_COUNT, "bits n 253 is ZK_ERR_COUNT");
  for (i = 0; i < 7; i++) {
    const ZkFr above = zk_fr_add(&bound[i], &one);
    const ZkFr xs[4] = {zero, one, bound[i], above};
    unsigned j;
    for (j = 0; j < 4; j++) {
      snprintf(what, sizeof what, "range [0, %s] at case %u agrees with x <= B", bname[i], j);
      check((gadget_check(G_RANGE, &xs[j], 0, &bound[i], NULL, 0) == ZK_OK) == le(&xs[j], &bound[i]), what);
    }
  }
  {
    const ZkFr big = fr_pow2_minus(252, 0);
    check(gadget_check(G_RANGE, &zero, 0, &big, NULL, 0) == ZK_ERR_COUNT, "range [0, 2^252] is ZK_ERR_COUNT");
  }
  for (i = 0; i < 6; i++) {
    const ZkFr x = fr_i64(sv[i]);
    snprintf(what, sizeof what, "signed 64 accepts the int64 %lld", (long long)sv[i]);
    check(gadget_check(G_SIGNED, &x, 64, NULL, NULL, 0) == ZK_OK, what);
  }
  {
    const ZkFr lo = fr_i64(INT64_MIN), hi = fr_pow2_minus(63, 0), m1 = fr_i64(-1);
    const ZkFr below = zk_fr_sub(&lo, &one);
    const ZkFr top127 = fr_pow2_minus(127, 1), over127 = fr_pow2_minus(127, 0);
    check(gadget_check(G_SIGNED, &hi, 64, NULL, NULL, 0) == ZK_ERR_UNSAT, "signed 64 refuses 2^63");
    check(gadget_check(G_SIGNED, &below, 64, NULL, NULL, 0) == ZK_ERR_UNSAT, "signed 64 refuses -2^63 - 1");
    check(gadget_check(G_SIGNED, &m1, 1, NULL, NULL, 0) == ZK_OK, "signed 1 accepts -1");
    check(gadget_check(G_SIGNED, &one, 1, NULL, NULL, 0) == ZK_ERR_UNSAT, "signed 1 refuses 1");
    check(gadget_check(G_SIGNED, &top127, 128, NULL, NULL, 0) == ZK_OK, "signed 128 accepts 2^127 - 1");
    check(gadget_check(G_SIGNED, &over127, 128, NULL, NULL, 0) == ZK_ERR_UNSAT, "signed 128 refuses 2^127");
  }
}

typedef enum { A_SPLIT, A_ADD64, A_MULADD64, A_ADD128, A_MUL128, A_ADDP, A_MULP } Arith;

enum { ARITH_WEIGHTS = 2048 };

typedef struct ArithCase {
  ZkFr input[6];
  ZkFr output[3];
  ZkFr weight[ARITH_WEIGHTS];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkWitness w;
} ArithCase;

/* A split shape: X = hi 2^LO + lo with hi in [0, HI]. */
typedef struct SplitShape {
  uint32_t lo;
  ZkFr hi;
} SplitShape;

/* The Fr element of three 64-bit words, low word first. */
static ZkFr fr_w3(uint64_t w0, uint64_t w1, uint64_t w2) {
  const uint64_t w[3] = {w0, w1, w2};
  ZkFr k;
  unsigned i;
  memset(&k, 0, sizeof k);
  for (i = 0; i < 3; i++) {
    k.limb[2 * i] = (uint32_t)w[i];
    k.limb[2 * i + 1] = (uint32_t)(w[i] >> 32);
  }
  return k;
}

/* zk_check of the D4 or D5 gadget G on public inputs IN, with OUT as its
 * instance outputs (two, or the three limbs of a D5 result). A D5 gadget
 * binds each operand to an element first (weights 0 and ZK_FP_WEIGHTS). After the fill, weights AT .. AT + NT - 1 become TAMPER. */
static ZkErr arith_check(Arith g, const SplitShape *sp, const ZkFr *in, const ZkFr *out, const ZkFr *tamper,
                         uint32_t at, uint32_t nt) {
  static ArithCase k;
  static const uint32_t nin[7] = {1, 2, 3, 4, 4, 6, 6};
  ZkCircuit c;
  ZkErr e;
  uint32_t m = 0, n, q, i, a[3], b[3], r[3] = {0, 0, 0};
  switch (g) {
    case A_SPLIT:
      m = zk_split_weights(sp->lo, &sp->hi);
      break;
    case A_ADD64:
      m = ZK_ADD64_WEIGHTS;
      break;
    case A_MULADD64:
      m = ZK_MULADD64_WEIGHTS;
      break;
    case A_ADD128:
      m = ZK_ADD128_WEIGHTS;
      break;
    case A_MUL128:
      m = ZK_MUL128_WEIGHTS;
      break;
    case A_ADDP:
      m = 2 * ZK_FP_WEIGHTS + ZK_ADDP_WEIGHTS;
      break;
    case A_MULP:
      m = 2 * ZK_FP_WEIGHTS + ZK_MULP_WEIGHTS;
      break;
  }
  if (m > ARITH_WEIGHTS) return ZK_ERR_COUNT;
  n = nin[g];
  q = g == A_ADDP || g == A_MULP ? 3 : 2;
  memset(&k, 0, sizeof k);
  for (i = 0; i < n; i++) k.input[i] = in[i];
  for (i = 0; i < q; i++) k.output[i] = out[i];
  k.matrix[0].rows = 1;
  k.matrix[0].cols = m;
  k.matrix[0].entry = k.weight;
  k.w.inputs = n;
  k.w.input = k.input;
  k.w.matrices = 1;
  k.w.matrix = k.matrix;
  k.w.maps = 1;
  k.w.map = k.map;
  k.w.outputs = q;
  k.w.output = k.output;
  zk_init(&c, n, m, q);
  switch (g) {
    case A_SPLIT:
      r[0] = zk_split(&c, zk_input(&c, 0), sp->lo, &sp->hi, 0, &r[1]);
      zk_split_fill(k.weight, &in[0], sp->lo, &sp->hi);
      break;
    case A_ADD64:
      r[0] = zk_add64(&c, zk_input(&c, 0), zk_input(&c, 1), 0, &r[1]);
      zk_add64_fill(k.weight, &in[0], &in[1]);
      break;
    case A_MULADD64:
      r[0] = zk_muladd64(&c, zk_input(&c, 0), zk_input(&c, 1), zk_input(&c, 2), 0, &r[1]);
      zk_muladd64_fill(k.weight, &in[0], &in[1], &in[2]);
      break;
    case A_ADD128:
    case A_MUL128:
      a[0] = zk_input(&c, 0);
      a[1] = zk_input(&c, 1);
      b[0] = zk_input(&c, 2);
      b[1] = zk_input(&c, 3);
      if (g == A_ADD128) {
        zk_add128(&c, a, b, 0, r);
        zk_add128_fill(k.weight, &in[0], &in[2]);
      } else {
        zk_mul128(&c, a, b, 0, r);
        zk_mul128_fill(k.weight, &in[0], &in[2]);
      }
      break;
    case A_ADDP:
    case A_MULP:
      for (i = 0; i < 3; i++) a[i] = zk_input(&c, i);
      for (i = 0; i < 3; i++) b[i] = zk_input(&c, 3 + i);
      zk_fp_bind(&c, a, 0);
      zk_fp_bind(&c, b, ZK_FP_WEIGHTS);
      zk_fp_fill(k.weight, &in[0]);
      zk_fp_fill(k.weight + ZK_FP_WEIGHTS, &in[3]);
      if (g == A_ADDP) {
        zk_addp(&c, a, b, 2 * ZK_FP_WEIGHTS, r);
        zk_addp_fill(k.weight + 2 * ZK_FP_WEIGHTS, &in[0], &in[3]);
      } else {
        zk_mulp(&c, a, b, 2 * ZK_FP_WEIGHTS, r);
        zk_mulp_fill(k.weight + 2 * ZK_FP_WEIGHTS, &in[0], &in[3]);
      }
      break;
  }
  zk_out(&c, 0, r[0]);
  zk_out(&c, 1, r[1]);
  if (q == 3) zk_out(&c, 2, r[2]);
  for (i = 0; i < nt && at + i < m; i++) k.weight[at + i] = tamper[i];
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

/* 1 when the split (LO, HI) of X with outputs (OLO, OHI) gives WANT. */
static int split_row(uint32_t lo, const ZkFr *hi, const ZkFr *x, const ZkFr *olo, const ZkFr *ohi, ZkErr want) {
  SplitShape s;
  ZkFr out[2];
  s.lo = lo;
  s.hi = *hi;
  out[0] = *olo;
  out[1] = *ohi;
  return arith_check(A_SPLIT, &s, x, out, NULL, 0, 0) == want;
}

/* S7 U2 D4 rows: mod 2^64 against uint64_t wrap, mod 2^128 against
 * squash_add and squash_mul (src/front/squash.c), the split bounds, and the
 * D8 alternate carry, quotient above its bound and changed output. */
static void rows_arith(void) {
  static const uint64_t v[6] = {0, 1, 2, UINT64_C(0x7fffffffffffffff), UINT64_C(0x0123456789abcdef), UINT64_MAX};
  static const uint64_t w[7][2] = {{0, 0},
                                   {1, 0},
                                   {UINT64_MAX, 0},
                                   {0, 1},
                                   {UINT64_MAX, UINT64_MAX},
                                   {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)},
                                   {0, UINT64_C(0x8000000000000000)}};
  static ZkFr tamper[ZK_MULADD64_WEIGHTS];
  const ZkFr one = zk_fr_u64(1), zero = zk_fr_u64(0), m64 = fr_pow2_minus(64, 1);
  const ZkFr q0 = fr_pow2_minus(64, 2), q1 = fr_pow2_minus(65, 3);
  char what[128];
  unsigned i, j, l;
  check(ZK_ADD64_WEIGHTS == zk_split_weights(64, &one), "D4 weight count add64");
  check(ZK_MULADD64_WEIGHTS == zk_split_weights(64, &m64), "D4 weight count muladd64");
  check(ZK_ADD128_WEIGHTS == 2 * zk_split_weights(64, &one), "D4 weight count add128");
  check(ZK_MUL128_WEIGHTS == zk_split_weights(64, &q0) + zk_split_weights(64, &q1), "D4 weight count mul128");
  for (i = 0; i < 6; i++)
    for (j = 0; j < 6; j++) {
      const uint64_t s = v[i] + v[j];
      const ZkFr in[2] = {zk_fr_u64(v[i]), zk_fr_u64(v[j])};
      const ZkFr out[2] = {zk_fr_u64(s), zk_fr_u64(s < v[i])};
      const ZkFr bad[2] = {zk_fr_add(&out[0], &one), out[1]};
      snprintf(what, sizeof what, "add 2^64 case %u %u equals uint64_t wrap; a changed sum is refused", i, j);
      check(arith_check(A_ADD64, NULL, in, out, NULL, 0, 0) == ZK_OK, what);
      check(arith_check(A_ADD64, NULL, in, bad, NULL, 0, 0) == ZK_ERR_UNSAT, what);
      for (l = 0; l < 6; l++) {
        const Squash128 t =
            squash_add(squash_mul(squash_from_u64(v[i]), squash_from_u64(v[j])), squash_from_u64(v[l]));
        const ZkFr in3[3] = {zk_fr_u64(v[i]), zk_fr_u64(v[j]), zk_fr_u64(v[l])};
        const ZkFr out3[2] = {zk_fr_u64(t.lo), zk_fr_u64(t.hi)};
        snprintf(what, sizeof what, "muladd 2^64 case %u %u %u equals uint64_t wrap and squash_mul", i, j, l);
        check(t.lo == v[i] * v[j] + v[l] && arith_check(A_MULADD64, NULL, in3, out3, NULL, 0, 0) == ZK_OK, what);
      }
    }
  for (i = 0; i < 7; i++)
    for (j = 0; j < 7; j++) {
      const Squash128 x = {w[i][0], w[i][1]}, y = {w[j][0], w[j][1]};
      const Squash128 s = squash_add(x, y), p = squash_mul(x, y);
      const ZkFr in[4] = {zk_fr_u64(x.lo), zk_fr_u64(x.hi), zk_fr_u64(y.lo), zk_fr_u64(y.hi)};
      const ZkFr so[2] = {zk_fr_u64(s.lo), zk_fr_u64(s.hi)}, po[2] = {zk_fr_u64(p.lo), zk_fr_u64(p.hi)};
      const ZkFr bad[2] = {po[0], zk_fr_add(&po[1], &one)};
      snprintf(what, sizeof what, "add and mul 2^128 case %u %u equal squash_add and squash_mul", i, j);
      check(arith_check(A_ADD128, NULL, in, so, NULL, 0, 0) == ZK_OK, what);
      check(arith_check(A_MUL128, NULL, in, po, NULL, 0, 0) == ZK_OK, what);
      check(arith_check(A_MUL128, NULL, in, bad, NULL, 0, 0) == ZK_ERR_UNSAT, what);
    }
  {
    const ZkFr x1 = fr_w3(UINT64_MAX, 1, 0), x2 = fr_w3(5, 2, 0), five = zk_fr_u64(5), two = zk_fr_u64(2);
    const ZkFr x3 = fr_w3(UINT64_MAX, UINT64_MAX - 1, 0), x4 = fr_w3(0, UINT64_MAX, 0);
    const ZkFr x5 = fr_w3(UINT64_MAX, UINT64_MAX - 2, 1), x6 = fr_w3(0, UINT64_MAX - 1, 1);
    const ZkFr h6 = fr_w3(UINT64_MAX - 1, 1, 0);
    const ZkFr b53 = fr_pow2_minus(53, 1), b52 = fr_pow2_minus(52, 1), t252 = fr_pow2_minus(252, 1);
    check(split_row(64, &one, &x1, &m64, &one, ZK_OK), "split [0, 1]: 2^65 - 1 accepted");
    check(split_row(64, &one, &x2, &five, &two, ZK_ERR_UNSAT), "split [0, 1]: quotient 2 (one above) refused");
    check(split_row(64, &q0, &x3, &m64, &q0, ZK_OK), "split q0: quotient 2^64 - 2 accepted");
    check(split_row(64, &q0, &x4, &zero, &m64, ZK_ERR_UNSAT), "split q0: quotient 2^64 - 1 refused");
    check(split_row(64, &q1, &x5, &m64, &q1, ZK_OK), "split q1: quotient 2^65 - 3 accepted");
    check(split_row(64, &q1, &x6, &zero, &h6, ZK_ERR_UNSAT), "split q1: quotient 2^65 - 2 refused");
    check(split_row(200, &b53, &zero, &zero, &zero, ZK_ERR_COUNT), "split 200 + 53 bits is ZK_ERR_COUNT");
    check(split_row(200, &b52, &zero, &zero, &zero, ZK_OK), "split 200 + 52 bits accepted");
    check(split_row(0, &one, &zero, &zero, &zero, ZK_ERR_COUNT), "split lo 0 is ZK_ERR_COUNT");
    check(split_row(252, &zero, &t252, &t252, &zero, ZK_OK), "split 252 + 0 bits accepts 2^252 - 1");
    check(split_row(253, &zero, &zero, &zero, &zero, ZK_ERR_COUNT), "split lo 253 is ZK_ERR_COUNT");
  }
  {
    /* D8 alternate carry, add: (2^64 - 1) + (2^64 - 1) with carry 0 needs lo =
     * 2^65 - 2. Bit 63 = 3 gives that word, so only b (b - 1) = 0 refuses it. */
    const ZkFr in[2] = {m64, m64};
    const ZkFr out[2] = {q0, one};
    const ZkFr alt[2] = {fr_pow2_minus(65, 2), zero};
    const ZkFr t3[3] = {zk_fr_u64(3), zero, zero};
    check(arith_check(A_ADD64, NULL, in, out, NULL, 0, 0) == ZK_OK, "add 2^64: (2^64 - 1) 2 accepted");
    check(arith_check(A_ADD64, NULL, in, alt, t3, 63, 3) == ZK_ERR_UNSAT, "add 2^64: alternate carry 0 refused");
  }
  {
    /* D8 alternate carry, muladd: 2 2 + 0 as (q + 1, r - 2^64 mod r), with
     * r - 2^64 as bit 0 and the range bits of q + 1 = 1 valid. */
    const ZkFr two = zk_fr_u64(2), four = zk_fr_u64(4), p64 = fr_pow2_minus(64, 0);
    const ZkFr in3[3] = {two, two, zero};
    const ZkFr out[2] = {four, zero};
    ZkFr alt[2];
    memset(tamper, 0, sizeof tamper);
    tamper[0] = zk_fr_sub(&four, &p64);
    tamper[64] = one;
    tamper[65] = one;
    alt[0] = tamper[0];
    alt[1] = one;
    check(arith_check(A_MULADD64, NULL, in3, out, NULL, 0, 0) == ZK_OK, "muladd 2^64: 2 2 + 0 accepted");
    check(arith_check(A_MULADD64, NULL, in3, alt, tamper, 0, ZK_MULADD64_WEIGHTS) == ZK_ERR_UNSAT,
          "muladd 2^64: alternate carry (q + 1, r - 2^64 mod r) refused");
  }
}

/* D5: the p of src/front/tshare.h (2^192 - 1253375) in 64-bit limbs. */
static const uint64_t FP_P[3] = {0xffffffffffece001u, UINT64_MAX, UINT64_MAX};

/* The limb elements of the 64-bit words X. */
static void fp_limbs(ZkFr out[3], const uint64_t x[3]) {
  unsigned i;
  for (i = 0; i < 3; i++) out[i] = fr_w3(x[i], 0, 0);
}

/* The 64-bit limb K of X as an Fr element. */
static ZkFr fr_limb64(const ZkFr *x, unsigned k) {
  return fr_w3(((uint64_t)x->limb[2 * k + 1] << 32) | x->limb[2 * k], 0, 0);
}

/* D5 rows: add and mul mod p over 7 x 7 values equal tshare_add and
 * tshare_mul (src/front/tshare.c); p as an operand or a result, a quotient
 * q + 1 with r - p, an alternate carry and a changed output limb are refused. */
static void rows_fp(void) {
  static const uint64_t v[7][3] = {{0, 0, 0},
                                   {1, 0, 0},
                                   {2, 0, 0},
                                   {UINT64_MAX, 0, 0},
                                   {UINT64_MAX, UINT64_MAX, 0},
                                   {0xffffffffffece000u, UINT64_MAX, UINT64_MAX},
                                   {0x0123456789abcdefu, 0xfedcba9876543210u, 0x8000000000000001u}};
  static const uint64_t z3[3] = {0, 0, 0}, o3[3] = {1, 0, 0}, e64[3] = {0, 1, 0}, e128[3] = {0, 0, 1};
  static ZkFr tb[2 * ZK_FP_WEIGHTS];
  const uint64_t f3[3] = {TSHARE_FOLD, 0, 0};
  const ZkFr one = zk_fr_u64(1), two = zk_fr_u64(2), fold = zk_fr_u64(TSHARE_FOLD);
  const ZkFr pfr = fr_w3(FP_P[0], FP_P[1], FP_P[2]), pm1 = fr_w3(FP_P[0] - 1, FP_P[1], FP_P[2]);
  ZkFr in[6], out[3], rp;
  TshareFe x, y, m;
  char what[96];
  unsigned i, j;
  check(ZK_FP_WEIGHTS == zk_range_weights(&pm1), "D5 weight count element");
  check(ZK_ADDP_WEIGHTS == 1 + ZK_FP_WEIGHTS, "D5 weight count addp");
  check(ZK_MULP_WEIGHTS == 2 * ZK_FP_WEIGHTS + 4 * 68, "D5 weight count mulp");
  for (i = 0; i < 7; i++)
    for (j = 0; j < 7; j++) {
      TshareFe s;
      ZkFr so[3], bad[3];
      memcpy(x.w, v[i], sizeof x.w);
      memcpy(y.w, v[j], sizeof y.w);
      s = tshare_add(x, y);
      m = tshare_mul(x, y);
      fp_limbs(in, v[i]);
      fp_limbs(in + 3, v[j]);
      fp_limbs(so, s.w);
      fp_limbs(out, m.w);
      memcpy(bad, out, sizeof bad);
      bad[1] = zk_fr_add(&out[1], &one);
      snprintf(what, sizeof what, "add and mul mod p case %u %u equal tshare_add and tshare_mul", i, j);
      check(arith_check(A_ADDP, NULL, in, so, NULL, 0, 0) == ZK_OK, what);
      check(arith_check(A_MULP, NULL, in, out, NULL, 0, 0) == ZK_OK, what);
      check(arith_check(A_MULP, NULL, in, bad, NULL, 0, 0) == ZK_ERR_UNSAT, what);
    }
  /* p as an operand: p + 1 = 1 and p 1 = 0 with honest fills are refused by the range. */
  fp_limbs(in, FP_P);
  fp_limbs(in + 3, o3);
  fp_limbs(out, o3);
  check(arith_check(A_ADDP, NULL, in, out, NULL, 0, 0) == ZK_ERR_UNSAT, "add mod p: operand p refused");
  fp_limbs(out, z3);
  check(arith_check(A_MULP, NULL, in, out, NULL, 0, 0) == ZK_ERR_UNSAT, "mul mod p: operand p refused");
  /* p as a result: (p - 1) + 1 = 0 with q 1 is accepted, = p with q 0 is refused. */
  fp_limbs(in, v[5]);
  check(arith_check(A_ADDP, NULL, in, out, NULL, 0, 0) == ZK_OK, "add mod p: (p - 1) + 1 = 0 accepted");
  tb[0] = zk_fr_u64(0);
  zk_range_fill(tb + 1, &pfr, &pm1);
  fp_limbs(out, FP_P);
  check(arith_check(A_ADDP, NULL, in, out, tb, 2 * ZK_FP_WEIGHTS, ZK_ADDP_WEIGHTS) == ZK_ERR_UNSAT,
        "add mod p: result p with q 0 refused");
  /* q + 1 with r - p (the low 192 bits are the limbs): add 0 + 1 with q 1. */
  fp_limbs(in, z3);
  rp = zk_fr_sub(&one, &pfr);
  tb[0] = one;
  zk_range_fill(tb + 1, &rp, &pm1);
  for (i = 0; i < 3; i++) out[i] = fr_limb64(&rp, i);
  check(arith_check(A_ADDP, NULL, in, out, tb, 2 * ZK_FP_WEIGHTS, ZK_ADDP_WEIGHTS) == ZK_ERR_UNSAT,
        "add mod p: q + 1 with r - p refused");
  /* mul 2^64 2^128 = p + 1253375: q 1 accepted, q 2 with r 1253375 - p refused. */
  memcpy(x.w, e64, sizeof x.w);
  memcpy(y.w, e128, sizeof y.w);
  m = tshare_mul(x, y);
  check(m.w[0] == TSHARE_FOLD && m.w[1] == 0 && m.w[2] == 0, "tshare_mul 2^64 2^128 = 1253375");
  fp_limbs(in, e64);
  fp_limbs(in + 3, e128);
  fp_limbs(out, f3);
  check(arith_check(A_MULP, NULL, in, out, NULL, 0, 0) == ZK_OK, "mul mod p: 2^64 2^128 = 1253375 accepted");
  rp = zk_fr_sub(&fold, &pfr);
  zk_range_fill(tb, &two, &pm1);
  zk_range_fill(tb + ZK_FP_WEIGHTS, &rp, &pm1);
  for (i = 0; i < 3; i++) out[i] = fr_limb64(&rp, i);
  check(arith_check(A_MULP, NULL, in, out, tb, 2 * ZK_FP_WEIGHTS, 2 * ZK_FP_WEIGHTS) == ZK_ERR_UNSAT,
        "mul mod p: q + 1 with r - p refused");
  /* Alternate carry: 0 0 has c_k = 0; c_0 + 1 and c_3 + 1 (bit 0 of c_k + 2^67) change a column by 2^64. */
  fp_limbs(in, z3);
  fp_limbs(in + 3, z3);
  fp_limbs(out, z3);
  check(arith_check(A_MULP, NULL, in, out, NULL, 0, 0) == ZK_OK, "mul mod p: 0 0 accepted");
  check(arith_check(A_MULP, NULL, in, out, &one, 4 * ZK_FP_WEIGHTS, 1) == ZK_ERR_UNSAT,
        "mul mod p: alternate carry c_0 + 1 refused");
  check(arith_check(A_MULP, NULL, in, out, &one, 4 * ZK_FP_WEIGHTS + 3 * 68, 1) == ZK_ERR_UNSAT,
        "mul mod p: alternate carry c_3 + 1 refused");
}

/* D6 rows: the hash circuit against poseidon2_hash, and a model of the
 * permutation over zk_fr_* with one defect for the D8 digests. */
enum { P2_WORDS_MAX = 9 };
static const uint32_t P2_NONE = UINT32_MAX;

typedef struct P2Case {
  ZkFr input[1];
  ZkFr weight[ZK_POSEIDON2_WORD_BITS * P2_WORDS_MAX + 1];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkFr output[1];
  ZkWitness w;
} P2Case;

static int p2_eq(const ZkFr *a, const ZkFr *b) { return memcmp(a->limb, b->limb, sizeof a->limb) == 0; }

static ZkFr p2_zk(const Fr *a) {
  ZkFr out;
  unsigned i;
  for (i = 0; i < ZK_LIMBS; i++) out.limb[i] = (uint32_t)a->limb[i];
  return out;
}

static void model_sbox(ZkFr *x) {
  const ZkFr x2 = zk_fr_mul(x, x);
  const ZkFr x4 = zk_fr_mul(&x2, &x2);
  *x = zk_fr_mul(x, &x4);
}

static void model_linear(ZkFr s[3], int internal) {
  const ZkFr s01 = zk_fr_add(&s[0], &s[1]);
  const ZkFr sum = zk_fr_add(&s01, &s[2]);
  unsigned i;
  if (internal) s[2] = zk_fr_add(&s[2], &s[2]);
  for (i = 0; i < POSEIDON2_T; i++) s[i] = zk_fr_add(&s[i], &sum);
}

/* X becomes (X + constant K)^5, with constant K + 1 when K is BUMP. */
static void model_round(ZkFr *x, uint32_t k, uint32_t bump) {
  const ZkFr one = zk_fr_u64(1);
  const ZkFr rc = zk_poseidon2_constant(k);
  const ZkFr rb = zk_fr_add(&rc, &one);
  *x = zk_fr_add(x, k == bump ? &rb : &rc);
  model_sbox(x);
}

static void model_external(ZkFr s[3], uint32_t k0, uint32_t bump) {
  uint32_t r, i;
  for (r = 0; r < POSEIDON2_HALF_F; r++) {
    for (i = 0; i < POSEIDON2_T; i++) model_round(&s[i], k0 + POSEIDON2_T * r + i, bump);
    model_linear(s, 0);
  }
}

/* poseidon2_permute with constant BUMP changed or internal round SKIP left
 * out (P2_NONE: no defect). */
static void model_permute(ZkFr s[3], uint32_t bump, uint32_t skip) {
  uint32_t r;
  model_linear(s, 0);
  model_external(s, 0, bump);
  for (r = 0; r < POSEIDON2_ROUNDS_P; r++)
    if (r != skip) {
      model_round(&s[0], POSEIDON2_HALF_F * POSEIDON2_T + r, bump);
      model_linear(s, 1);
    }
  model_external(s, POSEIDON2_HALF_F * POSEIDON2_T + POSEIDON2_ROUNDS_P, bump);
}

static ZkFr model_hash(uint64_t tag, const uint64_t *words, uint32_t n, uint32_t bump, uint32_t skip) {
  const uint32_t blocks = n == 0 ? 1 : n / 2 + n % 2;
  ZkFr s[POSEIDON2_T];
  uint32_t b, i;
  s[0] = zk_fr_u64(0);
  s[1] = zk_fr_u64(0);
  s[2] = zk_fr_u64(n);
  s[2].limb[2] = (uint32_t)tag;
  s[2].limb[3] = (uint32_t)(tag >> 32);
  for (b = 0; b < blocks; b++) {
    for (i = 0; i < 2; i++)
      if (2 * b + i < n) {
        const ZkFr x = zk_fr_u64(words[2 * b + i]);
        s[i] = zk_fr_add(&s[i], &x);
      }
    model_permute(s, bump, skip);
  }
  return s[0];
}

/* zk_check of the hash circuit of (TAG, N) with the honest fill of WORDS,
 * weight FLIP (P2_NONE: none) with its low bit changed, and output DIGEST. */
static ZkErr p2_check(uint64_t tag, const uint64_t *words, uint32_t n, uint32_t flip, const ZkFr *digest) {
  static P2Case k;
  ZkCircuit c;
  ZkErr e;
  const uint32_t m = ZK_POSEIDON2_WORD_BITS * n;
  const ZkFr t = zk_fr_u64(tag);
  uint32_t d, o;
  if (n > P2_WORDS_MAX) return ZK_ERR_COUNT;
  memset(&k, 0, sizeof k);
  k.matrix[0].rows = 1;
  k.matrix[0].cols = m;
  k.matrix[0].entry = k.weight;
  k.output[0] = *digest;
  k.w.inputs = 1;
  k.w.input = k.input;
  k.w.matrices = 1;
  k.w.matrix = k.matrix;
  k.w.maps = 1;
  k.w.map = k.map;
  k.w.outputs = 1;
  k.w.output = k.output;
  zk_init(&c, 1, m, 1);
  d = zk_poseidon2_hash(&c, tag, n, 0);
  o = zk_out(&c, 0, d);
  zk_eq(&c, o, d);
  /* Input 0 is the tag (Q-S7-U2-R12-2 (b)). */
  zk_eq(&c, zk_input(&c, 0), zk_const(&c, &t));
  k.input[0] = t;
  zk_poseidon2_hash_fill(k.weight, words, n);
  if (flip != P2_NONE) k.weight[flip].limb[0] ^= 1u;
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

/* S7 U3 (D10 to D16): the Merkle relation rows. A Digest is 4 words, word 0
 * low; SIB is 16 x 4 words, level 0 first. RelCase is one 1 x m matrix (map
 * 0) over the weights of the largest relation, gmotion. */
typedef struct RelCase {
  ZkFr input[2];
  ZkFr weight[ZK_GMOTION_WEIGHTS];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkFr output[2];
  ZkWitness w;
} RelCase;

static void rel_case(RelCase *k, uint32_t n, uint32_t m, uint32_t q) {
  memset(k, 0, sizeof *k);
  k->matrix[0].rows = 1;
  k->matrix[0].cols = m;
  k->matrix[0].entry = k->weight;
  k->w.inputs = n;
  k->w.input = k->input;
  k->w.matrices = 1;
  k->w.matrix = k->matrix;
  k->w.maps = 1;
  k->w.map = k->map;
  k->w.outputs = q;
  k->w.output = k->output;
}

/* The Fr value of the 4 words X, and the 4 words of A. */
static ZkFr dg_fr(const uint64_t x[4]) {
  ZkFr out;
  unsigned i;
  for (i = 0; i < 4; i++) {
    out.limb[2 * i] = (uint32_t)x[i];
    out.limb[2 * i + 1] = (uint32_t)(x[i] >> 32);
  }
  return out;
}

static void fr_dg(const ZkFr *a, uint64_t x[4]) {
  unsigned i;
  for (i = 0; i < 4; i++) x[i] = (uint64_t)a->limb[2 * i] | (uint64_t)a->limb[2 * i + 1] << 32;
}

/* zk_check of H(TAG, WORDS, N) over the word values (D10): word i is the
 * zk_word of the 64 bits at 64 i, and output 0 is DIGEST. */
static ZkErr hv_check(uint64_t tag, const uint64_t *words, uint32_t n, const ZkFr *digest) {
  static RelCase k;
  ZkCircuit c;
  ZkErr e;
  uint32_t x[P2_WORDS_MAX], i;
  const uint32_t m = ZK_POSEIDON2_WORD_BITS * n;
  if (n > P2_WORDS_MAX) return ZK_ERR_COUNT;
  rel_case(&k, 0, m, 1);
  k.output[0] = *digest;
  zk_init(&c, 0, m, 1);
  for (i = 0; i < n; i++) x[i] = zk_word(&c, ZK_POSEIDON2_WORD_BITS * i, ZK_POSEIDON2_WORD_BITS);
  zk_out(&c, 0, zk_poseidon2_hash_values(&c, tag, n, x));
  zk_poseidon2_hash_fill(k.weight, words, n);
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

static void rows_poseidon2(void) {
  static const uint64_t words[P2_WORDS_MAX] = {0, 1, UINT64_MAX, 0x0123456789abcdefu, 0x8000000000000000u,
                                                2, 0xfedcba9876543210u, 3, 0xdeadbeefcafef00du};
  static const uint64_t zeros[2] = {0, 0};
  static const uint32_t ns[5] = {0, 1, 2, 3, P2_WORDS_MAX};
  static const uint64_t tags[2] = {0, 0x0123456789abcdefu};
  static const uint32_t bumps[7] = {0, 11, 12, 40, 67, 68, POSEIDON2_CONSTANTS - 1};
  static const uint32_t skips[3] = {0, 27, POSEIDON2_ROUNDS_P - 1};
  const ZkFr one = zk_fr_u64(1);
  uint32_t k, t, i;
  int ok = poseidon2_constants_ok();
  Fr ref;
  ZkFr want, bad;
  for (k = 0; k < POSEIDON2_CONSTANTS; k++) {
    const ZkFr rc = zk_poseidon2_constant(k);
    ok &= zk_canonical(&rc);
  }
  check(ok, "poseidon2 constants canonical");
  for (t = 0; t < 2; t++)
    for (i = 0; i < 5; i++) {
      ZkFr model;
      poseidon2_hash(tags[t], words, ns[i], &ref);
      want = p2_zk(&ref);
      model = model_hash(tags[t], words, ns[i], P2_NONE, P2_NONE);
      check(p2_eq(&model, &want), "poseidon2 model equals poseidon2_hash");
      check(p2_check(tags[t], words, ns[i], P2_NONE, &want) == ZK_OK, "poseidon2 hash circuit equals poseidon2_hash");
      check(hv_check(tags[t], words, ns[i], &want) == ZK_OK, "poseidon2 word value circuit equals poseidon2_hash");
    }
  /* D8 on (tag 1, n 3): a changed digest, word bit, round constant or round. */
  poseidon2_hash(tags[1], words, 3, &ref);
  want = p2_zk(&ref);
  bad = zk_fr_add(&want, &one);
  check(p2_check(tags[1], words, 3, P2_NONE, &bad) == ZK_ERR_UNSAT, "poseidon2 digest + 1 refused");
  check(p2_check(tags[1], words, 3, 0, &want) == ZK_ERR_UNSAT, "poseidon2 word 0 bit 0 refused");
  check(p2_check(tags[1], words, 3, 2 * ZK_POSEIDON2_WORD_BITS + 63, &want) == ZK_ERR_UNSAT,
        "poseidon2 word 2 bit 63 refused");
  for (k = 0; k < 7; k++) {
    bad = model_hash(tags[1], words, 3, bumps[k], P2_NONE);
    check(!p2_eq(&bad, &want) && p2_check(tags[1], words, 3, P2_NONE, &bad) == ZK_ERR_UNSAT,
          "poseidon2 changed round constant refused");
  }
  for (k = 0; k < 3; k++) {
    bad = model_hash(tags[1], words, 3, P2_NONE, skips[k]);
    check(!p2_eq(&bad, &want) && p2_check(tags[1], words, 3, P2_NONE, &bad) == ZK_ERR_UNSAT,
          "poseidon2 skipped round refused");
  }
  /* The capacity binds the tag and N: tag + 1, and n 1 against n 2 over zeros. */
  poseidon2_hash(tags[1] + 1, words, 3, &ref);
  bad = p2_zk(&ref);
  check(p2_check(tags[1], words, 3, P2_NONE, &bad) == ZK_ERR_UNSAT, "poseidon2 tag + 1 digest refused");
  poseidon2_hash(0, zeros, 1, &ref);
  bad = p2_zk(&ref);
  check(p2_check(0, zeros, 2, P2_NONE, &bad) == ZK_ERR_UNSAT, "poseidon2 n 1 digest on n 2 refused");
  check(p2_check(0, zeros, 1, P2_NONE, &bad) == ZK_OK, "poseidon2 n 1 over zeros");
}

/* D7: SHA-512. The FIPS 180-4 vectors and the C sha512 are the oracles. */
enum { SHA_ROW_BYTES = 112, SHA_ROW_WEIGHTS = 40000 };

typedef struct ShaCase {
  ZkFr input[1];
  ZkFr weight[SHA_ROW_WEIGHTS];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkFr output[8];
  ZkWitness w;
} ShaCase;

static const char SHA_TWO_BLOCK[] =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
static const uint64_t SHA_ABC[8] = {0xddaf35a193617abau, 0xcc417349ae204131u, 0x12e6fa4e89a97ea2u,
                                    0x0a9eeee64b55d39au, 0x2192992a274fc1a8u, 0x36ba3c23a3feebbdu,
                                    0x454d4423643ce80eu, 0x2a9ac94fa54ca49fu};
static const uint64_t SHA_EMPTY[8] = {0xcf83e1357eefb8bdu, 0xf1542850d66d8007u, 0xd620e4050b5715dcu,
                                      0x83f4a921d36ce9ceu, 0x47d0d13c5d85f2b0u, 0xff8318d2877eec2fu,
                                      0x63b931bd47417a81u, 0xa538327af927da3eu};
static const uint64_t SHA_TWO[8] = {0x8e959b75dae313dau, 0x8cf4f72814fc143fu, 0x8f7779c6eb9f7fa1u,
                                    0x7299aeadb6889018u, 0x501d289e4900f7e4u, 0x331b99dec4b5433au,
                                    0xc7d329eeb6dd2654u, 0x5e96e55b874be909u};

static void sha_words(const uint8_t d[SHA512_BYTES], uint64_t out[8]) {
  uint32_t i, j;
  for (i = 0; i < 8; i++) {
    out[i] = 0;
    for (j = 0; j < 8; j++)
      out[i] = (out[i] << 8) | d[8 * i + j];
  }
}

static int sha_vector(const uint8_t *msg, uint32_t n, const uint64_t want[8]) {
  uint8_t d[SHA512_BYTES];
  uint64_t got[8];
  sha512(msg, n, d);
  sha_words(d, got);
  return memcmp(got, want, sizeof got) == 0;
}

static ZkErr sha_check(const uint8_t *msg, uint32_t n, uint32_t flip, const uint64_t digest[8]) {
  static ShaCase k;
  ZkCircuit c;
  ZkErr e;
  const uint32_t m = zk_sha512_weights(n);
  const ZkFr len = zk_fr_u64(n);
  uint32_t d[8], i, o;
  if (n > SHA_ROW_BYTES || m == 0 || m > SHA_ROW_WEIGHTS) return ZK_ERR_COUNT;
  memset(&k, 0, sizeof k);
  k.matrix[0].rows = 1;
  k.matrix[0].cols = m;
  k.matrix[0].entry = k.weight;
  for (i = 0; i < 8; i++)
    k.output[i] = zk_fr_u64(digest[i]);
  k.w.inputs = 1;
  k.w.input = k.input;
  k.w.matrices = 1;
  k.w.matrix = k.matrix;
  k.w.maps = 1;
  k.w.map = k.map;
  k.w.outputs = 8;
  k.w.output = k.output;
  zk_init(&c, 1, m, 8);
  zk_sha512(&c, n, 0, d);
  for (i = 0; i < 8; i++) {
    o = zk_out(&c, i, d[i]);
    zk_eq(&c, o, d[i]);
  }
  /* Input 0 is the message length in bytes (Q-S7-U2-R12-2 (b)). */
  zk_eq(&c, zk_input(&c, 0), zk_const(&c, &len));
  k.input[0] = len;
  zk_sha512_fill(k.weight, msg, n);
  if (flip != P2_NONE) k.weight[flip].limb[0] ^= 1u;
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

static void rows_sha512(void) {
  const uint8_t *abc = (const uint8_t *)"abc", *two = (const uint8_t *)SHA_TWO_BLOCK;
  const uint32_t one = zk_sha512_weights(0);
  uint8_t msg[SHA_ROW_BYTES], d[SHA512_BYTES];
  uint64_t want[8], bad[8];
  uint32_t i, n;
  for (i = 0; i < SHA_ROW_BYTES; i++)
    msg[i] = (uint8_t)(37u * i + 11u);
  check(one == 16176 && zk_sha512_weights(111) == 888 + one && zk_sha512_weights(112) == 896 + 2 * one &&
            zk_sha512_weights(ZK_SHA512_BYTES_MAX + 1) == 0,
        "sha512 weight counts across the padding edge");
  check(sizeof SHA_TWO_BLOCK - 1 == 112, "sha512 896-bit message is 112 bytes");
  /* FIPS 180-4 vectors: the C sha512 and the circuit. */
  check(sha_vector(abc, 3, SHA_ABC) && sha_check(abc, 3, P2_NONE, SHA_ABC) == ZK_OK, "sha512 abc vector");
  check(sha_vector(abc, 0, SHA_EMPTY) && sha_check(abc, 0, P2_NONE, SHA_EMPTY) == ZK_OK, "sha512 empty vector");
  check(sha_vector(two, 112, SHA_TWO) && sha_check(two, 112, P2_NONE, SHA_TWO) == ZK_OK,
        "sha512 896-bit two-block vector");
  /* The padding edge: 111 bytes are one block, 112 bytes are two. */
  for (n = 111; n <= 112; n++) {
    sha512(msg, n, d);
    sha_words(d, want);
    check(sha_check(msg, n, P2_NONE, want) == ZK_OK, "sha512 circuit equals sha512 at the padding edge");
  }
  /* D8 on abc: a changed message block word, a changed schedule bit and a changed digest. */
  check(sha_check(abc, 3, 0, SHA_ABC) == ZK_ERR_UNSAT, "sha512 changed message block word refused");
  check(sha_check(abc, 3, 24, SHA_ABC) == ZK_ERR_UNSAT, "sha512 changed schedule bit refused");
  memcpy(bad, SHA_ABC, sizeof bad);
  bad[7] ^= 1u;
  check(sha_check(abc, 3, P2_NONE, bad) == ZK_ERR_UNSAT, "sha512 changed digest refused");
}

/* D15: the S4 vectors (test/eval/words.txt:24-30), z_16 (test/checktool.c),
 * and the U3 member: key 1 2 3 4 (commit K = wCommit), e 5, u 6, ctx 7 8 9 10. */
static const uint64_t W_COMMIT[4] = {9650742922048484777u, 10142948782476511620u, 14957086067052391097u,
                                     237525277195470535u};
static const uint64_t W_PRF[4] = {13283709821737622318u, 14558195068774572559u, 8093880923303956827u,
                                  1647322402718720386u};
static const uint64_t W_ROOT_EMPTY[4] = {14066419723759741942u, 13229016871263759769u, 1266997135903399495u,
                                         521771725340632474u};
static const uint64_t W_ROOT_ONE[4] = {15477861471466060263u, 16244247719259099513u, 18050862254240247825u,
                                       550216951878748972u};
static const uint64_t W_ROOT_THREE[4] = {14815524925352525031u, 14616814821183985960u, 11689918464990631043u,
                                         1930649543507152205u};
static const char Z16_HEX[] = "0x073db49ea6c5659a1195472ea8f59e47b796e8c10b536d99c335f636303f6bf6";
static const uint64_t LEAF_ONE[4] = {1, 2, 3, 4};
static const uint64_t LEAVES_THREE[12] = {1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0};
static const uint64_t U3_KEY[4] = {1, 2, 3, 4};
static const uint64_t U3_U[4] = {6, 0, 0, 0};
static const uint64_t U3_CTX[4] = {7, 8, 9, 10};
enum { U3_E = 5, MERKLE_LEAVES_MAX = 1 << ZK_MERKLE_LEVELS, MERKLE_LAST = MERKLE_LEAVES_MAX - 1 };

static int dg_eq(const uint64_t a[4], const uint64_t b[4]) { return memcmp(a, b, 4 * sizeof *a) == 0; }

/* A + B over 256 bits (both small enough that no carry leaves word 3). */
static void dg_add(const uint64_t a[4], const uint64_t b[4], uint64_t out[4]) {
  uint64_t carry = 0, s;
  unsigned i;
  for (i = 0; i < 4; i++) {
    s = a[i] + carry;
    carry = s < carry;
    out[i] = s + b[i];
    carry += out[i] < s;
  }
}

/* The node H_3(L, R) and the leaf commit K = H_2(key) of the C oracle. */
static void model_node(const uint64_t l[4], const uint64_t r[4], uint64_t out[4]) {
  uint64_t w[8];
  Fr h;
  memcpy(w, l, 4 * sizeof *w);
  memcpy(w + 4, r, 4 * sizeof *w);
  poseidon2_hash(3, w, 8, &h);
  fr_to_words(&h, out);
}

static void commit_key(const uint64_t key[4], uint64_t out[4]) {
  Fr h;
  poseidon2_hash(2, key, 4, &h);
  fr_to_words(&h, out);
}

/* The root over the N leaves (N at most 2^16), level by level as expect_root
 * (test/checktool.c): an odd level gets z_d, and the empty list is one z_0
 * leaf, so its root is z_16. SIB (when not NULL) gets the sibling of leaf IDX
 * at each level, after the pad. */
static void model_root(const uint64_t *leaves, uint32_t n, uint32_t idx, uint64_t root[4], uint64_t *sib) {
  static uint64_t level[MERKLE_LEAVES_MAX * 4];
  uint64_t z[4] = {0, 0, 0, 0};
  uint32_t d, i, m = n;
  memmove(level, leaves, (size_t)n * 4 * sizeof *level);
  if (m == 0) {
    memcpy(level, z, sizeof z);
    m = 1;
  }
  for (d = 0; d < ZK_MERKLE_LEVELS; d++, idx >>= 1) {
    if (m % 2 == 1) memcpy(level + 4 * m++, z, sizeof z);
    if (sib) memcpy(sib + 4 * d, level + 4 * (idx ^ 1u), 4 * sizeof *sib);
    for (i = 0; i < m / 2; i++) model_node(level + 8 * i, level + 8 * i + 4, level + 4 * i);
    m /= 2;
    model_node(z, z, z);
  }
  memcpy(root, level, 4 * sizeof *root);
}

/* The root from LEAF at IDX with the siblings SIB (bit d of IDX: 0 is left). */
static void model_fold(const uint64_t leaf[4], const uint64_t *sib, uint32_t idx, uint64_t root[4]) {
  uint32_t d;
  memcpy(root, leaf, 4 * sizeof *root);
  for (d = 0; d < ZK_MERKLE_LEVELS; d++, idx >>= 1) {
    if (idx & 1u)
      model_node(sib + 4 * d, root, root);
    else
      model_node(root, sib + 4 * d, root);
  }
}

/* zk_check of a Digest of the words X (zk_digest: the words, then zk_canon)
 * with output 0 = OUT EQ its recompose (D11). */
static ZkErr canon_check(const uint64_t x[4], const ZkFr *out) {
  static RelCase k;
  ZkCircuit c;
  ZkErr e;
  uint32_t v[4];
  rel_case(&k, 0, ZK_DIGEST_WEIGHTS, 1);
  k.output[0] = *out;
  zk_init(&c, 0, ZK_DIGEST_WEIGHTS, 1);
  zk_digest(&c, 0, v);
  zk_out(&c, 0, zk_recompose(&c, v));
  zk_digest_fill(k.weight, x);
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

/* zk_check of one zk_node level (D12) over CUR, the value of a private
 * Digest: the children L and R and the direction B are the node weights, and
 * output 0 is OUT. */
static ZkErr node_check(const uint64_t cur[4], const uint64_t l[4], const uint64_t r[4], uint64_t b,
                        const uint64_t out[4]) {
  static RelCase k;
  ZkCircuit c;
  ZkErr e;
  uint32_t v[4];
  const uint32_t m = ZK_DIGEST_WEIGHTS + ZK_NODE_WEIGHTS;
  rel_case(&k, 0, m, 1);
  k.output[0] = dg_fr(out);
  zk_init(&c, 0, m, 1);
  zk_digest(&c, 0, v);
  zk_out(&c, 0, zk_node(&c, zk_recompose(&c, v), ZK_DIGEST_WEIGHTS));
  zk_digest_fill(k.weight, cur);
  zk_digest_fill(k.weight + ZK_DIGEST_WEIGHTS, l);
  zk_digest_fill(k.weight + 2 * ZK_DIGEST_WEIGHTS, r);
  k.weight[3 * ZK_DIGEST_WEIGHTS] = zk_fr_u64(b);
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

/* zk_check of zk_path (D12) from the value of a private leaf Digest LEAF at
 * IDX with the siblings SIB; output 0 is WANT, and the fill root equals it. */
static ZkErr path_check(const uint64_t leaf[4], const uint64_t *sib, uint32_t idx, const uint64_t want[4]) {
  static RelCase k;
  ZkCircuit c;
  ZkErr e;
  uint32_t v[4];
  uint64_t root[4];
  const uint32_t m = ZK_DIGEST_WEIGHTS + ZK_MERKLE_LEVELS * ZK_NODE_WEIGHTS;
  rel_case(&k, 0, m, 1);
  k.output[0] = dg_fr(want);
  zk_init(&c, 0, m, 1);
  zk_digest(&c, 0, v);
  zk_out(&c, 0, zk_path(&c, zk_recompose(&c, v), ZK_DIGEST_WEIGHTS));
  zk_digest_fill(k.weight, leaf);
  zk_path_fill(k.weight + ZK_DIGEST_WEIGHTS, leaf, sib, idx, root);
  check(dg_eq(root, want), "zk_path_fill root equals the model root");
  e = finish(&c, &k.w);
  zk_free(&c);
  return e;
}

/* D16: one change to an honest gvote or gmotion witness. T_DIR0 is last: it
 * needs the caller to give SIB[0] = commit K, so the level-0 children are
 * equal. */
typedef enum { T_NONE, T_ROOT, T_OUT1, T_E, T_UC, T_SIB, T_DIR3, T_KEY, T_KEY_R, T_DIR0 } Tamper;
static const char *const TAMPER_ROWS[T_DIR0 + 1] = {
    "relation honest",
    "relation root + 1 refused",
    "relation nf or mt + 1 refused",
    "relation e + 1 refused",
    "relation u or ctx + 1 refused",
    "relation changed level-3 sibling word refused",
    "relation flipped level-3 direction refused",
    "relation changed key word refused",
    "relation key + r refused",
    "relation level-0 direction 2 on equal children refused"};

static void rel_fill(int vote, ZkFr *wt, const uint64_t key[4], uint64_t e, const uint64_t uc[4],
                     const uint64_t *sib, uint32_t idx, uint64_t root[4], uint64_t out1[4]) {
  if (vote)
    zk_gvote_fill(wt, key, e, uc[0], sib, idx, root, out1);
  else
    zk_gmotion_fill(wt, key, e, uc, sib, idx, root, out1);
}

/* zk_check of gvote (VOTE 1) or gmotion (VOTE 0) with the honest fill of KEY,
 * E, UC (u is UC[0] for gvote, the ctx words for gmotion) and SIB at IDX.
 * Output 0 is WANT (the model root, not the fill root), output 1 the fill nf
 * or mt; then tamper T changes one thing. */
static ZkErr rel_check(int vote, const uint64_t key[4], uint64_t e, const uint64_t uc[4], const uint64_t *sib,
                       uint32_t idx, const uint64_t want[4], Tamper t) {
  static RelCase k;
  const ZkFr one = zk_fr_u64(1);
  const uint32_t member = vote ? ZK_DIGEST_WEIGHTS + 128 : 2 * ZK_DIGEST_WEIGHTS + 64;
  uint64_t bent[ZK_MERKLE_LEVELS * 4], key2[4], r[4], root[4], out1[4];
  ZkCircuit c;
  ZkErr err;
  rel_case(&k, 2, vote ? ZK_GVOTE_WEIGHTS : ZK_GMOTION_WEIGHTS, 2);
  if (vote)
    zk_gvote(&c);
  else
    zk_gmotion(&c);
  rel_fill(vote, k.weight, key, e, uc, sib, idx, root, out1);
  check(t != T_NONE || dg_eq(root, want), "relation fill root equals the model root");
  k.input[0] = zk_fr_u64(e);
  k.input[1] = vote ? zk_fr_u64(uc[0]) : dg_fr(uc);
  k.output[0] = dg_fr(want);
  k.output[1] = dg_fr(out1);
  memcpy(bent, sib, sizeof bent);
  memcpy(key2, key, sizeof key2);
  switch (t) {
  case T_NONE: break;
  case T_ROOT: k.output[0] = zk_fr_add(&k.output[0], &one); break;
  case T_OUT1: k.output[1] = zk_fr_add(&k.output[1], &one); break;
  case T_E: k.input[0] = zk_fr_add(&k.input[0], &one); break;
  case T_UC: k.input[1] = zk_fr_add(&k.input[1], &one); break;
  case T_SIB:
    bent[4 * 3] ^= 1u;
    rel_fill(vote, k.weight, key, e, uc, bent, idx, root, out1);
    break;
  case T_DIR3:
    k.weight[member + 3 * ZK_NODE_WEIGHTS + 2 * ZK_DIGEST_WEIGHTS] = zk_fr_u64(((idx >> 3) & 1u) ^ 1u);
    break;
  case T_KEY:
    key2[0] ^= 1u;
    rel_fill(vote, k.weight, key2, e, uc, sib, idx, root, out1);
    break;
  case T_KEY_R:
    fr_dg(&ZK_R_FR, r);
    dg_add(key, r, key2);
    zk_digest_fill(k.weight, key2);
    break;
  case T_DIR0: k.weight[member + 2 * ZK_DIGEST_WEIGHTS] = zk_fr_u64(2); break;
  }
  err = finish(&c, &k.w);
  zk_free(&c);
  return err;
}

/* The wRoot three list with commit K in slot IDX: gvote (VOTE 1) or gmotion
 * at IDX, root from model_root. With EQUAL, SIB[0] is commit K too and the
 * root comes from model_fold (the b = 2 pair). */
static ZkErr member_case(int vote, uint32_t idx, int equal, Tamper t) {
  uint64_t leaves[12], sib[ZK_MERKLE_LEVELS * 4], root[4];
  memcpy(leaves, LEAVES_THREE, sizeof leaves);
  commit_key(U3_KEY, leaves + 4 * idx);
  model_root(leaves, 3, idx, root, sib);
  if (equal) {
    memcpy(sib, leaves + 4 * idx, 4 * sizeof *sib);
    model_fold(leaves + 4 * idx, sib, idx, root);
  }
  return rel_check(vote, U3_KEY, U3_E, vote ? U3_U : U3_CTX, sib, idx, root, t);
}

/* Index 2^16 - 1 of a sparse tree: z_d siblings, but sib[5] = wCommit. */
static ZkErr sparse_case(int vote) {
  uint64_t sib[ZK_MERKLE_LEVELS * 4], z[4] = {0, 0, 0, 0}, leaf[4], root[4];
  uint32_t d;
  for (d = 0; d < ZK_MERKLE_LEVELS; d++) {
    memcpy(sib + 4 * d, d == 5 ? W_COMMIT : z, sizeof z);
    model_node(z, z, z);
  }
  commit_key(U3_KEY, leaf);
  model_fold(leaf, sib, MERKLE_LAST, root);
  return rel_check(vote, U3_KEY, U3_E, vote ? U3_U : U3_CTX, sib, MERKLE_LAST, root, T_NONE);
}

/* The cheap U3 rows of make check (D15 (1), D11, D12). */
static void rows_u3(void) {
  static const uint64_t prf[6] = {1, 2, 3, 4, 5, 6};
  static const uint64_t z4[4] = {0, 0, 0, 0};
  const ZkFr zero = zk_fr_u64(0), r1 = r_minus_1(), commit = dg_fr(W_COMMIT), prf_fr = dg_fr(W_PRF);
  uint64_t root[4], z16[4], x[4], r[4], up[4];
  Fr h;
  check(fr_from_hex(&h, Z16_HEX), "z_16 hex");
  fr_to_words(&h, z16);
  model_root(LEAF_ONE, 0, 0, root, NULL);
  check(dg_eq(z16, W_ROOT_EMPTY) && dg_eq(root, W_ROOT_EMPTY), "model root of the empty list is z_16");
  model_root(LEAF_ONE, 1, 0, root, NULL);
  check(dg_eq(root, W_ROOT_ONE), "model root equals wRoot one leaf");
  model_root(LEAVES_THREE, 3, 0, root, NULL);
  check(dg_eq(root, W_ROOT_THREE), "model root equals wRoot three leaves");
  commit_key(U3_KEY, x);
  check(dg_eq(x, W_COMMIT), "commit of key 1 2 3 4 equals wCommit");
  check(hv_check(2, U3_KEY, 4, &commit) == ZK_OK, "word value commit (1, 2, 3, 4) equals wCommit");
  check(hv_check(4, prf, 6, &prf_fr) == ZK_OK, "word value prf (1 .. 6) equals wPrf");
  check(hv_check(2, U3_KEY, 4, &prf_fr) == ZK_ERR_UNSAT, "word value commit against wPrf refused");
  fr_dg(&r1, x);
  check(canon_check(x, &r1) == ZK_OK, "canon r - 1");
  check(canon_check(z4, &zero) == ZK_OK, "canon 0");
  check(canon_check(W_COMMIT, &commit) == ZK_OK, "canon wCommit");
  fr_dg(&ZK_R_FR, r);
  dg_add(W_COMMIT, r, x);
  check(canon_check(x, &commit) == ZK_ERR_UNSAT, "canon wCommit + r refused");
  check(canon_check(r, &zero) == ZK_ERR_UNSAT, "canon r refused");
  model_node(W_COMMIT, W_PRF, up);
  check(node_check(W_COMMIT, W_COMMIT, W_PRF, 0, up) == ZK_OK, "node b 0");
  check(node_check(W_COMMIT, W_COMMIT, W_PRF, 1, up) == ZK_ERR_UNSAT, "node flipped direction refused");
  memcpy(x, W_PRF, sizeof x);
  x[0] ^= 1u;
  check(node_check(W_COMMIT, W_COMMIT, x, 0, up) == ZK_ERR_UNSAT, "node changed sibling word refused");
  model_node(W_PRF, W_COMMIT, up);
  check(node_check(W_COMMIT, W_PRF, W_COMMIT, 1, up) == ZK_OK, "node b 1");
  model_node(W_COMMIT, W_COMMIT, up);
  check(node_check(W_COMMIT, W_COMMIT, W_COMMIT, 0, up) == ZK_OK, "node b 0 on equal children");
  check(node_check(W_COMMIT, W_COMMIT, W_COMMIT, 2, up) == ZK_ERR_UNSAT, "node b 2 on equal children refused");
}

/* zktool member (check-lig): the 16-level rows (D15 (1) path, (2), D16). */
static int member_rows(void) {
  uint64_t sib[ZK_MERKLE_LEVELS * 4], root[4];
  uint32_t i, t;
  int v;
  for (i = 0; i < 3; i++) {
    model_root(LEAVES_THREE, 3, i, root, sib);
    check(dg_eq(root, W_ROOT_THREE) && path_check(LEAVES_THREE + 4 * i, sib, i, W_ROOT_THREE) == ZK_OK,
          "zk_path at a leaf of wRoot three");
  }
  model_root(LEAF_ONE, 1, 0, root, sib);
  check(dg_eq(root, W_ROOT_ONE) && path_check(LEAF_ONE, sib, 0, W_ROOT_ONE) == ZK_OK,
        "zk_path at the leaf of wRoot one");
  for (v = 0; v < 2; v++) {
    check(member_case(v, 0, 0, T_NONE) == ZK_OK, "relation honest at index 0");
    check(member_case(v, 2, 0, T_NONE) == ZK_OK, "relation honest at index 2");
    check(sparse_case(v) == ZK_OK, "relation honest at index 2^16 - 1 of a sparse tree");
    for (t = T_ROOT; t < T_DIR0; t++) check(member_case(v, 2, 0, (Tamper)t) == ZK_ERR_UNSAT, TAMPER_ROWS[t]);
    check(member_case(v, 2, 1, T_NONE) == ZK_OK, "relation honest on equal level-0 children");
    check(member_case(v, 2, 1, T_DIR0) == ZK_ERR_UNSAT, TAMPER_ROWS[T_DIR0]);
  }
  if (fails == 0) puts("zk member rows: passed");
  return fails != 0;
}

/* zktool full (check-lig, D15 (3)): leaves (i + 1, 0, 0, 0) below 2^16 -
 * 1 and commit K last; gvote at 2^16 - 1 with the model_root root. */
static int full_rows(void) {
  static uint64_t leaves[MERKLE_LEAVES_MAX * 4];
  uint64_t sib[ZK_MERKLE_LEVELS * 4], root[4], fold[4];
  uint32_t i;
  for (i = 0; i < MERKLE_LAST; i++) leaves[4 * i] = i + 1;
  commit_key(U3_KEY, leaves + 4 * MERKLE_LAST);
  model_root(leaves, MERKLE_LEAVES_MAX, MERKLE_LAST, root, sib);
  model_fold(leaves + 4 * MERKLE_LAST, sib, MERKLE_LAST, fold);
  check(dg_eq(root, fold), "full tree model_root equals the fold at 2^16 - 1");
  check(rel_check(1, U3_KEY, U3_E, U3_U, sib, MERKLE_LAST, root, T_NONE) == ZK_OK,
        "gvote at index 2^16 - 1 of a full tree");
  if (fails == 0) puts("zk full rows: passed");
  return fails != 0;
}

/* A one-matrix witness over the caller arrays (the PkeCase layout). */
static void wit_init(ZkWitness *w, ZkMatrix *mx, uint32_t *map, ZkFr *in, uint32_t ni, ZkFr *wt, uint32_t nw,
                     ZkFr *out, uint32_t no) {
  memset(w, 0, sizeof *w);
  memset(mx, 0, sizeof *mx);
  map[0] = 0;
  mx->rows = 1;
  mx->cols = nw;
  mx->entry = wt;
  w->inputs = ni;
  w->input = in;
  w->matrices = 1;
  w->matrix = mx;
  w->maps = 1;
  w->map = map;
  w->outputs = no;
  w->output = out;
}

/* V as an Fr element: a negative V is r - |V|. */
static ZkFr pke_fr(int64_t v) {
  const ZkFr zero = zk_fr_u64(0), mag = zk_fr_u64(v < 0 ? 0u - (uint64_t)v : (uint64_t)v);
  return v < 0 ? zk_fr_sub(&zero, &mag) : mag;
}

/* S7 U4 D25 (2), cheap: one zk_lwe_word with S = 2^64 - 1 (input 0), the
 * error E and the message term 2^59 when MSG (a body word, e2) or none (a
 * mask word, e1). The word W (input 1, also the output) is (S + e + M) mod
 * 2^64 and q = 1 when S + e + M wraps. */
static ZkErr lwe_case(int64_t e, int msg) {
  const uint64_t mv = msg ? (uint64_t)1 << ZK_PKE_DELTA_LOG : 0;
  const ZkFr delta = zk_fr_u64(mv);
  ZkFr in[2], wt[ZK_LWE_WEIGHTS], out[1];
  ZkMatrix mx[1];
  uint32_t map[1], mt = 0;
  ZkWitness w;
  ZkCircuit c;
  ZkErr err;
  in[0] = fr_pow2_minus(64, 1);
  in[1] = zk_fr_u64(UINT64_MAX + (uint64_t)e + mv);
  out[0] = in[1];
  zk_lwe_word_fill(wt, e, e + (int64_t)mv >= 1);
  wit_init(&w, mx, map, in, 2, wt, ZK_LWE_WEIGHTS, out, 1);
  zk_init(&c, 2, ZK_LWE_WEIGHTS, 1);
  if (msg) mt = zk_const(&c, &delta);
  zk_lwe_word(&c, zk_input(&c, 0), msg ? &mt : NULL, zk_input(&c, 1), 0);
  zk_out(&c, 0, zk_input(&c, 1));
  err = finish(&c, &w);
  zk_free(&c);
  return err;
}

/* D23 on its own: the width (input 0, also the output) and the 16 values M. */
static ZkErr onehot_case(uint64_t width, const int64_t *m) {
  ZkFr in[1], wt[ZK_PKE_SLOTS], out[1];
  ZkMatrix mx[1];
  uint32_t map[1], mv[ZK_PKE_SLOTS], j;
  ZkWitness w;
  ZkCircuit c;
  ZkErr err;
  in[0] = zk_fr_u64(width);
  out[0] = in[0];
  for (j = 0; j < ZK_PKE_SLOTS; j++) wt[j] = pke_fr(m[j]);
  wit_init(&w, mx, map, in, 1, wt, ZK_PKE_SLOTS, out, 1);
  zk_init(&c, 1, ZK_PKE_SLOTS, 1);
  zk_onehot(&c, zk_input(&c, 0), 0, mv);
  zk_out(&c, 0, zk_input(&c, 0));
  err = finish(&c, &w);
  zk_free(&c);
  return err;
}

/* S7 U4 D25 (2), the cheap rows (make check): choice 0 and w - 1 for w = 4
 * and w = 3 accepted; m all zero, two ones, a one in slot w (w = 3) and m = 2
 * (2 and -1: the sum stays 1, so only booleanity refuses) refused; e at -2^17
 * and 2^17 accepted, at 2^17 + 1 and -2^17 - 1 refused, for a mask word and
 * for a body word. The whole-circuit rows are in zktool pke. */
static void rows_pke(void) {
  static const uint32_t choice[4][2] = {{0, 4}, {3, 4}, {0, 3}, {2, 3}};
  static const int64_t refused[4][ZK_PKE_SLOTS] = {{0}, {1, 1}, {0, 0, 0, 1}, {2, -1}};
  static const uint64_t rw[4] = {4, 4, 3, 4};
  static const int64_t edge[4] = {-(1 << 17), 1 << 17, (1 << 17) + 1, -(1 << 17) - 1};
  int64_t m[ZK_PKE_SLOTS];
  uint32_t s;
  for (s = 0; s < 4; s++) {
    memset(m, 0, sizeof m);
    m[choice[s][0]] = 1;
    check(onehot_case(choice[s][1], m) == ZK_OK, "onehot: choice 0 and w - 1 for w = 4 and w = 3 accepted");
    check(onehot_case(rw[s], refused[s]) != ZK_OK, "onehot: m all zero, two ones, a one in slot w = 3, m = 2 refused");
    check((lwe_case(edge[s], 0) == ZK_OK) == (s < 2), "lwe mask word: e at -2^17 and 2^17 only accepted");
    check((lwe_case(edge[s], 1) == ZK_OK) == (s < 2), "lwe body word: e at -2^17 and 2^17 only accepted");
  }
}

/* S7 U7 (D149, D151, D152): the client witness rows of make check. The motion
 * rows: the C words of the motion block (D140) at index 0 and 2^16 - 1 of the
 * sparse_case tree are equal to the words of the client Wasm module
 * (build/tfhe-client.wasm, a Makefile prerequisite; one node call), the
 * reader (front/zkread.h) accepts the Wasm words, and each refusal class R1 to
 * R4 gives its one code. The vote rows: R1 and R2 only, on a synthetic block
 * that the reader refuses with the reference code under a zero pk, so each
 * changed limb shows as the limb code. No PkeBallot and no keygen here: the
 * vote agreement rows and the vote R3 and R4 rows are in zktool client. */
enum { CL_MOTION_IN = 74, CL_TWO = 2 };

typedef enum { CL_DIGEST, CL_SET, CL_FLIP } ClKind;

typedef struct ClEdit {
  size_t at;
  ClKind kind;
  uint64_t v;
  ZrErr want;
  const char *what;
} ClEdit;

/* One edit of the block W: a Digest of four all-ones words (not a canonical
 * Fr), one word set to V, or bit 0 of one word changed. */
static void client_edit(uint64_t *w, const ClEdit *t) {
  switch (t->kind) {
  case CL_DIGEST:
    memset(w + t->at, 0xff, 4 * sizeof *w);
    break;
  case CL_SET:
    w[t->at] = t->v;
    break;
  case CL_FLIP:
    w[t->at] ^= 1u;
    break;
  }
}

/* The sparse_case siblings (z_d, but sib[5] = wCommit) and the root from the
 * commit K leaf at IDX. */
static void client_path(uint32_t idx, uint64_t root[4], uint64_t sib[ZR_PATH_WORDS]) {
  uint64_t z[4] = {0, 0, 0, 0}, leaf[4];
  uint32_t d;
  for (d = 0; d < ZK_MERKLE_LEVELS; d++) {
    memcpy(sib + 4 * d, d == 5 ? W_COMMIT : z, sizeof z);
    model_node(z, z, z);
  }
  commit_key(U3_KEY, leaf);
  model_fold(leaf, sib, idx, root);
}

/* The C motion words at IDX: the module input IN (key, e, ctx, idx, the path)
 * and the block OUT (D140: root, mt, e, ctx, key, idx, the path), root and mt
 * from zk_gmotion_fill. MODEL gets the model_fold root; 1 when the two roots
 * are equal. */
static int client_motion(uint32_t idx, uint64_t *in, uint64_t *out, uint64_t model[4]) {
  static ZkFr wt[ZK_GMOTION_WEIGHTS];
  uint64_t sib[ZR_PATH_WORDS], root[4], mt[4];
  client_path(idx, model, sib);
  memcpy(in, U3_KEY, sizeof U3_KEY);
  in[4] = U3_E;
  memcpy(in + 5, U3_CTX, sizeof U3_CTX);
  in[9] = idx;
  memcpy(in + 10, sib, sizeof sib);
  zk_gmotion_fill(wt, U3_KEY, U3_E, U3_CTX, sib, idx, root, mt);
  memcpy(out, root, sizeof root);
  memcpy(out + 4, mt, sizeof mt);
  out[8] = U3_E;
  memcpy(out + 9, U3_CTX, sizeof U3_CTX);
  memcpy(out + 13, U3_KEY, sizeof U3_KEY);
  out[17] = idx;
  memcpy(out + 18, sib, sizeof sib);
  return dg_eq(root, model);
}

/* One node call of the client module: the CL_TWO lines of the entry ENTRY
 * (NIN words each, from IN) go to stdin and GOT gets the CL_TWO blocks of
 * NOUT words. 0 when the module, the input or node fails, a word is missing
 * or a word follows the last block. */
static int client_wasm(const char *entry, const uint64_t *in, size_t nin, uint64_t *got, size_t nout) {
  FILE *f = fopen("build/zk-client-in.txt", "w"), *g = NULL;
  unsigned long long v;
  size_t i, k;
  int ok = f != NULL;
  for (k = 0; ok && k < CL_TWO; k++) {
    fputs(entry, f);
    for (i = 0; i < nin; i++) fprintf(f, " %llu", (unsigned long long)in[k * nin + i]);
    fputc('\n', f);
  }
  ok = f != NULL && fclose(f) == 0 && ok &&
       system("node test/run-wasm.mjs --words build/tfhe-client.wasm - <build/zk-client-in.txt "
              ">build/zk-client-out.txt 2>&1") == 0;
  if (ok) g = fopen("build/zk-client-out.txt", "r");
  ok = ok && g != NULL;
  for (i = 0; ok && i < CL_TWO * nout; i++) {
    ok = fscanf(g, "%llu", &v) == 1;
    got[i] = ok ? (uint64_t)v : 0;
  }
  ok = ok && fscanf(g, "%llu", &v) != 1;
  if (g != NULL) fclose(g);
  if (ok) {
    remove("build/zk-client-in.txt");
    remove("build/zk-client-out.txt");
  }
  return ok;
}

/* 1 when the motion reader gives WANT on the N words W under C. */
static int client_mcode(const uint64_t *w, size_t n, const ZrContext *c, ZrErr want) {
  static ZrMotion m;
  return zr_read_motion(&m, w, n, c) == want;
}

static void rows_client_motion(void) {
  static const uint32_t idx[CL_TWO] = {0, MERKLE_LAST};
  static const ClEdit bad[] = {
      {0, CL_DIGEST, 0, ZR_ERR_LIMB, "client motion: a root that is not canonical gives the limb code"},
      {4, CL_DIGEST, 0, ZR_ERR_LIMB, "client motion: an mt that is not canonical gives the limb code"},
      {9, CL_DIGEST, 0, ZR_ERR_LIMB, "client motion: a ctx that is not canonical gives the limb code"},
      {13, CL_DIGEST, 0, ZR_ERR_LIMB, "client motion: a K that is not canonical gives the limb code"},
      {18 + 4 * (ZK_MERKLE_LEVELS - 1), CL_DIGEST, 0, ZR_ERR_LIMB,
       "client motion: a sibling that is not canonical gives the limb code"},
      {18, CL_DIGEST, 0, ZR_ERR_LIMB,
       "client motion: a first sibling that is not canonical gives the limb code"},
      {17, CL_SET, ZR_IDX_LIMIT, ZR_ERR_LIMB, "client motion: idx 2^16 gives the limb code"},
      {18, CL_FLIP, 0, ZR_ERR_REF, "client motion: a changed sibling gives the reference code"},
      {4, CL_FLIP, 0, ZR_ERR_REF, "client motion: a changed mt word gives the reference code"}};
  static uint64_t in[CL_TWO * CL_MOTION_IN], want[CL_TWO * ZR_MOTION_WORDS], got[CL_TWO * ZR_MOTION_WORDS];
  const uint64_t *last = got + (CL_TWO - 1) * ZR_MOTION_WORDS;
  uint64_t w[ZR_MOTION_WORDS + 1];
  ZrContext c[CL_TWO], x;
  size_t k, t;
  int ok = 1;
  memset(c, 0, sizeof c);
  for (k = 0; k < CL_TWO; k++) {
    ok = client_motion(idx[k], in + k * CL_MOTION_IN, want + k * ZR_MOTION_WORDS, c[k].root) && ok;
    c[k].e = U3_E;
    memcpy(c[k].ctx, U3_CTX, sizeof U3_CTX);
  }
  check(ok, "client motion: the zk_gmotion_fill root is the model_fold root at idx 0 and 2^16 - 1");
  ok = client_wasm("motion", in, CL_MOTION_IN, got, ZR_MOTION_WORDS);
  check(ok, "client motion: the module, the input or node failed (build/zk-client-out.txt)");
  if (!ok) return;
  check(memcmp(got, want, sizeof want) == 0, "client motion: the C words are the Wasm words at idx 0 and 2^16 - 1");
  for (k = 0; k < CL_TWO; k++)
    check(client_mcode(got + k * ZR_MOTION_WORDS, ZR_MOTION_WORDS, &c[k], ZR_OK),
          "client motion: the reader accepts the Wasm words at idx 0 and 2^16 - 1");
  memcpy(w, last, ZR_MOTION_WORDS * sizeof *w);
  w[ZR_MOTION_WORDS] = 0;
  check(client_mcode(w, ZR_MOTION_WORDS - 1, &c[CL_TWO - 1], ZR_ERR_COUNT),
        "client motion: a short count gives the count code");
  check(client_mcode(w, ZR_MOTION_WORDS + 1, &c[CL_TWO - 1], ZR_ERR_COUNT),
        "client motion: a long count gives the count code");
  for (t = 0; t < sizeof bad / sizeof *bad; t++) {
    memcpy(w, last, ZR_MOTION_WORDS * sizeof *w);
    client_edit(w, &bad[t]);
    check(client_mcode(w, ZR_MOTION_WORDS, &c[CL_TWO - 1], bad[t].want), bad[t].what);
  }
  x = c[CL_TWO - 1];
  x.root[0] ^= 1u;
  check(client_mcode(last, ZR_MOTION_WORDS, &x, ZR_ERR_CONTEXT),
        "client motion: a changed context root gives the context code");
  x = c[CL_TWO - 1];
  x.e ^= 1u;
  check(client_mcode(last, ZR_MOTION_WORDS, &x, ZR_ERR_CONTEXT),
        "client motion: a changed context epoch gives the context code");
  x = c[CL_TWO - 1];
  x.ctx[0] ^= 1u;
  check(client_mcode(last, ZR_MOTION_WORDS, &x, ZR_ERR_CONTEXT),
        "client motion: a changed context motion ctx gives the context code");
}

/* The vote R1 and R2 rows. The base block: zero Digests, e, u, w 3, idx 0, m
 * with the one at slot 0, zero mask, body, r, e1 and e2. */
static void rows_client_vote(void) {
  static const ClEdit bad[] = {
      {0, CL_DIGEST, 0, ZR_ERR_LIMB, "client vote: a root that is not canonical gives the limb code"},
      {4, CL_DIGEST, 0, ZR_ERR_LIMB, "client vote: an nf that is not canonical gives the limb code"},
      {2075, CL_DIGEST, 0, ZR_ERR_LIMB, "client vote: a K that is not canonical gives the limb code"},
      {2080, CL_DIGEST, 0, ZR_ERR_LIMB, "client vote: a sibling that is not canonical gives the limb code"},
      {2080 + 4 * (ZK_MERKLE_LEVELS - 1), CL_DIGEST, 0, ZR_ERR_LIMB,
       "client vote: a last sibling that is not canonical gives the limb code"},
      {10, CL_SET, 2, ZR_ERR_LIMB, "client vote: w 2 gives the limb code"},
      {10, CL_SET, 5, ZR_ERR_LIMB, "client vote: w 5 gives the limb code"},
      {2079, CL_SET, ZR_IDX_LIMIT, ZR_ERR_LIMB, "client vote: idx 2^16 gives the limb code"},
      {2145, CL_SET, 2, ZR_ERR_LIMB, "client vote: a slot at 2 that is not the hot slot gives the limb code"},
      {2145, CL_SET, 1, ZR_ERR_LIMB, "client vote: a two-hot m gives the limb code"},
      {2192, CL_SET, (1 << 17) + 1, ZR_ERR_LIMB, "client vote: an e1 word at 2^17 + 1 gives the limb code"},
      {4240, CL_SET, (1 << 17) + 1, ZR_ERR_LIMB, "client vote: an e2 word at 2^17 + 1 gives the limb code"},
      {2192, CL_SET, ~(uint64_t)0 - (1 << 17), ZR_ERR_LIMB,
       "client vote: an e1 word at -2^17 - 1 gives the limb code"},
      {2192, CL_SET, 1 << 17, ZR_ERR_REF, "client vote: an e1 word at 2^17 gives the reference code"},
      {2192, CL_SET, ~(uint64_t)0 - (1 << 17) + 1, ZR_ERR_REF,
       "client vote: an e1 word at -2^17 gives the reference code"}};
  static const uint64_t pk[ZK_PKE_N] = {0};
  static uint64_t base[ZR_VOTE_WORDS + 1], w[ZR_VOTE_WORDS + 1];
  static ZrVote v;
  ZrContext c;
  size_t t;
  memset(&c, 0, sizeof c);
  c.e = U3_E;
  c.pk_a = pk;
  c.pk_b = pk;
  memset(base, 0, sizeof base);
  base[8] = U3_E;
  base[9] = U3_U[0];
  base[10] = 3;
  base[2144] = 1;
  check(zr_read_vote(&v, base, ZR_VOTE_WORDS, &c) == ZR_ERR_REF,
        "client vote: the synthetic block gives the reference code under a zero pk");
  check(zr_read_vote(&v, base, ZR_VOTE_WORDS - 1, &c) == ZR_ERR_COUNT,
        "client vote: a short count gives the count code");
  check(zr_read_vote(&v, base, ZR_VOTE_WORDS + 1, &c) == ZR_ERR_COUNT,
        "client vote: a long count gives the count code");
  for (t = 0; t < sizeof bad / sizeof *bad; t++) {
    memcpy(w, base, sizeof base);
    client_edit(w, &bad[t]);
    check(zr_read_vote(&v, w, ZR_VOTE_WORDS, &c) == bad[t].want, bad[t].what);
  }
  memcpy(w, base, sizeof base);
  w[2144] = 0;
  w[2144 + 3] = 1;
  check(zr_read_vote(&v, w, ZR_VOTE_WORDS, &c) == ZR_ERR_LIMB,
        "client vote: the hot slot at index w = 3 gives the limb code");
}

static void rows_client(void) {
  rows_client_motion();
  rows_client_vote();
}

static void rows_u6(void);

static int rows(void) {
  rows_smoke();
  rows_empty();
  rows_canonical();
  rows_refs();
  rows_outputs();
  rows_witness();
  rows_init();
  rows_text();
  rows_check();
  rows_gadgets();
  rows_arith();
  rows_fp();
  rows_poseidon2();
  rows_sha512();
  rows_u3();
  rows_pke();
  rows_client();
  rows_u6();
  if (fails == 0) puts("zk writer rows: passed");
  return fails != 0;
}

static int parse_u64(const char *s, uint64_t *v) {
  char *end;
  if (*s < '0' || *s > '9') return 0;
  *v = strtoull(s, &end, 10);
  return *end == '\0';
}

static int smoke(const char *xs, const char *ys, const char *ws) {
  uint64_t x, y, w;
  ZkWords out = {NULL, 0, 0};
  ZkErr e;
  int ok;
  if (!parse_u64(xs, &x) || !parse_u64(ys, &y) || !parse_u64(ws, &w)) {
    fprintf(stderr, "zktool: X Y W are decimal numbers below 2^64\n");
    return 2;
  }
  e = smoke_words(x, y, w, &out);
  if (e != ZK_OK) {
    fprintf(stderr, "zktool: %s\n", zk_err_text(e));
    return 1;
  }
  ok = zk_print(&out, stdout);
  zk_words_free(&out);
  return !ok;
}

/* The word offsets in the smoke words (SMOKE_3_15_5). */
enum { AT_MUL_B = 9, AT_MAP = 29, AT_X = 31, AT_STAGES = 62, AT_STAGE_DIM = 64 };

static int bad(const char *kind) {
  ZkWords out = {NULL, 0, 0};
  int ok;
  if (smoke_words(3, 15, 5, &out) != ZK_OK || out.count != SMOKE_WORDS) {
    fprintf(stderr, "zktool: the smoke words are not written\n");
    zk_words_free(&out);
    return 1;
  }
  /* zk_words leaves room: the stream grows from 64 words by doubling. */
  if (strcmp(kind, "short") == 0)
    out.count--;
  else if (strcmp(kind, "trailing") == 0 && out.count < out.cap)
    out.word[out.count++] = 0;
  else if (strcmp(kind, "noncanonical") == 0)
    memcpy(&out.word[AT_X], ZK_R_FR.limb, sizeof ZK_R_FR.limb);
  else if (strcmp(kind, "wire") == 0)
    out.word[AT_MUL_B] = 99;
  else if (strcmp(kind, "map") == 0)
    out.word[AT_MAP] = 1;
  else if (strcmp(kind, "stages") == 0)
    out.word[AT_STAGES] = 0;
  else if (strcmp(kind, "outstage") == 0)
    out.word[AT_STAGE_DIM] = 0;
  else {
    fprintf(stderr, "zktool: KIND is short, trailing, noncanonical, wire, map, stages or outstage\n");
    zk_words_free(&out);
    return 2;
  }
  ok = zk_print(&out, stdout);
  zk_words_free(&out);
  return !ok;
}

/* S7 U4 D25 (1): the agree row of the complete relation gballotfull. The
 * keys come from the tfhe_pke_rows key seed (checktool.c); pk_a and pk_b are
 * drawn before the casting KSK, so a zero small key gives the checktool pk.
 * The ballot is choice PKE_CHOICE of width PKE_WIDTH (count 16), encrypted
 * from PKE_ENC_SEED; the DRBG is replayed in the draw order r, e1, e2 for the
 * witness. The gvote part is the U3 member at index 2 of the wRoot three list.
 * The fill words equal the C mask and the 16 bodies word for word, and
 * zk_check accepts. */
static const char PKE_KEY_SEED[] = "charter-lang S5 U5 tfhe pke keys";
static const char PKE_ENC_SEED[] = "charter-lang S7 U4 pke ballot 01";
enum { PKE_CHOICE = 2, PKE_WIDTH = 4 };

typedef struct PkeCase {
  ZkFr input[ZK_GBALLOT_INPUTS];
  ZkFr weight[ZK_GBALLOTFULL_WEIGHTS];
  ZkMatrix matrix[1];
  uint32_t map[1];
  ZkFr output[2];
  ZkWitness w;
} PkeCase;

static uint32_t pke_values, gballot_values, gmask_values;

/* The TUniform word V (two's complement) as a signed value. */
static int64_t tu_signed(uint64_t v) { return v >> 63 ? -(int64_t)(0u - v) : (int64_t)v; }

typedef struct PkeBallot {
  TfhePke p;
  uint64_t mask[TFHE_POLY_N], body[ZK_PKE_SLOTS], sib[ZK_MERKLE_LEVELS * 4], want[4];
  int64_t e1[TFHE_POLY_N], e2[ZK_PKE_SLOTS];
  uint8_t r[TFHE_POLY_N], m[ZK_PKE_SLOTS];
} PkeBallot;

/* The D25 ballot of choice CHOICE, made and replayed as above; WANT and SIB
 * are the model root and the siblings of the gvote member. */
static ZkErr pke_ballot(PkeBallot *b, uint32_t choice) {
  static TfheKeys keys;
  uint64_t leaves[12];
  uint32_t j;
  TfheDrbg d;
  check(ZK_PKE_N == TFHE_POLY_N && ZK_PKE_SLOTS == TFHE_PLAIN && ZK_PKE_NOISE == TFHE_PKE_NOISE &&
            ZK_PKE_DELTA_LOG == TFHE_DELTA_LOG,
        "the zk PKE constants are those of tfhe.h");
  tfhe_drbg_init(&d, (const uint8_t *)PKE_KEY_SEED);
  if (!tfhe_pke_generate(&b->p, &keys, &d)) return ZK_ERR_MEMORY;
  tfhe_pke_release(&b->p);
  memset(b->m, 0, sizeof b->m);
  b->m[choice] = 1;
  tfhe_drbg_init(&d, (const uint8_t *)PKE_ENC_SEED);
  tfhe_pke_encrypt(b->mask, b->body, &b->p, b->m, ZK_PKE_SLOTS, &d);
  tfhe_drbg_init(&d, (const uint8_t *)PKE_ENC_SEED);
  for (j = 0; j < TFHE_POLY_N; j++) b->r[j] = (uint8_t)(tfhe_drbg_bytes(&d, 1) & 1u);
  for (j = 0; j < TFHE_POLY_N; j++) b->e1[j] = tu_signed(tfhe_tuniform(&d, TFHE_PKE_NOISE));
  for (j = 0; j < ZK_PKE_SLOTS; j++) b->e2[j] = tu_signed(tfhe_tuniform(&d, TFHE_PKE_NOISE));
  memcpy(leaves, LEAVES_THREE, sizeof leaves);
  commit_key(U3_KEY, leaves + 8);
  model_root(leaves, 3, 2, b->want, b->sib);
  return ZK_OK;
}

static ZkErr pke_agree(void) {
  static PkeBallot b;
  static PkeCase k;
  uint64_t words[ZK_PKE_N + ZK_PKE_SLOTS], root[4], nf[4];
  uint32_t j;
  ZkCircuit c;
  ZkErr err = pke_ballot(&b, PKE_CHOICE);
  if (err != ZK_OK) return err;
  memset(&k, 0, sizeof k);
  k.matrix[0].rows = 1;
  k.matrix[0].cols = ZK_GBALLOTFULL_WEIGHTS;
  k.matrix[0].entry = k.weight;
  k.w.inputs = ZK_GBALLOT_INPUTS;
  k.w.input = k.input;
  k.w.matrices = 1;
  k.w.matrix = k.matrix;
  k.w.maps = 1;
  k.w.map = k.map;
  k.w.outputs = 2;
  k.w.output = k.output;
  zk_gballotfull_fill(k.weight, U3_KEY, U3_E, U3_U[0], b.sib, 2, b.p.pk_a, b.p.pk_b, b.r, b.m, b.e1, b.e2, root, nf,
                      words);
  check(dg_eq(root, b.want), "gballotfull fill root equals the model root");
  check(memcmp(words, b.mask, sizeof b.mask) == 0 && memcmp(words + ZK_PKE_N, b.body, sizeof b.body) == 0,
        "gballotfull words equal the C mask and the 16 bodies");
  k.input[0] = zk_fr_u64(U3_E);
  k.input[1] = zk_fr_u64(U3_U[0]);
  k.input[2] = zk_fr_u64(PKE_WIDTH);
  for (j = 0; j < ZK_PKE_N; j++) {
    k.input[ZK_GBALLOT_IN_PKA + j] = zk_fr_u64(b.p.pk_a[j]);
    k.input[ZK_GBALLOT_IN_PKB + j] = zk_fr_u64(b.p.pk_b[j]);
    k.input[ZK_GBALLOT_IN_MASK + j] = zk_fr_u64(b.mask[j]);
  }
  for (j = 0; j < ZK_PKE_SLOTS; j++) k.input[ZK_GBALLOT_IN_BODY + j] = zk_fr_u64(b.body[j]);
  k.output[0] = dg_fr(b.want);
  k.output[1] = dg_fr(nf);
  zk_gballotfull(&c);
  pke_values = c.vals;
  err = finish(&c, &k.w);
  zk_free(&c);
  return err;
}

/* X^-O PK_A mod (X^N + 1, 2^64): the D20 A' that the verifier forms. */
static void pke_shift(const uint64_t *pk_a, uint32_t o, uint64_t *ap) {
  uint32_t t;
  for (t = 0; t < ZK_PKE_N; t++) ap[t] = t + o < ZK_PKE_N ? pk_a[t + o] : 0u - pk_a[t + o - ZK_PKE_N];
}

/* gballot (S7 U4 D20, D24) over the ballot B with the width WIDTH, the bits
 * M and the errors E2. The body inputs are the fill words (the C bodies for
 * the values of B); Cr goes to CR and the body words to WORDS. */
static ZkErr gballot_case(const PkeBallot *b, uint32_t width, const uint8_t *m, const int64_t *e2, uint64_t cr[4],
                          uint64_t *words) {
  static ZkFr in[ZK_GB_INPUTS], wt[ZK_GB_WEIGHTS];
  ZkFr out[3];
  ZkMatrix mx[1];
  uint32_t map[1], j;
  uint64_t root[4], nf[4];
  ZkWitness w;
  ZkCircuit c;
  ZkErr err;
  memset(wt, 0, sizeof wt);
  zk_gballot_fill(wt, U3_KEY, U3_E, U3_U[0], b->sib, 2, b->p.pk_b, b->r, m, e2, root, nf, cr, words);
  in[0] = zk_fr_u64(U3_E);
  in[1] = zk_fr_u64(U3_U[0]);
  in[2] = zk_fr_u64(width);
  for (j = 0; j < ZK_PKE_N; j++) in[ZK_GB_IN_PKB + j] = zk_fr_u64(b->p.pk_b[j]);
  for (j = 0; j < ZK_PKE_SLOTS; j++) in[ZK_GB_IN_BODY + j] = zk_fr_u64(words[j]);
  out[0] = dg_fr(b->want);
  out[1] = dg_fr(nf);
  out[2] = dg_fr(cr);
  wit_init(&w, mx, map, in, ZK_GB_INPUTS, wt, ZK_GB_WEIGHTS, out, 3);
  zk_gballot(&c);
  gballot_values = c.vals;
  err = finish(&c, &w);
  zk_free(&c);
  return err;
}

/* gmask (S7 U4 D20) at the offset O over the ballot B and the N errors E1, in
 * the circuit C (one shape for all offsets): A' from pke_shift, the 64 mask
 * inputs are the fill words (WORDS); Cr goes to CR. */
static ZkErr gmask_case(const PkeBallot *b, const ZkCircuit *c, uint32_t o, const int64_t *e1, uint64_t cr[4],
                        uint64_t *words) {
  static ZkFr in[ZK_GMASK_INPUTS], wt[ZK_GMASK_WEIGHTS];
  uint64_t ap[ZK_PKE_N];
  ZkFr out[1];
  ZkMatrix mx[1];
  uint32_t map[1], t;
  ZkWitness w;
  pke_shift(b->p.pk_a, o, ap);
  memset(wt, 0, sizeof wt);
  zk_gmask_fill(wt, ap, b->r, e1 + o, words, cr);
  for (t = 0; t < ZK_PKE_N; t++) in[t] = zk_fr_u64(ap[t]);
  for (t = 0; t < ZK_GMASK_SPAN; t++) in[ZK_GMASK_IN_MASK + t] = zk_fr_u64(words[t]);
  out[0] = dg_fr(cr);
  wit_init(&w, mx, map, in, ZK_GMASK_INPUTS, wt, ZK_GMASK_WEIGHTS, out, 1);
  return finish(c, &w);
}

/* zktool case gmask O (O a multiple of 64 below N), or case gballot choice3,
 * error or slot (D31): the agree ballot with the one in slot 3, with e2_0 =
 * 2^17 + 1, or with the one in slot w = 4; the fill moves the body words to
 * match. The case goes to stdout (case_print); the exit is 0 when written. */
static int pke_case(const char *name, const char *arg) {
  static PkeBallot b;
  int64_t e2[ZK_PKE_SLOTS];
  uint64_t cr[4], words[ZK_GMASK_SPAN];
  uint8_t m[ZK_PKE_SLOTS];
  char *end;
  const unsigned long o = strtoul(arg, &end, 10);
  const int mask = strcmp(name, "gmask") == 0 && end != arg && *end == '\0' && o < ZK_PKE_N && o % ZK_GMASK_SPAN == 0;
  const int choice3 = strcmp(arg, "choice3") == 0, error = strcmp(arg, "error") == 0, slot = strcmp(arg, "slot") == 0;
  ZkCircuit c;
  ZkErr e;
  if (!mask && (strcmp(name, "gballot") != 0 || !(choice3 || error || slot))) return 2;
  if (pke_ballot(&b, PKE_CHOICE) != ZK_OK) return 1;
  print_case = 1;
  if (mask) {
    zk_gmask(&c);
    e = gmask_case(&b, &c, (uint32_t)o, b.e1, cr, words);
    zk_free(&c);
    return e != ZK_OK;
  }
  memcpy(e2, b.e2, sizeof e2);
  memset(m, 0, sizeof m);
  m[choice3 ? 3 : slot ? PKE_WIDTH : PKE_CHOICE] = 1;
  if (error) e2[0] = ((int64_t)1 << ZK_PKE_NOISE) + 1;
  return gballot_case(&b, PKE_WIDTH, m, e2, cr, words) != ZK_OK;
}

/* zktool circuit gballot, or gmask when MASK (offset 0): the agree ballot. */
static ZkErr pke_circuit(int mask) {
  static PkeBallot b;
  uint64_t cr[4], words[ZK_GMASK_SPAN];
  ZkCircuit c;
  ZkErr e = pke_ballot(&b, PKE_CHOICE);
  if (e != ZK_OK) return e;
  if (!mask) return gballot_case(&b, PKE_WIDTH, b.m, b.e2, cr, words);
  zk_gmask(&c);
  gmask_values = c.vals;
  e = gmask_case(&b, &c, 0, b.e1, cr, words);
  zk_free(&c);
  return e;
}

/* zktool pke (S7 U4 D25; check-lig runs it, make check does not): the
 * gballotfull agree row; the ruled shape (Q-S7-U4-1 (a)): gballot and all 32
 * gmask offsets agree with the C ballot under one shared Cr = H(7, r); the
 * error, width and ballot boundaries on the whole circuits; the value counts. */
static int pke_rows(void) {
  static PkeBallot b;
  static const int64_t edge[4] = {-(1 << 17), 1 << 17, (1 << 17) + 1, -(1 << 17) - 1};
  static const uint32_t choice[4][2] = {{0, 4}, {3, 4}, {0, 3}, {2, 3}}, rw[4] = {4, 4, 3, 4};
  static const uint8_t refused[4][ZK_PKE_SLOTS] = {{0}, {1, 1}, {0, 0, 0, 1}, {0, 0, 2}};
  static int64_t e1[TFHE_POLY_N], e2[ZK_PKE_SLOTS];
  uint64_t want[4], cr[4], words[ZK_GMASK_SPAN];
  uint8_t m[ZK_PKE_SLOTS];
  uint32_t o, s;
  int ok = 1;
  ZkCircuit c;
  check(pke_agree() == ZK_OK, "gballotfull agree: zk_check accepts the C ballot");
  printf("gballotfull values %u\n", pke_values);
  if (pke_ballot(&b, PKE_CHOICE) != ZK_OK) return 1;
  zk_pke_commit(b.r, want);
  check(gballot_case(&b, PKE_WIDTH, b.m, b.e2, cr, words) == ZK_OK, "gballot agree: zk_check accepts the C ballot");
  check(memcmp(words, b.body, sizeof b.body) == 0 && dg_eq(cr, want), "gballot words equal the 16 C bodies, Cr H(7, r)");
  zk_gmask(&c);
  gmask_values = c.vals;
  for (o = 0; o < ZK_PKE_N; o += ZK_GMASK_SPAN)
    ok = ok && gmask_case(&b, &c, o, b.e1, cr, words) == ZK_OK && memcmp(words, b.mask + o, sizeof words) == 0 &&
         dg_eq(cr, want);
  check(ok, "gmask agree: all 32 offsets accept the C mask slices with the gballot Cr");
  memcpy(e1, b.e1, sizeof e1);
  memcpy(e2, b.e2, sizeof e2);
  for (s = 0; s < 4; s++) {
    e1[0] = edge[s];
    e2[0] = edge[s];
    check((gmask_case(&b, &c, 0, e1, cr, words) == ZK_OK) == (s < 2), "gmask: e1 at -2^17 and 2^17 only accepted");
    check((gballot_case(&b, PKE_WIDTH, b.m, e2, cr, words) == ZK_OK) == (s < 2),
          "gballot: e2 at -2^17 and 2^17 only accepted");
    memset(m, 0, sizeof m);
    m[choice[s][0]] = 1;
    check(gballot_case(&b, choice[s][1], m, b.e2, cr, words) == ZK_OK,
          "gballot: choice 0 and w - 1 for w = 4 and w = 3 accepted");
    check(gballot_case(&b, rw[s], refused[s], b.e2, cr, words) != ZK_OK,
          "gballot: m all zero, two ones, a one in slot w = 3, m = 2 refused");
  }
  zk_free(&c);
  printf("gballot values %u\ngmask values %u\n", gballot_values, gmask_values);
  if (fails == 0) puts("zk pke rows: passed");
  return fails != 0;
}

typedef enum {
  C_BITS,
  C_RANGE,
  C_CARRY,
  C_FP,
  C_P2,
  C_SHA,
  C_GVOTE,
  C_GMOTION,
  C_GVOTEQ,
  C_GMOTIONEQ,
  C_GBALLOTFULL,
  C_GBALLOT,
  C_GMASK,
  C_GSHARECORE,
  C_GSHARECORE256,
  C_GSHAC1,
  C_GSHAC2,
  C_GSHAC3,
  C_GCHUNK0,
  C_GCHUNK1,
  C_GCHUNK255,
  C_GCHUNK256,
  C_GSLICE0,
  C_GSLICE1,
  C_GSLICE15,
  C_GTOSS0,
  C_GTOSS1,
  C_GDEALN,
  C_GDEALN2,
  C_GDEALR,
  C_GDEALZ,
  C_GDEALV16,
  C_GDEALV64,
  C_GFLOOD,
  C_GWORD64,
  C_GWORD128,
  C_GBIT,
  C_GOPENKSK,
  C_GOPENCAST,
  C_GOPENKSKK,
  C_GOPENBSK0,
  C_GOPENBSK1,
  C_GOPENPK,
  C_GOPENSQ0,
  C_GOPENSQ1,
  C_GOPENSQ2,
  C_NONE
} Circuit;
static const char *const CIRCUIT_NAMES[C_NONE] = {"gbits",   "grange", "gcarry",    "gfp",        "gp2",  "gsha",
                                                  "gvote",   "gmotion", "gvoteq",   "gmotioneq",  "gballotfull", "gballot", "gmask",
                                                  "gsharecore", "gsharecore256", "gshac1", "gshac2", "gshac3",
                                                  "gchunk0", "gchunk1", "gchunk255", "gchunk256",
                                                  "gslice0", "gslice1", "gslice15", "gtoss0", "gtoss1", "gdealn", "gdealn2", "gdealr", "gdealz", "gdealv16", "gdealv64", "gflood", "gword64", "gword128", "gbit", "gopenksk", "gopencast", "gopenkskk", "gopenbsk0", "gopenbsk1", "gopenpk", "gopensq0", "gopensq1", "gopensq2"};

static Circuit circuit_of(const char *name) {
  uint32_t i;
  for (i = 0; i < C_NONE && strcmp(name, CIRCUIT_NAMES[i]) != 0; i++) {
  }
  return (Circuit)i;
}

/* S7 U5 D41 M1 to M3 (zktool circuit gsharecore, gsharecore256 and gshac1 to
 * gshac3; no row). The key share of party 2 is tshare_share of a fixed bit
 * secret; the mask is fixed; the floods are those of dealers 1 to 3 (subset
 * {1, 2, 3}; the setup draws the floods of all 5 dealers, the D56 full set,
 * after those 3, so those 3 do not change); all come from one fixed DRBG.
 * Each case prints its value count,
 * its k and the zk_check time to stderr. */
enum {
  TDEC_PARTY = 2,
  TDEC_DEALERS = 3,
  GSHAC_BYTES = 4 + TSHARE_BYTES * SQUASH_BIG_N, /* 98308 */
  GSHAC_BLOCKS = 769                             /* (98308 + 17 + 127) / 128 */
};
static TshareFe tdec_shares[TSHARE_PARTIES * SQUASH_BIG_N];
static Squash128 tdec_mask[SQUASH_BIG_N];
static TshareFe tdec_noise[TSHARE_PARTIES * TSHARE_PARTIES];
static uint8_t gshac_msg[GSHAC_BYTES];
static int tdec_ready;

static void tdec_setup(void) {
  static TshareFe secret[SQUASH_BIG_N];
  uint8_t seed[TFHE_SEED_BYTES];
  TfheDrbg d;
  uint32_t i;
  if (tdec_ready) return;
  memcpy(seed, "charter-lang S7 U5 gsharecore 01", TFHE_SEED_BYTES);
  tfhe_drbg_init(&d, seed);
  for (i = 0; i < SQUASH_BIG_N; i++)
    secret[i] = tshare_from_u64(tfhe_drbg_bytes(&d, 1) & 1u);
  tshare_share(tdec_shares, secret, SQUASH_BIG_N, &d);
  for (i = 0; i < SQUASH_BIG_N; i++) {
    tdec_mask[i].lo = tfhe_uniform(&d);
    tdec_mask[i].hi = tfhe_uniform(&d);
  }
  for (i = 0; i < TSHARE_PARTIES; i++)
    tdec_flood(tdec_noise + TSHARE_PARTIES * i, &d);
  tdec_ready = 1;
}

/* The k of V values: the least k with 2^k >= V + 6 (as the U4 runner). */
static uint32_t rows_k(uint32_t v) {
  uint64_t p = 1;
  uint32_t k = 0;
  while (p < (uint64_t)v + 6) {
    p *= 2;
    k++;
  }
  return k;
}

/* zk_check of C and W, timed (stderr), then finish (the words when
 * print_words). */
static ZkErr timed_finish(const char *what, const ZkCircuit *c, const ZkWitness *w) {
  const clock_t t0 = clock();
  const ZkErr e = zk_check(c, w);
  if (!quiet_rows)
    fprintf(stderr, "%s values %u k %u weights %u zk_check %.3f s %s\n", what, (unsigned)c->vals,
            (unsigned)rows_k(c->vals), (unsigned)c->weights, (double)(clock() - t0) / CLOCKS_PER_SEC, zk_err_text(e));
  (void)lig_hook(what, c, w, e);
  if (print_case) return case_print(e, w);
  if (quiet_rows) return e;
  return e == ZK_OK ? finish_words(c, w, e) : e;
}

/* M3: the values of zk_poseidon2_hash_values for N absorbed values. */
static void p2_cost(void) {
  static const uint32_t ns[3] = {5, 64, 1024};
  static uint32_t x[1024];
  ZkCircuit c;
  uint32_t i, j, v0;
  for (i = 0; i < 3; i++) {
    zk_init(&c, ns[i], 0, 0);
    for (j = 0; j < ns[i]; j++)
      x[j] = zk_input(&c, j);
    v0 = c.vals;
    zk_poseidon2_hash_values(&c, 9, ns[i], x);
    fprintf(stderr, "p2cost absorbed %u values %u\n", (unsigned)ns[i], (unsigned)(c.vals - v0));
    zk_free(&c);
  }
}

/* M1 gsharecore(N) (L3): inputs P (0), the mask words 1 .. 2N (m_(i,0) lo at
 * 1 + 2 i, hi at 2 + 2 i), b_1 .. b_5 at 2N + 1 and the V limbs at 2N + 6;
 * outputs Cn_1 .. Cn_5. The weights are the 3N share limbs (private and not
 * ranged: M1 has no share commitment, so it is a cost shape and its soundness
 * needs the D36 binding), the five n_d (zk_fp) and zk_tdec_reduce. V is the C
 * partial (tdec_partial; the mask is 0 past coordinate N). */
static ZkErr gsharecore(uint32_t n) {
  static Squash128 mask[SQUASH_BIG_N];
  static uint32_t s[3 * SQUASH_BIG_N], mw[2 * SQUASH_BIG_N];
  static uint64_t sv[3 * SQUASH_BIG_N], mv[2 * SQUASH_BIG_N];
  static ZkFr input[2 * SQUASH_BIG_N + 9];
  const uint32_t ni = 2 * n + 9, wn = 3 * n + 5 * ZK_FP_WEIGHTS, m = wn + ZK_TDEC_WEIGHTS;
  const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1);
  const TshareFe *share = tdec_shares + (TDEC_PARTY - 1) * SQUASH_BIG_N;
  const uint32_t map = 0;
  uint64_t bv[5], nv[15], vv[3], words[5];
  uint32_t b[5], nl[15], v[3], p, k0, k1, i, j;
  ZkFr out[5], x[3], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  TshareFe part;
  Fr ref;
  char what[32];
  if (n == 0 || n > SQUASH_BIG_N) return ZK_ERR_COUNT;
  wt = calloc(m, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  p2_cost();
  tdec_setup();
  memset(mask, 0, sizeof mask);
  memcpy(mask, tdec_mask, n * sizeof *mask);
  if (!tdec_partial(&part, share, mask, tdec_noise, TDEC_DEALERS, TDEC_PARTY)) return ZK_ERR_COUNT;
  zk_init(&c, ni, m, 5);
  k0 = zk_const(&c, &zero);
  k1 = zk_const(&c, &one);
  p = zk_input(&c, 0);
  zk_party(&c, p);
  for (i = 0; i < 2 * n; i++)
    mw[i] = zk_input(&c, 1 + i);
  for (j = 0; j < 5; j++) {
    b[j] = zk_input(&c, 2 * n + 1 + j);
    zk_eq(&c, zk_mul(&c, b[j], zk_sub(&c, b[j], k1)), k0);
  }
  for (i = 0; i < 3 * n; i++)
    s[i] = zk_weight(&c, i);
  for (j = 0; j < 5; j++)
    zk_fp(&c, 3 * n + ZK_FP_WEIGHTS * j, nl + 3 * j);
  zk_tdec_reduce(&c, n, s, mw, b, nl, wn, v);
  for (i = 0; i < 3; i++)
    zk_eq(&c, v[i], zk_input(&c, 2 * n + 6 + i));
  for (j = 0; j < 5; j++)
    zk_out(&c, j, zk_noise_commit(&c, p, j + 1, nl + 3 * j));
  input[0] = zk_fr_u64(TDEC_PARTY);
  for (i = 0; i < n; i++) {
    mv[2 * i] = mask[i].lo;
    mv[2 * i + 1] = mask[i].hi;
    for (j = 0; j < 3; j++) {
      sv[3 * i + j] = share[i].w[j];
      wt[3 * i + j] = zk_fr_u64(sv[3 * i + j]);
    }
  }
  for (i = 0; i < 2 * n; i++)
    input[1 + i] = zk_fr_u64(mv[i]);
  for (j = 0; j < 5; j++) {
    bv[j] = j < TDEC_DEALERS ? 1 : 0;
    input[2 * n + 1 + j] = zk_fr_u64(bv[j]);
    for (i = 0; i < 3; i++) {
      nv[3 * j + i] = j < TDEC_DEALERS ? tdec_noise[TSHARE_PARTIES * j + TDEC_PARTY - 1].w[i] : 0;
      x[i] = zk_fr_u64(nv[3 * j + i]);
    }
    zk_fp_fill(wt + 3 * n + ZK_FP_WEIGHTS * j, x);
    words[0] = TDEC_PARTY;
    words[1] = j + 1;
    for (i = 0; i < 3; i++)
      words[2 + i] = nv[3 * j + i];
    poseidon2_hash(ZK_CN_TAG, words, 5, &ref);
    out[j] = p2_zk(&ref);
  }
  for (i = 0; i < 3; i++) {
    vv[i] = part.w[i];
    input[2 * n + 6 + i] = zk_fr_u64(vv[i]);
  }
  zk_tdec_reduce_fill(wt + wn, n, sv, mv, bv, nv, vv);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = m;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = ni;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = 5;
  w.output = out;
  snprintf(what, sizeof what, "gsharecore %u", (unsigned)n);
  e = timed_finish(what, &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* zk_check (and the words when print_words, for chunk 0 only) of the chunk
 * B0 .. B0 + NB - 1 with the public H_in HIN; HOUT gets its H_out. WT holds
 * the weights of chunk 0 (the largest). */
static ZkErr gshac_chunk(uint32_t b0, uint32_t nb, const uint64_t hin[8], uint64_t hout[8], ZkFr *wt) {
  const uint32_t m = zk_sha512_chunk_weights(GSHAC_BYTES, b0, nb);
  const uint32_t map = 0;
  const int pw = print_words;
  uint32_t hi[8], ho[8], i;
  ZkFr input[8], out[8];
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  char what[32];
  if (m == 0) return ZK_ERR_COUNT;
  zk_init(&c, 8, m, 8);
  for (i = 0; i < 8; i++)
    hi[i] = zk_input(&c, i);
  zk_sha512_chunk(&c, GSHAC_BYTES, b0, nb, 0, hi, ho, NULL);
  for (i = 0; i < 8; i++)
    zk_out(&c, i, ho[i]);
  memset(wt, 0, m * sizeof *wt);
  zk_sha512_chunk_fill(wt, gshac_msg, GSHAC_BYTES, b0, nb, hin, hout);
  for (i = 0; i < 8; i++) {
    input[i] = zk_fr_u64(hin[i]);
    out[i] = zk_fr_u64(hout[i]);
  }
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = m;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = 8;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = 8;
  w.output = out;
  snprintf(what, sizeof what, "gshac%u b0 %u", (unsigned)nb, (unsigned)b0);
  print_words = pw && b0 == 0;
  e = timed_finish(what, &c, &w);
  print_words = pw;
  zk_free(&c);
  return e;
}

/* M2 gshacB (L4): the 98308-byte commitment message of party 2 (LE32 P, then
 * tshare_bytes of its 4096 shares). The fill chains all 769 blocks (chunks of
 * NB, the last chunk at 769 - NB) and the last H_out must equal
 * tshare_commit; zk_check runs on chunk 0 (H_in = the IV) and on the last
 * chunk (with the padding). */
static ZkErr gshac(uint32_t nb) {
  const uint32_t last = GSHAC_BLOCKS - nb, m = zk_sha512_chunk_weights(GSHAC_BYTES, 0, nb);
  const TshareFe *share = tdec_shares + (TDEC_PARTY - 1) * SQUASH_BIG_N;
  uint64_t h[8], hn[8], iv[8], hlast[8], want[8];
  uint8_t dg[SHA512_BYTES];
  uint32_t b0, k, i;
  ZkFr *wt;
  ZkErr e;
  if (nb == 0 || nb > 3 || m == 0) return ZK_ERR_COUNT;
  wt = calloc(m, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  tdec_setup();
  for (i = 0; i < 4; i++)
    gshac_msg[i] = (uint8_t)(TDEC_PARTY >> (8 * i));
  for (i = 0; i < SQUASH_BIG_N; i++)
    tshare_bytes(gshac_msg + 4 + TSHARE_BYTES * i, share[i]);
  for (i = 0; i < 8; i++)
    iv[i] = h[i] = sha512_initial_hash(i);
  memcpy(hlast, iv, sizeof iv);
  for (b0 = 0; b0 < GSHAC_BLOCKS; b0 += k) {
    k = b0 < last && last - b0 < nb ? last - b0 : nb;
    if (b0 == last) memcpy(hlast, h, sizeof h);
    zk_sha512_chunk_fill(wt, gshac_msg, GSHAC_BYTES, b0, k, h, hn);
    memcpy(h, hn, sizeof h);
  }
  tshare_commit(dg, TDEC_PARTY, share, SQUASH_BIG_N);
  sha_words(dg, want);
  fprintf(stderr, "gshac%u chain %s\n", (unsigned)nb, memcmp(h, want, sizeof h) == 0 ? "= tshare_commit" : "DIFFERENT");
  e = memcmp(h, want, sizeof h) == 0 ? gshac_chunk(0, nb, iv, hn, wt) : ZK_ERR_UNSAT;
  if (e == ZK_OK) e = gshac_chunk(last, nb, hlast, hn, wt);
  if (e == ZK_OK && memcmp(hn, want, sizeof hn) != 0) e = ZK_ERR_UNSAT;
  free(wt);
  return e;
}

/* S7 U5 D48 to D55 (zktool circuit gchunk0, gchunk1, gchunk255 and gchunk256; no row
 * yet): chunk proof K (zk_gchunk) of party 2 over the gshac message, with the
 * test salts of split_salt. The fill chains chunks 0 .. K - 1 from the IV;
 * chunk 256 also checks Dg = tshare_commit. p2_fr is the C oracle of Cs_K
 * and Ch_K. Each case prints its value count, its k and the zk_check time to
 * stderr (the D55 measure). */

/* The sponge of p2_sponge (zk.c) over Fr values: s = (0, 0, N + TAG 2^64),
 * add 2 values for each block, permute; the digest is s[0]. */
static ZkFr p2_fr(uint64_t tag, const ZkFr *x, uint32_t n) {
  const uint32_t blocks = n == 0 ? 1 : n / 2 + n % 2;
  uint64_t wd[FR_WORDS];
  ZkFr s[POSEIDON2_T];
  Fr f[POSEIDON2_T];
  uint32_t b, i, j;
  memset(s, 0, sizeof s);
  s[2] = zk_fr_u64(n);
  s[2].limb[2] = (uint32_t)tag;
  s[2].limb[3] = (uint32_t)(tag >> 32);
  for (b = 0; b < blocks; b++) {
    for (i = 0; i < 2; i++)
      if (2 * b + i < n) s[i] = zk_fr_add(&s[i], &x[2 * b + i]);
    for (i = 0; i < POSEIDON2_T; i++) {
      for (j = 0; j < FR_WORDS; j++)
        wd[j] = (uint64_t)s[i].limb[2 * j] | (uint64_t)s[i].limb[2 * j + 1] << 32;
      (void)fr_from_words(&f[i], wd);
    }
    poseidon2_permute(f);
    for (i = 0; i < POSEIDON2_T; i++) {
      fr_to_words(&f[i], wd);
      for (j = 0; j < FR_WORDS; j++) {
        s[i].limb[2 * j] = (uint32_t)wd[j];
        s[i].limb[2 * j + 1] = (uint32_t)(wd[j] >> 32);
      }
    }
  }
  return s[0];
}

/* A fixed test salt below 2^253 (so below r): 4 tfhe_uniform words of the
 * DRBG seeded with "charter-lang S7 U5 split salt" and the bytes KIND, K low
 * and K high. Kind 0 is sigma_K, kind 1 is rho_K, kind 2 is salt_K (Ca_K). */
static ZkFr split_salt(uint32_t kind, uint32_t k) {
  uint8_t seed[TFHE_SEED_BYTES];
  TfheDrbg d;
  uint64_t v;
  uint32_t i;
  ZkFr r;
  memcpy(seed, "charter-lang S7 U5 split salt 00", TFHE_SEED_BYTES);
  seed[29] = (uint8_t)kind;
  seed[30] = (uint8_t)k;
  seed[31] = (uint8_t)(k >> 8);
  tfhe_drbg_init(&d, seed);
  memset(&r, 0, sizeof r);
  for (i = 0; i < 4; i++) {
    v = tfhe_uniform(&d);
    if (i == 3) v &= ((uint64_t)1 << 61) - 1;
    r.limb[2 * i] = (uint32_t)v;
    r.limb[2 * i + 1] = (uint32_t)(v >> 32);
  }
  return r;
}

/* The integer of the L bytes at B, low byte first (D49). */
static uint64_t split_piece_u64(const uint8_t *b, uint32_t l) {
  uint64_t v = 0;
  uint32_t t;
  for (t = l; t > 0; t--)
    v = v << 8 | b[t - 1];
  return v;
}

/* S7 U5 D56 and D57 (zktool split): the tamper of the next gchunk or gslice
 * case; S_NONE is the honest case. An instance tamper changes one public
 * value alone with the honest witness. A witness tamper (S_SIGMA, S_RHO,
 * S_SALT_IN, S_SALT_OUT, S_ACC, S_BYTE, S_NEIGHBOUR, S_NOISE, S_Q, S_CARRY)
 * fills the weights with one private value changed and keeps the honest
 * instance. S_MOVED moves Ch_(k-1) to the hash of chunk k - 1 with one share
 * byte changed (the moved chain) and keeps the honest witness of chunk k.
 * S_CHAIN changes byte 5 of chunk 16 and moves the whole chain after it to
 * the honest SHA of that message; the Dg instance of chunk 256 stays
 * tshare_commit. S_PBYTE changes byte 0 of chunk 0 (a P byte; the P input
 * stays) and moves Ch_0 to the honest SHA of that message. S_B4 sets b_4 = 2
 * with n_4 = 0 (dealer 4 is not in the subset {1, 2, 3}), so b_4 n_4 = 0 and
 * the witness stays. S_VPW moves n_1 (and Cn_1) so that V = 0, then sets the
 * V words of the witness and of the instance to p (V + p, not canonical) and
 * Q to Q - 1; the carries stay. */
typedef enum {
  S_NONE, S_PARTY, S_INDEX, S_CS, S_CS_LAST, S_CH_IN, S_CH_OUT, S_DG, S_SIGMA, S_RHO, S_BYTE, S_PBYTE,
  S_NEIGHBOUR, S_CA_IN, S_CA_OUT, S_SALT_IN, S_SALT_OUT, S_ACC, S_MASK_LO, S_MASK_HI, S_V, S_VP, S_VPW,
  S_CN, S_NOISE, S_B, S_B2, S_B4, S_Q, S_CARRY, S_MOVED, S_CHAIN
} SplitTamper;
static SplitTamper split_tamper;
/* S7 U6 STEP 3 case mode (zktool case NAME ARG for a U6 NAME, u6_case): the
 * false witness classes of D69 by name (u6_names; U_NONE is "honest"). The
 * RESUME19 tamper sites, the D69 gflood classes fyi and fcoef and olevel (the
 * gopen witness filled at level l % 4 + 1, the circuit at l) read u6_tamper;
 * u6_vid is the vid of `zktool circuit gbit` (vid1 sets 1). */
typedef enum {
  U_NONE, U_TSEED, U_TCOMMIT, U_TPARTY, U_TJWORD, U_D2T, U_DYI, U_DCOEF, U_DZERO, U_F2T, U_FYI, U_FCOEF,
  U_WSHARE, U_BRI, U_BZERO, U_BC, U_BROOT, U_BBIT, U_BVID, U_OMASK, U_OSHARE, U_OKEY, U_ONOISE, U_OCARRY,
  U_OSIGN0, U_OSIGN1, U_OLEVEL, U_DCOEFQ
} U6Tamper;
static U6Tamper u6_tamper;
static uint64_t u6_vid;

/* The party and the dealer count of the next gchunk or gslice case (D56;
 * split_rows resets them after each row). A party outside 1 to 5 (the
 * refused rows) takes the share and the floods of party 2. */
static uint32_t split_party = TDEC_PARTY, split_dealers = TDEC_DEALERS;

/* S7 U6 D71 boundary rows (rows_u6): the gdeal noise set size b and, when
 * deal_edge is 1, the edge value deal_e of each noise; the gword secret
 * (word_edge); the gflood u words (flood_u) and dealer. */
static uint32_t deal_b = 45, deal_edge, flood_dealer = 2;
static uint64_t deal_e;
static const TshareFe *word_edge;
static const uint64_t *flood_u;

/* tkeygen_noise with deal_e for each noise: the same draws (tfhe_tuniform,
 * then the dealing of the lift), so the replay of gdeal agrees. */
static void gdeal_edge(TshareFe *sh, uint64_t *eu, uint32_t m, uint32_t b, TkeygenDegree deg, TfheDrbg *d) {
  TshareFe lift, one[TSHARE_PARTIES];
  uint32_t k, i;
  for (k = 0; k < m; k++) {
    (void)tfhe_tuniform(d, b - 1u);
    eu[k] = deal_e;
    lift = tkeygen_lift(eu[k]);
    tkeygen_deal(one, &lift, 1, deg, d);
    for (i = 0; i < TSHARE_PARTIES; i++) sh[i * m + k] = one[i];
  }
}

static uint32_t split_pi(void) {
  return split_party >= 1 && split_party <= TSHARE_PARTIES ? split_party - 1 : (uint32_t)TDEC_PARTY - 1;
}

/* X + 1 (a changed public or private value). */
static ZkFr split_inc(const ZkFr *x) {
  const ZkFr one = zk_fr_u64(1);
  return zk_fr_add(x, &one);
}

/* V + p as the 3 limb inputs of V (D57): W = V - (2^192 - p) as 3 words,
 * then the limbs (W_0, W_1, W_2 + 2^64); the top limb is above 2^64 (not
 * canonical). When V < 2^192 - p (below 2^-170) IN keeps V and the row
 * fails. */
static void split_vp(ZkFr *in, const uint64_t v[3]) {
  const uint64_t b0 = v[0] < TSHARE_FOLD, b1 = v[1] < b0;
  if (v[2] < b1) return;
  in[0] = zk_fr_u64(v[0] - TSHARE_FOLD);
  in[1] = zk_fr_u64(v[1] - b0);
  in[2] = zk_fr_u64(v[2] - b1);
  in[2].limb[2] = 1;
}

static ZkErr gchunk(uint32_t k) {
  static const uint64_t w3[3] = {1, 2, 3};
  const int last = k + 1 == ZK_SPLIT_CHUNKS;
  const uint32_t m = zk_gchunk_weights(k), m3 = zk_sha512_chunk_weights(GSHAC_BYTES, 0, 3);
  const uint32_t ni = k > 0 ? 3 : 2, no = last ? 9 : 2;
  const uint32_t map = 0;
  const TshareFe *share = tdec_shares + split_pi() * SQUASH_BIG_N;
  const uint8_t *cb = gshac_msg + ZK_SPLIT_CHUNK_BYTES * k;
  uint64_t h[8], hn[8], hm[8] = {0}, want[8];
  uint8_t dg[SHA512_BYTES];
  uint32_t i, j, n;
  int dgok = 1;
  ZkFr salt[3], x[52], input[3], out[9], ref3, *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  Fr ref;
  char what[32];
  if (m == 0) return ZK_ERR_COUNT;
  wt = calloc(m > m3 ? m : m3, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  tdec_setup();
  for (i = 0; i < 3; i++)
    x[i] = zk_fr_u64(w3[i]);
  poseidon2_hash(ZK_CS_TAG, w3, 3, &ref);
  ref3 = p2_zk(&ref);
  x[3] = p2_fr(ZK_CS_TAG, x, 3);
  fprintf(stderr, "p2_fr (1, 2, 3) %s\n", memcmp(&x[3], &ref3, sizeof ref3) == 0 ? "= poseidon2_hash" : "DIFFERENT");
  for (i = 0; i < 4; i++)
    gshac_msg[i] = (uint8_t)(split_party >> (8 * i));
  for (i = 0; i < SQUASH_BIG_N; i++)
    tshare_bytes(gshac_msg + 4 + TSHARE_BYTES * i, share[i]);
  /* S_CHAIN: byte 5 of chunk 16 changed; the chain after it is the honest
   * SHA of that message. */
  if (split_tamper == S_CHAIN) gshac_msg[ZK_SPLIT_CHUNK_BYTES * 16 + 5] ^= 1;
  /* S_PBYTE: byte 0 of chunk 0 changed (P = 2: the P bytes 3, 0, 0, 0); the
   * weights and Ch_0 come from that message. */
  if (split_tamper == S_PBYTE && k == 0) gshac_msg[0] ^= 1;
  for (i = 0; i < 8; i++)
    h[i] = sha512_initial_hash(i);
  for (j = 0; j < k; j++) {
    if (split_tamper == S_MOVED && j + 1 == k) {
      /* S_MOVED: the H_out of chunk k - 1 with byte 5 changed. */
      gshac_msg[ZK_SPLIT_CHUNK_BYTES * j + 5] ^= 1;
      zk_sha512_chunk_fill(wt, gshac_msg, GSHAC_BYTES, 3 * j, 3, h, hm);
      gshac_msg[ZK_SPLIT_CHUNK_BYTES * j + 5] ^= 1;
    }
    zk_sha512_chunk_fill(wt, gshac_msg, GSHAC_BYTES, 3 * j, 3, h, hn);
    memcpy(h, hn, sizeof h);
  }
  if (split_tamper == S_CHAIN) gshac_msg[ZK_SPLIT_CHUNK_BYTES * 16 + 5] ^= 1;
  salt[0] = split_salt(0, k);
  salt[1] = split_salt(1, k);
  salt[2] = split_salt(1, k - 1);
  memset(wt, 0, m * sizeof *wt);
  zk_gchunk_fill(wt, gshac_msg, k, h, salt, hn);
  if (split_tamper == S_PBYTE && k == 0) gshac_msg[0] ^= 1;
  if (split_tamper == S_SIGMA || split_tamper == S_RHO || split_tamper == S_BYTE) {
    /* S_BYTE: a share byte of the first piece (byte 1 of chunk 256). */
    const uint32_t at = ZK_SPLIT_CHUNK_BYTES * k + (last ? 1 : 5);
    uint64_t hx[8];
    ZkFr bad[3];
    memcpy(bad, salt, sizeof bad);
    if (split_tamper == S_SIGMA) bad[0] = split_inc(&salt[0]);
    if (split_tamper == S_RHO) bad[1] = split_inc(&salt[1]);
    if (split_tamper == S_BYTE) gshac_msg[at] ^= 1;
    memset(wt, 0, m * sizeof *wt);
    zk_gchunk_fill(wt, gshac_msg, k, h, bad, hx);
    if (split_tamper == S_BYTE) gshac_msg[at] ^= 1;
  }
  input[0] = zk_fr_u64(split_party);
  input[1] = zk_fr_u64(k);
  x[1] = input[0];
  if (k > 0) {
    x[0] = salt[2];
    x[2] = zk_fr_u64(k - 1);
    for (i = 0; i < 8; i++)
      x[3 + i] = zk_fr_u64(split_tamper == S_MOVED ? hm[i] : h[i]);
    input[2] = p2_fr(ZK_CH_TAG, x, 11);
  }
  x[0] = salt[0];
  x[2] = input[1];
  n = 3;
  if (k > 0) x[n++] = zk_fr_u64(split_piece_u64(cb, 4));
  if (!last) {
    for (i = 0; i < 47; i++)
      x[n++] = zk_fr_u64(split_piece_u64(cb + 4 + 8 * i, 8));
    x[n++] = zk_fr_u64(split_piece_u64(cb + 380, 4));
  }
  out[0] = p2_fr(ZK_CS_TAG, x, n);
  if (last) {
    tshare_commit(dg, split_party, share, SQUASH_BIG_N);
    sha_words(dg, want);
    dgok = memcmp(hn, want, sizeof hn) == 0;
    fprintf(stderr, "gchunk 256 Dg %s\n", dgok ? "= tshare_commit" : "DIFFERENT");
    /* S_CHAIN: the Dg instance stays tshare_commit (the moved chain gives an
     * other H_out); the row needs zk_check to refuse. */
    if (split_tamper == S_CHAIN) dgok = 1;
    for (i = 0; i < 8; i++)
      out[1 + i] = zk_fr_u64(split_tamper == S_CHAIN ? want[i] : hn[i]);
  } else {
    x[0] = salt[1];
    for (i = 0; i < 8; i++)
      x[3 + i] = zk_fr_u64(hn[i]);
    out[1] = p2_fr(ZK_CH_TAG, x, 11);
  }
  if (split_tamper == S_PARTY) input[0] = zk_fr_u64(split_party + 1);
  if (split_tamper == S_INDEX) input[1] = zk_fr_u64(k + 1);
  if (split_tamper == S_CH_IN && k > 0) input[2] = split_inc(&input[2]);
  if (split_tamper == S_CS) out[0] = split_inc(&out[0]);
  if (split_tamper == S_CH_OUT || split_tamper == S_DG) out[1] = split_inc(&out[1]);
  zk_init(&c, ni, m, no);
  zk_gchunk(&c, k);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = m;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = ni;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = no;
  w.output = out;
  snprintf(what, sizeof what, "gchunk %u", (unsigned)k);
  e = timed_finish(what, &c, &w);
  if (e == ZK_OK && !dgok) e = ZK_ERR_UNSAT;
  zk_free(&c);
  free(wt);
  return e;
}

/* The Fr value of a native column (3 words, low word first; below 2^141). */
static ZkFr fr_col(const uint64_t col[3]) {
  ZkFr r;
  uint32_t i;
  memset(&r, 0, sizeof r);
  for (i = 0; i < 3; i++) {
    r.limb[2 * i] = (uint32_t)col[i];
    r.limb[2 * i + 1] = (uint32_t)(col[i] >> 32);
  }
  return r;
}

/* S7 U5 D52 to D56 (zktool circuit gslice0, gslice1 and gslice15; no row
 * yet): slice proof J (zk_gslice) of party 2 over the gshac message and the
 * tdec masks, with the test salts of split_salt. p2_fr is the C oracle of the
 * 17 Cs_k (the same values as in gchunk K), of Ca_(J-1) and of Ca_J; the
 * native columns come from zk_tdec_cols_fill. Slice 15 checks V against
 * tdec_partial and the Cn_d against poseidon2_hash, as gsharecore does. Each
 * case prints its value count, its k and the zk_check time to stderr. */
static ZkErr gslice(uint32_t j) {
  static uint64_t sv[3 * SQUASH_BIG_N], mv[2 * SQUASH_BIG_N];
  static ZkFr input[4 + ZK_SPLIT_SLICE_CHUNKS + 2 * ZK_SPLIT_SLICE_COORDS + 8];
  const int last = j + 1 == ZK_SPLIT_SLICES;
  const uint32_t m = zk_gslice_weights(j), ca = 3 + ZK_SPLIT_SLICE_CHUNKS, mi = ca + (j > 0 ? 1 : 0);
  const uint32_t ni = mi + 2 * ZK_SPLIT_SLICE_COORDS + (last ? 8 : 0), no = last ? 5 : 1;
  const uint32_t c0 = ZK_SPLIT_SLICE_COORDS * j, map = 0;
  const TshareFe *share = tdec_shares + split_pi() * SQUASH_BIG_N;
  uint64_t col[4][3], bv[5], nv[15], vv[3], words[5];
  uint32_t i, t, k, n, tail;
  ZkFr sigma[ZK_SPLIT_SLICE_CHUNKS + 1], salt[2], a0[4], x[52], out[5], f[3], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  TshareFe part;
  Fr ref;
  char what[32];
  if (m == 0) return ZK_ERR_COUNT;
  wt = calloc(m, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  tdec_setup();
  for (i = 0; i < 4; i++)
    gshac_msg[i] = (uint8_t)(split_party >> (8 * i));
  for (i = 0; i < SQUASH_BIG_N; i++) {
    tshare_bytes(gshac_msg + 4 + TSHARE_BYTES * i, share[i]);
    for (t = 0; t < 3; t++)
      sv[3 * i + t] = share[i].w[t];
    mv[2 * i] = tdec_mask[i].lo;
    mv[2 * i + 1] = tdec_mask[i].hi;
  }
  input[0] = zk_fr_u64(split_party);
  input[1] = zk_fr_u64(j);
  x[1] = input[0];
  for (t = 0; t <= ZK_SPLIT_SLICE_CHUNKS; t++) {
    const uint8_t *cb;
    k = ZK_SPLIT_SLICE_CHUNKS * j + t;
    cb = gshac_msg + ZK_SPLIT_CHUNK_BYTES * k;
    sigma[t] = split_salt(0, k);
    x[0] = sigma[t];
    x[2] = zk_fr_u64(k);
    n = 3;
    if (k > 0) x[n++] = zk_fr_u64(split_piece_u64(cb, 4));
    if (k + 1 < ZK_SPLIT_CHUNKS) {
      for (i = 0; i < 47; i++)
        x[n++] = zk_fr_u64(split_piece_u64(cb + 4 + 8 * i, 8));
      x[n++] = zk_fr_u64(split_piece_u64(cb + 380, 4));
    }
    input[2 + t] = p2_fr(ZK_CS_TAG, x, n);
  }
  memset(col, 0, sizeof col);
  zk_tdec_cols_fill(col, c0, sv, mv);
  for (i = 0; i < 4; i++)
    a0[i] = fr_col(col[i]);
  salt[0] = split_salt(2, j - 1);
  salt[1] = split_salt(2, j);
  if (j > 0) {
    x[0] = salt[0];
    x[2] = zk_fr_u64(j - 1);
    memcpy(x + 3, a0, sizeof a0);
    input[ca] = p2_fr(ZK_CA_TAG, x, 7);
  }
  for (i = 0; i < 2 * ZK_SPLIT_SLICE_COORDS; i++)
    input[mi + i] = zk_fr_u64(mv[2 * c0 + i]);
  memset(wt, 0, m * sizeof *wt);
  {
    /* S_BYTE: a share byte of chunk 16J + 1 (slice J); S_NEIGHBOUR: byte 0
     * of chunk 16J (a piece of slice J - 1, private, used by Cs_16J only). */
    const uint32_t at = ZK_SPLIT_CHUNK_BYTES * (ZK_SPLIT_SLICE_CHUNKS * j + (split_tamper == S_BYTE ? 1 : 0)) +
                        (split_tamper == S_BYTE ? 5 : 0);
    const int flip = split_tamper == S_BYTE || (split_tamper == S_NEIGHBOUR && j > 0);
    ZkFr bsigma[ZK_SPLIT_SLICE_CHUNKS + 1], bsalt[2], ba0[4];
    memcpy(bsigma, sigma, sizeof bsigma);
    memcpy(bsalt, salt, sizeof bsalt);
    memcpy(ba0, a0, sizeof ba0);
    if (split_tamper == S_SIGMA) bsigma[1] = split_inc(&sigma[1]);
    if (split_tamper == S_SALT_IN) bsalt[0] = split_inc(&salt[0]);
    if (split_tamper == S_SALT_OUT) bsalt[1] = split_inc(&salt[1]);
    if (split_tamper == S_ACC) ba0[0] = split_inc(&a0[0]);
    if (flip) gshac_msg[at] ^= 1;
    zk_gslice_fill(wt, gshac_msg, j, bsigma, bsalt, ba0);
    if (flip) gshac_msg[at] ^= 1;
  }
  if (!last) {
    zk_tdec_cols_fill(col, ZK_SPLIT_SLICE_COORDS, sv + 3 * c0, mv + 2 * c0);
    x[0] = salt[1];
    x[2] = input[1];
    for (i = 0; i < 4; i++)
      x[3 + i] = fr_col(col[i]);
    out[0] = p2_fr(ZK_CA_TAG, x, 7);
  } else {
    tail = m - ZK_TDEC_PARTIES * ZK_FP_WEIGHTS - ZK_TDEC_WEIGHTS;
    /* S_VPW: n_1 moved by -V first, so V = 0 and V + p = p is below 2^192. */
    if (split_tamper == S_VPW && tdec_partial(&part, share, tdec_mask, tdec_noise, split_dealers, split_party))
      tdec_noise[split_pi()] = tshare_sub(tdec_noise[split_pi()], part);
    if (!tdec_partial(&part, share, tdec_mask, tdec_noise, split_dealers, split_party)) {
      free(wt);
      return ZK_ERR_COUNT;
    }
    for (t = 0; t < 5; t++) {
      bv[t] = t < split_dealers ? 1 : 0;
      input[mi + 2 * ZK_SPLIT_SLICE_COORDS + t] = zk_fr_u64(bv[t]);
      for (i = 0; i < 3; i++) {
        nv[3 * t + i] = t < split_dealers ? tdec_noise[TSHARE_PARTIES * t + split_pi()].w[i] : 0;
        f[i] = zk_fr_u64(nv[3 * t + i]);
      }
      zk_fp_fill(wt + tail + ZK_FP_WEIGHTS * t, f);
      words[0] = split_party;
      words[1] = t + 1;
      for (i = 0; i < 3; i++)
        words[2 + i] = nv[3 * t + i];
      poseidon2_hash(ZK_CN_TAG, words, 5, &ref);
      out[t] = p2_zk(&ref);
    }
    if (split_tamper == S_NOISE) {
      nv[0] += 1;
      for (i = 0; i < 3; i++)
        f[i] = zk_fr_u64(nv[i]);
      zk_fp_fill(wt + tail, f);
    }
    for (i = 0; i < 3; i++) {
      vv[i] = part.w[i];
      input[mi + 2 * ZK_SPLIT_SLICE_COORDS + 5 + i] = zk_fr_u64(vv[i]);
    }
    zk_tdec_reduce_fill(wt + tail + ZK_TDEC_PARTIES * ZK_FP_WEIGHTS, SQUASH_BIG_N, sv, mv, bv, nv, vv);
    {
      /* The reduce weights after V: Q (ZK_TDEC_Q_BITS bits), then the
       * carries c_k + 2^79 (ZK_TDEC_CARRY_BITS bits each). S_Q: bit 0 of Q
       * flipped. S_CARRY: bit 79 of c_0 + 2^79 plus 2, so the carry word is
       * c_0 + 2^79 + 2^80 (out of its 80-bit range). S_VPW (V = 0): the V
       * words p in the weights and in the instance, and Q - 1 as q_0 - 1 (q_0
       * is 0 below 2^-64), so the carries stay. */
      const uint32_t wq = tail + ZK_TDEC_PARTIES * ZK_FP_WEIGHTS + ZK_FP_WEIGHTS;
      const uint32_t wc = wq + ZK_TDEC_Q_BITS + ZK_TDEC_CARRY_BITS - 1;
      const ZkFr zero = zk_fr_u64(0), one = zk_fr_u64(1), two = zk_fr_u64(2);
      if (split_tamper == S_Q) wt[wq] = memcmp(&wt[wq], &zero, sizeof zero) == 0 ? zk_fr_u64(1) : zero;
      if (split_tamper == S_CARRY) wt[wc] = zk_fr_add(&wt[wc], &two);
      if (split_tamper == S_VPW) {
        fp_limbs(f, FP_P);
        zk_fp_fill(wt + tail + ZK_TDEC_PARTIES * ZK_FP_WEIGHTS, f);
        memcpy(input + mi + 2 * ZK_SPLIT_SLICE_COORDS + 5, f, sizeof f);
        for (i = 0; i < 64 && memcmp(&wt[wq + i], &zero, sizeof zero) == 0; i++)
          wt[wq + i] = one;
        if (i < 64) wt[wq + i] = zero;
      }
    }
  }
  {
    const uint32_t vb = mi + 2 * ZK_SPLIT_SLICE_COORDS;
    if (split_tamper == S_PARTY) input[0] = zk_fr_u64(split_party + 1);
    if (split_tamper == S_INDEX) input[1] = zk_fr_u64(j + 1);
    if (split_tamper == S_CS) input[3] = split_inc(&input[3]);
    if (split_tamper == S_CS_LAST) input[2 + ZK_SPLIT_SLICE_CHUNKS] = split_inc(&input[2 + ZK_SPLIT_SLICE_CHUNKS]);
    if (split_tamper == S_CA_IN && j > 0) input[ca] = split_inc(&input[ca]);
    if (split_tamper == S_CA_OUT && !last) out[0] = split_inc(&out[0]);
    if (split_tamper == S_MASK_LO) input[mi] = split_inc(&input[mi]);
    if (split_tamper == S_MASK_HI) input[mi + 1] = split_inc(&input[mi + 1]);
    if (split_tamper == S_CN && last) out[0] = split_inc(&out[0]);
    if (split_tamper == S_V && last) input[vb + 5] = split_inc(&input[vb + 5]);
    if (split_tamper == S_VP && last) split_vp(input + vb + 5, vv);
    if (split_tamper == S_B && last) input[vb] = zk_fr_u64(0);
    if (split_tamper == S_B2 && last) input[vb] = zk_fr_u64(2);
    if (split_tamper == S_B4 && last) input[vb + 3] = zk_fr_u64(2);
  }
  zk_init(&c, ni, m, no);
  zk_gslice(&c, j);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = m;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = ni;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = no;
  w.output = out;
  snprintf(what, sizeof what, "gslice %u", (unsigned)j);
  e = timed_finish(what, &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U5 D56 (zktool split): the state change of a split row before its case
 * (split_rows restores the tdec setup, the party and the dealer count after
 * each row). X_PARTY: party A (1 to 5 accepted, 0 and 6 refused by the party
 * polynomial). X_FULL: party A with the full set of 5 dealers. X_SHARE: share
 * A of party 2 set to 0 (B = 0) or p - 1 (B = 1). X_CUT: group 2 of share A
 * of party 2 set to 0x0102030405060708 (the cut halves 0x05060708 and
 * 0x01020304 differ). X_MASK: the 256 masks of slice A set to 0 (B = 0) or
 * 2^128 - 1 (B = 1). X_FLOOD: the flood n_1 of dealer 1 to party 2 set to
 * -2^106 (B = 0) or 2^106 - 1 (B = 1). */
typedef enum { X_NONE, X_PARTY, X_FULL, X_SHARE, X_CUT, X_MASK, X_FLOOD } SplitSet;

static void split_set(SplitSet x, uint32_t a, uint32_t b) {
  const uint64_t ones = ~(uint64_t)0;
  TshareFe *share = tdec_shares + (TDEC_PARTY - 1) * SQUASH_BIG_N;
  TshareFe v;
  uint32_t i;
  memset(&v, 0, sizeof v);
  v.w[1] = (uint64_t)1 << 42;
  if (x == X_PARTY || x == X_FULL) split_party = a;
  if (x == X_FULL) split_dealers = TSHARE_PARTIES;
  if (x == X_SHARE) share[a] = b ? tshare_from_i64(-1) : tshare_from_u64(0);
  if (x == X_CUT) share[a].w[2] = 0x0102030405060708u;
  if (x == X_MASK)
    for (i = 0; i < ZK_SPLIT_SLICE_COORDS; i++) {
      tdec_mask[ZK_SPLIT_SLICE_COORDS * a + i].lo = b ? ones : 0;
      tdec_mask[ZK_SPLIT_SLICE_COORDS * a + i].hi = b ? ones : 0;
    }
  if (x == X_FLOOD) tdec_noise[TDEC_PARTY - 1] = b ? tshare_sub(v, tshare_from_u64(1)) : tshare_sub(tshare_from_u64(0), v);
}

/* S7 U5 D56 and D57 (zktool split; heavy, not make check): the check-lig
 * subset of the split against the C oracle. D56: chunk 0, the middle chunk
 * 16 (shares 255 and 256 at the slice edge), chunk 256 (Dg =
 * tshare_commit) and slices 0, 1 and 15 (V = tdec_partial, the Cn_d)
 * agree, also for parties 1 and 5 (0 and 6 refused), V of slice 15 for
 * parties 1 to 5 with the subset {1, 2, 3} and with the full set, the cut
 * weights (group 2 of shares 15 and 255) and the share, mask and flood
 * boundaries. D57: zk_check refuses each tamper alone. */
static int split_rows(void) {
  static const struct {
    int slice;
    uint32_t k;
    SplitTamper t;
    const char *what;
    SplitSet x;
    uint32_t a, b;
  } row[] = {
      {0, 0, S_NONE, "chunk 0 agrees", X_NONE, 0, 0},
      {0, 16, S_NONE, "chunk 16 agrees", X_NONE, 0, 0},
      {0, 256, S_NONE, "chunk 256 agrees (Dg = tshare_commit)", X_NONE, 0, 0},
      {1, 0, S_NONE, "slice 0 agrees", X_NONE, 0, 0},
      {1, 1, S_NONE, "slice 1 agrees", X_NONE, 0, 0},
      {1, 15, S_NONE, "slice 15 agrees (V = tdec_partial, Cn_d)", X_NONE, 0, 0},
      {0, 0, S_PARTY, "chunk 0: party alone refused (P bytes)", X_NONE, 0, 0},
      {0, 0, S_PBYTE, "chunk 0: P byte 0 = 3 with P = 2 (Ch_0 of that message) refused", X_NONE, 0, 0},
      {0, 16, S_PARTY, "chunk 16: party alone refused", X_NONE, 0, 0},
      {0, 16, S_INDEX, "chunk 16: index k alone refused", X_NONE, 0, 0},
      {0, 16, S_CS, "chunk 16: Cs_16 alone refused", X_NONE, 0, 0},
      {0, 16, S_CH_IN, "chunk 16: Ch_15 alone refused", X_NONE, 0, 0},
      {0, 16, S_CH_OUT, "chunk 16: Ch_16 alone refused", X_NONE, 0, 0},
      {0, 16, S_SIGMA, "chunk 16: sigma_16 changed, Cs_16 honest, refused", X_NONE, 0, 0},
      {0, 16, S_RHO, "chunk 16: rho_16 changed, Ch_16 honest, refused", X_NONE, 0, 0},
      {0, 16, S_BYTE, "chunk 16: one share byte changed refused", X_NONE, 0, 0},
      {0, 256, S_PARTY, "chunk 256: party alone refused", X_NONE, 0, 0},
      {0, 256, S_DG, "chunk 256: a Dg word alone refused", X_NONE, 0, 0},
      {0, 256, S_CH_IN, "chunk 256: Ch_255 alone refused", X_NONE, 0, 0},
      {1, 0, S_PARTY, "slice 0: party alone refused", X_NONE, 0, 0},
      {1, 0, S_CA_OUT, "slice 0: Ca_0 alone refused", X_NONE, 0, 0},
      {1, 1, S_PARTY, "slice 1: party alone refused", X_NONE, 0, 0},
      {1, 1, S_INDEX, "slice 1: index j alone refused", X_NONE, 0, 0},
      {1, 1, S_CS, "slice 1: Cs_17 alone (an opening) refused", X_NONE, 0, 0},
      {1, 1, S_CS_LAST, "slice 1: Cs_32 alone (the opening of t = 16) refused", X_NONE, 0, 0},
      {1, 1, S_CA_IN, "slice 1: Ca_0 alone refused", X_NONE, 0, 0},
      {1, 1, S_CA_OUT, "slice 1: Ca_1 alone refused", X_NONE, 0, 0},
      {1, 1, S_SIGMA, "slice 1: sigma_17 changed, Cs_17 honest, refused", X_NONE, 0, 0},
      {1, 1, S_SALT_IN, "slice 1: salt_0 changed, Ca_0 honest, refused", X_NONE, 0, 0},
      {1, 1, S_SALT_OUT, "slice 1: salt_1 changed, Ca_1 honest, refused", X_NONE, 0, 0},
      {1, 1, S_ACC, "slice 1: A_(0,0) changed, Ca_0 honest, refused", X_NONE, 0, 0},
      {1, 1, S_MASK_LO, "slice 1: mask word lo alone refused", X_NONE, 0, 0},
      {1, 1, S_MASK_HI, "slice 1: mask word hi alone refused", X_NONE, 0, 0},
      {1, 1, S_BYTE, "slice 1: one piece changed in an opening, Cs_17 honest, refused", X_NONE, 0, 0},
      {1, 1, S_NEIGHBOUR, "slice 1: the neighbour piece of chunk 16 changed refused", X_NONE, 0, 0},
      {1, 15, S_PARTY, "slice 15: party alone refused", X_NONE, 0, 0},
      {1, 15, S_CA_IN, "slice 15: Ca_14 alone refused", X_NONE, 0, 0},
      {1, 15, S_V, "slice 15: V + 1 refused", X_NONE, 0, 0},
      {1, 15, S_VP, "slice 15: V + p (not canonical) refused", X_NONE, 0, 0},
      {1, 15, S_VPW, "slice 15: V + p in the witness (n_1 moved so V = 0, V words p, Q - 1) refused", X_NONE, 0, 0},
      {1, 15, S_CN, "slice 15: Cn_1 alone refused", X_NONE, 0, 0},
      {1, 15, S_NOISE, "slice 15: n_1 changed, Cn_1 honest, refused", X_NONE, 0, 0},
      {1, 15, S_B, "slice 15: b_1 alone (1 to 0) refused", X_NONE, 0, 0},
      {1, 15, S_B2, "slice 15: b_1 = 2 refused", X_NONE, 0, 0},
      {1, 15, S_B4, "slice 15: b_4 = 2 with n_4 = 0 (subset {1, 2, 3}) refused", X_NONE, 0, 0},
      {1, 15, S_Q, "slice 15: quotient Q bit 0 changed refused", X_NONE, 0, 0},
      {1, 15, S_CARRY, "slice 15: carry c_0 + 2^80 (out of range) refused", X_NONE, 0, 0},
      {0, 17, S_MOVED, "chunk 17: share byte of chunk 16 changed, Ch_16 moved, refused", X_NONE, 0, 0},
      {0, 0, S_NONE, "party 1: chunk 0 agrees", X_PARTY, 1, 0},
      {0, 256, S_NONE, "party 1: chunk 256 agrees (Dg = tshare_commit)", X_PARTY, 1, 0},
      {1, 1, S_NONE, "party 1: slice 1 agrees", X_PARTY, 1, 0},
      {1, 15, S_NONE, "party 1: slice 15 agrees (V, subset {1, 2, 3})", X_PARTY, 1, 0},
      {0, 0, S_NONE, "party 5: chunk 0 agrees", X_PARTY, 5, 0},
      {0, 256, S_NONE, "party 5: chunk 256 agrees (Dg = tshare_commit)", X_PARTY, 5, 0},
      {1, 1, S_NONE, "party 5: slice 1 agrees", X_PARTY, 5, 0},
      {1, 15, S_NONE, "party 5: slice 15 agrees (V, subset {1, 2, 3})", X_PARTY, 5, 0},
      {0, 0, S_NONE, "party 0: chunk 0 refused", X_PARTY, 0, 0},
      {0, 16, S_NONE, "party 0: chunk 16 refused", X_PARTY, 0, 0},
      {1, 0, S_NONE, "party 0: slice 0 refused", X_PARTY, 0, 0},
      {1, 1, S_NONE, "party 0: slice 1 refused", X_PARTY, 0, 0},
      {0, 0, S_NONE, "party 6: chunk 0 refused", X_PARTY, 6, 0},
      {0, 16, S_NONE, "party 6: chunk 16 refused", X_PARTY, 6, 0},
      {1, 0, S_NONE, "party 6: slice 0 refused", X_PARTY, 6, 0},
      {1, 1, S_NONE, "party 6: slice 1 refused", X_PARTY, 6, 0},
      {1, 15, S_NONE, "party 3: slice 15 agrees (V, subset {1, 2, 3})", X_PARTY, 3, 0},
      {1, 15, S_NONE, "party 4: slice 15 agrees (V, subset {1, 2, 3})", X_PARTY, 4, 0},
      {1, 15, S_NONE, "party 1: slice 15 agrees (V, full set of 5)", X_FULL, 1, 0},
      {1, 15, S_NONE, "party 2: slice 15 agrees (V, full set of 5)", X_FULL, 2, 0},
      {1, 15, S_NONE, "party 3: slice 15 agrees (V, full set of 5)", X_FULL, 3, 0},
      {1, 15, S_NONE, "party 4: slice 15 agrees (V, full set of 5)", X_FULL, 4, 0},
      {1, 15, S_NONE, "party 5: slice 15 agrees (V, full set of 5)", X_FULL, 5, 0},
      {0, 0, S_NONE, "cut share 15 group 2: chunk 0 agrees", X_CUT, 15, 0},
      {0, 1, S_NONE, "cut share 15 group 2: chunk 1 agrees", X_CUT, 15, 0},
      {1, 0, S_NONE, "cut share 15 group 2: slice 0 agrees", X_CUT, 15, 0},
      {0, 15, S_NONE, "cut share 255 group 2: chunk 15 agrees", X_CUT, 255, 0},
      {0, 16, S_NONE, "cut share 255 group 2: chunk 16 agrees", X_CUT, 255, 0},
      {1, 0, S_NONE, "cut share 255 group 2: slice 0 agrees", X_CUT, 255, 0},
      {1, 1, S_NONE, "cut share 255 group 2: slice 1 agrees", X_CUT, 255, 0},
      {0, 0, S_NONE, "share 0 = 0: chunk 0 agrees", X_SHARE, 0, 0},
      {1, 0, S_NONE, "share 0 = 0: slice 0 agrees", X_SHARE, 0, 0},
      {0, 16, S_NONE, "share 255 = 0: chunk 16 agrees", X_SHARE, 255, 0},
      {1, 0, S_NONE, "share 255 = 0: slice 0 agrees", X_SHARE, 255, 0},
      {0, 16, S_NONE, "share 256 = 0: chunk 16 agrees", X_SHARE, 256, 0},
      {1, 1, S_NONE, "share 256 = 0: slice 1 agrees", X_SHARE, 256, 0},
      {0, 256, S_NONE, "share 4095 = 0: chunk 256 agrees", X_SHARE, 4095, 0},
      {1, 15, S_NONE, "share 4095 = 0: slice 15 agrees", X_SHARE, 4095, 0},
      {0, 0, S_NONE, "share 0 = p - 1: chunk 0 agrees", X_SHARE, 0, 1},
      {1, 0, S_NONE, "share 0 = p - 1: slice 0 agrees", X_SHARE, 0, 1},
      {0, 16, S_NONE, "share 255 = p - 1: chunk 16 agrees", X_SHARE, 255, 1},
      {1, 0, S_NONE, "share 255 = p - 1: slice 0 agrees", X_SHARE, 255, 1},
      {0, 16, S_NONE, "share 256 = p - 1: chunk 16 agrees", X_SHARE, 256, 1},
      {1, 1, S_NONE, "share 256 = p - 1: slice 1 agrees", X_SHARE, 256, 1},
      {0, 256, S_NONE, "share 4095 = p - 1: chunk 256 agrees", X_SHARE, 4095, 1},
      {1, 15, S_NONE, "share 4095 = p - 1: slice 15 agrees", X_SHARE, 4095, 1},
      {0, 15, S_NONE, "share 255 = 0: chunk 15 agrees", X_SHARE, 255, 0},
      {0, 15, S_NONE, "share 255 = p - 1: chunk 15 agrees", X_SHARE, 255, 1},
      {0, 255, S_NONE, "share 4095 = 0: chunk 255 agrees", X_SHARE, 4095, 0},
      {0, 255, S_NONE, "share 4095 = p - 1: chunk 255 agrees", X_SHARE, 4095, 1},
      {1, 0, S_NONE, "masks of slice 0 = 0: slice 0 agrees", X_MASK, 0, 0},
      {1, 0, S_NONE, "masks of slice 0 = 2^128 - 1: slice 0 agrees", X_MASK, 0, 1},
      {1, 15, S_NONE, "masks of slice 15 = 0: slice 15 agrees", X_MASK, 15, 0},
      {1, 15, S_NONE, "masks of slice 15 = 2^128 - 1: slice 15 agrees", X_MASK, 15, 1},
      {1, 15, S_NONE, "flood n_1 = -2^106: slice 15 agrees", X_FLOOD, 0, 0},
      {1, 15, S_NONE, "flood n_1 = 2^106 - 1: slice 15 agrees", X_FLOOD, 0, 1},
      {0, 256, S_CHAIN, "chunk 256: share byte of chunk 16 changed, whole chain moved, Dg refused", X_NONE, 0, 0},
  };
  static TshareFe bshares[TSHARE_PARTIES * SQUASH_BIG_N], bnoise[TSHARE_PARTIES * TSHARE_PARTIES];
  static Squash128 bmask[SQUASH_BIG_N];
  const uint32_t n = sizeof row / sizeof row[0];
  uint32_t i;
  tdec_setup();
  memcpy(bshares, tdec_shares, sizeof bshares);
  memcpy(bmask, tdec_mask, sizeof bmask);
  memcpy(bnoise, tdec_noise, sizeof bnoise);
  for (i = 0; i < n; i++) {
    /* A party outside 1 to 5 is refused by the party polynomial. */
    const int bad_party = row[i].x == X_PARTY && (row[i].a == 0 || row[i].a > TSHARE_PARTIES);
    const ZkErr want = row[i].t == S_NONE && !bad_party ? ZK_OK : ZK_ERR_UNSAT;
    ZkErr e;
    split_tamper = row[i].t;
    split_set(row[i].x, row[i].a, row[i].b);
    e = row[i].slice ? gslice(row[i].k) : gchunk(row[i].k);
    split_tamper = S_NONE;
    split_party = TDEC_PARTY;
    split_dealers = TDEC_DEALERS;
    memcpy(tdec_shares, bshares, sizeof bshares);
    memcpy(tdec_mask, bmask, sizeof bmask);
    memcpy(tdec_noise, bnoise, sizeof bnoise);
    printf("split %s: %s\n", row[i].what, zk_err_text(e));
    check(e == want, row[i].what);
  }
  printf("zktool split: %u rows, %d failed\n", (unsigned)n, fails);
  return fails != 0;
}

/* S7 U6 D62 (zktool circuit gtoss0 and gtoss1; no row yet): the toss of
 * tkeygen_toss_draw for parties 1 to 5 from a fixed DRBG, then
 * tkeygen_toss_check and tkeygen_toss_joint. gtoss0 is the commitment of party
 * 2; gtoss1 is J and K = H(12, [J, e], 9) for the epoch e = 3. */
static uint64_t gtoss_be64(const uint8_t *b) {
  uint64_t v = 0;
  uint32_t i;
  for (i = 0; i < 8; i++)
    v = v << 8 | b[i];
  return v;
}

static ZkErr gtoss(uint32_t form) {
  static const uint8_t dseed[TFHE_SEED_BYTES] = {0x67, 0x74, 0x6f, 0x73, 0x73};
  static TkeygenToss toss;
  static TfheDrbg d, masks;
  const uint32_t m = zk_gtoss_weights(form), ni = form == 0 ? 17 : 49, q = form == 0 ? 0 : 1, map = 0;
  const uint32_t party = 2, epoch = 3;
  uint8_t msg[TSHARE_PARTIES * TKEYGEN_SEED_BYTES], joint[SHA512_BYTES];
  uint64_t words[9];
  ZkFr input[49], out[1], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  Fr ref;
  uint32_t i, p;
  char what[32];
  if (m == 0) return ZK_ERR_COUNT;
  tfhe_drbg_init(&d, dseed);
  for (p = 1; p <= TSHARE_PARTIES; p++)
    if (!tkeygen_toss_draw(&toss, p, &d)) return ZK_ERR_COUNT;
  if (!tkeygen_toss_check(&toss) || !tkeygen_toss_joint(joint, &masks, &toss)) return ZK_ERR_COUNT;
  wt = calloc(m, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  out[0] = zk_fr_u64(0);
  if (form == 0) {
    for (i = 0; i < 4; i++)
      msg[i] = (uint8_t)(party >> (8 * i));
    memcpy(msg + 4, toss.seed[party - 1], TKEYGEN_SEED_BYTES);
    input[0] = zk_fr_u64(party);
    for (i = 0; i < 8; i++) {
      input[1 + i] = zk_fr_u64(gtoss_be64(toss.commit[party - 1] + 8 * i));
      input[9 + i] = zk_fr_u64(gtoss_be64(toss.seed[party - 1] + 8 * i));
    }
  } else {
    for (p = 0; p < TSHARE_PARTIES; p++)
      memcpy(msg + TKEYGEN_SEED_BYTES * p, toss.seed[p], TKEYGEN_SEED_BYTES);
    for (i = 0; i < 40; i++)
      input[i] = zk_fr_u64(gtoss_be64(msg + 8 * i));
    for (i = 0; i < 8; i++) {
      words[i] = gtoss_be64(joint + 8 * i);
      input[40 + i] = zk_fr_u64(words[i]);
    }
    words[8] = epoch;
    input[48] = zk_fr_u64(epoch);
    poseidon2_hash(ZK_K_TAG, words, 9, &ref);
    out[0] = p2_zk(&ref);
  }
  if (u6_tamper == U_TSEED && form == 0) { msg[4] ^= 1; input[9] = zk_fr_u64(gtoss_be64(msg + 4)); }
  zk_gtoss_fill(wt, form, msg);
  zk_init(&c, ni, m, q);
  zk_gtoss(&c, form);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = m;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = ni;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = q;
  w.output = out;
  if (u6_tamper == U_TCOMMIT && form == 0) input[1] = split_inc(&input[1]);
  if (u6_tamper == U_TPARTY && form == 0) input[0] = zk_fr_u64(party + 1);
  if (u6_tamper == U_TJWORD && form == 1) input[40] = split_inc(&input[40]);
  snprintf(what, sizeof what, "gtoss %u", (unsigned)form);
  e = timed_finish(what, &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U6 D63 (zktool circuit gdealn, gdealn2, gdealr, gdealz, gdealv16 and
 * gdealv64; no row yet): dealer 2 from a fixed DRBG, the S6b dealing
 * functions (tkeygen_noise with b = 45, tkeygen_deal of tshare_random
 * secrets, tkeygen_deal of zeros), the coefficients replayed from a copy of
 * the DRBG in the draw order of tkeygen_deal, K = H(12, [1 .. 9], 9), I = F
 * 2^40 + 3 2^20 (F 1 noise, 7 r, 8 zero), the salts from the DRBG. */
static void gdeal_limbs(ZkFr out[3], TshareFe a) {
  uint32_t i;
  for (i = 0; i < 3; i++)
    out[i] = zk_fr_u64(a.w[i]);
}

/* The first weight of c_1 of secret 0 in the gdeal witness: the secret
 * weights of zk.c (the noise: u, its range, q and x; r: x; zero: none). The
 * class dcoefq (D99) writes c_1 + 1 there after zk_gdeal_fill and keeps each
 * q, so only the share eq y_i + q_i p = x + sum_e c_e i^e sees it. */
static uint32_t gdeal_c1(uint32_t cls, uint32_t b) {
  const ZkFr bound = zk_fr_u64(1ull << b);
  return cls == ZK_GDEAL_NOISE ? 2 + zk_range_weights(&bound) + ZK_FP_WEIGHTS : cls == ZK_GDEAL_R ? ZK_FP_WEIGHTS : 0;
}

static ZkErr gdeal(uint32_t cls, uint32_t top, uint32_t m) {
  static const uint8_t dseed[TFHE_SEED_BYTES] = {0x67, 0x64, 0x65, 0x61, 0x6c};
  static TshareFe sec[ZK_GDEAL_MAX], sh[ZK_GDEAL_PARTIES * ZK_GDEAL_MAX];
  static ZkFr xl[3 * ZK_GDEAL_MAX], cl[3 * 4 * ZK_GDEAL_MAX], yl[3 * ZK_GDEAL_PARTIES * ZK_GDEAL_MAX];
  static ZkFr hx[5 + 3 * ZK_GDEAL_MAX];
  static int64_t ev[ZK_GDEAL_MAX];
  static uint64_t eu[ZK_GDEAL_MAX];
  static TfheDrbg d, r;
  const uint32_t b = deal_b, map = 0, fam = cls == ZK_GDEAL_NOISE ? 1 : cls == ZK_GDEAL_R ? 7 : 8;
  const uint32_t mw = zk_gdeal_weights(cls, top, m, b);
  const TkeygenDegree deg = top == 2 ? TKEYGEN_DEGREE_T : TKEYGEN_DEGREE_2T;
  uint64_t kw[9];
  ZkFr input[3], out[ZK_GDEAL_PARTIES], salt[ZK_GDEAL_PARTIES], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  Fr ref;
  uint32_t i, k, j;
  char what[32];
  if (mw == 0) return ZK_ERR_COUNT;
  tfhe_drbg_init(&d, dseed);
  for (i = 0; i < 9; i++)
    kw[i] = i + 1;
  poseidon2_hash(ZK_K_TAG, kw, 9, &ref);
  input[0] = p2_zk(&ref);
  input[1] = zk_fr_u64((uint64_t)fam << 40 | (uint64_t)3 << 20);
  input[2] = zk_fr_u64(2);
  for (k = 0; k < m; k++)
    sec[k] = cls == ZK_GDEAL_R ? tshare_random(&d) : tshare_from_u64(u6_tamper == U_DZERO);
  r = d;
  if (cls == ZK_GDEAL_NOISE && !deal_edge) tkeygen_noise(sh, eu, m, b, deg, &d);
  if (cls == ZK_GDEAL_NOISE && deal_edge) gdeal_edge(sh, eu, m, b, deg, &d);
  if (cls != ZK_GDEAL_NOISE) tkeygen_deal(sh, sec, m, u6_tamper == U_D2T ? TKEYGEN_DEGREE_2T : deg, &d);
  for (k = 0; k < m; k++) {
    if (cls == ZK_GDEAL_NOISE) {
      (void)tfhe_tuniform(&r, b - 1u);
      sec[k] = tkeygen_lift(eu[k]);
      ev[k] = (int64_t)eu[k];
    }
    for (j = 0; j < top; j++)
      gdeal_limbs(cl + 3 * (k * top + j), tshare_random(&r));
    gdeal_limbs(xl + 3 * k, sec[k]);
  }
  for (i = 0; i < ZK_GDEAL_PARTIES * m; i++)
    gdeal_limbs(yl + 3 * i, sh[i]);
  for (i = 0; i < ZK_GDEAL_PARTIES; i++) {
    salt[i] = zk_fr_u64(tfhe_uniform(&d));
    hx[0] = salt[i];
    hx[1] = input[0];
    hx[2] = input[1];
    hx[3] = input[2];
    hx[4] = zk_fr_u64(i + 1);
    memcpy(hx + 5, yl + 3 * i * m, 3 * m * sizeof hx[0]);
    out[i] = p2_fr(ZK_CD_TAG, hx, 5 + 3 * m);
  }
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  if (u6_tamper == U_DYI) yl[0] = split_inc(&yl[0]);
  if (u6_tamper == U_DCOEF) cl[0] = split_inc(&cl[0]);
  zk_gdeal_fill(wt, cls, top, m, b, xl, ev, cl, yl, salt);
  if (u6_tamper == U_DCOEFQ) {
    cl[0] = split_inc(&cl[0]);
    zk_fp_fill(wt + gdeal_c1(cls, b), cl);
  }
  zk_init(&c, 3, mw, ZK_GDEAL_PARTIES);
  zk_gdeal(&c, cls, top, m, b);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = 3;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = ZK_GDEAL_PARTIES;
  w.output = out;
  snprintf(what, sizeof what, "gdeal %u %u %u", (unsigned)cls, (unsigned)top, (unsigned)m);
  e = timed_finish(what, &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U6 D63 (zktool circuit gflood; no row yet): dealer 2 from a fixed DRBG,
 * tdec_flood (the S6 U3 producer), u and the coefficients replayed from a copy
 * of the DRBG in the draw order of tdec_flood, x the lift of e = u - 2^106,
 * Cn_(2,P) = H(8, [P, 2, y_P limbs], 5) native. */
static ZkErr gflood(void) {
  static const uint8_t dseed[TFHE_SEED_BYTES] = {0x67, 0x66, 0x6c, 0x6f, 0x6f, 0x64};
  const uint32_t map = 0, mw = zk_gflood_weights(), dealer = flood_dealer;
  const uint64_t top = 1ull << (TDEC_FLOOD_LOG - 64);
  TshareFe sh[TSHARE_PARTIES], m;
  TfheDrbg d, r, s;
  uint64_t u[2];
  ZkFr input[1], out[ZK_GDEAL_PARTIES], xl[3], cl[6], yl[15], hx[5], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  uint32_t i;
  tfhe_drbg_init(&d, dseed);
  r = d;
  if (flood_u == NULL) tdec_flood(sh, &d);
  u[0] = tfhe_uniform(&r);
  u[1] = tfhe_uniform(&r) & ((1ull << (TDEC_FLOOD_LOG + 1 - 64)) - 1u);
  s = r;
  if (flood_u != NULL) memcpy(u, flood_u, sizeof u);
  for (i = 0; i < 2; i++)
    gdeal_limbs(cl + 3 * i, tshare_random(&r));
  m.w[2] = 0;
  if (u[1] >= top) {
    m.w[0] = u[0];
    m.w[1] = u[1] - top;
  } else {
    m.w[0] = 0 - u[0];
    m.w[1] = top - u[1] - (u[0] != 0);
    m = tshare_sub(tshare_from_u64(0), m);
  }
  gdeal_limbs(xl, m);
  if (flood_u != NULL) tshare_share(sh, &m, 1, &s);
  if (u6_tamper == U_F2T) tkeygen_deal(sh, &m, 1, TKEYGEN_DEGREE_2T, &s);
  for (i = 0; i < ZK_GDEAL_PARTIES; i++) {
    gdeal_limbs(yl + 3 * i, sh[i]);
    hx[0] = zk_fr_u64(i + 1);
    hx[1] = zk_fr_u64(dealer);
    memcpy(hx + 2, yl + 3 * i, 3 * sizeof hx[0]);
    out[i] = p2_fr(ZK_CN_TAG, hx, 5);
  }
  input[0] = zk_fr_u64(dealer);
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  if (u6_tamper == U_FYI) yl[0] = split_inc(&yl[0]);
  if (u6_tamper == U_FCOEF) cl[0] = split_inc(&cl[0]);
  zk_gflood_fill(wt, u, xl, cl, yl);
  zk_init(&c, 1, mw, ZK_GDEAL_PARTIES);
  zk_gflood(&c);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = 1;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = ZK_GDEAL_PARTIES;
  w.output = out;
  e = timed_finish("gflood", &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U6 D66 (zktool circuits gword64 and gword128; no row yet): one secret
 * from a fixed DRBG shared at degree t (tshare_share), v = open_all of the 5
 * shares (the Lagrange constants 5, -10, 10, -5, 1; open_all is static in
 * tkeygen.c), v = the secret checked, the key word tkeygen_word64 (v) or
 * tkeygen_word128 (v) native. */
static ZkErr gword(uint32_t words) {
  static const uint8_t dseed[TFHE_SEED_BYTES] = {0x67, 0x77, 0x6f, 0x72, 0x64};
  static const int64_t lam[TSHARE_PARTIES] = {5, -10, 10, -5, 1};
  const uint32_t map = 0, mw = zk_gword_weights(words);
  TshareFe sh[TSHARE_PARTIES], sec, v;
  TfheDrbg d;
  Squash128 sq;
  ZkFr input[3 * ZK_GDEAL_PARTIES], out[2], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  uint32_t i;
  tfhe_drbg_init(&d, dseed);
  sec = tshare_random(&d);
  if (word_edge != NULL) sec = *word_edge;
  tshare_share(sh, &sec, 1, &d);
  v = tshare_from_u64(0);
  for (i = 0; i < TSHARE_PARTIES; i++) {
    v = tshare_add(v, tshare_mul(tshare_from_i64(lam[i]), sh[i]));
    gdeal_limbs(input + 3 * i, sh[i]);
  }
  if (!tshare_eq(v, sec)) return ZK_ERR_COUNT;
  sq = tkeygen_word128(v);
  out[0] = zk_fr_u64(words == 1 ? tkeygen_word64(v) : sq.lo);
  out[1] = zk_fr_u64(sq.hi);
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  zk_gword_fill(wt, words, input, v.w);
  zk_init(&c, 3 * ZK_GDEAL_PARTIES, mw, words);
  zk_gword(&c, words);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = 3 * ZK_GDEAL_PARTIES;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = words;
  w.output = out;
  if (u6_tamper == U_WSHARE) input[0] = split_inc(&input[0]);
  e = timed_finish(words == 1 ? "gword64" : "gword128", &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U6 D64 (zktool circuit gbit; no row yet): tkeygen_bit_try on 5 party
 * DRBGs (seed "gbit" and the party byte), tried again on a 0 (at most 64
 * tries), then replayed from a copy in the native order: the 5 r dealings
 * (degree t), then the 5 zero dealings (degree 2t, count 1). Party i = 3,
 * bit j = 5, K the gdeal stand-in H(12, [1 .. 9], 9). Native checks: r_i,
 * r_i^2 + z_i = o_i, the root c of the square and b_i = r_i w + 2^-1 with
 * w = (2c)^-1. The 11 salts come from a salt DRBG of its own ("gbs"). VID is the key-vector id of C7 (Q-S7-U6-4,
 * input 9): the bit index is 6 2^40 + j 2^20 + vid. */
static ZkErr gbit(uint64_t vid) {
  static const uint8_t sseed[TFHE_SEED_BYTES] = {0x67, 0x62, 0x73};
  const uint32_t map = 0, mw = zk_gbit_weights(), pi = 3;
  const uint64_t bj = 5;
  TfheDrbg party[TSHARE_PARTIES], replay[TSHARE_PARTIES], sd;
  TshareFe rd[TSHARE_PARTIES][TSHARE_PARTIES], zd[TSHARE_PARTIES][TSHARE_PARTIES], rv, nil, ri, zi, root, half, wv;
  TkeygenBit bt;
  Fr ref;
  uint64_t kw[9];
  ZkFr input[10], out[11], rs[15], zs[15], wl[3], bl[3], salt[11], hx[8], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  uint32_t i, d;
  int ok = 0;
  for (d = 0; d < TSHARE_PARTIES; d++) {
    uint8_t s[TFHE_SEED_BYTES] = {0x67, 0x62, 0x69, 0x74};
    s[4] = (uint8_t)(d + 1);
    tfhe_drbg_init(&party[d], s);
  }
  for (i = 0; i < 64 && !ok; i++) {
    memcpy(replay, party, sizeof replay);
    ok = tkeygen_bit_try(&bt, party);
  }
  if (!ok) return ZK_ERR_COUNT;
  nil = tshare_from_u64(0);
  for (d = 0; d < TSHARE_PARTIES; d++) {
    rv = tshare_random(&replay[d]);
    tkeygen_deal(rd[d], &rv, 1, TKEYGEN_DEGREE_T, &replay[d]);
  }
  for (d = 0; d < TSHARE_PARTIES; d++)
    tkeygen_deal(zd[d], &nil, 1, TKEYGEN_DEGREE_2T, &replay[d]);
  ri = nil;
  zi = nil;
  for (d = 0; d < TSHARE_PARTIES; d++) {
    ri = tshare_add(ri, rd[d][pi - 1]);
    zi = tshare_add(zi, zd[d][pi - 1]);
    gdeal_limbs(rs + 3 * d, rd[d][pi - 1]);
    gdeal_limbs(zs + 3 * d, zd[d][pi - 1]);
  }
  if (!tshare_eq(ri, bt.r[pi - 1])) return ZK_ERR_COUNT;
  if (!tshare_eq(tshare_add(tshare_mul(ri, ri), zi), bt.opened[pi - 1])) return ZK_ERR_COUNT;
  if (tshare_sqrt(&root, bt.square) != 1) return ZK_ERR_COUNT;
  half = tshare_inverse(tshare_from_u64(2));
  wv = tshare_mul(tshare_inverse(root), half);
  if (!tshare_eq(tshare_add(tshare_mul(ri, wv), half), bt.bit[pi - 1])) return ZK_ERR_COUNT;
  for (i = 0; i < 9; i++)
    kw[i] = i + 1;
  poseidon2_hash(ZK_K_TAG, kw, 9, &ref);
  input[0] = p2_zk(&ref);
  input[1] = zk_fr_u64(bj);
  input[2] = zk_fr_u64(pi);
  gdeal_limbs(wl, u6_tamper == U_BROOT ? tshare_sub(nil, wv) : wv);
  memcpy(input + 3, wl, sizeof wl);
  gdeal_limbs(input + 6, bt.opened[pi - 1]);
  input[9] = zk_fr_u64(vid);
  if (u6_tamper == U_BRI) rs[0] = split_inc(&rs[0]);
  if (u6_tamper == U_BZERO) zs[0] = split_inc(&zs[0]);
  gdeal_limbs(bl, u6_tamper == U_BBIT ? tshare_add(bt.bit[pi - 1], tshare_from_u64(1)) : bt.bit[pi - 1]);
  tfhe_drbg_init(&sd, sseed);
  for (i = 0; i < 11; i++)
    salt[i] = zk_fr_u64(tfhe_uniform(&sd));
  hx[1] = input[0];
  hx[4] = input[2];
  for (d = 0; d < TSHARE_PARTIES; d++) {
    hx[3] = zk_fr_u64(d + 1);
    hx[0] = salt[d];
    hx[2] = zk_fr_u64((uint64_t)7 << 40 | bj << 20);
    memcpy(hx + 5, rs + 3 * d, 3 * sizeof hx[0]);
    out[d] = p2_fr(ZK_CD_TAG, hx, 8);
    hx[0] = salt[TSHARE_PARTIES + d];
    hx[2] = zk_fr_u64((uint64_t)8 << 40 | bj << 20);
    memcpy(hx + 5, zs + 3 * d, 3 * sizeof hx[0]);
    out[TSHARE_PARTIES + d] = p2_fr(ZK_CD_TAG, hx, 8);
  }
  hx[0] = salt[10];
  hx[2] = zk_fr_u64((uint64_t)6 << 40 | bj << 20 | vid);
  hx[3] = input[2];
  memcpy(hx + 4, bl, sizeof bl);
  out[10] = p2_fr(ZK_CB_TAG, hx, 7);
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  zk_gbit_fill(wt, rs, zs, wl, salt);
  zk_init(&c, 10, mw, 11);
  zk_gbit(&c);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = 10;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = 11;
  w.output = out;
  if (u6_tamper == U_BC) input[3] = split_inc(&input[3]);
  if (u6_tamper == U_BVID) input[9] = zk_fr_u64(vid + 1);
  e = timed_finish("gbit", &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* The low 64 bits of F (ZkFr limbs are 32 bits, low limb first). */
static uint64_t gopen_u64(const ZkFr *f) {
  return (uint64_t)f->limb[0] | (uint64_t)f->limb[1] << 32;
}

/* The D71 boundary rows of keygen_rows: the KSK level of gopen (gopen_lv) and,
 * when set, the coefficient C of gopen_glwe and gopen_sq (gopen_c). */
static uint32_t gopen_lv = 2;
static const uint32_t *gopen_c;

/* S7 U6 D65 (zktool circuit gopenksk, gopencast and gopenkskk): one KSK or
 * cast KSK row (j = 7, l = gopen_lv, 2) by one tkeygen_lwe_row with n 918. The 918 lwe
 * key shares and the x share (one glwe or pke bit, 1) by tshare_share of
 * bits from a key DRBG ("gok"), not tkeygen_bits. The masks DRBG ("gopn", 0)
 * and the 5 party DRBGs ("gopn", d) are copied first and replayed in the
 * native order: the 918 mask words, then the noise of dealers 1 .. 5
 * (degree t, set_log 45). Party i = 3. Native checks: each replayed mask word
 * equals ct[k]; the Lagrange sum (5, -10, 10, -5, 1) of the 5 replayed share
 * values, then tkeygen_word64, equals ct[918]. K the gdeal stand-in H(12,
 * [1 .. 9], 9); the salts come from a salt DRBG of its own ("gos"). */
static ZkErr gopen(uint32_t fam, uint32_t keys) {
  static const uint8_t kseed[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x6b}, sseed[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x73};
  static const uint64_t lag[TSHARE_PARTIES] = {5, 10, 10, 5, 1};
  static const char *const names[2][2] = {{"gopenksk", "gopenkskk"}, {"gopencast", "gopencastk"}};
  static TshareFe key[TSHARE_PARTIES * TFHE_LWE_N], bit[TFHE_LWE_N];
  static uint64_t ct[TFHE_LWE_N + 1], sl[3 * TFHE_LWE_N];
  static ZkFr input[6 + TFHE_LWE_N], out[TSHARE_PARTIES + TFHE_LWE_N + 1], salt[TSHARE_PARTIES + TFHE_LWE_N + 1];
  const uint32_t map = 0, l = gopen_lv, pi = 3, mw = zk_gopen_weights(fam, l, keys);
  const uint32_t nin = 6 + TFHE_LWE_N, nout = TSHARE_PARTIES + keys * (TFHE_LWE_N + 1);
  const uint64_t bj = 7;
  uint8_t ms[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x70, 0x6e};
  TfheDrbg kd, masks, party[TSHARE_PARTIES], mcopy, pcopy[TSHARE_PARTIES], sd;
  TshareFe xs[TSHARE_PARTIES], plain[TSHARE_PARTIES], sh[TSHARE_PARTIES], deal[TSHARE_PARTIES], xb, a, g, open;
  Fr ref;
  uint64_t kw[9], xl[3], nz[15], vl[3], esum, en, ix;
  ZkFr lb[3], hx[8], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  uint32_t i, d, k;
  if (mw == 0) return ZK_ERR_COUNT;
  tfhe_drbg_init(&kd, kseed);
  for (k = 0; k < TFHE_LWE_N; k++)
    bit[k] = tshare_from_u64(tfhe_uniform(&kd) & 1u);
  tshare_share(key, bit, TFHE_LWE_N, &kd);
  xb = tshare_from_u64(1);
  tshare_share(xs, &xb, 1, &kd);
  g = tshare_from_u64((uint64_t)1 << (64 - 4 * l));
  for (i = 0; i < TSHARE_PARTIES; i++)
    plain[i] = tshare_mul(g, xs[i]);
  tfhe_drbg_init(&masks, ms);
  for (d = 0; d < TSHARE_PARTIES; d++) {
    ms[4] = (uint8_t)(d + 1);
    tfhe_drbg_init(&party[d], ms);
  }
  mcopy = masks;
  memcpy(pcopy, party, sizeof pcopy);
  tkeygen_lwe_row(ct, &esum, key, TFHE_LWE_N, plain, TFHE_LWE_NOISE, &masks, party);
  memcpy(sh, plain, sizeof sh);
  for (k = 0; k < TFHE_LWE_N; k++) {
    if (tfhe_uniform(&mcopy) != ct[k]) return ZK_ERR_COUNT;
    a = tshare_from_u64(ct[k]);
    for (i = 0; i < TSHARE_PARTIES; i++)
      sh[i] = tshare_add(sh[i], tshare_mul(a, key[i * TFHE_LWE_N + k]));
  }
  for (d = 0; d < TSHARE_PARTIES; d++) {
    tkeygen_noise(deal, &en, 1, TFHE_LWE_NOISE, TKEYGEN_DEGREE_T, &pcopy[d]);
    gdeal_limbs(lb, deal[pi - 1]);
    for (k = 0; k < 3; k++)
      nz[3 * d + k] = gopen_u64(&lb[k]);
    for (i = 0; i < TSHARE_PARTIES; i++)
      sh[i] = tshare_add(sh[i], deal[i]);
  }
  open = tshare_from_u64(0);
  for (i = 0; i < TSHARE_PARTIES; i++)
    open = i % 2 == 0 ? tshare_add(open, tshare_mul(tshare_from_u64(lag[i]), sh[i]))
                      : tshare_sub(open, tshare_mul(tshare_from_u64(lag[i]), sh[i]));
  if (tkeygen_word64(open) != ct[TFHE_LWE_N]) return ZK_ERR_COUNT;
  for (k = 0; k < TFHE_LWE_N; k++) {
    gdeal_limbs(lb, key[(pi - 1) * TFHE_LWE_N + k]);
    for (d = 0; d < 3; d++)
      sl[3 * k + d] = gopen_u64(&lb[d]);
  }
  gdeal_limbs(lb, xs[pi - 1]);
  for (k = 0; k < 3; k++)
    xl[k] = gopen_u64(&lb[k]);
  gdeal_limbs(input + 3, sh[pi - 1]);
  for (k = 0; k < 3; k++)
    vl[k] = gopen_u64(&input[3 + k]);
  for (i = 0; i < 9; i++)
    kw[i] = i + 1;
  poseidon2_hash(ZK_K_TAG, kw, 9, &ref);
  input[0] = p2_zk(&ref);
  input[1] = zk_fr_u64(bj);
  input[2] = zk_fr_u64(pi);
  for (k = 0; k < TFHE_LWE_N; k++)
    input[6 + k] = zk_fr_u64(ct[k]);
  tfhe_drbg_init(&sd, sseed);
  for (k = 0; k < nout; k++)
    salt[k] = zk_fr_u64(tfhe_uniform(&sd));
  ix = ((fam == ZK_GOPEN_KSK ? (uint64_t)1 : (uint64_t)4) << 40) + ((uint64_t)(l - 1) << 20) + (bj << 22);
  hx[1] = input[0];
  hx[2] = zk_fr_u64(ix);
  hx[4] = input[2];
  for (d = 0; d < TSHARE_PARTIES; d++) {
    hx[0] = salt[d];
    hx[3] = zk_fr_u64(d + 1);
    for (k = 0; k < 3; k++)
      hx[5 + k] = zk_fr_u64(nz[3 * d + k]);
    out[d] = p2_fr(ZK_CD_TAG, hx, 8);
  }
  hx[3] = input[2];
  for (k = 0; k < keys * (TFHE_LWE_N + 1); k++) {
    hx[0] = salt[TSHARE_PARTIES + k];
    hx[2] = zk_fr_u64(k < TFHE_LWE_N ? (uint64_t)6 << 40 | (uint64_t)k << 20
                                     : (uint64_t)6 << 40 | bj << 20 | (fam == ZK_GOPEN_KSK ? 1u : 2u));
    for (d = 0; d < 3; d++)
      hx[4 + d] = zk_fr_u64(k < TFHE_LWE_N ? sl[3 * k + d] : xl[d]);
    out[TSHARE_PARTIES + k] = p2_fr(ZK_CB_TAG, hx, 7);
  }
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  if (u6_tamper == U_OKEY && keys == 1) sl[0] += 1;
  zk_gopen_fill(wt, fam, u6_tamper == U_OLEVEL ? l % 4 + 1 : l, keys, ct, sl, xl, nz, vl, salt);
  zk_init(&c, nin, mw, nout);
  zk_gopen(&c, fam, l, keys);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = nin;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = nout;
  w.output = out;
  if (u6_tamper == U_OMASK) input[6] = split_inc(&input[6]);
  if (u6_tamper == U_OSHARE) input[3] = split_inc(&input[3]);
  if (u6_tamper == U_OCARRY)
  { const uint32_t wc = 3 * ZK_GOPEN_N + 3 + 3 * ZK_TDEC_PARTIES + ZK_FP_WEIGHTS + ZK_TDEC_Q_BITS + ZK_TDEC_CARRY_BITS - 1; wt[wc] = split_inc(&wt[wc]); wt[wc] = split_inc(&wt[wc]); }
  e = timed_finish(names[fam][keys], &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U6 D65 (zktool circuit gopenbsk0, gopenbsk1 and gopenpk, RESUME13): one
 * coefficient C of one GLWE row by the native tkeygen_bsk_ggsw (GGSW g = 7;
 * row 0 at C = 1029, row 1 at C = 0) or tkeygen_pk (g 0, C = 1029). The lwe,
 * glwe and pke key shares by tshare_share of bits from a key DRBG ("gokg").
 * The masks DRBG ("gopn", 0) and the 5 party DRBGs ("gopn", d) are copied
 * first and replayed in the native order: row 0 (2048 mask words, then the
 * noise of dealers 1 .. 5, degree 2t), then row 1 (degree t); pk one row,
 * degree t. Party i = 3. Native checks: each replayed mask word equals the ct
 * word; the Lagrange sum (5, -10, 10, -5, 1) of the 5 replayed shares at C,
 * then tkeygen_word64, equals body word C; share_i + W = U. K the gdeal
 * stand-in H(12, [1 .. 9], 9); the salts from a salt DRBG ("gos"). */
static ZkErr gopen_glwe(uint32_t fam) {
  static const uint8_t kseed[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x6b, 0x67}, sseed[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x73};
  static const uint64_t lag[TSHARE_PARTIES] = {5, 10, 10, 5, 1};
  static const char *const names[3] = {"gopenbsk0", "gopenbsk1", "gopenpk"};
  static TkeygenShares ks;
  static TshareFe bits[TFHE_BIG_N], deal[TSHARE_PARTIES * TSHARE_N], key[TSHARE_PARTIES * TSHARE_N];
  static uint64_t ct[4 * TFHE_POLY_N], en[TSHARE_N], sl[3 * TSHARE_N];
  static TfhePke pk;
  static ZkFr input[6 + TSHARE_N], out[TSHARE_PARTIES], salt[TSHARE_PARTIES];
  const uint32_t map = 0, pi = 3, row = fam == ZK_GOPEN_BSK1, rows = fam == ZK_GOPEN_PK ? 1 : row + 1;
  const uint32_t cc = gopen_c != NULL ? *gopen_c : fam == ZK_GOPEN_BSK1 ? 0 : 1029, mw = zk_gopen_weights(fam, cc, 0);
  const uint32_t nin = 6 + TSHARE_N, nout = TSHARE_PARTIES;
  const uint64_t bg = fam == ZK_GOPEN_PK ? 0 : 7;
  const TshareFe nil = tshare_from_u64(0), g41 = tshare_from_u64((uint64_t)1 << 41);
  uint8_t ms[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x70, 0x6e};
  TfheDrbg kd, masks, party[TSHARE_PARTIES], mcopy, pcopy[TSHARE_PARTIES], sd;
  TkeygenWork *tw;
  TshareFe pos[TSHARE_PARTIES], neg[TSHARE_PARTIES], nsum[TSHARE_PARTIES], sh[TSHARE_PARTIES], plain, a, r, u, wv, open;
  const uint64_t *mask, *body;
  Fr ref;
  uint64_t kw[9], xl[3], nz[15], vl[12], ix;
  ZkFr hx[8], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  uint32_t i, d, k, t, q;
  if (mw == 0) return ZK_ERR_COUNT;
  tw = calloc(1, sizeof *tw);
  if (tw == NULL) return ZK_ERR_COUNT;
  tkeygen_work_init(tw);
  tfhe_drbg_init(&kd, kseed);
  for (k = 0; k < TFHE_LWE_N; k++)
    bits[k] = tshare_from_u64(tfhe_uniform(&kd) & 1u);
  tshare_share(&ks.lwe[0][0], bits, TFHE_LWE_N, &kd);
  for (k = 0; k < TFHE_POLY_N; k++)
    bits[k] = tshare_from_u64(tfhe_uniform(&kd) & 1u);
  tshare_share(&ks.glwe[0][0], bits, TFHE_POLY_N, &kd);
  for (k = 0; k < TFHE_BIG_N; k++)
    bits[k] = tshare_from_u64(tfhe_uniform(&kd) & 1u);
  tshare_share(&ks.pke[0][0], bits, TFHE_BIG_N, &kd);
  /* The key of the row: the glwe shares (BSK) or the reversed pke shares (pk). */
  for (i = 0; i < TSHARE_PARTIES; i++)
    for (k = 0; k < TSHARE_N; k++)
      key[i * TSHARE_N + k] = fam == ZK_GOPEN_PK ? ks.pke[i][TFHE_BIG_N - 1 - k] : ks.glwe[i][k];
  tfhe_drbg_init(&masks, ms);
  for (d = 0; d < TSHARE_PARTIES; d++) {
    ms[4] = (uint8_t)(d + 1);
    tfhe_drbg_init(&party[d], ms);
  }
  mcopy = masks;
  memcpy(pcopy, party, sizeof pcopy);
  if (fam == ZK_GOPEN_PK) {
    tkeygen_load(tw, &ks, TKEYGEN_KEY_PKE);
    tkeygen_pk(tw, &pk, &masks, party);
    mask = pk.pk_a;
    body = pk.pk_b;
  } else {
    tkeygen_load(tw, &ks, TKEYGEN_KEY_GLWE);
    tkeygen_bsk_ggsw(tw, ct, bg, &ks, &masks, party);
    mask = ct + 2 * TFHE_POLY_N * row;
    body = mask + TFHE_POLY_N;
  }
  free(tw);
  for (q = 0; q < rows; q++)
    for (t = 0; t < TSHARE_N; t++)
      if (tfhe_uniform(&mcopy) != (fam == ZK_GOPEN_PK ? pk.pk_a[t] : ct[2 * TFHE_POLY_N * q + t])) return ZK_ERR_COUNT;
  for (i = 0; i < TSHARE_PARTIES; i++)
    nsum[i] = nil;
  for (d = 0; d < TSHARE_PARTIES; d++) {
    for (q = 0; q < rows; q++)
      tkeygen_noise(deal, en, TSHARE_N, fam == ZK_GOPEN_PK ? TFHE_PKE_NOISE : TFHE_GLWE_NOISE,
                    fam == ZK_GOPEN_PK || q == 1 ? TKEYGEN_DEGREE_T : TKEYGEN_DEGREE_2T, &pcopy[d]);
    for (k = 0; k < 3; k++)
      nz[3 * d + k] = deal[(pi - 1) * TSHARE_N + cc].w[k];
    for (i = 0; i < TSHARE_PARTIES; i++)
      nsum[i] = tshare_add(nsum[i], deal[i * TSHARE_N + cc]);
  }
  /* share[C] = plain[C] + sum_(t <= C) a_t K[C - t] - sum_(t > C) a_t K[C - t + N] + noise. */
  for (i = 0; i < TSHARE_PARTIES; i++) {
    pos[i] = nil;
    neg[i] = nil;
    for (t = 0; t < TSHARE_N; t++) {
      a = tshare_mul(tshare_from_u64(mask[t]), key[i * TSHARE_N + (cc + TSHARE_N - t) % TSHARE_N]);
      if (t <= cc)
        pos[i] = tshare_add(pos[i], a);
      else
        neg[i] = tshare_add(neg[i], a);
    }
    plain = fam == ZK_GOPEN_BSK0                ? tshare_sub(nil, tshare_mul(tshare_mul(g41, ks.lwe[i][bg]), ks.glwe[i][cc]))
            : fam == ZK_GOPEN_BSK1 && cc == 0 ? tshare_mul(g41, ks.lwe[i][bg])
                                              : nil;
    sh[i] = tshare_add(tshare_sub(tshare_add(plain, pos[i]), neg[i]), nsum[i]);
  }
  open = nil;
  for (i = 0; i < TSHARE_PARTIES; i++)
    open = i % 2 == 0 ? tshare_add(open, tshare_mul(tshare_from_u64(lag[i]), sh[i]))
                      : tshare_sub(open, tshare_mul(tshare_from_u64(lag[i]), sh[i]));
  if (tkeygen_word64(open) != body[cc]) return ZK_ERR_COUNT;
  /* U = the terms t <= C, the noise and 2^41 x (row 1, C = 0); W = the terms t > C and 2^41 r (row 0). */
  r = tshare_mul(ks.lwe[pi - 1][bg], ks.glwe[pi - 1][cc]);
  u = tshare_add(pos[pi - 1], nsum[pi - 1]);
  if (fam == ZK_GOPEN_BSK1 && cc == 0) u = tshare_add(u, tshare_mul(g41, ks.lwe[pi - 1][bg]));
  wv = fam == ZK_GOPEN_BSK0 ? tshare_add(neg[pi - 1], tshare_mul(g41, r)) : neg[pi - 1];
  if (u6_tamper == U_OSIGN0 && cc == 0) { a = tshare_mul(tshare_from_u64(mask[1]), key[(pi - 1) * TSHARE_N + TSHARE_N - 1]); u = tshare_add(u, a); wv = tshare_sub(wv, a); sh[pi - 1] = tshare_add(sh[pi - 1], tshare_add(a, a)); }
  open = tshare_add(sh[pi - 1], wv);
  if (memcmp(open.w, u.w, sizeof u.w) != 0) return ZK_ERR_COUNT;
  for (k = 0; k < TSHARE_N; k++)
    for (d = 0; d < 3; d++)
      sl[3 * k + d] = key[(pi - 1) * TSHARE_N + k].w[d];
  for (k = 0; k < 3; k++) {
    xl[k] = ks.lwe[pi - 1][bg].w[k];
    vl[k] = sh[pi - 1].w[k];
    vl[3 + k] = u.w[k];
    vl[6 + k] = wv.w[k];
    vl[9 + k] = r.w[k];
    input[3 + k] = zk_fr_u64(vl[k]);
  }
  for (i = 0; i < 9; i++)
    kw[i] = i + 1;
  poseidon2_hash(ZK_K_TAG, kw, 9, &ref);
  input[0] = p2_zk(&ref);
  input[1] = zk_fr_u64(bg);
  input[2] = zk_fr_u64(pi);
  for (k = 0; k < TSHARE_N; k++)
    input[6 + k] = zk_fr_u64(mask[k]);
  tfhe_drbg_init(&sd, sseed);
  for (k = 0; k < nout; k++)
    salt[k] = zk_fr_u64(tfhe_uniform(&sd));
  ix = ((fam == ZK_GOPEN_PK ? (uint64_t)3 : (uint64_t)2) << 40) + ((2 * bg + row) << 20) + cc;
  hx[1] = input[0];
  hx[2] = zk_fr_u64(ix);
  hx[4] = input[2];
  for (d = 0; d < TSHARE_PARTIES; d++) {
    hx[0] = salt[d];
    hx[3] = zk_fr_u64(d + 1);
    for (k = 0; k < 3; k++)
      hx[5 + k] = zk_fr_u64(nz[3 * d + k]);
    out[d] = p2_fr(ZK_CD_TAG, hx, 8);
  }
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  zk_gopen_fill(wt, fam, cc, 0, mask, sl, xl, nz, vl, salt);
  zk_init(&c, nin, mw, nout);
  zk_gopen(&c, fam, cc, 0);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = nin;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = nout;
  w.output = out;
  e = timed_finish(names[fam - ZK_GOPEN_BSK0], &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* S7 U6 D65 (zktool circuit gopensq0, gopensq1 and gopensq2, RESUME14): one
 * coefficient C of one squash GGSW row by the native tkeygen_squash_row (GGSW
 * g = 7; row 0 level 1 and row 1 level 2 at C = 1029, row 2 level 3 at C = 0).
 * The lwe and squash key shares by tshare_share of bits from a key DRBG
 * ("goks"). The masks DRBG ("gosq", 0) and the 5 party DRBGs ("gosq", d) are
 * copied first and replayed: 2 x 2048 squash_uniform words, then the noise of
 * dealers 1 .. 5 (SQUASH_NOISE, degree 2t for rows 0 and 1, t for row 2).
 * Party i = 3. Native checks: each replayed mask word equals the ct word; the
 * Lagrange sum (5, -10, 10, -5, 1) of the 5 replayed shares at C, then
 * tkeygen_word128, equals body word C; share_i + W = U. K the gdeal stand-in
 * H(12, [1 .. 9], 9); the salts from a salt DRBG ("gos"). */
static ZkErr gopen_sq(uint32_t row) {
  static const uint8_t kseed[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x6b, 0x73}, sseed[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x73};
  static const uint64_t lag[TSHARE_PARTIES] = {5, 10, 10, 5, 1};
  static const char *const names[3] = {"gopensq0", "gopensq1", "gopensq2"};
  static TkeygenShares ks;
  static TshareFe bits[SQUASH_BIG_N], deal[TSHARE_PARTIES * TSHARE_N];
  static Squash128 ct[(SQUASH_GLWE_K + 1) * SQUASH_POLY_N];
  static uint64_t en[TSHARE_N], sl[3 * SQUASH_BIG_N], am[2 * SQUASH_BIG_N];
  static ZkFr input[6 + 2 * SQUASH_BIG_N], out[TSHARE_PARTIES], salt[TSHARE_PARTIES];
  const uint32_t map = 0, pi = 3, fam = ZK_GOPEN_SQ0 + row, level = row + 1, cc = gopen_c != NULL ? *gopen_c : row == 2 ? 0 : 1029;
  const uint32_t l = (level - 1) * ZK_GOPEN_GN + cc, mw = zk_gopen_weights(fam, l, 0);
  const uint32_t nin = 6 + 2 * SQUASH_BIG_N, nout = TSHARE_PARTIES, ge = 128 - 24 * level;
  const uint64_t bg = 7;
  const TshareFe nil = tshare_from_u64(0);
  uint8_t ms[TFHE_SEED_BYTES] = {0x67, 0x6f, 0x73, 0x71};
  TfheDrbg kd, masks, party[TSHARE_PARTIES], mcopy, pcopy[TSHARE_PARTIES], sd;
  TkeygenWork *tw;
  TshareFe pos[TSHARE_PARTIES], neg[TSHARE_PARTIES], nsum[TSHARE_PARTIES], sh[TSHARE_PARTIES], gg, plain, a, r, u, wv, open;
  Squash128 sw;
  Fr ref;
  uint64_t kw[9], xl[3], nz[15], vl[12], ix;
  ZkFr hx[8], *wt;
  ZkMatrix mat;
  ZkWitness w;
  ZkCircuit c;
  ZkErr e;
  uint32_t i, d, k, t, p;
  if (mw == 0) return ZK_ERR_COUNT;
  tw = calloc(1, sizeof *tw);
  if (tw == NULL) return ZK_ERR_COUNT;
  tkeygen_work_init(tw);
  tfhe_drbg_init(&kd, kseed);
  for (k = 0; k < TFHE_LWE_N; k++)
    bits[k] = tshare_from_u64(tfhe_uniform(&kd) & 1u);
  tshare_share(&ks.lwe[0][0], bits, TFHE_LWE_N, &kd);
  for (k = 0; k < SQUASH_BIG_N; k++)
    bits[k] = tshare_from_u64(tfhe_uniform(&kd) & 1u);
  tshare_share(&ks.squash[0][0], bits, SQUASH_BIG_N, &kd);
  tfhe_drbg_init(&masks, ms);
  for (d = 0; d < TSHARE_PARTIES; d++) {
    ms[4] = (uint8_t)(d + 1);
    tfhe_drbg_init(&party[d], ms);
  }
  mcopy = masks;
  memcpy(pcopy, party, sizeof pcopy);
  tkeygen_load(tw, &ks, TKEYGEN_KEY_SQUASH);
  tkeygen_squash_row(tw, ct, bg, level, row, &ks, &masks, party);
  free(tw);
  for (k = 0; k < SQUASH_BIG_N; k++) {
    sw = squash_uniform(&mcopy);
    if (sw.lo != ct[k].lo || sw.hi != ct[k].hi) return ZK_ERR_COUNT;
    am[2 * k] = sw.lo;
    am[2 * k + 1] = sw.hi;
  }
  for (i = 0; i < TSHARE_PARTIES; i++)
    nsum[i] = nil;
  for (d = 0; d < TSHARE_PARTIES; d++) {
    tkeygen_noise(deal, en, TSHARE_N, SQUASH_NOISE, row == 2 ? TKEYGEN_DEGREE_T : TKEYGEN_DEGREE_2T, &pcopy[d]);
    for (k = 0; k < 3; k++)
      nz[3 * d + k] = deal[(pi - 1) * TSHARE_N + cc].w[k];
    for (i = 0; i < TSHARE_PARTIES; i++)
      nsum[i] = tshare_add(nsum[i], deal[i * TSHARE_N + cc]);
  }
  /* share[C] = plain[C] + sum_k (sum_(t <= C) a_(k,t) S_k[C - t] - sum_(t > C) a_(k,t) S_k[C - t + N]) + noise;
   * plain = -(g x S_row[C]) (rows 0 and 1) or g x at C = 0 (row 2), g = 2^(128 - 24 level). */
  gg = nil;
  gg.w[ge / 64] = (uint64_t)1 << (ge % 64);
  for (i = 0; i < TSHARE_PARTIES; i++) {
    pos[i] = nil;
    neg[i] = nil;
    for (p = 0; p < SQUASH_GLWE_K; p++)
      for (t = 0; t < TSHARE_N; t++) {
        a = tshare_from_u64(am[2 * (p * TSHARE_N + t)]);
        a.w[1] = am[2 * (p * TSHARE_N + t) + 1];
        a = tshare_mul(a, ks.squash[i][p * TSHARE_N + (cc + TSHARE_N - t) % TSHARE_N]);
        if (t <= cc)
          pos[i] = tshare_add(pos[i], a);
        else
          neg[i] = tshare_add(neg[i], a);
      }
    plain = row < 2     ? tshare_sub(nil, tshare_mul(tshare_mul(gg, ks.lwe[i][bg]), ks.squash[i][row * TSHARE_N + cc]))
            : cc == 0 ? tshare_mul(gg, ks.lwe[i][bg])
                      : nil;
    sh[i] = tshare_add(tshare_sub(tshare_add(plain, pos[i]), neg[i]), nsum[i]);
  }
  open = nil;
  for (i = 0; i < TSHARE_PARTIES; i++)
    open = i % 2 == 0 ? tshare_add(open, tshare_mul(tshare_from_u64(lag[i]), sh[i]))
                      : tshare_sub(open, tshare_mul(tshare_from_u64(lag[i]), sh[i]));
  sw = tkeygen_word128(open);
  if (sw.lo != ct[SQUASH_GLWE_K * SQUASH_POLY_N + cc].lo || sw.hi != ct[SQUASH_GLWE_K * SQUASH_POLY_N + cc].hi)
    return ZK_ERR_COUNT;
  /* U = the terms t <= C, the noise and g x (row 2, C = 0); W = the terms t > C and g r (rows 0 and 1). */
  r = tshare_mul(ks.lwe[pi - 1][bg], ks.squash[pi - 1][(row < 2 ? row : 0) * TSHARE_N + cc]);
  u = tshare_add(pos[pi - 1], nsum[pi - 1]);
  if (row == 2 && cc == 0) u = tshare_add(u, tshare_mul(gg, ks.lwe[pi - 1][bg]));
  wv = row < 2 ? tshare_add(neg[pi - 1], tshare_mul(gg, r)) : neg[pi - 1];
  if (u6_tamper == U_OSIGN1 && cc == ZK_GOPEN_GN - 1) { a = tshare_from_u64(am[2 * cc]); a.w[1] = am[2 * cc + 1]; a = tshare_mul(a, ks.squash[pi - 1][0]); u = tshare_sub(u, a); wv = tshare_add(wv, a); sh[pi - 1] = tshare_sub(sh[pi - 1], tshare_add(a, a)); }
  open = tshare_add(sh[pi - 1], wv);
  if (memcmp(open.w, u.w, sizeof u.w) != 0) return ZK_ERR_COUNT;
  for (k = 0; k < SQUASH_BIG_N; k++)
    for (d = 0; d < 3; d++)
      sl[3 * k + d] = ks.squash[pi - 1][k].w[d];
  for (k = 0; k < 3; k++) {
    xl[k] = ks.lwe[pi - 1][bg].w[k];
    vl[k] = sh[pi - 1].w[k];
    vl[3 + k] = u.w[k];
    vl[6 + k] = wv.w[k];
    vl[9 + k] = r.w[k];
    input[3 + k] = zk_fr_u64(vl[k]);
  }
  for (i = 0; i < 9; i++)
    kw[i] = i + 1;
  poseidon2_hash(ZK_K_TAG, kw, 9, &ref);
  input[0] = p2_zk(&ref);
  input[1] = zk_fr_u64(bg);
  input[2] = zk_fr_u64(pi);
  for (k = 0; k < 2 * SQUASH_BIG_N; k++)
    input[6 + k] = zk_fr_u64(am[k]);
  tfhe_drbg_init(&sd, sseed);
  for (k = 0; k < nout; k++)
    salt[k] = zk_fr_u64(tfhe_uniform(&sd));
  ix = ((uint64_t)5 << 40) + ((16 * bg + 4 * (level - 1) + row) << 20) + cc;
  hx[1] = input[0];
  hx[2] = zk_fr_u64(ix);
  hx[4] = input[2];
  for (d = 0; d < TSHARE_PARTIES; d++) {
    hx[0] = salt[d];
    hx[3] = zk_fr_u64(d + 1);
    for (k = 0; k < 3; k++)
      hx[5 + k] = zk_fr_u64(nz[3 * d + k]);
    out[d] = p2_fr(ZK_CD_TAG, hx, 8);
  }
  wt = calloc(mw, sizeof *wt);
  if (wt == NULL) return ZK_ERR_COUNT;
  if (u6_tamper == U_ONOISE) nz[0] += 1;
  zk_gopen_fill(wt, fam, l, 0, am, sl, xl, nz, vl, salt);
  zk_init(&c, nin, mw, nout);
  zk_gopen(&c, fam, l, 0);
  memset(&mat, 0, sizeof mat);
  mat.rows = 1;
  mat.cols = mw;
  mat.entry = wt;
  memset(&w, 0, sizeof w);
  w.inputs = nin;
  w.input = input;
  w.matrices = 1;
  w.matrix = &mat;
  w.maps = 1;
  w.map = &map;
  w.outputs = nout;
  w.output = out;
  e = timed_finish(names[row], &c, &w);
  zk_free(&c);
  free(wt);
  return e;
}

/* zktool case NAME ARG (S7 U5, ruling Q-S7-U5-6): one gchunk or gslice case
 * of the split for the Rust rows, printed as zktool case prints (D31), also
 * when zk_check refuses (timed_finish). NAME is gchunkK (K 0 to 256) or
 * gsliceJ (J 0 to 15). ARG is none (the honest case), a SplitTamper name in
 * lower case (party to chain, the tamper as split_rows sets it) or party0 /
 * party6 (a party refused by the party polynomial). A tamper that does not
 * apply to the shape leaves the case honest. A bad NAME or ARG exits 2. */
static const char *const split_names[] = {
    "none", "party", "index", "cs", "cs_last", "ch_in", "ch_out", "dg", "sigma", "rho", "byte", "pbyte",
    "neighbour", "ca_in", "ca_out", "salt_in", "salt_out", "acc", "mask_lo", "mask_hi", "v", "vp", "vpw",
    "cn", "noise", "b", "b2", "b4", "q", "carry", "moved", "chain"};

/* The index of NAME after the prefix P (decimal, no sign, no leading zero, at
 * most MAX), or -1. */
static long split_index(const char *name, const char *p, unsigned long max) {
  const size_t n = strlen(p);
  char *end;
  unsigned long v;
  if (strncmp(name, p, n) != 0 || name[n] < '0' || name[n] > '9' || (name[n] == '0' && name[n + 1] != '\0'))
    return -1;
  v = strtoul(name + n, &end, 10);
  return *end == '\0' && v <= max ? (long)v : -1;
}

/* S7 U6 STEP 2b (D71 agree rows, the D85 shapes): one honest row of each
 * family at the real dimensions, the witness from the S6b values of each
 * fixture; zk_check must accept each. The cheap rows (toss form 0, deal,
 * flood, word, bit) are here; gtoss 1 and every gopen row are in zktool
 * keygen (check-lig, the warm budget); gdealv16 and gdealv64 are measures
 * only (D85). */
static void rows_u6(void) {
  static const uint32_t deal[4][2] = {{ZK_GDEAL_NOISE, 2}, {ZK_GDEAL_NOISE, 4}, {ZK_GDEAL_R, 2}, {ZK_GDEAL_ZERO, 4}};
  static const uint32_t bs[3] = {17, 30, 45}, party[4] = {1, 5, 0, 6};
  static const uint64_t flood[2][2] = {{0, 0}, {UINT64_MAX, (1ull << (TDEC_FLOOD_LOG + 1 - 64)) - 1u}};
  /* (p - 1)/2, (p + 1)/2, 2^64, 2^128 and p - 1, low word first. */
  static const TshareFe word[5] = {{{0xfffffffffff67000ull, UINT64_MAX, 0x7fffffffffffffffull}},
                                   {{0xfffffffffff67001ull, UINT64_MAX, 0x7fffffffffffffffull}},
                                   {{0, 1, 0}},
                                   {{0, 0, 1}},
                                   {{0xffffffffffece000ull, UINT64_MAX, UINT64_MAX}}};
  uint32_t i, j;
  quiet_rows = 1;
  check(gtoss(0) == ZK_OK, "gtoss: form 0 accepted");
  for (i = 0; i < 4; i++)
    check(gdeal(deal[i][0], deal[i][1], 1) == ZK_OK, "gdeal: noise t, noise 2t, r and zero accepted");
  check(gflood() == ZK_OK, "gflood: accepted");
  for (i = 1; i <= 2; i++)
    check(gword(i) == ZK_OK, "gword: gword64 and gword128 accepted");
  check(gbit(0) == ZK_OK, "gbit: vid 0 (lwe) accepted");
  check(gbit(4) == ZK_OK, "gbit: vid 4 (squash poly 1) accepted");
  /* D71 boundaries: the noise at both ends for b = 17, 30 and 45 (top 2,
   * m 1); v at the centered lift edges and the torus wraps; the flood at
   * both ends; P at both ends of zk_party and one past each end. */
  deal_edge = 1;
  for (i = 0; i < 3; i++)
    for (j = 0; j < 2; j++) {
      deal_b = bs[i];
      deal_e = j == 0 ? 0ull - (1ull << (bs[i] - 1)) : 1ull << (bs[i] - 1);
      check(gdeal(ZK_GDEAL_NOISE, 2, 1) == ZK_OK, "gdeal: the noise at -2^(b - 1) and 2^(b - 1), b = 17, 30 and 45, accepted");
    }
  deal_edge = 0;
  deal_b = 45;
  check(tshare_eq(tshare_add(word[1], word[1]), tshare_from_u64(1)) &&
            tshare_eq(tshare_add(word[0], word[1]), tshare_from_u64(0)) &&
            tshare_eq(tshare_add(word[4], tshare_from_u64(1)), tshare_from_u64(0)),
        "gword: the edge words are (p - 1)/2, (p + 1)/2 and p - 1");
  for (i = 0; i < 5; i++)
    for (j = 1; j <= 2; j++) {
      word_edge = word + i;
      check(gword(j) == ZK_OK, "gword: v = (p - 1)/2, (p + 1)/2, 2^64, 2^128 and p - 1 accepted");
    }
  word_edge = NULL;
  for (i = 0; i < 2; i++) {
    flood_u = flood[i];
    check(gflood() == ZK_OK, "gflood: the flood at -2^106 and 2^106 - 1 accepted");
  }
  flood_u = NULL;
  for (i = 0; i < 4; i++) {
    flood_dealer = party[i];
    check((gflood() == ZK_OK) == (i < 2), "gflood: P = 1 and 5 accepted, P = 0 and 6 refused");
  }
  flood_dealer = 2;
  /* D99 (STEP 4 phase 2): zk_check refusals for the 4 classes that the D98
   * probe left LIVE: the seed and the commit of gtoss 0 (mseed), z_0 + 1 of
   * gbit 0 (mbit), dcoefq on gdeal r (mdeg), and the noise one past
   * 2^(b - 1) for b = 17, 30 and 45 (mnoise: u = 2^b + 1, q = 0; the range
   * alone refuses it). */
  for (i = 0; i < 2; i++) {
    u6_tamper = i == 0 ? U_TSEED : U_TCOMMIT;
    check(gtoss(0) == ZK_ERR_UNSAT, "gtoss: tseed and tcommit refused");
  }
  u6_tamper = U_BZERO;
  check(gbit(0) == ZK_ERR_UNSAT, "gbit: bzero refused");
  u6_tamper = U_DCOEFQ;
  check(gdeal(ZK_GDEAL_R, 2, 1) == ZK_ERR_UNSAT, "gdeal: dcoefq (c_1 + 1, q kept) refused");
  u6_tamper = U_NONE;
  deal_edge = 1;
  for (i = 0; i < 3; i++) {
    deal_b = bs[i];
    deal_e = (1ull << (bs[i] - 1)) + 1;
    check(gdeal(ZK_GDEAL_NOISE, 2, 1) == ZK_ERR_UNSAT, "gdeal: the noise at 2^(b - 1) + 1, b = 17, 30 and 45, refused");
  }
  deal_edge = 0;
  deal_b = 45;
  quiet_rows = 0;
}

/* zktool keygen (check-lig, S7 U6 D85): the heavy agree rows, too slow for
 * the warm budget of make check: gtoss 1, the gopen rows (keys 0) and the
 * keys 1 KSK row gopenkskk (2,918,028 values, C6). */
static int keygen_rows(void) {
  static const uint32_t lv[4] = {1, 4, 0, 5}, ce[2] = {0, ZK_GOPEN_GN - 1};
  uint32_t i, j;
  quiet_rows = 1;
  check(gtoss(1) == ZK_OK, "gtoss: form 1 accepted");
  check(gopen(ZK_GOPEN_KSK, 0) == ZK_OK, "gopen: KSK row (keys 0) accepted");
  check(gopen(ZK_GOPEN_CAST, 0) == ZK_OK, "gopen: cast KSK row (keys 0) accepted");
  check(gopen_glwe(ZK_GOPEN_BSK0) == ZK_OK, "gopen: BSK row 0 accepted");
  check(gopen_glwe(ZK_GOPEN_BSK1) == ZK_OK, "gopen: BSK row 1 accepted");
  check(gopen_glwe(ZK_GOPEN_PK) == ZK_OK, "gopen: pk row accepted");
  for (i = 0; i < 3; i++)
    check(gopen_sq(i) == ZK_OK, "gopen: squash rows 0, 1 and 2 accepted");
  check(gopen(ZK_GOPEN_KSK, 1) == ZK_OK, "gopen: KSK row (keys 1) accepted");
  /* D71 boundaries: the KSK level l = 1 and 4 (l = 0 and 5 refused: no
   * weights); the sign split of the BSK and squash rows (the terms t <= C
   * in U, t > C in W) at C = 0 and N - 1. */
  for (i = 0; i < 4; i++) {
    gopen_lv = lv[i];
    check((gopen(ZK_GOPEN_KSK, 0) == ZK_OK) == (i < 2), "gopen: the KSK level l = 1 and 4 accepted, l = 0 and 5 refused");
  }
  gopen_lv = 2;
  for (i = 0; i < 2; i++) {
    gopen_c = ce + i;
    for (j = ZK_GOPEN_BSK0; j <= ZK_GOPEN_BSK1; j++)
      check(gopen_glwe(j) == ZK_OK, "gopen: BSK rows 0 and 1 at C = 0 and N - 1 accepted");
    for (j = 0; j < 3; j++)
      check(gopen_sq(j) == ZK_OK, "gopen: squash rows 0, 1 and 2 at C = 0 and N - 1 accepted");
  }
  gopen_c = NULL;
  quiet_rows = 0;
  if (fails == 0) puts("zk keygen rows: passed");
  return fails != 0;
}

static int split_case(const char *name, const char *arg) {
  const long k = split_index(name, "gchunk", ZK_SPLIT_CHUNKS - 1), j = split_index(name, "gslice", ZK_SPLIT_SLICES - 1);
  const int party = strcmp(arg, "party0") == 0 ? 0 : strcmp(arg, "party6") == 0 ? 6 : -1;
  const uint32_t n = sizeof split_names / sizeof split_names[0];
  uint32_t t;
  ZkErr e;
  for (t = 0; t < n; t++)
    if (strcmp(arg, split_names[t]) == 0) break;
  if ((k < 0 && j < 0) || (t == n && party < 0)) return 2;
  split_tamper = t < n ? (SplitTamper)t : S_NONE;
  if (party >= 0) split_party = (uint32_t)party;
  print_case = 1;
  e = k >= 0 ? gchunk((uint32_t)k) : gslice((uint32_t)j);
  split_tamper = S_NONE;
  split_party = TDEC_PARTY;
  return e != ZK_OK;
}

/* zktool circuit NAME: the words of one valid gadget circuit and its witness
 * (S7 U2 Rust rows). gbits: 2^64 - 1 as 64 bits. grange: 12345 in [0, 99999].
 * gcarry: (2^64 - 1) (2^64 - 1) + (2^64 - 1) = (2^64 - 1) 2^64 + 0.
 * gfp: 2^64 2^128 = 1253375 mod p. gp2: Poseidon2 hash of (1, 2, 3), tag 0
 * (input 0). gsha: SHA-512 of "abc" (one block), length 3 (input 0). gvote
 * and gmotion: the U3 member at index 2 of the wRoot three list. gvoteq and
 * gmotioneq: the same member with the level-0 sibling equal to the leaf (the
 * witness of the Rust b = 2 row; the circuit is that of gvote or gmotion).
 * gballotfull: the D25 (1) agree ballot (S7 U4 D19; no crate). gballot
 * and gmask (offset 0): the same ballot in the ruled shape (D20, D24).
 * gsharecore, gsharecore256 and gshac1 to gshac3: the S7 U5 D41 measures (no
 * crate; each case also prints its values, k and zk_check time to stderr). */
static int circuit(const char *name) {
  const ZkFr zero = zk_fr_u64(0), max64 = fr_pow2_minus(64, 1);
  const ZkFr x = zk_fr_u64(12345), b = zk_fr_u64(99999);
  const ZkFr in3[3] = {max64, max64, max64}, out2[2] = {zero, max64};
  static const uint64_t e64[3] = {0, 1, 0}, e128[3] = {0, 0, 1}, f3[3] = {TSHARE_FOLD, 0, 0};
  static const uint64_t words[3] = {1, 2, 3};
  const uint8_t *abc = (const uint8_t *)"abc";
  ZkFr in6[6], out3[3], want;
  Fr ref;
  ZkErr e = ZK_ERR_COUNT;
  fp_limbs(in6, e64);
  fp_limbs(in6 + 3, e128);
  fp_limbs(out3, f3);
  poseidon2_hash(0, words, 3, &ref);
  want = p2_zk(&ref);
  print_words = 1;
  switch (circuit_of(name)) {
  case C_BITS: e = gadget_check(G_BITS, &max64, 64, NULL, NULL, 0); break;
  case C_RANGE: e = gadget_check(G_RANGE, &x, 0, &b, NULL, 0); break;
  case C_CARRY: e = arith_check(A_MULADD64, NULL, in3, out2, NULL, 0, 0); break;
  case C_FP: e = arith_check(A_MULP, NULL, in6, out3, NULL, 0, 0); break;
  case C_P2: e = p2_check(0, words, 3, P2_NONE, &want); break;
  case C_SHA: e = sha_check(abc, 3, P2_NONE, SHA_ABC); break;
  case C_GVOTE: e = member_case(1, 2, 0, T_NONE); break;
  case C_GMOTION: e = member_case(0, 2, 0, T_NONE); break;
  case C_GVOTEQ: e = member_case(1, 2, 1, T_NONE); break;
  case C_GMOTIONEQ: e = member_case(0, 2, 1, T_NONE); break;
  case C_GBALLOTFULL: e = pke_agree(); break;
  case C_GBALLOT: e = pke_circuit(0); break;
  case C_GMASK: e = pke_circuit(1); break;
  case C_GSHARECORE: e = gsharecore(SQUASH_BIG_N); break;
  case C_GSHARECORE256: e = gsharecore(256); break;
  case C_GSHAC1: e = gshac(1); break;
  case C_GSHAC2: e = gshac(2); break;
  case C_GSHAC3: e = gshac(3); break;
  case C_GCHUNK0: e = gchunk(0); break;
  case C_GCHUNK1: e = gchunk(1); break;
  case C_GCHUNK255: e = gchunk(255); break;
  case C_GCHUNK256: e = gchunk(256); break;
  case C_GSLICE0: e = gslice(0); break;
  case C_GSLICE1: e = gslice(1); break;
  case C_GSLICE15: e = gslice(15); break;
  case C_GTOSS0: e = gtoss(0); break;
  case C_GTOSS1: e = gtoss(1); break;
  case C_GDEALN: e = gdeal(ZK_GDEAL_NOISE, 2, 1); break;
  case C_GDEALN2: e = gdeal(ZK_GDEAL_NOISE, 4, 1); break;
  case C_GDEALR: e = gdeal(ZK_GDEAL_R, 2, 1); break;
  case C_GDEALZ: e = gdeal(ZK_GDEAL_ZERO, 4, 1); break;
  case C_GDEALV16: e = gdeal(ZK_GDEAL_NOISE, 2, 16); break;
  case C_GDEALV64: e = gdeal(ZK_GDEAL_NOISE, 2, 64); break;
  case C_GFLOOD: e = gflood(); break;
  case C_GWORD64: e = gword(1); break;
  case C_GWORD128: e = gword(2); break;
  case C_GBIT: e = gbit(u6_vid); break;
  case C_GOPENKSK: e = gopen(ZK_GOPEN_KSK, 0); break;
  case C_GOPENCAST: e = gopen(ZK_GOPEN_CAST, 0); break;
  case C_GOPENKSKK: e = gopen(ZK_GOPEN_KSK, 1); break;
  case C_GOPENBSK0: e = gopen_glwe(ZK_GOPEN_BSK0); break;
  case C_GOPENBSK1: e = gopen_glwe(ZK_GOPEN_BSK1); break;
  case C_GOPENPK: e = gopen_glwe(ZK_GOPEN_PK); break;
  case C_GOPENSQ0: e = gopen_sq(0); break;
  case C_GOPENSQ1: e = gopen_sq(1); break;
  case C_GOPENSQ2: e = gopen_sq(2); break;
  case C_NONE:
    fprintf(stderr, "zktool: circuit NAME is gbits, grange, gcarry, gfp, gp2, gsha, gvote, gmotion, gvoteq, "
                    "gmotioneq, gballotfull, gballot, gmask, gsharecore, gsharecore256, gshac1, "
                    "gshac2, gshac3, gchunk0, gchunk1, gchunk255, gchunk256, gslice0, gslice1, "
                    "gslice15, gtoss0, gtoss1, gdealn, gdealn2, gdealr, gdealz, gdealv16, gdealv64, gflood, gword64, gword128, gbit, gopenksk, gopencast, gopenkskk, "
                    "gopenbsk0, gopenbsk1, gopenpk, gopensq0, gopensq1 or gopensq2\n");
    return 2;
  }
  if (e != ZK_OK) fprintf(stderr, "zktool: circuit %s: %s\n", name, zk_err_text(e));
  return e != ZK_OK || fails != 0;
}

/* zktool case NAME ARG for a U6 NAME (gtoss0 to gopensq2): the case of
 * `zktool circuit NAME` with ARG honest, a false witness class of D69
 * (u6_names; a class that does not apply to NAME leaves the case honest), or a
 * second honest instance for the replay rows (dealer1: the gflood dealer 1;
 * vid1: the gbit vid 1). The case goes to stdout (case_print). A bad ARG
 * exits 2. */
static const char *const u6_names[] = {
    "honest", "tseed", "tcommit", "tparty", "tjword", "d2t", "dyi", "dcoef", "dzero", "f2t", "fyi", "fcoef",
    "wshare", "bri", "bzero", "bc", "broot", "bbit", "bvid", "omask", "oshare", "okey", "onoise", "ocarry",
    "osign0", "osign1", "olevel", "dcoefq"};
static int u6_case(const char *name, const char *arg) {
  const uint32_t n = sizeof u6_names / sizeof u6_names[0];
  const int dealer1 = strcmp(arg, "dealer1") == 0, vid1 = strcmp(arg, "vid1") == 0;
  uint32_t t;
  int rc;
  for (t = 0; t < n; t++)
    if (strcmp(arg, u6_names[t]) == 0) break;
  if (t == n && !dealer1 && !vid1) return 2;
  u6_tamper = t < n ? (U6Tamper)t : U_NONE;
  if (dealer1) flood_dealer = 1;
  if (vid1) u6_vid = 1;
  print_case = 1;
  rc = circuit(name);
  u6_tamper = U_NONE;
  flood_dealer = 2;
  u6_vid = 0;
  return rc;
}

/* S7 U6 L4 (RESUME47) zktool cases: the case classes that the removed Rust
 * tests (test/zk/tests/NAME.rs, D114) ran through `zktool case NAME ARG`, each
 * with the zk_check verdict that its test required (accept 1, refuse 0). Each
 * row runs the case dispatch with the case print off and checks the verdict of
 * the first case_print; build/ligzk gives a lig row for each through the hook. */
typedef struct {
  const char *name, *arg;
  int accept;
} CaseRow;

static const CaseRow case_table[] = {
    /* gballot.rs and gmask.rs (pke_case) */
    {"gballot", "choice3", 1}, {"gballot", "error", 0}, {"gballot", "slot", 0}, {"gmask", "64", 1}, {"gmask", "1984", 1},
    /* gchunk.rs (split_case) */
    {"gchunk0", "party0", 0}, {"gchunk0", "party6", 0}, {"gchunk16", "none", 1}, {"gchunk255", "none", 1},
    {"gchunk16", "sigma", 0}, {"gchunk16", "rho", 0}, {"gchunk16", "byte", 0}, {"gchunk17", "moved", 0},
    {"gchunk16", "party0", 0}, {"gchunk16", "party6", 0}, {"gchunk256", "chain", 0},
    /* gslice.rs (split_case) */
    {"gslice0", "party0", 0}, {"gslice0", "party6", 0}, {"gslice1", "sigma", 0}, {"gslice1", "salt_in", 0},
    {"gslice1", "salt_out", 0}, {"gslice1", "acc", 0}, {"gslice1", "byte", 0}, {"gslice1", "neighbour", 0},
    {"gslice1", "party0", 0}, {"gslice1", "party6", 0}, {"gslice15", "noise", 0}, {"gslice15", "q", 0},
    {"gslice15", "carry", 0}, {"gslice15", "vp", 0}, {"gslice15", "b", 0}, {"gslice15", "b2", 0},
    /* gbit.rs (u6_case) */
    {"gbit", "honest", 1}, {"gbit", "bri", 0}, {"gbit", "bzero", 0}, {"gbit", "bc", 0}, {"gbit", "broot", 0},
    {"gbit", "bbit", 0}, {"gbit", "bvid", 0}, {"gbit", "vid1", 1},
    /* gdeal.rs (u6_case) */
    {"gdealn", "honest", 1}, {"gdealn", "dyi", 0}, {"gdealn", "dcoef", 0},
    {"gdealn2", "honest", 1}, {"gdealn2", "dyi", 0}, {"gdealn2", "dcoef", 0},
    {"gdealr", "honest", 1}, {"gdealr", "d2t", 0}, {"gdealr", "dyi", 0}, {"gdealr", "dcoef", 0},
    {"gdealz", "honest", 1}, {"gdealz", "dyi", 0}, {"gdealz", "dcoef", 0}, {"gdealz", "dzero", 0},
    {"gdealv16", "honest", 1}, {"gdealv16", "dyi", 0}, {"gdealv16", "dcoef", 0},
    /* gflood.rs (u6_case) */
    {"gflood", "honest", 1}, {"gflood", "f2t", 0}, {"gflood", "fyi", 0}, {"gflood", "fcoef", 0}, {"gflood", "dealer1", 1},
    /* gopen.rs (u6_case) */
    {"gopenksk", "honest", 1}, {"gopenksk", "omask", 0}, {"gopenksk", "oshare", 0}, {"gopenksk", "ocarry", 0},
    {"gopenksk", "olevel", 0}, {"gopencast", "honest", 1}, {"gopencast", "omask", 0}, {"gopencast", "oshare", 0},
    {"gopencast", "ocarry", 0}, {"gopencast", "olevel", 0}, {"gopenbsk1", "honest", 1}, {"gopenbsk1", "osign0", 0},
    {"gopenpk", "honest", 1}, {"gopenbsk0", "honest", 1}, {"gopensq0", "honest", 1}, {"gopensq0", "onoise", 0},
    {"gopensq1", "honest", 1}, {"gopensq1", "onoise", 0}, {"gopensq2", "honest", 1}, {"gopensq2", "onoise", 0},
    /* gtoss.rs (u6_case) */
    {"gtoss0", "honest", 1}, {"gtoss0", "tseed", 0}, {"gtoss0", "tcommit", 0}, {"gtoss0", "tparty", 0},
    {"gtoss1", "honest", 1}, {"gtoss1", "tjword", 0},
};

/* zktool case NAME ARG: the split, U6 or pke case of NAME. */
static int case_one(const char *name, const char *arg) {
  if (strncmp(name, "gchunk", 6) == 0 || strncmp(name, "gslice", 6) == 0) return split_case(name, arg);
  if (circuit_of(name) >= C_GTOSS0 && circuit_of(name) < C_NONE) return u6_case(name, arg);
  return pke_case(name, arg);
}

static int cases_rows(void) {
  const uint32_t n = sizeof case_table / sizeof case_table[0];
  uint32_t i;
  int rc;
  case_quiet = 1;
  for (i = 0; i < n; i++) {
    const CaseRow *r = &case_table[i];
    case_seen = 0;
    case_first = ZK_OK;
    rc = case_one(r->name, r->arg);
    printf("case %s %s: rc %d seen %d %s\n", r->name, r->arg, rc, case_seen, case_first == ZK_OK ? "accept" : "refuse");
    check(rc == 0 && case_seen >= 1 && (case_first == ZK_OK) == r->accept, "case table row (the row above)");
  }
  case_quiet = 0;
  print_case = 0;
  if (fails == 0) printf("zk writer cases: %u rows passed\n", (unsigned)n);
  return fails != 0;
}

/* S7 U7 zktool client (check-lig; D149): the vote rows that need a PkeBallot.
 * One ballot (choice PKE_CHOICE of width PKE_WIDTH, PKE_ENC_SEED) on the
 * client_path tree at idx 0 and 2^16 - 1. The C words are equal to the words
 * of the client Wasm module (one node call for the two vote lines), the reader
 * accepts them, the mask, r and e1 words do not depend on idx (D150), and the
 * classes R3 and R4 give their codes on the block at 2^16 - 1. The motion
 * words of the same tree are read the same way. */
enum { CL_VOTE_IN = 4188 };

/* The C vote words at IDX for the ballot B: the module input IN (the
 * encryption seed as 4 words, pk_a, pk_b, m, the width, key, e, u, idx, the
 * path) and the block OUT (D139: root, nf, e, u, w, the mask, the bodies, key,
 * idx, the path, m, the r bits, e1, e2), root, nf and the bodies from
 * zk_gballot_fill. MODEL gets the model_fold root; 1 when the fill root is the
 * model root, root and nf are those of zk_gvote_fill and the fill bodies are
 * the pke bodies. */
static int client_vote(const PkeBallot *b, uint32_t idx, uint64_t *in, uint64_t *out, uint64_t model[4]) {
  static ZkFr wt[ZK_GB_WEIGHTS];
  uint64_t sib[ZR_PATH_WORDS], root[4], nf[4], root2[4], nf2[4], cr[4], body[ZK_PKE_SLOTS];
  uint32_t j;
  client_path(idx, model, sib);
  memset(in, 0, CL_VOTE_IN * sizeof *in);
  for (j = 0; j < 32; j++) in[j / 8] |= (uint64_t)(unsigned char)PKE_ENC_SEED[j] << (8 * (j % 8));
  memcpy(in + 4, b->p.pk_a, ZK_PKE_N * sizeof *in);
  memcpy(in + 2052, b->p.pk_b, ZK_PKE_N * sizeof *in);
  for (j = 0; j < ZK_PKE_SLOTS; j++) in[4100 + j] = b->m[j];
  in[4116] = PKE_WIDTH;
  memcpy(in + 4117, U3_KEY, sizeof U3_KEY);
  in[4121] = U3_E;
  in[4122] = U3_U[0];
  in[4123] = idx;
  memcpy(in + 4124, sib, sizeof sib);
  zk_gvote_fill(wt, U3_KEY, U3_E, U3_U[0], sib, idx, root2, nf2);
  zk_gballot_fill(wt, U3_KEY, U3_E, U3_U[0], sib, idx, b->p.pk_b, b->r, b->m, b->e2, root, nf, cr, body);
  memset(out, 0, ZR_VOTE_WORDS * sizeof *out);
  memcpy(out, root, sizeof root);
  memcpy(out + 4, nf, sizeof nf);
  out[8] = U3_E;
  out[9] = U3_U[0];
  out[10] = PKE_WIDTH;
  memcpy(out + 11, b->mask, ZK_PKE_N * sizeof *out);
  memcpy(out + 2059, body, sizeof body);
  memcpy(out + 2075, U3_KEY, sizeof U3_KEY);
  out[2079] = idx;
  memcpy(out + 2080, sib, sizeof sib);
  for (j = 0; j < ZK_PKE_SLOTS; j++) out[2144 + j] = b->m[j];
  for (j = 0; j < ZK_PKE_N; j++) out[2160 + j / 64] |= (uint64_t)(b->r[j] & 1u) << (j % 64);
  for (j = 0; j < ZK_PKE_N; j++) out[2192 + j] = (uint64_t)b->e1[j];
  for (j = 0; j < ZK_PKE_SLOTS; j++) out[4240 + j] = (uint64_t)b->e2[j];
  return dg_eq(root, model) && dg_eq(root2, root) && dg_eq(nf2, nf) && memcmp(body, b->body, sizeof body) == 0;
}

#ifdef ZK_LIG
/* The proof rows of client_rows (S7 U7, the second build only). Each helper
 * fills the witness of one relation from the READ values (M or V) and takes
 * the public context values from X. finish gives the zk_check code after the
 * lig_hook row. gmotion: the inputs are the e and the ctx of X, the outputs
 * are the root of X and the mt of M. */
static ZkErr client_gmotion(const ZrMotion *m, const ZrContext *x) {
  static ZkFr wt[ZK_GMOTION_WEIGHTS];
  ZkFr in[2], out[2];
  ZkMatrix mx[1];
  uint32_t map[1];
  uint64_t root[4], mt[4];
  ZkWitness w;
  ZkCircuit c;
  ZkErr err;
  memset(wt, 0, sizeof wt);
  zk_gmotion_fill(wt, m->key, m->e, m->ctx, m->sib, m->idx, root, mt);
  in[0] = zk_fr_u64(x->e);
  in[1] = dg_fr(x->ctx);
  out[0] = dg_fr(x->root);
  out[1] = dg_fr(m->mt);
  wit_init(&w, mx, map, in, 2, wt, ZK_GMOTION_WEIGHTS, out, 2);
  zk_gmotion(&c);
  err = finish(&c, &w);
  zk_free(&c);
  return err;
}

/* gballot: the inputs are the e of X, the u and the w of V, the pk_b of X and
 * the 16 bodies of V. The outputs are the root of X, the nf of V and the Cr
 * of the fill, which goes to CR. */
static ZkErr client_gballot(const ZrVote *v, const ZrContext *x, uint64_t cr[4]) {
  static ZkFr in[ZK_GB_INPUTS], wt[ZK_GB_WEIGHTS];
  ZkFr out[3];
  ZkMatrix mx[1];
  uint32_t map[1], j;
  uint64_t root[4], nf[4], words[ZK_PKE_SLOTS];
  ZkWitness w;
  ZkCircuit c;
  ZkErr err;
  memset(wt, 0, sizeof wt);
  zk_gballot_fill(wt, v->key, v->e, v->u, v->sib, v->idx, x->pk_b, v->r, v->m, v->e2, root, nf, cr, words);
  in[0] = zk_fr_u64(x->e);
  in[1] = zk_fr_u64(v->u);
  in[2] = zk_fr_u64(v->w);
  for (j = 0; j < ZK_PKE_N; j++) in[ZK_GB_IN_PKB + j] = zk_fr_u64(x->pk_b[j]);
  for (j = 0; j < ZK_PKE_SLOTS; j++) in[ZK_GB_IN_BODY + j] = zk_fr_u64(v->body[j]);
  out[0] = dg_fr(x->root);
  out[1] = dg_fr(v->nf);
  out[2] = dg_fr(cr);
  wit_init(&w, mx, map, in, ZK_GB_INPUTS, wt, ZK_GB_WEIGHTS, out, 3);
  zk_gballot(&c);
  err = finish(&c, &w);
  zk_free(&c);
  return err;
}

/* gmask at the offset O: the inputs are A' = X^-O pk_a of X and the mask
 * slice of V. The output is CR, the Cr of the ballot proof (the 33 proofs of
 * one ballot have one Cr). */
static ZkErr client_gmask(const ZrVote *v, const ZrContext *x, uint32_t o, const uint64_t cr[4]) {
  static ZkFr in[ZK_GMASK_INPUTS], wt[ZK_GMASK_WEIGHTS];
  uint64_t ap[ZK_PKE_N], fcr[4], words[ZK_GMASK_SPAN];
  ZkFr out[1];
  ZkMatrix mx[1];
  uint32_t map[1], t;
  ZkWitness w;
  ZkCircuit c;
  ZkErr err;
  pke_shift(x->pk_a, o, ap);
  memset(wt, 0, sizeof wt);
  zk_gmask_fill(wt, ap, v->r, v->e1 + o, words, fcr);
  for (t = 0; t < ZK_PKE_N; t++) in[t] = zk_fr_u64(ap[t]);
  for (t = 0; t < ZK_GMASK_SPAN; t++) in[ZK_GMASK_IN_MASK + t] = zk_fr_u64(v->mask[o + t]);
  out[0] = dg_fr(cr);
  wit_init(&w, mx, map, in, ZK_GMASK_INPUTS, wt, ZK_GMASK_WEIGHTS, out, 1);
  zk_gmask(&c);
  err = finish(&c, &w);
  zk_free(&c);
  return err;
}

/* gmotion and gballot at each of the CL_TWO positions, then the two refusals
 * (a motion under another ctx, a vote under another e), then the 32 gmask
 * slices one time (D150: the mask, r and e1 words do not depend on idx). */
static void client_proofs(const ZrVote *v, const ZrMotion *m, const ZrContext *c) {
  uint64_t cr[CL_TWO][4], other[4];
  ZrContext x;
  uint32_t o;
  size_t k;
  int ok = 1;
  for (k = 0; k < CL_TWO; k++) ok = client_gmotion(&m[k], &c[k]) == ZK_OK && ok;
  check(ok, "client proof: gmotion of the READ motion has a bound proof at idx 0 and 2^16 - 1");
  ok = 1;
  for (k = 0; k < CL_TWO; k++) ok = client_gballot(&v[k], &c[k], cr[k]) == ZK_OK && ok;
  check(ok, "client proof: gballot of the READ vote has a bound proof at idx 0 and 2^16 - 1");
  check(dg_eq(cr[0], cr[CL_TWO - 1]), "client proof: the Cr at idx 0 is the Cr at idx 2^16 - 1");
  x = c[0];
  x.ctx[0] ^= 1u;
  check(client_gmotion(&m[0], &x) == ZK_ERR_UNSAT, "client proof: a motion proof under another ctx is refused");
  x = c[CL_TWO - 1];
  x.e ^= 1u;
  check(client_gballot(&v[CL_TWO - 1], &x, other) == ZK_ERR_UNSAT,
        "client proof: a vote proof under another e is refused");
  ok = 1;
  for (o = 0; o < ZK_PKE_N; o += ZK_GMASK_SPAN) ok = client_gmask(&v[0], &c[0], o, cr[0]) == ZK_OK && ok;
  check(ok, "client proof: the 32 gmask slices of the READ vote have a bound proof under the Cr of the ballot proof");
}
#endif

static int client_rows(void) {
  static const uint32_t idx[CL_TWO] = {0, MERKLE_LAST};
  static const ClEdit bad[] = {
      {2080, CL_FLIP, 0, ZR_ERR_REF, "client vote: a changed sibling gives the reference code"},
      {0, CL_FLIP, 0, ZR_ERR_REF, "client vote: a changed root word gives the reference code"},
      {4, CL_FLIP, 0, ZR_ERR_REF, "client vote: a changed nf word gives the reference code"},
      {2059, CL_FLIP, 0, ZR_ERR_REF, "client vote: a changed body word gives the reference code"},
      {11, CL_FLIP, 0, ZR_ERR_REF, "client vote: a changed mask word in the first slice gives the reference code"},
      {11 + ZK_PKE_N - 1, CL_FLIP, 0, ZR_ERR_REF,
       "client vote: a changed mask word in the last slice gives the reference code"},
      {2079, CL_FLIP, 0, ZR_ERR_REF, "client vote: a changed idx below 2^16 gives the reference code"}};
  static PkeBallot b;
  static uint64_t in[CL_TWO * CL_VOTE_IN], want[CL_TWO * ZR_VOTE_WORDS], got[CL_TWO * ZR_VOTE_WORDS];
  static uint64_t w[ZR_VOTE_WORDS], pk[ZK_PKE_N], min[CL_TWO * CL_MOTION_IN], mwant[CL_TWO * ZR_MOTION_WORDS],
      mgot[CL_TWO * ZR_MOTION_WORDS];
  static ZrVote v[CL_TWO], sv;
  static ZrMotion m[CL_TWO];
  const uint64_t *last = got + (CL_TWO - 1) * ZR_VOTE_WORDS;
  uint64_t model[4];
  ZrContext c[CL_TWO], x;
  size_t k, t;
  int ok = 1;
  check(pke_ballot(&b, PKE_CHOICE) == ZK_OK, "client: the pke ballot");
  if (fails != 0) return 1;
  memset(c, 0, sizeof c);
  for (k = 0; k < CL_TWO; k++) {
    ok = client_vote(&b, idx[k], in + k * CL_VOTE_IN, want + k * ZR_VOTE_WORDS, c[k].root) && ok;
    c[k].e = U3_E;
    c[k].pk_a = b.p.pk_a;
    c[k].pk_b = b.p.pk_b;
    memcpy(c[k].ctx, U3_CTX, sizeof U3_CTX);
  }
  check(ok, "client vote: the zk_gballot_fill root is the model_fold root, root and nf are those of zk_gvote_fill "
            "and the bodies are the pke bodies at idx 0 and 2^16 - 1");
  ok = client_wasm("vote", in, CL_VOTE_IN, got, ZR_VOTE_WORDS);
  check(ok, "client vote: the module, the input or node failed (build/zk-client-out.txt)");
  if (!ok) return 1;
  check(memcmp(got, want, sizeof want) == 0, "client vote: the C words are the Wasm words at idx 0 and 2^16 - 1");
  for (k = 0; k < CL_TWO; k++)
    check(zr_read_vote(&v[k], got + k * ZR_VOTE_WORDS, ZR_VOTE_WORDS, &c[k]) == ZR_OK,
          "client vote: the reader accepts the Wasm words at idx 0 and 2^16 - 1");
  check(memcmp(got + 11, last + 11, ZK_PKE_N * sizeof *got) == 0 &&
            memcmp(got + 2160, last + 2160, (4240 - 2160) * sizeof *got) == 0,
        "client vote: the mask, r and e1 words at idx 0 are those at idx 2^16 - 1 (D150)");
  for (t = 0; t < sizeof bad / sizeof *bad; t++) {
    memcpy(w, last, sizeof w);
    client_edit(w, &bad[t]);
    check(zr_read_vote(&sv, w, ZR_VOTE_WORDS, &c[CL_TWO - 1]) == bad[t].want, bad[t].what);
  }
  memcpy(pk, b.p.pk_a, sizeof pk);
  pk[0] ^= 1u;
  x = c[CL_TWO - 1];
  x.pk_a = pk;
  check(zr_read_vote(&sv, last, ZR_VOTE_WORDS, &x) == ZR_ERR_REF,
        "client vote: a changed pk_a word gives the reference code");
  memcpy(pk, b.p.pk_b, sizeof pk);
  pk[0] ^= 1u;
  x = c[CL_TWO - 1];
  x.pk_b = pk;
  check(zr_read_vote(&sv, last, ZR_VOTE_WORDS, &x) == ZR_ERR_REF,
        "client vote: a changed pk_b word gives the reference code");
  x = c[CL_TWO - 1];
  x.root[0] ^= 1u;
  check(zr_read_vote(&sv, last, ZR_VOTE_WORDS, &x) == ZR_ERR_CONTEXT,
        "client vote: a changed context root gives the context code");
  x = c[CL_TWO - 1];
  x.e ^= 1u;
  check(zr_read_vote(&sv, last, ZR_VOTE_WORDS, &x) == ZR_ERR_CONTEXT,
        "client vote: a changed context epoch gives the context code");
  ok = 1;
  for (k = 0; k < CL_TWO; k++)
    ok = client_motion(idx[k], min + k * CL_MOTION_IN, mwant + k * ZR_MOTION_WORDS, model) &&
         dg_eq(model, c[k].root) && ok;
  check(ok, "client motion: the zk_gmotion_fill root is the vote context root at idx 0 and 2^16 - 1");
  ok = client_wasm("motion", min, CL_MOTION_IN, mgot, ZR_MOTION_WORDS);
  check(ok, "client motion: the module, the input or node failed (build/zk-client-out.txt)");
  if (!ok) return 1;
  check(memcmp(mgot, mwant, sizeof mwant) == 0, "client motion: the C words are the Wasm words at idx 0 and 2^16 - 1");
  for (k = 0; k < CL_TWO; k++)
    check(zr_read_motion(&m[k], mgot + k * ZR_MOTION_WORDS, ZR_MOTION_WORDS, &c[k]) == ZR_OK,
          "client motion: the reader accepts the Wasm words at idx 0 and 2^16 - 1");
#ifdef ZK_LIG
  if (fails == 0) client_proofs(v, m, c);
#endif
  if (fails == 0) puts("zk client rows: passed");
  return fails != 0;
}

int main(int argc, char **argv) {
  if (argc == 1) return rows();
  if (argc == 2 && strcmp(argv[1], "client") == 0) return client_rows();
  if (argc == 5 && strcmp(argv[1], "smoke") == 0) return smoke(argv[2], argv[3], argv[4]);
  if (argc == 3 && strcmp(argv[1], "bad") == 0) return bad(argv[2]);
  if (argc == 3 && strcmp(argv[1], "circuit") == 0) return circuit(argv[2]);
  if (argc == 2 && strcmp(argv[1], "member") == 0) return member_rows();
  if (argc == 2 && strcmp(argv[1], "full") == 0) return full_rows();
  if (argc == 2 && strcmp(argv[1], "pke") == 0) return pke_rows();
  if (argc == 2 && strcmp(argv[1], "split") == 0) return split_rows();
  if (argc == 2 && strcmp(argv[1], "keygen") == 0) return keygen_rows();
  if (argc == 2 && strcmp(argv[1], "cases") == 0) return cases_rows();
  if (argc == 4 && strcmp(argv[1], "case") == 0) return case_one(argv[2], argv[3]);
  fprintf(stderr, "usage: zktool | zktool smoke X Y W | zktool bad KIND | zktool circuit NAME | zktool member | "
                  "zktool full | zktool pke | zktool split | zktool keygen | zktool cases | zktool case NAME ARG | "
                  "zktool client\n");
  return 2;
}
