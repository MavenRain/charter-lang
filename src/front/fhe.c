/* S5 U4a: the FHE circuit table (front/fhe.h): the builder with the level
 * rule, the printer, the C eval on the radix layer, and the circuit LUTs. */
#include "front/fhe.h"

#include <string.h>

static const char *const LUT_NAMES[FHE_LUTS] = {"THETA", "ISREL", "ISREF", "AMD"};

/* An input is fresh (level 1). */
static unsigned level(const FheCircuit *c, FheReg r) {
  switch (r.slot) {
  case FHE_RADIX_IN:
  case FHE_BLOCK_IN:
    return 1u;
  case FHE_RADIX_REG:
    return c->radix_level[r.index];
  case FHE_BLOCK_REG:
    return c->block_level[r.index];
  }
  return 1u;
}

static void set_level(FheCircuit *c, FheReg r, unsigned v) {
  if (r.slot == FHE_RADIX_REG) c->radix_level[r.index] = v;
  if (r.slot == FHE_BLOCK_REG) c->block_level[r.index] = v;
}

/* A new register of SLOT (FHE_RADIX_REG or FHE_BLOCK_REG). */
static FheReg new_reg(FheCircuit *c, FheSlot slot) {
  unsigned *used = slot == FHE_RADIX_REG ? &c->radix_regs : &c->block_regs;
  unsigned limit = slot == FHE_RADIX_REG ? FHE_RADIX_REGS : FHE_BLOCK_REGS;
  FheReg r;
  r.slot = slot;
  r.index = 0;
  if (*used >= limit) {
    c->failed = 1;
    return r;
  }
  r.index = (*used)++;
  return r;
}

/* A new input of SLOT (FHE_RADIX_IN or FHE_BLOCK_IN). */
static FheReg input(FheCircuit *c, FheSlot slot, const char *name) {
  unsigned *count = slot == FHE_RADIX_IN ? &c->radix_ins : &c->block_ins;
  char (*names)[FHE_NAME_BYTES] = slot == FHE_RADIX_IN ? c->radix_in : c->block_in;
  FheReg r;
  r.slot = slot;
  r.index = 0;
  if (*count >= FHE_INPUTS) {
    c->failed = 1;
    return r;
  }
  snprintf(names[*count], FHE_NAME_BYTES, "%s", name);
  r.index = (*count)++;
  return r;
}

static FheClear param(FheCircuit *c, const char *name) {
  FheClear p;
  p.kind = FHE_PARAM;
  p.value = 0;
  if (c->params >= FHE_INPUTS) {
    c->failed = 1;
    return p;
  }
  snprintf(c->param[c->params], FHE_NAME_BYTES, "%s", name);
  p.value = c->params++;
  return p;
}

static FheClear lit(uint64_t v) {
  FheClear p;
  p.kind = FHE_LIT;
  p.value = v;
  return p;
}

static FheClear neg(FheClear p) {
  p.kind = FHE_NEG_PARAM;
  return p;
}

static FheStmt stmt(FheOp op, FheReg dst, FheReg a, FheReg b, unsigned pbs) {
  FheStmt s;
  memset(&s, 0, sizeof s);
  s.op = op;
  s.dst = dst;
  s.a = a;
  s.b = b;
  s.pbs = pbs;
  return s;
}

/* Adds S; its output DST gets level LVL. */
static void emit(FheCircuit *c, FheStmt s, unsigned lvl) {
  if (c->stmts >= FHE_STMTS) {
    c->failed = 1;
    return;
  }
  c->stmt[c->stmts++] = s;
  c->pbs += s.pbs;
  set_level(c, s.dst, lvl);
}

static void output(FheCircuit *c, FheReg r) {
  if (c->outs >= FHE_OUTPUTS) {
    c->failed = 1;
    return;
  }
  c->out[c->outs++] = r;
}

/* R := refresh(R). An input is fresh and does not get a refresh. */
static void refresh(FheCircuit *c, FheReg r) {
  c->failed |= r.slot != FHE_RADIX_REG;
  emit(c, stmt(FHE_REFRESH, r, r, r, TFHE_RADIX_BLOCKS), 1u);
  c->refreshes++;
}

/* The largest 2-bit digit of V: 3 for a parameter. */
static unsigned digit_max(FheClear v) {
  unsigned i, m = 0;
  for (i = 0; i < TFHE_RADIX_BLOCKS && v.kind == FHE_LIT; i++) {
    unsigned d = (unsigned)(v.value >> (2u * i)) & (TFHE_MSG_MOD - 1u);
    m = d > m ? d : m;
  }
  return v.kind == FHE_LIT ? m : TFHE_MSG_MOD - 1u;
}

static void trivial(FheCircuit *c, FheReg dst, FheClear v) {
  FheStmt s = stmt(FHE_TRIVIAL, dst, dst, dst, 0);
  s.c = v;
  emit(c, s, 0u);
}

static void rmul(FheCircuit *c, FheReg dst, FheReg bit, FheClear v) {
  FheStmt s = stmt(FHE_RMUL, dst, bit, bit, 0);
  s.c = v;
  emit(c, s, digit_max(v) * level(c, bit));
}

/* A radd block holds the levels of X and Y and a carry of level 1. Over
 * FHE_LEVEL_MAX, the input with the higher level gets a refresh first (two
 * rmul outputs of a parameter: 3 + 3 + 1). */
static void radd(FheCircuit *c, FheReg dst, FheReg x, FheReg y) {
  unsigned i;
  for (i = 0; i < 2u; i++) {
    if (level(c, x) + level(c, y) + 1u > FHE_LEVEL_MAX) refresh(c, level(c, x) >= level(c, y) ? x : y);
  }
  emit(c, stmt(FHE_RADD, dst, x, y, TFHE_PROPAGATE_PBS), 1u);
}

/* The terms are the radix registers FIRST to FIRST + M - 1. A term over
 * level 1 gets a refresh first: 4 terms of level 1 and a carry give 4 + 1 =
 * 5 (tfhe_radix_sum). */
static void rsum(FheCircuit *c, FheReg dst, FheReg first, unsigned m) {
  FheStmt s;
  FheReg x = first;
  unsigned i;
  c->failed |= first.slot != FHE_RADIX_REG || m == 0 || first.index + m > c->radix_regs;
  for (i = 0; i < m && !c->failed; i++) {
    x.index = first.index + i;
    if (level(c, x) > 1u) refresh(c, x);
  }
  s = stmt(FHE_RSUM, dst, first, first, TFHE_PROPAGATE_PBS * ((m + 1u) / 3u));
  s.count = m;
  emit(c, s, 1u);
}

/* The CMP input of block i is 4 x_i + y_i, of level 4 level(x) + level(y). */
static void rle(FheCircuit *c, FheReg dst, FheReg x, FheReg y) {
  if (TFHE_MSG_MOD * level(c, x) + level(c, y) > FHE_LEVEL_MAX && level(c, x) > 1u) refresh(c, x);
  if (TFHE_MSG_MOD * level(c, x) + level(c, y) > FHE_LEVEL_MAX) refresh(c, y);
  emit(c, stmt(FHE_RLE, dst, x, y, TFHE_LE_PBS), 1u);
}

static void pair(FheCircuit *c, FheReg dst, FheReg h, FheReg l) {
  emit(c, stmt(FHE_PAIR, dst, h, l, 0), TFHE_MSG_MOD * level(c, h) + level(c, l));
}

/* A LUT input must have a level of FHE_LEVEL_MAX or less: a pair cannot get
 * a refresh. */
static void lut(FheCircuit *c, FheReg dst, FheReg a, unsigned id) {
  FheStmt s = stmt(FHE_LUT, dst, a, a, 1u);
  c->failed |= level(c, a) > FHE_LEVEL_MAX;
  s.lut = id;
  emit(c, s, 1u);
}

static void badd(FheCircuit *c, FheReg dst, FheReg x, FheReg y) {
  emit(c, stmt(FHE_BADD, dst, x, y, 0), level(c, x) + level(c, y));
}

/* tauE (Option DecE, 4 options) and tauA (Option BallotA, 3 options): x<i>_<j>
 * is bit j of the one-hot ballot i, and count j is the sum of bit j of each
 * ballot. The terms are r0 to r(N - 1), for each count again. */
static void build_tally(FheCircuit *c, unsigned n, unsigned options) {
  FheReg count[4], first = {FHE_RADIX_REG, 0};
  char name[FHE_NAME_BYTES];
  unsigned i, j;
  c->failed |= n == 0 || n > FHE_N_MAX;
  for (i = 0; i < n * options && !c->failed; i++) {
    snprintf(name, sizeof name, "x%u_%u", i / options, i % options);
    input(c, FHE_BLOCK_IN, name);
  }
  for (i = 0; i < n && !c->failed; i++) new_reg(c, FHE_RADIX_REG);
  for (j = 0; j < options; j++) count[j] = new_reg(c, FHE_RADIX_REG);
  for (j = 0; j < options && !c->failed; j++) {
    for (i = 0; i < n; i++) {
      FheReg bit = {FHE_BLOCK_IN, i * options + j}, term = {FHE_RADIX_REG, i};
      rmul(c, term, bit, lit(1));
    }
    rsum(c, count[j], first, n);
    output(c, count[j]);
  }
}

/* ruleApply (ruleThreshold t): decRelease when t <= cRel, else decRefund
 * when t <= cRef, else decHold. */
static void build_theta(FheCircuit *c) {
  FheReg rel = input(c, FHE_RADIX_IN, "cRel"), ref = input(c, FHE_RADIX_IN, "cRef");
  FheClear t = param(c, "t");
  FheReg tr = new_reg(c, FHE_RADIX_REG), b1 = new_reg(c, FHE_BLOCK_REG), b2 = new_reg(c, FHE_BLOCK_REG);
  FheReg p = new_reg(c, FHE_BLOCK_REG), d = new_reg(c, FHE_BLOCK_REG);
  trivial(c, tr, t);
  rle(c, b1, tr, rel);
  rle(c, b2, tr, ref);
  pair(c, p, b1, b2);
  lut(c, d, p, FHE_LUT_THETA);
  output(c, d);
}

/* The settle bits (note L550, L551) of the DecE code d: r (release), rf
 * (refund) and z = r + rf, 1 at release or refund and 0 at hold. */
static void build_settle(FheCircuit *c) {
  FheReg d = input(c, FHE_BLOCK_IN, "d");
  FheReg r = new_reg(c, FHE_BLOCK_REG), rf = new_reg(c, FHE_BLOCK_REG), z = new_reg(c, FHE_BLOCK_REG);
  lut(c, r, d, FHE_LUT_ISREL);
  lut(c, rf, d, FHE_LUT_ISREF);
  badd(c, z, r, rf);
  output(c, r);
  output(c, rf);
  output(c, z);
}

/* ledgerAdd at release (the payee q) and at refund (the payer p), mod 2^64
 * (note L552, L553): q' = q + r amount, p' = p + rf amount. */
static void build_credit(FheCircuit *c) {
  FheReg q = input(c, FHE_RADIX_IN, "q"), p = input(c, FHE_RADIX_IN, "p");
  FheReg r = input(c, FHE_BLOCK_IN, "r"), rf = input(c, FHE_BLOCK_IN, "rf");
  FheClear amount = param(c, "amount");
  FheReg m1 = new_reg(c, FHE_RADIX_REG), q2 = new_reg(c, FHE_RADIX_REG);
  FheReg m2 = new_reg(c, FHE_RADIX_REG), p2 = new_reg(c, FHE_RADIX_REG);
  rmul(c, m1, r, amount);
  radd(c, q2, q, m1);
  rmul(c, m2, rf, amount);
  radd(c, p2, p, m2);
  output(c, q2);
  output(c, p2);
}

/* ledgerSub (note L560, L561): ok = amount <= a, and a' = a + ok (2^64 -
 * amount), that is a - amount when ok = 1, else a. */
static void build_withdraw(FheCircuit *c) {
  FheReg a = input(c, FHE_RADIX_IN, "a");
  FheClear amount = param(c, "amount");
  FheReg tr = new_reg(c, FHE_RADIX_REG), ok = new_reg(c, FHE_BLOCK_REG);
  FheReg m = new_reg(c, FHE_RADIX_REG), a2 = new_reg(c, FHE_RADIX_REG);
  trivial(c, tr, amount);
  rle(c, ok, tr, a);
  rmul(c, m, ok, neg(amount));
  radd(c, a2, a, m);
  output(c, ok);
  output(c, a2);
}

/* amdThreshold n tA: amendAdopt when tA <= cAdopt, else amendReject when
 * slack < cReject (slack = natSub n tA, from the caller), else amendHold.
 * b2 = (cReject <= slack) is the inverse of the reject test. */
static void build_amd(FheCircuit *c) {
  FheReg adopt = input(c, FHE_RADIX_IN, "cAdopt"), reject = input(c, FHE_RADIX_IN, "cReject");
  FheClear ta = param(c, "tA"), slack = param(c, "slack");
  FheReg tr = new_reg(c, FHE_RADIX_REG), b1 = new_reg(c, FHE_BLOCK_REG), sr = new_reg(c, FHE_RADIX_REG);
  FheReg b2 = new_reg(c, FHE_BLOCK_REG), p = new_reg(c, FHE_BLOCK_REG), code = new_reg(c, FHE_BLOCK_REG);
  trivial(c, tr, ta);
  rle(c, b1, tr, adopt);
  trivial(c, sr, slack);
  rle(c, b2, reject, sr);
  pair(c, p, b1, b2);
  lut(c, code, p, FHE_LUT_AMD);
  output(c, code);
}

/* The refresh row: x a + y 2. rmul(x, a) has level 3 and rmul(y, 2) level
 * 2, so the radd needs one refresh (3 + 2 + 1 = 6). */
static void build_mix(FheCircuit *c) {
  FheReg x = input(c, FHE_BLOCK_IN, "x"), y = input(c, FHE_BLOCK_IN, "y");
  FheClear a = param(c, "a");
  FheReg m1 = new_reg(c, FHE_RADIX_REG), m2 = new_reg(c, FHE_RADIX_REG), s = new_reg(c, FHE_RADIX_REG);
  rmul(c, m1, x, a);
  rmul(c, m2, y, lit(2));
  radd(c, s, m1, m2);
  output(c, s);
}

int fhe_build(FheCircuit *c, FheKind kind, unsigned n) {
  static const char *const names[] = {"tally4", "tally3", "theta", "settle", "credit", "withdraw", "amd", "mix"};
  memset(c, 0, sizeof *c);
  snprintf(c->name, sizeof c->name, "%s", names[kind]);
  switch (kind) {
  case FHE_TALLY4:
    build_tally(c, n, 4u);
    break;
  case FHE_TALLY3:
    build_tally(c, n, 3u);
    break;
  case FHE_THETA:
    build_theta(c);
    break;
  case FHE_SETTLE:
    build_settle(c);
    break;
  case FHE_CREDIT:
    build_credit(c);
    break;
  case FHE_WITHDRAW:
    build_withdraw(c);
    break;
  case FHE_AMD:
    build_amd(c);
    break;
  case FHE_MIX:
    build_mix(c);
    break;
  }
  return !c->failed;
}

/* The name of R: the input name, or r<i>, b<i> (in BUF). */
static const char *reg_name(const FheCircuit *c, FheReg r, char buf[FHE_NAME_BYTES]) {
  switch (r.slot) {
  case FHE_RADIX_IN:
    return c->radix_in[r.index];
  case FHE_BLOCK_IN:
    return c->block_in[r.index];
  case FHE_RADIX_REG:
    snprintf(buf, FHE_NAME_BYTES, "r%u", r.index);
    return buf;
  case FHE_BLOCK_REG:
    snprintf(buf, FHE_NAME_BYTES, "b%u", r.index);
    return buf;
  }
  return "?";
}

static const char *clear_text(const FheCircuit *c, FheClear v, char buf[32]) {
  switch (v.kind) {
  case FHE_LIT:
    snprintf(buf, 32, "%llu", (unsigned long long)v.value);
    return buf;
  case FHE_PARAM:
    return c->param[v.value];
  case FHE_NEG_PARAM:
    snprintf(buf, 32, "2^64 - %s", c->param[v.value]);
    return buf;
  }
  return "?";
}

static void stmt_text(const FheCircuit *c, const FheStmt *s, char *line, size_t size) {
  static const char *const ops[] = {"trivial", "rmul", "radd", "rsum", "rle", "pair", "lut", "badd", "refresh"};
  char d[FHE_NAME_BYTES], a[FHE_NAME_BYTES], b[FHE_NAME_BYTES], v[32];
  FheReg last = s->a;
  const char *dn = reg_name(c, s->dst, d), *an = reg_name(c, s->a, a);
  switch (s->op) {
  case FHE_TRIVIAL:
    snprintf(line, size, "%s := trivial %s", dn, clear_text(c, s->c, v));
    return;
  case FHE_RMUL:
    snprintf(line, size, "%s := rmul(%s, %s)", dn, an, clear_text(c, s->c, v));
    return;
  case FHE_RSUM:
    last.index += s->count - 1u;
    snprintf(line, size, "%s := rsum(%s .. %s)", dn, an, reg_name(c, last, b));
    return;
  case FHE_LUT:
    snprintf(line, size, "%s := lut(%s, %s)", dn, an, LUT_NAMES[s->lut]);
    return;
  case FHE_REFRESH:
    snprintf(line, size, "%s := refresh(%s)", dn, an);
    return;
  case FHE_RADD:
  case FHE_RLE:
  case FHE_PAIR:
  case FHE_BADD:
    snprintf(line, size, "%s := %s(%s, %s)", dn, ops[s->op], an, reg_name(c, s->b, b));
    return;
  }
}

void fhe_print(const FheCircuit *c, FILE *out) {
  char line[96], name[FHE_NAME_BYTES];
  unsigned i;
  fprintf(out, "circuit %s (", c->name);
  for (i = 0; i < c->radix_ins; i++) fprintf(out, "%sradix %s", i == 0 ? "" : ", ", c->radix_in[i]);
  for (i = 0; i < c->block_ins; i++) fprintf(out, "%sblock %s", i + c->radix_ins == 0 ? "" : ", ", c->block_in[i]);
  for (i = 0; i < c->params; i++) fprintf(out, "%sclear %s", i == 0 ? "; " : ", ", c->param[i]);
  fputs(c->outs > 1u ? ") -> (" : ") -> ", out);
  for (i = 0; i < c->outs; i++) {
    fprintf(out, "%s%s", i == 0 ? "" : ", ", c->out[i].slot == FHE_RADIX_REG ? "radix" : "block");
  }
  fprintf(out, "%s, %u PBS\n", c->outs > 1u ? ")" : "", c->pbs);
  for (i = 0; i < c->stmts; i++) {
    stmt_text(c, &c->stmt[i], line, sizeof line);
    if (c->stmt[i].pbs == 0)
      fprintf(out, "  %s\n", line);
    else
      fprintf(out, "  %-34s %u\n", line, c->stmt[i].pbs);
  }
  fputs("  return", out);
  for (i = 0; i < c->outs; i++) fprintf(out, "%s%s", i == 0 ? " " : ", ", reg_name(c, c->out[i], name));
  fputs("\n", out);
}

void fhe_luts(FheLuts *l) {
  uint8_t table[FHE_LUTS][TFHE_PLAIN];
  unsigned v, id;
  for (v = 0; v < TFHE_PLAIN; v++) {
    unsigned h = v / TFHE_MSG_MOD, lo = v % TFHE_MSG_MOD;
    table[FHE_LUT_THETA][v] = (uint8_t)(h == 1u ? 0u : lo == 1u ? 1u : 2u);
    table[FHE_LUT_ISREL][v] = (uint8_t)(v == 0u);
    table[FHE_LUT_ISREF][v] = (uint8_t)(v == 1u);
    table[FHE_LUT_AMD][v] = (uint8_t)(h == 1u ? 0u : lo == 0u ? 1u : 2u);
  }
  for (id = 0; id < FHE_LUTS; id++) tfhe_lut(l->lut[id], table[id]);
}

static const TfheRadix *radix_get(const FheEval *e, FheReg r) {
  return r.slot == FHE_RADIX_IN ? &e->rin[r.index] : &e->radix[r.index];
}

static const uint64_t *block_get(const FheEval *e, FheReg r) {
  return r.slot == FHE_BLOCK_IN ? e->bin[r.index] : e->block[r.index];
}

static uint64_t clear_get(const FheEval *e, FheClear v) {
  switch (v.kind) {
  case FHE_LIT:
    return v.value;
  case FHE_PARAM:
    return e->param[v.value];
  case FHE_NEG_PARAM:
    return 0u - e->param[v.value];
  }
  return 0;
}

/* The propagations of tfhe_radix_sum on M terms: after each third added
 * term and after the last term. */
static unsigned sum_pbs(size_t m) {
  size_t i;
  unsigned pbs = 0;
  for (i = 1; i < m; i++) pbs += i % 3u == 0 || i + 1u == m ? TFHE_PROPAGATE_PBS : 0u;
  return pbs;
}

static void eval_stmt(FheEval *e, const FheStmt *s) {
  uint64_t tmp[TFHE_BLOCK_WORDS];
  unsigned i;
  switch (s->op) {
  case FHE_TRIVIAL:
    tfhe_radix_trivial(&e->radix[s->dst.index], clear_get(e, s->c));
    return;
  case FHE_RMUL:
    tfhe_radix_scalar_mul(&e->radix[s->dst.index], block_get(e, s->a), clear_get(e, s->c));
    return;
  case FHE_RADD:
    tfhe_radix_add(e->f, &e->radix[s->dst.index], radix_get(e, s->a), radix_get(e, s->b), e->k, e->rl);
    e->pbs += TFHE_PROPAGATE_PBS;
    return;
  case FHE_RSUM:
    tfhe_radix_sum(e->f, &e->radix[s->dst.index], radix_get(e, s->a), s->count, e->k, e->rl);
    e->pbs += sum_pbs(s->count);
    return;
  case FHE_RLE:
    tfhe_radix_le(e->f, e->block[s->dst.index], radix_get(e, s->a), radix_get(e, s->b), e->k, e->rl);
    e->pbs += TFHE_LE_PBS;
    return;
  case FHE_PAIR:
    memcpy(e->block[s->dst.index], block_get(e, s->a), sizeof tmp);
    tfhe_block_scale(e->block[s->dst.index], TFHE_MSG_MOD);
    tfhe_block_add(e->block[s->dst.index], block_get(e, s->b));
    return;
  case FHE_LUT:
    tfhe_pbs(e->f, e->block[s->dst.index], block_get(e, s->a), e->k, e->l->lut[s->lut]);
    e->pbs += 1u;
    return;
  case FHE_BADD:
    memcpy(e->block[s->dst.index], block_get(e, s->a), sizeof tmp);
    tfhe_block_add(e->block[s->dst.index], block_get(e, s->b));
    return;
  case FHE_REFRESH:
    for (i = 0; i < TFHE_RADIX_BLOCKS; i++) {
      tfhe_pbs(e->f, tmp, e->radix[s->dst.index].block[i], e->k, e->rl->lut[TFHE_LUT_MSG]);
      memcpy(e->radix[s->dst.index].block[i], tmp, sizeof tmp);
      e->pbs += 1u;
    }
    return;
  }
}

void fhe_eval(FheEval *e, const FheCircuit *c) {
  unsigned i;
  e->pbs = 0;
  for (i = 0; i < c->stmts; i++) eval_stmt(e, &c->stmt[i]);
}
