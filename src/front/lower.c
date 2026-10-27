/* The lowering from checked values to the first-order IR. SHARED by the tcc
   kits.

   Each entry is evaluated on variables for its parameters. The normal form
   is the residual program, and this file writes it as IR statements. Each
   value becomes an Operand: a word and a trap flag (see src/ir.h). An
   eliminator on a heap value loads the tag and the fields of the block,
   behind a guard on the trap flag. A fold over a list or a linear family
   walks the spine into a reversed chain, then folds the chain from its last
   node. The chain is a list: a block [1, word, flag, rest, 0]. */
#include "front/lower.h"

#include <string.h>

#include "front/check.h"

#define IR_PRINT_DEPTH_MAX 4000u

/* A value at run time: its word and its trap flag. Each part is a constant
   or a local. */
typedef struct {
  const IrExpr *w;
  const IrExpr *f;
} Operand;

/* The two locals of a result. */
typedef struct {
  uint32_t w;
  uint32_t f;
} Slot;

typedef struct Buf Buf;

/* The operand of a value lowered earlier: one lowering per Value pointer
   (flag 51). A block finds the entries of its own memo and of the blocks it
   is placed in (flag 52), so a local set in a sibling arm is never read. */
typedef struct {
  const Value *key;
  Operand op;
} Memo;

struct Buf {
  const IrStmt **items;
  size_t count;
  size_t cap;
  const Buf *parent; /* the block this one is placed in, or NULL */
  Memo *memo;        /* open addressing on the Value pointer */
  size_t memo_count;
  size_t memo_cap; /* 0 or a power of two */
};

typedef struct {
  Machine *m;
  uint32_t local_count;
  Operand *levels; /* the operand of each de Bruijn level */
  uint32_t level_count;
  uint32_t level_cap;
} Low;

static int oom(Low *l) {
  return diag_fail(l->m->diag, "OOM", l->m->def, "out of memory");
}

static int internal(Low *l, const char *what) {
  return diag_fail(l->m->diag, "INTERNAL", l->m->def, "the lowering found %s", what);
}

static IrExpr *expr_alloc(Low *l, IrExprKind kind) {
  IrExpr *e = arena_alloc(l->m->arena, sizeof *e);
  if (e == NULL)
    oom(l);
  else
    e->kind = kind;
  return e;
}

static const IrExpr *ex_const(Low *l, uint64_t value) {
  IrExpr *e = expr_alloc(l, IR_EXPR_CONST);
  if (e != NULL)
    e->value = value;
  return e;
}

static const IrExpr *ex_local(Low *l, uint32_t local) {
  IrExpr *e = expr_alloc(l, IR_EXPR_LOCAL);
  if (e != NULL)
    e->local = local;
  return e;
}

static const IrExpr *ex_bin(Low *l, IrOp op, const IrExpr *a, const IrExpr *b) {
  IrExpr *e = a == NULL || b == NULL ? NULL : expr_alloc(l, IR_EXPR_BINARY);
  if (e == NULL)
    return NULL;
  e->op = op;
  e->left = a;
  e->right = b;
  return e;
}

/* Word WORD of the block at ADDR. */
static const IrExpr *ex_load(Low *l, const IrExpr *addr, uint32_t word) {
  IrExpr *e = addr == NULL ? NULL : expr_alloc(l, IR_EXPR_LOAD);
  if (e == NULL)
    return NULL;
  e->left = addr;
  e->field = word;
  return e;
}

static int is_const(const IrExpr *e, uint64_t value) {
  return e != NULL && e->kind == IR_EXPR_CONST && e->value == value;
}

/* The or of two flags. A constant flag folds away. */
static const IrExpr *ex_or(Low *l, const IrExpr *a, const IrExpr *b) {
  if (a == NULL || b == NULL)
    return NULL;
  if (is_const(a, 0) || is_const(b, 1))
    return b;
  if (is_const(b, 0) || is_const(a, 1))
    return a;
  return ex_bin(l, IR_OP_OR, a, b);
}

static Operand operand(const IrExpr *w, const IrExpr *f) {
  Operand o;
  o.w = w;
  o.f = f;
  return o;
}

static int give(Low *l, Operand *out, uint64_t w, uint64_t f) {
  *out = operand(ex_const(l, w), ex_const(l, f));
  return out->w != NULL && out->f != NULL;
}

static Operand trap_value(Low *l) {
  return operand(ex_const(l, 0), ex_const(l, 1));
}

static uint32_t local_new(Low *l) {
  return l->local_count++;
}

static Slot slot_new(Low *l) {
  Slot s;
  s.w = local_new(l);
  s.f = local_new(l);
  return s;
}

static Operand slot_get(Low *l, Slot s) {
  return operand(ex_local(l, s.w), ex_local(l, s.f));
}

/* A new block, placed in PARENT (NULL for the body of an entry). */
static Buf buf_under(const Buf *parent) {
  Buf b;
  memset(&b, 0, sizeof b);
  b.parent = parent;
  return b;
}

/* The slot of KEY in MEMO (CAP entries): its entry, or the free slot
   where it goes. */
static size_t memo_slot(const Memo *memo, size_t cap, const Value *key) {
  size_t i = (((size_t)(uintptr_t)key) >> 4) * 2654435761u & (cap - 1u);
  while (memo[i].key != NULL && memo[i].key != key)
    i = (i + 1u) & (cap - 1u);
  return i;
}

/* 1 and OUT when V was lowered into B or into a block B is placed in. */
static int memo_find(const Buf *b, const Value *v, Operand *out) {
  size_t i;
  for (; b != NULL; b = b->parent) {
    if (b->memo_cap == 0)
      continue;
    i = memo_slot(b->memo, b->memo_cap, v);
    if (b->memo[i].key == v) {
      *out = b->memo[i].op;
      return 1;
    }
  }
  return 0;
}

static int memo_grow(Low *l, Buf *b) {
  size_t cap = b->memo_cap == 0 ? 16u : b->memo_cap * 2u;
  Memo *grown = arena_alloc(l->m->arena, cap * sizeof *grown);
  size_t i;
  if (grown == NULL)
    return oom(l);
  memset(grown, 0, cap * sizeof *grown);
  for (i = 0; i < b->memo_cap; i++)
    if (b->memo[i].key != NULL)
      grown[memo_slot(grown, cap, b->memo[i].key)] = b->memo[i];
  b->memo = grown;
  b->memo_cap = cap;
  return 1;
}

/* Records V as O in the memo of B. The table stays at most half full. */
static int memo_put(Low *l, Buf *b, const Value *v, Operand o) {
  size_t i;
  if (2u * (b->memo_count + 1u) > b->memo_cap && !memo_grow(l, b))
    return 0;
  i = memo_slot(b->memo, b->memo_cap, v);
  if (b->memo[i].key == NULL)
    b->memo_count++;
  b->memo[i].key = v;
  b->memo[i].op = o;
  return 1;
}

/* A value with a lowering worth one memo entry: an operation or a stuck
   operation (flag 54). A number, a type, a variable and a closure are
   constants, a level or a diagnostic. */
static int memo_kind(const Value *v) {
  return v->kind == VAL_OP || v->kind == VAL_STUCK;
}

static int buf_grow(Low *l, Buf *b) {
  size_t cap = b->cap == 0 ? 8u : b->cap * 2u;
  const IrStmt **grown = arena_alloc(l->m->arena, cap * sizeof *grown);
  size_t i;
  if (grown == NULL)
    return oom(l);
  for (i = 0; i < b->count; i++)
    grown[i] = b->items[i];
  b->items = grown;
  b->cap = cap;
  return 1;
}

static int emit(Low *l, Buf *b, const IrStmt *s) {
  if (s == NULL || (b->count == b->cap && !buf_grow(l, b)))
    return 0;
  b->items[b->count++] = s;
  return 1;
}

static int splice(Low *l, Buf *b, const Buf *in) {
  size_t i;
  for (i = 0; i < in->count; i++)
    if (!emit(l, b, in->items[i]))
      return 0;
  return 1;
}

static IrBlock block_of(const Buf *b) {
  IrBlock out;
  out.items = b->items;
  out.count = b->count;
  return out;
}

static IrStmt *stmt_new(Low *l, IrStmtKind kind) {
  IrStmt *s = arena_alloc(l->m->arena, sizeof *s);
  if (s == NULL)
    oom(l);
  else
    s->kind = kind;
  return s;
}

/* A statement that reads the expression E. */
static IrStmt *stmt_expr(Low *l, IrStmtKind kind, const IrExpr *e) {
  IrStmt *s = e == NULL ? NULL : stmt_new(l, kind);
  if (s != NULL)
    s->expr = e;
  return s;
}

static int set(Low *l, Buf *b, uint32_t local, const IrExpr *e) {
  IrStmt *s = stmt_expr(l, IR_STMT_SET, e);
  if (s != NULL)
    s->local = local;
  return emit(l, b, s);
}

/* DST := SRC. A flag that reads the word local of DST goes through a
   temporary, so a loop-carried update stays correct. */
static int store(Low *l, Buf *b, Slot dst, Operand src) {
  uint32_t t;
  if (src.w == NULL || src.f == NULL)
    return 0;
  if (src.f->kind == IR_EXPR_LOCAL && src.f->local == dst.w) {
    t = local_new(l);
    return set(l, b, t, src.f) && set(l, b, dst.w, src.w) && set(l, b, dst.f, ex_local(l, t));
  }
  return set(l, b, dst.w, src.w) && set(l, b, dst.f, src.f);
}

/* E as a constant or a local. */
static const IrExpr *atom(Low *l, Buf *b, const IrExpr *e) {
  uint32_t t;
  if (e == NULL || e->kind == IR_EXPR_CONST || e->kind == IR_EXPR_LOCAL)
    return e;
  t = local_new(l);
  return set(l, b, t, e) ? ex_local(l, t) : NULL;
}

static int atoms(Low *l, Buf *b, const IrExpr *w, const IrExpr *f, Operand *out) {
  out->w = atom(l, b, w);
  out->f = atom(l, b, f);
  return out->w != NULL && out->f != NULL;
}

static int st_if(Low *l, Buf *b, const IrExpr *c, const Buf *yes, const Buf *no) {
  IrStmt *s = stmt_expr(l, IR_STMT_IF, c);
  if (s == NULL)
    return 0;
  s->body = block_of(yes);
  s->otherwise = block_of(no);
  return emit(l, b, s);
}

/* IF F {YES} ELSE {NO}. A constant F keeps one block. */
static int if_flag(Low *l, Buf *b, const IrExpr *f, const Buf *yes, const Buf *no) {
  if (f == NULL)
    return 0;
  if (is_const(f, 0) || is_const(f, 1))
    return splice(l, b, is_const(f, 1) ? yes : no);
  return st_if(l, b, f, yes, no);
}

/* Runs IN when the trap flag F is 0. When F is 1, RES gets the trap. */
static int guard(Low *l, Buf *b, const IrExpr *f, Slot res, const Buf *in) {
  Buf trap = buf_under(b);
  return store(l, &trap, res, trap_value(l)) && if_flag(l, b, f, &trap, in);
}

static int st_switch(Low *l, Buf *b, const IrExpr *e, const IrBlock *arms, size_t n) {
  IrStmt *s = stmt_expr(l, IR_STMT_SWITCH, e);
  if (s == NULL)
    return 0;
  s->arms = arms;
  s->arm_count = n;
  return emit(l, b, s);
}

/* REPEAT COUNT {BODY}, with a new counter local. */
static int st_repeat(Low *l, Buf *b, const IrExpr *count, const Buf *body) {
  IrStmt *s = stmt_expr(l, IR_STMT_REPEAT, count);
  if (s == NULL)
    return 0;
  s->counter = local_new(l);
  s->body = block_of(body);
  return emit(l, b, s);
}

/* WHILE COUNT, LOCAL {BODY}, with a new counter local. */
static int st_while(Low *l, Buf *b, const IrExpr *count, uint32_t local, const Buf *body) {
  IrStmt *s = stmt_expr(l, IR_STMT_WHILE, count);
  if (s == NULL)
    return 0;
  s->counter = local_new(l);
  s->local = local;
  s->body = block_of(body);
  return emit(l, b, s);
}

/* A new block [TAG, the word and the flag of each of the N operands]. */
static int block_ops(Low *l, Buf *b, uint64_t tag, const Operand *ops, uint32_t n, Operand *out) {
  const IrExpr **fields = arena_alloc(l->m->arena, (2u * (size_t)n + 1u) * sizeof *fields);
  IrStmt *s = stmt_new(l, IR_STMT_ALLOC);
  uint32_t i;
  if (fields == NULL || s == NULL)
    return fields == NULL ? oom(l) : 0;
  fields[0] = ex_const(l, tag);
  for (i = 0; i < n; i++) {
    fields[1u + 2u * i] = ops[i].w;
    fields[2u + 2u * i] = ops[i].f;
  }
  s->local = local_new(l);
  s->fields = fields;
  s->field_count = 2u * (size_t)n + 1u;
  *out = operand(ex_local(l, s->local), ex_const(l, 0));
  return fields[0] != NULL && emit(l, b, s);
}

/* The operand of field K of the block at ADDR. */
static Operand field_op(Low *l, const IrExpr *addr, uint32_t k) {
  return operand(ex_load(l, addr, 1u + 2u * k), ex_load(l, addr, 2u + 2u * k));
}

/* Field K of the block at ADDR, copied into two new locals. */
static int field_at(Low *l, Buf *b, const IrExpr *addr, uint32_t k, Operand *out) {
  Slot s = slot_new(l);
  *out = slot_get(l, s);
  return store(l, b, s, field_op(l, addr, k));
}

static int levels_grow(Low *l) {
  uint32_t cap = l->level_cap == 0 ? 64u : l->level_cap * 2u;
  Operand *grown = arena_alloc(l->m->arena, (size_t)cap * sizeof *grown);
  uint32_t i;
  if (grown == NULL)
    return oom(l);
  for (i = 0; i < l->level_count; i++)
    grown[i] = l->levels[i];
  l->levels = grown;
  l->level_cap = cap;
  return 1;
}

/* A new variable that stands for the operand O. Levels never repeat. */
static const Value *fresh(Low *l, Operand o) {
  if (o.w == NULL || o.f == NULL || (l->level_count == l->level_cap && !levels_grow(l)))
    return NULL;
  l->levels[l->level_count] = o;
  return val_var(l->m, l->level_count++);
}

static const char *op_word(IrOp op) {
  switch (op) {
  case IR_OP_ADD:
    return "add";
  case IR_OP_SUB:
    return "sub";
  case IR_OP_MUL:
    return "mul";
  case IR_OP_EQ:
    return "eq";
  case IR_OP_LE:
    return "le";
  case IR_OP_ADD_CARRY:
    return "add_carry";
  case IR_OP_MUL_CARRY:
    return "mul_carry";
  case IR_OP_OR:
    return "or";
  }
  return "?";
}

static void expr_print(const IrExpr *e, FILE *out, unsigned depth) {
  if (depth > IR_PRINT_DEPTH_MAX) {
    fputs("...", out);
    return;
  }
  switch (e->kind) {
  case IR_EXPR_CONST:
    fprintf(out, "%llu", (unsigned long long)e->value);
    return;
  case IR_EXPR_LOCAL:
    fprintf(out, "l%u", (unsigned)e->local);
    return;
  case IR_EXPR_BINARY:
    fprintf(out, "%s(", op_word(e->op));
    expr_print(e->left, out, depth + 1u);
    fputs(", ", out);
    expr_print(e->right, out, depth + 1u);
    fputs(")", out);
    return;
  case IR_EXPR_LOAD:
    fputs("load(", out);
    expr_print(e->left, out, depth + 1u);
    fprintf(out, ", %u)", (unsigned)e->field);
    return;
  }
}

static void block_print(const IrBlock *b, FILE *out, unsigned depth);

static void indent(FILE *out, unsigned depth) {
  fprintf(out, "%*s", (int)(2u * depth), "");
}

static void close_print(FILE *out, unsigned depth) {
  indent(out, depth);
  fputs("}\n", out);
}

static void stmt_print(const IrStmt *s, FILE *out, unsigned depth) {
  size_t i;
  indent(out, depth);
  switch (s->kind) {
  case IR_STMT_SET:
    fprintf(out, "l%u := ", (unsigned)s->local);
    expr_print(s->expr, out, 0);
    fputs("\n", out);
    return;
  case IR_STMT_ALLOC:
    fprintf(out, "l%u := alloc [", (unsigned)s->local);
    for (i = 0; i < s->field_count; i++) {
      fputs(i == 0 ? "" : ", ", out);
      expr_print(s->fields[i], out, 0);
    }
    fputs("]\n", out);
    return;
  case IR_STMT_IF:
    fputs("if ", out);
    expr_print(s->expr, out, 0);
    fputs(" {\n", out);
    block_print(&s->body, out, depth + 1u);
    indent(out, depth);
    fputs("} else {\n", out);
    block_print(&s->otherwise, out, depth + 1u);
    close_print(out, depth);
    return;
  case IR_STMT_SWITCH:
    fputs("switch ", out);
    expr_print(s->expr, out, 0);
    fputs(" {\n", out);
    for (i = 0; i < s->arm_count; i++) {
      indent(out, depth);
      fprintf(out, "arm %zu:\n", i);
      block_print(&s->arms[i], out, depth + 1u);
    }
    close_print(out, depth);
    return;
  case IR_STMT_REPEAT:
    fprintf(out, "repeat l%u := ", (unsigned)s->counter);
    expr_print(s->expr, out, 0);
    fputs(" {\n", out);
    block_print(&s->body, out, depth + 1u);
    close_print(out, depth);
    return;
  case IR_STMT_WHILE:
    fprintf(out, "while l%u := ", (unsigned)s->counter);
    expr_print(s->expr, out, 0);
    fprintf(out, ", l%u {\n", (unsigned)s->local);
    block_print(&s->body, out, depth + 1u);
    close_print(out, depth);
    return;
  case IR_STMT_TRAP:
    fputs("trap\n", out);
    return;
  case IR_STMT_RETURN:
    fputs("return ", out);
    expr_print(s->expr, out, 0);
    fputs("\n", out);
    return;
  }
}

static void block_print(const IrBlock *b, FILE *out, unsigned depth) {
  size_t i;
  if (depth > IR_PRINT_DEPTH_MAX) {
    fputs("...\n", out);
    return;
  }
  for (i = 0; i < b->count; i++)
    stmt_print(b->items[i], out, depth);
}

static const char *scalar_word(IrScalar s) {
  switch (s) {
  case IR_SCALAR_NAT:
    return "nat";
  case IR_SCALAR_FLAG:
    return "flag";
  }
  return "?";
}

void ir_print(const IrProgram *prog, FILE *out) {
  size_t i;
  size_t k;
  for (i = 0; i < prog->func_count; i++) {
    const IrFunc *fn = &prog->funcs[i];
    fprintf(out, "func %s (", fn->name);
    for (k = 0; k < fn->param_count; k++)
      fprintf(out, "%s%s", k == 0 ? "" : ", ", scalar_word(fn->params[k]));
    fprintf(out, ") -> %s, %u locals\n", scalar_word(fn->result), (unsigned)fn->local_count);
    block_print(&fn->body, out, 1u);
  }
}

static int lower(Low *l, Buf *b, const Value *v, Operand *out);

static int closure(Low *l) {
  return diag_fail(l->m->diag, "REFUSE_RUNTIME_CLOSURE", l->m->def, "a function value must exist at run time (HOST-LIMIT)");
}

/* 1 when the evaluator gave a value, else 0 after a diagnostic. */
static int got(Low *l, const Value *v) {
  return v != NULL ? 1 : (l->m->diag->set ? 0 : internal(l, "a missing value"));
}

/* RES := the lowering of V. */
static int lower_into(Low *l, Buf *b, const Value *v, Slot res) {
  Operand o;
  return lower(l, b, v, &o) && store(l, b, res, o);
}

/* RES := FN applied to N new variables, one for each operand of ARGS. */
static int apply_into(Low *l, Buf *b, const Value *fn, const Operand *args, uint32_t n, Slot res) {
  const Value *v = fn;
  const Value *x;
  uint32_t i;
  for (i = 0; i < n && v != NULL; i++) {
    x = fresh(l, args[i]);
    v = x == NULL ? NULL : apply_value(l->m, v, x);
  }
  return got(l, v) && lower_into(l, b, v, res);
}

/* A new block [TAG, the lowering of each of the N values of ARGS]. */
static int ctor_block(Low *l, Buf *b, uint64_t tag, const Value *const *args, uint32_t n, Operand *out) {
  Operand *ops = arena_alloc(l->m->arena, ((size_t)n + 1u) * sizeof *ops);
  uint32_t i;
  if (ops == NULL)
    return oom(l);
  for (i = 0; i < n; i++)
    if (!lower(l, b, args[i], &ops[i]))
      return 0;
  return block_ops(l, b, tag, ops, n, out);
}

/* A constructor with fewer arguments than its arity is a function. */
static int ctor_full(Low *l, Buf *b, const Value *v, uint32_t skip, uint32_t n, uint64_t tag, Operand *out) {
  return v->argc < skip + n ? closure(l) : ctor_block(l, b, tag, v->args + skip, n, out);
}

static int lower_ctor(Low *l, Buf *b, const Value *v, Operand *out) {
  const CtorInfo *c = &l->m->ctors[v->inst];
  const FamilyInfo *fam = &l->m->families[c->family];
  return ctor_full(l, b, v, fam->param_count, c->field_count, v->inst - fam->first_ctor, out);
}

/* A canonical value. An eliminator here has too few arguments, so it is a
   function. */
static int lower_canon(Low *l, Buf *b, const Value *v, Operand *out) {
  switch (v->op) {
  case OP_NAT:
  case OP_FLAG:
  case OP_UNIT:
  case OP_PROD:
  case OP_SUM:
  case OP_OPTION:
  case OP_LIST:
  case OP_EQ:
  case OP_FAMILY:
  case OP_UNIT_VAL:
  case OP_FLAG_NO:
  case OP_REFL:
    return give(l, out, 0, 0);
  case OP_FLAG_YES:
    return give(l, out, 1, 0);
  case OP_PAIR:
  case OP_PACK:
    return ctor_full(l, b, v, 0, 2, 0, out);
  case OP_INL:
    return ctor_full(l, b, v, 0, 1, 0, out);
  case OP_INR:
  case OP_SOME:
    return ctor_full(l, b, v, 0, 1, 1, out);
  case OP_NONE:
  case OP_NIL:
    return ctor_full(l, b, v, 0, 0, 0, out);
  case OP_CONS:
    return ctor_full(l, b, v, 0, 2, 1, out);
  case OP_CTOR:
    return lower_ctor(l, b, v, out);
  case OP_FIRST:
  case OP_SECOND:
  case OP_EITHER:
  case OP_OPTION_ELIM:
  case OP_PURE:
  case OP_MAP:
  case OP_BIND:
  case OP_FOLD_NAT:
  case OP_FOLD_LIST:
  case OP_FOLD_FAMILY:
  case OP_UNFOLD:
  case OP_FILTER:
  case OP_WITNESS:
  case OP_PAYLOAD:
  case OP_SYMM:
  case OP_TRANS:
  case OP_TRANSPORT:
  case OP_CONG:
  case OP_NAT_ADD:
  case OP_NAT_SUB:
  case OP_NAT_MUL:
  case OP_NAT_EQ:
  case OP_NAT_LE:
  case OP_FLAG_IF:
  case OP_PROJ:
    return closure(l);
  }
  return internal(l, "an unknown operation");
}

/* A Nat operation. CARRY: OP can overflow, and the overflow sets the flag. */
static int nat_bin(Low *l, Buf *b, const Value *v, IrOp op, int carry, Operand *out) {
  Operand x;
  Operand y;
  const IrExpr *f;
  if (!lower(l, b, v->args[0], &x) || !lower(l, b, v->args[1], &y))
    return 0;
  f = ex_or(l, x.f, y.f);
  if (carry)
    f = ex_or(l, f, ex_bin(l, op == IR_OP_ADD ? IR_OP_ADD_CARRY : IR_OP_MUL_CARRY, x.w, y.w));
  return atoms(l, b, ex_bin(l, op, x.w, y.w), f, out);
}

/* Field K of the block X, behind the guard on the flag of X. */
static int field_of(Low *l, Buf *b, const Value *xv, uint32_t k, Operand *out) {
  Operand x;
  Slot res = slot_new(l);
  Buf in = buf_under(b);
  *out = slot_get(l, res);
  return lower(l, b, xv, &x) && store(l, &in, res, field_op(l, x.w, k)) && guard(l, b, x.f, res, &in);
}

static int flag_if(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand c;
  Slot res = slot_new(l);
  Buf yes = buf_under(b);
  Buf no = buf_under(b);
  Buf in = buf_under(b);
  *out = slot_get(l, res);
  return lower(l, b, v->args[0], &c) && lower_into(l, &yes, v->args[1], res) && lower_into(l, &no, v->args[2], res) &&
         if_flag(l, &in, c.w, &yes, &no) && guard(l, b, c.f, res, &in);
}

/* SWITCH on the tag of X, N arms. Arm I applies CASES[I] to the FIELDS[I]
   fields of the block (with 0 fields, the arm lowers CASES[I]). */
static int cases_of(Low *l, Buf *b, const Value *xv, const Value *const *cases, const uint32_t *fields, uint32_t n, Operand *out) {
  IrBlock *arms = arena_alloc(l->m->arena, ((size_t)n + 1u) * sizeof *arms);
  Operand *args;
  Operand x;
  Slot res = slot_new(l);
  Buf in = buf_under(b);
  Buf arm;
  uint32_t i;
  uint32_t k;
  *out = slot_get(l, res);
  if (arms == NULL)
    return oom(l);
  if (!lower(l, b, xv, &x))
    return 0;
  for (i = 0; i < n; i++) {
    arm = buf_under(b);
    args = arena_alloc(l->m->arena, ((size_t)fields[i] + 1u) * sizeof *args);
    if (args == NULL)
      return oom(l);
    for (k = 0; k < fields[i]; k++)
      if (!field_at(l, &arm, x.w, k, &args[k]))
        return 0;
    if (!apply_into(l, &arm, cases[i], args, fields[i], res))
      return 0;
    arms[i] = block_of(&arm);
  }
  return st_switch(l, &in, ex_load(l, x.w, 0), arms, n) && guard(l, b, x.f, res, &in);
}

static int two_cases(Low *l, Buf *b, const Value *v, uint32_t none_fields, Operand *out) {
  uint32_t fields[2];
  fields[0] = none_fields;
  fields[1] = 1;
  return cases_of(l, b, v->args[2], v->args, fields, 2, out);
}

/* The fuel of a walk over a heap spine. */
#define SPINE_FUEL ((uint64_t)1 << 63)

/* A constructor without a recursive field. */
#define NO_REC UINT32_MAX

/* The recursive field of each list tag: nil has none, cons has the tail. */
static const uint32_t LIST_REC[2] = {NO_REC, 1u};

/* The locals of a walk: the reversed chain, its length, the trap flag of
   the end, the node where the walk stopped, and the WHILE condition. */
typedef struct {
  uint32_t rev;
  uint32_t count;
  uint32_t end;
  uint32_t cur;
  uint32_t cont;
} Walk;

static Walk walk_new(Low *l) {
  Walk w;
  w.rev = local_new(l);
  w.count = local_new(l);
  w.end = local_new(l);
  w.cur = local_new(l);
  w.cont = local_new(l);
  return w;
}

/* REV := a new chain cell [1, the word and the flag of OP, REV, 0], and
   COUNT increases by 1. */
static int chain_push(Low *l, Buf *b, const Walk *w, Operand op) {
  Operand ops[2];
  Operand c;
  ops[0] = op;
  ops[1] = operand(ex_local(l, w->rev), ex_const(l, 0));
  return block_ops(l, b, 1, ops, 2u, &c) && set(l, b, w->rev, c.w) &&
         set(l, b, w->count, ex_bin(l, IR_OP_ADD, ex_local(l, w->count), ex_const(l, 1)));
}

/* A walk step at a node whose recursive field is K: push the node, then go
   to field K. A trapped field ends the walk. */
static int walk_step(Low *l, Buf *b, const Walk *w, uint32_t k) {
  const IrExpr *cur = ex_local(l, w->cur);
  return chain_push(l, b, w, operand(cur, ex_const(l, 0))) && set(l, b, w->end, ex_load(l, cur, 2u + 2u * k)) &&
         set(l, b, w->cur, ex_load(l, cur, 1u + 2u * k)) &&
         set(l, b, w->cont, ex_bin(l, IR_OP_EQ, ex_local(l, w->end), ex_const(l, 0)));
}

/* The spine walk of X. A node with tag I has the recursive field REC[I] (or
   NO_REC). A node with a recursive field goes on the chain. The walk stops
   at a node without one (CUR), or at a trapped field (END = 1). The cell of
   the last node comes first. */
static int walk(Low *l, Buf *b, Operand x, const uint32_t *rec, uint32_t n, Walk *w) {
  IrBlock *arms = arena_alloc(l->m->arena, ((size_t)n + 1u) * sizeof *arms);
  Buf body = buf_under(b);
  Buf arm;
  uint32_t i;
  *w = walk_new(l);
  if (arms == NULL)
    return oom(l);
  for (i = 0; i < n; i++) {
    arm = buf_under(&body);
    if (!(rec[i] == NO_REC ? set(l, &arm, w->cont, ex_const(l, 0)) : walk_step(l, &arm, w, rec[i])))
      return 0;
    arms[i] = block_of(&arm);
  }
  return set(l, b, w->rev, ex_const(l, 0)) && set(l, b, w->count, ex_const(l, 0)) && set(l, b, w->end, x.f) &&
         set(l, b, w->cur, x.w) && set(l, b, w->cont, ex_bin(l, IR_OP_EQ, x.f, ex_const(l, 0))) &&
         st_switch(l, &body, ex_load(l, ex_local(l, w->cur), 0), arms, n) &&
         st_while(l, b, ex_const(l, SPINE_FUEL), w->cont, &body);
}

/* The start of a pass over the chain of W: NODE := word 1 of the cell. */
static int chain_node(Low *l, Buf *body, const Walk *w, const IrExpr **node) {
  uint32_t t = local_new(l);
  *node = ex_local(l, t);
  return set(l, body, t, ex_load(l, ex_local(l, w->rev), 1));
}

/* The start of a pass over a chain of list nodes: H := the head. */
static int chain_head(Low *l, Buf *body, const Walk *w, Operand *h) {
  const IrExpr *node;
  return chain_node(l, body, w, &node) && field_at(l, body, node, 0, h);
}

/* The end of a pass: REV := the next cell, and REPEAT COUNT {BODY}. */
static int chain_end(Low *l, Buf *b, const Walk *w, Buf *body) {
  return set(l, body, w->rev, ex_load(l, ex_local(l, w->rev), 3)) && st_repeat(l, b, ex_local(l, w->count), body);
}

/* OUT := a trap tail when the flag local END is 1, else nil. */
static int tail_init(Low *l, Buf *b, uint32_t end, Slot out) {
  Operand nil;
  Buf in = buf_under(b);
  return block_ops(l, &in, 0, NULL, 0, &nil) && store(l, &in, out, nil) && guard(l, b, ex_local(l, end), out, &in);
}

/* OUT := a new cons cell [1, H, OUT]. */
static int prepend(Low *l, Buf *b, Operand h, Slot out) {
  Operand ops[2];
  Operand c;
  ops[0] = h;
  ops[1] = slot_get(l, out);
  return block_ops(l, b, 1, ops, 2u, &c) && store(l, b, out, c);
}

/* A right fold over a list. F takes the head, then the acc. A trap tail
   gives a trap base acc. */
static int fold_list(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand args[2];
  Walk w;
  Slot acc = slot_new(l);
  Buf in = buf_under(b);
  Buf body = buf_under(b);
  *out = slot_get(l, acc);
  args[1] = slot_get(l, acc);
  return lower(l, b, v->args[2], &x) && walk(l, b, x, LIST_REC, 2u, &w) && lower_into(l, &in, v->args[1], acc) &&
         guard(l, b, ex_local(l, w.end), acc, &in) && chain_head(l, &body, &w, &args[0]) &&
         apply_into(l, &body, v->args[0], args, 2u, acc) && chain_end(l, b, &w, &body);
}

/* MAP on a list. A trap tail stays a trap tail. */
static int list_map(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand h;
  Walk w;
  Slot res = slot_new(l);
  Slot ys = slot_new(l);
  Buf body = buf_under(b);
  *out = slot_get(l, res);
  return lower(l, b, v->args[1], &x) && walk(l, b, x, LIST_REC, 2u, &w) && tail_init(l, b, w.end, res) &&
         chain_head(l, &body, &w, &h) && apply_into(l, &body, v->args[0], &h, 1u, ys) &&
         prepend(l, &body, slot_get(l, ys), res) && chain_end(l, b, &w, &body);
}

/* BIND on a list. The pass starts at the last node, so a result of F with
   a trap tail drops the items after it. */
static int list_bind(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand h;
  Operand y;
  Walk w;
  Walk u;
  Slot res = slot_new(l);
  Slot rs = slot_new(l);
  Buf body = buf_under(b);
  Buf inner = buf_under(&body);
  Buf none = buf_under(&body);
  *out = slot_get(l, res);
  return lower(l, b, v->args[0], &x) && walk(l, b, x, LIST_REC, 2u, &w) && tail_init(l, b, w.end, res) &&
         chain_head(l, &body, &w, &h) && apply_into(l, &body, v->args[1], &h, 1u, rs) &&
         walk(l, &body, slot_get(l, rs), LIST_REC, 2u, &u) && guard(l, &body, ex_local(l, u.end), res, &none) &&
         chain_head(l, &inner, &u, &y) && prepend(l, &inner, y, res) && chain_end(l, &body, &u, &inner) &&
         chain_end(l, b, &w, &body);
}

/* FILTER on a list. The pass starts at the last node, so a trapped test
   drops the items after it: the result is the items kept before the first
   trapped test, then a trap tail. */
static int list_filter(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand h;
  Walk w;
  Slot res = slot_new(l);
  Slot ts = slot_new(l);
  Buf body = buf_under(b);
  Buf keep = buf_under(&body);
  Buf drop = buf_under(&body);
  Buf test = buf_under(&body);
  *out = slot_get(l, res);
  return lower(l, b, v->args[1], &x) && walk(l, b, x, LIST_REC, 2u, &w) && tail_init(l, b, w.end, res) &&
         chain_head(l, &body, &w, &h) && apply_into(l, &body, v->args[0], &h, 1u, ts) && prepend(l, &keep, h, res) &&
         if_flag(l, &test, ex_local(l, ts.w), &keep, &drop) && guard(l, &body, ex_local(l, ts.f), res, &test) &&
         chain_end(l, b, &w, &body);
}

/* An unfold that ends at a trap: END := 1, and the WHILE stops. */
static int unfold_stop(Low *l, Buf *b, const Walk *w) {
  return set(l, b, w->end, ex_const(l, 1)) && set(l, b, w->cont, ex_const(l, 0));
}

/* Push the item of the pair at P, then SEED := the next seed. */
static int unfold_push(Low *l, Buf *b, const Walk *w, const IrExpr *p, Slot seed) {
  Operand a;
  Operand s;
  return field_at(l, b, p, 0, &a) && field_at(l, b, p, 1, &s) && chain_push(l, b, w, a) && store(l, b, seed, s);
}

/* The WHILE body of an unfold: R := G SEED. None stops; a trap or some(trap)
   stops with END = 1; some(pair) pushes the item. */
static int unfold_step(Low *l, Buf *b, const Walk *w, const Value *g, Slot seed) {
  Operand s = slot_get(l, seed);
  Operand p;
  Slot rs = slot_new(l);
  Operand r = slot_get(l, rs);
  Buf stop = buf_under(b);
  Buf stop_some = buf_under(b);
  Buf push = buf_under(b);
  Buf some = buf_under(b);
  Buf none = buf_under(b);
  Buf tag = buf_under(b);
  return apply_into(l, b, g, &s, 1u, rs) && field_at(l, &some, r.w, 0, &p) && unfold_push(l, &push, w, p.w, seed) &&
         unfold_stop(l, &stop_some, w) && if_flag(l, &some, p.f, &stop_some, &push) &&
         set(l, &none, w->cont, ex_const(l, 0)) && if_flag(l, &tag, ex_load(l, r.w, 0), &some, &none) &&
         unfold_stop(l, &stop, w) && if_flag(l, b, r.f, &stop, &tag);
}

/* UNFOLD G LIMIT SEED. The WHILE pushes the items on a chain, then a pass
   from the last item builds the list. A trap limit gives a trap. */
static int unfold(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand lim;
  Operand h;
  Walk w = walk_new(l);
  Slot res = slot_new(l);
  Slot seed = slot_new(l);
  Buf in = buf_under(b);
  Buf step = buf_under(&in);
  Buf body = buf_under(&in);
  *out = slot_get(l, res);
  return lower(l, b, v->args[1], &lim) && set(l, &in, w.rev, ex_const(l, 0)) && set(l, &in, w.count, ex_const(l, 0)) &&
         set(l, &in, w.end, ex_const(l, 0)) && set(l, &in, w.cont, ex_const(l, 1)) &&
         lower_into(l, &in, v->args[2], seed) && unfold_step(l, &step, &w, v->args[0], seed) &&
         st_while(l, &in, lim.w, w.cont, &step) && tail_init(l, &in, w.end, res) &&
         field_at(l, &body, ex_local(l, w.rev), 0, &h) && prepend(l, &body, h, res) && chain_end(l, &in, &w, &body) &&
         guard(l, b, lim.f, res, &in);
}

/* A fold step at the node ADDR of the constructor C: ACC := FN applied to
   the fields, with ACC for the recursive field R. */
static int fam_case(Low *l, Buf *b, const IrExpr *addr, const Value *fn, const CtorInfo *c, uint32_t r, Slot acc) {
  Operand *args = arena_alloc(l->m->arena, ((size_t)c->field_count + 1u) * sizeof *args);
  uint32_t k;
  if (args == NULL)
    return oom(l);
  for (k = 0; k < c->field_count; k++)
    if (k != r && !field_at(l, b, addr, k, &args[k]))
      return 0;
  if (r < c->field_count)
    args[r] = slot_get(l, acc);
  return apply_into(l, b, fn, args, c->field_count, acc);
}

/* SWITCH on the tag of the node at ADDR into ACC. When REC_ARMS is 1, the
   arms of the constructors with a recursive field apply their case (else
   the arms of the ones without). The other arms are not reached; they give
   a trap. */
static int fam_switch(Low *l, Buf *b, const IrExpr *addr, const Value *v, const uint32_t *rec, int rec_arms, Slot acc) {
  const FamilyInfo *fam = &l->m->families[v->inst];
  IrBlock *arms = arena_alloc(l->m->arena, ((size_t)fam->ctor_count + 1u) * sizeof *arms);
  Buf arm;
  uint32_t i;
  if (arms == NULL)
    return oom(l);
  for (i = 0; i < fam->ctor_count; i++) {
    arm = buf_under(b);
    if (!((rec[i] != NO_REC) == rec_arms ? fam_case(l, &arm, addr, v->args[i], &l->m->ctors[fam->first_ctor + i], rec[i], acc)
                                         : store(l, &arm, acc, trap_value(l))))
      return 0;
    arms[i] = block_of(&arm);
  }
  return st_switch(l, b, ex_load(l, addr, 0), arms, fam->ctor_count);
}

/* A fold over a linear family: the walk, the base node into ACC, then a
   pass from the last recursive node with ACC for its recursive field. */
static int family_spine(Low *l, Buf *b, const Value *v, const uint32_t *rec, Operand *out) {
  const FamilyInfo *fam = &l->m->families[v->inst];
  const IrExpr *node;
  Operand x;
  Walk w;
  Slot acc = slot_new(l);
  Buf in = buf_under(b);
  Buf body = buf_under(b);
  *out = slot_get(l, acc);
  return lower(l, b, v->args[fam->ctor_count], &x) && walk(l, b, x, rec, fam->ctor_count, &w) &&
         fam_switch(l, &in, ex_local(l, w.cur), v, rec, 0, acc) && guard(l, b, ex_local(l, w.end), acc, &in) &&
         chain_node(l, &body, &w, &node) && fam_switch(l, &body, node, v, rec, 1, acc) && chain_end(l, b, &w, &body);
}

/* A fold over a family without a recursive field is a case split. With at
   most one recursive field in each constructor, it is a spine walk. */
static int family_fold(Low *l, Buf *b, const Value *v, Operand *out) {
  const FamilyInfo *fam = &l->m->families[v->inst];
  uint32_t *fields = arena_alloc(l->m->arena, ((size_t)fam->ctor_count + 1u) * sizeof *fields);
  uint32_t *recs = arena_alloc(l->m->arena, ((size_t)fam->ctor_count + 1u) * sizeof *recs);
  const CtorInfo *c;
  uint32_t rec = 0;
  uint32_t here;
  uint32_t i;
  uint32_t k;
  if (fields == NULL || recs == NULL)
    return oom(l);
  for (i = 0; i < fam->ctor_count; i++) {
    c = &l->m->ctors[fam->first_ctor + i];
    here = 0;
    recs[i] = NO_REC;
    for (k = 0; k < c->field_count; k++) {
      here += c->fields[k].recursive ? 1u : 0u;
      recs[i] = c->fields[k].recursive ? k : recs[i];
    }
    if (here > 1u)
      return diag_fail(l->m->diag, "REFUSE_RUNTIME_TREE", l->m->def, "a fold over a tree of %s must exist at run time (HOST-LIMIT)", fam->name);
    rec += here;
    fields[i] = c->field_count;
  }
  return rec != 0 ? family_spine(l, b, v, recs, out) : cases_of(l, b, v->args[fam->ctor_count], v->args, fields, fam->ctor_count, out);
}

/* The two arms of an option or a sum, behind the guard on the flag of X. */
static int two_arms(Low *l, Buf *b, Operand x, const Buf *a0, const Buf *a1, Slot res) {
  IrBlock *arms = arena_alloc(l->m->arena, 2u * sizeof *arms);
  Buf in = buf_under(b);
  if (arms == NULL)
    return oom(l);
  arms[0] = block_of(a0);
  arms[1] = block_of(a1);
  return st_switch(l, &in, ex_load(l, x.w, 0), arms, 2u) && guard(l, b, x.f, res, &in);
}

/* Lowers the option or sum XV into X. Arm 0 gets RES := X; arm 1 gets P :=
   the payload. */
static int carrier_begin(Low *l, Buf *b, const Value *xv, Slot res, Operand *x, Buf *a0, Buf *a1, Operand *p) {
  return lower(l, b, xv, x) && store(l, a0, res, *x) && field_at(l, a1, x->w, 0, p);
}

static int carrier_map(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand p;
  Operand y;
  Operand t;
  Slot res = slot_new(l);
  Slot ts = slot_new(l);
  Buf a0 = buf_under(b);
  Buf a1 = buf_under(b);
  *out = slot_get(l, res);
  t = slot_get(l, ts);
  return carrier_begin(l, b, v->args[1], res, &x, &a0, &a1, &p) && apply_into(l, &a1, v->args[0], &p, 1, ts) &&
         block_ops(l, &a1, 1, &t, 1, &y) && store(l, &a1, res, y) && two_arms(l, b, x, &a0, &a1, res);
}

static int carrier_bind(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand p;
  Slot res = slot_new(l);
  Buf a0 = buf_under(b);
  Buf a1 = buf_under(b);
  *out = slot_get(l, res);
  return carrier_begin(l, b, v->args[0], res, &x, &a0, &a1, &p) && apply_into(l, &a1, v->args[1], &p, 1, res) &&
         two_arms(l, b, x, &a0, &a1, res);
}

static int carrier_filter(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand x;
  Operand p;
  Operand y;
  Slot res = slot_new(l);
  Slot ts = slot_new(l);
  Buf a0 = buf_under(b);
  Buf a1 = buf_under(b);
  Buf keep = buf_under(&a1);
  Buf drop = buf_under(&a1);
  Buf test = buf_under(&a1);
  *out = slot_get(l, res);
  return carrier_begin(l, b, v->args[1], res, &x, &a0, &a1, &p) && apply_into(l, &a1, v->args[0], &p, 1, ts) &&
         store(l, &keep, res, x) && block_ops(l, &drop, 0, NULL, 0, &y) && store(l, &drop, res, y) &&
         if_flag(l, &test, ex_local(l, ts.w), &keep, &drop) && guard(l, &a1, ex_local(l, ts.f), res, &test) &&
         two_arms(l, b, x, &a0, &a1, res);
}

/* FILTER on a list, or on a sum. */
static int not_option(Low *l, Buf *b, const Value *v, Operand *out) {
  return v->inst == CARRIER_LIST ? list_filter(l, b, v, out) : internal(l, "a filter over a sum");
}

/* ACC := Z, then ACC := STEP ACC, N times. */
static int fold_nat(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand n;
  Operand a;
  Slot acc = slot_new(l);
  Buf in = buf_under(b);
  Buf body = buf_under(&in);
  *out = slot_get(l, acc);
  a = slot_get(l, acc);
  return lower(l, b, v->args[2], &n) && lower_into(l, &in, v->args[1], acc) && apply_into(l, &body, v->args[0], &a, 1, acc) &&
         st_repeat(l, &in, n.w, &body) && guard(l, b, n.f, acc, &in);
}

/* Proof contents erase, but forcing a proof must preserve its trap flag. */
static int proof_op(Low *l, Buf *b, const Value *v, uint32_t first, uint32_t count, Operand *out) {
  Operand p;
  const IrExpr *flag = ex_const(l, 0);
  uint32_t i;
  for (i = first; i < first + count; i++) {
    if (!lower(l, b, v->args[i], &p))
      return 0;
    flag = ex_or(l, flag, p.f);
  }
  return atoms(l, b, ex_const(l, 0), flag, out);
}

static int transport(Low *l, Buf *b, const Value *v, Operand *out) {
  Operand proof;
  Slot res = slot_new(l);
  Buf in = buf_under(b);
  *out = slot_get(l, res);
  return lower(l, b, v->args[1], &proof) && lower_into(l, &in, v->args[2], res) &&
         guard(l, b, proof.f, res, &in);
}

/* An eliminator on a variable. */
static int lower_stuck(Low *l, Buf *b, const Value *v, Operand *out) {
  switch (v->op) {
  case OP_NAT:
  case OP_FLAG:
  case OP_UNIT:
  case OP_PROD:
  case OP_SUM:
  case OP_OPTION:
  case OP_LIST:
  case OP_EQ:
  case OP_FAMILY:
  case OP_UNIT_VAL:
  case OP_FLAG_YES:
  case OP_FLAG_NO:
  case OP_PAIR:
  case OP_INL:
  case OP_INR:
  case OP_NONE:
  case OP_SOME:
  case OP_NIL:
  case OP_CONS:
  case OP_PACK:
  case OP_REFL:
  case OP_CTOR:
  case OP_PURE:
    return internal(l, "a stuck canonical value");
  case OP_FIRST:
  case OP_WITNESS:
    return field_of(l, b, v->args[0], 0, out);
  case OP_SECOND:
  case OP_PAYLOAD:
    return field_of(l, b, v->args[0], 1, out);
  case OP_PROJ:
    return field_of(l, b, v->args[0], v->field, out);
  case OP_EITHER:
    return two_cases(l, b, v, 1, out);
  case OP_OPTION_ELIM:
    return two_cases(l, b, v, 0, out);
  case OP_MAP:
    return v->inst == CARRIER_LIST ? list_map(l, b, v, out) : carrier_map(l, b, v, out);
  case OP_BIND:
    return v->inst == CARRIER_LIST ? list_bind(l, b, v, out) : carrier_bind(l, b, v, out);
  case OP_FILTER:
    return v->inst == CARRIER_OPTION ? carrier_filter(l, b, v, out) : not_option(l, b, v, out);
  case OP_FOLD_NAT:
    return fold_nat(l, b, v, out);
  case OP_FOLD_LIST:
    return fold_list(l, b, v, out);
  case OP_UNFOLD:
    return unfold(l, b, v, out);
  case OP_FOLD_FAMILY:
    return family_fold(l, b, v, out);
  case OP_SYMM:
    return proof_op(l, b, v, 0, 1, out);
  case OP_TRANS:
    return proof_op(l, b, v, 0, 2, out);
  case OP_CONG:
    return proof_op(l, b, v, 1, 1, out);
  case OP_TRANSPORT:
    return transport(l, b, v, out);
  case OP_NAT_ADD:
    return nat_bin(l, b, v, IR_OP_ADD, 1, out);
  case OP_NAT_SUB:
    return nat_bin(l, b, v, IR_OP_SUB, 0, out);
  case OP_NAT_MUL:
    return nat_bin(l, b, v, IR_OP_MUL, 1, out);
  case OP_NAT_EQ:
    return nat_bin(l, b, v, IR_OP_EQ, 0, out);
  case OP_NAT_LE:
    return nat_bin(l, b, v, IR_OP_LE, 0, out);
  case OP_FLAG_IF:
    return flag_if(l, b, v, out);
  }
  return internal(l, "an unknown operation");
}

static int lower_value(Low *l, Buf *b, const Value *v, Operand *out) {
  switch (v->kind) {
  case VAL_NAT:
    return give(l, out, v->nat, 0);
  case VAL_TRAP:
    return give(l, out, 0, 1);
  case VAL_UNIV:
  case VAL_PI:
  case VAL_SIGMA:
    return give(l, out, 0, 0);
  case VAL_LAM:
  case VAL_APP:
    return closure(l);
  case VAL_VAR:
    if (v->nat >= l->level_count)
      return internal(l, "a variable without an operand");
    *out = l->levels[v->nat];
    return 1;
  case VAL_OP:
    return lower_canon(l, b, v, out);
  case VAL_STUCK:
    return lower_stuck(l, b, v, out);
  }
  return internal(l, "an unknown value");
}

static int lower(Low *l, Buf *b, const Value *v, Operand *out) {
  int ok;
  if (v == NULL)
    return got(l, v);
  if (memo_kind(v) && memo_find(b, v, out))
    return 1;
  if (l->m->depth >= EVAL_DEPTH_LIMIT)
    return diag_fail(l->m->diag, "EVAL_DEPTH", l->m->def, "the lowering nests deeper than %u levels", EVAL_DEPTH_LIMIT);
  l->m->depth++;
  ok = lower_value(l, b, v, out);
  l->m->depth--;
  return ok && (!memo_kind(v) || memo_put(l, b, v, *out));
}

/* The entry INDEX, applied to a variable for each parameter. Only the
   result is strict: its flag runs TRAP. */
static int lower_entry(Machine *m, uint32_t index, const Entry *e, IrFunc *fn) {
  Low l;
  Buf body = buf_under(NULL);
  Buf trap = buf_under(NULL);
  Buf none = buf_under(NULL);
  IrScalar *params = arena_alloc(m->arena, ((size_t)e->param_count + 1u) * sizeof *params);
  const Value *v;
  const Value *x;
  Operand r;
  uint32_t k;
  memset(&l, 0, sizeof l);
  l.m = m;
  l.local_count = e->param_count;
  m->def = m->defs[index].name;
  m->fuel = EVAL_FUEL_STEPS;
  if (params == NULL)
    return oom(&l);
  v = def_value(m, index);
  for (k = 0; k < e->param_count && v != NULL; k++) {
    params[k] = e->param_flag[k] ? IR_SCALAR_FLAG : IR_SCALAR_NAT;
    x = fresh(&l, operand(ex_local(&l, k), ex_const(&l, 0)));
    v = x == NULL ? NULL : apply_value(m, v, x);
  }
  if (!got(&l, v) || !lower(&l, &body, v, &r) || !emit(&l, &trap, stmt_new(&l, IR_STMT_TRAP)) ||
      !if_flag(&l, &body, r.f, &trap, &none) || !emit(&l, &body, stmt_expr(&l, IR_STMT_RETURN, r.w)))
    return 0;
  fn->name = m->defs[index].name;
  fn->params = params;
  fn->param_count = e->param_count;
  fn->result = e->result_flag ? IR_SCALAR_FLAG : IR_SCALAR_NAT;
  fn->local_count = l.local_count;
  fn->body = block_of(&body);
  return 1;
}

int lower_program(Machine *m, IrProgram *prog) {
  IrFunc *funcs = arena_alloc(m->arena, ((size_t)m->def_count + 1u) * sizeof *funcs);
  Entry e;
  size_t n = 0;
  uint32_t i;
  int entry;
  prog->funcs = funcs;
  prog->func_count = 0;
  if (funcs == NULL)
    return diag_fail(m->diag, "OOM", m->def, "out of memory");
  for (i = 0; i < m->def_count; i++) {
    m->fuel = EVAL_FUEL_STEPS;
    entry = m->defs[i].origin == ORIGIN_PROGRAM && entry_of(m, m->defs[i].type, &e);
    if (entry && !lower_entry(m, i, &e, &funcs[n]))
      return 0;
    n += entry ? 1u : 0u;
  }
  prog->func_count = n;
  return 1;
}
