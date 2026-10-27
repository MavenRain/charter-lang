/* The Wasm back end. It writes a Wasm 1.0 (MVP) binary module directly.

   Module layout:
   - Function 0 is the internal allocator `alloc (bytes : i32) -> i64`. It
     bumps the mutable i64 global 0 (the heap pointer) over memory 0. When a
     block does not fit, it grows the memory. When the memory cannot grow (the
     maximum is WASM_MAX_PAGES), it traps.
   - Function 1 + K is IR entry K, exported as its name. Each parameter and the
     result is an i64. Each entry first resets the heap pointer to 0, and it
     traps on a Flag argument larger than 1.
   - A word is 8 bytes. Word K of the block at address A is at A + 8K.

   Each entry has three i64 scratch locals after the IR locals: S and S + 1
   hold the operands of SUB, ADD_CARRY and MUL_CARRY, and S + 2 holds the
   address of an ALLOC. An operator reads its operands into S and S + 1 only
   after both operand expressions are done, so a nested operator cannot
   overwrite them.

   Each sized part (a section, a function body) is written in two passes: the
   first pass counts the bytes, the second pass writes them after the size.
   So the back end needs no buffer. */
#include <stdint.h>
#include <string.h>

#include "target.h"

#define WASM_MAX_PAGES 16384u /* 1 GiB, the arena limit of langc eval */
#define WASM_DEPTH_MAX 2000u

enum {
  OP_UNREACHABLE = 0x00,
  OP_BLOCK = 0x02,
  OP_LOOP = 0x03,
  OP_IF = 0x04,
  OP_ELSE = 0x05,
  OP_END = 0x0B,
  OP_BR = 0x0C,
  OP_BR_IF = 0x0D,
  OP_BR_TABLE = 0x0E,
  OP_RETURN = 0x0F,
  OP_CALL = 0x10,
  OP_SELECT = 0x1B,
  OP_LOCAL_GET = 0x20,
  OP_LOCAL_SET = 0x21,
  OP_LOCAL_TEE = 0x22,
  OP_GLOBAL_GET = 0x23,
  OP_GLOBAL_SET = 0x24,
  OP_I64_LOAD = 0x29,
  OP_I64_STORE = 0x37,
  OP_MEMORY_SIZE = 0x3F,
  OP_MEMORY_GROW = 0x40,
  OP_I32_CONST = 0x41,
  OP_I64_CONST = 0x42,
  OP_I32_EQ = 0x46,
  OP_I64_EQZ = 0x50,
  OP_I64_EQ = 0x51,
  OP_I64_LT_U = 0x54,
  OP_I64_GT_U = 0x56,
  OP_I64_LE_U = 0x58,
  OP_I64_GE_U = 0x5A,
  OP_I64_ADD = 0x7C,
  OP_I64_SUB = 0x7D,
  OP_I64_MUL = 0x7E,
  OP_I64_DIV_U = 0x80,
  OP_I64_OR = 0x84,
  OP_I64_SHL = 0x86,
  OP_I64_SHR_U = 0x88,
  OP_I32_WRAP_I64 = 0xA7,
  OP_I64_EXTEND_I32_U = 0xAD,
  TYPE_I32 = 0x7F,
  TYPE_I64 = 0x7E,
  TYPE_FUNC = 0x60,
  TYPE_EMPTY = 0x40,
  ALIGN_WORD = 3
};

enum {
  SECTION_TYPE = 1,
  SECTION_FUNCTION = 3,
  SECTION_MEMORY = 5,
  SECTION_GLOBAL = 6,
  SECTION_EXPORT = 7,
  SECTION_CODE = 10
};

/* A byte sink. With out == NULL it only counts. */
typedef struct {
  FILE *out;
  size_t count;
  FILE *err;
} Sink;

typedef int (*Part)(Sink *s, const void *arg);

const char target_name[] = "wasm";

static int put_byte(Sink *s, unsigned v) {
  s->count++;
  return s->out == NULL || fputc((int)(v & 0xFFu), s->out) != EOF;
}

static int put_uleb(Sink *s, uint64_t v) {
  int ok = 1;
  for (; ok && v >= 0x80u; v >>= 7) ok = put_byte(s, (unsigned)(v & 0x7Fu) | 0x80u);
  return ok && put_byte(s, (unsigned)v);
}

/* Signed LEB128 of the two's complement value of V. */
static int put_sleb(Sink *s, uint64_t v) {
  uint64_t fill = (v >> 63) != 0 ? ~(~(uint64_t)0 >> 7) : 0;
  unsigned low = (unsigned)(v & 0x7Fu);
  uint64_t rest = (v >> 7) | fill;
  int last = (rest == 0 && (low & 0x40u) == 0) || (rest == ~(uint64_t)0 && (low & 0x40u) != 0);
  int ok = put_byte(s, last ? low : low | 0x80u);
  return ok && (last || put_sleb(s, rest));
}

static int put_name(Sink *s, const char *name) {
  size_t i;
  size_t len = strlen(name);
  int ok = put_uleb(s, len);
  for (i = 0; i < len && ok; i++) ok = put_byte(s, (unsigned char)name[i]);
  return ok;
}

/* Writes the byte size of PART, then PART. */
static int sized(Sink *s, Part part, const void *arg) {
  Sink count = {NULL, 0, s->err};
  return part(&count, arg) && put_uleb(s, count.count) && part(s, arg);
}

static int section(Sink *s, unsigned id, Part part, const void *arg) {
  return put_byte(s, id) && sized(s, part, arg);
}

static int op2(Sink *s, unsigned op, uint64_t imm) {
  return put_byte(s, op) && put_uleb(s, imm);
}

static int i64_const(Sink *s, uint64_t v) {
  return put_byte(s, OP_I64_CONST) && put_sleb(s, v);
}

static int i32_const(Sink *s, uint64_t v) {
  return put_byte(s, OP_I32_CONST) && put_sleb(s, v);
}

static int memarg(Sink *s, unsigned op, uint32_t word) {
  return put_byte(s, op) && put_uleb(s, ALIGN_WORD) && put_uleb(s, 8u * (uint64_t)word);
}

static int deep(Sink *s) {
  fprintf(s->err, "langc: WASM_DEPTH: -: the IR nests deeper than %u levels\n", WASM_DEPTH_MAX);
  return 0;
}

static int emit_expr(Sink *s, const IrExpr *e, uint32_t t, unsigned depth);

/* The operands are on the stack. Moves them to the scratch locals T, T + 1. */
static int operands(Sink *s, uint32_t t) {
  return op2(s, OP_LOCAL_SET, t + 1u) && op2(s, OP_LOCAL_SET, t);
}

static int emit_op(Sink *s, IrOp op, uint32_t t) {
  switch (op) {
    case IR_OP_ADD:
      return put_byte(s, OP_I64_ADD);
    case IR_OP_SUB: /* select(a - b, 0, a >= b) */
      return operands(s, t) && op2(s, OP_LOCAL_GET, t) && op2(s, OP_LOCAL_GET, t + 1u) && put_byte(s, OP_I64_SUB) &&
             i64_const(s, 0) && op2(s, OP_LOCAL_GET, t) && op2(s, OP_LOCAL_GET, t + 1u) && put_byte(s, OP_I64_GE_U) &&
             put_byte(s, OP_SELECT);
    case IR_OP_MUL:
      return put_byte(s, OP_I64_MUL);
    case IR_OP_EQ:
      return put_byte(s, OP_I64_EQ) && put_byte(s, OP_I64_EXTEND_I32_U);
    case IR_OP_LE:
      return put_byte(s, OP_I64_LE_U) && put_byte(s, OP_I64_EXTEND_I32_U);
    case IR_OP_ADD_CARRY: /* a + b < a, modulo 2^64 */
      return operands(s, t) && op2(s, OP_LOCAL_GET, t) && op2(s, OP_LOCAL_GET, t + 1u) && put_byte(s, OP_I64_ADD) &&
             op2(s, OP_LOCAL_GET, t) && put_byte(s, OP_I64_LT_U) && put_byte(s, OP_I64_EXTEND_I32_U);
    case IR_OP_MUL_CARRY:
      /* Exact: a * b > 2^64 - 1 if and only if b > floor((2^64 - 1) / a), for
         a > 0. For a = 0 the divisor is 1, and no b is larger than 2^64 - 1. */
      return operands(s, t) && op2(s, OP_LOCAL_GET, t + 1u) && i64_const(s, ~(uint64_t)0) && i64_const(s, 1) &&
             op2(s, OP_LOCAL_GET, t) && op2(s, OP_LOCAL_GET, t) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_SELECT) &&
             put_byte(s, OP_I64_DIV_U) && put_byte(s, OP_I64_GT_U) && put_byte(s, OP_I64_EXTEND_I32_U);
    case IR_OP_OR:
      return put_byte(s, OP_I64_OR);
  }
  return 0;
}

static int emit_expr(Sink *s, const IrExpr *e, uint32_t t, unsigned depth) {
  if (depth > WASM_DEPTH_MAX) return deep(s);
  switch (e->kind) {
    case IR_EXPR_CONST:
      return i64_const(s, e->value);
    case IR_EXPR_LOCAL:
      return op2(s, OP_LOCAL_GET, e->local);
    case IR_EXPR_BINARY:
      return emit_expr(s, e->left, t, depth + 1u) && emit_expr(s, e->right, t, depth + 1u) && emit_op(s, e->op, t);
    case IR_EXPR_LOAD:
      return emit_expr(s, e->left, t, depth + 1u) && put_byte(s, OP_I32_WRAP_I64) && memarg(s, OP_I64_LOAD, e->field);
  }
  return 0;
}

static int emit_block(Sink *s, const IrBlock *b, uint32_t t, unsigned depth);

/* local := alloc(8 * n); word k := fields[k]. The address waits in T + 2. */
static int emit_alloc(Sink *s, const IrStmt *st, uint32_t t, unsigned depth) {
  size_t k;
  int ok = i32_const(s, 8u * (uint64_t)st->field_count) && op2(s, OP_CALL, 0) && op2(s, OP_LOCAL_SET, t + 2u);
  for (k = 0; k < st->field_count && ok; k++) {
    ok = op2(s, OP_LOCAL_GET, t + 2u) && put_byte(s, OP_I32_WRAP_I64) && emit_expr(s, st->fields[k], t, depth + 1u) &&
         memarg(s, OP_I64_STORE, (uint32_t)k);
  }
  return ok && op2(s, OP_LOCAL_GET, t + 2u) && op2(s, OP_LOCAL_SET, st->local);
}

/* Blocks: exit, trap, then arm n - 1 down to arm 0 (the innermost). br_table
   label k ends the block of arm k, so the code of arm k follows. A value of
   n or more takes label n, the trap block. After arm k, label n - k is the
   exit block. */
static int emit_switch(Sink *s, const IrStmt *st, uint32_t t, unsigned depth) {
  size_t k;
  size_t n = st->arm_count;
  int ok = put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY) && put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY);
  for (k = 0; k < n && ok; k++) ok = put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY);
  ok = ok && emit_expr(s, st->expr, t, depth + 1u) && op2(s, OP_LOCAL_TEE, t) && put_byte(s, OP_I32_WRAP_I64) &&
       i32_const(s, n) && op2(s, OP_LOCAL_GET, t) && i64_const(s, n) && put_byte(s, OP_I64_LT_U) &&
       put_byte(s, OP_SELECT) && op2(s, OP_BR_TABLE, n);
  for (k = 0; k <= n && ok; k++) ok = put_uleb(s, k);
  for (k = 0; k < n && ok; k++) {
    ok = put_byte(s, OP_END) && emit_block(s, &st->arms[k], t, depth + 1u) && op2(s, OP_BR, n - k);
  }
  return ok && put_byte(s, OP_END) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END);
}

/* counter := expr; then, at the top of each run, leave when counter = 0 or
   (for WHILE) local = 0. counter decreases by 1 after each run. */
static int emit_loop(Sink *s, const IrStmt *st, int is_while, uint32_t t, unsigned depth) {
  return emit_expr(s, st->expr, t, depth + 1u) && op2(s, OP_LOCAL_SET, st->counter) && put_byte(s, OP_BLOCK) &&
         put_byte(s, TYPE_EMPTY) && put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY) &&
         op2(s, OP_LOCAL_GET, st->counter) && put_byte(s, OP_I64_EQZ) && op2(s, OP_BR_IF, 1) &&
         (!is_while || (op2(s, OP_LOCAL_GET, st->local) && put_byte(s, OP_I64_EQZ) && op2(s, OP_BR_IF, 1))) &&
         emit_block(s, &st->body, t, depth + 1u) && op2(s, OP_LOCAL_GET, st->counter) && i64_const(s, 1) &&
         put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_SET, st->counter) && op2(s, OP_BR, 0) && put_byte(s, OP_END) &&
         put_byte(s, OP_END);
}

static int emit_stmt(Sink *s, const IrStmt *st, uint32_t t, unsigned depth) {
  if (depth > WASM_DEPTH_MAX) return deep(s);
  switch (st->kind) {
    case IR_STMT_SET:
      return emit_expr(s, st->expr, t, depth + 1u) && op2(s, OP_LOCAL_SET, st->local);
    case IR_STMT_ALLOC:
      return emit_alloc(s, st, t, depth);
    case IR_STMT_IF: /* expr = 0: otherwise, else: body */
      return emit_expr(s, st->expr, t, depth + 1u) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_IF) &&
             put_byte(s, TYPE_EMPTY) && emit_block(s, &st->otherwise, t, depth + 1u) && put_byte(s, OP_ELSE) &&
             emit_block(s, &st->body, t, depth + 1u) && put_byte(s, OP_END);
    case IR_STMT_SWITCH:
      return emit_switch(s, st, t, depth);
    case IR_STMT_REPEAT:
      return emit_loop(s, st, 0, t, depth);
    case IR_STMT_WHILE:
      return emit_loop(s, st, 1, t, depth);
    case IR_STMT_TRAP:
      return put_byte(s, OP_UNREACHABLE);
    case IR_STMT_RETURN:
      return emit_expr(s, st->expr, t, depth + 1u) && put_byte(s, OP_RETURN);
  }
  return 0;
}

static int emit_block(Sink *s, const IrBlock *b, uint32_t t, unsigned depth) {
  size_t i;
  int ok = depth <= WASM_DEPTH_MAX || deep(s);
  for (i = 0; i < b->count && ok; i++) ok = emit_stmt(s, b->items[i], t, depth + 1u);
  return ok;
}

/* alloc (bytes : i32) -> i64, local 1 = the new end:
   old := heap; end := old + bytes; if end > memory bytes { grow by
   ceil(end / 65536) - pages; trap on -1 }; heap := end; return old. */
static int part_alloc(Sink *s, const void *arg) {
  (void)arg;
  return put_uleb(s, 1) && put_uleb(s, 1) && put_byte(s, TYPE_I64) && op2(s, OP_GLOBAL_GET, 0) &&
         op2(s, OP_GLOBAL_GET, 0) && op2(s, OP_LOCAL_GET, 0) && put_byte(s, OP_I64_EXTEND_I32_U) &&
         put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_TEE, 1) && op2(s, OP_MEMORY_SIZE, 0) &&
         put_byte(s, OP_I64_EXTEND_I32_U) && i64_const(s, 16) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_GT_U) &&
         put_byte(s, OP_IF) && put_byte(s, TYPE_EMPTY) && op2(s, OP_LOCAL_GET, 1) && i64_const(s, 65535) &&
         put_byte(s, OP_I64_ADD) && i64_const(s, 16) && put_byte(s, OP_I64_SHR_U) && op2(s, OP_MEMORY_SIZE, 0) &&
         put_byte(s, OP_I64_EXTEND_I32_U) && put_byte(s, OP_I64_SUB) && put_byte(s, OP_I32_WRAP_I64) &&
         op2(s, OP_MEMORY_GROW, 0) && i32_const(s, ~(uint64_t)0) && put_byte(s, OP_I32_EQ) && put_byte(s, OP_IF) &&
         put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END) && put_byte(s, OP_END) &&
         op2(s, OP_LOCAL_GET, 1) && op2(s, OP_GLOBAL_SET, 0) && put_byte(s, OP_END);
}

/* Traps when the Flag parameter K is larger than 1. */
static int flag_guard(Sink *s, const IrFunc *fn, size_t k) {
  return fn->params[k] == IR_SCALAR_NAT ||
         (op2(s, OP_LOCAL_GET, k) && i64_const(s, 1) && put_byte(s, OP_I64_GT_U) && put_byte(s, OP_IF) &&
          put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END));
}

static int part_entry(Sink *s, const void *arg) {
  const IrFunc *fn = arg;
  uint32_t t = fn->local_count;
  size_t k;
  int ok = put_uleb(s, 1) && put_uleb(s, (uint64_t)(fn->local_count - fn->param_count) + 3u) &&
           put_byte(s, TYPE_I64) && i64_const(s, 0) && op2(s, OP_GLOBAL_SET, 0);
  for (k = 0; k < fn->param_count && ok; k++) ok = flag_guard(s, fn, k);
  return ok && emit_block(s, &fn->body, t, 0) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END);
}

static int part_types(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  size_t i;
  size_t k;
  int ok = put_uleb(s, 1u + prog->func_count) && put_byte(s, TYPE_FUNC) && put_uleb(s, 1) && put_byte(s, TYPE_I32) &&
           put_uleb(s, 1) && put_byte(s, TYPE_I64);
  for (i = 0; i < prog->func_count && ok; i++) {
    ok = put_byte(s, TYPE_FUNC) && put_uleb(s, prog->funcs[i].param_count);
    for (k = 0; k < prog->funcs[i].param_count && ok; k++) ok = put_byte(s, TYPE_I64);
    ok = ok && put_uleb(s, 1) && put_byte(s, TYPE_I64);
  }
  return ok;
}

static int part_functions(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  size_t i;
  int ok = put_uleb(s, 1u + prog->func_count);
  for (i = 0; i <= prog->func_count && ok; i++) ok = put_uleb(s, i);
  return ok;
}

static int part_memory(Sink *s, const void *arg) {
  (void)arg;
  return put_uleb(s, 1) && put_byte(s, 1) && put_uleb(s, 1) && put_uleb(s, WASM_MAX_PAGES);
}

static int part_global(Sink *s, const void *arg) {
  (void)arg;
  return put_uleb(s, 1) && put_byte(s, TYPE_I64) && put_byte(s, 1) && i64_const(s, 0) && put_byte(s, OP_END);
}

static int part_exports(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  size_t i;
  int ok = put_uleb(s, prog->func_count);
  for (i = 0; i < prog->func_count && ok; i++) {
    ok = put_name(s, prog->funcs[i].name) && put_byte(s, 0) && put_uleb(s, 1u + i);
  }
  return ok;
}

static int part_code(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  size_t i;
  int ok = put_uleb(s, 1u + prog->func_count) && sized(s, part_alloc, NULL);
  for (i = 0; i < prog->func_count && ok; i++) ok = sized(s, part_entry, &prog->funcs[i]);
  return ok;
}

int target_abi_line(const IrFunc *fn, FILE *out, FILE *err) {
  (void)err;
  fprintf(out, "%s\n", fn->name);
  return 1;
}

/* Both parts are the module bytes. */
int target_write(const IrProgram *prog, TargetPart part, FILE *out, FILE *err) {
  static const unsigned char header[8] = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
  Sink s = {out, 0, err};
  size_t i;
  int ok = 1;
  (void)part;
  for (i = 0; i < sizeof header && ok; i++) ok = put_byte(&s, header[i]);
  ok = ok && section(&s, SECTION_TYPE, part_types, prog) && section(&s, SECTION_FUNCTION, part_functions, prog) &&
       section(&s, SECTION_MEMORY, part_memory, NULL) && section(&s, SECTION_GLOBAL, part_global, NULL) &&
       section(&s, SECTION_EXPORT, part_exports, prog) && section(&s, SECTION_CODE, part_code, prog);
  if (!ok && ferror(out)) fputs("langc: IO: -: cannot write the wasm module\n", err);
  return ok;
}
