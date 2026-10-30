/* The Wasm back end. It writes a Wasm 1.0 (MVP) binary module directly.

   Module layout:
   - Function 0 is the internal allocator `alloc (bytes : i32) -> i64`. It
     bumps the mutable i64 global 0 (the heap pointer) over memory 0. When a
     block does not fit, it grows the memory. When the memory cannot grow (the
     maximum is WASM_MAX_PAGES), it traps.
   - Function 1 + K is IR entry K, exported as its name. Each parameter and the
     result is an i64. Each entry first resets the heap pointer to 0, and it
     traps on a Bool argument larger than 1.
   - A stream entry (IrFunc.stream, Q-S3-7) has one parameter: the count n of
     the input words at address 0. Its heap starts at 8n, and its result is
     the address of the block [m, the m output words]. A module with a stream
     entry also exports memory 0 as `memory`.
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

#include "front/ed25519.h"
#include "front/poseidon2.h"
#include "front/sha512.h"
#include "target.h"
#include "wasm_kernel.h"

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
  OP_I64_LOAD8_U = 0x31,
  OP_I64_STORE = 0x37,
  OP_I64_STORE8 = 0x3C,
  OP_MEMORY_SIZE = 0x3F,
  OP_MEMORY_GROW = 0x40,
  OP_I32_CONST = 0x41,
  OP_I64_CONST = 0x42,
  OP_I32_EQ = 0x46,
  OP_I64_EQZ = 0x50,
  OP_I64_EQ = 0x51,
  OP_I64_NE = 0x52,
  OP_I64_LT_U = 0x54,
  OP_I64_GT_U = 0x56,
  OP_I64_LE_U = 0x58,
  OP_I64_GE_U = 0x5A,
  OP_I64_ADD = 0x7C,
  OP_I64_SUB = 0x7D,
  OP_I64_MUL = 0x7E,
  OP_I64_DIV_U = 0x80,
  OP_I64_AND = 0x83,
  OP_I64_OR = 0x84,
  OP_I64_XOR = 0x85,
  OP_I64_SHL = 0x86,
  OP_I64_SHR_S = 0x87,
  OP_I64_SHR_U = 0x88,
  OP_I64_ROTR = 0x8A,
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

/* KERNEL is K, the index of the first kernel function. */
static int emit_block(Sink *s, const IrBlock *b, uint32_t t, uint32_t kernel, unsigned depth);
static int emit_kernel(Sink *s, const IrStmt *st, uint32_t t, uint32_t kernel, unsigned depth);
static int emit_frost(Sink *s, const IrStmt *st, uint32_t t, uint32_t kernel, unsigned depth);

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
static int emit_switch(Sink *s, const IrStmt *st, uint32_t t, uint32_t kernel, unsigned depth) {
  size_t k;
  size_t n = st->arm_count;
  int ok = put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY) && put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY);
  for (k = 0; k < n && ok; k++) ok = put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY);
  ok = ok && emit_expr(s, st->expr, t, depth + 1u) && op2(s, OP_LOCAL_TEE, t) && put_byte(s, OP_I32_WRAP_I64) &&
       i32_const(s, n) && op2(s, OP_LOCAL_GET, t) && i64_const(s, n) && put_byte(s, OP_I64_LT_U) &&
       put_byte(s, OP_SELECT) && op2(s, OP_BR_TABLE, n);
  for (k = 0; k <= n && ok; k++) ok = put_uleb(s, k);
  for (k = 0; k < n && ok; k++) {
    ok = put_byte(s, OP_END) && emit_block(s, &st->arms[k], t, kernel, depth + 1u) && op2(s, OP_BR, n - k);
  }
  return ok && put_byte(s, OP_END) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END);
}

/* counter := expr; then, at the top of each run, leave when counter = 0 or
   (for WHILE) local = 0. counter decreases by 1 after each run. */
static int emit_loop(Sink *s, const IrStmt *st, int is_while, uint32_t t, uint32_t kernel, unsigned depth) {
  return emit_expr(s, st->expr, t, depth + 1u) && op2(s, OP_LOCAL_SET, st->counter) && put_byte(s, OP_BLOCK) &&
         put_byte(s, TYPE_EMPTY) && put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY) &&
         op2(s, OP_LOCAL_GET, st->counter) && put_byte(s, OP_I64_EQZ) && op2(s, OP_BR_IF, 1) &&
         (!is_while || (op2(s, OP_LOCAL_GET, st->local) && put_byte(s, OP_I64_EQZ) && op2(s, OP_BR_IF, 1))) &&
         emit_block(s, &st->body, t, kernel, depth + 1u) && op2(s, OP_LOCAL_GET, st->counter) && i64_const(s, 1) &&
         put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_SET, st->counter) && op2(s, OP_BR, 0) && put_byte(s, OP_END) &&
         put_byte(s, OP_END);
}

static int emit_stmt(Sink *s, const IrStmt *st, uint32_t t, uint32_t kernel, unsigned depth) {
  if (depth > WASM_DEPTH_MAX) return deep(s);
  switch (st->kind) {
    case IR_STMT_SET:
      return emit_expr(s, st->expr, t, depth + 1u) && op2(s, OP_LOCAL_SET, st->local);
    case IR_STMT_ALLOC:
      return emit_alloc(s, st, t, depth);
    case IR_STMT_IF: /* expr = 0: otherwise, else: body */
      return emit_expr(s, st->expr, t, depth + 1u) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_IF) &&
             put_byte(s, TYPE_EMPTY) && emit_block(s, &st->otherwise, t, kernel, depth + 1u) && put_byte(s, OP_ELSE) &&
             emit_block(s, &st->body, t, kernel, depth + 1u) && put_byte(s, OP_END);
    case IR_STMT_SWITCH:
      return emit_switch(s, st, t, kernel, depth);
    case IR_STMT_REPEAT:
      return emit_loop(s, st, 0, t, kernel, depth);
    case IR_STMT_WHILE:
      return emit_loop(s, st, 1, t, kernel, depth);
    case IR_STMT_TRAP:
      return put_byte(s, OP_UNREACHABLE);
    case IR_STMT_RETURN:
      return emit_expr(s, st->expr, t, depth + 1u) && put_byte(s, OP_RETURN);
    case IR_STMT_KERNEL:
      return st->counter == IR_KERNEL_FROST ? emit_frost(s, st, t, kernel, depth) : emit_kernel(s, st, t, kernel, depth);
  }
  return 0;
}

static int emit_block(Sink *s, const IrBlock *b, uint32_t t, uint32_t kernel, unsigned depth) {
  size_t i;
  int ok = depth <= WASM_DEPTH_MAX || deep(s);
  for (i = 0; i < b->count && ok; i++) ok = emit_stmt(s, b->items[i], t, kernel, depth + 1u);
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

/* Traps when the Bool parameter K is larger than 1. */
static int bool_guard(Sink *s, const IrFunc *fn, size_t k) {
  return fn->params[k] == IR_SCALAR_NAT ||
         (op2(s, OP_LOCAL_GET, k) && i64_const(s, 1) && put_byte(s, OP_I64_GT_U) && put_byte(s, OP_IF) &&
          put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END));
}

/* Validate n before scaling it: the input must fit in the current memory.
   This also prevents a count at least 2^61 from wrapping the heap start. */
static int stream_guard(Sink *s, const IrFunc *fn) {
  return !fn->stream ||
    (op2(s, OP_LOCAL_GET, 0) && op2(s, OP_MEMORY_SIZE, 0) && put_byte(s, OP_I64_EXTEND_I32_U) &&
     i64_const(s, 13) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_GT_U) &&
     put_byte(s, OP_IF) && put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END));
}

/* The heap start: 0, or 8n after the n input words of a stream entry. */
static int heap_start(Sink *s, const IrFunc *fn) {
  return fn->stream ? op2(s, OP_LOCAL_GET, 0) && i64_const(s, 3) && put_byte(s, OP_I64_SHL) : i64_const(s, 0);
}

/* The arg of part_entry: the function and K, the index of the first kernel
   function. */
typedef struct {
  const IrFunc *fn;
  uint32_t kernel;
} Entry;

static int part_entry(Sink *s, const void *arg) {
  const Entry *entry = arg;
  const IrFunc *fn = entry->fn;
  uint32_t t = fn->local_count;
  size_t k;
  int ok = put_uleb(s, 1) && put_uleb(s, (uint64_t)(fn->local_count - fn->param_count) + 3u) &&
           put_byte(s, TYPE_I64) && stream_guard(s, fn) && heap_start(s, fn) && op2(s, OP_GLOBAL_SET, 0);
  for (k = 0; k < fn->param_count && ok; k++) ok = bool_guard(s, fn, k);
  return ok && emit_block(s, &fn->body, t, entry->kernel, 0) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END);
}

/* The Ed25519 kernel functions, in order (the comment "The Ed25519 verify
   kernel" below has the shapes). */
enum {
  ED_CARRY,
  ED_MUL,
  ED_ADD,
  ED_SUB,
  ED_POW2523,
  ED_PACK,
  ED_EQUAL,
  ED_PADD,
  ED_PMUL,
  ED_DECODE,
  ED_MODL,
  ED_VERIFY,
  ED_FUNCS
};

/* The kernel functions: the comment "The Poseidon2 kernel" below has the
   list, then the SHA-512 kernel and the ED_FUNCS Ed25519 functions (S4 U5).
   KERNEL_TYPES: reduce, mul and add, permute, hash, merkle, then carry, equal
   and decode, verify. */
enum {
  KERNEL_REDUCE,
  KERNEL_MUL,
  KERNEL_ADD,
  KERNEL_PERMUTE,
  KERNEL_HASH,
  KERNEL_MERKLE,
  KERNEL_SHA512,
  KERNEL_ED,
  KERNEL_FUNCS = KERNEL_ED + ED_FUNCS
};
enum { KERNEL_TYPES = 8 };

static int kernel_types(Sink *s);
static int kernel_functions(Sink *s, uint32_t base);
static int kernel_code(Sink *s, const uint32_t *kernel);
static int block_kernel(const IrBlock *b, unsigned depth);

/* 1 when ST is or holds an IR_STMT_KERNEL. */
static int stmt_kernel(const IrStmt *st, unsigned depth) {
  size_t k;
  int found = 0;
  switch (st->kind) {
    case IR_STMT_KERNEL:
      return 1;
    case IR_STMT_IF:
      return block_kernel(&st->body, depth + 1u) || block_kernel(&st->otherwise, depth + 1u);
    case IR_STMT_SWITCH:
      for (k = 0; k < st->arm_count && !found; k++) found = block_kernel(&st->arms[k], depth + 1u);
      return found;
    case IR_STMT_REPEAT:
    case IR_STMT_WHILE:
      return block_kernel(&st->body, depth + 1u);
    case IR_STMT_SET:
    case IR_STMT_ALLOC:
    case IR_STMT_TRAP:
    case IR_STMT_RETURN:
      return 0;
  }
  return 0;
}

/* Past WASM_DEPTH_MAX the scan stops: emit_stmt refuses that IR. */
static int block_kernel(const IrBlock *b, unsigned depth) {
  size_t i;
  int found = 0;
  for (i = 0; i < b->count && !found && depth <= WASM_DEPTH_MAX; i++) found = stmt_kernel(b->items[i], depth + 1u);
  return found;
}

/* 1 when a function of PROG has an IR_STMT_KERNEL: the module then has the
   kernel after its entries (Q-S4-10 (a)). */
static int prog_kernel(const IrProgram *prog) {
  size_t i;
  int found = 0;
  for (i = 0; i < prog->func_count && !found; i++) found = block_kernel(&prog->funcs[i].body, 0);
  return found;
}

static int part_types(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  int kernel = prog_kernel(prog);
  size_t i;
  size_t k;
  int ok = put_uleb(s, 1u + prog->func_count + (kernel ? (unsigned)KERNEL_TYPES : 0u)) && put_byte(s, TYPE_FUNC) && put_uleb(s, 1) && put_byte(s, TYPE_I32) &&
           put_uleb(s, 1) && put_byte(s, TYPE_I64);
  for (i = 0; i < prog->func_count && ok; i++) {
    ok = put_byte(s, TYPE_FUNC) && put_uleb(s, prog->funcs[i].param_count);
    for (k = 0; k < prog->funcs[i].param_count && ok; k++) ok = put_byte(s, TYPE_I64);
    ok = ok && put_uleb(s, 1) && put_byte(s, TYPE_I64);
  }
  return ok && (!kernel || kernel_types(s));
}

static int part_functions(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  size_t i;
  int kernel = prog_kernel(prog);
  int ok = put_uleb(s, 1u + prog->func_count + (kernel ? (unsigned)KERNEL_FUNCS : 0u));
  for (i = 0; i <= prog->func_count && ok; i++) ok = put_uleb(s, i);
  return ok && (!kernel || kernel_functions(s, 1u + (uint32_t)prog->func_count));
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
  int stream = 0;
  int ok;
  for (i = 0; i < prog->func_count; i++) stream = stream || prog->funcs[i].stream;
  ok = put_uleb(s, prog->func_count + (size_t)stream);
  for (i = 0; i < prog->func_count && ok; i++) {
    ok = put_name(s, prog->funcs[i].name) && put_byte(s, 0) && put_uleb(s, 1u + i);
  }
  return ok && (!stream || (put_name(s, "memory") && put_byte(s, 2) && put_uleb(s, 0)));
}

static int part_code(Sink *s, const void *arg) {
  const IrProgram *prog = arg;
  size_t i;
  uint32_t kernel = 1u + (uint32_t)prog->func_count;
  int has_kernel = prog_kernel(prog);
  int ok = put_uleb(s, 1u + prog->func_count + (has_kernel ? (unsigned)KERNEL_FUNCS : 0u)) && sized(s, part_alloc, NULL);
  for (i = 0; i < prog->func_count && ok; i++) {
    Entry entry = {&prog->funcs[i], kernel};
    ok = sized(s, part_entry, &entry);
  }
  return ok && (!has_kernel || kernel_code(s, &kernel));
}

/* The Poseidon2 kernel (S4 U2, Q-C6, the leaf-lang Q9 (a) mechanism):
   internal functions over BN254 Fr that mirror src/front/poseidon2.c. An
   element is 8 limbs of 32 bits, low limb first: limb K of the element at
   address A is the word at A + 8K (64 bytes). The arithmetic is in
   Montgomery form, R = 2^256. The constants (r, R^2, n' and the round
   constants in Montgomery form) come from the C, one source, as i64.const
   immediates: a data segment at a fixed address would collide with the
   stream input and the heap. The kernel does not call alloc: each caller
   gives a scratch address.

   With K the index of the first kernel function:
   - K + 0 reduce (out, x0 .. x7, hi): out := x - r when hi != 0 or x >= r,
     else x (the final conditional subtract).
   - K + 1 mul (out, a, b): out := a b R^-1 mod r, the CIOS of mont_mul. OUT
     can be A or B.
   - K + 2 add (out, a, b): out := a + b mod r.
   - K + 3 permute (state, scratch): poseidon2_permute on the 3 canonical
     elements at STATE. SCRATCH is 192 bytes.
   - K + 4 hash (tag, words, n, out, scratch): poseidon2_hash; OUT gets the
     digest element. SCRATCH is 448 bytes.
   - K + 5 merkle (words, n, out, scratch): merkleRoot over the FreeMon
     Digest chain at WORDS; OUT gets the root element. SCRATCH is 1056
     bytes.

   An IR module has the kernel only when a function has an IR_STMT_KERNEL
   (Q-S4-10 (a)): K = 1 + func_count, after the entries, so each other
   module stays as it was. The kernel test module (wasm_write_kernel_test)
   has K + 0 .. K + 4 at K = 0, then its entries and the SHA-512 kernel
   (part_sha512; an IR module gets it with the frostVerify lowering). */

/* The locals after the parameters. */
enum { REDUCE_HI = 9, REDUCE_D = 10, REDUCE_BORROW = 18, REDUCE_KEEP = 19 };
enum { MUL_A = 3, MUL_B = 11, MUL_T = 19, MUL_CARRY = 29, MUL_M = 30 };
enum { ADD_S = 3, ADD_CARRY = 11 };
enum { HASH_TAG, HASH_WORDS, HASH_N, HASH_OUT, HASH_SCRATCH, HASH_BLOCKS, HASH_K, HASH_W };

/* Byte offsets in the scratch of permute (the sum, the S-box temporary, the
   constant) and of hash (the state, the scratch of permute, the word), and
   the size of the hash scratch. */
enum { PERM_SUM = 0, PERM_TMP = 64, PERM_CONST = 128, HASH_PERM = 192, HASH_WORD = 384, HASH_BYTES = 448 };

/* The Wasm 1.0 module header. */
static const unsigned char header[8] = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};

/* An element address: the base address in a local plus a byte offset. */
typedef struct {
  uint32_t local;
  uint32_t bytes;
} Slot;

/* Element I of the state at the base address in local L. */
static Slot element(uint32_t l, unsigned i) {
  Slot at = {l, 64u * i};
  return at;
}

/* Pushes the i64 address of AT. */
static int slot_addr(Sink *s, Slot at) {
  return op2(s, OP_LOCAL_GET, at.local) && (at.bytes == 0 || (i64_const(s, at.bytes) && put_byte(s, OP_I64_ADD)));
}

/* Pushes the base address in local L as an i32, before a load or a store. */
static int base_of(Sink *s, uint32_t l) {
  return op2(s, OP_LOCAL_GET, l) && put_byte(s, OP_I32_WRAP_I64);
}

/* Pushes word K of the block at local L. */
static int load_at(Sink *s, uint32_t l, uint32_t k) {
  return base_of(s, l) && memarg(s, OP_I64_LOAD, k);
}

static int mask32(Sink *s) {
  return i64_const(s, 0xFFFFFFFFu) && put_byte(s, OP_I64_AND);
}

/* Pops V: local LOW := V mod 2^32, local HIGH := V >> 32. */
static int split(Sink *s, uint32_t low, uint32_t high) {
  return op2(s, OP_LOCAL_TEE, low) && i64_const(s, 32) && put_byte(s, OP_I64_SHR_U) && op2(s, OP_LOCAL_SET, high) &&
         op2(s, OP_LOCAL_GET, low) && mask32(s) && op2(s, OP_LOCAL_SET, low);
}

/* Words K and K + 1 of the block at local L := the low and the high 32 bits
   of local V. */
static int store_split(Sink *s, uint32_t l, uint32_t k, uint32_t v) {
  return base_of(s, l) && op2(s, OP_LOCAL_GET, v) && mask32(s) && memarg(s, OP_I64_STORE, k) && base_of(s, l) &&
         op2(s, OP_LOCAL_GET, v) && i64_const(s, 32) && put_byte(s, OP_I64_SHR_U) && memarg(s, OP_I64_STORE, k + 1u);
}

/* Pushes word K | word K + 1 << 32 of the block at local L. */
static int join(Sink *s, uint32_t l, uint32_t k) {
  return load_at(s, l, k) && load_at(s, l, k + 1u) && i64_const(s, 32) && put_byte(s, OP_I64_SHL) &&
         put_byte(s, OP_I64_OR);
}

/* Stores the limbs of V at AT. */
static int store_element(Sink *s, Slot at, Fr v) {
  unsigned k;
  int ok = 1;
  for (k = 0; k < FR_LIMBS && ok; k++)
    ok = base_of(s, at.local) && i64_const(s, v.limb[k]) && memarg(s, OP_I64_STORE, at.bytes / 8u + k);
  return ok;
}

/* Calls the kernel function F (out, a, b). */
static int call3(Sink *s, uint32_t f, Slot out, Slot a, Slot b) {
  return slot_addr(s, out) && slot_addr(s, a) && slot_addr(s, b) && op2(s, OP_CALL, f);
}

/* Declares N i64 locals after the parameters. */
static int i64_locals(Sink *s, unsigned n) {
  return put_uleb(s, 1) && put_uleb(s, n) && put_byte(s, TYPE_I64);
}

/* local 1 := 8n, the heap start of a stream entry. */
static int heap_local(Sink *s) {
  return op2(s, OP_LOCAL_GET, 0) && i64_const(s, 3) && put_byte(s, OP_I64_SHL) && op2(s, OP_LOCAL_SET, 1);
}

/* reduce: d := x - r with the borrow in bit 63 of each limb difference (the
   subtract of poseidon2.c); keep x when (hi | (borrow ^ 1)) = 0. */
static int part_reduce(Sink *s, const void *arg) {
  Fr r = fr_modulus();
  unsigned k;
  int ok = i64_locals(s, REDUCE_KEEP + 1u - REDUCE_D);
  (void)arg;
  for (k = 0; k < FR_LIMBS && ok; k++)
    ok = op2(s, OP_LOCAL_GET, 1u + k) && i64_const(s, r.limb[k]) && put_byte(s, OP_I64_SUB) &&
         op2(s, OP_LOCAL_GET, REDUCE_BORROW) && put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_TEE, REDUCE_D + k) &&
         i64_const(s, 63) && put_byte(s, OP_I64_SHR_U) && op2(s, OP_LOCAL_SET, REDUCE_BORROW) &&
         op2(s, OP_LOCAL_GET, REDUCE_D + k) && mask32(s) && op2(s, OP_LOCAL_SET, REDUCE_D + k);
  ok = ok && op2(s, OP_LOCAL_GET, REDUCE_HI) && op2(s, OP_LOCAL_GET, REDUCE_BORROW) && i64_const(s, 1) &&
       put_byte(s, OP_I64_XOR) && put_byte(s, OP_I64_OR) && put_byte(s, OP_I64_EQZ) &&
       put_byte(s, OP_I64_EXTEND_I32_U) && op2(s, OP_LOCAL_SET, REDUCE_KEEP);
  for (k = 0; k < FR_LIMBS && ok; k++)
    ok = base_of(s, 0) && op2(s, OP_LOCAL_GET, 1u + k) && op2(s, OP_LOCAL_GET, REDUCE_D + k) &&
         op2(s, OP_LOCAL_GET, REDUCE_KEEP) && put_byte(s, OP_I32_WRAP_I64) && put_byte(s, OP_SELECT) &&
         memarg(s, OP_I64_STORE, k);
  return ok && put_byte(s, OP_END);
}

/* mul: the CIOS loop of mont_mul, unrolled. a and b go to locals first, so
   OUT can be A or B. Each step x + y z + c is at most 2^64 - 1. */
static int part_mul(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  Fr r = fr_modulus();
  unsigned i;
  unsigned j;
  int ok = i64_locals(s, MUL_M + 1u - MUL_A);
  for (j = 0; j < FR_LIMBS && ok; j++)
    ok = load_at(s, 1, j) && op2(s, OP_LOCAL_SET, MUL_A + j) && load_at(s, 2, j) && op2(s, OP_LOCAL_SET, MUL_B + j);
  for (i = 0; i < FR_LIMBS && ok; i++) {
    ok = i64_const(s, 0) && op2(s, OP_LOCAL_SET, MUL_CARRY);
    /* t[j] + a[j] b[i] + carry */
    for (j = 0; j < FR_LIMBS && ok; j++)
      ok = op2(s, OP_LOCAL_GET, MUL_T + j) && op2(s, OP_LOCAL_GET, MUL_A + j) && op2(s, OP_LOCAL_GET, MUL_B + i) &&
           put_byte(s, OP_I64_MUL) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, MUL_CARRY) &&
           put_byte(s, OP_I64_ADD) && split(s, MUL_T + j, MUL_CARRY);
    /* t[N] + carry; m := t[0] n' mod 2^32; carry := (t[0] + m r[0]) >> 32 */
    ok = ok && op2(s, OP_LOCAL_GET, MUL_T + 8u) && op2(s, OP_LOCAL_GET, MUL_CARRY) && put_byte(s, OP_I64_ADD) &&
         split(s, MUL_T + 8u, MUL_T + 9u) && op2(s, OP_LOCAL_GET, MUL_T) && i64_const(s, fr_n_prime()) &&
         put_byte(s, OP_I64_MUL) && mask32(s) && op2(s, OP_LOCAL_SET, MUL_M) && op2(s, OP_LOCAL_GET, MUL_T) &&
         op2(s, OP_LOCAL_GET, MUL_M) && i64_const(s, r.limb[0]) && put_byte(s, OP_I64_MUL) && put_byte(s, OP_I64_ADD) &&
         i64_const(s, 32) && put_byte(s, OP_I64_SHR_U) && op2(s, OP_LOCAL_SET, MUL_CARRY);
    /* t[j - 1] := t[j] + m r[j] + carry */
    for (j = 1; j < FR_LIMBS && ok; j++)
      ok = op2(s, OP_LOCAL_GET, MUL_T + j) && op2(s, OP_LOCAL_GET, MUL_M) && i64_const(s, r.limb[j]) &&
           put_byte(s, OP_I64_MUL) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, MUL_CARRY) &&
           put_byte(s, OP_I64_ADD) && split(s, MUL_T + j - 1u, MUL_CARRY);
    /* t[N - 1] := t[N] + carry mod 2^32; t[N] := t[N + 1] + the high part */
    ok = ok && op2(s, OP_LOCAL_GET, MUL_T + 8u) && op2(s, OP_LOCAL_GET, MUL_CARRY) && put_byte(s, OP_I64_ADD) &&
         split(s, MUL_T + 7u, MUL_CARRY) && op2(s, OP_LOCAL_GET, MUL_T + 9u) && op2(s, OP_LOCAL_GET, MUL_CARRY) &&
         put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, MUL_T + 8u);
  }
  ok = ok && op2(s, OP_LOCAL_GET, 0);
  for (j = 0; j <= FR_LIMBS && ok; j++) ok = op2(s, OP_LOCAL_GET, MUL_T + j);
  return ok && op2(s, OP_CALL, *kernel + KERNEL_REDUCE) && put_byte(s, OP_END);
}

/* add: the limb sum with the carry, then reduce with the carry out as hi. */
static int part_add(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  unsigned k;
  int ok = i64_locals(s, ADD_CARRY + 1u - ADD_S);
  for (k = 0; k < FR_LIMBS && ok; k++)
    ok = load_at(s, 1, k) && load_at(s, 2, k) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, ADD_CARRY) &&
         put_byte(s, OP_I64_ADD) && split(s, ADD_S + k, ADD_CARRY);
  ok = ok && op2(s, OP_LOCAL_GET, 0);
  for (k = 0; k <= FR_LIMBS && ok; k++) ok = op2(s, OP_LOCAL_GET, ADD_S + k);
  return ok && op2(s, OP_CALL, *kernel + KERNEL_REDUCE) && put_byte(s, OP_END);
}

/* x := x^5 with TMP (sbox). */
static int sbox_at(Sink *s, uint32_t mul, Slot x, Slot tmp) {
  return call3(s, mul, tmp, x, x) && call3(s, mul, tmp, tmp, tmp) && call3(s, mul, x, x, tmp);
}

/* The external matrix (FULL) or the internal matrix on the state at local 0,
   with the sum in the scratch at local 1. */
static int linear_at(Sink *s, uint32_t add, int full) {
  Slot sum = {1, PERM_SUM};
  int ok = call3(s, add, sum, element(0, 0), element(0, 1)) && call3(s, add, sum, sum, element(0, 2)) &&
           call3(s, add, element(0, 0), element(0, 0), sum) && call3(s, add, element(0, 1), element(0, 1), sum);
  return ok && (full || call3(s, add, element(0, 2), element(0, 2), element(0, 2))) &&
         call3(s, add, element(0, 2), element(0, 2), sum);
}

/* The 4 external rounds with the round constants FIRST .. FIRST + 11. */
static int external_rounds_at(Sink *s, const uint32_t *kernel, unsigned first) {
  Slot c = {1, PERM_CONST};
  Slot tmp = {1, PERM_TMP};
  unsigned k;
  int ok = 1;
  for (k = 0; k < POSEIDON2_HALF_F * POSEIDON2_T && ok; k++)
    ok = store_element(s, c, poseidon2_round_constant(first + k)) &&
         call3(s, *kernel + KERNEL_ADD, element(0, k % POSEIDON2_T), element(0, k % POSEIDON2_T), c) &&
         sbox_at(s, *kernel + KERNEL_MUL, element(0, k % POSEIDON2_T), tmp) &&
         (k % POSEIDON2_T != POSEIDON2_T - 1u || linear_at(s, *kernel + KERNEL_ADD, 1));
  return ok;
}

/* permute: to Montgomery form (mul by R^2), the initial external matrix, 4
   external rounds, 56 internal rounds, 4 external rounds, from Montgomery
   form (mul by 1). */
static int part_permute(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  Slot c = {1, PERM_CONST};
  Slot tmp = {1, PERM_TMP};
  Fr one = {{1}};
  unsigned external = POSEIDON2_HALF_F * POSEIDON2_T;
  unsigned i;
  int ok = put_uleb(s, 0) && store_element(s, c, fr_r_squared());
  for (i = 0; i < POSEIDON2_T && ok; i++) ok = call3(s, *kernel + KERNEL_MUL, element(0, i), element(0, i), c);
  ok = ok && linear_at(s, *kernel + KERNEL_ADD, 1) && external_rounds_at(s, kernel, 0);
  for (i = 0; i < POSEIDON2_ROUNDS_P && ok; i++)
    ok = store_element(s, c, poseidon2_round_constant(external + i)) &&
         call3(s, *kernel + KERNEL_ADD, element(0, 0), element(0, 0), c) &&
         sbox_at(s, *kernel + KERNEL_MUL, element(0, 0), tmp) && linear_at(s, *kernel + KERNEL_ADD, 0);
  ok = ok && external_rounds_at(s, kernel, external + POSEIDON2_ROUNDS_P) && store_element(s, c, one);
  for (i = 0; i < POSEIDON2_T && ok; i++) ok = call3(s, *kernel + KERNEL_MUL, element(0, i), element(0, i), c);
  return ok && put_byte(s, OP_END);
}

/* Pushes word I of the current block: words[k + I]. */
static int stream_word(Sink *s, unsigned i) {
  return op2(s, OP_LOCAL_GET, HASH_WORDS) && op2(s, OP_LOCAL_GET, HASH_K) && i64_const(s, 3) &&
         put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_ADD) && put_byte(s, OP_I32_WRAP_I64) &&
         memarg(s, OP_I64_LOAD, i);
}

/* hash: blocks := n = 0 ? 1 : n / 2 + n % 2; the state (at the scratch) is
   0, 0, tag * 2^64 + n; for each block, words k and k + 1 (when below n) add
   into the rate, then permute; out := element 0. */
static int part_hash(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  Fr zero = {{0}};
  Slot word = {HASH_SCRATCH, HASH_WORD};
  Slot perm = {HASH_SCRATCH, HASH_PERM};
  unsigned i;
  int ok = i64_locals(s, HASH_W + 1u - HASH_BLOCKS) && i64_const(s, 1) && op2(s, OP_LOCAL_GET, HASH_N) &&
           i64_const(s, 1) && put_byte(s, OP_I64_SHR_U) && op2(s, OP_LOCAL_GET, HASH_N) && i64_const(s, 1) &&
           put_byte(s, OP_I64_AND) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, HASH_N) &&
           put_byte(s, OP_I64_EQZ) && put_byte(s, OP_SELECT) && op2(s, OP_LOCAL_SET, HASH_BLOCKS) &&
           store_element(s, word, zero);
  for (i = 0; i < POSEIDON2_T && ok; i++) ok = store_element(s, element(HASH_SCRATCH, i), zero);
  ok = ok && store_split(s, HASH_SCRATCH, 16, HASH_N) && store_split(s, HASH_SCRATCH, 18, HASH_TAG) &&
       put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY);
  for (i = 0; i < 2 && ok; i++)
    ok = op2(s, OP_LOCAL_GET, HASH_K) && i64_const(s, i) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, HASH_N) &&
         put_byte(s, OP_I64_LT_U) && put_byte(s, OP_IF) && put_byte(s, TYPE_EMPTY) && stream_word(s, i) &&
         op2(s, OP_LOCAL_SET, HASH_W) && store_split(s, HASH_SCRATCH, HASH_WORD / 8u, HASH_W) &&
         call3(s, *kernel + KERNEL_ADD, element(HASH_SCRATCH, i), element(HASH_SCRATCH, i), word) &&
         put_byte(s, OP_END);
  ok = ok && slot_addr(s, element(HASH_SCRATCH, 0)) && slot_addr(s, perm) &&
       op2(s, OP_CALL, *kernel + KERNEL_PERMUTE) && op2(s, OP_LOCAL_GET, HASH_K) && i64_const(s, 2) &&
       put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_TEE, HASH_K) && op2(s, OP_LOCAL_GET, HASH_BLOCKS) &&
       i64_const(s, 1) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_LT_U) && op2(s, OP_BR_IF, 0) &&
       put_byte(s, OP_END);
  for (i = 0; i < FR_LIMBS && ok; i++)
    ok = base_of(s, HASH_OUT) && load_at(s, HASH_SCRATCH, i) && memarg(s, OP_I64_STORE, i);
  return ok && put_byte(s, OP_END);
}

/* The locals of merkle: the parameters (words, n, out, scratch), then the
   leaves left, the leaf count, the level d, the stack slot address, the leaf
   address and a word. */
enum { MERKLE_WORDS, MERKLE_N, MERKLE_OUT, MERKLE_SCRATCH, MERKLE_LEFT, MERKLE_COUNT, MERKLE_D, MERKLE_TOP, MERKLE_AT, MERKLE_W };

/* The scratch of merkle, in words: the scratch of hash, the pair l, r (r is
   cur) and the stack of 17 full subtrees, 4 words each. */
enum { MERKLE_LEVELS = 16, MERKLE_TAG = 3, MERKLE_PAIR = HASH_BYTES / 8, MERKLE_CUR = MERKLE_PAIR + FR_WORDS };
enum { MERKLE_STACK = MERKLE_PAIR + 2 * FR_WORDS, MERKLE_BYTES = 8 * (MERKLE_STACK + FR_WORDS * (MERKLE_LEVELS + 1)) };

/* Words TO .. TO + 3 of the block at local L := words FROM .. FROM + 3 of
   the block at local M. */
static int copy_words(Sink *s, uint32_t l, uint32_t to, uint32_t m, uint32_t from) {
  unsigned w;
  int ok = 1;
  for (w = 0; w < FR_WORDS && ok; w++) ok = base_of(s, l) && load_at(s, m, from + w) && memarg(s, OP_I64_STORE, to + w);
  return ok;
}

/* Words AT .. AT + 3 of the merkle scratch := V. */
static int store_words(Sink *s, uint32_t at, const uint64_t v[FR_WORDS]) {
  unsigned w;
  int ok = 1;
  for (w = 0; w < FR_WORDS && ok; w++) ok = base_of(s, MERKLE_SCRATCH) && i64_const(s, v[w]) && memarg(s, OP_I64_STORE, at + w);
  return ok;
}

/* TOP := scratch + 32 d: stack slot d is at word MERKLE_STACK of TOP. */
static int stack_top(Sink *s) {
  return op2(s, OP_LOCAL_GET, MERKLE_SCRATCH) && op2(s, OP_LOCAL_GET, MERKLE_D) && i64_const(s, 5) &&
         put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, MERKLE_TOP);
}

/* local L := local L + V, modulo 2^64. */
static int bump(Sink *s, uint32_t l, uint64_t v) {
  return op2(s, OP_LOCAL_GET, l) && i64_const(s, v) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, l);
}

/* cur := node(l, r) = hash 3 over the 8 pair words, joined into 4 words. */
static int merkle_node(Sink *s, uint32_t kernel) {
  Slot pair = {MERKLE_SCRATCH, 8u * MERKLE_PAIR};
  unsigned w;
  int ok = i64_const(s, MERKLE_TAG) && slot_addr(s, pair) && i64_const(s, 2u * FR_WORDS) &&
           op2(s, OP_LOCAL_GET, MERKLE_OUT) && op2(s, OP_LOCAL_GET, MERKLE_SCRATCH) &&
           op2(s, OP_CALL, kernel + KERNEL_HASH);
  for (w = 0; w < FR_WORDS && ok; w++)
    ok = base_of(s, MERKLE_SCRATCH) && join(s, MERKLE_OUT, 2u * w) && memarg(s, OP_I64_STORE, MERKLE_CUR + w);
  return ok;
}

/* merkle: the root of the Merkle tree of 16 levels (eval.c reduce_merkle).
   WORDS is the FreeMon Digest chain: per leaf the word 1 then 4 words, at
   the end 0 (n = 5L + 1, L at most 2^16). Per leaf: cur := the leaf; while
   bit d of count is 1, cur := node(stack[d], cur), d += 1; stack[d] := cur.
   Then, for count below 2^16, cur := z_0 and, at each level h below 16, cur
   := node(stack[h], cur) when bit h of count is 1, else node(cur, z_h). At
   count 2^16, cur is stack[16]. OUT := the limbs of cur. node(l, r) = hash 3
   over the 4 words of l then of r; z_0 = 0, z_h+1 = node(z_h, z_h), from
   poseidon2_hash at emit time. */
static int part_merkle(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  uint64_t zero[MERKLE_LEVELS][FR_WORDS] = {{0}};
  uint64_t pair[2 * FR_WORDS];
  Fr digest;
  unsigned h;
  unsigned w;
  int ok;
  for (h = 0; h + 1u < MERKLE_LEVELS; h++) {
    memcpy(pair, zero[h], sizeof zero[h]);
    memcpy(pair + FR_WORDS, zero[h], sizeof zero[h]);
    poseidon2_hash(MERKLE_TAG, pair, 2u * FR_WORDS, &digest);
    fr_to_words(&digest, zero[h + 1u]);
  }
  ok = i64_locals(s, MERKLE_W + 1u - MERKLE_LEFT) && op2(s, OP_LOCAL_GET, MERKLE_N) && i64_const(s, 1u + FR_WORDS) &&
       put_byte(s, OP_I64_DIV_U) && op2(s, OP_LOCAL_SET, MERKLE_LEFT) && op2(s, OP_LOCAL_GET, MERKLE_WORDS) &&
       i64_const(s, 8) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, MERKLE_AT) && put_byte(s, OP_BLOCK) &&
       put_byte(s, TYPE_EMPTY) && put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY) && op2(s, OP_LOCAL_GET, MERKLE_LEFT) &&
       put_byte(s, OP_I64_EQZ) && op2(s, OP_BR_IF, 1) && copy_words(s, MERKLE_SCRATCH, MERKLE_CUR, MERKLE_AT, 0) &&
       i64_const(s, 0) && op2(s, OP_LOCAL_SET, MERKLE_D) && put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY) &&
       put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY) && op2(s, OP_LOCAL_GET, MERKLE_COUNT) &&
       op2(s, OP_LOCAL_GET, MERKLE_D) && put_byte(s, OP_I64_SHR_U) && i64_const(s, 1) && put_byte(s, OP_I64_AND) &&
       put_byte(s, OP_I64_EQZ) && op2(s, OP_BR_IF, 1) && stack_top(s) &&
       copy_words(s, MERKLE_SCRATCH, MERKLE_PAIR, MERKLE_TOP, MERKLE_STACK) && merkle_node(s, *kernel) &&
       bump(s, MERKLE_D, 1) && op2(s, OP_BR, 0) && put_byte(s, OP_END) && put_byte(s, OP_END) && stack_top(s) &&
       copy_words(s, MERKLE_TOP, MERKLE_STACK, MERKLE_SCRATCH, MERKLE_CUR) && bump(s, MERKLE_COUNT, 1) &&
       bump(s, MERKLE_LEFT, ~(uint64_t)0) && bump(s, MERKLE_AT, 8u * (1u + FR_WORDS)) && op2(s, OP_BR, 0) &&
       put_byte(s, OP_END) && put_byte(s, OP_END) && op2(s, OP_LOCAL_GET, MERKLE_COUNT) &&
       i64_const(s, (uint64_t)1 << MERKLE_LEVELS) && put_byte(s, OP_I64_LT_U) && put_byte(s, OP_IF) &&
       put_byte(s, TYPE_EMPTY) && store_words(s, MERKLE_CUR, zero[0]);
  for (h = 0; h < MERKLE_LEVELS && ok; h++)
    ok = op2(s, OP_LOCAL_GET, MERKLE_COUNT) && i64_const(s, h) && put_byte(s, OP_I64_SHR_U) && i64_const(s, 1) &&
         put_byte(s, OP_I64_AND) && put_byte(s, OP_I32_WRAP_I64) && put_byte(s, OP_IF) && put_byte(s, TYPE_EMPTY) &&
         copy_words(s, MERKLE_SCRATCH, MERKLE_PAIR, MERKLE_SCRATCH, MERKLE_STACK + FR_WORDS * h) &&
         put_byte(s, OP_ELSE) && copy_words(s, MERKLE_SCRATCH, MERKLE_PAIR, MERKLE_SCRATCH, MERKLE_CUR) &&
         store_words(s, MERKLE_CUR, zero[h]) && put_byte(s, OP_END) && merkle_node(s, *kernel);
  ok = ok && put_byte(s, OP_END);
  for (w = 0; w < FR_WORDS && ok; w++)
    ok = load_at(s, MERKLE_SCRATCH, MERKLE_CUR + w) && op2(s, OP_LOCAL_SET, MERKLE_W) &&
         store_split(s, MERKLE_OUT, 2u * w, MERKLE_W);
  return ok && put_byte(s, OP_END);
}

/* The kernel stmt: local := alloc(bytes + 64), the scratch, with OUT at
   word bytes / 8; call hash (counter, expr, n, OUT, scratch) or, for counter
   0, merkle (expr, n, OUT, scratch); local := the Digest block [0, w0, 0, w1,
   0, w2, 0, w3, 0], word w = limbs 2w and 2w + 1 of OUT. The block address
   waits in T + 2. */
static int emit_kernel(Sink *s, const IrStmt *st, uint32_t t, uint32_t kernel, unsigned depth) {
  int merkle = st->counter == 0;
  uint32_t bytes = merkle ? MERKLE_BYTES : HASH_BYTES;
  uint32_t k;
  int ok = i32_const(s, bytes + 64u) && op2(s, OP_CALL, 0) && op2(s, OP_LOCAL_SET, st->local) &&
           (merkle || i64_const(s, st->counter)) && emit_expr(s, st->expr, t, depth + 1u) &&
           emit_expr(s, st->fields[0], t, depth + 1u) && op2(s, OP_LOCAL_GET, st->local) && i64_const(s, bytes) &&
           put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, st->local) &&
           op2(s, OP_CALL, kernel + (merkle ? KERNEL_MERKLE : KERNEL_HASH)) &&
           i32_const(s, 8u * (2u * FR_WORDS + 1u)) && op2(s, OP_CALL, 0) && op2(s, OP_LOCAL_SET, t + 2u);
  for (k = 0; k < 2u * FR_WORDS + 1u && ok; k++)
    ok = base_of(s, t + 2u) && (k % 2u == 0 ? i64_const(s, 0) : join(s, st->local, bytes / 8u + k - 1u)) &&
         memarg(s, OP_I64_STORE, k);
  return ok && op2(s, OP_LOCAL_GET, t + 2u) && op2(s, OP_LOCAL_SET, st->local);
}

/* Traps unless the stream entry has N input words. */
static int count_guard(Sink *s, uint64_t n) {
  return op2(s, OP_LOCAL_GET, 0) && i64_const(s, n) && put_byte(s, OP_I64_NE) && put_byte(s, OP_IF) &&
         put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END);
}

/* The SHA-512 kernel (S4 U5, FIPS 180-4 6.4 with the padding of 5.1.2):
   sha512 (bytes, n, out, scratch): OUT gets the 64 digest bytes of the N
   bytes at BYTES. The full blocks are read in place; SCRATCH (256 bytes)
   gets the last 1 or 2 blocks: the tail of the message, 0x80, the zeros
   and the bit length. A message word is big endian: an i64.load and a
   byte swap. K and H(0) come from src/front/sha512.c, one source. The 80
   rounds are unrolled: round t names a .. h by the locals SHA_V + (i - t)
   mod 8, so no round moves a word, and W_t is in local SHA_W + t mod 16.
   The locals: the parameters, the full block count, the block count, the
   block index, the block address, T1, a temporary, H, a .. h and W. */
enum { SHA_BYTES, SHA_N, SHA_OUT, SHA_SCRATCH, SHA_FULL, SHA_BLOCKS, SHA_K, SHA_AT, SHA_T1, SHA_X, SHA_H };
enum { SHA_V = SHA_H + 8, SHA_W = SHA_V + 8, SHA_LOCALS = SHA_W + 16 };

/* The rotate amounts of Sigma0 and Sigma1 (4.10, 4.11), then of sigma0 and
   sigma1 (4.12, 4.13; there the third amount is a shift). */
static const unsigned sha_rotations[4][3] = {{28, 34, 39}, {14, 18, 41}, {1, 8, 7}, {19, 61, 6}};

/* A byte load or store at offset 0 (the alignment is 2^0). */
static int memarg8(Sink *s, unsigned op) {
  return put_byte(s, op) && put_uleb(s, 0) && put_uleb(s, 0);
}

/* Pushes n mod 128, the byte count of the message tail. */
static int sha_tail(Sink *s) {
  return op2(s, OP_LOCAL_GET, SHA_N) && i64_const(s, 127) && put_byte(s, OP_I64_AND);
}

/* Pushes Sigma0, Sigma1 (K = 0, 1), sigma0 or sigma1 (K = 2, 3) of local L. */
static int sha_sigma(Sink *s, unsigned k, uint32_t l) {
  unsigned i;
  int ok = 1;
  for (i = 0; i < 3 && ok; i++)
    ok = op2(s, OP_LOCAL_GET, l) && i64_const(s, sha_rotations[k][i]) &&
         put_byte(s, k >= 2 && i == 2 ? OP_I64_SHR_U : OP_I64_ROTR) && (i == 0 || put_byte(s, OP_I64_XOR));
  return ok;
}

/* Pops x, pushes x with its 8 bytes in the reverse order. SHA_X is the
   temporary. */
static int byte_swap(Sink *s) {
  static const uint64_t masks[2] = {0x00FF00FF00FF00FFu, 0x0000FFFF0000FFFFu};
  unsigned i;
  int ok = 1;
  for (i = 0; i < 2 && ok; i++)
    ok = op2(s, OP_LOCAL_TEE, SHA_X) && i64_const(s, masks[i]) && put_byte(s, OP_I64_AND) && i64_const(s, 8u << i) &&
         put_byte(s, OP_I64_SHL) && op2(s, OP_LOCAL_GET, SHA_X) && i64_const(s, 8u << i) && put_byte(s, OP_I64_SHR_U) &&
         i64_const(s, masks[i]) && put_byte(s, OP_I64_AND) && put_byte(s, OP_I64_OR);
  return ok && i64_const(s, 32) && put_byte(s, OP_I64_ROTR);
}

/* The local of the working word I (a = 0 .. h = 7) in round T. */
static uint32_t sha_v(unsigned i, unsigned t) {
  return SHA_V + (i + 8u - t % 8u) % 8u;
}

/* Round T (6.4.2 step 3): W_t from the schedule when t >= 16, then T1,
   d := d + T1 and h := T1 + T2. Ch is g ^ (e & (f ^ g)); Maj is
   (a & b) | (c & (a | b)). */
static int sha_round(Sink *s, unsigned t) {
  uint32_t w = SHA_W + t % 16u;
  int ok = t < 16u || (sha_sigma(s, 3, SHA_W + (t - 2u) % 16u) && op2(s, OP_LOCAL_GET, SHA_W + (t - 7u) % 16u) &&
                       put_byte(s, OP_I64_ADD) && sha_sigma(s, 2, SHA_W + (t - 15u) % 16u) && put_byte(s, OP_I64_ADD) &&
                       op2(s, OP_LOCAL_GET, w) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, w));
  ok = ok && op2(s, OP_LOCAL_GET, sha_v(7, t)) && sha_sigma(s, 1, sha_v(4, t)) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_GET, sha_v(6, t)) && op2(s, OP_LOCAL_GET, sha_v(4, t)) && op2(s, OP_LOCAL_GET, sha_v(5, t)) &&
       op2(s, OP_LOCAL_GET, sha_v(6, t)) && put_byte(s, OP_I64_XOR) && put_byte(s, OP_I64_AND) &&
       put_byte(s, OP_I64_XOR) && put_byte(s, OP_I64_ADD) && i64_const(s, sha512_round_constant(t)) &&
       put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, w) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_TEE, SHA_T1) &&
       op2(s, OP_LOCAL_GET, sha_v(3, t)) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, sha_v(3, t)) &&
       op2(s, OP_LOCAL_GET, SHA_T1) && sha_sigma(s, 0, sha_v(0, t)) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_GET, sha_v(0, t)) && op2(s, OP_LOCAL_GET, sha_v(1, t)) && put_byte(s, OP_I64_AND) &&
       op2(s, OP_LOCAL_GET, sha_v(2, t)) && op2(s, OP_LOCAL_GET, sha_v(0, t)) && op2(s, OP_LOCAL_GET, sha_v(1, t)) &&
       put_byte(s, OP_I64_OR) && put_byte(s, OP_I64_AND) && put_byte(s, OP_I64_OR) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_SET, sha_v(7, t));
  return ok;
}

/* The steps: zero the scratch; copy the tail bytes; 0x80 after them; the
   block count (one more block when the tail is 112 bytes or more: no room
   for the 16 length bytes); the bit length, big endian, at the end of the
   last block; H := H(0); per block (in place, then in the scratch) load W,
   80 rounds, H := H + a .. h; OUT := H, big endian. */
static int part_sha512(Sink *s, const void *arg) {
  unsigned i;
  int ok = i64_locals(s, SHA_LOCALS - SHA_FULL) && op2(s, OP_LOCAL_GET, SHA_N) && i64_const(s, 7) &&
           put_byte(s, OP_I64_SHR_U) && op2(s, OP_LOCAL_SET, SHA_FULL);
  (void)arg;
  for (i = 0; i < 32 && ok; i++) ok = base_of(s, SHA_SCRATCH) && i64_const(s, 0) && memarg(s, OP_I64_STORE, i);
  ok = ok && put_byte(s, OP_BLOCK) && put_byte(s, TYPE_EMPTY) && put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY) &&
       op2(s, OP_LOCAL_GET, SHA_X) && sha_tail(s) && put_byte(s, OP_I64_GE_U) && op2(s, OP_BR_IF, 1) &&
       op2(s, OP_LOCAL_GET, SHA_SCRATCH) && op2(s, OP_LOCAL_GET, SHA_X) && put_byte(s, OP_I64_ADD) &&
       put_byte(s, OP_I32_WRAP_I64) && op2(s, OP_LOCAL_GET, SHA_BYTES) && op2(s, OP_LOCAL_GET, SHA_FULL) &&
       i64_const(s, 7) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_GET, SHA_X) &&
       put_byte(s, OP_I64_ADD) && put_byte(s, OP_I32_WRAP_I64) && memarg8(s, OP_I64_LOAD8_U) &&
       memarg8(s, OP_I64_STORE8) && op2(s, OP_LOCAL_GET, SHA_X) && i64_const(s, 1) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_SET, SHA_X) && op2(s, OP_BR, 0) && put_byte(s, OP_END) && put_byte(s, OP_END);
  ok = ok && op2(s, OP_LOCAL_GET, SHA_SCRATCH) && sha_tail(s) && put_byte(s, OP_I64_ADD) &&
       put_byte(s, OP_I32_WRAP_I64) && i64_const(s, 0x80) && memarg8(s, OP_I64_STORE8) &&
       op2(s, OP_LOCAL_GET, SHA_FULL) && i64_const(s, 1) && put_byte(s, OP_I64_ADD) && sha_tail(s) &&
       i64_const(s, 112) && put_byte(s, OP_I64_GE_U) && put_byte(s, OP_I64_EXTEND_I32_U) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_SET, SHA_BLOCKS) && op2(s, OP_LOCAL_GET, SHA_SCRATCH) && op2(s, OP_LOCAL_GET, SHA_BLOCKS) &&
       op2(s, OP_LOCAL_GET, SHA_FULL) && put_byte(s, OP_I64_SUB) && i64_const(s, 7) && put_byte(s, OP_I64_SHL) &&
       put_byte(s, OP_I64_ADD) && i64_const(s, 16) && put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_SET, SHA_AT) &&
       base_of(s, SHA_AT) && op2(s, OP_LOCAL_GET, SHA_N) && i64_const(s, 61) && put_byte(s, OP_I64_SHR_U) &&
       byte_swap(s) && memarg(s, OP_I64_STORE, 0) && base_of(s, SHA_AT) && op2(s, OP_LOCAL_GET, SHA_N) &&
       i64_const(s, 3) && put_byte(s, OP_I64_SHL) && byte_swap(s) && memarg(s, OP_I64_STORE, 1);
  for (i = 0; i < 8 && ok; i++) ok = i64_const(s, sha512_initial_hash(i)) && op2(s, OP_LOCAL_SET, SHA_H + i);
  ok = ok && put_byte(s, OP_LOOP) && put_byte(s, TYPE_EMPTY) && op2(s, OP_LOCAL_GET, SHA_BYTES) &&
       op2(s, OP_LOCAL_GET, SHA_K) && i64_const(s, 7) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_GET, SHA_SCRATCH) && op2(s, OP_LOCAL_GET, SHA_K) && op2(s, OP_LOCAL_GET, SHA_FULL) &&
       put_byte(s, OP_I64_SUB) && i64_const(s, 7) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_ADD) &&
       op2(s, OP_LOCAL_GET, SHA_K) && op2(s, OP_LOCAL_GET, SHA_FULL) && put_byte(s, OP_I64_LT_U) &&
       put_byte(s, OP_SELECT) && op2(s, OP_LOCAL_SET, SHA_AT);
  for (i = 0; i < 16 && ok; i++) ok = load_at(s, SHA_AT, i) && byte_swap(s) && op2(s, OP_LOCAL_SET, SHA_W + i);
  for (i = 0; i < 8 && ok; i++) ok = op2(s, OP_LOCAL_GET, SHA_H + i) && op2(s, OP_LOCAL_SET, SHA_V + i);
  for (i = 0; i < 80 && ok; i++) ok = sha_round(s, i);
  for (i = 0; i < 8 && ok; i++)
    ok = op2(s, OP_LOCAL_GET, SHA_H + i) && op2(s, OP_LOCAL_GET, SHA_V + i) && put_byte(s, OP_I64_ADD) &&
         op2(s, OP_LOCAL_SET, SHA_H + i);
  ok = ok && op2(s, OP_LOCAL_GET, SHA_K) && i64_const(s, 1) && put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_TEE, SHA_K) &&
       op2(s, OP_LOCAL_GET, SHA_BLOCKS) && put_byte(s, OP_I64_LT_U) && op2(s, OP_BR_IF, 0) && put_byte(s, OP_END);
  for (i = 0; i < 8 && ok; i++)
    ok = base_of(s, SHA_OUT) && op2(s, OP_LOCAL_GET, SHA_H + i) && byte_swap(s) && memarg(s, OP_I64_STORE, i);
  return ok && put_byte(s, OP_END);
}

/* p2perm: the state at h = 8n, the scratch at h + 192, the block [12, the 12
   words] at h + 384. Input word q is limbs 2q and 2q + 1 of the state. */
static int part_test_permute(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  Slot scratch = {1, 192};
  Slot block = {1, 384};
  unsigned q;
  int ok = i64_locals(s, 2) && count_guard(s, 12) && heap_local(s);
  for (q = 0; q < 12 && ok; q++)
    ok = i32_const(s, 0) && memarg(s, OP_I64_LOAD, q) && op2(s, OP_LOCAL_SET, 2) && store_split(s, 1, 2u * q, 2);
  ok = ok && slot_addr(s, element(1, 0)) && slot_addr(s, scratch) && op2(s, OP_CALL, *kernel + KERNEL_PERMUTE) &&
       base_of(s, 1) && i64_const(s, 12) && memarg(s, OP_I64_STORE, 48);
  for (q = 0; q < 12 && ok; q++) ok = base_of(s, 1) && join(s, 1, 2u * q) && memarg(s, OP_I64_STORE, 49u + q);
  return ok && slot_addr(s, block) && put_byte(s, OP_END);
}

/* p2hash: [tag, w_1 .. w_m] -> the scratch at h = 8n, the digest at h + 448,
   the block [4, the 4 words] at h + 512. */
static int part_test_hash(Sink *s, const void *arg) {
  const uint32_t *kernel = arg;
  Slot digest = {1, 448};
  Slot block = {1, 512};
  unsigned w;
  int ok = i64_locals(s, 1) && op2(s, OP_LOCAL_GET, 0) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_IF) &&
           put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END) && heap_local(s) &&
           i32_const(s, 0) && memarg(s, OP_I64_LOAD, 0) && i64_const(s, 8) && op2(s, OP_LOCAL_GET, 0) &&
           i64_const(s, 1) && put_byte(s, OP_I64_SUB) && slot_addr(s, digest) && op2(s, OP_LOCAL_GET, 1) &&
           op2(s, OP_CALL, *kernel + KERNEL_HASH) && base_of(s, 1) && i64_const(s, 4) && memarg(s, OP_I64_STORE, 64);
  for (w = 0; w < FR_WORDS && ok; w++) ok = base_of(s, 1) && join(s, 1, 56u + 2u * w) && memarg(s, OP_I64_STORE, 65u + w);
  return ok && slot_addr(s, block) && put_byte(s, OP_END);
}

/* ops: [a, b, k] -> the block [3, a xor b, a and b, a rotr k] at h = 24. */
static int part_test_ops(Sink *s, const void *arg) {
  static const unsigned ops[3] = {OP_I64_XOR, OP_I64_AND, OP_I64_ROTR};
  unsigned i;
  int ok = i64_locals(s, 1) && count_guard(s, 3) && heap_local(s) && base_of(s, 1) && i64_const(s, 3) &&
           memarg(s, OP_I64_STORE, 0);
  (void)arg;
  for (i = 0; i < 3 && ok; i++)
    ok = base_of(s, 1) && i32_const(s, 0) && memarg(s, OP_I64_LOAD, 0) && i32_const(s, 0) &&
         memarg(s, OP_I64_LOAD, 1u + i / 2u) && put_byte(s, ops[i]) && memarg(s, OP_I64_STORE, 1u + i);
  return ok && op2(s, OP_LOCAL_GET, 1) && put_byte(s, OP_END);
}

/* The SHA-512 kernel in the kernel test module (sha512 is the next one). */
enum { KERNEL_TEST_SHA512 = KERNEL_MERKLE + 3 };

/* sha512: [n, w_1 .. w_m] (the n bytes, 8 per word, little endian; n <= 8m,
   else a trap) -> the scratch at h = 8(m + 1), the digest at h + 256, the
   block [8, the 8 digest words in the same byte order] at h + 320. */
static int part_test_sha512(Sink *s, const void *arg) {
  Slot digest = {1, 256};
  Slot block = {1, 320};
  unsigned w;
  int ok = i64_locals(s, 1) && op2(s, OP_LOCAL_GET, 0) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_IF) &&
           put_byte(s, TYPE_EMPTY) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END) && heap_local(s) &&
           i32_const(s, 0) && memarg(s, OP_I64_LOAD, 0) && op2(s, OP_LOCAL_GET, 1) && i64_const(s, 8) &&
           put_byte(s, OP_I64_SUB) && put_byte(s, OP_I64_GT_U) && put_byte(s, OP_IF) && put_byte(s, TYPE_EMPTY) &&
           put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END) && i64_const(s, 8) && i32_const(s, 0) &&
           memarg(s, OP_I64_LOAD, 0) && slot_addr(s, digest) && op2(s, OP_LOCAL_GET, 1) &&
           op2(s, OP_CALL, KERNEL_TEST_SHA512) && base_of(s, 1) && i64_const(s, 8) && memarg(s, OP_I64_STORE, 40);
  (void)arg;
  for (w = 0; w < 8 && ok; w++) ok = base_of(s, 1) && load_at(s, 1, 32u + w) && memarg(s, OP_I64_STORE, 41u + w);
  return ok && slot_addr(s, block) && put_byte(s, OP_END);
}

/* The Ed25519 verify kernel (S4 U5, RFC 8032 5.1.7, the mirror of
   src/front/ed25519.c): a field element is 16 signed i64 limbs of 16 bits
   (128 bytes), a point is x, y, z, t (512 bytes), a bit is an i64 0 or 1.
   Every parameter is an i64 address. The functions are numbered from
   EdIndex.ed in the order of the ED_ enum, and verify calls the SHA-512
   kernel at EdIndex.sha512: a module places them by the ARG. */
typedef struct {
  uint32_t ed;
  uint32_t sha512;
} EdIndex;

/* The byte offsets of the coordinates of a point. */
enum { ED_X = 0, ED_Y = 128, ED_Z = 256, ED_T = 384 };

/* A three-address step: F (o, a, b). */
typedef struct {
  unsigned f;
  Slot o, a, b;
} EdStep;

static Slot ed_at(uint32_t l, uint32_t bytes) {
  Slot at = {l, bytes};
  return at;
}

/* Calls the kernel function F (out, a, b, c). */
static int call4(Sink *s, uint32_t f, Slot out, Slot a, Slot b, Slot c) {
  return slot_addr(s, out) && slot_addr(s, a) && slot_addr(s, b) && slot_addr(s, c) && op2(s, OP_CALL, f);
}

/* Runs the N steps of STEPS in order. */
static int ed_steps(Sink *s, const EdIndex *x, const EdStep *steps, size_t n) {
  size_t i;
  int ok = 1;
  for (i = 0; i < n && ok; i++) ok = call3(s, x->ed + steps[i].f, steps[i].o, steps[i].a, steps[i].b);
  return ok;
}

/* Pushes local L op the constant V. */
static int ed_get_op(Sink *s, uint32_t l, uint64_t v, unsigned op) {
  return op2(s, OP_LOCAL_GET, l) && i64_const(s, v) && put_byte(s, op);
}

/* Opens a block, a loop or an if (OP) with no result. */
static int ed_open(Sink *s, unsigned op) {
  return put_byte(s, op) && put_byte(s, TYPE_EMPTY);
}

/* Traps when the i32 on the stack is not 0. */
static int ed_trap_if(Sink *s) {
  return ed_open(s, OP_IF) && put_byte(s, OP_UNREACHABLE) && put_byte(s, OP_END);
}

/* Stores the N words at FROM to TO. */
static int ed_copy(Sink *s, Slot to, Slot from, unsigned n) {
  unsigned k;
  int ok = 1;
  for (k = 0; k < n && ok; k++)
    ok = base_of(s, to.local) && load_at(s, from.local, from.bytes / 8u + k) &&
         memarg(s, OP_I64_STORE, to.bytes / 8u + k);
  return ok;
}

/* Stores the limbs of the curve constant WHICH at AT. */
static int ed_store_const(Sink *s, Slot at, unsigned which) {
  unsigned k;
  int ok = 1;
  for (k = 0; k < 16 && ok; k++)
    ok = base_of(s, at.local) && i64_const(s, ed25519_constant(which, k)) &&
         memarg(s, OP_I64_STORE, at.bytes / 8u + k);
  return ok;
}

/* Stores the field element V (below 2^16) at AT. */
static int ed_store_small(Sink *s, Slot at, uint64_t v) {
  unsigned k;
  int ok = 1;
  for (k = 0; k < 16 && ok; k++)
    ok = base_of(s, at.local) && i64_const(s, k == 0 ? v : 0) && memarg(s, OP_I64_STORE, at.bytes / 8u + k);
  return ok;
}

/* carry (o): one carry pass of fe_carry over the 16 limbs of O (limb i
   keeps its low 16 bits; the carry of limb 15 goes to limb 0 times 38).
   Locals: O, the limbs, the carry. */
enum { EDC_L = 1, EDC_C = EDC_L + 16 };

static int part_ed_carry(Sink *s, const void *arg) {
  unsigned i;
  int ok = i64_locals(s, 17);
  (void)arg;
  for (i = 0; i < 16 && ok; i++) ok = load_at(s, 0, i) && op2(s, OP_LOCAL_SET, EDC_L + i);
  for (i = 0; i < 16 && ok; i++) {
    unsigned next = EDC_L + (i + 1u) % 16u;
    ok = ed_get_op(s, EDC_L + i, 65536, OP_I64_ADD) && op2(s, OP_LOCAL_TEE, EDC_L + i) && i64_const(s, 16) &&
         put_byte(s, OP_I64_SHR_S) && op2(s, OP_LOCAL_SET, EDC_C) && op2(s, OP_LOCAL_GET, next) &&
         ed_get_op(s, EDC_C, 1, OP_I64_SUB) && (i < 15u || (i64_const(s, 38) && put_byte(s, OP_I64_MUL))) &&
         put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, next) && op2(s, OP_LOCAL_GET, EDC_L + i) &&
         ed_get_op(s, EDC_C, 16, OP_I64_SHL) && put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_SET, EDC_L + i);
  }
  for (i = 0; i < 16 && ok; i++) ok = base_of(s, 0) && op2(s, OP_LOCAL_GET, EDC_L + i) && memarg(s, OP_I64_STORE, i);
  return ok && put_byte(s, OP_END);
}

/* mul (o, a, b): O := A B mod p (fe_mul: the 31 product limbs, the top 15
   folded down times 38, then 2 carry passes; O may be A or B, as A and B
   are read first). Locals: the parameters, A, B, the product limbs T. */
enum { EDM_A = 3, EDM_B = EDM_A + 16, EDM_T = EDM_B + 16, EDM_LOCALS = EDM_T + 31 };

static int part_ed_mul(Sink *s, const void *arg) {
  const EdIndex *x = arg;
  unsigned i;
  unsigned k;
  int ok = i64_locals(s, EDM_LOCALS - EDM_A);
  for (i = 0; i < 16 && ok; i++)
    ok = load_at(s, 1, i) && op2(s, OP_LOCAL_SET, EDM_A + i) && load_at(s, 2, i) && op2(s, OP_LOCAL_SET, EDM_B + i);
  for (k = 0; k < 31 && ok; k++) {
    unsigned lo = k < 16u ? 0 : k - 15u;
    unsigned hi = k < 16u ? k : 15u;
    for (i = lo; i <= hi && ok; i++)
      ok = op2(s, OP_LOCAL_GET, EDM_A + i) && op2(s, OP_LOCAL_GET, EDM_B + k - i) && put_byte(s, OP_I64_MUL) &&
           (i == lo || put_byte(s, OP_I64_ADD));
    ok = ok && op2(s, OP_LOCAL_SET, EDM_T + k);
  }
  for (i = 0; i < 15 && ok; i++)
    ok = op2(s, OP_LOCAL_GET, EDM_T + i) && ed_get_op(s, EDM_T + 16u + i, 38, OP_I64_MUL) && put_byte(s, OP_I64_ADD) &&
         op2(s, OP_LOCAL_SET, EDM_T + i);
  for (i = 0; i < 16 && ok; i++) ok = base_of(s, 0) && op2(s, OP_LOCAL_GET, EDM_T + i) && memarg(s, OP_I64_STORE, i);
  return ok && op2(s, OP_LOCAL_GET, 0) && op2(s, OP_CALL, x->ed + ED_CARRY) && op2(s, OP_LOCAL_GET, 0) &&
         op2(s, OP_CALL, x->ed + ED_CARRY) && put_byte(s, OP_END);
}

/* add and sub (o, a, b): O := A op B limb by limb, no carry (fe_add,
   fe_sub; O may be A or B). */
static int ed_limbwise(Sink *s, unsigned op) {
  unsigned i;
  int ok = put_uleb(s, 0);
  for (i = 0; i < 16 && ok; i++)
    ok = base_of(s, 0) && load_at(s, 1, i) && load_at(s, 2, i) && put_byte(s, op) && memarg(s, OP_I64_STORE, i);
  return ok && put_byte(s, OP_END);
}

static int part_ed_add(Sink *s, const void *arg) {
  (void)arg;
  return ed_limbwise(s, OP_I64_ADD);
}

static int part_ed_sub(Sink *s, const void *arg) {
  (void)arg;
  return ed_limbwise(s, OP_I64_SUB);
}

/* pow2523 (o, a, tmp): O := A^((p - 5) / 8) (fe_pow2523: 251 squares,
   each but the second last one times A). TMP (128 bytes) holds the power,
   so O may be A. Locals: the parameters, J = the C index + 1. */
static int part_ed_pow2523(Sink *s, const void *arg) {
  const EdIndex *x = arg;
  Slot tmp = ed_at(2, 0);
  int ok = i64_locals(s, 1) && ed_copy(s, tmp, ed_at(1, 0), 16) && i64_const(s, 251) && op2(s, OP_LOCAL_SET, 3) &&
           ed_open(s, OP_LOOP) && call3(s, x->ed + ED_MUL, tmp, tmp, tmp) && ed_get_op(s, 3, 2, OP_I64_NE) &&
           ed_open(s, OP_IF) && call3(s, x->ed + ED_MUL, tmp, tmp, ed_at(1, 0)) && put_byte(s, OP_END) &&
           ed_get_op(s, 3, 1, OP_I64_SUB) && op2(s, OP_LOCAL_TEE, 3) && i64_const(s, 0) && put_byte(s, OP_I64_NE) &&
           op2(s, OP_BR_IF, 0) && put_byte(s, OP_END) && ed_copy(s, ed_at(0, 0), tmp, 16);
  return ok && put_byte(s, OP_END);
}

/* pack (out, a, tmp): the 32 bytes of A mod p at OUT (fe_pack: 3 carry
   passes, then 2 passes that subtract p when it does not borrow). TMP (128
   bytes) gets the carried copy. Locals: the parameters, T, M, the
   borrow. */
enum { EDP_T = 3, EDP_M = EDP_T + 16, EDP_BORROW = EDP_M + 16 };

static int part_ed_pack(Sink *s, const void *arg) {
  const EdIndex *x = arg;
  unsigned pass;
  unsigned i;
  unsigned w;
  int ok = i64_locals(s, 33) && ed_copy(s, ed_at(2, 0), ed_at(1, 0), 16);
  for (i = 0; i < 3 && ok; i++) ok = op2(s, OP_LOCAL_GET, 2) && op2(s, OP_CALL, x->ed + ED_CARRY);
  for (i = 0; i < 16 && ok; i++) ok = load_at(s, 2, i) && op2(s, OP_LOCAL_SET, EDP_T + i);
  for (pass = 0; pass < 2 && ok; pass++) {
    for (i = 0; i < 16 && ok; i++) {
      uint64_t p = 0xFFFFu - (i == 0 ? 0x12u : 0) - (i == 15 ? 0x8000u : 0);
      ok = ed_get_op(s, EDP_T + i, p, OP_I64_SUB) &&
           (i == 0 || (ed_get_op(s, EDP_M + i - 1u, 16, OP_I64_SHR_S) && i64_const(s, 1) && put_byte(s, OP_I64_AND) &&
                       put_byte(s, OP_I64_SUB))) &&
           op2(s, OP_LOCAL_SET, EDP_M + i) &&
           (i == 0 || (ed_get_op(s, EDP_M + i - 1u, 0xFFFF, OP_I64_AND) && op2(s, OP_LOCAL_SET, EDP_M + i - 1u)));
    }
    ok = ok && ed_get_op(s, EDP_M + 15, 16, OP_I64_SHR_S) && i64_const(s, 1) && put_byte(s, OP_I64_AND) &&
         op2(s, OP_LOCAL_SET, EDP_BORROW);
    for (i = 0; i < 16 && ok; i++)
      ok = op2(s, OP_LOCAL_GET, EDP_M + i) && op2(s, OP_LOCAL_GET, EDP_T + i) && op2(s, OP_LOCAL_GET, EDP_BORROW) &&
           put_byte(s, OP_I64_EQZ) && put_byte(s, OP_SELECT) && op2(s, OP_LOCAL_SET, EDP_T + i);
  }
  for (w = 0; w < 4 && ok; w++) {
    ok = base_of(s, 0);
    for (i = 0; i < 4 && ok; i++)
      ok = ed_get_op(s, EDP_T + 4u * w + i, 0xFFFF, OP_I64_AND) &&
           (i == 0 || (i64_const(s, 16u * i) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_OR)));
    ok = ok && memarg(s, OP_I64_STORE, w);
  }
  return ok && put_byte(s, OP_END);
}

/* equal (a, b, tmp) -> bit: 1 when A = B mod p (the packed bytes match).
   TMP (192 bytes): the 2 packed values, then the pack scratch. */
static int part_ed_equal(Sink *s, const void *arg) {
  const EdIndex *x = arg;
  unsigned w;
  int ok = put_uleb(s, 0) && call3(s, x->ed + ED_PACK, ed_at(2, 0), ed_at(0, 0), ed_at(2, 64)) &&
           call3(s, x->ed + ED_PACK, ed_at(2, 32), ed_at(1, 0), ed_at(2, 64));
  for (w = 0; w < 4 && ok; w++)
    ok = load_at(s, 2, w) && load_at(s, 2, 4u + w) && put_byte(s, OP_I64_XOR) && (w == 0 || put_byte(s, OP_I64_OR));
  return ok && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_I64_EXTEND_I32_U) && put_byte(s, OP_END);
}

/* padd (o, p, q, tmp): O := P + Q (add-2008-hwcd-3 as point_add; O may be
   P or Q: the 4 writes of O come after every read). TMP (1280 bytes)
   holds a, b, c, d, t, e, f, g, h and 2d. */
enum {
  PADD_A = 0,
  PADD_B = 128,
  PADD_C = 256,
  PADD_D = 384,
  PADD_T = 512,
  PADD_E = 640,
  PADD_F = 768,
  PADD_G = 896,
  PADD_H = 1024,
  PADD_D2 = 1152
};

static int part_ed_padd(Sink *s, const void *arg) {
  static const EdStep steps[18] = {
    {ED_SUB, {3, PADD_A}, {1, ED_Y}, {1, ED_X}},     {ED_SUB, {3, PADD_T}, {2, ED_Y}, {2, ED_X}},
    {ED_MUL, {3, PADD_A}, {3, PADD_A}, {3, PADD_T}}, {ED_ADD, {3, PADD_B}, {1, ED_X}, {1, ED_Y}},
    {ED_ADD, {3, PADD_T}, {2, ED_X}, {2, ED_Y}},     {ED_MUL, {3, PADD_B}, {3, PADD_B}, {3, PADD_T}},
    {ED_MUL, {3, PADD_C}, {1, ED_T}, {2, ED_T}},     {ED_MUL, {3, PADD_C}, {3, PADD_C}, {3, PADD_D2}},
    {ED_MUL, {3, PADD_D}, {1, ED_Z}, {2, ED_Z}},     {ED_ADD, {3, PADD_D}, {3, PADD_D}, {3, PADD_D}},
    {ED_SUB, {3, PADD_E}, {3, PADD_B}, {3, PADD_A}}, {ED_SUB, {3, PADD_F}, {3, PADD_D}, {3, PADD_C}},
    {ED_ADD, {3, PADD_G}, {3, PADD_D}, {3, PADD_C}}, {ED_ADD, {3, PADD_H}, {3, PADD_B}, {3, PADD_A}},
    {ED_MUL, {0, ED_X}, {3, PADD_E}, {3, PADD_F}},   {ED_MUL, {0, ED_Y}, {3, PADD_H}, {3, PADD_G}},
    {ED_MUL, {0, ED_Z}, {3, PADD_G}, {3, PADD_F}},   {ED_MUL, {0, ED_T}, {3, PADD_E}, {3, PADD_H}}};
  return put_uleb(s, 0) && ed_store_const(s, ed_at(3, PADD_D2), ED25519_CONST_D2) && ed_steps(s, arg, steps, 18) &&
         put_byte(s, OP_END);
}

/* pmul (o, q, sc, tmp): O := [SC] Q, double and add from bit 255 of the
   32 bytes at SC down (point_mul). TMP (1792 bytes): the sum, then the
   padd scratch. Locals: the parameters, the bit index I. */
static int part_ed_pmul(Sink *s, const void *arg) {
  const EdIndex *x = arg;
  Slot acc = ed_at(3, 0);
  Slot work = ed_at(3, 512);
  int ok = i64_locals(s, 1) && ed_store_small(s, ed_at(3, ED_X), 0) && ed_store_small(s, ed_at(3, ED_Y), 1) &&
           ed_store_small(s, ed_at(3, ED_Z), 1) && ed_store_small(s, ed_at(3, ED_T), 0) && i64_const(s, 255) &&
           op2(s, OP_LOCAL_SET, 4) && ed_open(s, OP_LOOP) && call4(s, x->ed + ED_PADD, acc, acc, acc, work) &&
           op2(s, OP_LOCAL_GET, 2) && ed_get_op(s, 4, 3, OP_I64_SHR_U) && put_byte(s, OP_I64_ADD) &&
           put_byte(s, OP_I32_WRAP_I64) && memarg8(s, OP_I64_LOAD8_U) && ed_get_op(s, 4, 7, OP_I64_AND) &&
           put_byte(s, OP_I64_SHR_U) && i64_const(s, 1) && put_byte(s, OP_I64_AND) && i64_const(s, 0) &&
           put_byte(s, OP_I64_NE) && ed_open(s, OP_IF) && call4(s, x->ed + ED_PADD, acc, acc, ed_at(1, 0), work) &&
           put_byte(s, OP_END) && ed_get_op(s, 4, 1, OP_I64_SUB) && op2(s, OP_LOCAL_TEE, 4) &&
           i64_const(s, ~(uint64_t)0) && put_byte(s, OP_I64_NE) && op2(s, OP_BR_IF, 0) && put_byte(s, OP_END) &&
           ed_copy(s, ed_at(0, 0), acc, 64);
  return ok && put_byte(s, OP_END);
}

/* decode (p, in, tmp) -> bit: P := the point of the 32 bytes at IN
   (point_decode, RFC 8032 5.1.3); the bit is 0 when y is not below p, when
   no square root exists or when x = 0 with the sign bit set (P is then
   some point: the caller ands the bit). TMP (1504 bytes) holds num, den,
   den2, den4, den6, t, chk, d, sqrt(-1), 0, the equal and pack scratch
   (192 bytes) and the packed bytes (32). Locals: the parameters, OK,
   SIGN. */
enum {
  DEC_NUM = 0,
  DEC_DEN = 128,
  DEC_DEN2 = 256,
  DEC_DEN4 = 384,
  DEC_DEN6 = 512,
  DEC_T = 640,
  DEC_CHK = 768,
  DEC_D = 896,
  DEC_SQRT_M1 = 1024,
  DEC_ZERO = 1152,
  DEC_EQ = 1280,
  DEC_CANON = 1472
};
enum { DEC_OK = 3, DEC_SIGN };

static int part_ed_decode(Sink *s, const void *arg) {
  static const EdStep roots[16] = {
    {ED_MUL, {2, DEC_NUM}, {0, ED_Y}, {0, ED_Y}},          {ED_MUL, {2, DEC_DEN}, {2, DEC_NUM}, {2, DEC_D}},
    {ED_SUB, {2, DEC_NUM}, {2, DEC_NUM}, {0, ED_Z}},       {ED_ADD, {2, DEC_DEN}, {0, ED_Z}, {2, DEC_DEN}},
    {ED_MUL, {2, DEC_DEN2}, {2, DEC_DEN}, {2, DEC_DEN}},   {ED_MUL, {2, DEC_DEN4}, {2, DEC_DEN2}, {2, DEC_DEN2}},
    {ED_MUL, {2, DEC_DEN6}, {2, DEC_DEN4}, {2, DEC_DEN2}}, {ED_MUL, {2, DEC_T}, {2, DEC_DEN6}, {2, DEC_NUM}},
    {ED_MUL, {2, DEC_T}, {2, DEC_T}, {2, DEC_DEN}},        {ED_POW2523, {2, DEC_T}, {2, DEC_T}, {2, DEC_EQ}},
    {ED_MUL, {2, DEC_T}, {2, DEC_T}, {2, DEC_NUM}},        {ED_MUL, {2, DEC_T}, {2, DEC_T}, {2, DEC_DEN}},
    {ED_MUL, {2, DEC_T}, {2, DEC_T}, {2, DEC_DEN}},        {ED_MUL, {0, ED_X}, {2, DEC_T}, {2, DEC_DEN}},
    {ED_MUL, {2, DEC_CHK}, {0, ED_X}, {0, ED_X}},          {ED_MUL, {2, DEC_CHK}, {2, DEC_CHK}, {2, DEC_DEN}}};
  const EdIndex *x = arg;
  Slot px = ed_at(0, ED_X);
  Slot chk = ed_at(2, DEC_CHK);
  Slot num = ed_at(2, DEC_NUM);
  Slot eq = ed_at(2, DEC_EQ);
  Slot canon = ed_at(2, DEC_CANON);
  Slot zero = ed_at(2, DEC_ZERO);
  unsigned i;
  unsigned w;
  int ok = i64_locals(s, 2) && load_at(s, 1, 3) && i64_const(s, 63) && put_byte(s, OP_I64_SHR_U) &&
           op2(s, OP_LOCAL_SET, DEC_SIGN);
  for (i = 0; i < 16 && ok; i++)
    ok = base_of(s, 0) && load_at(s, 1, i / 4u) && i64_const(s, 16u * (i % 4u)) && put_byte(s, OP_I64_SHR_U) &&
         i64_const(s, i == 15 ? 0x7FFFu : 0xFFFFu) && put_byte(s, OP_I64_AND) && memarg(s, OP_I64_STORE, ED_Y / 8 + i);
  ok = ok && call3(s, x->ed + ED_PACK, canon, ed_at(0, ED_Y), eq);
  for (w = 0; w < 4 && ok; w++)
    ok = load_at(s, 2, DEC_CANON / 8 + w) && load_at(s, 1, w) &&
         (w < 3 || (i64_const(s, 0x7FFFFFFFFFFFFFFFu) && put_byte(s, OP_I64_AND))) && put_byte(s, OP_I64_XOR) &&
         (w == 0 || put_byte(s, OP_I64_OR));
  ok = ok && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_I64_EXTEND_I32_U) && op2(s, OP_LOCAL_SET, DEC_OK) &&
       ed_store_small(s, ed_at(0, ED_Z), 1) && ed_store_const(s, ed_at(2, DEC_D), ED25519_CONST_D) &&
       ed_store_const(s, ed_at(2, DEC_SQRT_M1), ED25519_CONST_SQRT_M1) && ed_store_small(s, zero, 0) &&
       ed_steps(s, x, roots, 16) && call3(s, x->ed + ED_EQUAL, chk, num, eq) && put_byte(s, OP_I64_EQZ) &&
       ed_open(s, OP_IF) && call3(s, x->ed + ED_MUL, px, px, ed_at(2, DEC_SQRT_M1)) && put_byte(s, OP_END) &&
       ed_steps(s, x, roots + 14, 2) && op2(s, OP_LOCAL_GET, DEC_OK) && call3(s, x->ed + ED_EQUAL, chk, num, eq) &&
       put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_GET, DEC_SIGN) && call3(s, x->ed + ED_EQUAL, px, zero, eq) &&
       put_byte(s, OP_I64_AND) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_I64_EXTEND_I32_U) &&
       put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_SET, DEC_OK) && call3(s, x->ed + ED_PACK, canon, px, eq) &&
       load_at(s, 2, DEC_CANON / 8) && i64_const(s, 1) && put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_GET, DEC_SIGN) &&
       put_byte(s, OP_I64_NE) && ed_open(s, OP_IF) && call3(s, x->ed + ED_SUB, px, zero, px) && put_byte(s, OP_END) &&
       call3(s, x->ed + ED_MUL, ed_at(0, ED_T), px, ed_at(0, ED_Y));
  return ok && op2(s, OP_LOCAL_GET, DEC_OK) && put_byte(s, OP_END);
}

/* modl (out, x): OUT := the 64 bytes at X mod L (reduce_limbs: the byte
   limbs 63 .. 32 folded down with 16 L, then the top nibble of limb 31,
   then the byte carries; the shifts are signed). The 32 bytes go out in 4
   words. Locals: the parameters, the 64 limbs X, the carry. */
enum { MODL_X = 2, MODL_CARRY = MODL_X + 64 };

static int part_ed_modl(Sink *s, const void *arg) {
  unsigned i;
  unsigned j;
  unsigned w;
  int ok = i64_locals(s, 65);
  (void)arg;
  for (i = 0; i < 64 && ok; i++)
    ok = load_at(s, 1, i / 8u) && i64_const(s, 8u * (i % 8u)) && put_byte(s, OP_I64_SHR_U) && i64_const(s, 255) &&
         put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_SET, MODL_X + i);
  for (i = 63; i >= 32 && ok; i--) {
    ok = i64_const(s, 0) && op2(s, OP_LOCAL_SET, MODL_CARRY);
    for (j = i - 32u; j < i - 12u && ok; j++)
      ok = op2(s, OP_LOCAL_GET, MODL_X + j) && op2(s, OP_LOCAL_GET, MODL_CARRY) && put_byte(s, OP_I64_ADD) &&
           ed_get_op(s, MODL_X + i, 16u * ed25519_order_byte(j - (i - 32u)), OP_I64_MUL) && put_byte(s, OP_I64_SUB) &&
           op2(s, OP_LOCAL_TEE, MODL_X + j) && i64_const(s, 128) && put_byte(s, OP_I64_ADD) && i64_const(s, 8) &&
           put_byte(s, OP_I64_SHR_S) && op2(s, OP_LOCAL_SET, MODL_CARRY) && op2(s, OP_LOCAL_GET, MODL_X + j) &&
           ed_get_op(s, MODL_CARRY, 8, OP_I64_SHL) && put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_SET, MODL_X + j);
    ok = ok && op2(s, OP_LOCAL_GET, MODL_X + i - 12u) && op2(s, OP_LOCAL_GET, MODL_CARRY) && put_byte(s, OP_I64_ADD) &&
         op2(s, OP_LOCAL_SET, MODL_X + i - 12u) && i64_const(s, 0) && op2(s, OP_LOCAL_SET, MODL_X + i);
  }
  ok = ok && i64_const(s, 0) && op2(s, OP_LOCAL_SET, MODL_CARRY);
  for (j = 0; j < 32 && ok; j++)
    ok = op2(s, OP_LOCAL_GET, MODL_X + j) && op2(s, OP_LOCAL_GET, MODL_CARRY) && put_byte(s, OP_I64_ADD) &&
         ed_get_op(s, MODL_X + 31, 4, OP_I64_SHR_S) && i64_const(s, ed25519_order_byte(j)) && put_byte(s, OP_I64_MUL) &&
         put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_TEE, MODL_X + j) && i64_const(s, 8) && put_byte(s, OP_I64_SHR_S) &&
         op2(s, OP_LOCAL_SET, MODL_CARRY) && ed_get_op(s, MODL_X + j, 255, OP_I64_AND) &&
         op2(s, OP_LOCAL_SET, MODL_X + j);
  for (j = 0; j < 32 && ok; j++)
    ok = op2(s, OP_LOCAL_GET, MODL_X + j) && ed_get_op(s, MODL_CARRY, ed25519_order_byte(j), OP_I64_MUL) &&
         put_byte(s, OP_I64_SUB) && op2(s, OP_LOCAL_SET, MODL_X + j);
  for (i = 0; i < 31 && ok; i++)
    ok = op2(s, OP_LOCAL_GET, MODL_X + i + 1u) && ed_get_op(s, MODL_X + i, 8, OP_I64_SHR_S) &&
         put_byte(s, OP_I64_ADD) && op2(s, OP_LOCAL_SET, MODL_X + i + 1u);
  for (w = 0; w < 4 && ok; w++) {
    ok = base_of(s, 0);
    for (j = 0; j < 8 && ok; j++)
      ok = ed_get_op(s, MODL_X + 8u * w + j, 255, OP_I64_AND) &&
           (j == 0 || (i64_const(s, 8u * j) && put_byte(s, OP_I64_SHL) && put_byte(s, OP_I64_OR)));
    ok = ok && memarg(s, OP_I64_STORE, w);
  }
  return ok && put_byte(s, OP_END);
}

/* verify (vk, msg, n, sig, scratch) -> bit: the bit of ed25519_verify for
   the 64 bytes at SIG on the N bytes at MSG under the 32 bytes at VK (RFC
   8032 5.1.7): S < L, A and R decode, [8]A is not the identity, and
   [8][S]B = [8](R + [k]A) with k =
   SHA-512(R || A || M) mod L, compared as X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1
   (no Z is 0 under the complete addition). SCRATCH: A, R, B, the 2 sides,
   k, the digest, the 4 products, the work area, the SHA-512 scratch, then
   the hash input R || A || M (64 + N bytes). Locals: the parameters, OK,
   the byte index I, a byte of S. */
enum {
  VER_A = 0,
  VER_R = 512,
  VER_B = 1024,
  VER_LHS = 1536,
  VER_RHS = 2048,
  VER_K = 2560,
  VER_DIGEST = 2592,
  VER_XL = 2656,
  VER_XR = 2784,
  VER_YL = 2912,
  VER_YR = 3040,
  VER_WORK = 3168,
  VER_SHA = 4960,
  VER_HBUF = 5216
};
enum { VER_OK = 5, VER_I, VER_BYTE };

static int part_ed_verify(Sink *s, const void *arg) {
  static const EdStep products[4] = {{ED_MUL, {4, VER_XL}, {4, VER_LHS + ED_X}, {4, VER_RHS + ED_Z}},
                                     {ED_MUL, {4, VER_XR}, {4, VER_RHS + ED_X}, {4, VER_LHS + ED_Z}},
                                     {ED_MUL, {4, VER_YL}, {4, VER_LHS + ED_Y}, {4, VER_RHS + ED_Z}},
                                     {ED_MUL, {4, VER_YR}, {4, VER_RHS + ED_Y}, {4, VER_LHS + ED_Z}}};
  const EdIndex *x = arg;
  Slot lhs = ed_at(4, VER_LHS);
  Slot rhs = ed_at(4, VER_RHS);
  Slot work = ed_at(4, VER_WORK);
  Slot zero = ed_at(4, VER_XL);
  unsigned j;
  unsigned w;
  int ok = i64_locals(s, 3) && i64_const(s, 0) && op2(s, OP_LOCAL_SET, VER_OK);
  for (j = 0; j < 32 && ok; j++)
    ok = load_at(s, 3, 4u + j / 8u) && i64_const(s, 8u * (j % 8u)) && put_byte(s, OP_I64_SHR_U) && i64_const(s, 255) &&
         put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_SET, VER_BYTE) && i64_const(s, 1) && i64_const(s, 0) &&
         op2(s, OP_LOCAL_GET, VER_OK) && ed_get_op(s, VER_BYTE, ed25519_order_byte(j), OP_I64_GT_U) &&
         put_byte(s, OP_SELECT) && ed_get_op(s, VER_BYTE, ed25519_order_byte(j), OP_I64_LT_U) &&
         put_byte(s, OP_SELECT) && op2(s, OP_LOCAL_SET, VER_OK);
  ok = ok && op2(s, OP_LOCAL_GET, VER_OK) && call3(s, x->ed + ED_DECODE, ed_at(4, VER_A), ed_at(0, 0), work) &&
       put_byte(s, OP_I64_AND) && call3(s, x->ed + ED_DECODE, ed_at(4, VER_R), ed_at(3, 0), work) &&
       put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_SET, VER_OK);
  /* A pure small-order key makes the cofactored equation independent of the
     key and message. Reject it while retaining mixed-torsion keys. */
  ok = ok && call4(s, x->ed + ED_PADD, rhs, ed_at(4, VER_A), ed_at(4, VER_A), work);
  for (j = 0; j < 2 && ok; j++) ok = call4(s, x->ed + ED_PADD, rhs, rhs, rhs, work);
  ok = ok && ed_store_small(s, zero, 0) && op2(s, OP_LOCAL_GET, VER_OK) &&
       call3(s, x->ed + ED_EQUAL, ed_at(4, VER_RHS + ED_X), zero, work) &&
       call3(s, x->ed + ED_EQUAL, ed_at(4, VER_RHS + ED_Y), ed_at(4, VER_RHS + ED_Z), work) &&
       put_byte(s, OP_I64_AND) && put_byte(s, OP_I64_EQZ) && put_byte(s, OP_I64_EXTEND_I32_U) &&
       put_byte(s, OP_I64_AND) && op2(s, OP_LOCAL_SET, VER_OK);
  for (w = 0; w < 4 && ok; w++)
    ok = base_of(s, 4) && load_at(s, 3, w) && memarg(s, OP_I64_STORE, VER_HBUF / 8 + w) && base_of(s, 4) &&
         load_at(s, 0, w) && memarg(s, OP_I64_STORE, VER_HBUF / 8 + 4u + w);
  ok = ok && op2(s, OP_LOCAL_GET, 2) && i64_const(s, 0) && put_byte(s, OP_I64_NE) && ed_open(s, OP_IF) &&
       i64_const(s, 0) && op2(s, OP_LOCAL_SET, VER_I) && ed_open(s, OP_LOOP) &&
       slot_addr(s, ed_at(4, VER_HBUF + 64)) && op2(s, OP_LOCAL_GET, VER_I) && put_byte(s, OP_I64_ADD) &&
       put_byte(s, OP_I32_WRAP_I64) && op2(s, OP_LOCAL_GET, 1) && op2(s, OP_LOCAL_GET, VER_I) &&
       put_byte(s, OP_I64_ADD) && put_byte(s, OP_I32_WRAP_I64) && memarg8(s, OP_I64_LOAD8_U) &&
       memarg8(s, OP_I64_STORE8) && ed_get_op(s, VER_I, 1, OP_I64_ADD) && op2(s, OP_LOCAL_TEE, VER_I) &&
       op2(s, OP_LOCAL_GET, 2) && put_byte(s, OP_I64_LT_U) && op2(s, OP_BR_IF, 0) && put_byte(s, OP_END) &&
       put_byte(s, OP_END) && slot_addr(s, ed_at(4, VER_HBUF)) && ed_get_op(s, 2, 64, OP_I64_ADD) &&
       slot_addr(s, ed_at(4, VER_DIGEST)) && slot_addr(s, ed_at(4, VER_SHA)) && op2(s, OP_CALL, x->sha512) &&
       slot_addr(s, ed_at(4, VER_K)) && slot_addr(s, ed_at(4, VER_DIGEST)) && op2(s, OP_CALL, x->ed + ED_MODL) &&
       ed_store_const(s, ed_at(4, VER_B + ED_X), ED25519_CONST_BASE_X) &&
       ed_store_const(s, ed_at(4, VER_B + ED_Y), ED25519_CONST_BASE_Y) && ed_store_small(s, ed_at(4, VER_B + ED_Z), 1) &&
       call3(s, x->ed + ED_MUL, ed_at(4, VER_B + ED_T), ed_at(4, VER_B + ED_X), ed_at(4, VER_B + ED_Y)) &&
       call4(s, x->ed + ED_PMUL, lhs, ed_at(4, VER_B), ed_at(3, 32), work) &&
       call4(s, x->ed + ED_PMUL, rhs, ed_at(4, VER_A), ed_at(4, VER_K), work) &&
       call4(s, x->ed + ED_PADD, rhs, ed_at(4, VER_R), rhs, work);
  for (j = 0; j < 3 && ok; j++)
    ok = call4(s, x->ed + ED_PADD, lhs, lhs, lhs, work) && call4(s, x->ed + ED_PADD, rhs, rhs, rhs, work);
  ok = ok && ed_steps(s, x, products, 4) && op2(s, OP_LOCAL_GET, VER_OK) &&
       call3(s, x->ed + ED_EQUAL, ed_at(4, VER_XL), ed_at(4, VER_XR), work) && put_byte(s, OP_I64_AND) &&
       call3(s, x->ed + ED_EQUAL, ed_at(4, VER_YL), ed_at(4, VER_YR), work) && put_byte(s, OP_I64_AND);
  return ok && put_byte(s, OP_END);
}

/* frostVerify (IR_KERNEL_FROST): scratch := alloc (8n + VER_HBUF + 64) for
   the n = fields[0] message words; local := verify (vk = fields[1], msg =
   expr, 8n bytes, sig = fields[2], scratch), the bit 0 or 1. The scratch
   address waits in T + 2. */
static int emit_frost(Sink *s, const IrStmt *st, uint32_t t, uint32_t kernel, unsigned depth) {
  return emit_expr(s, st->fields[0], t, depth + 1u) && i64_const(s, 3) && put_byte(s, OP_I64_SHL) &&
         i64_const(s, VER_HBUF + 64u) && put_byte(s, OP_I64_ADD) && put_byte(s, OP_I32_WRAP_I64) &&
         op2(s, OP_CALL, 0) && op2(s, OP_LOCAL_SET, t + 2u) && emit_expr(s, st->fields[1], t, depth + 1u) &&
         emit_expr(s, st->expr, t, depth + 1u) && emit_expr(s, st->fields[0], t, depth + 1u) && i64_const(s, 3) &&
         put_byte(s, OP_I64_SHL) && emit_expr(s, st->fields[2], t, depth + 1u) && op2(s, OP_LOCAL_GET, t + 2u) &&
         op2(s, OP_CALL, kernel + KERNEL_ED + ED_VERIFY) && op2(s, OP_LOCAL_SET, st->local);
}

/* The Ed25519 kernel in the kernel test module (ed25519 is the entry after
   it). */
enum { KERNEL_TEST_ED = KERNEL_TEST_SHA512 + 2 };

/* ed25519: [n, vk (4 words), sig (8 words), w_1 .. w_m] (the bytes 8 per
   word, little endian; under 13 words or n > 8m, a trap) -> the block [1,
   the verify bit] at h = 8(13 + m); the verify scratch is at h + 16. */
static int part_test_ed25519(Sink *s, const void *arg) {
  const EdIndex *x = arg;
  int ok = i64_locals(s, 1) && ed_get_op(s, 0, 13, OP_I64_LT_U) && ed_trap_if(s) && heap_local(s) &&
           i32_const(s, 0) && memarg(s, OP_I64_LOAD, 0) && ed_get_op(s, 1, 104, OP_I64_SUB) &&
           put_byte(s, OP_I64_GT_U) && ed_trap_if(s) && base_of(s, 1) && i64_const(s, 1) &&
           memarg(s, OP_I64_STORE, 0) && base_of(s, 1) && i64_const(s, 8) && i64_const(s, 104) && i32_const(s, 0) &&
           memarg(s, OP_I64_LOAD, 0) && i64_const(s, 40) && slot_addr(s, ed_at(1, 16)) &&
           op2(s, OP_CALL, x->ed + ED_VERIFY) && memarg(s, OP_I64_STORE, 1);
  return ok && op2(s, OP_LOCAL_GET, 1) && put_byte(s, OP_END);
}

static int func_type(Sink *s, unsigned params, unsigned results) {
  unsigned k;
  int ok = put_byte(s, TYPE_FUNC) && put_uleb(s, params);
  for (k = 0; k < params && ok; k++) ok = put_byte(s, TYPE_I64);
  ok = ok && put_uleb(s, results);
  for (k = 0; k < results && ok; k++) ok = put_byte(s, TYPE_I64);
  return ok;
}

/* The kernel test module: functions 0 .. 4 are the kernel up to hash (K =
   0; no merkle), 5 .. 7 are p2perm, p2hash and ops, 8 is the SHA-512
   kernel, 9 is sha512, 10 .. 21 are the Ed25519 kernel (EdIndex {10, 8})
   and 22 is ed25519. Types: 0 reduce, 1 mul and add (and the Ed25519 mul,
   add, sub, pow2523 and pack), 2 permute (and modl), 3 hash, 4 the
   entries, 5 the SHA-512 kernel (and padd, pmul), 6 carry, 7 equal and
   decode, 8 verify. */
static const unsigned char kernel_test_types[KERNEL_TEST_ED + ED_FUNCS + 1] = {
  0, 1, 1, 2, 3, 4, 4, 4, 5, 4, 6, 1, 1, 1, 1, 1, 7, 5, 5, 7, 2, 8, 4};
static const char *const kernel_test_names[5] = {"p2perm", "p2hash", "ops", "sha512", "ed25519"};
static const unsigned char kernel_test_entries[5] = {KERNEL_MERKLE, KERNEL_MERKLE + 1, KERNEL_MERKLE + 2,
                                                     KERNEL_TEST_SHA512 + 1, KERNEL_TEST_ED + ED_FUNCS};

static int part_kernel_test_types(Sink *s, const void *arg) {
  (void)arg;
  return put_uleb(s, 9) && func_type(s, 10, 0) && func_type(s, 3, 0) && func_type(s, 2, 0) && func_type(s, 5, 0) &&
         func_type(s, 1, 1) && func_type(s, 4, 0) && func_type(s, 1, 0) && func_type(s, 3, 1) && func_type(s, 5, 1);
}

static int part_kernel_test_functions(Sink *s, const void *arg) {
  size_t i;
  int ok = put_uleb(s, sizeof kernel_test_types);
  (void)arg;
  for (i = 0; i < sizeof kernel_test_types && ok; i++) ok = put_uleb(s, kernel_test_types[i]);
  return ok;
}

static int part_kernel_test_exports(Sink *s, const void *arg) {
  unsigned i;
  int ok = put_uleb(s, 6);
  (void)arg;
  for (i = 0; i < 5 && ok; i++) ok = put_name(s, kernel_test_names[i]) && put_byte(s, 0) && put_uleb(s, kernel_test_entries[i]);
  return ok && put_name(s, "memory") && put_byte(s, 2) && put_uleb(s, 0);
}

static int part_kernel_test_code(Sink *s, const void *arg) {
  static const Part parts[sizeof kernel_test_types] = {
    part_reduce,      part_mul,       part_add,        part_permute,      part_hash,     part_test_permute,
    part_test_hash,   part_test_ops,  part_sha512,     part_test_sha512,  part_ed_carry, part_ed_mul,
    part_ed_add,      part_ed_sub,    part_ed_pow2523, part_ed_pack,      part_ed_equal, part_ed_padd,
    part_ed_pmul,     part_ed_decode, part_ed_modl,    part_ed_verify,    part_test_ed25519};
  static const uint32_t kernel = 0;
  static const EdIndex ed = {KERNEL_TEST_ED, KERNEL_TEST_SHA512};
  size_t i;
  int ok = put_uleb(s, sizeof kernel_test_types);
  (void)arg;
  for (i = 0; i < sizeof kernel_test_types && ok; i++)
    ok = sized(s, parts[i], i < KERNEL_TEST_ED ? (const void *)&kernel : (const void *)&ed);
  return ok;
}

/* The kernel of an IR module (K = 1 + func_count): the types reduce, mul
   and add (and the Ed25519 mul, add, sub, pow2523 and pack), permute (and
   modl), hash, merkle (and the SHA-512 kernel, padd and pmul), carry, equal
   and decode, verify (from type K), then the functions: the Poseidon2
   kernel, the SHA-512 kernel at K + KERNEL_SHA512 and the Ed25519 kernel
   from K + KERNEL_ED (EdIndex {K + KERNEL_ED, K + KERNEL_SHA512}). */
static int kernel_types(Sink *s) {
  return func_type(s, 10, 0) && func_type(s, 3, 0) && func_type(s, 2, 0) && func_type(s, 5, 0) && func_type(s, 4, 0) &&
         func_type(s, 1, 0) && func_type(s, 3, 1) && func_type(s, 5, 1);
}

static int kernel_functions(Sink *s, uint32_t base) {
  static const unsigned char types[KERNEL_FUNCS] = {0, 1, 1, 2, 3, 4, 4, 5, 1, 1, 1, 1, 1, 6, 4, 4, 6, 2, 7};
  size_t i;
  int ok = 1;
  for (i = 0; i < KERNEL_FUNCS && ok; i++) ok = put_uleb(s, base + types[i]);
  return ok;
}

static int kernel_code(Sink *s, const uint32_t *kernel) {
  static const Part parts[KERNEL_FUNCS] = {
    part_reduce,   part_mul,     part_add,     part_permute,    part_hash,    part_merkle,    part_sha512,
    part_ed_carry, part_ed_mul,  part_ed_add,  part_ed_sub,     part_ed_pow2523, part_ed_pack, part_ed_equal,
    part_ed_padd,  part_ed_pmul, part_ed_decode, part_ed_modl,  part_ed_verify};
  EdIndex ed;
  size_t i;
  int ok = 1;
  ed.ed = *kernel + KERNEL_ED;
  ed.sha512 = *kernel + KERNEL_SHA512;
  for (i = 0; i < KERNEL_FUNCS && ok; i++)
    ok = sized(s, parts[i], i < KERNEL_ED ? (const void *)kernel : (const void *)&ed);
  return ok;
}

int wasm_write_kernel_test(FILE *out, FILE *err) {
  Sink s = {out, 0, err};
  size_t i;
  int ok = 1;
  for (i = 0; i < sizeof header && ok; i++) ok = put_byte(&s, header[i]);
  ok = ok && section(&s, SECTION_TYPE, part_kernel_test_types, NULL) &&
       section(&s, SECTION_FUNCTION, part_kernel_test_functions, NULL) &&
       section(&s, SECTION_MEMORY, part_memory, NULL) && section(&s, SECTION_EXPORT, part_kernel_test_exports, NULL) &&
       section(&s, SECTION_CODE, part_kernel_test_code, NULL);
  if (!ok && ferror(out)) fputs("langc: IO: -: cannot write the wasm kernel module\n", err);
  return ok;
}

int target_abi_line(const IrFunc *fn, FILE *out, FILE *err) {
  (void)err;
  fprintf(out, "%s\n", fn->name);
  return 1;
}

/* Both parts are the module bytes. */
int target_write(const IrProgram *prog, TargetPart part, FILE *out, FILE *err) {
  Sink s = {out, 0, err};
  size_t i;
  int stream = 0;
  int ok = 1;
  (void)part;
  for (i = 0; i < prog->func_count; i++) stream = stream || prog->funcs[i].stream;
  for (i = 0; stream && i < prog->func_count; i++) {
    if (strcmp(prog->funcs[i].name, "memory") == 0) {
      fputs("langc: REFUSE_EXPORT: memory: the name is reserved for the memory of a stream module\n", err);
      return 0;
    }
  }
  for (i = 0; i < sizeof header && ok; i++) ok = put_byte(&s, header[i]);
  ok = ok && section(&s, SECTION_TYPE, part_types, prog) && section(&s, SECTION_FUNCTION, part_functions, prog) &&
       section(&s, SECTION_MEMORY, part_memory, NULL) && section(&s, SECTION_GLOBAL, part_global, NULL) &&
       section(&s, SECTION_EXPORT, part_exports, prog) && section(&s, SECTION_CODE, part_code, prog);
  if (!ok && ferror(out)) fputs("langc: IO: -: cannot write the wasm module\n", err);
  return ok;
}
