/* S5 U4a: the FHE circuits of docs/PLAN.md 4.3 as a circuit table over the
 * radix layer of front/tfhe.h (Q-S5-6 (a), Q-S5-7 (a)). A circuit is a list
 * of statements on numbered registers: radix registers r0, r1, ... and block
 * registers b0, b1, .... The inputs are encrypted radix values, encrypted
 * bit blocks and clear u64 parameters, by name. The builder gives each
 * statement its static PBS count and each register a static noise level, and
 * it adds a refresh where the level rule needs one. */
#ifndef CHARTER_FHE_H
#define CHARTER_FHE_H

#include <stdio.h>

#include "front/tfhe.h"

enum {
  FHE_RADIX_REGS = 12, /* tally: N terms and 4 counts */
  FHE_BLOCK_REGS = 8,
  FHE_INPUTS = 32, /* the limit for each input kind and for the parameters */
  FHE_STMTS = 64,
  FHE_OUTPUTS = 4,
  FHE_NAME_BYTES = 12,
  FHE_N_MAX = 8,    /* the ballot count limit */
  FHE_LEVEL_MAX = 5 /* the tfhe-rs max_noise_level */
};

/* Where a value is: an input or a register. */
typedef enum { FHE_RADIX_IN, FHE_BLOCK_IN, FHE_RADIX_REG, FHE_BLOCK_REG } FheSlot;

typedef struct FheReg {
  FheSlot slot;
  unsigned index;
} FheReg;

/* A clear u64: a literal, a parameter, or 2^64 minus a parameter (mod 2^64). */
typedef enum { FHE_LIT, FHE_PARAM, FHE_NEG_PARAM } FheClearKind;

typedef struct FheClear {
  FheClearKind kind;
  uint64_t value; /* the literal or the parameter index */
} FheClear;

/* The statements and their static PBS counts. */
typedef enum {
  FHE_TRIVIAL, /* r := trivial c: 0 PBS, level 0 */
  FHE_RMUL,    /* r := rmul(b, c): 0 PBS, level (the largest digit of c) x level(b) */
  FHE_RADD,    /* r := radd(x, y): 63 PBS, level 1 */
  FHE_RSUM,    /* r := rsum(x .. x + count - 1): 63 x ceil((count - 1) / 3) PBS, level 1 */
  FHE_RLE,     /* b := rle(x, y), 1 when x <= y: 63 PBS, level 1 */
  FHE_PAIR,    /* b := pair(h, l) = 4 h + l: 0 PBS, level 4 level(h) + level(l) */
  FHE_LUT,     /* b := lut(a, NAME): 1 PBS, level 1 */
  FHE_BADD,    /* b := badd(x, y): 0 PBS, the sum of the levels */
  FHE_REFRESH  /* r := refresh(r): a MSG PBS on each block, 32 PBS, level 1 */
} FheOp;

/* The circuit LUTs. The codes follow the constructor order of
 * domain/domain.lang (DecE, DecA). THETA (4h + l): h = 1 gives decRelease,
 * else l = 1 gives decRefund, else decHold. ISREL: v = 0. ISREF: v = 1. AMD
 * (4h + l): h = 1 gives amendAdopt, else l = 0 gives amendReject, else
 * amendHold. */
enum { FHE_LUT_THETA, FHE_LUT_ISREL, FHE_LUT_ISREF, FHE_LUT_AMD, FHE_LUTS };

typedef struct FheStmt {
  FheOp op;
  FheReg dst, a, b;
  unsigned count; /* FHE_RSUM: the number of registers from A */
  FheClear c;     /* FHE_TRIVIAL, FHE_RMUL */
  unsigned lut;   /* FHE_LUT */
  unsigned pbs;
} FheStmt;

/* The circuits. FHE_MIX is the refresh row of the checktool: two rmul
 * outputs into one radd. `langc fhe N` prints the circuits before FHE_MIX. */
typedef enum { FHE_TALLY4, FHE_TALLY3, FHE_THETA, FHE_SETTLE, FHE_CREDIT, FHE_WITHDRAW, FHE_AMD, FHE_MIX } FheKind;
enum { FHE_PRINTED = FHE_MIX };

typedef struct FheCircuit {
  char name[FHE_NAME_BYTES];
  char radix_in[FHE_INPUTS][FHE_NAME_BYTES];
  char block_in[FHE_INPUTS][FHE_NAME_BYTES];
  char param[FHE_INPUTS][FHE_NAME_BYTES];
  unsigned radix_ins, block_ins, params;
  unsigned radix_regs, block_regs;
  unsigned radix_level[FHE_RADIX_REGS], block_level[FHE_BLOCK_REGS];
  FheStmt stmt[FHE_STMTS];
  unsigned stmts;
  FheReg out[FHE_OUTPUTS];
  unsigned outs;
  unsigned pbs; /* the sum of the statement counts */
  unsigned refreshes;
  int failed;
} FheCircuit;

/* Builds circuit KIND at N ballots (the tally circuits only read N, from 1
 * to FHE_N_MAX). 1 when ok; 0 when a limit is too small. */
int fhe_build(FheCircuit *c, FheKind kind, unsigned n);

/* The circuit text: a header with the inputs, the outputs and the PBS total,
 * then one statement for each line with its PBS count, then the return. */
void fhe_print(const FheCircuit *c, FILE *out);

/* The LUT polynomial of each circuit LUT, in the enum order (4 x 16 KiB). */
typedef struct FheLuts {
  uint64_t lut[FHE_LUTS][TFHE_POLY_N];
} FheLuts;

void fhe_luts(FheLuts *l);

/* The eval context, about 6 MiB: keep it in static storage. The caller sets
 * the keys, the LUTs and the inputs: RIN[i] is radix input i, BIN[i] block
 * input i, PARAM[i] parameter i. */
typedef struct FheEval {
  const TfheFft *f;
  const TfheKeys *k;
  const TfheRadixLuts *rl;
  const FheLuts *l;
  const TfheRadix *rin;
  const uint64_t (*bin)[TFHE_BLOCK_WORDS];
  const uint64_t *param;
  unsigned pbs; /* the PBS calls of the last fhe_eval */
  TfheRadix radix[FHE_RADIX_REGS];
  uint64_t block[FHE_BLOCK_REGS][TFHE_BLOCK_WORDS];
} FheEval;

/* Runs the statements of C in order. The outputs are the registers C->out.
 * E->pbs counts each PBS call that a statement makes. */
void fhe_eval(FheEval *e, const FheCircuit *c);
#endif
