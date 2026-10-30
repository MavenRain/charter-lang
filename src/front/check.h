/* The type checker, the refusals R1-R4 and the eval command. SHARED by the
   tcc kits. */
#ifndef LANG_FRONT_CHECK_H
#define LANG_FRONT_CHECK_H

#include "front/core.h"
#include "front/poseidon2.h"

#define ENTRY_PARAMS_MAX 16u

/* An entry: a program definition of type Nat, Bool, or a function of Nat and
   Bool arguments to a Nat or Bool result. */
typedef struct {
  uint32_t param_count;
  int param_bool[ENTRY_PARAMS_MAX];
  int result_bool;
} Entry;

/* Checks the domain declarations, then the program, into M. Returns 1, or 0
   after a diagnostic. */
int check_program(Arena *arena, const DeclList *decls, Machine *m, Diag *diag);
/* Returns 1 when TYPE is the type of an entry. */
int entry_of(Machine *m, const Value *type, Entry *out);
/* Evaluates the definition NAME on ARGS and prints the result. Returns 0, 1
   after a diagnostic, or 2 after an EVAL_ARGS diagnostic. */
int eval_command(Machine *m, const char *name, char *const *args, int arg_count, FILE *out, FILE *err);
/* Evaluates the stream entry NAME on the word stream ARGS and prints the
   result stream (Q-S3-7). A bad stream prints `trap` (Q-S3-8). Returns 0, 1
   after a diagnostic, or 2 after an EVAL_ARGS diagnostic. */
int eval_words_command(Machine *m, const char *name, char *const *args, int arg_count, FILE *out, FILE *err);
/* Returns 1 when TYPE is the type of a stream entry; *PARAMS = its parameter
   count. Shared with the lowering (`--words`). */
int words_entry(Machine *m, const Value *type, uint32_t *params);
/* The environment of the N family parameters VALS: the last one is index 0. */
const Env *words_env(Machine *m, const Value *const *vals, uint32_t n);
/* The Poseidon2 digest with the domain tag TAG of the stream form of X : T
   (hashOf, Q-S4-7) into OUT. Returns 1; 0 when X is not a closed value of T
   (no diagnostic); 2 when a component of X is an overflow; -1 after a
   diagnostic. */
int words_hash(Machine *m, uint64_t tag, const Value *t, const Value *x, Fr *out);
/* frostVerify (Q-S4-4, Q-S4-12 (a)): the RFC 8032 verify, cofactored, of the
   64 bytes SIG under the 32 bytes PK on the bytes of the stream form of X : T
   (8 bytes per word, little endian). Returns as words_hash; on 1, *VALID is
   the verify result. */
int words_frost(Machine *m, const uint8_t *pk, const Value *t, const Value *x, const uint8_t *sig, int *valid);

#endif
