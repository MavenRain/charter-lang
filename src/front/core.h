/* Core terms, values and the evaluator. SHARED by the tcc kits.

   The checker (front/check.c) writes core terms. Evaluation is normalization
   by evaluation: each value is a normal form. A neutral value (VAL_VAR,
   VAL_APP, VAL_STUCK) is stuck on a variable. A trap (a Nat overflow) is a
   value too. It goes up through each strict position (a Nat operation, the
   scrutinee of an eliminator, the function of an application) and nowhere
   else. So the evaluator and the residual program agree: a trap that no
   strict position reads does not stop the program. */
#ifndef LANG_FRONT_CORE_H
#define LANG_FRONT_CORE_H

#include "front/ast.h"
#include "front/base.h"

#define EVAL_DEPTH_LIMIT 2000u
#define EVAL_FUEL_STEPS 20000000u

/* The core names: type formers, constructors and operations. */
typedef enum {
  OP_NAT,
  OP_BOOL,
  OP_UNIT,
  OP_PROD,
  OP_SUM,
  OP_OPTION,
  OP_LIST,
  OP_EQ,
  OP_FAMILY,
  OP_UNIT_VAL,
  OP_TRUE,
  OP_FALSE,
  OP_PAIR,
  OP_INL,
  OP_INR,
  OP_NONE,
  OP_SOME,
  OP_NIL,
  OP_CONS,
  OP_PACK,
  OP_REFL,
  OP_CTOR,
  OP_FIRST,
  OP_SECOND,
  OP_EITHER,
  OP_OPTION_ELIM,
  OP_PURE,
  OP_MAP,
  OP_BIND,
  OP_FOLD_NAT,
  OP_IND_NAT,
  OP_IND_FAMILY,
  OP_IND_OPTION,
  OP_FOLD_LIST,
  OP_FOLD_FAMILY,
  OP_UNFOLD,
  OP_FILTER,
  OP_WITNESS,
  OP_PAYLOAD,
  OP_SYMM,
  OP_TRANS,
  OP_TRANSPORT,
  OP_CONG,
  OP_NAT_ADD,
  OP_NAT_SUB,
  OP_NAT_MUL,
  OP_NAT_EQ,
  OP_NAT_LE,
  OP_FLAG_IF,
  OP_PROJ,
  OP_DIGEST,
  OP_KEY,
  OP_FR, /* an element of Fr (a Digest or a Key): 4 Nat limbs, low limb first */
  OP_HASH, /* hashOf tag T x (Q-S4-7): the Poseidon2 digest of the stream form of x */
  OP_MERKLE, /* merkleRoot xs (Q-S4-6): the root of the Merkle tree of 16 levels over the leaves of xs */
  OP_VKEY, /* the type VKey (PLAN 3.3): a FROST group public key, 32 bytes */
  OP_SIG, /* the type Sig (PLAN 3.3): a signature R || z, 64 bytes */
  OP_VKEY_WORDS, /* a VKey value: 4 Nat words, the key bytes 8 per word, little endian, low word first */
  OP_SIG_WORDS, /* a Sig value: 8 Nat words, in the same byte order */
  OP_FROST /* frostVerify vk T msg sig (Q-S4-4, Q-S4-12 (a)): the cofactored RFC 8032 verify on the bytes of the stream form of msg */
} Op;

/* The words of a VKey and of a Sig value (PLAN 3.3). */
enum { VKEY_WORDS = 4, SIG_WORDS = 8 };

/* The instance of pure, map, bind and filter (formers F5 and F8). */
typedef enum {
  CARRIER_OPTION,
  CARRIER_LIST,
  CARRIER_SUM
} Carrier;

typedef enum {
  CORE_VAR,    /* index: de Bruijn index */
  CORE_GLOBAL, /* index: definition number */
  CORE_NAT,    /* nat */
  CORE_TRAP,   /* an overflow; only quote writes it */
  CORE_UNIV,   /* Type nat */
  CORE_LAM,    /* fun name => b */
  CORE_PI,     /* (name : a) -> b */
  CORE_SIGMA,  /* Sigma (name : a) b */
  CORE_APP,    /* a b */
  CORE_OP      /* a core name with all of its arguments */
} CoreKind;

typedef struct Core Core;
struct Core {
  CoreKind kind;
  uint32_t index;
  uint64_t nat;
  Op op;
  /* OP_FAMILY, OP_FOLD_FAMILY, OP_IND_FAMILY: the family. OP_CTOR, OP_PROJ: the
     constructor. OP_PURE, OP_MAP, OP_BIND, OP_FILTER: the Carrier. */
  uint32_t inst;
  uint32_t field; /* OP_PROJ: the field number */
  const char *name;
  const Core *a;
  const Core *b;
  const Core *const *args;
  uint32_t argc;
};

typedef enum {
  VAL_NAT,
  VAL_TRAP,
  VAL_UNIV,
  VAL_LAM,
  VAL_PI,
  VAL_SIGMA,
  VAL_OP,   /* a canonical value or a type */
  VAL_VAR,  /* neutral: a variable at a de Bruijn level */
  VAL_APP,  /* neutral: a neutral function applied to a value */
  VAL_STUCK /* neutral: an operation with a neutral scrutinee */
} ValKind;

typedef struct Value Value;
typedef struct Env Env;

/* The head is de Bruijn index 0. */
struct Env {
  const Value *value;
  const Env *next;
};

struct Value {
  ValKind kind;
  uint64_t nat; /* NAT: the number. UNIV: the level. VAR: the level. */
  Op op;        /* OP, STUCK */
  uint32_t inst;
  uint32_t field;
  const Value *const *args;
  uint32_t argc;
  const char *name; /* LAM, PI, SIGMA: the binder */
  const Value *dom; /* PI, SIGMA: the domain. APP: the function. */
  const Value *arg; /* APP: the argument. A PI with no body: the codomain. */
  const Env *env;   /* LAM, PI, SIGMA: the closure */
  const Core *body;
};

typedef struct {
  const char *name;
  const Core *type; /* in the context of the family parameters */
  int recursive;    /* the family at its own parameters (uniform) */
} FieldInfo;

typedef struct {
  const char *name;
  uint32_t family;
  const FieldInfo *fields;
  uint32_t field_count;
} CtorInfo;

/* A domain family. Its constructors are ctors[first_ctor ...]. A family
   with one constructor has one projection for each field. */
typedef struct {
  const char *name;
  const Core *const *param_types;
  uint32_t param_count;
  uint32_t first_ctor;
  uint32_t ctor_count;
  uint64_t universe; /* the largest universe of a constructor field */
} FamilyInfo;

typedef struct {
  const char *name;
  Origin origin;
  const Core *body;
  const Value *type;
  const Value *value; /* computed when first used */
} DefInfo;

/* The checked program and the evaluation state. No global state: every
   function gets this context. */
typedef struct {
  Arena *arena;
  Diag *diag;
  const char *def; /* the current definition, for diagnostics */
  DefInfo *defs;
  uint32_t def_count;
  uint32_t def_cap;
  FamilyInfo *families;
  uint32_t family_count;
  uint32_t family_cap;
  CtorInfo *ctors;
  uint32_t ctor_count;
  uint32_t ctor_cap;
  unsigned depth;
  uint64_t fuel;
  int overflowed;
  int runtime; /* preserve checked arithmetic effects during execution/lowering */
  size_t checked;  /* check_program: the declarations before the current one */
  int decl_failed; /* check_program: 1 when declaration CHECKED failed */
} Machine;

/* Each function returns NULL (or 0) after a diagnostic. A NULL input gives a
   NULL result, so a caller can test once at the end. */
const Value *val_nat(Machine *m, uint64_t n);
const Value *val_var(Machine *m, uint32_t level);
const Value *val_univ(Machine *m, uint64_t level);
const Value *val_op(Machine *m, ValKind kind, Op op, uint32_t inst, uint32_t field, const Value *const *args, uint32_t argc);
const Value *val_make(Machine *m, Op op, uint32_t inst, uint32_t argc, const Value *a, const Value *b, const Value *c);
/* A non-dependent function type. */
const Value *val_arrow(Machine *m, const Value *dom, const Value *cod);
const Value *val_closure(Machine *m, ValKind kind, const char *name, const Value *dom, const Env *env, const Core *body);
int val_is(const Value *v, Op op);
const Env *env_push(Machine *m, const Env *env, const Value *value);
const Value *def_value(Machine *m, uint32_t index);
/* Start execution with fresh definition values, without proof-only reductions. */
void runtime_begin(Machine *m);
const Value *eval_core(Machine *m, const Env *env, const Core *core);
const Value *apply_value(Machine *m, const Value *fn, const Value *arg);
/* The body of a LAM, PI or SIGMA value at ARG. */
const Value *closure_apply(Machine *m, const Value *binder, const Value *arg);
/* 1 when A and B have the same normal form. LEVEL is the next free level. */
int conv_values(Machine *m, uint32_t level, const Value *a, const Value *b);
const Core *quote_value(Machine *m, uint32_t level, const Value *v);
/* Writes V in the surface syntax. NAMES gives the names of the levels below
   NAME_COUNT. Returns 1 for a complete rendering, 0 on truncation or error. */
int value_print(Machine *m, const char *const *names, uint32_t name_count, const Value *v, char *buf, size_t cap);
const char *op_name(const Machine *m, Op op, uint32_t inst, uint32_t field);

#endif
