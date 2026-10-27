/* The syntax tree. SHARED by the tcc kits. Terms and types share one syntax. */
#ifndef LANG_FRONT_AST_H
#define LANG_FRONT_AST_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  TERM_VAR,   /* name */
  TERM_NAT,   /* nat */
  TERM_APP,   /* left applied to right */
  TERM_LAM,   /* fun (name : left) => right; left is NULL for a bare binder */
  TERM_PI,    /* (name : left) -> right; name is NULL for left -> right */
  TERM_SIGMA, /* Sigma (name : left) right, or (name : left) * right */
  TERM_UNIV   /* Type nat */
} TermKind;

typedef struct Term Term;
struct Term {
  TermKind kind;
  int line;
  int col;
  const char *name;
  uint64_t nat;
  const Term *left;
  const Term *right;
};

/* A named field of a constructor, or a parameter of a family. */
typedef struct {
  const char *name;
  const Term *type;
  int line;
  int col;
} Field;

typedef struct {
  const char *name;
  const Field *fields;
  size_t field_count;
  int line;
  int col;
} Ctor;

typedef enum {
  DECL_DEF,    /* def [rec] name : type := body */
  DECL_AXIOM,  /* axiom name : type */
  DECL_FAMILY  /* family name params := ctor | ... */
} DeclKind;

/* A family is legal only in the domain file (rule R1). */
typedef enum {
  ORIGIN_DOMAIN,
  ORIGIN_PROGRAM
} Origin;

typedef struct {
  DeclKind kind;
  Origin origin;
  int is_rec;
  int line;
  int col;
  const char *name;
  const Term *type;
  const Term *body;
  const Field *params;
  size_t param_count;
  const Ctor *ctors;
  size_t ctor_count;
} Decl;

/* Domain declarations come first, then the program. */
typedef struct {
  Decl *items;
  size_t count;
  size_t cap;
} DeclList;

#endif
