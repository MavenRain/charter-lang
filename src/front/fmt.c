#include <string.h>

#include "front/fmt.h"

#define SYM_ARROW "\xE2\x86\x92"  /* → */
#define SYM_LAMBDA "\xCE\xBB"     /* λ */
#define SYM_TIMES "\xC3\x97"      /* × */
#define SYM_NAT "\xE2\x84\x95"    /* ℕ */

/* Precedence levels. A term below the level of its slot gets parentheses. */
enum {
  LEVEL_BINDER, /* λ, Pi */
  LEVEL_SIGMA,
  LEVEL_APP,    /* application, Type n */
  LEVEL_ATOM
};

void fmt_text_init(FmtText *out, Arena *arena) {
  out->arena = arena;
  out->data = NULL;
  out->len = 0;
  out->cap = 0;
  out->oom = 0;
}

static void put_bytes(FmtText *out, const char *bytes, size_t len) {
  if (out->oom || len == 0) return;
  if (out->len + len > out->cap) {
    size_t next = out->cap == 0 ? 256 : out->cap;
    while (next < out->len + len) next *= 2;
    char *fresh = arena_alloc(out->arena, next);
    out->oom = fresh == NULL;
    if (out->oom) return;
    if (out->len > 0) memcpy(fresh, out->data, out->len);
    out->data = fresh;
    out->cap = next;
  }
  memcpy(out->data + out->len, bytes, len);
  out->len += len;
}

static void put_str(FmtText *out, const char *text) {
  put_bytes(out, text, strlen(text));
}

static void put_nat(FmtText *out, uint64_t nat) {
  char digits[24];
  size_t at = sizeof digits;
  do {
    digits[--at] = (char)('0' + nat % 10);
    nat /= 10;
  } while (nat > 0);
  put_bytes(out, digits + at, sizeof digits - at);
}

/* The core name Nat prints as `ℕ`. */
static void put_name(FmtText *out, const char *name) {
  put_str(out, strcmp(name, "Nat") == 0 ? SYM_NAT : name);
}

static int term_level(const Term *t) {
  switch (t->kind) {
    case TERM_VAR:
    case TERM_NAT:
      return LEVEL_ATOM;
    case TERM_APP:
    case TERM_UNIV:
      return LEVEL_APP;
    case TERM_SIGMA:
      return LEVEL_SIGMA;
    case TERM_LAM:
    case TERM_PI:
      return LEVEL_BINDER;
  }
  return LEVEL_BINDER;
}

static void put_term(FmtText *out, const Term *t, int level);

/* `(x : A)` */
static void put_group(FmtText *out, const char *name, const Term *type) {
  put_str(out, "(");
  put_str(out, name);
  put_str(out, " : ");
  put_term(out, type, LEVEL_BINDER);
  put_str(out, ")");
}

/* `λ x (y : A) → t`: all leading binders in one λ. */
static void put_lambda(FmtText *out, const Term *t) {
  put_str(out, SYM_LAMBDA);
  for (; t->kind == TERM_LAM; t = t->right) {
    put_str(out, " ");
    if (t->left == NULL) put_str(out, t->name);
    else put_group(out, t->name, t->left);
  }
  put_str(out, " " SYM_ARROW " ");
  put_term(out, t, LEVEL_BINDER);
}

/* Pi and Sigma. A named binder is a group and is never merged. */
static void put_binary(FmtText *out, const Term *t, const char *op, int left_level, int right_level) {
  if (t->name != NULL) put_group(out, t->name, t->left);
  else put_term(out, t->left, left_level);
  put_str(out, op);
  put_term(out, t->right, right_level);
}

static void put_term(FmtText *out, const Term *t, int level) {
  int paren = term_level(t) < level;
  if (paren) put_str(out, "(");
  switch (t->kind) {
    case TERM_VAR:
      put_name(out, t->name);
      break;
    case TERM_NAT:
      put_nat(out, t->nat);
      break;
    case TERM_UNIV:
      put_str(out, "Type ");
      put_nat(out, t->nat);
      break;
    case TERM_APP:
      put_term(out, t->left, LEVEL_APP);
      put_str(out, " ");
      put_term(out, t->right, LEVEL_ATOM);
      break;
    case TERM_LAM:
      put_lambda(out, t);
      break;
    case TERM_PI:
      put_binary(out, t, " " SYM_ARROW " ", LEVEL_SIGMA, LEVEL_BINDER);
      break;
    case TERM_SIGMA:
      put_binary(out, t, " " SYM_TIMES " ", LEVEL_APP, LEVEL_SIGMA);
      break;
  }
  if (paren) put_str(out, ")");
}

/* `name : T` on one line, then the clause `name x y = t`: the leading bare
   binders of the body become the clause arguments. */
static void put_def(FmtText *out, const Decl *d) {
  const Term *body = d->body;
  if (d->is_rec) put_str(out, "rec ");
  put_str(out, d->name);
  put_str(out, " : ");
  put_term(out, d->type, LEVEL_BINDER);
  put_str(out, "\n");
  put_str(out, d->name);
  for (; body->kind == TERM_LAM && body->left == NULL; body = body->right) {
    put_str(out, " ");
    put_str(out, body->name);
  }
  put_str(out, " = ");
  put_term(out, body, LEVEL_BINDER);
}

/* `  c : (f : A) → F p1 .. pn` */
static void put_ctor(FmtText *out, const Decl *d, const Ctor *c) {
  put_str(out, "\n  ");
  put_str(out, c->name);
  put_str(out, " : ");
  for (size_t i = 0; i < c->field_count; i++) {
    put_group(out, c->fields[i].name, c->fields[i].type);
    put_str(out, " " SYM_ARROW " ");
  }
  put_str(out, d->name);
  for (size_t i = 0; i < d->param_count; i++) {
    put_str(out, " ");
    put_str(out, d->params[i].name);
  }
}

/* `data F (p : A) : Type where`, then one constructor a line. */
static void put_data(FmtText *out, const Decl *d) {
  put_str(out, "data ");
  put_str(out, d->name);
  for (size_t i = 0; i < d->param_count; i++) {
    put_str(out, " ");
    put_group(out, d->params[i].name, d->params[i].type);
  }
  put_str(out, " : Type where");
  for (size_t i = 0; i < d->ctor_count; i++) put_ctor(out, d, &d->ctors[i]);
}

void fmt_decl(FmtText *out, const Decl *decl) {
  switch (decl->kind) {
    case DECL_DEF:
      put_def(out, decl);
      break;
    case DECL_AXIOM:
      put_str(out, "postulate ");
      put_str(out, decl->name);
      put_str(out, " : ");
      put_term(out, decl->type, LEVEL_BINDER);
      break;
    case DECL_FAMILY:
      put_data(out, decl);
      break;
  }
}

static void put_comment(FmtText *out, const Comment *c) {
  put_bytes(out, c->text, c->len);
  put_str(out, "\n");
}

void fmt_region(FmtText *out, const Decl *decls, size_t i, const TokenList *toks, size_t *next_comment) {
  const Decl *d = &decls[i];
  if (i > 0) put_str(out, "\n");
  for (; *next_comment < toks->comment_count && toks->comments[*next_comment].line <= d->end_line; (*next_comment)++) {
    put_comment(out, &toks->comments[*next_comment]);
  }
  fmt_decl(out, d);
  put_str(out, "\n");
}

void fmt_tail(FmtText *out, size_t decl_count, const TokenList *toks, size_t next_comment) {
  if (decl_count > 0 && next_comment < toks->comment_count) put_str(out, "\n");
  for (; next_comment < toks->comment_count; next_comment++) put_comment(out, &toks->comments[next_comment]);
}

int fmt_program(FmtText *out, const Decl *decls, size_t count, const TokenList *toks) {
  size_t next_comment = 0;
  for (size_t i = 0; i < count; i++) fmt_region(out, decls, i, toks, &next_comment);
  fmt_tail(out, count, toks, next_comment);
  return !out->oom;
}
