/* Tokens of the DSL. SHARED by the tcc kits. */
#ifndef LANG_FRONT_LEXER_H
#define LANG_FRONT_LEXER_H

#include "front/base.h"

typedef enum {
  TOK_EOF,
  TOK_IDENT,    /* `ℕ` is the name Nat */
  TOK_NAT,
  TOK_LPAREN,
  TOK_RPAREN,
  TOK_COLON,
  TOK_DEFINE,   /* := (no rule takes it; it gives a clear refusal) */
  TOK_EQUALS,   /* = */
  TOK_ARROW,    /* → or the alias -> */
  TOK_FATARROW, /* => (the `fun` alias only) */
  TOK_TIMES,    /* × or the alias * */
  TOK_LAMBDA,   /* λ or the alias \ */
  TOK_KW_REC,
  TOK_KW_FUN,   /* the alias of λ */
  TOK_KW_DATA,
  TOK_KW_WHERE,
  TOK_KW_POSTULATE,
  TOK_KW_TYPE,
  TOK_KW_SIGMA  /* the alias of × with a binder */
} TokKind;

/* LINE and COL are 1-based; COL counts code points. END_COL is the column
   after the last code point of the token. */
typedef struct {
  TokKind kind;
  const char *text;
  size_t len;
  uint64_t nat;
  int line;
  int col;
  int end_col;
} Token;

/* A `--` comment to the end of its line, without trailing blanks. */
typedef struct {
  const char *text;
  size_t len;
  int line;
  int col;
} Comment;

/* The last token is TOK_EOF. The comments are in source order. */
typedef struct {
  const Token *items;
  size_t count;
  const Comment *comments;
  size_t comment_count;
} TokenList;

/* SOURCE names the input in diagnostics. Returns 1, or 0 after a diagnostic. */
int lex_source(Arena *arena, const char *source, const char *text, size_t len, TokenList *out, Diag *diag);
const char *tok_kind_name(TokKind kind);
/* The core text of a name token: Nat for `ℕ`, else the token bytes. */
const char *tok_core_text(const Token *tok, size_t *len);

#endif
