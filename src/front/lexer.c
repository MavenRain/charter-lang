#include <string.h>

#include "front/lexer.h"

typedef struct {
  const char *text;
  size_t len;
  size_t pos;
  int line;
  int col;
  Token *out;
  size_t count;
  Comment *comments;
  size_t comment_count;
  size_t comment_cap;
  Arena *arena;
  Diag *diag;
  const char *source;
} Lexer;

static const struct {
  const char *word;
  TokKind kind;
} KEYWORDS[] = {
  {"rec", TOK_KW_REC},
  {"fun", TOK_KW_FUN},
  {"data", TOK_KW_DATA},
  {"where", TOK_KW_WHERE},
  {"postulate", TOK_KW_POSTULATE},
  {"Type", TOK_KW_TYPE},
  {"Sigma", TOK_KW_SIGMA},
};

/* The UTF-8 symbols. `ℕ` is a name token; tok_core_text gives Nat. */
static const struct {
  const char *bytes;
  TokKind kind;
} SYMBOLS[] = {
  {"\xE2\x86\x92", TOK_ARROW},
  {"\xCE\xBB", TOK_LAMBDA},
  {"\xC3\x97", TOK_TIMES},
  {"\xE2\x84\x95", TOK_IDENT},
};

#define NAT_SIGN "\xE2\x84\x95"

const char *tok_kind_name(TokKind kind) {
  switch (kind) {
    case TOK_EOF: return "end of input";
    case TOK_IDENT: return "a name";
    case TOK_NAT: return "a Nat literal";
    case TOK_LPAREN: return "'('";
    case TOK_RPAREN: return "')'";
    case TOK_COLON: return "':'";
    case TOK_DEFINE: return "':='";
    case TOK_EQUALS: return "'='";
    case TOK_ARROW: return "'→'";
    case TOK_FATARROW: return "'=>'";
    case TOK_TIMES: return "'×'";
    case TOK_LAMBDA: return "'λ'";
    case TOK_KW_REC: return "'rec'";
    case TOK_KW_FUN: return "'fun'";
    case TOK_KW_DATA: return "'data'";
    case TOK_KW_WHERE: return "'where'";
    case TOK_KW_POSTULATE: return "'postulate'";
    case TOK_KW_TYPE: return "'Type'";
    case TOK_KW_SIGMA: return "'Sigma'";
  }
  return "a token";
}

static int is_digit(char c) {
  return c >= '0' && c <= '9';
}

static int is_ident_start(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_ident_char(char c) {
  return is_ident_start(c) || is_digit(c) || c == '\'';
}

static char peek(const Lexer *lx, size_t ahead) {
  return lx->pos + ahead < lx->len ? lx->text[lx->pos + ahead] : '\0';
}

/* A UTF-8 continuation byte (0x80..0xBF) adds no column, so COL counts code
   points. */
static void advance(Lexer *lx, size_t width) {
  for (size_t i = 0; i < width && lx->pos < lx->len; i++) {
    unsigned char c = (unsigned char)lx->text[lx->pos];
    int newline = c == '\n';
    int continuation = c >= 0x80 && c <= 0xBF;
    lx->line += newline;
    lx->col = newline ? 1 : lx->col + (continuation ? 0 : 1);
    lx->pos++;
  }
}

static Token *push(Lexer *lx, TokKind kind, size_t start, int line, int col) {
  Token *tok = &lx->out[lx->count];
  lx->count++;
  tok->kind = kind;
  tok->text = lx->text + start;
  tok->len = lx->pos - start;
  tok->nat = 0;
  tok->line = line;
  tok->col = col;
  tok->end_col = lx->col;
  return tok;
}

/* The span of the one code point at LINE and COL. */
static Span point_span(const Lexer *lx, int line, int col) {
  Span span = {lx->source, line, col, line, col + 1};
  return span;
}

static int is_blank(char c) {
  return c == ' ' || c == '\t' || c == '\r';
}

/* Records the `--` comment at the current position, without trailing
   blanks. The comment array grows by doubling in the arena. */
static int take_comment(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  while (lx->pos < lx->len && lx->text[lx->pos] != '\n') advance(lx, 1);
  size_t end = lx->pos;
  while (end > start && is_blank(lx->text[end - 1])) end--;
  if (lx->comment_count == lx->comment_cap) {
    size_t next = lx->comment_cap == 0 ? 8 : lx->comment_cap * 2;
    Comment *fresh = arena_alloc(lx->arena, next * sizeof *fresh);
    if (fresh == NULL) return diag_fail(lx->diag, "OOM", NULL, "%s: no memory for the comments", lx->source);
    if (lx->comment_count > 0) memcpy(fresh, lx->comments, lx->comment_count * sizeof *fresh);
    lx->comments = fresh;
    lx->comment_cap = next;
  }
  Comment *comment = &lx->comments[lx->comment_count];
  lx->comment_count++;
  comment->text = lx->text + start;
  comment->len = end - start;
  comment->line = line;
  comment->col = col;
  return 1;
}

/* Skips white space and records `--` comments to the end of the line. */
static int skip_trivia(Lexer *lx) {
  for (;;) {
    char c = peek(lx, 0);
    int space = lx->pos < lx->len && (is_blank(c) || c == '\n');
    int comment = c == '-' && peek(lx, 1) == '-';
    if (!space && !comment) return 1;
    if (space) {
      advance(lx, 1);
      continue;
    }
    if (!take_comment(lx)) return 0;
  }
}

static TokKind keyword_kind(const char *text, size_t len) {
  for (size_t i = 0; i < sizeof KEYWORDS / sizeof KEYWORDS[0]; i++) {
    if (strlen(KEYWORDS[i].word) == len && memcmp(KEYWORDS[i].word, text, len) == 0) return KEYWORDS[i].kind;
  }
  return TOK_IDENT;
}

static int lex_ident(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  while (is_ident_char(peek(lx, 0))) advance(lx, 1);
  push(lx, keyword_kind(lx->text + start, lx->pos - start), start, line, col);
  return 1;
}

static int lex_nat(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  uint64_t value = 0;
  int overflow = 0;
  while (is_digit(peek(lx, 0))) {
    uint64_t digit = (uint64_t)(peek(lx, 0) - '0');
    overflow |= value > (UINT64_MAX - digit) / 10u;
    value = value * 10u + digit;
    advance(lx, 1);
  }
  char digits[256];
  size_t count = lx->pos - start < sizeof digits - 1 ? lx->pos - start : sizeof digits - 1;
  memcpy(digits, lx->text + start, count);
  digits[count] = '\0';
  if (overflow) {
    Span span = {lx->source, line, col, line, lx->col};
    return diag_fail_at(lx->diag, "LEX_NAT_RANGE", NULL, span, "a Nat literal at most 18446744073709551615", digits, NULL,
                        "%s:%d:%d: a Nat literal is larger than 2^64 - 1", lx->source, line, col);
  }
  if (is_ident_start(peek(lx, 0))) {
    char letter[2] = {peek(lx, 0), '\0'};
    return diag_fail_at(lx->diag, "LEX_CHAR", NULL, point_span(lx, lx->line, lx->col), "a blank after the Nat literal",
                        letter, NULL, "%s:%d:%d: a letter follows a Nat literal", lx->source, lx->line, lx->col);
  }
  push(lx, TOK_NAT, start, line, col)->nat = value;
  return 1;
}

/* Reads one symbol of SYMBOLS. Any other byte at or above 0x80 is LEX_CHAR,
   and FOUND is its UTF-8 sequence. */
static int lex_unicode(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  size_t rest = lx->len - lx->pos;
  for (size_t i = 0; i < sizeof SYMBOLS / sizeof SYMBOLS[0]; i++) {
    size_t width = strlen(SYMBOLS[i].bytes);
    if (rest >= width && memcmp(lx->text + lx->pos, SYMBOLS[i].bytes, width) == 0) {
      advance(lx, width);
      push(lx, SYMBOLS[i].kind, start, line, col);
      return 1;
    }
  }
  unsigned char lead = (unsigned char)peek(lx, 0);
  size_t width = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
  size_t count = width < rest ? width : rest;
  char found[8];
  memcpy(found, lx->text + lx->pos, count);
  found[count] = '\0';
  return diag_fail_at(lx->diag, "LEX_CHAR", NULL, point_span(lx, line, col), "a symbol of the language", found, NULL,
                      "%s:%d:%d: unexpected byte 0x%02x", lx->source, line, col, (unsigned)lead);
}

static int lex_symbol(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  char c = peek(lx, 0);
  char next = peek(lx, 1);
  TokKind kind = TOK_EOF;
  size_t width = 1;
  switch (c) {
    case '(': kind = TOK_LPAREN; break;
    case ')': kind = TOK_RPAREN; break;
    case '*': kind = TOK_TIMES; break;
    case '\\': kind = TOK_LAMBDA; break;
    case ':':
      kind = next == '=' ? TOK_DEFINE : TOK_COLON;
      width = next == '=' ? 2 : 1;
      break;
    case '-':
      kind = next == '>' ? TOK_ARROW : TOK_EOF;
      width = 2;
      break;
    case '=':
      kind = next == '>' ? TOK_FATARROW : TOK_EQUALS;
      width = next == '>' ? 2 : 1;
      break;
    default: break;
  }
  if (kind == TOK_EOF) {
    char found[2] = {c, '\0'};
    return diag_fail_at(lx->diag, "LEX_CHAR", NULL, point_span(lx, line, col), "a symbol of the language", found, NULL,
                        "%s:%d:%d: unexpected byte 0x%02x", lx->source, line, col, (unsigned)(unsigned char)c);
  }
  advance(lx, width);
  push(lx, kind, start, line, col);
  return 1;
}

int lex_source(Arena *arena, const char *source, const char *text, size_t len, TokenList *out, Diag *diag) {
  /* Each token takes at least one byte, and one EOF token follows. */
  Token *tokens = arena_alloc(arena, (len + 1) * sizeof(Token));
  if (tokens == NULL) return diag_fail(diag, "OOM", NULL, "%s: no memory for the tokens", source);
  Lexer lx = {
    .text = text, .len = len, .pos = 0, .line = 1, .col = 1,
    .out = tokens, .count = 0, .comments = NULL, .comment_count = 0, .comment_cap = 0,
    .arena = arena, .diag = diag, .source = source,
  };
  for (;;) {
    if (!skip_trivia(&lx)) return 0;
    if (lx.pos >= lx.len) break;
    char c = peek(&lx, 0);
    int wide = (unsigned char)c >= 0x80;
    int ok = wide ? lex_unicode(&lx) : is_ident_start(c) ? lex_ident(&lx) : is_digit(c) ? lex_nat(&lx) : lex_symbol(&lx);
    if (!ok) return 0;
  }
  push(&lx, TOK_EOF, lx.pos, lx.line, lx.col);
  out->items = tokens;
  out->count = lx.count;
  out->comments = lx.comments;
  out->comment_count = lx.comment_count;
  return 1;
}

const char *tok_core_text(const Token *tok, size_t *len) {
  int nat = tok->kind == TOK_IDENT && tok->len == 3 && memcmp(tok->text, NAT_SIGN, 3) == 0;
  *len = nat ? 3 : tok->len;
  return nat ? "Nat" : tok->text;
}
