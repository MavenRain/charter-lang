/* Grammar (× binds tighter than →; both nest to the right):
     decl   := 'postulate' NAME ':' term
             | 'rec'? NAME ':' term NAME NAME* '=' term
             | 'data' NAME group* ':' 'Type' 'where' ctor+
     ctor   := NAME ':' term
     group  := '(' NAME+ ':' term ')'
     term   := ('λ' | '\') (NAME | group)+ '→' term
             | 'fun' (NAME | group)+ '=>' term
             | prod ('→' term)?
     prod   := group '→' term | group '×' prod | app ('×' prod)?
     app    := atom atom*
     atom   := NAME | NAT | 'Type' NAT | 'Sigma' group atom | '(' term ')'
   Layout: a declaration starts at column 1. A token that is the first on its
   line, at a column <= STOP, ends the current term as end of input does. The
   clause line repeats the signature name. In a `data` block the first
   constructor sets the constructor column; each constructor starts a new
   line at that column. */
#include <string.h>

#include "front/parser.h"

#define PARSE_MAX_DEPTH 1000

typedef struct {
  const Token *toks;
  size_t count;
  size_t pos;
  Arena *arena;
  Diag *diag;
  const char *source;
  const char *def;
  Origin origin;
  int depth;
  int stop;
} Parser;

/* One binder group: `(x y : A)` gives two names that share one type. */
typedef struct {
  const char **names;
  size_t count;
  const Term *type;
  const Token *tok;
} Binders;

static const Term *parse_term(Parser *p);
static const Term *parse_atom(Parser *p);
static const Term *parse_prod(Parser *p);

static const Token *peek_at(const Parser *p, size_t ahead) {
  size_t i = p->pos + ahead;
  return &p->toks[i < p->count ? i : p->count - 1];
}

static const Token *cur(const Parser *p) {
  return peek_at(p, 0);
}

static int first_on_line(const Parser *p) {
  return p->pos == 0 || p->toks[p->pos].line != p->toks[p->pos - 1].line;
}

/* A line-start token at or left of the stop column ends the term. */
static int at_stop(const Parser *p) {
  return cur(p)->kind != TOK_EOF && first_on_line(p) && cur(p)->col <= p->stop;
}

/* The kind that the grammar sees: end of input at a stop. */
static TokKind kind_of(const Parser *p) {
  return at_stop(p) ? TOK_EOF : cur(p)->kind;
}

static int at(const Parser *p, TokKind kind) {
  return kind_of(p) == kind;
}

static void bump(Parser *p) {
  p->pos += p->pos + 1 < p->count ? 1u : 0u;
}

static int eat(Parser *p, TokKind kind) {
  if (!at(p, kind)) return 0;
  bump(p);
  return 1;
}

static int oom(Parser *p) {
  return diag_fail(p->diag, "OOM", p->def, "%s: the arena limit is reached", p->source);
}

/* The source bytes of TOK, at most 80. */
static void token_found(const Token *tok, char *out, size_t size) {
  int width = (int)(tok->len < 80 ? tok->len : 80);
  snprintf(out, size, "%.*s", width, tok->text);
}

static Span token_span(const Parser *p, const Token *tok) {
  Span span = {p->source, tok->line, tok->col, tok->line, tok->kind == TOK_EOF ? tok->col : tok->end_col};
  return span;
}

/* FOUND is the token text, or the layout reason at a stop. */
static int fail_at(Parser *p, const Token *tok, const char *what) {
  int stop = tok == cur(p) && at_stop(p);
  char found[96];
  token_found(tok, found, sizeof found);
  if (tok->kind == TOK_EOF) snprintf(found, sizeof found, "end of input");
  if (stop) snprintf(found, sizeof found, "a new line at column %d", tok->col);
  return diag_fail_at(p->diag, "PARSE_EXPECT", p->def, token_span(p, tok), what, found, NULL,
                      "%s:%d:%d: expected %s, found %s", p->source, tok->line, tok->col, what,
                      stop ? found : tok_kind_name(tok->kind));
}

static int expect(Parser *p, TokKind kind, const char *what) {
  return eat(p, kind) ? 1 : fail_at(p, cur(p), what);
}

static int enter(Parser *p) {
  p->depth++;
  if (p->depth <= PARSE_MAX_DEPTH) return 1;
  const Token *tok = cur(p);
  Span span = {p->source, tok->line, tok->col, tok->line, tok->kind == TOK_EOF ? tok->col : tok->end_col};
  return diag_fail_at(p->diag, "PARSE_DEPTH", p->def, span, NULL, NULL, NULL, "%s:%d:%d: terms nest deeper than %d levels",
                      p->source, tok->line, tok->col, PARSE_MAX_DEPTH);
}

static const char *token_text(Parser *p, const Token *tok) {
  size_t len = 0;
  const char *core = tok_core_text(tok, &len);
  char *text = arena_strndup(p->arena, core, len);
  if (text == NULL) oom(p);
  return text;
}

static const char *take_name(Parser *p, const char *what) {
  if (!at(p, TOK_IDENT)) {
    fail_at(p, cur(p), what);
    return NULL;
  }
  const Token *tok = cur(p);
  bump(p);
  return token_text(p, tok);
}

static Term *make_term(Parser *p, TermKind kind, int line, int col) {
  Term *term = arena_alloc(p->arena, sizeof *term);
  if (term == NULL) {
    oom(p);
    return NULL;
  }
  term->kind = kind;
  term->line = line;
  term->col = col;
  return term;
}

/* Grows an arena array by doubling. The old block stays in the arena. */
static void *grow(Parser *p, void *items, size_t count, size_t *cap, size_t size) {
  if (count < *cap) return items;
  size_t next = *cap == 0 ? 4 : *cap * 2;
  void *fresh = arena_alloc(p->arena, next * size);
  if (fresh == NULL) {
    oom(p);
    return NULL;
  }
  if (count > 0) memcpy(fresh, items, count * size);
  *cap = next;
  return fresh;
}

static int starts_atom(TokKind kind) {
  switch (kind) {
    case TOK_IDENT:
    case TOK_NAT:
    case TOK_LPAREN:
    case TOK_KW_TYPE:
    case TOK_KW_SIGMA:
      return 1;
    case TOK_EOF:
    case TOK_RPAREN:
    case TOK_COLON:
    case TOK_DEFINE:
    case TOK_EQUALS:
    case TOK_ARROW:
    case TOK_FATARROW:
    case TOK_TIMES:
    case TOK_LAMBDA:
    case TOK_KW_REC:
    case TOK_KW_FUN:
    case TOK_KW_DATA:
    case TOK_KW_WHERE:
    case TOK_KW_POSTULATE:
      return 0;
  }
  return 0;
}

/* `(` NAME+ `:` starts a binder group. `(f x)` does not. */
static int at_binder_group(const Parser *p) {
  if (!at(p, TOK_LPAREN) || peek_at(p, 1)->kind != TOK_IDENT) return 0;
  size_t ahead = 2;
  while (peek_at(p, ahead)->kind == TOK_IDENT) ahead++;
  return peek_at(p, ahead)->kind == TOK_COLON;
}

static int parse_group(Parser *p, Binders *out) {
  out->tok = cur(p);
  if (!expect(p, TOK_LPAREN, "'('")) return 0;
  size_t start = p->pos;
  while (at(p, TOK_IDENT)) bump(p);
  out->count = p->pos - start;
  if (out->count == 0) return fail_at(p, cur(p), "a binder name");
  out->names = arena_alloc(p->arena, out->count * sizeof *out->names);
  if (out->names == NULL) return oom(p);
  for (size_t i = 0; i < out->count; i++) {
    out->names[i] = token_text(p, &p->toks[start + i]);
    if (out->names[i] == NULL) return 0;
  }
  if (!expect(p, TOK_COLON, "':'")) return 0;
  out->type = parse_term(p);
  return out->type != NULL && expect(p, TOK_RPAREN, "')'");
}

/* A bare lambda binder `x` has no type. The checker infers it. */
static int parse_bare(Parser *p, Binders *out) {
  out->tok = cur(p);
  out->names = arena_alloc(p->arena, sizeof *out->names);
  if (out->names == NULL) return oom(p);
  out->names[0] = take_name(p, "a binder");
  out->count = 1;
  out->type = NULL;
  return out->names[0] != NULL;
}

/* Builds the nested binders of B around BODY, the last name innermost. */
static const Term *wrap(Parser *p, TermKind kind, const Binders *b, const Term *body) {
  const Term *acc = body;
  for (size_t i = b->count; i > 0 && acc != NULL; i--) {
    Term *node = make_term(p, kind, b->tok->line, b->tok->col);
    if (node == NULL) return NULL;
    node->name = b->names[i - 1];
    node->left = b->type;
    node->right = acc;
    acc = node;
  }
  return acc;
}

/* Reads binders up to CLOSE, then the body. */
static const Term *parse_lambda_tail(Parser *p, TokKind close, const char *what) {
  if (eat(p, close)) return parse_term(p);
  Binders b;
  int ok = at(p, TOK_IDENT) ? parse_bare(p, &b) : at(p, TOK_LPAREN) ? parse_group(p, &b) : fail_at(p, cur(p), what);
  if (!ok || !enter(p)) return NULL;
  const Term *body = parse_lambda_tail(p, close, what);
  p->depth--;
  return body == NULL ? NULL : wrap(p, TERM_LAM, &b, body);
}

/* `λ x → t`, and the aliases `\ x → t` and `fun x => t`. */
static const Term *parse_lambda(Parser *p) {
  TokKind close = at(p, TOK_KW_FUN) ? TOK_FATARROW : TOK_ARROW;
  const char *what = close == TOK_FATARROW ? "a binder or '=>'" : "a binder or '→'";
  bump(p);
  if (at(p, close)) {
    fail_at(p, cur(p), "a binder after the lambda");
    return NULL;
  }
  return parse_lambda_tail(p, close, what);
}

static const Term *parse_universe(Parser *p) {
  const Token *tok = cur(p);
  bump(p);
  if (!at(p, TOK_NAT)) {
    fail_at(p, cur(p), "a universe level after 'Type'");
    return NULL;
  }
  Term *term = make_term(p, TERM_UNIV, tok->line, tok->col);
  if (term == NULL) return NULL;
  term->nat = cur(p)->nat;
  bump(p);
  return term;
}

static const Term *parse_sigma_tail(Parser *p) {
  if (!at_binder_group(p)) {
    fail_at(p, cur(p), "a binder (x : A) after 'Sigma'");
    return NULL;
  }
  Binders b;
  if (!parse_group(p, &b)) return NULL;
  const Term *body = parse_atom(p);
  return body == NULL ? NULL : wrap(p, TERM_SIGMA, &b, body);
}

/* `Sigma (x : A) Sigma (y : B) C` nests without parentheses, so it counts
   toward the depth limit. */
static const Term *parse_sigma(Parser *p) {
  bump(p);
  const Term *term = enter(p) ? parse_sigma_tail(p) : NULL;
  p->depth--;
  return term;
}

static const Term *parse_paren(Parser *p) {
  bump(p);
  const Term *inner = parse_term(p);
  return inner != NULL && expect(p, TOK_RPAREN, "')'") ? inner : NULL;
}

static const Term *parse_leaf(Parser *p, TermKind kind) {
  const Token *tok = cur(p);
  Term *term = make_term(p, kind, tok->line, tok->col);
  if (term == NULL) return NULL;
  term->nat = tok->nat;
  term->name = kind == TERM_VAR ? token_text(p, tok) : NULL;
  bump(p);
  return kind == TERM_VAR && term->name == NULL ? NULL : term;
}

static const Term *parse_atom(Parser *p) {
  const Token *tok = cur(p);
  switch (kind_of(p)) {
    case TOK_IDENT: return parse_leaf(p, TERM_VAR);
    case TOK_NAT: return parse_leaf(p, TERM_NAT);
    case TOK_LPAREN: return parse_paren(p);
    case TOK_KW_TYPE: return parse_universe(p);
    case TOK_KW_SIGMA: return parse_sigma(p);
    case TOK_EOF:
    case TOK_RPAREN:
    case TOK_COLON:
    case TOK_DEFINE:
    case TOK_EQUALS:
    case TOK_ARROW:
    case TOK_FATARROW:
    case TOK_TIMES:
    case TOK_LAMBDA:
    case TOK_KW_REC:
    case TOK_KW_FUN:
    case TOK_KW_DATA:
    case TOK_KW_WHERE:
    case TOK_KW_POSTULATE:
      break;
  }
  fail_at(p, tok, "a term");
  return NULL;
}

static const Term *parse_app(Parser *p) {
  const Term *head = parse_atom(p);
  while (head != NULL && starts_atom(kind_of(p))) {
    const Term *arg = parse_atom(p);
    Term *app = arg == NULL ? NULL : make_term(p, TERM_APP, head->line, head->col);
    if (app == NULL) return NULL;
    app->left = head;
    app->right = arg;
    head = app;
  }
  return head;
}

/* A non-dependent `A → B` or `A × B` at the operator OP. */
static const Term *make_binary(Parser *p, TermKind kind, const Token *op, const Term *left, const Term *right) {
  Term *node = right == NULL ? NULL : make_term(p, kind, op->line, op->col);
  if (node == NULL) return NULL;
  node->name = NULL;
  node->left = left;
  node->right = right;
  return node;
}

static const Term *parse_binder_type(Parser *p) {
  Binders b;
  if (!parse_group(p, &b)) return NULL;
  int sigma = at(p, TOK_TIMES);
  if (!sigma && !at(p, TOK_ARROW)) {
    fail_at(p, cur(p), "'→' or '×' after a binder");
    return NULL;
  }
  bump(p);
  const Term *body = sigma ? parse_prod(p) : parse_term(p);
  return body == NULL ? NULL : wrap(p, sigma ? TERM_SIGMA : TERM_PI, &b, body);
}

static const Term *parse_prod_body(Parser *p) {
  if (at_binder_group(p)) return parse_binder_type(p);
  const Term *head = parse_app(p);
  if (head == NULL || !at(p, TOK_TIMES)) return head;
  const Token *op = cur(p);
  bump(p);
  return make_binary(p, TERM_SIGMA, op, head, parse_prod(p));
}

/* `A × B × C` nests without parentheses, so it counts toward the depth
   limit. */
static const Term *parse_prod(Parser *p) {
  const Term *term = enter(p) ? parse_prod_body(p) : NULL;
  p->depth--;
  return term;
}

static const Term *parse_term_body(Parser *p) {
  if (at(p, TOK_LAMBDA) || at(p, TOK_KW_FUN)) return parse_lambda(p);
  const Term *head = parse_prod(p);
  if (head == NULL || !at(p, TOK_ARROW)) return head;
  const Token *op = cur(p);
  bump(p);
  return make_binary(p, TERM_PI, op, head, parse_term(p));
}

static const Term *parse_term(Parser *p) {
  const Term *term = enter(p) ? parse_term_body(p) : NULL;
  p->depth--;
  return term;
}

static int parse_fields(Parser *p, const Field **out, size_t *out_count) {
  Field *items = NULL;
  size_t count = 0;
  size_t cap = 0;
  while (at_binder_group(p)) {
    Binders b;
    if (!parse_group(p, &b)) return 0;
    for (size_t i = 0; i < b.count; i++) {
      items = grow(p, items, count, &cap, sizeof *items);
      if (items == NULL) return 0;
      items[count].name = b.names[i];
      items[count].type = b.type;
      items[count].line = b.tok->line;
      items[count].col = b.tok->col;
      count++;
    }
  }
  *out = items;
  *out_count = count;
  return 1;
}

/* NAME ':' term. The name is the first token of its line when no keyword
   comes before it, so the stop column is set only after it. */
static int parse_signature(Parser *p, Decl *d, const char *what) {
  d->name = take_name(p, what);
  p->stop = 1;
  if (d->name == NULL) return 0;
  p->def = d->name;
  if (!expect(p, TOK_COLON, "':'")) return 0;
  d->type = parse_term(p);
  return d->type != NULL;
}

static int parse_postulate(Parser *p, Decl *d) {
  bump(p);
  d->kind = DECL_AXIOM;
  return parse_signature(p, d, "a postulate name");
}

static int clause_name_fail(Parser *p, const Token *tok, const char *name) {
  char found[96];
  token_found(tok, found, sizeof found);
  return diag_fail_at(p->diag, "PARSE_CLAUSE_NAME", p->def, token_span(p, tok), name, found, name,
                      "%s:%d:%d: the clause name %s is not the signature name %s", p->source, tok->line, tok->col,
                      found, name);
}

static int no_signature_fail(Parser *p, const Token *tok) {
  char found[96];
  token_found(tok, found, sizeof found);
  return diag_fail_at(p->diag, "PARSE_CLAUSE_NAME", found, token_span(p, tok), "a signature `NAME : T` before the clause",
                      found, NULL, "%s:%d:%d: the clause %s has no signature before it", p->source, tok->line,
                      tok->col, found);
}

/* The clause `name x y = body` on a new line at column 1. The arguments
   become bare lambdas around the body. */
static int parse_clause(Parser *p, Decl *d) {
  p->stop = 0;
  const Token *head = cur(p);
  int line_start = head->kind == TOK_IDENT && first_on_line(p) && head->col == 1;
  if (!line_start || peek_at(p, 1)->kind == TOK_COLON) {
    return fail_at(p, head, "the clause of the signature on a new line at column 1");
  }
  size_t len = 0;
  const char *core = tok_core_text(head, &len);
  if (strlen(d->name) != len || memcmp(core, d->name, len) != 0) return clause_name_fail(p, head, d->name);
  bump(p);
  p->stop = 1;
  size_t start = p->pos;
  while (at(p, TOK_IDENT)) bump(p);
  Binders b = {NULL, p->pos - start, NULL, &p->toks[start]};
  b.names = b.count == 0 ? NULL : arena_alloc(p->arena, b.count * sizeof *b.names);
  if (b.count > 0 && b.names == NULL) return oom(p);
  for (size_t i = 0; i < b.count; i++) {
    b.names[i] = token_text(p, &p->toks[start + i]);
    if (b.names[i] == NULL) return 0;
  }
  if (!expect(p, TOK_EQUALS, "'='")) return 0;
  const Term *body = parse_term(p);
  d->body = body == NULL ? NULL : wrap(p, TERM_LAM, &b, body);
  return d->body != NULL;
}

static int parse_def(Parser *p, Decl *d) {
  d->kind = DECL_DEF;
  d->is_rec = eat(p, TOK_KW_REC);
  TokKind next = peek_at(p, 1)->kind;
  int clause = at(p, TOK_IDENT) && (next == TOK_EQUALS || next == TOK_IDENT);
  if (clause) return no_signature_fail(p, cur(p));
  return parse_signature(p, d, "a definition name") && parse_clause(p, d);
}

/* A constructor result is the data type applied to its parameters in
   order. */
static int ctor_result_ok(const Decl *d, const Term *t) {
  const Term *head = t;
  for (size_t i = d->param_count; i > 0; i--) {
    int ok = head->kind == TERM_APP && head->right->kind == TERM_VAR && strcmp(head->right->name, d->params[i - 1].name) == 0;
    if (!ok) return 0;
    head = head->left;
  }
  return head->kind == TERM_VAR && strcmp(head->name, d->name) == 0;
}

/* FOUND is the source text of the constructor type. */
static int ctor_fail(Parser *p, const Ctor *ctor, size_t type_start, const char *expected, const char *why) {
  const Token *first = &p->toks[type_start];
  const Token *last = &p->toks[p->pos - 1];
  Span span = {p->source, ctor->line, ctor->col, last->line, last->end_col};
  size_t len = (size_t)(last->text + last->len - first->text);
  char found[256];
  snprintf(found, sizeof found, "%.*s", (int)(len < 255 ? len : 255), first->text);
  return diag_fail_at(p->diag, "PARSE_CTOR_RESULT", p->def, span, expected, found, NULL,
                      "%s:%d:%d: the constructor %s %s", p->source, ctor->line, ctor->col, ctor->name, why);
}

/* `(x : A) → .. → F p1 .. pn` gives the fields x ... */
static int split_ctor(Parser *p, const Decl *d, Ctor *ctor, const Term *type, size_t type_start) {
  size_t count = 0;
  const Term *t = type;
  while (t->kind == TERM_PI && t->name != NULL) {
    count++;
    t = t->right;
  }
  if (t->kind == TERM_PI) return ctor_fail(p, ctor, type_start, "(name : A) →", "has a field without a name");
  char result[256];
  size_t used = (size_t)snprintf(result, sizeof result, "%s", d->name);
  for (size_t i = 0; i < d->param_count && used < sizeof result; i++) {
    used += (size_t)snprintf(result + used, sizeof result - used, " %s", d->params[i].name);
  }
  char why[320];
  snprintf(why, sizeof why, "must end in %s", result);
  if (!ctor_result_ok(d, t)) return ctor_fail(p, ctor, type_start, result, why);
  Field *fields = count == 0 ? NULL : arena_alloc(p->arena, count * sizeof *fields);
  if (count > 0 && fields == NULL) return oom(p);
  const Term *f = type;
  for (size_t i = 0; i < count; i++) {
    fields[i].name = f->name;
    fields[i].type = f->left;
    fields[i].line = f->line;
    fields[i].col = f->col;
    f = f->right;
  }
  ctor->fields = fields;
  ctor->field_count = count;
  return 1;
}

static int parse_ctor(Parser *p, const Decl *d, Ctor *ctor, int column) {
  ctor->line = cur(p)->line;
  ctor->col = cur(p)->col;
  ctor->name = take_name(p, "a constructor name");
  if (ctor->name == NULL || !expect(p, TOK_COLON, "':'")) return 0;
  size_t type_start = p->pos;
  p->stop = column;
  const Term *type = parse_term(p);
  p->stop = 1;
  return type != NULL && split_ctor(p, d, ctor, type, type_start);
}

static int at_ctor(const Parser *p, int column) {
  return cur(p)->kind != TOK_EOF && first_on_line(p) && cur(p)->col == column;
}

static int parse_data(Parser *p, Decl *d) {
  bump(p);
  d->kind = DECL_FAMILY;
  d->name = take_name(p, "a data type name");
  p->stop = 1;
  if (d->name == NULL) return 0;
  p->def = d->name;
  if (!parse_fields(p, &d->params, &d->param_count)) return 0;
  if (!expect(p, TOK_COLON, "':'") || !expect(p, TOK_KW_TYPE, "'Type'") || !expect(p, TOK_KW_WHERE, "'where'")) return 0;
  if (!at(p, TOK_IDENT) || !first_on_line(p)) return fail_at(p, cur(p), "a constructor on a new indented line");
  int column = cur(p)->col;
  Ctor *ctors = NULL;
  size_t count = 0;
  size_t cap = 0;
  do {
    ctors = grow(p, ctors, count, &cap, sizeof *ctors);
    if (ctors == NULL) return 0;
    Ctor *ctor = &ctors[count];
    count++;
    if (!parse_ctor(p, d, ctor, column)) return 0;
  } while (at_ctor(p, column));
  d->ctors = ctors;
  d->ctor_count = count;
  return 1;
}

static int parse_decl_body(Parser *p, Decl *d) {
  switch (cur(p)->kind) {
    case TOK_KW_POSTULATE: return parse_postulate(p, d);
    case TOK_KW_DATA: return parse_data(p, d);
    case TOK_KW_REC:
    case TOK_IDENT: return parse_def(p, d);
    case TOK_EOF:
    case TOK_NAT:
    case TOK_LPAREN:
    case TOK_RPAREN:
    case TOK_COLON:
    case TOK_DEFINE:
    case TOK_EQUALS:
    case TOK_ARROW:
    case TOK_FATARROW:
    case TOK_TIMES:
    case TOK_LAMBDA:
    case TOK_KW_FUN:
    case TOK_KW_WHERE:
    case TOK_KW_TYPE:
    case TOK_KW_SIGMA:
      break;
  }
  return fail_at(p, cur(p), "a signature, 'rec', 'postulate' or 'data'");
}

/* The head token is read with stop 0; the parts after it set stop 1. */
static int parse_decl(Parser *p, Decl *d) {
  const Token *tok = cur(p);
  p->def = NULL;
  p->stop = 0;
  d->origin = p->origin;
  d->line = tok->line;
  d->col = tok->col;
  if (tok->col != 1) return fail_at(p, tok, "a declaration at column 1");
  if (!parse_decl_body(p, d)) return 0;
  const Token *last = &p->toks[p->pos - 1];
  d->end_line = last->line;
  d->end_col = last->end_col;
  if (!at(p, TOK_EOF)) return fail_at(p, cur(p), "a new line after the declaration");
  p->stop = 0;
  return 1;
}

int parse_source(Arena *arena, const char *source, Origin origin, const TokenList *toks, DeclList *list, Diag *diag) {
  Parser p = {
    .toks = toks->items, .count = toks->count, .pos = 0, .arena = arena, .diag = diag,
    .source = source, .def = NULL, .origin = origin, .depth = 0, .stop = 0,
  };
  Decl *items = list->items;
  size_t count = list->count;
  size_t cap = list->cap;
  int ok = 1;
  /* After a failure LIST keeps the complete declarations (the progress
     counts of `check --json`). */
  while (ok && !at(&p, TOK_EOF)) {
    Decl *grown = grow(&p, items, count, &cap, sizeof *items);
    ok = grown != NULL && parse_decl(&p, &grown[count]);
    items = grown != NULL ? grown : items;
    count += (size_t)ok;
  }
  list->items = items;
  list->count = count;
  list->cap = cap;
  return ok;
}
