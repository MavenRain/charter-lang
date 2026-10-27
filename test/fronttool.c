/* Domain declaration regressions use the same parser and checker as langc.
   `fronttool dump FILE` prints the syntax tree of FILE, one node a line and
   no positions, so a file and its fmt text can be compared. */
#include <stdio.h>
#include <string.h>

#include "front/check.h"
#include "front/lexer.h"
#include "front/parser.h"

static int domain(const char *text, const char *want) {
  Arena arena;
  Diag diag;
  TokenList tokens = {0};
  DeclList decls = {0};
  Machine machine;
  arena_init(&arena, (size_t)1 << 24);
  diag_init(&diag);
  int ok = lex_source(&arena, "test-domain", text, strlen(text), &tokens, &diag)
    && parse_source(&arena, "test-domain", ORIGIN_DOMAIN, &tokens, &decls, &diag)
    && check_program(&arena, &decls, &machine, &diag);
  int passed = want == NULL ? ok : !ok && diag.code != NULL && strcmp(diag.code, want) == 0;
  if (!passed) {
    fprintf(stderr, "FAIL domain: wanted %s, got %s: %s\n", want == NULL ? "ok" : want,
            ok ? "ok" : diag.code == NULL ? "no diagnostic" : diag.code, text);
  }
  arena_release(&arena);
  return passed;
}

/* Even malformed source bytes must produce a readable JSON diagnostic. */
static int json_encoding(void) {
  static const struct { const char *source; const char *found; } cases[] = {
    {"\xff", "\\u00ff"},
    {"\x80", "\\u0080"},
    {"\xc0\xaf", "\\u00c0\\u00af"},
    {"\xe2\x86", "\\u00e2\\u0086"},
    {"\xe0\x80\x80", "\\u00e0\\u0080\\u0080"},
    {"\xed\xa0\x80", "\\u00ed\\u00a0\\u0080"},
    {"\xf4\x90\x80\x80", "\\u00f4\\u0090\\u0080\\u0080"},
    {"\xc3\xa9", "\xc3\xa9"},
    {"\xe2\x98\x83", "\xe2\x98\x83"},
    {"\xf0\x9f\x98\x80", "\xf0\x9f\x98\x80"},
  };
  int passed = 1;
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    Arena arena;
    Diag diag;
    TokenList tokens = {0};
    arena_init(&arena, (size_t)1 << 16);
    diag_init(&diag);
    int lexed = lex_source(&arena, "test-encoding", cases[i].source, strlen(cases[i].source), &tokens, &diag);
    FILE *out = tmpfile();
    char got[2048] = {0};
    char want[128];
    snprintf(want, sizeof want, "\"found\":\"%s\"", cases[i].found);
    if (out != NULL) {
      if (diag.set) diag_print_json(&diag, out);
      rewind(out);
      fread(got, 1, sizeof got - 1, out);
      fclose(out);
    }
    if (lexed || out == NULL || strstr(got, want) == NULL) {
      fprintf(stderr, "FAIL JSON encoding case %zu: expected %s\n", i, want);
      passed = 0;
    }
    arena_release(&arena);
  }
  return passed;
}

static const char *const TERM_KINDS[] = {"var", "nat", "app", "lam", "pi", "sigma", "univ"};
static const char *const DECL_KINDS[] = {"def", "postulate", "data"};

static void dump_term(const char *role, const Term *t, int depth) {
  if (t == NULL) return;
  printf("%*s%s %s", depth * 2, "", role, TERM_KINDS[t->kind]);
  if (t->name != NULL) printf(" %s", t->name);
  if (t->kind == TERM_NAT || t->kind == TERM_UNIV) printf(" %llu", (unsigned long long)t->nat);
  putchar('\n');
  dump_term("left", t->left, depth + 1);
  dump_term("right", t->right, depth + 1);
}

static void dump_fields(const char *role, const Field *fields, size_t count, int depth) {
  size_t i;
  for (i = 0; i < count; i++) {
    printf("%*s%s %s\n", depth * 2, "", role, fields[i].name == NULL ? "_" : fields[i].name);
    dump_term("type", fields[i].type, depth + 1);
  }
}

/* Prints each declaration, then its parameters, type, body and constructors. */
static int dump(const char *file) {
  static char text[1 << 20];
  FILE *in = fopen(file, "rb");
  if (in == NULL) {
    fprintf(stderr, "fronttool: cannot read %s\n", file);
    return 2;
  }
  size_t len = fread(text, 1, sizeof text, in);
  fclose(in);
  if (len == sizeof text) {
    fprintf(stderr, "fronttool: %s is too large\n", file);
    return 2;
  }
  Arena arena;
  Diag diag;
  TokenList tokens = {0};
  DeclList decls = {0};
  arena_init(&arena, (size_t)1 << 24);
  diag_init(&diag);
  int ok = lex_source(&arena, file, text, len, &tokens, &diag)
    && parse_source(&arena, file, ORIGIN_DOMAIN, &tokens, &decls, &diag);
  if (!ok) diag_print(&diag, stderr);
  size_t i, j;
  for (i = 0; ok && i < decls.count; i++) {
    const Decl *d = &decls.items[i];
    printf("%s %s%s\n", DECL_KINDS[d->kind], d->name, d->is_rec ? " rec" : "");
    dump_fields("param", d->params, d->param_count, 1);
    dump_term("type", d->type, 1);
    dump_term("body", d->body, 1);
    for (j = 0; j < d->ctor_count; j++) {
      printf("  ctor %s\n", d->ctors[j].name);
      dump_fields("field", d->ctors[j].fields, d->ctors[j].field_count, 2);
    }
  }
  arena_release(&arena);
  return ok ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "dump") == 0) return dump(argv[2]);
  if (argc != 1) {
    fputs("usage: fronttool [dump FILE]\n", stderr);
    return 2;
  }
  int ok = json_encoding();
  ok &= domain("data F : Type where\n  makeF : (field : ℕ) → (field : Bool) → F", "REFUSE_NAME");
  ok &= domain("data F : Type where\n  makeF : (makeF : ℕ) → F", "REFUSE_NAME");
  ok &= domain("data F : Type where\n  makeF : (firstField : ℕ) → (secondField : Bool) → F", NULL);
  ok &= domain("data F : Type where\n  a : (field : ℕ) → F\n  b : (field : ℕ) → F", "REFUSE_NAME");
  ok &= domain("s : Sum ℕ ℕ\ns = inl 7\n\nbad : Sum Bool ℕ\nbad = bind s (λ x → inr x)", "TYPE_MISMATCH");
  ok &= domain("data Lot (n : ℕ) : Type where\n  makeLot : (amount : ℕ) → Lot n\n\n"
               "s : Sum ℕ ℕ\ns = inl 0\n\n"
               "f : (n : ℕ) → ℕ → Lot n\nf n x = makeLot n x\n\n"
               "bad : (n : ℕ) → Lot n\nbad = either f f s", "TYPE_MISMATCH");
  ok &= domain("bad : Type 1\nbad = ℕ", "TYPE_MISMATCH");
  ok &= domain("bad : Type 2\nbad = Type 1", "TYPE_UNIVERSE");
  ok &= domain("data U : Type where\n  makeU : (decode : Type 0) → U\n\nbad : Type 0\nbad = U", "TYPE_MISMATCH");
  ok &= domain("data U : Type where\n  makeU : (decode : Type 0) → U\n\n"
               "data W : Type where\n  makeW : (wrapped : U) → W\n\nbad : Type 0\nbad = W", "TYPE_MISMATCH");
  ok &= domain("data Box (A : Type 1) : Type where\n  box : (unbox : A) → Box A\n\nbad : Type 0\nbad = Box (Type 0)", "TYPE_MISMATCH");
  ok &= domain("data U : Type where\n  makeU : (decode : Type 0) → U\n\ngood : Type 1\ngood = U", NULL);
  ok &= domain("eta : (p : (n : ℕ) × Eq ℕ n n) → Eq ((n : ℕ) × Eq ℕ n n) (pack (witness p) (payload p)) p\n"
               "eta p = refl", NULL);
  ok &= domain("data Wrap (A : Type 0) : Type where\n  wrap : (val : A) → Wrap A\n  label : (code : ℕ) → Wrap A", NULL);
  ok &= domain("data Pair (A : Type 0) : Type where\n  makePair : (one : A) → (two : A) → Pair A", "REFUSE_CELL");
  ok &= domain("data Tag (A : Type 0) (n : ℕ) : Type where\n  tag : (val : A) → Tag A n", "REFUSE_CELL");
  ok &= domain("data Twice (A : Type 0) : Type where\n  once : (x : A) → Twice A\n  again : (y : A) → Twice A", "REFUSE_CELL");
  ok &= domain("data Ghost (A : Type 0) : Type where\n  ghost : (code : ℕ) → Ghost A", "REFUSE_CELL");
  ok &= domain("data Leak (A : Type 0) : Type where\n  wrap : (val : A) → Leak A\n  maybe : (o : Option A) → Leak A", "REFUSE_CELL");
  ok &= domain("data Higher (F : Type 0 → Type 0) : Type where\n  hold : (code : ℕ) → Higher F", "REFUSE_CELL");
  ok &= domain("U : Type 1\nU = Type 0\n\n"
               "data Bad (A : U) : Type where\n  bad : (left : A) → (right : A) → Bad A", "REFUSE_CELL");
  ok &= domain("U : Type 1\nU = Type 0\n\n"
               "data Good (A : U) : Type where\n  good : (value : A) → Good A", NULL);
  ok &= domain("H : Type 1\nH = Type 0 → Type 0\n\n"
               "data Higher (F : H) : Type where\n  hold : (code : ℕ) → Higher F", "REFUSE_CELL");
  ok &= domain("Id : Type 0 → Type 0\nId A = A\n\n"
               "data Good (A : Type 0) : Type where\n  good : (value : Id A) → Good A", NULL);
  ok &= domain("Id : Type 0 → Type 0\nId A = A\n\n"
               "data Twice (A : Type 0) : Type where\n  once : (x : A) → Twice A\n  again : (y : Id A) → Twice A", "REFUSE_CELL");
  ok &= domain("data List : Type where\n  makeList : (code : ℕ) → List", "REFUSE_NAME");
  ok &= domain("cons : ℕ\ncons = 1", "REFUSE_NAME");
  ok &= domain("unitL : (a : ℕ) → Eq ℕ (natAdd 0 a) a\n"
               "unitL a = ind (λ (n : ℕ) → Eq ℕ (natAdd 0 n) n) refl "
               "(λ (k : ℕ) (ih : Eq ℕ (natAdd 0 k) k) → cong (λ (x : ℕ) → natAdd x 1) ih) a", NULL);
  ok &= domain("bad : ℕ\nbad = ind (λ (n : Bool) → ℕ) 0 (λ (k : ℕ) (ih : ℕ) → ih) 3", "TYPE_MISMATCH");
  ok &= domain("data Run (n : ℕ) : Type where\n  runEnd : Run n\n  runStep : (runVal : ℕ) → (runNext : Run n) → Run n\n\n"
               "runSum : ℕ → ℕ\nrunSum k = fold 0 (λ (v : ℕ) (acc : ℕ) → natAdd v acc) (runStep 2 k (runEnd 2))", NULL);
  ok &= domain("data Emit (Z : Type 0) : Type where\n  emRet : (emZ : Z) → Emit Z\n  emNone : Emit Z\n"
               "  emStep : (emV : ℕ) → (emT : Emit Z) → Emit Z", NULL);
  ok &= domain("data Run (n : ℕ) : Type where\n  runEnd : Run n\n  runStep : (runVal : ℕ) → (runNext : Run n) → Run n\n\n"
               "runF : (r : Run 2) → ℕ\nrunF r = fold 0 (λ (v : ℕ) (acc : ℕ) → natAdd v acc) r\n\n"
               "runI : (r : Run 2) → ℕ\nrunI r = ind (λ (x : Run 2) → ℕ) 0 (λ (v : ℕ) (t : Run 2) (ih : ℕ) → natAdd v ih) r\n\n"
               "runSame : (r : Run 2) → Eq ℕ (runF r) (runI r)\n"
               "runSame r = ind (λ (x : Run 2) → Eq ℕ (runF x) (runI x)) refl "
               "(λ (v : ℕ) (t : Run 2) (ih : Eq ℕ (runF t) (runI t)) → cong (λ (y : ℕ) → natAdd v y) ih) r", NULL);
  ok &= domain("data Run (n : ℕ) : Type where\n  runEnd : Run n\n  runStep : (runVal : ℕ) → (runNext : Run n) → Run n\n\n"
               "bad : (r : Run 2) → ℕ\nbad r = ind (λ (n : ℕ) → ℕ) 0 (λ (v : ℕ) (t : Run 2) (ih : ℕ) → natAdd v ih) r",
               "TYPE_MISMATCH");
  ok &= domain("data Emit (Z : Type 0) : Type where\n  emRet : (emZ : Z) → Emit Z\n  emNone : Emit Z\n"
               "  emStep : (emV : ℕ) → (emT : Emit Z) → Emit Z\n\n"
               "emSum : (e : Emit ℕ) → ℕ\n"
               "emSum e = ind (λ (x : Emit ℕ) → ℕ) (λ (z : ℕ) → z) 0 (λ (v : ℕ) (t : Emit ℕ) (ih : ℕ) → natAdd v ih) e\n\n"
               "emLaw : (v : ℕ) → (t : Emit ℕ) → Eq ℕ (emSum (emStep ℕ v t)) (natAdd v (emSum t))\nemLaw v t = refl", NULL);
  /* R1 second class (Q-S2a-2): a free monoid, and the cons forms it refuses. */
  ok &= domain("data FreeM (A : Type 0) : Type where\n  frNil : FreeM A\n  frCons : (frHead : A) → (frTail : FreeM A) → FreeM A", NULL);
  ok &= domain("data TwoA (A : Type 0) : Type where\n  twNil : TwoA A\n  twCons : (twHead : A) → (twNext : A) → TwoA A", "REFUSE_CELL");
  ok &= domain("data NoTail (A : Type 0) : Type where\n  ntNil : NoTail A\n  ntCons : (ntHead : A) → (ntCode : ℕ) → NoTail A", "REFUSE_CELL");
  ok &= domain("data SkewM (A : Type 0) : Type where\n  smNil : SkewM A\n  smCons : (smHead : A) → (smTail : SkewM ℕ) → SkewM A", "DOMAIN_FAMILY");
  ok &= domain("data ExtraM (A : Type 0) : Type where\n  exNil : ExtraM A\n  exOne : (exVal : A) → ExtraM A\n  exCons : (exHead : A) → (exTail : ExtraM A) → ExtraM A", "REFUSE_CELL");
  ok &= domain("data Skew (A : Type 0) (B : Type 0) : Type where\n  skLeft : (skA : A) → Skew A B\n"
               "  skRight : (skB : B) → Skew A B\n  skSwap : (skInner : Skew B A) → Skew A B", "DOMAIN_FAMILY");
  ok &= domain("data Grow (n : ℕ) : Type where\n  grEnd : Grow n\n  grStep : (grNext : Grow (natAdd n 1)) → Grow n", "DOMAIN_FAMILY");
  /* D31: natLe and natSub close on a variable only when the offsets make the result true for each value. */
  ok &= domain("bad : (y : ℕ) → Eq Bool (natLe 3 y) true\nbad y = refl", "TYPE_REFL");
  ok &= domain("bad : (x : ℕ) → Eq Bool (natLe x 0) false\nbad x = refl", "TYPE_REFL");
  ok &= domain("bad : (x : ℕ) → Eq ℕ (natSub x 3) x\nbad x = refl", "TYPE_REFL");
  ok &= domain("good : (x : ℕ) → Eq Bool (natLe (natAdd x 1) 0) false\ngood x = refl", NULL);
  ok &= domain("data Choice : Type where\n  choiceA : Choice\n  choiceB : Choice\n\n"
               "select : (b : Choice) → (n : ℕ) → ℕ\n"
               "select b n = ind (λ (x : Choice) → ℕ → ℕ) (λ (k : ℕ) → k) (λ (k : ℕ) → natAdd k 1) b n\n\n"
               "selected : Eq ℕ (select choiceB 4) 5\nselected = refl", NULL);
  ok &= domain("data Three : Type where\n  threeA : Three\n  threeB : Three\n  threeC : Three\n\n"
               "natResult : (n : ℕ) → (b : Three) → ℕ\n"
               "natResult n b = ind (λ (x : ℕ) → Three → ℕ) (λ (t : Three) → 7) "
               "(λ (k : ℕ) (ih : Three → ℕ) → ih) n b", NULL);
  if (ok) puts("domain regressions: passed");
  return ok ? 0 : 1;
}
