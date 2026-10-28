/* Exercise the check command's warning fixes through the parser and printer. */
#define main langc_main
#include "../src/main.c"
#undef main

/* Resolve a code point position to a byte offset for applying a JSON fix. */
static size_t source_offset(const char *text, size_t len, int line, int col) {
  int row = 1;
  int column = 1;
  size_t at = 0;
  while (at < len && (row != line || column != col)) {
    if (text[at++] == '\n') {
      row++;
      column = 1;
    } else {
      while (at < len && ((unsigned char)text[at] & 0xC0u) == 0x80u) at++;
      column++;
    }
  }
  return row == line && column == col ? at : SIZE_MAX;
}

static int warning_fix(const char *text) {
  Arena arena;
  Diag diag, warn;
  Front front;
  FmtText canon;
  size_t len = strlen(text);
  arena_init(&arena, (size_t)1 << 24);
  diag_init(&diag);
  diag_init(&warn);
  int ok = front_load(&arena, "test-warning", text, len, &front, &diag);
  fmt_text_init(&canon, &arena);
  if (ok) {
    noncanon(&arena, "test-warning", text, len, &front, &warn);
    ok = fmt_program(&canon, front.decls.items + front.domain_count,
                     front.decls.count - front.domain_count, &front.toks);
  }
  size_t first = warn.set ? source_offset(text, len, warn.span.line, warn.span.col) : SIZE_MAX;
  size_t end = warn.set ? source_offset(text, len, warn.span.end_line, warn.span.end_col) : SIZE_MAX;
  ok = ok && warn.set && warn.found != NULL && warn.fix != NULL && first <= end && end <= len;
  if (ok) {
    size_t fix_len = strlen(warn.fix);
    size_t suffix = len - end;
    ok = strlen(warn.found) == end - first && memcmp(text + first, warn.found, end - first) == 0
      && canon.len == first + fix_len + suffix;
    if (ok && canon.len > 0) {
      /* Applying the reported replacement must produce the canonical file. */
      ok = memcmp(canon.data, text, first) == 0
        && memcmp(canon.data + first, warn.fix, fix_len) == 0
        && memcmp(canon.data + first + fix_len, text + end, suffix) == 0;
    }
  }
  if (!ok) fprintf(stderr, "FAIL warning fix: %s\n", text);
  arena_release(&arena);
  return ok;
}

/* A constant induction step must not erase overflow in a symbolic successor. */
static int runtime_ind_effect(void) {
  static const char text[] =
    "guarded : (n : ℕ) → ℕ\n"
    "guarded n = ind (λ (m : ℕ) → ℕ) 7 (λ (k : ℕ) (ih : ℕ) → 7) (natAdd n 1)\n";
  Arena arena;
  Diag diag;
  Front front;
  Machine machine;
  IrProgram prog;
  arena_init(&arena, (size_t)1 << 30);
  diag_init(&diag);
  int checked = front_load(&arena, "test-ind-effect", text, strlen(text), &front, &diag)
    && check_program(&arena, &front.decls, &machine, &diag);
  int ok = checked && !lower_program(&machine, &prog) && diag.code != NULL
    && strcmp(diag.code, "REFUSE_RUNTIME_TREE") == 0;
  if (!ok) fprintf(stderr, "FAIL runtime ind: symbolic successor lost its overflow effect\n");
  arena_release(&arena);
  return ok;
}

int main(void) {
  int ok = 1;
  ok &= warning_fix("-- keep this comment\nid : Nat -> Nat\nid x = x\n");
  ok &= warning_fix("id : ℕ → ℕ\nid x = x\nnext : Nat\nnext = 1\n");
  ok &= warning_fix("value : ℕ\nvalue = 1");
  ok &= warning_fix("value : ℕ\nvalue = 1\n\n-- tail   ");
  ok &= warning_fix("value : ℕ\nvalue = 1 -- inline\n");
  ok &= warning_fix(" \n\t");
  ok &= runtime_ind_effect();
  if (ok) puts("warning fix regressions: passed");
  return ok ? 0 : 1;
}
