/* Exercise the check command's warning fixes through the parser and printer. */
#include <stdlib.h>

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

/* A constant induction step must not erase overflow in a symbolic successor:
   the lowered ind keeps the carry of natAdd n 1 and its trap. */
static int runtime_ind_effect(void) {
  static const char text[] =
    "guarded : (n : ℕ) → ℕ\n"
    "guarded n = ind (λ (m : ℕ) → ℕ) 7 (λ (k : ℕ) (ih : ℕ) → 7) (natAdd n 1)\n";
  Arena arena;
  Diag diag;
  Front front;
  Machine machine;
  IrProgram prog;
  FILE *out = NULL;
  char got[4096] = {0};
  arena_init(&arena, (size_t)1 << 30);
  diag_init(&diag);
  int checked = front_load(&arena, "test-ind-effect", text, strlen(text), &front, &diag)
    && check_program(&arena, &front.decls, &machine, &diag);
  int lowered = checked && lower_program(&machine, &prog, 0) && (out = tmpfile()) != NULL;
  if (lowered) {
    ir_print(&prog, out);
    rewind(out);
    fread(got, 1, sizeof got - 1, out);
    fclose(out);
  }
  int ok = lowered && strstr(got, "add_carry(l0, 1)") != NULL && strstr(got, "trap") != NULL;
  if (!ok) fprintf(stderr, "FAIL runtime ind: symbolic successor lost its overflow effect\n");
  arena_release(&arena);
  return ok;
}

/* Compile through the real encoder, including its export validation. */
static int stream_module(const char *text, int accepted) {
  Arena arena;
  Diag diag;
  Front front;
  Machine machine;
  IrProgram prog;
  FILE *out = fopen("build/review-stream.wasm", "wb");
  FILE *err = tmpfile();
  char message[256] = {0};
  arena_init(&arena, (size_t)1 << 30);
  diag_init(&diag);
  int checked = front_load(&arena, "test-stream", text, strlen(text), &front, &diag)
    && check_program(&arena, &front.decls, &machine, &diag)
    && lower_program(&machine, &prog, 1);
  int written = checked && out != NULL && err != NULL
    && target_write(&prog, TARGET_PART_MAIN, out, err);
  int ok = checked && out != NULL && err != NULL && written == accepted;
  if (!accepted && out != NULL && err != NULL) {
    rewind(err);
    fread(message, 1, sizeof message - 1, err);
    ok = ok && ftell(out) == 0 && strstr(message, "langc: REFUSE_EXPORT: memory:") != NULL;
  }
  if (out != NULL) ok = fclose(out) == 0 && ok;
  if (err != NULL) fclose(err);
  if (!ok) fprintf(stderr, "FAIL stream module: want accepted=%d, got %d (%s)\n", accepted, written, message);
  arena_release(&arena);
  return ok;
}

/* Run generated Wasm with the existing runner or the WABT interpreter. */
static int wasm_case(const char *command, const char *want) {
  char got[512] = {0};
  int status = system(command);
  FILE *out = fopen("build/review-stream.out", "rb");
  if (out != NULL) {
    fread(got, 1, sizeof got - 1, out);
    fclose(out);
  }
  int ok = status == 0 && out != NULL && strcmp(got, want) == 0;
  if (!ok) fprintf(stderr, "FAIL Wasm stream: %s: status %d, want '%s', got '%s'\n", command, status, want, got);
  return ok;
}

static int stream_regressions(void) {
  static const char text[] =
    "evidence : ℕ → Eq ℕ 0 0\n"
    "evidence n = flagIf (natEq (natAdd n 1) 0) refl refl\n"
    "boxedProof : ℕ → (n : ℕ) × Eq ℕ 0 0\n"
    "boxedProof n = pack 7 (evidence n)\n"
    "optionalProof : ℕ → Option (Eq ℕ 0 0)\n"
    "optionalProof n = some (evidence n)\n"
    "erasedProof : Eq ℕ 0 0\n"
    "erasedProof = refl\n";
  int ok = stream_module(text, 1);
  if (ok) {
    ok &= wasm_case("node test/run-wasm.mjs --words build/review-stream.wasm evidence 18446744073709551615 >build/review-stream.out 2>&1", "trap\n");
    ok &= wasm_case("node test/run-wasm.mjs --words build/review-stream.wasm boxedProof 18446744073709551615 >build/review-stream.out 2>&1", "trap\n");
    ok &= wasm_case("node test/run-wasm.mjs --words build/review-stream.wasm optionalProof 18446744073709551615 >build/review-stream.out 2>&1", "trap\n");
    ok &= wasm_case("node test/run-wasm.mjs --words build/review-stream.wasm evidence 3 >build/review-stream.out 2>&1", "\n");
    ok &= wasm_case("node test/run-wasm.mjs --words build/review-stream.wasm boxedProof 3 >build/review-stream.out 2>&1", "7\n");
    ok &= wasm_case("node test/run-wasm.mjs --words build/review-stream.wasm optionalProof 3 >build/review-stream.out 2>&1", "1\n");
    ok &= wasm_case("wasm-interp build/review-stream.wasm -r erasedProof -a i64:0 >build/review-stream.out 2>&1", "erasedProof(i64:0) => i64:0\n");
    ok &= wasm_case("wasm-interp build/review-stream.wasm -r erasedProof -a i64:2305843009213693952 >build/review-stream.out 2>&1", "erasedProof(i64:2305843009213693952) => error: unreachable executed\n");
    ok &= wasm_case("wasm-interp build/review-stream.wasm -r erasedProof -a i64:18446744073709551615 >build/review-stream.out 2>&1", "erasedProof(i64:18446744073709551615) => error: unreachable executed\n");
    ok &= wasm_case("wasm-interp build/review-stream.wasm -r erasedProof -a i64:8193 >build/review-stream.out 2>&1", "erasedProof(i64:8193) => error: unreachable executed\n");
  }
  ok &= stream_module("memory : Address\nmemory = address 5\n", 0);
  ok &= stream_module("memory : ℕ\nmemory = 5\nmarker : Eq ℕ 0 0\nmarker = refl\n", 0);
  ok &= stream_module("memory : ℕ\nmemory = 5\n", 1);
  remove("build/review-stream.wasm");
  remove("build/review-stream.out");
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
  ok &= stream_regressions();
  if (ok) puts("warning fix regressions: passed");
  return ok ? 0 : 1;
}
