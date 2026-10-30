/* Exercise the check command's warning fixes through the parser and printer. */
#include <stdlib.h>
#include <string.h>

#include "front/ed25519.h"
#include "front/poseidon2.h"
#include "front/sha512.h"
#include "wasm_kernel.h"

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

/* Compare a digest with a hex vector; LABEL names the case on a failure. */
static int digest_case(const char *label, const Fr *got, const char *want) {
  Fr expected;
  int ok = fr_from_hex(&expected, want) && fr_equal(got, &expected);
  if (!ok) fprintf(stderr, "FAIL poseidon2: %s\n", label);
  return ok;
}

/* Poseidon2 BN254 t = 3 (W/S4-r1-vectors.md). Each round constant reads as
 * a canonical element. The known answer is poseidon2_tests_bn256::kats of
 * HorizenLabs/poseidon2 rev 055bde3f: the permutation of (0, 1, 2). The own
 * vectors (S4 r1, not from a source) pin H on the empty stream for tags 1 to
 * 5, and H(1, [7], 1) and H(1, [7, 0], 2), which differ by the count in the
 * capacity. */
static int poseidon2_regressions(void) {
  static const char *const kat[POSEIDON2_T] = {
    "0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033",
    "0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570",
    "0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8"
  };
  static const char *const empty[5] = {
    "0x2590abf0843316738b6f6d0138d2654dfd59a6eb4a47cd43a354fd65971be07d",
    "0x1af3d549efcf2e24b829e45a68bb32a2fe55e47fb3f6c2502bfd69bf7a9e569d",
    "0x007740adad9285ad5cf8a8ec861813aef6c1619c77cfe3eefab7cd1615748c90",
    "0x2e5e9eadebbb18eed7f20667199f2f02c454e0c61dd39f5e821a9091493abe89",
    "0x12ea277be56060a3edfc791974fb28bd16514e3232a0b3d455897193d6c2f34f"
  };
  uint64_t seven[2] = {7, 0};
  Fr state[POSEIDON2_T];
  Fr digest;
  int ok = poseidon2_constants_ok();
  if (!ok) fprintf(stderr, "FAIL poseidon2: a round constant is not canonical\n");
  for (unsigned i = 0; i < POSEIDON2_T; i++) {
    uint64_t words[FR_WORDS] = {0, 0, 0, 0};
    words[0] = i;
    ok &= fr_from_words(&state[i], words);
  }
  poseidon2_permute(state);
  ok &= digest_case("KAT element 0", &state[0], kat[0]);
  ok &= digest_case("KAT element 1", &state[1], kat[1]);
  ok &= digest_case("KAT element 2", &state[2], kat[2]);
  for (unsigned tag = 1; tag <= 5; tag++) {
    poseidon2_hash(tag, NULL, 0, &digest);
    ok &= digest_case("own empty stream", &digest, empty[tag - 1]);
  }
  poseidon2_hash(1, seven, 1, &digest);
  ok &= digest_case("own H(1, [7], 1)", &digest,
                    "0x2343a981b3acf166d0c759280df76e6b08c37ad7bd82dca197d86cff6002b1b1");
  poseidon2_hash(1, seven, 2, &digest);
  ok &= digest_case("own H(1, [7, 0], 2)", &digest,
                    "0x25471bb5ce35fd076f761cb5435d05e46ffeb8daf88a2ba46e894f17d43699a8");
  return ok;
}

/* Writes word W in decimal after TEXT, with a space after a word before it. */
static void append_word(char *text, size_t size, uint64_t w) {
  size_t len = strlen(text);
  snprintf(text + len, size - len, "%s%llu", len == 0 ? "" : " ", (unsigned long long)w);
}

/* Runs ENTRY of the kernel module on the N words ARGS; it must print the M
 * words WANT. */
static int kernel_case(const char *entry, const uint64_t *args, size_t n, const uint64_t *want, size_t m) {
  char words[1024] = {0};
  char expect[512] = {0};
  char command[2048];
  size_t i;
  for (i = 0; i < n; i++) append_word(words, sizeof words, args[i]);
  for (i = 0; i < m; i++) append_word(expect, sizeof expect, want[i]);
  strcat(expect, "\n");
  snprintf(command, sizeof command,
           "node test/run-wasm.mjs --words build/p2-kernel.wasm %s %s >build/review-stream.out 2>&1", entry, words);
  return wasm_case(command, expect);
}

/* The FIPS 180-4 SHA-512 examples: one block, the empty message, two
 * blocks. */
static const char *const sha512_texts[3] = {
  "abc", "",
  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};

enum { SHA512_CASE_MAX = 240 };

/* Runs sha512 of the kernel module on the N bytes of TEXT (N at most
 * SHA512_CASE_MAX); it must print the C digest, 8 bytes per word, little
 * endian. */
static int sha512_kernel_case(const uint8_t *text, size_t n) {
  uint64_t args[1 + SHA512_CASE_MAX / 8] = {0};
  uint64_t want[SHA512_BYTES / 8] = {0};
  uint8_t digest[SHA512_BYTES];
  size_t i;
  if (n > SHA512_CASE_MAX) {
    printf("FAIL sha512 wasm: %u bytes\n", (unsigned)n);
    return 0;
  }
  sha512(text, n, digest);
  args[0] = n;
  for (i = 0; i < n; i++) args[1 + i / 8] |= (uint64_t)text[i] << (8 * (i % 8));
  for (i = 0; i < SHA512_BYTES; i++) want[i / 8] |= (uint64_t)digest[i] << (8 * (i % 8));
  return kernel_case("sha512", args, 1 + (n + 7) / 8, want, SHA512_BYTES / 8);
}

static int ed25519_kernel_rows(void);

/* The Wasm kernel of Poseidon2 against the C (Q-C6, S4 U2): the permutation
 * of the KAT input (0, 1, 2), of r - 1 in each element (the conditional
 * subtract) and of the KAT output; H on the own vectors of
 * poseidon2_regressions, on 5 words (3 blocks) and with a tag above 2^32;
 * one row for the ops XOR, AND and ROTR; and the SHA-512 kernel (S4 U5) on
 * the FIPS 180-4 examples and on 111, 112, 127, 128 and 239 bytes (the
 * padding edges: 1 or 2 final blocks); and the Ed25519 verify kernel (S4
 * U5) on the rows of ed25519_kernel_rows, including forged signatures under
 * pure small-order keys. */
static int kernel_regressions(void) {
  static const uint64_t stream[5] = {7, 0, 0xffffffffffffffffu, 0x100000000u, 3};
  static const uint64_t tags[9] = {1, 2, 3, 4, 5, 1, 1, 5, 0x500000002u};
  static const size_t counts[9] = {0, 0, 0, 0, 0, 1, 2, 5, 3};
  static const uint64_t ops[3] = {0x0123456789abcdefu, 0xff00ff00ff00ff00u, 12};
  static const size_t edges[5] = {111, 112, 127, 128, 239};
  Fr cases[3][POSEIDON2_T];
  Fr top = fr_modulus();
  Fr digest;
  uint64_t args[12];
  uint64_t want[12];
  uint8_t bytes[239];
  unsigned c;
  unsigned i;
  FILE *module = fopen("build/p2-kernel.wasm", "wb");
  int ok = module != NULL && wasm_write_kernel_test(module, stderr);
  if (module != NULL) ok = fclose(module) == 0 && ok;
  if (!ok) fprintf(stderr, "FAIL poseidon2 wasm: cannot write build/p2-kernel.wasm\n");
  top.limb[0] -= 1;
  for (i = 0; i < POSEIDON2_T; i++) {
    uint64_t words[FR_WORDS] = {0, 0, 0, 0};
    words[0] = i;
    ok &= fr_from_words(&cases[0][i], words);
    cases[1][i] = top;
    cases[2][i] = cases[0][i];
  }
  poseidon2_permute(cases[2]);
  for (c = 0; c < 3; c++) {
    for (i = 0; i < POSEIDON2_T; i++) fr_to_words(&cases[c][i], args + FR_WORDS * i);
    poseidon2_permute(cases[c]);
    for (i = 0; i < POSEIDON2_T; i++) fr_to_words(&cases[c][i], want + FR_WORDS * i);
    ok &= kernel_case("p2perm", args, 12, want, 12);
  }
  for (c = 0; c < 9; c++) {
    args[0] = tags[c];
    for (i = 0; i < counts[c]; i++) args[1 + i] = stream[i];
    poseidon2_hash(tags[c], stream, counts[c], &digest);
    fr_to_words(&digest, want);
    ok &= kernel_case("p2hash", args, 1 + counts[c], want, FR_WORDS);
  }
  want[0] = ops[0] ^ ops[1];
  want[1] = ops[0] & ops[1];
  want[2] = (ops[0] >> ops[2]) | (ops[0] << (64u - ops[2]));
  ok &= kernel_case("ops", ops, 3, want, 3);
  for (i = 0; i < sizeof bytes; i++) bytes[i] = (uint8_t)(i * 37u + 11u);
  for (c = 0; c < 3; c++) ok &= sha512_kernel_case((const uint8_t *)sha512_texts[c], strlen(sha512_texts[c]));
  for (c = 0; c < 5; c++) ok &= sha512_kernel_case(bytes, edges[c]);
  ok &= ed25519_kernel_rows();
  remove("build/p2-kernel.wasm");
  return ok;
}

/* Evaluates the stream entry NAME of TEXT on ARGS into WORDS (at most MAX).
   Returns the word count, or -1 when the check or the eval fails. */
static int eval_words(const char *text, const char *name, char *const *args, int argc, uint64_t *words, int max) {
  Arena arena;
  Diag diag;
  Front front;
  Machine machine;
  FILE *out = tmpfile();
  FILE *err = tmpfile();
  unsigned long long w;
  int n = -1;
  arena_init(&arena, (size_t)1 << 30);
  diag_init(&diag);
  int checked = front_load(&arena, "test-hash", text, strlen(text), &front, &diag)
    && check_program(&arena, &front.decls, &machine, &diag);
  int evaluated = checked && out != NULL && err != NULL && eval_words_command(&machine, name, args, argc, out, err) == 0;
  if (!evaluated) fprintf(stderr, "FAIL hashOf %s: %s: %s\n", name, diag.code != NULL ? diag.code : "none", diag.msg);
  if (evaluated) {
    rewind(out);
    n = 0;
    while (n < max && fscanf(out, "%llu", &w) == 1)
      words[n++] = (uint64_t)w;
  }
  if (out != NULL) fclose(out);
  if (err != NULL) fclose(err);
  arena_release(&arena);
  return n;
}

/* The eval digest of the entry NAME against the C poseidon2_hash of STREAM. */
static int hash_case(const char *text, const char *name, char *const *args, int argc, uint64_t tag,
                     const uint64_t *stream, size_t count) {
  uint64_t got[FR_WORDS + 1];
  uint64_t want[FR_WORDS];
  Fr digest;
  int n = eval_words(text, name, args, argc, got, (int)FR_WORDS + 1);
  poseidon2_hash(tag, stream, count, &digest);
  fr_to_words(&digest, want);
  int ok = n == (int)FR_WORDS && memcmp(got, want, sizeof want) == 0;
  if (!ok) fprintf(stderr, "FAIL hashOf eval %s: %d words, want the C digest\n", name, n);
  return ok;
}

/* TEXT fails the check with the diagnostic CODE. */
static int hash_refused(const char *text, const char *code) {
  Arena arena;
  Diag diag;
  Front front;
  Machine machine;
  arena_init(&arena, (size_t)1 << 30);
  diag_init(&diag);
  int checked = front_load(&arena, "test-hash", text, strlen(text), &front, &diag)
    && check_program(&arena, &front.decls, &machine, &diag);
  int ok = !checked && diag.code != NULL && strcmp(diag.code, code) == 0;
  if (!ok) fprintf(stderr, "FAIL hashOf refusal: want %s, got %s (%s)\n", code, diag.code != NULL ? diag.code : "none", diag.msg);
  arena_release(&arena);
  return ok;
}

/* hashOf (Q-S4-7): the eval digest of each entry against the C poseidon2_hash
   of its stream, the pinned own vector H(1, [7], 1), the trap, and the
   check-time refusals. */
static int hash_regressions(void) {
  static const char text[] =
    "hashSeven : ℕ → Digest\n"
    "hashSeven n = hashOf 1 ℕ n\n"
    "hashCommit : Key → Digest\n"
    "hashCommit k = hashOf 2 Key k\n"
    "hashTriple : Key → ℕ → ℕ → Digest\n"
    "hashTriple k e u = hashOf 4 (Key × (ℕ × ℕ)) (pack k (pack e u))\n"
    "hashPair : Digest\n"
    "hashPair = hashOf 3 (ℕ × Bool) (pack 7 true)\n"
    "hashNode : Digest\n"
    "hashNode = hashOf 3 (Digest × Digest) (pack (hashOf 1 ℕ 7) (hashOf 1 ℕ 7))\n"
    "hashTrap : ℕ → Digest\n"
    "hashTrap n = hashOf 1 ℕ (natAdd n 1)\n";
  char *seven[] = {"7"};
  char *key[] = {"1", "2", "3", "4"};
  char *triple[] = {"1", "2", "3", "4", "5", "6"};
  char *top[] = {"18446744073709551615"};
  static const uint64_t seven_stream[1] = {7};
  static const uint64_t key_stream[4] = {1, 2, 3, 4};
  static const uint64_t triple_stream[6] = {1, 2, 3, 4, 5, 6};
  static const uint64_t pair_stream[2] = {7, 1};
  uint64_t node_stream[2 * FR_WORDS];
  uint64_t got[FR_WORDS + 1];
  Fr digest;
  int n = eval_words(text, "hashSeven", seven, 1, got, (int)FR_WORDS + 1);
  int ok = n == (int)FR_WORDS && fr_from_words(&digest, got)
    && digest_case("eval hashOf 1 ℕ 7", &digest, "0x2343a981b3acf166d0c759280df76e6b08c37ad7bd82dca197d86cff6002b1b1");
  if (n != (int)FR_WORDS) fprintf(stderr, "FAIL hashOf eval hashSeven: %d words\n", n);
  ok &= hash_case(text, "hashSeven", seven, 1, 1, seven_stream, 1);
  ok &= hash_case(text, "hashCommit", key, 4, 2, key_stream, 4);
  ok &= hash_case(text, "hashTriple", triple, 6, 4, triple_stream, 6);
  ok &= hash_case(text, "hashPair", NULL, 0, 3, pair_stream, 2);
  poseidon2_hash(1, seven_stream, 1, &digest);
  fr_to_words(&digest, node_stream);
  fr_to_words(&digest, node_stream + FR_WORDS);
  ok &= hash_case(text, "hashNode", NULL, 0, 3, node_stream, 2 * FR_WORDS);
  n = eval_words(text, "hashTrap", top, 1, got, (int)FR_WORDS + 1);
  if (n != 0) fprintf(stderr, "FAIL hashOf eval hashTrap: want trap, got %d words\n", n);
  ok &= n == 0;
  ok &= hash_refused("bad : ℕ → Digest\nbad n = hashOf 6 ℕ n\n", "TYPE_HASH_TAG");
  ok &= hash_refused("bad : ℕ → Digest\nbad n = hashOf n ℕ n\n", "TYPE_HASH_TAG");
  ok &= hash_refused("bad : Digest\nbad = hashOf 1 (ℕ → ℕ) (λ (x : ℕ) → x)\n", "TYPE_HASH");
  return ok;
}

/* The node H_3(l, r) of the test oracle. */
static void expect_node(const Fr *l, const Fr *r, Fr *out) {
  uint64_t w[2 * FR_WORDS];
  fr_to_words(l, w);
  fr_to_words(r, w + FR_WORDS);
  poseidon2_hash(3, w, 2 * FR_WORDS, out);
}

/* The Merkle root over N leaves (N at most 3), level by level (Q-S4-6): an
   odd level gets z_d, z_0 = 0, z_{d+1} = H_3(z_d, z_d), 16 levels. */
static void expect_root(const Fr *leaves, unsigned n, Fr *root) {
  static const uint64_t nothing[FR_WORDS] = {0, 0, 0, 0};
  Fr level[4];
  Fr zero;
  unsigned d;
  unsigned i;
  unsigned m = n;
  fr_from_words(&zero, nothing);
  for (i = 0; i < n; i++)
    level[i] = leaves[i];
  for (d = 0; d < 16u; d++) {
    if (m % 2u == 1u)
      level[m++] = zero;
    for (i = 0; i < m / 2u; i++)
      expect_node(&level[2u * i], &level[2u * i + 1u], &level[i]);
    m /= 2u;
    expect_node(&zero, &zero, &zero);
  }
  *root = m == 0u ? zero : level[0];
}

/* The eval root of the entry NAME against the oracle root over the N leaves
   H(1, [1]), ..., H(1, [N]). */
static int root_case(const char *text, const char *name, unsigned n) {
  uint64_t got[FR_WORDS + 1];
  uint64_t want[FR_WORDS];
  Fr leaves[3];
  Fr root;
  unsigned i;
  for (i = 0; i < n; i++) {
    uint64_t v = i + 1u;
    poseidon2_hash(1, &v, 1, &leaves[i]);
  }
  expect_root(leaves, n, &root);
  fr_to_words(&root, want);
  int k = eval_words(text, name, NULL, 0, got, (int)FR_WORDS + 1);
  int ok = k == (int)FR_WORDS && memcmp(got, want, sizeof want) == 0;
  if (!ok) fprintf(stderr, "FAIL merkleRoot eval %s: %d words, want the oracle root\n", name, k);
  return ok;
}

/* The entry NAME refuses the 4 stream words ARGS with a message that holds
   WANT. */
static int codec_refused(const char *text, const char *name, char *const *args, const char *want) {
  Arena arena;
  Diag diag;
  Front front;
  Machine machine;
  FILE *out = tmpfile();
  FILE *err = tmpfile();
  char msg[512];
  char trap[16];
  size_t got = 0;
  size_t said = 0;
  arena_init(&arena, (size_t)1 << 30);
  diag_init(&diag);
  int checked = front_load(&arena, "test-codec", text, strlen(text), &front, &diag)
    && check_program(&arena, &front.decls, &machine, &diag);
  /* A bad stream is the IR TRAP (Q-S3-8): exit 0, "trap" on OUT and the
     EVAL_WORDS reason on ERR. */
  int ran = checked && out != NULL && err != NULL
    && eval_words_command(&machine, name, args, (int)FR_WORDS, out, err) == 0;
  if (ran) {
    rewind(err);
    got = fread(msg, 1, sizeof msg - 1u, err);
    rewind(out);
    said = fread(trap, 1, sizeof trap - 1u, out);
  }
  msg[got] = '\0';
  trap[said] = '\0';
  int ok = ran && strcmp(trap, "trap\n") == 0 && strstr(msg, want) != NULL;
  if (!ok) fprintf(stderr, "FAIL Digest codec refusal: want \"%s\", got \"%s\" (%s)\n", want, msg, trap);
  if (out != NULL) fclose(out);
  if (err != NULL) fclose(err);
  arena_release(&arena);
  return ok;
}

/* merkleRoot (Q-S4-6), the domain hashes commit, prf and chainZero (Q-S4-7,
   Q-S4-9) and the Digest codec: eval against the C poseidon2_hash and the
   level-by-level oracle, the pinned z_16, a round trip, and the refusal of r
   and of 2^256 - 1. */
static int merkle_regressions(void) {
  static const char text[] =
    "leafOf : ℕ → Digest\n"
    "leafOf n = hashOf 1 ℕ n\n"
    "rootEmpty : Digest\n"
    "rootEmpty = merkleRoot (fmNil Digest)\n"
    "rootOne : Digest\n"
    "rootOne = merkleRoot (fmCons Digest (leafOf 1) (fmNil Digest))\n"
    "rootThree : Digest\n"
    "rootThree = merkleRoot (fmCons Digest (leafOf 1) (fmCons Digest (leafOf 2) (fmCons Digest (leafOf 3) (fmNil Digest))))\n"
    "commitRow : Key → Digest\n"
    "commitRow k = commit k\n"
    "prfRow : Key → ℕ → ℕ → Digest\n"
    "prfRow k e u = prf k e u\n"
    "zeroRow : Digest\n"
    "zeroRow = chainZero\n"
    "idDigest : Digest → Digest\n"
    "idDigest d = d\n";
  char *key[] = {"1", "2", "3", "4"};
  char *triple[] = {"1", "2", "3", "4", "5", "6"};
  char *modulus[] = {"4891460686036598785", "2896914383306846353", "13281191951274694749", "3486998266802970665"};
  char *top[] = {"18446744073709551615", "18446744073709551615", "18446744073709551615", "18446744073709551615"};
  static const uint64_t key_stream[4] = {1, 2, 3, 4};
  static const uint64_t triple_stream[6] = {1, 2, 3, 4, 5, 6};
  static const uint64_t empty_stream[1] = {0};
  uint64_t got[FR_WORDS + 1];
  Fr digest;
  int n = eval_words(text, "rootEmpty", NULL, 0, got, (int)FR_WORDS + 1);
  int ok = n == (int)FR_WORDS && fr_from_words(&digest, got)
    && digest_case("eval merkleRoot of the empty list = z_16", &digest, "0x073db49ea6c5659a1195472ea8f59e47b796e8c10b536d99c335f636303f6bf6");
  if (n != (int)FR_WORDS) fprintf(stderr, "FAIL merkleRoot eval rootEmpty: %d words\n", n);
  ok &= root_case(text, "rootEmpty", 0);
  ok &= root_case(text, "rootOne", 1);
  ok &= root_case(text, "rootThree", 3);
  ok &= hash_case(text, "commitRow", key, 4, 2, key_stream, 4);
  ok &= hash_case(text, "prfRow", triple, 6, 4, triple_stream, 6);
  ok &= hash_case(text, "zeroRow", NULL, 0, 1, empty_stream, 0);
  n = eval_words(text, "idDigest", key, 4, got, (int)FR_WORDS + 1);
  int trip = n == (int)FR_WORDS && memcmp(got, key_stream, sizeof key_stream) == 0;
  if (!trip) fprintf(stderr, "FAIL Digest codec round trip: %d words\n", n);
  ok &= trip;
  ok &= codec_refused(text, "idDigest", modulus, "a value at or above r");
  ok &= codec_refused(text, "idDigest", top, "a value at or above r");
  ok &= hash_refused("bad : Digest\nbad = merkleRoot (fmNil ℕ)\n", "TYPE_MISMATCH");
  return ok;
}

static int hex_digit(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Reads 2 N lower-case hex digits into N bytes, first byte first. Returns 0
 * on any other text. */
static int vector_bytes(uint8_t *out, const char *hex, size_t n) {
  size_t i;
  for (i = 0; i < 2 * n; i++) {
    int v = hex_digit(hex[i]);
    if (v < 0)
      return 0;
    if (i % 2 == 0)
      out[i / 2] = (uint8_t)(v << 4);
    else
      out[i / 2] |= (uint8_t)v;
  }
  return hex[2 * n] == '\0';
}

/* L, the order of B, low byte first (RFC 8032 5.1). */
static const char ed25519_order_hex[] = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/* SHA-512 known answers (W/S4-r4-vectors.md): the FIPS 180-4 examples "abc"
 * (one block) and the 896-bit message (the padding takes a second block), the
 * empty message, and the 896-bit message split across 2 updates. */
static int sha512_regressions(void) {
  const char *const *texts = sha512_texts;
  static const char *const digests[3] = {
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"};
  uint8_t want[SHA512_BYTES], got[SHA512_BYTES];
  Sha512 s;
  int ok = 1;
  unsigned c;
  for (c = 0; c < 3; c++) {
    sha512((const uint8_t *)texts[c], strlen(texts[c]), got);
    if (!vector_bytes(want, digests[c], SHA512_BYTES) || memcmp(want, got, SHA512_BYTES) != 0) {
      printf("FAIL sha512 vector %u\n", c);
      ok = 0;
    }
  }
  sha512_init(&s);
  sha512_update(&s, (const uint8_t *)texts[2], 100);
  sha512_update(&s, (const uint8_t *)texts[2] + 100, 12);
  sha512_final(&s, got);
  if (memcmp(want, got, SHA512_BYTES) != 0) {
    puts("FAIL sha512 split stream");
    ok = 0;
  }
  return ok;
}

/* RFC 8032 7.1 TEST 1 to 3 (W/S4-r4-vectors.md): the keys, the messages,
 * their byte counts and the signatures. */
static const char *const ed25519_keys[3] = {
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"};
static const char *const ed25519_msgs[3] = {"", "72", "af82"};
static const size_t ed25519_lens[3] = {0, 1, 2};
static const char *const ed25519_sigs[3] = {
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"};

/* Adds L to the scalar S (S below 2^256 - L, so no carry out). */
static void add_order(uint8_t s[32]) {
  uint8_t l[32];
  unsigned carry = 0;
  unsigned i;
  vector_bytes(l, ed25519_order_hex, 32);
  for (i = 0; i < 32; i++) {
    unsigned v = s[i] + l[i] + carry;
    s[i] = (uint8_t)v;
    carry = v >> 8;
  }
}

/* Ed25519 verify (RFC 8032 7.1 TEST 1 to 3, W/S4-r4-vectors.md): each
 * signature verifies; a flipped bit in R, in S or in the message fails; S + L
 * fails (the same group equation, but S is not below L); the scalar reduce
 * takes L + 5 to 5. */
static int ed25519_regressions(void) {
  const char *const *keys = ed25519_keys;
  const char *const *msgs = ed25519_msgs;
  const size_t *lens = ed25519_lens;
  const char *const *sigs = ed25519_sigs;
  uint8_t pk[32], msg[2], sig[64], bad[64], wide[64] = {0}, reduced[32], five[32];
  int ok = ed25519_constants_ok() && ed25519_constant(ED25519_CONST_BASE_Y, 0) == 0x6658
           && ed25519_constant(ED25519_CONST_SQRT_M1, 15) == 0x2b83 && ed25519_constant(ED25519_CONSTS, 0) == 0
           && ed25519_constant(ED25519_CONST_D, 16) == 0 && ed25519_order_byte(31) == 0x10
           && ed25519_order_byte(32) == 0;
  unsigned c;
  if (!ok)
    puts("FAIL ed25519 constants");
  for (c = 0; c < 3; c++) {
    if (!vector_bytes(pk, keys[c], 32) || !vector_bytes(msg, msgs[c], lens[c]) || !vector_bytes(sig, sigs[c], 64)) {
      printf("FAIL ed25519 TEST %u vector text\n", c + 1);
      ok = 0;
      continue;
    }
    if (!ed25519_verify(pk, msg, lens[c], sig)) {
      printf("FAIL ed25519 TEST %u verify\n", c + 1);
      ok = 0;
    }
    memcpy(bad, sig, 64);
    bad[0] ^= 1u;
    if (ed25519_verify(pk, msg, lens[c], bad)) {
      printf("FAIL ed25519 TEST %u flipped R verifies\n", c + 1);
      ok = 0;
    }
    memcpy(bad, sig, 64);
    bad[32] ^= 1u;
    if (ed25519_verify(pk, msg, lens[c], bad)) {
      printf("FAIL ed25519 TEST %u flipped S verifies\n", c + 1);
      ok = 0;
    }
    memcpy(bad, sig, 64);
    add_order(bad + 32);
    if (ed25519_verify(pk, msg, lens[c], bad)) {
      printf("FAIL ed25519 TEST %u S + L verifies\n", c + 1);
      ok = 0;
    }
    if (lens[c] > 0) {
      msg[0] ^= 1u;
      if (ed25519_verify(pk, msg, lens[c], sig)) {
        printf("FAIL ed25519 TEST %u flipped message verifies\n", c + 1);
        ok = 0;
      }
    }
  }
  vector_bytes(wide, ed25519_order_hex, 32);
  wide[0] += 5u;
  ed25519_scalar_reduce(reduced, wide);
  ed25519_scalar_from_u32(five, 5);
  if (memcmp(reduced, five, 32) != 0) {
    puts("FAIL ed25519 reduce of L + 5");
    ok = 0;
  }
  return ok;
}

enum { ED25519_CASE_MAX = 64 };

/* Runs ed25519 of the kernel module on the key VK, the signature SIG and
 * the N bytes of MSG (N at most ED25519_CASE_MAX); it must print WANT, and
 * the C verify must give WANT too (so a C bug cannot hide a kernel bug). */
static int ed25519_kernel_case(const uint8_t vk[32], const uint8_t sig[64], const uint8_t *msg, size_t n,
                               uint64_t want) {
  uint64_t args[13 + ED25519_CASE_MAX / 8] = {0};
  uint64_t bit = ed25519_verify(vk, msg, n, sig) != 0;
  size_t i;
  if (n > ED25519_CASE_MAX || bit != want) {
    printf("FAIL ed25519 wasm: %u bytes, C bit %u, want %u\n", (unsigned)n, (unsigned)bit, (unsigned)want);
    return 0;
  }
  args[0] = n;
  for (i = 0; i < 32; i++) args[1 + i / 8] |= (uint64_t)vk[i] << (8 * (i % 8));
  for (i = 0; i < 64; i++) args[5 + i / 8] |= (uint64_t)sig[i] << (8 * (i % 8));
  for (i = 0; i < n; i++) args[13 + i / 8] |= (uint64_t)msg[i] << (8 * (i % 8));
  return kernel_case("ed25519", args, 13 + (n + 7) / 8, &want, 1);
}

/* The Ed25519 verify kernel (S4 U5) against the C verify: RFC 8032 TEST 1
 * to 3 and the RFC 9591 E.1 signature (the vector of frost_regressions)
 * verify; on TEST 1, a flipped bit in R, in S or in the key fails, S + L
 * fails, and the encoding of p (y not below p) as A or as R fails. Three
 * keys with a torsion part verify under the cofactored check (Q-S4-14): cases
 * 4 and 5 of ed25519-speccheck (Chalkias, Garillot, Nikolaenko 2020; torsion
 * of order 2 and 4) and an own key aB + T8 (order 8, so all 3 doublings
 * count). */
static int ed25519_kernel_rows(void) {
  static const uint8_t frost_msg[4] = {0x74, 0x65, 0x73, 0x74};
  static const char *const small_keys[4] = {
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"};
  uint8_t pk[32], msg[2], sig[64], bad[64], key[32], p[32], tmsg[32];
  int ok = 1;
  unsigned c;
  for (c = 0; c < 3; c++)
    ok &= vector_bytes(pk, ed25519_keys[c], 32) && vector_bytes(msg, ed25519_msgs[c], ed25519_lens[c]) &&
          vector_bytes(sig, ed25519_sigs[c], 64) && ed25519_kernel_case(pk, sig, msg, ed25519_lens[c], 1);
  ok &= vector_bytes(key, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673", 32) &&
        vector_bytes(bad, "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b", 64) &&
        ed25519_kernel_case(key, bad, frost_msg, 4, 1);
  ok &= vector_bytes(pk, ed25519_keys[0], 32) && vector_bytes(sig, ed25519_sigs[0], 64) &&
        vector_bytes(p, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32);
  memcpy(bad, sig, 64);
  bad[0] ^= 1u;
  ok &= ed25519_kernel_case(pk, bad, msg, 0, 0);
  memcpy(bad, sig, 64);
  bad[32] ^= 1u;
  ok &= ed25519_kernel_case(pk, bad, msg, 0, 0);
  memcpy(key, pk, 32);
  key[0] ^= 1u;
  ok &= ed25519_kernel_case(key, sig, msg, 0, 0);
  memcpy(bad, sig, 64);
  add_order(bad + 32);
  ok &= ed25519_kernel_case(pk, bad, msg, 0, 0);
  ok &= ed25519_kernel_case(p, sig, msg, 0, 0);
  memcpy(bad, sig, 64);
  memcpy(bad, p, 32);
  ok &= ed25519_kernel_case(pk, bad, msg, 0, 0);
  ok &= vector_bytes(tmsg, "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", 32) &&
        vector_bytes(pk, "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", 32) &&
        vector_bytes(sig, "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09", 64) && ed25519_kernel_case(pk, sig, tmsg, 32, 1);
  ok &= vector_bytes(sig, "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405", 64) && ed25519_kernel_case(pk, sig, tmsg, 32, 1);
  ok &= vector_bytes(key, "19b8a9303bfcce8fd020dc1b3522adefe78f9531ba9dd32dc087c584b17e4f4e", 32) &&
        vector_bytes(sig, "5f2d40c0d104bdc25d24c2f06f4254688b6f0ff29c5f7ea113e90f93c9428c6914e02dd0ac228c87cd8dcea8b1af65f87d3515ae7e739bfa6b8e9fc824211b08", 64) && ed25519_kernel_case(key, sig, tmsg, 32, 1);
  /* R = identity and S = 0 forge every message under a pure torsion key
     unless the verifier rejects [8]A = identity before the equation. */
  memset(bad, 0, sizeof bad);
  bad[0] = 1;
  for (c = 0; c < 4; c++) {
    ok &= vector_bytes(key, small_keys[c], 32);
    ok &= ed25519_kernel_case(key, bad, frost_msg, 0, 0);
    ok &= ed25519_kernel_case(key, bad, frost_msg, sizeof frost_msg, 0);
  }
  if (!ok)
    puts("FAIL ed25519 wasm rows");
  return ok;
}

/* The Lagrange coefficient of participant ID at x = 0 over the N ids of IDS
 * (RFC 9591 4.2 derive_interpolating_value): the product over the other ids
 * j of j / (j - ID), mod L. */
static void lagrange_at_zero(uint8_t out[32], uint32_t id, const uint32_t *ids, size_t n) {
  uint8_t num[32], den[32], minus_id[32], xj[32], diff[32];
  size_t j;
  ed25519_scalar_from_u32(num, 1);
  ed25519_scalar_from_u32(den, 1);
  ed25519_scalar_from_u32(minus_id, id);
  ed25519_scalar_negate(minus_id, minus_id);
  for (j = 0; j < n; j++) {
    if (ids[j] == id)
      continue;
    ed25519_scalar_from_u32(xj, ids[j]);
    ed25519_scalar_mul(num, num, xj);
    ed25519_scalar_add(diff, xj, minus_id);
    ed25519_scalar_mul(den, den, diff);
  }
  ed25519_scalar_invert(den, den);
  ed25519_scalar_mul(out, num, den);
}

/* RFC 9591 Appendix E.1, FROST(Ed25519, SHA-512), participants 1 and 3 of 3,
 * threshold 2 (W/S4-r4-vectors.md): the signature on "test" verifies as an
 * RFC 8032 signature (6.1: H2 has no context prefix) and a flipped bit fails;
 * the (1.3) oracle: the Lagrange combination at x = 0 of shares 1 and 3 is the
 * group secret key sk, and [sk]B encodes to the group public key. */
static int frost_regressions(void) {
  static const char *const shares[2] = {
    "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
    "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"};
  static const uint32_t ids[2] = {1, 3};
  static const uint8_t msg[4] = {0x74, 0x65, 0x73, 0x74};
  uint8_t sk[32], pk[32], sig[64], share[32], lambda[32], term[32], sum[32] = {0}, enc[32];
  int ok = vector_bytes(sk, "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304", 32) &&
           vector_bytes(pk, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673", 32) &&
           vector_bytes(sig, "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b", 64);
  size_t i;
  if (!ok) {
    puts("FAIL frost vector text");
    return 0;
  }
  if (!ed25519_verify(pk, msg, 4, sig)) {
    puts("FAIL frost E.1 signature");
    ok = 0;
  }
  sig[40] ^= 1u;
  if (ed25519_verify(pk, msg, 4, sig)) {
    puts("FAIL frost flipped signature verifies");
    ok = 0;
  }
  for (i = 0; i < 2; i++) {
    if (!vector_bytes(share, shares[i], 32)) {
      puts("FAIL frost share text");
      return 0;
    }
    lagrange_at_zero(lambda, ids[i], ids, 2);
    ed25519_scalar_mul(term, lambda, share);
    ed25519_scalar_add(sum, sum, term);
  }
  if (memcmp(sum, sk, 32) != 0) {
    puts("FAIL frost (1.3) Lagrange combination is not sk");
    ok = 0;
  }
  ed25519_base_mul(enc, sum);
  if (memcmp(enc, pk, 32) != 0) {
    puts("FAIL frost (1.3) [sk]B is not the group public key");
    ok = 0;
  }
  return ok;
}

int main(void) {
  int ok = 1;
  int hashed = poseidon2_regressions();
  if (hashed) puts("poseidon2 regressions: passed");
  ok &= hashed;
  int kernel = kernel_regressions();
  if (kernel) puts("poseidon2 wasm regressions: passed");
  ok &= kernel;
  ok &= warning_fix("-- keep this comment\nid : Nat -> Nat\nid x = x\n");
  ok &= warning_fix("id : ℕ → ℕ\nid x = x\nnext : Nat\nnext = 1\n");
  ok &= warning_fix("value : ℕ\nvalue = 1");
  ok &= warning_fix("value : ℕ\nvalue = 1\n\n-- tail   ");
  ok &= warning_fix("value : ℕ\nvalue = 1 -- inline\n");
  ok &= warning_fix(" \n\t");
  ok &= runtime_ind_effect();
  ok &= stream_regressions();
  int hash_eval = hash_regressions();
  if (hash_eval) puts("hashOf eval regressions: passed");
  ok &= hash_eval;
  int merkle_eval = merkle_regressions();
  if (merkle_eval) puts("merkleRoot eval regressions: passed");
  ok &= merkle_eval;
  int sha = sha512_regressions();
  if (sha) puts("sha512 regressions: passed");
  ok &= sha;
  int ed = ed25519_regressions();
  if (ed) puts("ed25519 regressions: passed");
  ok &= ed;
  int frost = frost_regressions();
  if (frost) puts("frost regressions: passed");
  ok &= frost;
  if (ok) puts("warning fix regressions: passed");
  return ok ? 0 : 1;
}
