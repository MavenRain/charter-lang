/* Exercise the check command's warning fixes through the parser and printer. */
#include <stdlib.h>
#include <string.h>

#include "front/ed25519.h"
#include "front/poseidon2.h"
#include "front/sha512.h"
#include "front/squash.h"
#include "front/tdec.h"
#include "front/tfhe.h"
#include "front/tkeygen.h"
#include "front/tshare.h"
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

/* The number of bits of X (0 for 0). */
static unsigned top_bit(uint64_t x) {
  unsigned bits = 0;
  while (x != 0) {
    bits++;
    x >>= 1;
  }
  return bits;
}

/* Each TUniform(b) value stays in [-2^b, 2^b]. */
static int tfhe_tuniform_rows(TfheDrbg *d) {
  static const unsigned bounds[3] = {1, 17, 45};
  unsigned c, i;
  for (c = 0; c < 3; c++) {
    int64_t limit = (int64_t)1 << bounds[c];
    for (i = 0; i < 4096; i++) {
      int64_t v = (int64_t)tfhe_tuniform(d, bounds[c]);
      if (v < -limit || v > limit) {
        printf("FAIL tfhe tuniform %u\n", bounds[c]);
        return 0;
      }
    }
  }
  return 1;
}

/* The bound on |FFT - schoolbook| for a digit product of the PBS shape. */
enum { TFHE_FFT_BOUND_BITS = 50 };

/* The FFT product against the exact schoolbook product mod 2^64: equal for
 * small inputs (|a|, |b| <= 2^10) and for a key product (64-bit a, the 0 or 1
 * GLWE key); within 2^50 for the PBS shape (|digit| <= 2^22, 64-bit b). */
static int tfhe_fft_rows(const TfheFft *f, const TfheKeys *k, TfheDrbg *d) {
  uint64_t a[TFHE_POLY_N], b[TFHE_POLY_N], want[TFHE_POLY_N], got[TFHE_POLY_N], worst = 0;
  unsigned j;
  int ok = 1;
  for (j = 0; j < TFHE_POLY_N; j++) {
    a[j] = tfhe_tuniform(d, 10);
    b[j] = tfhe_tuniform(d, 10);
  }
  tfhe_poly_mul_exact(want, a, b);
  tfhe_poly_mul_fft(f, got, a, b);
  if (memcmp(want, got, sizeof want) != 0) {
    puts("FAIL tfhe fft small product");
    ok = 0;
  }
  for (j = 0; j < TFHE_POLY_N; j++) {
    a[j] = tfhe_tuniform(d, 22);
    b[j] = tfhe_uniform(d);
  }
  tfhe_poly_mul_exact(want, a, b);
  tfhe_poly_mul_fft(f, got, a, b);
  for (j = 0; j < TFHE_POLY_N; j++) {
    uint64_t e = got[j] - want[j];
    if (e >> 63) e = 0u - e;
    if (e > worst) worst = e;
  }
  printf("tfhe fft digit product: max error below 2^%u (bound 2^%u)\n", top_bit(worst), TFHE_FFT_BOUND_BITS);
  if (top_bit(worst) > TFHE_FFT_BOUND_BITS) {
    puts("FAIL tfhe fft digit product");
    ok = 0;
  }
  for (j = 0; j < TFHE_POLY_N; j++) a[j] = tfhe_uniform(d);
  tfhe_poly_mul_exact(want, a, k->glwe_key);
  tfhe_poly_mul_key(f, got, a, &k->glwe_key_fourier);
  if (memcmp(want, got, sizeof want) != 0) {
    puts("FAIL tfhe fft key product");
    ok = 0;
  }
  return ok;
}

/* The KS round trip, then decrypt(PBS(Enc m)) = LUT(m) for all 16 inputs
 * under the identity LUT and m -> 7m + 3 mod 16. Then the box edges under the
 * identity LUT: a trivial input (mask 0) has no noise, so its switched phase
 * is the 2N bin t of its body. Box m holds the bins 128m - 64 to 128m + 63,
 * so at each inner edge (m = 1 to 15) the bin centers t = 128m - 65 and
 * t = 128m - 64 give m - 1 and m. A LUT rotation off by one moves each edge
 * by one bin. */
static int tfhe_pbs_rows(const TfheFft *f, const TfheKeys *k, TfheDrbg *d) {
  uint64_t lut[TFHE_POLY_N], in[TFHE_BIG_N + 1], out[TFHE_BIG_N + 1], small[TFHE_LWE_N + 1];
  uint8_t tables[2][TFHE_PLAIN];
  unsigned m, c, e, got;
  int ok = 1;
  for (m = 0; m < TFHE_PLAIN; m++) {
    tables[0][m] = (uint8_t)m;
    tables[1][m] = (uint8_t)((7u * m + 3u) % TFHE_PLAIN);
  }
  for (m = 0; m < TFHE_PLAIN; m++) {
    tfhe_lwe_encrypt(in, k->glwe_key, TFHE_BIG_N, tfhe_encode(m), TFHE_GLWE_NOISE, d);
    tfhe_keyswitch(small, in, k->ksk);
    got = tfhe_decode(tfhe_lwe_phase(small, k->lwe_key, TFHE_LWE_N));
    if (got != m) {
      printf("FAIL tfhe ks %u: %u\n", m, got);
      ok = 0;
    }
  }
  for (c = 0; c < 2; c++) {
    tfhe_lut(lut, tables[c]);
    for (m = 0; m < TFHE_PLAIN; m++) {
      tfhe_lwe_encrypt(in, k->glwe_key, TFHE_BIG_N, tfhe_encode(m), TFHE_GLWE_NOISE, d);
      tfhe_pbs(f, out, in, k, lut);
      got = tfhe_decode(tfhe_lwe_phase(out, k->glwe_key, TFHE_BIG_N));
      if (got != tables[c][m]) {
        printf("FAIL tfhe pbs lut %u input %u: %u\n", c, m, got);
        ok = 0;
      }
    }
  }
  tfhe_lut(lut, tables[0]);
  for (m = 1; m < TFHE_PLAIN; m++) {
    for (e = 0; e < 2; e++) {
      uint64_t bin = (uint64_t)(TFHE_BOX * m - 65u + e);
      memset(in, 0, sizeof in);
      in[TFHE_BIG_N] = (bin << (64 - TFHE_LOG_2N)) | ((uint64_t)1 << (63 - TFHE_LOG_2N));
      tfhe_pbs(f, out, in, k, lut);
      got = tfhe_decode(tfhe_lwe_phase(out, k->glwe_key, TFHE_BIG_N));
      if (got != tables[0][m - 1u + e]) {
        printf("FAIL tfhe pbs edge bin %u: %u\n", (unsigned)bin, got);
        ok = 0;
      }
    }
  }
  return ok;
}

/* S5 U1 rows: the keys come from a fixed seed. */
/* Writes the TFHE kernel test module of src/wasm.c to PATH. */
static int tfhe_wasm_write(const char *path) {
  FILE *module = fopen(path, "wb");
  int ok = module != NULL && wasm_write_tfhe_test(module, stderr);
  return module != NULL && fclose(module) == 0 && ok;
}

static void put_words(FILE *out, const uint64_t *w, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) fprintf(out, " %llu", (unsigned long long)w[i]);
}

/* Reads N words into W; 0 when a word is missing (a trap prints `trap`). */
static int read_words(FILE *in, uint64_t *w, size_t n) {
  unsigned long long v;
  size_t i;
  int ok = 1;
  for (i = 0; i < n && ok; i++) {
    ok = fscanf(in, "%llu", &v) == 1;
    w[i] = ok ? (uint64_t)v : 0;
  }
  return ok;
}

/* 1 when GOT = WANT; else a FAIL line names ROW and the first other word. */
static int words_equal(const char *row, const uint64_t *got, const uint64_t *want, size_t n) {
  size_t i = 0;
  while (i < n && got[i] == want[i]) i++;
  if (i < n)
    printf("FAIL tfhe wasm %s: word %u is %llu, want %llu\n", row, (unsigned)i, (unsigned long long)got[i],
           (unsigned long long)want[i]);
  return i == n;
}

/* The re bits, then the im bits of X. */
static void fourier_bits(const TfheFourier *x, uint64_t bits[TFHE_POLY_N]) {
  memcpy(bits, x->re, sizeof x->re);
  memcpy(bits + TFHE_FFT_M, x->im, sizeof x->im);
}

/* The TFHE kernel test module against the C kernels, word for word: the
   forward FFT of A, the backward FFT of P = fft(A) x fft(B) into zeros, and
   tfhe_poly_mul_fft (A, B). A is uniform; B has digits in [-2^22, 2^22) (the
   PBS shape: the product takes the mod 2^64 branch of torus_from_double). */
static int tfhe_wasm_rows(const TfheFft *f, TfheDrbg *d) {
  static const char *const rows[3] = {"forward", "backward", "product"};
  uint64_t a[TFHE_POLY_N], b[TFHE_POLY_N], p[TFHE_POLY_N], want[3][TFHE_POLY_N], got[TFHE_POLY_N];
  TfheFourier fa, fb, acc;
  FILE *in;
  FILE *out = NULL;
  unsigned i;
  int ok = tfhe_wasm_write("build/tfhe-kernel.wasm");
  for (i = 0; i < TFHE_POLY_N; i++) a[i] = tfhe_uniform(d);
  for (i = 0; i < TFHE_POLY_N; i++) b[i] = (tfhe_uniform(d) & (((uint64_t)1 << 23) - 1u)) - ((uint64_t)1 << 22);
  tfhe_fft_forward(f, &fa, a);
  tfhe_fft_forward(f, &fb, b);
  memset(&acc, 0, sizeof acc);
  tfhe_fourier_mul_add(&acc, &fa, fb.re, fb.im);
  fourier_bits(&fa, want[0]);
  fourier_bits(&acc, p);
  memset(want[1], 0, sizeof want[1]);
  tfhe_fft_backward_add(f, want[1], &acc);
  tfhe_poly_mul_fft(f, want[2], a, b);
  in = fopen("build/tfhe-in.txt", "w");
  if (in != NULL) {
    fputs("fft", in);
    put_words(in, a, TFHE_POLY_N);
    fputs("\nifft", in);
    put_words(in, p, TFHE_POLY_N);
    fputs("\npolymul", in);
    put_words(in, a, TFHE_POLY_N);
    put_words(in, b, TFHE_POLY_N);
    fputs("\n", in);
  }
  ok = ok && in != NULL && fclose(in) == 0 &&
       system("node test/run-wasm.mjs --words build/tfhe-kernel.wasm - <build/tfhe-in.txt >build/tfhe-out.txt 2>&1") == 0;
  if (ok) out = fopen("build/tfhe-out.txt", "r");
  if (!ok || out == NULL) puts("FAIL tfhe wasm: the module, the input or node failed (build/tfhe-out.txt)");
  ok = ok && out != NULL;
  for (i = 0; i < 3 && ok; i++) {
    ok = read_words(out, got, TFHE_POLY_N);
    if (!ok) printf("FAIL tfhe wasm %s: fewer than %u words (build/tfhe-out.txt)\n", rows[i], (unsigned)TFHE_POLY_N);
    ok = ok && words_equal(rows[i], got, want[i], TFHE_POLY_N);
  }
  if (out != NULL) fclose(out);
  if (ok) {
    puts("tfhe wasm fft: C = Wasm words (forward 2048, backward 2048, product 2048)");
    remove("build/tfhe-kernel.wasm");
    remove("build/tfhe-in.txt");
    remove("build/tfhe-out.txt");
  }
  return ok;
}

/* Writes the N 8-byte words at W (uint64_t words, or the bits of doubles)
   to PATH, each low byte first (the order of the Wasm memory), through a 64
   KiB buffer. */
static int key_write(const char *path, const void *w, size_t n) {
  static unsigned char buf[65536];
  const unsigned char *src = w;
  FILE *out = fopen(path, "wb");
  uint64_t x;
  size_t i, j, k, c;
  int ok = out != NULL;
  for (i = 0; i < n && ok; i += c) {
    c = n - i < sizeof buf / 8u ? n - i : sizeof buf / 8u;
    for (j = 0; j < c; j++) {
      memcpy(&x, src + 8u * (i + j), sizeof x);
      for (k = 0; k < 8u; k++) buf[8u * j + k] = (unsigned char)(x >> (8u * k));
    }
    ok = fwrite(buf, 8u, c, out) == c;
  }
  return out != NULL && fclose(out) == 0 && ok;
}

/* S5 O4: the PBS time budget in ms, ceil (1.5 x the median) of the first
   clean run (r2e). The checktool prints the median and the budget and does
   not FAIL on the time (PLAN O4 takes the budget at the S5 close). The
   median is over TFHE_PBS_TIMED pbs calls after one warm-up call. */
enum { TFHE_PBS_BUDGET_MS = 138, TFHE_PBS_TIMED = 9 };

/* The median of the N (odd) values of T; sorts T (an insertion sort). */
static double median_of(double *t, size_t n) {
  size_t i, j;
  double x;
  for (i = 1; i < n; i++) {
    x = t[i];
    for (j = i; j > 0 && t[j - 1] > x; j--) t[j] = t[j - 1];
    t[j] = x;
  }
  return t[n / 2];
}

/* Reads the `--time` lines of run-wasm.mjs at PATH: the host line, then
   SKIP + N times. The N times after the first SKIP go to T. */
static int time_read(const char *path, char arch[32], char node[32], size_t skip, double *t, size_t n) {
  FILE *in = fopen(path, "r");
  double x;
  size_t i;
  int ok = in != NULL && fscanf(in, "host %31s node %31s", arch, node) == 2;
  for (i = 0; i < skip + n && ok; i++) {
    ok = fscanf(in, " time %lf", &x) == 1;
    if (ok && i >= skip) t[i - skip] = x;
  }
  if (in != NULL) fclose(in);
  return ok;
}

/* S5 U3b: the node command of the Wasm TFHE rows. The `--load` offsets come
   from WASM_TFHE_KSK (the BSK follows the KSK words). */
static const char *tfhe_node_cmd(char *cmd, size_t size, int timed, const char *in, const char *out) {
  snprintf(cmd, size,
           "node test/run-wasm.mjs %s--load %lu build/tfhe-ksk.bin --load %lu build/tfhe-bsk.bin "
           "--words build/tfhe-kernel.wasm - <%s >%s%s",
           timed ? "--time " : "", (unsigned long)WASM_TFHE_KSK,
           (unsigned long)WASM_TFHE_KSK + 8ul * (unsigned long)TFHE_KSK_WORDS, in, out,
           timed ? " 2>build/tfhe-time.txt" : "");
  return cmd;
}

/* S5 U2b rows: the PBS kernels of the module against the C kernels, word
   for word, on one encryption of m = 6 under the identity LUT. Each stage
   has its own entry, so a FAIL line names the first stage that differs;
   the Wasm pbs decrypts to LUT (m) = 6. The keys go to the module memory
   through build/tfhe-ksk.bin (at WASM_TFHE_KSK) and build/tfhe-bsk.bin
   (the bits of the BSK doubles, at TFHE_BSK); the checktool removes both
   after the node call. The same call (`--time`, stderr into
   build/tfhe-time.txt) runs TFHE_PBS_TIMED more pbs lines: the first pbs
   line is the warm-up (S5 O4). */
static int tfhe_pbs_wasm_rows(const TfheFft *f, const TfheKeys *k, TfheDrbg *d) {
  static const char *const rows[5] = {"ks", "ms", "se", "br", "pbs"};
  static const size_t counts[5] = {TFHE_LWE_N + 1, TFHE_LWE_N + 1, TFHE_BIG_N + 1, 2 * TFHE_POLY_N, TFHE_BIG_N + 1};
  uint64_t ct[TFHE_BIG_N + 1], small[TFHE_LWE_N + 1], switched[TFHE_LWE_N + 1], lut[TFHE_POLY_N];
  uint64_t acc[2 * TFHE_POLY_N], extracted[TFHE_BIG_N + 1], pbs[TFHE_BIG_N + 1], got[2 * TFHE_POLY_N];
  const uint64_t *const want[5] = {small, switched, extracted, acc, pbs};
  uint8_t table[TFHE_PLAIN];
  double times[TFHE_PBS_TIMED];
  char arch[32], node[32], cmd[512];
  FILE *in;
  FILE *out = NULL;
  unsigned i, passed = 0;
  int ok;
  for (i = 0; i < TFHE_PLAIN; i++) table[i] = (uint8_t)i;
  tfhe_lut(lut, table);
  tfhe_lwe_encrypt(ct, k->glwe_key, TFHE_BIG_N, tfhe_encode(6), TFHE_GLWE_NOISE, d);
  tfhe_keyswitch(small, ct, k->ksk);
  tfhe_modulus_switch(switched, small);
  tfhe_blind_rotate(f, acc, switched, lut, k->bsk_fourier);
  tfhe_sample_extract(extracted, acc);
  tfhe_pbs(f, pbs, ct, k, lut);
  ok = tfhe_wasm_write("build/tfhe-kernel.wasm") && key_write("build/tfhe-ksk.bin", k->ksk, TFHE_KSK_WORDS) &&
       key_write("build/tfhe-bsk.bin", k->bsk_fourier, TFHE_BSK_FOURIER_DOUBLES);
  in = fopen("build/tfhe-pbs-in.txt", "w");
  if (in != NULL) {
    fputs("ks", in);
    put_words(in, ct, TFHE_BIG_N + 1);
    fputs("\nms", in);
    put_words(in, small, TFHE_LWE_N + 1);
    fputs("\nse", in);
    put_words(in, acc, 2 * TFHE_POLY_N);
    fputs("\nbr", in);
    put_words(in, switched, TFHE_LWE_N + 1);
    put_words(in, lut, TFHE_POLY_N);
    for (i = 0; i <= TFHE_PBS_TIMED; i++) {
      fputs("\npbs", in);
      put_words(in, ct, TFHE_BIG_N + 1);
      put_words(in, lut, TFHE_POLY_N);
    }
    fputs("\n", in);
  }
  ok = in != NULL && fclose(in) == 0 && ok &&
       system(tfhe_node_cmd(cmd, sizeof cmd, 1, "build/tfhe-pbs-in.txt", "build/tfhe-pbs-out.txt")) == 0;
  remove("build/tfhe-ksk.bin");
  remove("build/tfhe-bsk.bin");
  if (ok) out = fopen("build/tfhe-pbs-out.txt", "r");
  if (!ok || out == NULL)
    puts("FAIL tfhe wasm ks: the module, a key file, the input or node failed (build/tfhe-pbs-out.txt, "
         "build/tfhe-time.txt)");
  ok = ok && out != NULL;
  for (i = 0; i < 5 && ok; i++) {
    ok = read_words(out, got, counts[i]);
    if (!ok) printf("FAIL tfhe wasm %s: fewer than %u words (build/tfhe-pbs-out.txt)\n", rows[i], (unsigned)counts[i]);
    ok = ok && words_equal(rows[i], got, want[i], counts[i]);
    passed += (unsigned)ok;
  }
  if (out != NULL) fclose(out);
  if (ok && tfhe_decode(tfhe_lwe_phase(got, k->glwe_key, TFHE_BIG_N)) != 6) {
    puts("FAIL tfhe wasm pbs: the Wasm pbs output does not decrypt to LUT (6) = 6");
    ok = 0;
  }
  if (passed >= 3) puts("tfhe wasm ks: C = Wasm words (ks 919, ms 919, se 2049)");
  if (ok) puts("tfhe wasm pbs: C = Wasm words (br 4096, pbs 2049), decrypt = LUT(m)");
  if (ok && !time_read("build/tfhe-time.txt", arch, node, 5, times, TFHE_PBS_TIMED)) {
    puts("FAIL tfhe wasm pbs time: fewer time lines than calls (build/tfhe-time.txt)");
    ok = 0;
  }
  if (ok) {
    printf("pbs: %.1f ms (budget %u ms)\npbs host: %s, node %s\n", median_of(times, TFHE_PBS_TIMED),
           (unsigned)TFHE_PBS_BUDGET_MS, arch, node);
    remove("build/tfhe-kernel.wasm");
    remove("build/tfhe-pbs-in.txt");
    remove("build/tfhe-pbs-out.txt");
    remove("build/tfhe-time.txt");
  }
  return ok;
}

/* S5 U3a rows: the radix layer in C, after the U1 and U2 rows, so their DRBG
   stream does not change. The inputs are tfhe_drbg_bytes (D, 8) in row order.
   A trivial row (level 0) makes real PBS calls (0.1 ms each) and checks each
   output word: mask 0, body = digit i Delta. An encrypted row (fresh blocks)
   checks the value and that each block is clean. */
enum { RADIX_ADD_ROWS = 12, RADIX_LE_ROWS = 14, RADIX_SUM_ROWS = 10, RADIX_MUL_ROWS = 6 };

static TfheRadix radix_in[7], radix_out, radix_want;

/* 1 when GOT is the trivial radix of WANT, word by word. */
static int radix_exact(const char *op, unsigned row, const TfheRadix *got, uint64_t want, const TfheKeys *k) {
  tfhe_radix_trivial(&radix_want, want);
  if (memcmp(got, &radix_want, sizeof radix_want) == 0) return 1;
  printf("FAIL tfhe radix trivial %s row %u: words differ (value %016llx, want %016llx)\n", op, row,
         (unsigned long long)tfhe_radix_decrypt(got, k), (unsigned long long)want);
  return 0;
}

/* 1 when the le output GOT is the trivial block of WANT, word by word. */
static int le_exact(unsigned row, const uint64_t got[TFHE_BLOCK_WORDS], unsigned want, const TfheKeys *k) {
  tfhe_radix_trivial(&radix_want, want);
  if (memcmp(got, radix_want.block[0], sizeof radix_want.block[0]) == 0) return 1;
  printf("FAIL tfhe radix trivial le row %u: words differ (value %u, want %u)\n", row,
         tfhe_decode(tfhe_lwe_phase(got, k->glwe_key, TFHE_BIG_N)), want);
  return 0;
}

/* 1 when GOT decrypts to WANT and each block is clean (its decode is digit i). */
static int radix_clean(const char *op, const TfheRadix *got, uint64_t want, const TfheKeys *k) {
  uint64_t value = tfhe_radix_decrypt(got, k);
  unsigned i, dirty = 0;
  for (i = 0; i < TFHE_RADIX_BLOCKS; i++) {
    dirty += tfhe_decode(tfhe_lwe_phase(got->block[i], k->glwe_key, TFHE_BIG_N)) != ((want >> (2u * i)) & 3u);
  }
  if (value == want && dirty == 0) return 1;
  printf("FAIL tfhe radix encrypted %s: %016llx, want %016llx, %u blocks not clean\n", op, (unsigned long long)value,
         (unsigned long long)want, dirty);
  return 0;
}

/* (2^64 - 1, 1) is the full carry chain. Then 8 DRBG pairs. */
static int radix_add_rows(const TfheFft *f, const TfheKeys *k, const TfheRadixLuts *l, TfheDrbg *d) {
  uint64_t x[RADIX_ADD_ROWS] = {0, UINT64_MAX, UINT64_MAX, UINT64_C(0x5555555555555555)};
  uint64_t y[RADIX_ADD_ROWS] = {0, 1, UINT64_MAX, UINT64_C(0xAAAAAAAAAAAAAAAA)};
  unsigned i;
  int ok = 1;
  for (i = 4; i < RADIX_ADD_ROWS; i++) {
    x[i] = tfhe_drbg_bytes(d, 8);
    y[i] = tfhe_drbg_bytes(d, 8);
  }
  for (i = 0; i < RADIX_ADD_ROWS; i++) {
    tfhe_radix_trivial(&radix_in[0], x[i]);
    tfhe_radix_trivial(&radix_in[1], y[i]);
    tfhe_radix_add(f, &radix_out, &radix_in[0], &radix_in[1], k, l);
    ok &= radix_exact("add", i, &radix_out, x[i] + y[i], k);
  }
  return ok;
}

/* X0 has the low digit 3, so X0 + 1 carries out of block 0: in the row
   (X0 + 1, X0), the highest block that differs is GT and block 0 is LT (a
   MERGE with the low block first fails it). Then 8 DRBG pairs. */
static int radix_le_rows(const TfheFft *f, const TfheKeys *k, const TfheRadixLuts *l, TfheDrbg *d) {
  const uint64_t x0 = tfhe_drbg_bytes(d, 8) | 3u;
  uint64_t x[RADIX_LE_ROWS] = {0, 0, UINT64_MAX, x0, x0, x0 + 1u};
  uint64_t y[RADIX_LE_ROWS] = {0, UINT64_MAX, 0, x0, x0 + 1u, x0};
  uint64_t out[TFHE_BLOCK_WORDS];
  unsigned i;
  int ok = 1;
  for (i = 6; i < RADIX_LE_ROWS; i++) {
    x[i] = tfhe_drbg_bytes(d, 8);
    y[i] = tfhe_drbg_bytes(d, 8);
  }
  for (i = 0; i < RADIX_LE_ROWS; i++) {
    tfhe_radix_trivial(&radix_in[0], x[i]);
    tfhe_radix_trivial(&radix_in[1], y[i]);
    tfhe_radix_le(f, out, &radix_in[0], &radix_in[1], k, l);
    ok &= le_exact(i, out, x[i] <= y[i], k);
  }
  return ok;
}

/* N = 1, 2, 4, 5 and 7 terms of 2^64 - 1, then of DRBG values. */
static int radix_sum_rows(const TfheFft *f, const TfheKeys *k, const TfheRadixLuts *l, TfheDrbg *d) {
  static const unsigned terms[5] = {1, 2, 4, 5, 7};
  uint64_t v, want;
  unsigned r, j;
  int ok = 1;
  for (r = 0; r < RADIX_SUM_ROWS; r++) {
    want = 0;
    for (j = 0; j < terms[r % 5u]; j++) {
      v = r < 5u ? UINT64_MAX : tfhe_drbg_bytes(d, 8);
      want += v;
      tfhe_radix_trivial(&radix_in[j], v);
    }
    tfhe_radix_sum(f, &radix_out, radix_in, terms[r % 5u], k, l);
    ok &= radix_exact("sum", r, &radix_out, want, k);
  }
  return ok;
}

/* A trivial BIT of 0 and of 1, A = 0, 2^64 - 1 and a DRBG value. */
static int radix_mul_rows(const TfheKeys *k, TfheDrbg *d) {
  const uint64_t a[3] = {0, UINT64_MAX, tfhe_drbg_bytes(d, 8)};
  uint64_t bit[TFHE_BLOCK_WORDS];
  unsigned r;
  int ok = 1;
  for (r = 0; r < RADIX_MUL_ROWS; r++) {
    memset(bit, 0, sizeof bit);
    bit[TFHE_BIG_N] = tfhe_encode(r / 3u);
    tfhe_radix_scalar_mul(&radix_out, bit, a[r % 3u]);
    ok &= radix_exact("scalar_mul", r, &radix_out, a[r % 3u] * (r / 3u), k);
  }
  return ok;
}

/* scalar_mul (Enc 0, a) and (Enc 1, a) (0 PBS); the sum of 4 DRBG values (63
   PBS, the carry-in at level 5); le (x, y) with the high 16 blocks of y =
   those of x (63 PBS: MERGE with h = EQ, then with h = LT or GT). */
static int radix_encrypted_rows(const TfheFft *f, const TfheKeys *k, const TfheRadixLuts *l, TfheDrbg *d) {
  uint64_t bit[TFHE_BLOCK_WORDS], out[TFHE_BLOCK_WORDS], a, x, y, want = 0;
  unsigned b, j, got;
  int ok = 1;
  a = tfhe_drbg_bytes(d, 8);
  for (b = 0; b < 2; b++) {
    tfhe_lwe_encrypt(bit, k->glwe_key, TFHE_BIG_N, tfhe_encode(b), TFHE_GLWE_NOISE, d);
    tfhe_radix_scalar_mul(&radix_out, bit, a);
    ok &= radix_clean("scalar_mul", &radix_out, a * b, k);
  }
  for (j = 0; j < 4; j++) {
    x = tfhe_drbg_bytes(d, 8);
    want += x;
    tfhe_radix_encrypt(&radix_in[j], k, x, d);
  }
  tfhe_radix_sum(f, &radix_out, radix_in, 4, k, l);
  ok &= radix_clean("sum4", &radix_out, want, k);
  x = tfhe_drbg_bytes(d, 8);
  y = (x & ~UINT64_C(0xFFFFFFFF)) | (tfhe_drbg_bytes(d, 8) & UINT64_C(0xFFFFFFFF));
  tfhe_radix_encrypt(&radix_in[0], k, x, d);
  tfhe_radix_encrypt(&radix_in[1], k, y, d);
  tfhe_radix_le(f, out, &radix_in[0], &radix_in[1], k, l);
  got = tfhe_decode(tfhe_lwe_phase(out, k->glwe_key, TFHE_BIG_N));
  if (got != (unsigned)(x <= y)) {
    printf("FAIL tfhe radix encrypted le: %u, want %u\n", got, (unsigned)(x <= y));
    ok = 0;
  }
  return ok;
}

/* S5 U3b rows: the radix kernels of the module against the C radix
   functions, word for word (one node call, the keys through `--load`), and
   each Wasm output against its value (so a mutant of C and Wasm together
   also fails here). The encrypted rows are those of radix_encrypted_rows
   (new DRBG values); the trivial rows are (2^64 - 1, 1), le (x0 + 1, x0)
   with the low digit of x0 = 3, and 5 x (2^64 - 1) (a propagation at term 3
   and at the last term). */
enum { RADIX_WORDS = TFHE_RADIX_BLOCKS * TFHE_BLOCK_WORDS, RADIX_WASM_ROWS = 7 };

static TfheRadix radix_wasm_want[RADIX_WASM_ROWS], radix_got;

/* One input line: NAME, then the N radixes at XS. */
static void radix_put(FILE *in, const char *name, const TfheRadix *xs, unsigned n) {
  fputs(name, in);
  put_words(in, (const uint64_t *)xs, (size_t)n * RADIX_WORDS);
  fputs("\n", in);
}

static void radix_wasm_input(FILE *in, const TfheFft *f, const TfheKeys *k, const TfheRadixLuts *l, TfheDrbg *d,
                             uint64_t value[RADIX_WASM_ROWS]) {
  uint64_t bit[TFHE_BLOCK_WORDS], a = tfhe_drbg_bytes(d, 8), x, y;
  const uint64_t x0 = tfhe_drbg_bytes(d, 8) | 3u;
  unsigned r, j;
  for (r = 0; r < 2; r++) {
    tfhe_lwe_encrypt(bit, k->glwe_key, TFHE_BIG_N, tfhe_encode(r), TFHE_GLWE_NOISE, d);
    tfhe_radix_scalar_mul(&radix_wasm_want[r], bit, a);
    value[r] = a * r;
    fputs("rmul", in);
    put_words(in, bit, TFHE_BLOCK_WORDS);
    put_words(in, &a, 1);
    fputs("\n", in);
  }
  value[2] = 0;
  for (j = 0; j < 4; j++) {
    x = tfhe_drbg_bytes(d, 8);
    value[2] += x;
    tfhe_radix_encrypt(&radix_in[j], k, x, d);
  }
  tfhe_radix_sum(f, &radix_wasm_want[2], radix_in, 4, k, l);
  radix_put(in, "rsum4", radix_in, 4);
  x = tfhe_drbg_bytes(d, 8);
  y = (x & ~UINT64_C(0xFFFFFFFF)) | (tfhe_drbg_bytes(d, 8) & UINT64_C(0xFFFFFFFF));
  tfhe_radix_encrypt(&radix_in[0], k, x, d);
  tfhe_radix_encrypt(&radix_in[1], k, y, d);
  tfhe_radix_le(f, radix_wasm_want[3].block[0], &radix_in[0], &radix_in[1], k, l);
  value[3] = x <= y;
  radix_put(in, "rle", radix_in, 2);
  tfhe_radix_trivial(&radix_in[0], UINT64_MAX);
  tfhe_radix_trivial(&radix_in[1], 1);
  tfhe_radix_add(f, &radix_wasm_want[4], &radix_in[0], &radix_in[1], k, l);
  value[4] = 0;
  radix_put(in, "radd", radix_in, 2);
  tfhe_radix_trivial(&radix_in[0], x0 + 1u);
  tfhe_radix_trivial(&radix_in[1], x0);
  tfhe_radix_le(f, radix_wasm_want[5].block[0], &radix_in[0], &radix_in[1], k, l);
  value[5] = x0 + 1u <= x0;
  radix_put(in, "rle", radix_in, 2);
  for (j = 0; j < 5; j++) tfhe_radix_trivial(&radix_in[j], UINT64_MAX);
  tfhe_radix_sum(f, &radix_wasm_want[6], radix_in, 5, k, l);
  value[6] = UINT64_MAX * 5u;
  radix_put(in, "rsum5", radix_in, 5);
}

static int tfhe_radix_wasm_rows(const TfheFft *f, const TfheKeys *k, const TfheRadixLuts *l, TfheDrbg *d) {
  static const char *const names[RADIX_WASM_ROWS] = {"rmul", "rmul", "rsum4", "rle", "radd", "rle", "rsum5"};
  uint64_t value[RADIX_WASM_ROWS];
  char cmd[512];
  FILE *in = fopen("build/tfhe-radix-in.txt", "w");
  FILE *out = NULL;
  unsigned r, got;
  int ok = in != NULL;
  if (in != NULL) radix_wasm_input(in, f, k, l, d, value);
  ok = ok && fclose(in) == 0 && tfhe_wasm_write("build/tfhe-kernel.wasm") &&
       key_write("build/tfhe-ksk.bin", k->ksk, TFHE_KSK_WORDS) &&
       key_write("build/tfhe-bsk.bin", k->bsk_fourier, TFHE_BSK_FOURIER_DOUBLES) &&
       system(tfhe_node_cmd(cmd, sizeof cmd, 0, "build/tfhe-radix-in.txt", "build/tfhe-radix-out.txt")) == 0;
  remove("build/tfhe-ksk.bin");
  remove("build/tfhe-bsk.bin");
  remove("build/tfhe-radix-in.txt");
  if (ok) out = fopen("build/tfhe-radix-out.txt", "r");
  if (!ok || out == NULL) puts("FAIL tfhe wasm radix: the module, a key file, the input or node failed");
  ok = ok && out != NULL;
  for (r = 0; r < RADIX_WASM_ROWS && ok; r++) {
    const int le = names[r][1] == 'l';
    const size_t n = le ? TFHE_BLOCK_WORDS : RADIX_WORDS;
    ok = read_words(out, (uint64_t *)radix_got.block, n);
    if (!ok) printf("FAIL tfhe wasm radix %s: fewer than %u words\n", names[r], (unsigned)n);
    ok = ok && words_equal(names[r], (const uint64_t *)radix_got.block, (const uint64_t *)radix_wasm_want[r].block, n);
    got = ok && le ? tfhe_decode(tfhe_lwe_phase(radix_got.block[0], k->glwe_key, TFHE_BIG_N)) : (unsigned)value[r];
    if (got != (unsigned)value[r]) printf("FAIL tfhe wasm radix %s row %u: %u, want %u\n", names[r], r, got,
                                          (unsigned)value[r]);
    ok = ok && got == (unsigned)value[r] && (le || radix_clean(names[r], &radix_got, value[r], k));
  }
  if (out != NULL) fclose(out);
  remove("build/tfhe-radix-out.txt");
  if (ok) puts("tfhe wasm radix: C = Wasm (rmul 2, rsum4 1, rle 2, radd 1, rsum5 1; 7 rows)");
  return ok;
}

static int tfhe_radix_rows(const TfheFft *f, const TfheKeys *k, TfheDrbg *d) {
  static TfheRadixLuts l;
  int ok, enc;
  tfhe_radix_luts(&l);
  ok = radix_add_rows(f, k, &l, d);
  ok &= radix_le_rows(f, k, &l, d);
  ok &= radix_sum_rows(f, k, &l, d);
  ok &= radix_mul_rows(k, d);
  if (ok) {
    printf("tfhe radix trivial: %d rows (add %d, le %d, sum %d, scalar_mul %d)\n",
           RADIX_ADD_ROWS + RADIX_LE_ROWS + RADIX_SUM_ROWS + RADIX_MUL_ROWS, RADIX_ADD_ROWS, RADIX_LE_ROWS,
           RADIX_SUM_ROWS, RADIX_MUL_ROWS);
  }
  enc = radix_encrypted_rows(f, k, &l, d);
  if (enc) printf("tfhe radix encrypted: scalar_mul 2, sum4 1, le 1 (%d PBS)\n", TFHE_PROPAGATE_PBS + TFHE_LE_PBS);
  return ok & enc & tfhe_radix_wasm_rows(f, k, &l, d);
}

/* S5 U4a rows: the circuits of front/fhe.h on trivial inputs (mask 0, body =
   the encoded value), after the radix rows, so their DRBG stream does not
   change. A trivial PBS is exact (0.1 ms each). Each row checks each output
   against its domain.lang value and the eval PBS count against the built
   count. The tally ballots are tfhe_drbg_bytes (D, 8) mod the option count.
   The DecE codes: 0 decRelease, 1 decRefund, 2 decHold. */
enum {
  FHE_TALLY_ROWS = 8,
  FHE_THETA_ROWS = 6,
  FHE_SETTLE_ROWS = 3,
  FHE_CREDIT_ROWS = 6,
  FHE_WITHDRAW_ROWS = 6,
  FHE_AMD_ROWS = 6,
  FHE_MIX_ROWS = 2
};

static FheEval fhe_ctx;
static FheLuts fhe_lut_set;
static TfheRadixLuts fhe_radix_lut_set;
static TfheRadix fhe_rin[2];
static uint64_t fhe_bin[FHE_INPUTS][TFHE_BLOCK_WORDS];
static uint64_t fhe_param[FHE_INPUTS];
static FheCircuit fhe_c;

/* Block input I is the trivial block of V. */
static void fhe_block_set(unsigned i, unsigned v) {
  memset(fhe_bin[i], 0, sizeof fhe_bin[i]);
  fhe_bin[i][TFHE_BIG_N] = tfhe_encode(v);
}

/* The value of output I of the last eval: a radix decrypt or a block decode. */
static uint64_t fhe_out(unsigned i, const TfheKeys *k) {
  FheReg r = fhe_c.out[i];
  if (r.slot == FHE_RADIX_REG) return tfhe_radix_decrypt(&fhe_ctx.radix[r.index], k);
  return tfhe_decode(tfhe_lwe_phase(fhe_ctx.block[r.index], k->glwe_key, TFHE_BIG_N));
}

/* Builds KIND at N and runs it on the inputs: each output must be WANT and the
   eval PBS count must be the built count. */
static int fhe_row(FheKind kind, unsigned n, unsigned row, const uint64_t *want, const TfheKeys *k) {
  unsigned i;
  int ok;
  if (!fhe_build(&fhe_c, kind, n)) {
    printf("FAIL fhe %s row %u: the build fails\n", fhe_c.name, row);
    return 0;
  }
  fhe_eval(&fhe_ctx, &fhe_c);
  ok = fhe_ctx.pbs == fhe_c.pbs;
  if (!ok) printf("FAIL fhe %s row %u: eval %u PBS, built %u PBS\n", fhe_c.name, row, fhe_ctx.pbs, fhe_c.pbs);
  for (i = 0; i < fhe_c.outs; i++) {
    uint64_t got = fhe_out(i, k);
    if (got != want[i]) {
      printf("FAIL fhe %s row %u: output %u is %llu, want %llu\n", fhe_c.name, row, i, (unsigned long long)got,
             (unsigned long long)want[i]);
      ok = 0;
    }
  }
  return ok;
}

/* tauE (tally4) and tauA (tally3) at N 1, 2, 4, 7: count j is the number of
   ballots with choice j. */
static int fhe_tally_rows(const TfheKeys *k, TfheDrbg *d) {
  static const unsigned ns[] = {1, 2, 4, 7};
  uint64_t want[4];
  unsigned row, i, j;
  int ok = 1;
  for (row = 0; row < FHE_TALLY_ROWS; row++) {
    unsigned options = row < 4u ? 4u : 3u, n = ns[row % 4u];
    memset(want, 0, sizeof want);
    for (i = 0; i < n; i++) {
      unsigned choice = (unsigned)(tfhe_drbg_bytes(d, 8) % options);
      want[choice]++;
      for (j = 0; j < options; j++) fhe_block_set(i * options + j, j == choice);
    }
    ok &= fhe_row(row < 4u ? FHE_TALLY4 : FHE_TALLY3, n, row, want, k);
  }
  return ok;
}

/* ruleApply (ruleThreshold t) on (t, cRel, cRef): decRelease when t <= cRel,
   else decRefund when t <= cRef, else decHold. */
static int fhe_theta_rows(const TfheKeys *k) {
  static const uint64_t rows[FHE_THETA_ROWS][3] = {{3, 3, 0}, {4, 3, 4}, {4, 3, 3},
                                                   {0, 0, 0}, {5, 7, 9}, {UINT64_MAX, UINT64_MAX - 1u, UINT64_MAX}};
  unsigned row;
  int ok = 1;
  for (row = 0; row < FHE_THETA_ROWS; row++) {
    uint64_t t = rows[row][0], rel = rows[row][1], ref = rows[row][2];
    uint64_t want = t <= rel ? 0u : t <= ref ? 1u : 2u;
    tfhe_radix_trivial(&fhe_rin[0], rel);
    tfhe_radix_trivial(&fhe_rin[1], ref);
    fhe_param[0] = t;
    ok &= fhe_row(FHE_THETA, 0, row, &want, k);
  }
  return ok;
}

/* The settle bits of the code d (note L550, L551): r = (d = decRelease), rf =
   (d = decRefund), z = r + rf. */
static int fhe_settle_rows(const TfheKeys *k) {
  unsigned row;
  int ok = 1;
  for (row = 0; row < FHE_SETTLE_ROWS; row++) {
    uint64_t want[3] = {row == 0u, row == 1u, row <= 1u};
    fhe_block_set(0, row);
    ok &= fhe_row(FHE_SETTLE, 0, row, want, k);
  }
  return ok;
}

/* ledgerAdd on (q, p, d, amount), mod 2^64: q + r amount and p + rf amount. */
static int fhe_credit_rows(const TfheKeys *k) {
  static const uint64_t rows[FHE_CREDIT_ROWS][4] = {{10, 20, 0, 5}, {10, 20, 1, 5}, {10, 20, 2, 5},
                                                    {UINT64_MAX, 0, 0, 1}, {7, 9, 0, 0}, {1, 2, 1, UINT64_MAX}};
  unsigned row;
  int ok = 1;
  for (row = 0; row < FHE_CREDIT_ROWS; row++) {
    uint64_t q = rows[row][0], p = rows[row][1], amount = rows[row][3];
    unsigned r = rows[row][2] == 0u, rf = rows[row][2] == 1u;
    uint64_t want[2] = {q + r * amount, p + rf * amount};
    tfhe_radix_trivial(&fhe_rin[0], q);
    tfhe_radix_trivial(&fhe_rin[1], p);
    fhe_block_set(0, r);
    fhe_block_set(1, rf);
    fhe_param[0] = amount;
    ok &= fhe_row(FHE_CREDIT, 0, row, want, k);
  }
  return ok;
}

/* ledgerSub on (a, amount): ok = (amount <= a), and a - amount when ok, else a. */
static int fhe_withdraw_rows(const TfheKeys *k) {
  static const uint64_t rows[FHE_WITHDRAW_ROWS][2] = {{50, 50}, {50, 51}, {50, 0},
                                                      {UINT64_MAX, UINT64_MAX}, {5, UINT64_MAX}, {0, 0}};
  unsigned row;
  int ok = 1;
  for (row = 0; row < FHE_WITHDRAW_ROWS; row++) {
    uint64_t a = rows[row][0], amount = rows[row][1];
    uint64_t want[2] = {amount <= a, amount <= a ? a - amount : a};
    tfhe_radix_trivial(&fhe_rin[0], a);
    fhe_param[0] = amount;
    ok &= fhe_row(FHE_WITHDRAW, 0, row, want, k);
  }
  return ok;
}

/* amdThreshold n tA on (n, tA, cAdopt, cReject), slack = natSub n tA: 0
   amendAdopt when tA <= cAdopt, else 1 amendReject when slack < cReject, else
   2 amendHold. */
static int fhe_amd_rows(const TfheKeys *k) {
  static const uint64_t rows[FHE_AMD_ROWS][4] = {{7, 5, 5, 0}, {7, 5, 4, 3}, {7, 5, 4, 2},
                                                 {5, 5, 4, 0}, {5, 5, 4, 1}, {3, 5, 2, 1}};
  unsigned row;
  int ok = 1;
  for (row = 0; row < FHE_AMD_ROWS; row++) {
    uint64_t n = rows[row][0], ta = rows[row][1], adopt = rows[row][2], reject = rows[row][3];
    uint64_t slack = n > ta ? n - ta : 0u;
    uint64_t want = ta <= adopt ? 0u : slack < reject ? 1u : 2u;
    tfhe_radix_trivial(&fhe_rin[0], adopt);
    tfhe_radix_trivial(&fhe_rin[1], reject);
    fhe_param[0] = ta;
    fhe_param[1] = slack;
    ok &= fhe_row(FHE_AMD, 0, row, &want, k);
  }
  return ok;
}

/* The refresh row on (x, y, a): x a + y 2 mod 2^64, with one refresh (32 PBS)
   before the radd. */
static int fhe_mix_rows(const TfheKeys *k) {
  static const uint64_t rows[FHE_MIX_ROWS][3] = {{1, 1, UINT64_MAX}, {1, 0, 12345}};
  unsigned row;
  int ok = 1;
  for (row = 0; row < FHE_MIX_ROWS; row++) {
    uint64_t want = rows[row][0] * rows[row][2] + rows[row][1] * 2u;
    fhe_block_set(0, (unsigned)rows[row][0]);
    fhe_block_set(1, (unsigned)rows[row][1]);
    fhe_param[0] = rows[row][2];
    ok &= fhe_row(FHE_MIX, 0, row, &want, k);
    if (fhe_c.refreshes != 1u || fhe_c.pbs != TFHE_RADIX_BLOCKS + TFHE_PROPAGATE_PBS) {
      printf("FAIL fhe mix row %u: %u refreshes and %u PBS, want 1 and %d\n", row, fhe_c.refreshes, fhe_c.pbs,
             TFHE_RADIX_BLOCKS + TFHE_PROPAGATE_PBS);
      ok = 0;
    }
  }
  return ok;
}

/* S5 U4b rows: the circuit entries of the tfhe module at N 7 (one node call
   on one instance). Rows 1 to 7 have trivial inputs: the Wasm out words must
   be the C eval words, and the decrypt must be the table value. Row 8 is theta
   on encrypted radixes (the DRBG D after all the other rows): only its decrypt
   is checked (a C eval of its PBS costs about 49 s). */
enum { FHE_WASM_ROWS = 8 };

typedef struct FheWasmRow {
  FheKind kind;
  uint64_t radix[2], block[2], param[2], want[FHE_OUTPUTS];
} FheWasmRow;

/* tally4: ballot i votes option (3i + 1) % 4; tally3: ballot i votes option
   i % 3 (i = 0 .. 6). The radixes, blocks and params are in the circuit input
   order. */
static const FheWasmRow fhe_wasm_table[FHE_WASM_ROWS] = {
  {FHE_TALLY4, {0, 0}, {0, 0}, {0, 0}, {2, 2, 1, 2}},
  {FHE_TALLY3, {0, 0}, {0, 0}, {0, 0}, {3, 2, 2, 0}},
  {FHE_THETA, {4, 5}, {0, 0}, {5, 0}, {1, 0, 0, 0}},
  {FHE_SETTLE, {0, 0}, {1, 0}, {0, 0}, {0, 1, 1, 0}},
  {FHE_CREDIT, {100, 200}, {1, 0}, {50, 0}, {150, 200, 0, 0}},
  {FHE_WITHDRAW, {100, 0}, {0, 0}, {30, 0}, {1, 70, 0, 0}},
  {FHE_AMD, {2, 5}, {0, 0}, {3, 4}, {1, 0, 0, 0}},
  {FHE_THETA, {3, 9}, {0, 0}, {10, 0}, {2, 0, 0, 0}}};

static TfheRadix fhe_wasm_got;

/* Sets the inputs of row ROW. The last row encrypts its radixes with D. */
static void fhe_wasm_set(unsigned row, const TfheKeys *k, TfheDrbg *d) {
  const FheWasmRow *w = &fhe_wasm_table[row];
  const unsigned options = row == 0 ? 4u : 3u;
  unsigned i, j;
  for (i = 0; i < 2u; i++) {
    if (row + 1u == FHE_WASM_ROWS)
      tfhe_radix_encrypt(&fhe_rin[i], k, w->radix[i], d);
    else
      tfhe_radix_trivial(&fhe_rin[i], w->radix[i]);
    fhe_block_set(i, (unsigned)w->block[i]);
    fhe_param[i] = w->param[i];
  }
  for (i = 0; i < 7u && row < 2u; i++) {
    const unsigned choice = row == 0 ? (3u * i + 1u) % 4u : i % 3u;
    for (j = 0; j < options; j++) fhe_block_set(i * options + j, j == choice);
  }
}

/* Writes the input line of fhe_c: the name, the radix inputs, the block
   inputs, then the parameters. */
static void fhe_wasm_line(FILE *in) {
  unsigned i;
  fputs(fhe_c.name, in);
  for (i = 0; i < fhe_c.radix_ins && i < 2u; i++) put_words(in, (const uint64_t *)fhe_rin[i].block, RADIX_WORDS);
  for (i = 0; i < fhe_c.block_ins; i++) put_words(in, fhe_bin[i], TFHE_BLOCK_WORDS);
  put_words(in, fhe_param, fhe_c.params);
  fputs("\n", in);
}

/* Reads the out words of row ROW from OUT and checks them. 0 when a word is
   missing; *PASS := 0 when the row fails. */
static int fhe_wasm_row(FILE *out, unsigned row, const TfheKeys *k, int *pass) {
  const FheWasmRow *w = &fhe_wasm_table[row];
  const int enc = row + 1u == FHE_WASM_ROWS;
  char name[32];
  unsigned i;
  int ok = fhe_build(&fhe_c, w->kind, 7);
  if (ok && !enc) {
    fhe_wasm_set(row, k, NULL);
    fhe_eval(&fhe_ctx, &fhe_c);
  }
  snprintf(name, sizeof name, "fhe %s", fhe_c.name);
  for (i = 0; i < fhe_c.outs && ok; i++) {
    const FheReg r = fhe_c.out[i];
    const int radix = r.slot == FHE_RADIX_REG;
    const size_t n = radix ? RADIX_WORDS : TFHE_BLOCK_WORDS;
    const uint64_t *want = radix ? (const uint64_t *)fhe_ctx.radix[r.index].block : fhe_ctx.block[r.index];
    uint64_t got;
    int same;
    ok = read_words(out, (uint64_t *)fhe_wasm_got.block, n);
    if (!ok) printf("FAIL fhe wasm %s row %u: fewer than %u words\n", fhe_c.name, row + 1u, (unsigned)n);
    same = ok && (enc || words_equal(name, (const uint64_t *)fhe_wasm_got.block, want, n));
    got = radix ? tfhe_radix_decrypt(&fhe_wasm_got, k)
                : tfhe_decode(tfhe_lwe_phase(fhe_wasm_got.block[0], k->glwe_key, TFHE_BIG_N));
    if (ok && got != w->want[i])
      printf("FAIL fhe wasm %s row %u: %llu, want %llu\n", fhe_c.name, row + 1u, (unsigned long long)got,
             (unsigned long long)w->want[i]);
    *pass &= same && got == w->want[i];
  }
  return ok;
}

static int fhe_wasm_rows(const TfheKeys *k, TfheDrbg *d) {
  char cmd[512];
  FILE *in = fopen("build/tfhe-fhe-in.txt", "w");
  FILE *out = NULL;
  unsigned row;
  int ok = in != NULL, pass = 1;
  for (row = 0; row < FHE_WASM_ROWS && ok; row++) {
    fhe_wasm_set(row, k, d);
    ok = fhe_build(&fhe_c, fhe_wasm_table[row].kind, 7);
    if (ok) fhe_wasm_line(in);
  }
  ok = in != NULL && fclose(in) == 0 && ok && tfhe_wasm_write("build/tfhe-kernel.wasm") &&
       key_write("build/tfhe-ksk.bin", k->ksk, TFHE_KSK_WORDS) &&
       key_write("build/tfhe-bsk.bin", k->bsk_fourier, TFHE_BSK_FOURIER_DOUBLES) &&
       system(tfhe_node_cmd(cmd, sizeof cmd, 0, "build/tfhe-fhe-in.txt", "build/tfhe-fhe-out.txt")) == 0;
  remove("build/tfhe-ksk.bin");
  remove("build/tfhe-bsk.bin");
  remove("build/tfhe-fhe-in.txt");
  if (ok) out = fopen("build/tfhe-fhe-out.txt", "r");
  if (!ok || out == NULL) puts("FAIL fhe wasm: the module, a key file, the input or node failed");
  ok = ok && out != NULL;
  for (row = 0; row < FHE_WASM_ROWS && ok; row++) ok = fhe_wasm_row(out, row, k, &pass);
  if (out != NULL) fclose(out);
  remove("build/tfhe-fhe-out.txt");
  if (ok && pass)
    puts("fhe wasm: C = Wasm (tally4, tally3, theta, settle, credit, withdraw, amd trivial 7; theta encrypted 1; 8 "
         "rows)");
  return ok && pass;
}

/* The built PBS total of each printed circuit at N 7. */
static int fhe_circuit_totals(void) {
  char line[160];
  size_t at = (size_t)snprintf(line, sizeof line, "fhe circuits (N 7):");
  unsigned kind;
  for (kind = 0; kind < FHE_PRINTED; kind++) {
    if (!fhe_build(&fhe_c, (FheKind)kind, 7)) {
      printf("FAIL fhe %s: the build at N 7 fails\n", fhe_c.name);
      return 0;
    }
    at += (size_t)snprintf(line + at, sizeof line - at, "%s %s %u", kind == 0 ? "" : ",", fhe_c.name, fhe_c.pbs);
  }
  printf("%s PBS\n", line);
  return 1;
}

static int tfhe_fhe_rows(const TfheFft *f, const TfheKeys *k, TfheDrbg *d) {
  int ok;
  tfhe_radix_luts(&fhe_radix_lut_set);
  fhe_luts(&fhe_lut_set);
  fhe_ctx.f = f;
  fhe_ctx.k = k;
  fhe_ctx.rl = &fhe_radix_lut_set;
  fhe_ctx.l = &fhe_lut_set;
  fhe_ctx.rin = fhe_rin;
  fhe_ctx.bin = (const uint64_t(*)[TFHE_BLOCK_WORDS])fhe_bin;
  fhe_ctx.param = fhe_param;
  ok = fhe_circuit_totals();
  ok &= fhe_tally_rows(k, d);
  ok &= fhe_theta_rows(k);
  ok &= fhe_settle_rows(k);
  ok &= fhe_credit_rows(k);
  ok &= fhe_withdraw_rows(k);
  ok &= fhe_amd_rows(k);
  ok &= fhe_mix_rows(k);
  ok &= fhe_wasm_rows(k, d);
  if (ok) {
    printf("fhe trivial: %d rows\n", FHE_TALLY_ROWS + FHE_THETA_ROWS + FHE_SETTLE_ROWS + FHE_CREDIT_ROWS +
                                         FHE_WITHDRAW_ROWS + FHE_AMD_ROWS + FHE_MIX_ROWS);
  }
  return ok;
}

/* S5 U5b rows: the public-key encryption of one chunk (W/S5-NOTES.md "### U5
   plan" item 6). The PKE keys and the chunk come from two new fixed seeds, so
   the DRBG streams of the other rows do not move. P1: each coefficient of
   pk_b - pk_a phi_1(key) is in [-2^17, 2^17]. P2: entry j of the chunk
   (m_j = j) decodes to j under KEY, with an error below 2^40. P3: the cast of
   entry j decodes to j under the big key. */
static int tfhe_client_write(const char *path) {
  FILE *module = fopen(path, "wb");
  int ok = module != NULL && wasm_write_tfhe_client(module, stderr);
  return module != NULL && fclose(module) == 0 && ok;
}

/* S5 U5c (W2): the node module with the casting KSK at WASM_TFHE_KSK (in
   place of the compute KSK) and the BSK after it: expand j = 0, 1, 15 and
   the cast (the pbs entry, the identity LUT) of j = 0, 15 give the C words,
   and each cast decrypts to j under the big key. Each row is checked. */
static int tfhe_pke_node_rows(const TfheFft *f, const TfheKeys *k, const TfhePke *p, const uint64_t *mask,
                              const uint64_t *body) {
  static const unsigned js[3] = {0, 1, 15};
  static uint64_t want[5][TFHE_BIG_N + 1];
  uint64_t got[TFHE_BIG_N + 1], lut[TFHE_POLY_N], jw;
  uint8_t table[TFHE_PLAIN];
  char cmd[512], row[32];
  FILE *in = fopen("build/tfhe-pke-in.txt", "w"), *out = NULL;
  unsigned i;
  int pass = 1, ran = tfhe_wasm_write("build/tfhe-kernel.wasm") &&
                      key_write("build/tfhe-cksk.bin", p->cksk, TFHE_KSK_WORDS) &&
                      key_write("build/tfhe-bsk.bin", k->bsk_fourier, TFHE_BSK_FOURIER_DOUBLES) && in != NULL;
  for (i = 0; i < TFHE_PLAIN; i++) table[i] = (uint8_t)i;
  tfhe_lut(lut, table);
  for (i = 0; i < 3; i++) tfhe_pke_expand(want[i], mask, body[js[i]], js[i]);
  tfhe_pke_cast(f, want[3], want[0], p, k);
  tfhe_pke_cast(f, want[4], want[2], p, k);
  for (i = 0; i < 3 && in != NULL; i++) {
    jw = js[i];
    fputs("expand", in);
    put_words(in, mask, TFHE_POLY_N);
    put_words(in, body + js[i], 1);
    put_words(in, &jw, 1);
    fputs("\n", in);
  }
  for (i = 0; i < 2 && in != NULL; i++) {
    fputs("pbs", in);
    put_words(in, want[2 * i], TFHE_BIG_N + 1);
    put_words(in, lut, TFHE_POLY_N);
    fputs("\n", in);
  }
  snprintf(cmd, sizeof cmd,
           "node test/run-wasm.mjs --load %lu build/tfhe-cksk.bin --load %lu build/tfhe-bsk.bin "
           "--words build/tfhe-kernel.wasm - <build/tfhe-pke-in.txt >build/tfhe-pke-out.txt 2>&1",
           (unsigned long)WASM_TFHE_KSK, (unsigned long)WASM_TFHE_KSK + 8ul * (unsigned long)TFHE_KSK_WORDS);
  ran = in != NULL && fclose(in) == 0 && ran && system(cmd) == 0;
  remove("build/tfhe-cksk.bin");
  remove("build/tfhe-bsk.bin");
  if (ran) out = fopen("build/tfhe-pke-out.txt", "r");
  ran = ran && out != NULL;
  for (i = 0; i < 5 && ran; i++) {
    ran = read_words(out, got, TFHE_BIG_N + 1);
    snprintf(row, sizeof row, "%s j %u", i < 3 ? "expand" : "cast", i < 3 ? js[i] : js[2 * (i - 3)]);
    pass = ran && words_equal(row, got, want[i], TFHE_BIG_N + 1) && pass;
    if (ran && i >= 3 && tfhe_decode(tfhe_lwe_phase(got, k->glwe_key, TFHE_BIG_N)) != js[2 * (i - 3)]) {
      printf("FAIL tfhe wasm cast j %u: the Wasm cast does not decrypt to j\n", js[2 * (i - 3)]);
      pass = 0;
    }
  }
  if (!ran) puts("FAIL tfhe wasm expand: the module, a key file, the input or node failed (build/tfhe-pke-out.txt)");
  if (out != NULL) fclose(out);
  if (ran && pass) {
    remove("build/tfhe-pke-in.txt");
    remove("build/tfhe-pke-out.txt");
  }
  return ran && pass;
}

/* S5 U5c (W1): the client module pkenc with the seed of the C chunk and the
   16 messages gives the C mask and body words. */
static int tfhe_pke_wasm_rows(const TfheFft *f, const TfheKeys *k, const TfhePke *p, const uint8_t *seed,
                              const uint64_t *mask, const uint64_t *body) {
  static uint64_t got[TFHE_POLY_N + TFHE_PLAIN];
  uint64_t words[TFHE_SEED_BYTES / 8u] = {0}, m[TFHE_PLAIN];
  unsigned j;
  FILE *in = fopen("build/tfhe-client-in.txt", "w"), *out = NULL;
  int ok = tfhe_client_write("build/tfhe-client.wasm") && in != NULL;
  for (j = 0; j < TFHE_SEED_BYTES; j++) words[j / 8u] |= (uint64_t)seed[j] << (8u * (j % 8u));
  for (j = 0; j < TFHE_PLAIN; j++) m[j] = j;
  if (in != NULL) {
    fputs("pkenc", in);
    put_words(in, words, TFHE_SEED_BYTES / 8u);
    put_words(in, p->pk_a, TFHE_POLY_N);
    put_words(in, p->pk_b, TFHE_POLY_N);
    put_words(in, m, TFHE_PLAIN);
    fputs("\n", in);
  }
  ok = in != NULL && fclose(in) == 0 && ok &&
       system("node test/run-wasm.mjs --words build/tfhe-client.wasm - <build/tfhe-client-in.txt "
              ">build/tfhe-client-out.txt 2>&1") == 0;
  if (ok) out = fopen("build/tfhe-client-out.txt", "r");
  ok = ok && out != NULL && read_words(out, got, TFHE_POLY_N + TFHE_PLAIN);
  if (!ok) puts("FAIL tfhe wasm pkenc: the module, the input or node failed (build/tfhe-client-out.txt)");
  ok = ok && words_equal("pkenc mask", got, mask, TFHE_POLY_N) &&
       words_equal("pkenc body", got + TFHE_POLY_N, body, TFHE_PLAIN);
  if (out != NULL) fclose(out);
  if (ok) {
    remove("build/tfhe-client-in.txt");
    remove("build/tfhe-client-out.txt");
  }
  ok = tfhe_pke_node_rows(f, k, p, mask, body) && ok;
  if (ok)
    printf("tfhe wasm pke: C = Wasm words (pkenc mask %d body %d, expand 3 x %d, cast 2 x %d), decrypt = m\n",
           TFHE_POLY_N, TFHE_PLAIN, TFHE_BIG_N + 1, TFHE_BIG_N + 1);
  return ok;
}

/* S5 U6b rows: the encrypted chain at N 7, part 1 (W/S5-NOTES.md "### U6
   plan"). The client module encrypts 18 lists of 16 messages under the PKE
   key, each with the chain seed (word 0 xor the line number): the DecE and the
   BallotA ballots (lines 0 to 13, one bit block for each option) and the
   radixes q and p (lines 14 to 17, 16 digits a line). C expands the 113 used
   slots, and the node module with the casting KSK casts each (the pbs entry,
   the identity LUT): each cast must decrypt to its message under the big key.
   Run A is tally4 and tally3 on the cast ballot blocks (the compute KSK). */
enum { CHAIN_LINES = 18, CHAIN_CASTS = 113, CHAIN_DEC = 0, CHAIN_BALLOT = 28, CHAIN_Q = 49, CHAIN_P = 81 };

/* The choice of each ballot: DecE (4 options), BallotA (3 options). */
static const unsigned chain_dec[7] = {0, 0, 0, 1, 1, 2, 3};
static const unsigned chain_ballot[7] = {0, 0, 0, 0, 1, 1, 2};
/* The radixes q and p of the credit stage (U6c). */
static const uint64_t chain_radix[2] = {0x00000000FFFFFFFFu, 0x123456789ABCDEF0u};
static uint64_t chain_m[CHAIN_LINES][TFHE_PLAIN];
static uint64_t chain_ct[CHAIN_LINES][TFHE_POLY_N + TFHE_PLAIN];
static uint64_t chain_slot[CHAIN_CASTS];
static uint64_t chain_cast[CHAIN_CASTS][TFHE_BLOCK_WORDS];
static TfheRadix chain_count[7];

/* The used slots of client line LINE: 4 (DecE), 3 (BallotA) or 16 (q, p). */
static unsigned chain_width(unsigned line) {
  return line < 7u ? 4u : line < 14u ? 3u : (unsigned)TFHE_PLAIN;
}

/* The 16 messages of client line LINE: a ballot has 1 at its choice and 0 at
   the other slots; lines 14 to 17 are the 2-bit digits of q and p, low digit
   first. */
static void chain_list(uint64_t m[TFHE_PLAIN], unsigned line) {
  const unsigned w = chain_width(line), half = line < 14u ? 0u : line - 14u;
  const unsigned choice = line < 7u ? chain_dec[line] : line < 14u ? chain_ballot[line - 7u] : 0u;
  unsigned j;
  for (j = 0; j < TFHE_PLAIN; j++)
    m[j] = line < 14u ? (uint64_t)(j < w && j == choice)
                      : (chain_radix[half / 2u] >> (2u * (16u * (half % 2u) + j))) & 3u;
}

/* The decode of block B under the big key. */
static uint64_t chain_value(const uint64_t *b, const TfheKeys *k) {
  return tfhe_decode(tfhe_lwe_phase(b, k->glwe_key, TFHE_BIG_N));
}

/* The (1.1) row of tally STAGE (0 tally4, 1 tally3) with the counts COUNT:
   each ballot block decrypts to its planned bit, and count j decrypts to the
   sum of the decrypted bits j (f of the decrypted inputs) and to the plan. */
static int chain_tally_row(unsigned stage, const TfheRadix *count, const TfheKeys *k) {
  const unsigned options = stage == 0 ? 4u : 3u, base = stage == 0 ? CHAIN_DEC : CHAIN_BALLOT;
  const char *name = stage == 0 ? "tally4" : "tally3";
  uint64_t sum[4] = {0}, plan[4] = {0}, bit, got;
  unsigned i, j, wrong = 0;
  int ok = 1;
  for (i = 0; i < 7u; i++) {
    const unsigned choice = stage == 0 ? chain_dec[i] : chain_ballot[i];
    plan[choice]++;
    for (j = 0; j < options; j++) {
      bit = chain_value(chain_cast[base + i * options + j], k);
      sum[j] += bit;
      if (wrong == 0 && bit != (uint64_t)(j == choice))
        printf("FAIL fhe chain %s: x%u_%u = %llu, want %u\n", name, i, j, (unsigned long long)bit,
               (unsigned)(j == choice));
      wrong += bit != (uint64_t)(j == choice);
    }
  }
  for (j = 0; j < options; j++) {
    got = tfhe_radix_decrypt(&count[j], k);
    if (got != sum[j])
      printf("FAIL fhe chain %s (1.1): count %u = %llu, want %llu\n", name, j, (unsigned long long)got,
             (unsigned long long)sum[j]);
    if (got == sum[j] && got != plan[j])
      printf("FAIL fhe chain %s: count %u = %llu, want %llu\n", name, j, (unsigned long long)got,
             (unsigned long long)plan[j]);
    ok &= got == sum[j] && got == plan[j];
  }
  return ok && wrong == 0;
}

/* S5 U6c rows: runs B to E of the chain and step 5 (W/S5-NOTES.md "### U6 plan").
   Run B: theta on (cRel, cRef) = the DecE counts 0 and 1, amd on (cAdopt,
   cReject) = the BallotA counts 0 and 1. Run C: settle on the theta d. Run D:
   credit on the cast radixes q and p (32 casts each, low digit first) and the
   settle r and rf. Run E: withdraw on the credit q2. Each run is one node call
   (the compute KSK). A stage keeps its decrypted inputs (the stream order:
   radixes, blocks, params) at the line write; its (1.1) row checks each input
   against the plan, and each output against f of the decrypted inputs and
   against the plan. Step 5: the C settle eval (2 PBS in C) on the theta d
   block; its words must be the run C words. */
typedef struct ChainStage {
  FheKind kind;
  unsigned ni, no;
  const char *name[7];
  uint64_t plan[7];
} ChainStage;

/* The inputs, then the outputs. theta t 3; amd tA 4 and slack = natSub 7 4 =
   3; credit amount 1; withdraw amount 2^32 - 1. */
static const ChainStage chain_stage[5] = {
  {FHE_THETA, 3, 1, {"cRel", "cRef", "t", "d"}, {3, 2, 3, 0}},
  {FHE_AMD, 4, 1, {"cAdopt", "cReject", "tA", "slack", "code"}, {4, 2, 4, 3, 0}},
  {FHE_SETTLE, 1, 3, {"d", "r", "rf", "z"}, {0, 1, 0, 1}},
  {FHE_CREDIT, 5, 2, {"q", "p", "r", "rf", "amount", "q2", "p2"},
   {0x00000000FFFFFFFFu, 0x123456789ABCDEF0u, 1, 0, 1, 0x0000000100000000u, 0x123456789ABCDEF0u}},
  {FHE_WITHDRAW, 2, 2, {"a", "amount", "ok", "a2"}, {0x0000000100000000u, 0x00000000FFFFFFFFu, 1, 1}}};
static TfheRadix chain_out[5][3];
static uint64_t chain_v[5][7];
static char chain_file[2][40];

/* One FAIL line of a stage: decimal when both values are below 2^16, else 16 hex digits. */
static void chain_fail(const char *stage, const char *tag, const char *name, uint64_t got, uint64_t want) {
  if ((got | want) >> 16 == 0)
    printf("FAIL fhe chain %s%s: %s = %llu, want %llu\n", stage, tag, name, (unsigned long long)got,
           (unsigned long long)want);
  else
    printf("FAIL fhe chain %s%s: %s = 0x%016llx, want 0x%016llx\n", stage, tag, name, (unsigned long long)got,
           (unsigned long long)want);
}

/* Output I of stage KIND on the decrypted inputs V (the stream order): the
   clear meaning of the trivial rows (theta, amd, settle, credit, withdraw). */
static uint64_t chain_f(FheKind kind, const uint64_t *v, unsigned i) {
  const uint64_t settle[3] = {v[0] == 0u, v[0] == 1u, v[0] <= 1u};
  return kind == FHE_THETA    ? (v[2] <= v[0] ? 0u : v[2] <= v[1] ? 1u : 2u)
         : kind == FHE_AMD    ? (v[2] <= v[0] ? 0u : v[3] < v[1] ? 1u : 2u)
         : kind == FHE_SETTLE ? settle[i % 3u]
         : kind == FHE_CREDIT ? v[i % 2u] + v[2u + i % 2u] * v[4]
         : i == 0             ? (uint64_t)(v[1] <= v[0])
                              : v[1] <= v[0] ? v[0] - v[1] : v[0];
}

/* Radix inputs 0 and 1 are A and B. */
static void chain_rin(const TfheRadix *a, const TfheRadix *b) {
  fhe_rin[0] = *a;
  fhe_rin[1] = *b;
}

/* The in and out files of run X (b to e); the in file opens when OK. */
static FILE *chain_open(char x, int ok) {
  snprintf(chain_file[0], sizeof chain_file[0], "build/tfhe-chain-%c-in.txt", x);
  snprintf(chain_file[1], sizeof chain_file[1], "build/tfhe-chain-%c-out.txt", x);
  return ok ? fopen(chain_file[0], "w") : NULL;
}

/* Writes the line of stage S to IN (its radix and block inputs are in fhe_rin
   and fhe_bin; its params come from the plan) and keeps the decrypted inputs
   in chain_v[S]. */
static int chain_line(FILE *in, unsigned s, const TfheKeys *k, unsigned *pbs) {
  const ChainStage *st = &chain_stage[s];
  unsigned i, n = 0;
  int ok = in != NULL && fhe_build(&fhe_c, st->kind, 7) &&
           fhe_c.radix_ins + fhe_c.block_ins + fhe_c.params == st->ni && fhe_c.radix_ins <= 2u;
  for (i = 0; i < fhe_c.params && ok; i++) fhe_param[i] = st->plan[st->ni - fhe_c.params + i];
  for (i = 0; i < fhe_c.radix_ins && ok; i++) chain_v[s][n++] = tfhe_radix_decrypt(&fhe_rin[i], k);
  for (i = 0; i < fhe_c.block_ins && ok; i++) chain_v[s][n++] = chain_value(fhe_bin[i], k);
  for (i = 0; i < fhe_c.params && ok; i++) chain_v[s][n++] = fhe_param[i];
  if (ok) fhe_wasm_line(in);
  *pbs += ok ? fhe_c.pbs : 0u;
  return ok;
}

/* Closes IN (the lines of stages S0 to S1 - 1), runs the node module on it
   (the compute KSK) and reads the outputs of each stage into chain_out (a
   radix, or block 0 of it). */
static int chain_run(FILE *in, int ok, unsigned s0, unsigned s1) {
  char cmd[512];
  FILE *out = NULL;
  unsigned s, i;
  ok = in != NULL && fclose(in) == 0 && ok &&
       system(tfhe_node_cmd(cmd, sizeof cmd, 0, chain_file[0], chain_file[1])) == 0;
  if (ok) out = fopen(chain_file[1], "r");
  ok = ok && out != NULL;
  for (s = s0; s < s1 && ok; s++) {
    ok = fhe_build(&fhe_c, chain_stage[s].kind, 7) && fhe_c.outs == chain_stage[s].no;
    for (i = 0; i < fhe_c.outs && ok; i++)
      ok = read_words(out, (uint64_t *)chain_out[s][i].block,
                      fhe_c.out[i].slot == FHE_RADIX_REG ? RADIX_WORDS : TFHE_BLOCK_WORDS);
  }
  if (out != NULL) fclose(out);
  return ok;
}

/* The (1.1) row of stage S: each input decrypts to its plan; each output
   decrypts to f of the decrypted inputs (chain_f) and to its plan. */
static int chain_stage_row(unsigned s, const TfheKeys *k) {
  const ChainStage *st = &chain_stage[s];
  uint64_t *v = chain_v[s], got, f, want;
  unsigned i;
  int ok = fhe_build(&fhe_c, st->kind, 7);
  for (i = 0; i < st->ni; i++) {
    if (v[i] != st->plan[i]) chain_fail(fhe_c.name, "", st->name[i], v[i], st->plan[i]);
    ok &= v[i] == st->plan[i];
  }
  for (i = 0; i < st->no; i++)
    v[st->ni + i] = fhe_c.out[i].slot == FHE_RADIX_REG ? tfhe_radix_decrypt(&chain_out[s][i], k)
                                                        : chain_value(chain_out[s][i].block[0], k);
  for (i = 0; i < st->no; i++) {
    got = v[st->ni + i];
    f = chain_f(st->kind, v, i);
    want = st->plan[st->ni + i];
    if (got != f) chain_fail(fhe_c.name, " (1.1)", st->name[st->ni + i], got, f);
    if (got == f && got != want) chain_fail(fhe_c.name, "", st->name[st->ni + i], got, want);
    ok &= got == f && got == want;
  }
  return ok;
}

/* Runs B to E and step 5. 0 on an I/O fault; *PASS := 0 when a row fails. */
static int chain_stage_rows(const TfheKeys *k, unsigned *pbs, int *pass) {
  const uint64_t *c_word, *w_word;
  FILE *in = chain_open('b', 1);
  unsigned s, c, i;
  int ok;
  chain_rin(chain_count, chain_count + 1);
  ok = chain_line(in, 0, k, pbs);
  chain_rin(chain_count + 4, chain_count + 5);
  ok = ok && chain_line(in, 1, k, pbs);
  ok = chain_run(in, ok, 0, 2);
  in = chain_open('c', ok);
  memcpy(fhe_bin[0], chain_out[0][0].block[0], sizeof fhe_bin[0]);
  ok = ok && chain_line(in, 2, k, pbs);
  ok = chain_run(in, ok, 2, 3);
  in = chain_open('d', ok);
  for (c = 0; c < TFHE_RADIX_BLOCKS; c++) {
    memcpy(fhe_rin[0].block[c], chain_cast[CHAIN_Q + c], sizeof fhe_rin[0].block[c]);
    memcpy(fhe_rin[1].block[c], chain_cast[CHAIN_P + c], sizeof fhe_rin[1].block[c]);
  }
  memcpy(fhe_bin[0], chain_out[2][0].block[0], sizeof fhe_bin[0]);
  memcpy(fhe_bin[1], chain_out[2][1].block[0], sizeof fhe_bin[1]);
  ok = ok && chain_line(in, 3, k, pbs);
  ok = chain_run(in, ok, 3, 4);
  in = chain_open('e', ok);
  fhe_rin[0] = chain_out[3][0];
  ok = ok && chain_line(in, 4, k, pbs);
  ok = chain_run(in, ok, 4, 5);
  for (s = 0; s < 5u && ok; s++) *pass &= chain_stage_row(s, k);
  /* Step 5: the C settle eval on the theta d block of run B. */
  if (ok) {
    fhe_ctx.bin = (const uint64_t(*)[TFHE_BLOCK_WORDS])chain_out[0][0].block;
    ok = fhe_build(&fhe_c, FHE_SETTLE, 7);
    if (ok) fhe_eval(&fhe_ctx, &fhe_c);
    fhe_ctx.bin = (const uint64_t(*)[TFHE_BLOCK_WORDS])fhe_bin;
  }
  for (c = 0; c < fhe_c.outs && ok; c++) {
    c_word = fhe_ctx.block[fhe_c.out[c].index];
    w_word = chain_out[2][c].block[0];
    i = 0;
    while (i < TFHE_BLOCK_WORDS && c_word[i] == w_word[i]) i++;
    if (i < TFHE_BLOCK_WORDS)
      printf("FAIL fhe chain settle: C = Wasm word %u of %s: C %llu, Wasm %llu\n", i, chain_stage[2].name[1u + c],
             (unsigned long long)c_word[i], (unsigned long long)w_word[i]);
    *pass &= i == TFHE_BLOCK_WORDS;
  }
  return ok;
}

static int fhe_chain_rows(const TfheKeys *k, const TfhePke *p) {
  static const char chain_seed[] = "charter-lang S5 U6 fhe chain 000";
  uint64_t words[TFHE_SEED_BYTES / 8u] = {0}, seed[TFHE_SEED_BYTES / 8u], ct[TFHE_BIG_N + 1], lut[TFHE_POLY_N], got;
  uint8_t table[TFHE_PLAIN];
  char cmd[512];
  FILE *in = fopen("build/tfhe-chain-client-in.txt", "w"), *out = NULL;
  unsigned line, j, c = 0, bad = 0, first = 0, pbs = CHAIN_CASTS;
  int ok = tfhe_client_write("build/tfhe-client.wasm") && in != NULL, pass = 1;
  for (j = 0; j < TFHE_SEED_BYTES; j++) words[j / 8u] |= (uint64_t)(uint8_t)chain_seed[j] << (8u * (j % 8u));
  for (j = 0; j < TFHE_PLAIN; j++) table[j] = (uint8_t)j;
  tfhe_lut(lut, table);
  for (line = 0; line < CHAIN_LINES; line++) chain_list(chain_m[line], line);
  for (line = 0; line < CHAIN_LINES && in != NULL; line++) {
    memcpy(seed, words, sizeof seed);
    seed[0] ^= line;
    fputs("pkenc", in);
    put_words(in, seed, TFHE_SEED_BYTES / 8u);
    put_words(in, p->pk_a, TFHE_POLY_N);
    put_words(in, p->pk_b, TFHE_POLY_N);
    put_words(in, chain_m[line], TFHE_PLAIN);
    fputs("\n", in);
  }
  ok = in != NULL && fclose(in) == 0 && ok &&
       system("node test/run-wasm.mjs --words build/tfhe-client.wasm - <build/tfhe-chain-client-in.txt "
              ">build/tfhe-chain-client-out.txt 2>&1") == 0;
  if (ok) out = fopen("build/tfhe-chain-client-out.txt", "r");
  ok = ok && out != NULL;
  for (line = 0; line < CHAIN_LINES && ok; line++) ok = read_words(out, chain_ct[line], TFHE_POLY_N + TFHE_PLAIN);
  if (out != NULL) fclose(out);
  /* The C expand of each used slot is the input of one cast. */
  in = ok ? fopen("build/tfhe-chain-cast-in.txt", "w") : NULL;
  for (line = 0; line < CHAIN_LINES && in != NULL; line++) {
    for (j = 0; j < chain_width(line); j++) {
      tfhe_pke_expand(ct, chain_ct[line], chain_ct[line][TFHE_POLY_N + j], j);
      chain_slot[c++] = chain_m[line][j];
      fputs("pbs", in);
      put_words(in, ct, TFHE_BIG_N + 1);
      put_words(in, lut, TFHE_POLY_N);
      fputs("\n", in);
    }
  }
  snprintf(cmd, sizeof cmd,
           "node test/run-wasm.mjs --load %lu %s --load %lu build/tfhe-bsk.bin --words build/tfhe-kernel.wasm - "
           "<build/tfhe-chain-cast-in.txt >build/tfhe-chain-cast-out.txt 2>&1",
           (unsigned long)WASM_TFHE_KSK, "build/tfhe-cksk.bin",
           (unsigned long)WASM_TFHE_KSK + 8ul * (unsigned long)TFHE_KSK_WORDS);
  ok = in != NULL && fclose(in) == 0 && ok && tfhe_wasm_write("build/tfhe-kernel.wasm") &&
       key_write("build/tfhe-cksk.bin", p->cksk, TFHE_KSK_WORDS) &&
       key_write("build/tfhe-ksk.bin", k->ksk, TFHE_KSK_WORDS) &&
       key_write("build/tfhe-bsk.bin", k->bsk_fourier, TFHE_BSK_FOURIER_DOUBLES) && system(cmd) == 0;
  out = NULL;
  if (ok) out = fopen("build/tfhe-chain-cast-out.txt", "r");
  ok = ok && out != NULL;
  for (c = 0; c < CHAIN_CASTS && ok; c++) ok = read_words(out, chain_cast[c], TFHE_BLOCK_WORDS);
  if (out != NULL) fclose(out);
  for (c = 0; c < CHAIN_CASTS && ok; c++) {
    got = chain_value(chain_cast[c], k);
    first = bad == 0 && got != chain_slot[c] ? c : first;
    bad += got != chain_slot[c];
  }
  if (bad != 0)
    printf("FAIL fhe chain cast: %u of %d slots differ, first slot %u = %llu, want %llu\n", bad, CHAIN_CASTS, first,
           (unsigned long long)chain_value(chain_cast[first], k), (unsigned long long)chain_slot[first]);
  pass = bad == 0;
  /* Run A: the radix inputs (none), the block inputs x<i>_<j> = cast i k + j, the params (none). */
  in = ok ? fopen("build/tfhe-chain-a-in.txt", "w") : NULL;
  for (j = 0; j < 2u && in != NULL && ok; j++) {
    ok = fhe_build(&fhe_c, j == 0 ? FHE_TALLY4 : FHE_TALLY3, 7);
    for (c = 0; c < fhe_c.block_ins && ok; c++)
      memcpy(fhe_bin[c], chain_cast[(j == 0 ? CHAIN_DEC : CHAIN_BALLOT) + c], sizeof fhe_bin[c]);
    pbs += fhe_c.pbs;
    if (ok) fhe_wasm_line(in);
  }
  ok = in != NULL && fclose(in) == 0 && ok &&
       system(tfhe_node_cmd(cmd, sizeof cmd, 0, "build/tfhe-chain-a-in.txt", "build/tfhe-chain-a-out.txt")) == 0;
  out = NULL;
  if (ok) out = fopen("build/tfhe-chain-a-out.txt", "r");
  ok = ok && out != NULL;
  for (c = 0; c < 7u && ok; c++) ok = read_words(out, (uint64_t *)chain_count[c].block, RADIX_WORDS);
  if (out != NULL) fclose(out);
  if (ok) {
    pass &= chain_tally_row(0, chain_count, k);
    pass &= chain_tally_row(1, chain_count + 4, k);
  }
  ok = ok && chain_stage_rows(k, &pbs, &pass);
  remove("build/tfhe-cksk.bin");
  remove("build/tfhe-ksk.bin");
  remove("build/tfhe-bsk.bin");
  if (!ok) puts("FAIL fhe chain: a module, a key file, an input or node failed (build/tfhe-chain-*.txt)");
  if (ok && pass) {
    remove("build/tfhe-chain-client-in.txt");
    remove("build/tfhe-chain-client-out.txt");
    remove("build/tfhe-chain-cast-in.txt");
    remove("build/tfhe-chain-cast-out.txt");
    remove("build/tfhe-chain-a-in.txt");
    remove("build/tfhe-chain-a-out.txt");
    remove("build/tfhe-chain-b-in.txt");
    remove("build/tfhe-chain-b-out.txt");
    remove("build/tfhe-chain-c-in.txt");
    remove("build/tfhe-chain-c-out.txt");
    remove("build/tfhe-chain-d-in.txt");
    remove("build/tfhe-chain-d-out.txt");
    remove("build/tfhe-chain-e-in.txt");
    remove("build/tfhe-chain-e-out.txt");
    printf("fhe chain (N 7): ballots DecE 7 x 4, BallotA 7 x 3 (client module, cast %d PBS); (1.1) tally4, tally3, "
           "theta, amd, settle, credit, withdraw (%u Wasm PBS); settle C = Wasm\n",
           CHAIN_CASTS, pbs);
  }
  return ok && pass;
}

static int tfhe_pke_rows(const TfheFft *f, const TfheKeys *k) {
  static const char key_seed[] = "charter-lang S5 U5 tfhe pke keys";
  static const char enc_seed[] = "charter-lang S5 U5 pke ballot 01";
  static TfhePke p;
  const uint64_t bound = (uint64_t)1 << 40;
  uint64_t rev[TFHE_POLY_N], prod[TFHE_POLY_N], mask[TFHE_POLY_N], body[TFHE_PLAIN];
  uint64_t ct[TFHE_BIG_N + 1], out[TFHE_BIG_N + 1], max_error = 0;
  uint8_t m[TFHE_PLAIN];
  unsigned j, got, error_log = 0;
  TfheDrbg d;
  int ok = 1;
  tfhe_drbg_init(&d, (const uint8_t *)key_seed);
  if (!tfhe_pke_generate(&p, k, &d)) {
    puts("FAIL tfhe pke keys");
    return 0;
  }
  for (j = 0; j < TFHE_POLY_N; j++) rev[j] = p.key[TFHE_POLY_N - 1u - j];
  tfhe_poly_mul_exact(prod, p.pk_a, rev);
  for (j = 0; j < TFHE_POLY_N; j++) {
    uint64_t e = p.pk_b[j] - prod[j];
    if (e + ((uint64_t)1 << TFHE_PKE_NOISE) > ((uint64_t)1 << (TFHE_PKE_NOISE + 1))) {
      printf("FAIL tfhe pke key noise %u: %lld\n", j, (long long)e);
      ok = 0;
    }
  }
  for (j = 0; j < TFHE_PLAIN; j++) m[j] = (uint8_t)j;
  tfhe_drbg_init(&d, (const uint8_t *)enc_seed);
  tfhe_pke_encrypt(mask, body, &p, m, TFHE_PLAIN, &d);
  for (j = 0; j < TFHE_PLAIN; j++) {
    uint64_t phase, error;
    tfhe_pke_expand(ct, mask, body[j], j);
    phase = tfhe_lwe_phase(ct, p.key, TFHE_BIG_N);
    error = phase - tfhe_encode(j);
    if (error >> 63) error = 0u - error;
    if (error > max_error) max_error = error;
    got = tfhe_decode(phase);
    if (got != j || error >= bound) {
      printf("FAIL tfhe pke expand %u: %u, error %llu\n", j, got, (unsigned long long)error);
      ok = 0;
    }
    tfhe_pke_cast(f, out, ct, &p, k);
    got = tfhe_decode(tfhe_lwe_phase(out, k->glwe_key, TFHE_BIG_N));
    if (got != j) {
      printf("FAIL tfhe pke cast %u: %u\n", j, got);
      ok = 0;
    }
  }
  while (error_log < 64u && (max_error >> error_log) != 0) error_log++;
  if (ok) {
    printf("tfhe pke: key noise %d coefficients, expand decode %d rows (max error below 2^%u), cast decode %d rows\n",
           TFHE_POLY_N, TFHE_PLAIN, error_log, TFHE_PLAIN);
  }
  ok = tfhe_pke_wasm_rows(f, k, &p, (const uint8_t *)enc_seed, mask, body) && ok;
  ok = fhe_chain_rows(k, &p) && ok;
  tfhe_pke_release(&p);
  return ok;
}

/* Miller-Rabin of p in F_p arithmetic with the 16 prime bases 2 to 53. Also
 * 2^13 exactly divides p - 1, w^2048 = -1 and w^4096 = 1. */
static int tshare_prime_rows(void) {
  static const unsigned bases[16] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};
  const TshareFe one = tshare_from_u64(1), minus_one = tshare_from_i64(-1);
  uint64_t d[TSHARE_LIMBS], e[TSHARE_LIMBS] = {2048, 0, 0};
  unsigned s = 0, k, r, i;
  memcpy(d, minus_one.w, sizeof d);
  while ((d[0] & 1u) == 0) {
    for (i = 0; i + 1 < TSHARE_LIMBS; i++) d[i] = (d[i] >> 1) | (d[i + 1] << 63);
    d[TSHARE_LIMBS - 1] >>= 1;
    s++;
  }
  if (s != TSHARE_TWO_ADICITY) {
    printf("FAIL tshare p - 1 has the factor 2^%u\n", s);
    return 0;
  }
  for (k = 0; k < 16; k++) {
    TshareFe x = tshare_pow(tshare_from_u64(bases[k]), d);
    if (tshare_eq(x, one) || tshare_eq(x, minus_one)) continue;
    for (r = 1; r < s; r++) {
      x = tshare_mul(x, x);
      if (tshare_eq(x, minus_one)) break;
    }
    if (r == s) {
      printf("FAIL tshare miller-rabin base %u\n", bases[k]);
      return 0;
    }
  }
  if (!tshare_eq(tshare_pow(tshare_root(), e), minus_one)) {
    puts("FAIL tshare w^2048");
    return 0;
  }
  e[0] = 4096;
  if (!tshare_eq(tshare_pow(tshare_root(), e), one)) {
    puts("FAIL tshare w^4096");
    return 0;
  }
  return 1;
}

/* The edges (p - 1)^2 = 1 and 0 - (p - 1) = 1. On random values: a / a = 1,
 * (a + b) c = a c + b c, (a - b) + b = a, and the root of a^2 is a or -a.
 * 3 is not a square, and the root of 0 is 0. */
static int tshare_field_rows(TfheDrbg *d) {
  const TshareFe one = tshare_from_u64(1), zero = tshare_from_u64(0), minus_one = tshare_from_i64(-1);
  TshareFe root;
  unsigned i;
  if (!tshare_eq(tshare_mul(minus_one, minus_one), one) || !tshare_eq(tshare_sub(zero, minus_one), one)) {
    puts("FAIL tshare field edges");
    return 0;
  }
  for (i = 0; i < 256; i++) {
    TshareFe a = tshare_random(d), b = tshare_random(d), c = tshare_random(d), square = tshare_mul(a, a);
    if (!tshare_eq(tshare_mul(a, tshare_inverse(a)), one)) {
      puts("FAIL tshare inverse");
      return 0;
    }
    if (!tshare_eq(tshare_mul(tshare_add(a, b), c), tshare_add(tshare_mul(a, c), tshare_mul(b, c)))) {
      puts("FAIL tshare distributive law");
      return 0;
    }
    if (!tshare_eq(tshare_add(tshare_sub(a, b), b), a)) {
      puts("FAIL tshare sub");
      return 0;
    }
    if (!tshare_sqrt(&root, square) || !(tshare_eq(root, a) || tshare_eq(root, tshare_sub(zero, a)))) {
      puts("FAIL tshare square root");
      return 0;
    }
  }
  if (tshare_sqrt(&root, tshare_from_u64(3))) {
    puts("FAIL tshare root of 3");
    return 0;
  }
  if (!tshare_sqrt(&root, zero) || !tshare_eq(root, zero)) {
    puts("FAIL tshare root of 0");
    return 0;
  }
  return 1;
}

/* The NTT product against the schoolbook negacyclic product on random
 * operands; the inverse NTT round trip; and output aliases of each input. */
static int tshare_ntt_rows(TfheDrbg *d) {
  static TshareNtt t;
  static TshareFe a[TSHARE_N], b[TSHARE_N], want[TSHARE_N], got[TSHARE_N];
  unsigned i, j;
  tshare_ntt_init(&t);
  for (j = 0; j < TSHARE_N; j++) {
    a[j] = tshare_random(d);
    b[j] = tshare_random(d);
  }
  for (i = 0; i < TSHARE_N; i++) {
    TshareFe acc = tshare_from_u64(0);
    for (j = 0; j <= i; j++) acc = tshare_add(acc, tshare_mul(a[j], b[i - j]));
    for (j = i + 1; j < TSHARE_N; j++) acc = tshare_sub(acc, tshare_mul(a[j], b[TSHARE_N + i - j]));
    want[i] = acc;
  }
  tshare_poly_mul(&t, got, a, b);
  for (i = 0; i < TSHARE_N; i++) {
    if (!tshare_eq(got[i], want[i])) {
      printf("FAIL tshare ntt product %u\n", i);
      return 0;
    }
  }
  memcpy(got, a, sizeof got);
  tshare_ntt_forward(&t, got);
  tshare_ntt_inverse(&t, got);
  for (i = 0; i < TSHARE_N; i++) {
    if (!tshare_eq(got[i], a[i])) {
      printf("FAIL tshare ntt round trip %u\n", i);
      return 0;
    }
  }
  for (j = 0; j < 2; j++) {
    memcpy(got, j == 0 ? a : b, sizeof got);
    tshare_poly_mul(&t, got, j == 0 ? got : a, j == 0 ? b : got);
    for (i = 0; i < TSHARE_N; i++) {
      if (!tshare_eq(got[i], want[i])) {
        printf("FAIL tshare ntt alias input %u coefficient %u\n", j, i);
        return 0;
      }
    }
  }
  memset(got, 0, sizeof got);
  got[0] = tshare_from_u64(1);
  got[TSHARE_N - 1] = tshare_from_u64(2);
  tshare_poly_mul(&t, got, got, got);
  for (i = 0; i < TSHARE_N; i++) {
    TshareFe square = tshare_from_i64(i == 0 ? 1 : i == TSHARE_N - 2 ? -4 : i == TSHARE_N - 1 ? 4 : 0);
    if (!tshare_eq(got[i], square)) {
      printf("FAIL tshare ntt in-place square %u\n", i);
      return 0;
    }
  }
  return 1;
}

/* (1.3) The S5 small key bits, lifted to F_p and shared. Each of the 16
 * subsets of 3, 4 or 5 parties gives the key. For each of the 10 sets of 2
 * parties, the combine refuses the set, and the interpolation at 0 gives no
 * key coordinate. A changed share fails its commitment at the combine; a
 * subset without that party still gives the key. */
static int tshare_key_rows(const uint64_t small_key[TFHE_LWE_N], TfheDrbg *d) {
  static TshareFe key[TFHE_LWE_N], shares[TSHARE_PARTIES * TFHE_LWE_N], got[TFHE_LWE_N];
  static const unsigned changed[3] = {1, 2, 3}, other[3] = {1, 3, 4};
  uint8_t commits[TSHARE_PARTIES][SHA512_BYTES];
  unsigned mask, i, m, large = 0, pairs = 0;
  size_t j;
  for (j = 0; j < TFHE_LWE_N; j++) key[j] = tshare_from_u64(small_key[j]);
  tshare_share(shares, key, TFHE_LWE_N, d);
  for (i = 0; i < TSHARE_PARTIES; i++) tshare_commit(commits[i], i + 1, shares + (size_t)i * TFHE_LWE_N, TFHE_LWE_N);
  for (mask = 1; mask < (1u << TSHARE_PARTIES); mask++) {
    unsigned subset[TSHARE_PARTIES];
    TshareFe lambda[TSHARE_PARTIES];
    size_t equal = 0;
    m = 0;
    for (i = 0; i < TSHARE_PARTIES; i++) {
      if ((mask >> i) & 1u) subset[m++] = i + 1;
    }
    if (m > TSHARE_THRESHOLD) {
      if (!tshare_combine(got, shares, TFHE_LWE_N, subset, m, commits) || memcmp(got, key, sizeof key) != 0) {
        printf("FAIL tshare key from set %u\n", mask);
        return 0;
      }
      large++;
    }
    if (m == TSHARE_THRESHOLD) {
      if (tshare_combine(got, shares, TFHE_LWE_N, subset, m, commits) || !tshare_lagrange(lambda, subset, m)) {
        printf("FAIL tshare set of 2 %u\n", mask);
        return 0;
      }
      for (j = 0; j < TFHE_LWE_N; j++) {
        TshareFe acc = tshare_from_u64(0);
        for (i = 0; i < m; i++) acc = tshare_add(acc, tshare_mul(lambda[i], shares[(size_t)(subset[i] - 1) * TFHE_LWE_N + j]));
        equal += tshare_eq(acc, key[j]);
      }
      if (equal != 0) {
        printf("FAIL tshare set of 2 %u gives %u key coordinates\n", mask, (unsigned)equal);
        return 0;
      }
      pairs++;
    }
  }
  if (large != 16 || pairs != 10) {
    printf("FAIL tshare subsets %u and %u\n", large, pairs);
    return 0;
  }
  shares[TFHE_LWE_N] = tshare_add(shares[TFHE_LWE_N], tshare_from_u64(1));
  if (tshare_combine(got, shares, TFHE_LWE_N, changed, 3, commits)) {
    puts("FAIL tshare changed share");
    return 0;
  }
  if (!tshare_combine(got, shares, TFHE_LWE_N, other, 3, commits) || memcmp(got, key, sizeof key) != 0) {
    puts("FAIL tshare set without the changed share");
    return 0;
  }
  return 1;
}

static int tshare_regressions(const uint64_t small_key[TFHE_LWE_N]) {
  static const char seed[] = "charter-lang S6 U1 tshare seeds.";
  TfheDrbg d;
  int ok;
  tfhe_drbg_init(&d, (const uint8_t *)seed);
  ok = tshare_prime_rows();
  ok &= tshare_field_rows(&d);
  ok &= tshare_ntt_rows(&d);
  ok &= tshare_key_rows(small_key, &d);
  return ok;
}

static Squash128 squash_row_word(uint64_t hi, uint64_t lo) {
  Squash128 r;
  r.hi = hi;
  r.lo = lo;
  return r;
}

/* |P - M 2^123| over Z/2^128. */
static Squash128 squash_row_error(Squash128 p, unsigned m) {
  Squash128 e = squash_sub(p, squash_shl(squash_from_u64(m), SQUASH_DELTA_LOG));
  return e.hi >> 63 ? squash_neg(e) : e;
}

/* The first J with X[j] different from Y[j], or N when the N words are equal. */
static unsigned squash_row_diff(const Squash128 *x, const Squash128 *y, unsigned n) {
  unsigned j = 0;
  while (j < n && squash_eq(x[j], y[j])) j++;
  return j;
}

/* The words of the noise squashing (front/squash.h). The u128 operations give
 * 9 fixed values. 4096 decompositions (the tie 2^55 and -1 are 2 of them) give
 * digits in [-2^23, 2^23], and the sum of the digits is within 2^55 of the
 * word. A GLWE of 2048 messages of 4 bits decrypts with a noise below 2^31.
 * For r 0 and 1, GGSW(r) x GLWE decrypts to r m. For r 1, the external
 * product is equal to the schoolbook rule on the same digits. Then 256 random
 * u128 identities. The f64 and NTT products are equal to the schoolbook rule
 * on one random product, and the f64 product is equal on a binary b. */
static int squash_regressions(void) {
  static const char seed[] = "charter-lang S6 U2a2 squash seed";
  static TfheFft f;
  static TshareNtt t;
  static SquashKey k;
  static SquashFftWork w;
  static SquashExtWork x;
  static SquashNttWork nw;
  static Squash128 m[SQUASH_POLY_N], p[SQUASH_POLY_N], a[SQUASH_POLY_N], want[SQUASH_POLY_N], got[SQUASH_POLY_N];
  static Squash128 ct[SQUASH_GLWE_WORDS], out[SQUASH_GLWE_WORDS], ref[SQUASH_GLWE_WORDS], g[SQUASH_GGSW_WORDS];
  static unsigned msg[SQUASH_POLY_N];
  static int64_t b[SQUASH_POLY_N];
  const Squash128 one = squash_from_u64(1);
  const int fixed[9] = {
      squash_eq(squash_add(squash_row_word(0, ~0ull), one), squash_row_word(1, 0)),
      squash_eq(squash_sub(squash_from_u64(0), one), squash_row_word(~0ull, ~0ull)),
      squash_eq(squash_neg(one), squash_from_i64(-1)),
      squash_eq(squash_mul(squash_row_word(1, 3), squash_row_word(1, 5)), squash_row_word(8, 15)),
      squash_eq(squash_mul(squash_row_word(0, ~0ull), squash_row_word(0, ~0ull)), squash_row_word(~0ull - 1, 1)),
      squash_eq(squash_shl(one, 127), squash_row_word(1ull << 63, 0)),
      squash_eq(squash_shl(squash_row_word(0, 0x8000000000000001ull), 1), squash_row_word(1, 2)),
      squash_eq(squash_shr(squash_row_word(1ull << 63, 0), 127), one),
      squash_eq(squash_shr(squash_row_word(1, 2), 1), squash_row_word(0, 0x8000000000000001ull))};
  int64_t digits[SQUASH_LEVEL];
  TfheDrbg d;
  unsigned r, j, q, i, l;
  tfhe_drbg_init(&d, (const uint8_t *)seed);
  tfhe_fft_init(&f);
  tshare_ntt_init(&t);
  for (r = 0; r < 9; r++) {
    if (!fixed[r]) {
      printf("FAIL squash u128 value %u\n", r);
      return 0;
    }
  }
  for (r = 0; r < 4096; r++) {
    Squash128 v = squash_uniform(&d), s = squash_from_u64(0), e;
    if (r == 0) v = squash_shl(one, 55);
    if (r == 1) v = squash_from_i64(-1);
    squash_decompose(digits, v);
    for (l = 0; l < SQUASH_LEVEL; l++) {
      if (digits[l] < -(1 << 23) || digits[l] > (1 << 23)) {
        printf("FAIL squash digit range %u\n", r);
        return 0;
      }
      s = squash_add(s, squash_mul(squash_from_i64(digits[l]), squash_shl(one, 104u - 24u * l)));
    }
    e = squash_sub(v, s);
    if (e.hi >> 63) e = squash_neg(e);
    if (e.hi != 0 || e.lo > (1ull << 55)) {
      printf("FAIL squash closest decomposition %u\n", r);
      return 0;
    }
  }
  squash_key_generate(&k, &d);
  for (j = 0; j < SQUASH_POLY_N; j++) {
    msg[j] = (unsigned)(tfhe_uniform(&d) & 15u);
    m[j] = squash_shl(squash_from_u64(msg[j]), SQUASH_DELTA_LOG);
  }
  squash_glwe_encrypt(&f, &w, ct, &k, m, &d);
  squash_glwe_phase(&f, &w, p, ct, &k);
  for (j = 0; j < SQUASH_POLY_N; j++) {
    Squash128 e = squash_row_error(p[j], msg[j]);
    if (e.hi != 0 || (e.lo >> 31) != 0) {
      printf("FAIL squash glwe decrypt %u\n", j);
      return 0;
    }
  }
  /* The last pass (r 1) keeps GGSW(1), the digits and the product for the
   * schoolbook rule. */
  for (r = 0; r < 2; r++) {
    squash_ggsw_encrypt(&f, &w, g, &k, (int64_t)r, &d);
    squash_external_product(&f, &x, out, g, ct);
    squash_glwe_phase(&f, &w, p, out, &k);
    for (j = 0; j < SQUASH_POLY_N; j++) {
      if ((squash_row_error(p[j], r * msg[j]).hi >> 58) != 0) {
        printf("FAIL squash external product decrypt %u %u\n", r, j);
        return 0;
      }
    }
  }
  memset(ref, 0, sizeof ref);
  for (q = 0; q < SQUASH_GGSW_ROWS; q++) {
    for (i = 0; i <= SQUASH_GLWE_K; i++) {
      squash_poly_mul_exact(want, g + ((size_t)q * (SQUASH_GLWE_K + 1) + i) * SQUASH_POLY_N, x.digit[q]);
      for (j = 0; j < SQUASH_POLY_N; j++) ref[i * SQUASH_POLY_N + j] = squash_add(ref[i * SQUASH_POLY_N + j], want[j]);
    }
  }
  j = squash_row_diff(out, ref, SQUASH_GLWE_WORDS);
  if (j < SQUASH_GLWE_WORDS) {
    printf("FAIL squash external product %u\n", j);
    return 0;
  }
  for (r = 0; r < 256; r++) {
    Squash128 u = squash_uniform(&d), v = squash_uniform(&d), z = squash_uniform(&d);
    if (!squash_eq(squash_mul(u, squash_add(v, z)), squash_add(squash_mul(u, v), squash_mul(u, z))) ||
        !squash_eq(squash_sub(squash_add(u, v), v), u) || !squash_eq(squash_mul(u, squash_from_u64(8)), squash_shl(u, 3))) {
      printf("FAIL squash u128 identity %u\n", r);
      return 0;
    }
  }
  for (j = 0; j < SQUASH_POLY_N; j++) {
    a[j] = squash_uniform(&d);
    b[j] = (int64_t)tfhe_tuniform(&d, SQUASH_SMALL_LOG);
  }
  b[0] = 1 << SQUASH_SMALL_LOG;
  b[1] = -(1 << SQUASH_SMALL_LOG);
  squash_poly_mul_exact(want, a, b);
  squash_poly_mul_fft(&f, &w, got, a, b);
  j = squash_row_diff(got, want, SQUASH_POLY_N);
  if (j < SQUASH_POLY_N) {
    printf("FAIL squash fft product %u\n", j);
    return 0;
  }
  squash_poly_mul_ntt(&t, &nw, got, a, b);
  j = squash_row_diff(got, want, SQUASH_POLY_N);
  if (j < SQUASH_POLY_N) {
    printf("FAIL squash ntt product %u\n", j);
    return 0;
  }
  for (j = 0; j < SQUASH_POLY_N; j++) b[j] = (int64_t)(tfhe_uniform(&d) & 1u);
  squash_poly_mul_exact(want, a, b);
  squash_poly_mul_fft(&f, &w, got, a, b);
  j = squash_row_diff(got, want, SQUASH_POLY_N);
  if (j < SQUASH_POLY_N) {
    printf("FAIL squash fft product of a binary b %u\n", j);
    return 0;
  }
  return 1;
}

/* OUT = X^(-R) IN mod (X^N + 1), R < 2N: coefficient j is IN[j + R], with
 * the sign -1 for each pass of N. */
static void squash_row_rotate(Squash128 out[SQUASH_POLY_N], const Squash128 in[SQUASH_POLY_N], unsigned r) {
  unsigned j;
  for (j = 0; j < SQUASH_POLY_N; j++) {
    unsigned k = j + r;
    out[j] = k < SQUASH_POLY_N        ? in[k]
             : k < 2u * SQUASH_POLY_N ? squash_neg(in[k - SQUASH_POLY_N])
                                      : in[k - 2u * SQUASH_POLY_N];
  }
}

/* The parts of the squash PBS (front/squash.h, U2b) without the 812 MB BSK;
 * `make check-squash` runs the full squash PBS (Q-S6-13). The LUT: box m
 * holds m 2^123, then the polynomial is multiplied by X^(-64). The LWE phase
 * of the sample extract of a random GLWE is coefficient 0 of its GLWE phase.
 * With a mask of 0 (no CMux), the blind rotation gives the trivial GLWE of
 * X^(-b) LUT for 10 values of b in [0, 2N), b >= N included. Over a BSK of 4
 * GGSW (a_i = 0 for i >= 4), the blind rotation decrypts to X^(-r) LUT with
 * r = b - sum a_i s_i mod 2N and a noise below 2^90. */
static int squash_pbs_regressions(void) {
  static const char seed[] = "charter-lang S6 U2b2 squash rows";
  static TfheFft f;
  static SquashKey k;
  static SquashFftWork w;
  static SquashPbsWork pw;
  static Squash128 lut[SQUASH_POLY_N], m[SQUASH_POLY_N], p[SQUASH_POLY_N], want[SQUASH_POLY_N];
  static Squash128 ct[SQUASH_GLWE_WORDS], out[SQUASH_BIG_N + 1], zero[SQUASH_GLWE_K * SQUASH_POLY_N];
  static uint64_t sw[TFHE_LWE_N + 1];
  const unsigned box = SQUASH_POLY_N / TFHE_PLAIN, half = box / 2u;
  const unsigned bs[10] = {0, 1, 63, 64, 384, SQUASH_POLY_N - 1, SQUASH_POLY_N, SQUASH_POLY_N + 64,
                           SQUASH_POLY_N + 384, 2 * SQUASH_POLY_N - 1};
  const int64_t s[4] = {1, 0, 1, 1};
  SquashBsk bsk;
  Squash128 e;
  TfheDrbg d;
  unsigned i, j, r;
  tfhe_drbg_init(&d, (const uint8_t *)seed);
  tfhe_fft_init(&f);
  squash_lut(lut);
  for (i = 0; i < SQUASH_POLY_N; i++) {
    Squash128 v = squash_shl(squash_from_u64(i / box), SQUASH_DELTA_LOG);
    j = i >= half ? i - half : i + SQUASH_POLY_N - half;
    if (!squash_eq(lut[j], i >= half ? v : squash_neg(v))) {
      printf("FAIL squash lut %u\n", j);
      return 0;
    }
  }
  squash_key_generate(&k, &d);
  for (j = 0; j < SQUASH_POLY_N; j++) m[j] = squash_uniform(&d);
  squash_glwe_encrypt(&f, &w, ct, &k, m, &d);
  squash_glwe_phase(&f, &w, p, ct, &k);
  squash_sample_extract(out, ct);
  e = out[SQUASH_BIG_N];
  for (i = 0; i < SQUASH_GLWE_K; i++)
    for (j = 0; j < SQUASH_POLY_N; j++)
      if (k.s[i][j] != 0) e = squash_sub(e, out[i * SQUASH_POLY_N + j]);
  if (!squash_eq(e, p[0])) {
    puts("FAIL squash sample extract phase");
    return 0;
  }
  memset(sw, 0, sizeof sw);
  bsk.ggsw = NULL;
  for (r = 0; r < 10; r++) {
    sw[TFHE_LWE_N] = bs[r];
    squash_blind_rotate(&f, &pw, sw, lut, &bsk);
    squash_row_rotate(want, lut, bs[r]);
    if (squash_row_diff(pw.acc, zero, SQUASH_GLWE_K * SQUASH_POLY_N) < SQUASH_GLWE_K * SQUASH_POLY_N ||
        squash_row_diff(pw.acc + SQUASH_GLWE_K * SQUASH_POLY_N, want, SQUASH_POLY_N) < SQUASH_POLY_N) {
      printf("FAIL squash blind rotation with a mask of 0, b %u\n", bs[r]);
      return 0;
    }
  }
  bsk.ggsw = malloc((size_t)4 * SQUASH_GGSW_WORDS * sizeof bsk.ggsw[0]);
  if (bsk.ggsw == NULL) {
    puts("FAIL squash partial bsk");
    return 0;
  }
  for (i = 0; i < 4; i++) squash_ggsw_encrypt(&f, &w, bsk.ggsw + (size_t)i * SQUASH_GGSW_WORDS, &k, s[i], &d);
  r = (unsigned)(tfhe_uniform(&d) % (2u * SQUASH_POLY_N));
  sw[TFHE_LWE_N] = r;
  for (i = 0; i < 4; i++) {
    sw[i] = tfhe_uniform(&d) % (2u * SQUASH_POLY_N);
    if (s[i] != 0) r = (r + 2u * SQUASH_POLY_N - (unsigned)sw[i]) % (2u * SQUASH_POLY_N);
  }
  squash_blind_rotate(&f, &pw, sw, lut, &bsk);
  free(bsk.ggsw);
  squash_glwe_phase(&f, &w, p, pw.acc, &k);
  squash_row_rotate(want, lut, r);
  for (j = 0; j < SQUASH_POLY_N; j++) {
    e = squash_sub(p[j], want[j]);
    if (e.hi >> 63) e = squash_neg(e);
    if ((e.hi >> 26) != 0) {
      printf("FAIL squash blind rotation over 4 GGSW %u\n", j);
      return 0;
    }
  }
  return 1;
}


/* Threshold decryption of (MASK, BODY) by the M parties in SUBSET (U3). The
 * test dealer gave the key shares SHARES (party i holds the 4096 values at
 * (i - 1) 4096); each party in SUBSET also deals a flood noise. */
static int tdec_run(Squash128 *phase, TshareFe *partial, const TshareFe *shares, const Squash128 *mask, Squash128 body,
                    const unsigned *subset, unsigned m, TfheDrbg *d) {
  static TshareFe noise[TSHARE_PARTIES * TSHARE_PARTIES];
  unsigned i;
  for (i = 0; i < m; i++) tdec_flood(noise + i * TSHARE_PARTIES, d);
  for (i = 0; i < m; i++)
    partial[i] = tdec_partial(shares + (size_t)(subset[i] - 1) * SQUASH_BIG_N, mask, noise, m, subset[i]);
  return tdec_combine(phase, body, partial, subset, m);
}

/* A squash LWE of V: a uniform mask, body = <a, s> + V Delta_128 + e with
 * e = 2^66 - 1 for an even V and -(2^66 - 1) for an odd V (the U2b bound). */
static Squash128 tdec_lwe(Squash128 mask[SQUASH_BIG_N], const SquashKey *k, unsigned v, TfheDrbg *d) {
  Squash128 e = squash_sub(squash_shl(squash_from_u64(1), 66), squash_from_u64(1));
  Squash128 b = squash_add(squash_shl(squash_from_u64(v), SQUASH_DELTA_LOG), (v & 1u) ? squash_neg(e) : e);
  unsigned j;
  for (j = 0; j < SQUASH_BIG_N; j++) {
    mask[j] = squash_uniform(d);
    if (k->s[j / SQUASH_POLY_N][j % SQUASH_POLY_N] != 0) b = squash_add(b, mask[j]);
  }
  return b;
}

/* 1 when the integer of V (V - p above (p - 1) / 2) is in (-5 2^106, 5 2^106). */
static int tdec_small(TshareFe v) {
  TshareFe n = tshare_sub(tshare_from_u64(0), v);
  return (v.w[2] == 0 && v.w[1] < (5ull << 42)) || (n.w[2] == 0 && n.w[1] < (5ull << 42));
}

/* The threshold decryption (front/tdec.h, U3) under a test dealer of the
 * squash key: the messages 0 to 15 with S = {1, ..., 5}, one message for
 * each of the 10 sets of 3, and the blocks of p = 0x123456789ABCDEF0. The
 * combine of shared known values gives the exact phase (the centered lift at
 * (p - 1) / 2). A set of 2, a bad set, and one changed partial give no phase.
 * The flood row: the value at 0 minus the clear <a, s> is E, not 0, with
 * |E| below 5 2^106. The flood sign row: the shares of a flood noise e give
 * e at 0 for e >= 0 and p - |e| for e < 0. */
static int tdec_regressions(void) {
  static const char seed[] = "charter-lang S6 U3 tdec seed!!!!";
  static SquashKey k;
  static TshareFe key[SQUASH_BIG_N], shares[TSHARE_PARTIES * SQUASH_BIG_N];
  static Squash128 mask[SQUASH_BIG_N];
  static const unsigned all[TSHARE_PARTIES] = {1, 2, 3, 4, 5};
  static const unsigned bad[4] = {1, 2, 3, 1};
  const uint64_t p = 0x123456789ABCDEF0u;
  TshareFe partial[TSHARE_PARTIES], x[TSHARE_PARTIES], lambda[3], v0, e, hp;
  TshareFe known[4];
  Squash128 want[4], body, ph, fu, fe;
  unsigned subset[3], i, j, a, b, c, v, n = 0, neg = 0, sgn;
  uint64_t got = 0;
  TfheDrbg d, dc;
  int ok = 1;
  tfhe_drbg_init(&d, (const uint8_t *)seed);
  squash_key_generate(&k, &d);
  for (j = 0; j < SQUASH_BIG_N; j++) key[j] = tshare_from_u64((uint64_t)k.s[j / SQUASH_POLY_N][j % SQUASH_POLY_N]);
  tshare_share(shares, key, SQUASH_BIG_N, &d);

  /* (1.3) v 0 to 15, S = {1, ..., 5}. */
  for (v = 0; v < 16; v++) {
    body = tdec_lwe(mask, &k, v, &d);
    ok &= tdec_run(&ph, partial, shares, mask, body, all, TSHARE_PARTIES, &d) && tdec_decode(ph) == v;
  }
  /* The 10 sets of 3: set n decodes v = n. */
  for (a = 1; a <= 3; a++)
    for (b = a + 1; b <= 4; b++)
      for (c = b + 1; c <= 5; c++) {
        subset[0] = a;
        subset[1] = b;
        subset[2] = c;
        body = tdec_lwe(mask, &k, n, &d);
        ok &= tdec_run(&ph, partial, shares, mask, body, subset, 3, &d) && tdec_decode(ph) == n;
        n++;
      }
  ok &= n == 10;
  /* The blocks of p (the 2-bit digits), S = {1, ..., 5}. */
  for (i = 0; i < 32; i++) {
    body = tdec_lwe(mask, &k, (unsigned)(p >> (2u * i)) & 3u, &d);
    ok &= tdec_run(&ph, partial, shares, mask, body, all, TSHARE_PARTIES, &d);
    got |= (uint64_t)(tdec_decode(ph) & 3u) << (2u * i);
  }
  ok &= got == p;

  /* No phase: a set of 2, a bad set, one changed partial of a set of 4 or 5. */
  body = tdec_lwe(mask, &k, 7, &d);
  ok &= !tdec_run(&ph, partial, shares, mask, body, all, 2, &d);
  ok &= !tdec_run(&ph, partial, shares, mask, body, bad, 4, &d);
  ok &= tdec_run(&ph, partial, shares, mask, body, all, 4, &d) && tdec_decode(ph) == 7;
  for (i = 0; i < 4; i++) {
    partial[i] = tshare_add(partial[i], tshare_from_u64(1));
    ok &= !tdec_combine(&ph, body, partial, all, 4);
    partial[i] = tshare_sub(partial[i], tshare_from_u64(1));
  }
  ok &= tdec_combine(&ph, body, partial, all, 4) && tdec_decode(ph) == 7;
  ok &= tdec_run(&ph, partial, shares, mask, body, all, TSHARE_PARTIES, &d);
  partial[4] = tshare_add(partial[4], tshare_from_u64(1));
  ok &= !tdec_combine(&ph, body, partial, all, TSHARE_PARTIES);

  /* The exact phase for the shared values 5, -5, (p - 1) / 2 and
   * (p + 1) / 2 (the integer -(p - 1) / 2), with body 0. (p - 1) / 2 is
   * 2^128 - 626688 mod 2^128. */
  hp = tshare_inverse(tshare_from_u64(2));
  known[0] = tshare_from_u64(5);
  known[1] = tshare_from_i64(-5);
  known[2] = tshare_sub(hp, tshare_from_u64(1));
  known[3] = hp;
  want[0] = squash_neg(squash_from_u64(5));
  want[1] = squash_from_u64(5);
  want[2] = squash_from_u64(626688);
  want[3] = squash_neg(squash_from_u64(626688));
  for (i = 0; i < 4; i++) {
    tshare_share(x, known + i, 1, &d);
    ok &= tdec_combine(&ph, squash_from_u64(0), x, all, TSHARE_PARTIES) && squash_eq(ph, want[i]);
  }

  /* The flood row: E = V0 - <a, s> over F_p (V0 over the parties 1 to 3). */
  ok &= tdec_run(&ph, partial, shares, mask, body, all, TSHARE_PARTIES, &d) && tshare_lagrange(lambda, all, 3);
  v0 = tshare_from_u64(0);
  for (i = 0; i < 3; i++) v0 = tshare_add(v0, tshare_mul(lambda[i], partial[i]));
  e = tshare_sub(v0, tdec_mask_product(key, mask));
  ok &= !tshare_eq(e, tshare_from_u64(0)) && tdec_small(e);

  /* The flood sign row: for 8 noises, a copy of the DRBG gives the 2 words
   * of tdec_flood, so e = u - 2^106. The value at 0 of the shares of the
   * parties 1 to 3 is e for e >= 0, and p - |e| (value + |e| = 0) for
   * e < 0. The 8 noises have the two signs. */
  ok &= tshare_lagrange(lambda, all, 3);
  for (i = 0; i < 8; i++) {
    dc = d;
    fu.lo = tfhe_uniform(&dc);
    fu.hi = tfhe_uniform(&dc) & ((1ull << (TDEC_FLOOD_LOG + 1 - 64)) - 1u);
    fe = squash_sub(fu, squash_shl(squash_from_u64(1), TDEC_FLOOD_LOG));
    tdec_flood(x, &d);
    v0 = tshare_from_u64(0);
    for (j = 0; j < 3; j++) v0 = tshare_add(v0, tshare_mul(lambda[j], x[j]));
    sgn = (unsigned)(fe.hi >> 63);
    fe = sgn ? squash_neg(fe) : fe;
    e.w[0] = fe.lo;
    e.w[1] = fe.hi;
    e.w[2] = 0;
    ok &= sgn ? tshare_eq(tshare_add(v0, e), tshare_from_u64(0)) : tshare_eq(v0, e);
    neg += sgn;
  }
  ok &= neg > 0 && neg < 8;
  return ok;
}

/* Also writes the small key to SMALL_KEY for the tshare rows. */
static int tfhe_regressions(uint64_t small_key[TFHE_LWE_N]) {
  static const char seed[] = "charter-lang S5 U1 tfhe test key";
  TfheFft f;
  TfheKeys k;
  TfheDrbg d;
  int ok;
  tfhe_fft_init(&f);
  tfhe_drbg_init(&d, (const uint8_t *)seed);
  if (!tfhe_keys_generate(&k, &f, &d)) {
    puts("FAIL tfhe keys");
    return 0;
  }
  memcpy(small_key, k.lwe_key, sizeof k.lwe_key);
  ok = tfhe_tuniform_rows(&d);
  ok &= tfhe_fft_rows(&f, &k, &d);
  ok &= tfhe_pbs_rows(&f, &k, &d);
  ok &= tfhe_wasm_rows(&f, &d);
  ok &= tfhe_pbs_wasm_rows(&f, &k, &d);
  ok &= tfhe_radix_rows(&f, &k, &d);
  ok &= tfhe_fhe_rows(&f, &k, &d);
  ok &= tfhe_pke_rows(&f, &k);
  tfhe_keys_release(&k);
  return ok;
}

/* The tkeygen rows (S6b U4a, W/S6-NOTES.md "## S6b plan", r1 to r5). */
enum { TKEYGEN_ROW_BITS = 64, TKEYGEN_ROW_NOISE = 820, TKEYGEN_ROW_DEGREE = 16 };

/* The 10 sets of 3 parties. */
static const unsigned tkeygen_subsets[10][3] = {{1, 2, 3}, {1, 2, 4}, {1, 2, 5}, {1, 3, 4}, {1, 3, 5},
                                                {1, 4, 5}, {2, 3, 4}, {2, 3, 5}, {2, 4, 5}, {3, 4, 5}};
static const unsigned tkeygen_all[TSHARE_PARTIES] = {1, 2, 3, 4, 5};

/* The Lagrange coefficients at 0 of each set of 3 and of the 5 parties. */
typedef struct TkeygenLambda {
  TshareFe set[10][3];
  TshareFe all[TSHARE_PARTIES];
} TkeygenLambda;

static int tkeygen_lambda(TkeygenLambda *l) {
  unsigned s;
  int ok = tshare_lagrange(l->all, tkeygen_all, TSHARE_PARTIES);
  for (s = 0; s < 10; s++) ok &= tshare_lagrange(l->set[s], tkeygen_subsets[s], 3);
  return ok;
}

/* The 5 party DRBGs: party j from SEED with its last byte set to the digit j. */
static void tkeygen_parties(TfheDrbg party[TSHARE_PARTIES], const char *seed) {
  uint8_t s[TFHE_SEED_BYTES];
  unsigned j;
  memcpy(s, seed, TFHE_SEED_BYTES);
  for (j = 0; j < TSHARE_PARTIES; j++) {
    s[TFHE_SEED_BYTES - 1] = (uint8_t)('1' + j);
    tfhe_drbg_init(&party[j], s);
  }
}

/* The value at 0 of secret J (the layout of tshare_share with COUNT) from the
 * shares of the M parties in SUBSET; LAMBDA holds their coefficients. */
static TshareFe tkeygen_at0(const TshareFe *lambda, const TshareFe *shares, size_t count, size_t j,
                            const unsigned *subset, unsigned m) {
  TshareFe v = tshare_from_u64(0);
  unsigned i;
  for (i = 0; i < m; i++) v = tshare_add(v, tshare_mul(lambda[i], shares[(subset[i] - 1) * count + j]));
  return v;
}

/* (r1) The 5 parties get the same joint seed and the same masks; a changed
 * seed or commitment of one party gives no joint seed. */
static int tkeygen_toss_rows(TfheDrbg party[TSHARE_PARTIES]) {
  static TkeygenToss toss, view;
  uint8_t joint[SHA512_BYTES], want[SHA512_BYTES];
  TfheDrbg masks, direct;
  Sha512 s;
  uint64_t first;
  unsigned i, j;
  int ok = 1;
  for (j = 1; j <= TSHARE_PARTIES; j++) ok &= tkeygen_toss_draw(&toss, j, &party[j - 1]);
  ok &= tkeygen_toss_check(&toss) && memcmp(toss.seed[0], toss.seed[1], TKEYGEN_SEED_BYTES) != 0;
  sha512_init(&s);
  for (j = 0; j < TSHARE_PARTIES; j++) sha512_update(&s, toss.seed[j], TKEYGEN_SEED_BYTES);
  sha512_final(&s, want);
  tfhe_drbg_init(&direct, want);
  first = tfhe_uniform(&direct);
  /* Each party uses its own copy of the commitments and the seeds. */
  for (i = 0; i < TSHARE_PARTIES; i++) {
    view = toss;
    ok &= tkeygen_toss_joint(joint, &masks, &view) && memcmp(joint, want, SHA512_BYTES) == 0 &&
          tfhe_uniform(&masks) == first;
  }
  for (j = 0; j < TSHARE_PARTIES; j++) {
    view = toss;
    view.seed[j][j] ^= 1u;
    ok &= !tkeygen_toss_check(&view) && !tkeygen_toss_joint(joint, &masks, &view);
    view = toss;
    view.commit[j][SHA512_BYTES - 1] ^= 0x80u;
    ok &= !tkeygen_toss_joint(joint, &masks, &view);
  }
  ok &= !tkeygen_toss_draw(&view, 0, &party[0]) && !tkeygen_toss_draw(&view, 6, &party[0]);
  return ok;
}

/* (r2) 64 shared bits: the 10 sets of 3 give one value, 0 or 1; both occur. */
static int tkeygen_bit_rows(TfheDrbg party[TSHARE_PARTIES], const TkeygenLambda *l) {
  static TshareFe bits[TSHARE_PARTIES * TKEYGEN_ROW_BITS];
  const TshareFe zero = tshare_from_u64(0), one = tshare_from_u64(1);
  unsigned j, s, ones = 0;
  int ok = 1;
  tkeygen_bits(bits, TKEYGEN_ROW_BITS, party);
  for (j = 0; j < TKEYGEN_ROW_BITS; j++) {
    TshareFe v = tkeygen_at0(l->set[0], bits, TKEYGEN_ROW_BITS, j, tkeygen_subsets[0], 3);
    ok &= tshare_eq(v, zero) || tshare_eq(v, one);
    ones += (unsigned)tshare_eq(v, one);
    for (s = 1; s < 10; s++)
      ok &= tshare_eq(tkeygen_at0(l->set[s], bits, TKEYGEN_ROW_BITS, j, tkeygen_subsets[s], 3), v);
  }
  return ok && ones > 0 && ones < TKEYGEN_ROW_BITS;
}

/* (r3) The 5 opened shares are not the r_i^2 (the zero sharing is in), and
 * their degree-2t polynomial has the value r^2 at 0. */
static int tkeygen_square_rows(TfheDrbg party[TSHARE_PARTIES], const TkeygenLambda *l) {
  TkeygenBit b;
  TshareFe r, v;
  unsigned i, n;
  int ok = 1;
  for (n = 0; n < 8; n++) {
    ok &= tkeygen_bit_try(&b, party);
    r = tkeygen_at0(l->set[n], b.r, 1, 0, tkeygen_subsets[n], 3);
    v = tkeygen_at0(l->all, b.opened, 1, 0, tkeygen_all, TSHARE_PARTIES);
    ok &= tshare_eq(v, tshare_mul(r, r)) && tshare_eq(b.square, v);
    for (i = 0; i < TSHARE_PARTIES; i++) ok &= !tshare_eq(b.opened[i], tshare_mul(b.r[i], b.r[i]));
  }
  return ok;
}

/* (r4) Party noise, 5 x 820 samples for each b - 1 in {16, 44}: each
 * |e| <= 2^(b - 1) and one |e| > 2^(b - 2) at least; the dealt shares give the
 * sum of the 5 noises (degree t: each set of 3; degree 2t: the 5 parties). */
static int tkeygen_noise_rows(TfheDrbg party[TSHARE_PARTIES], const TkeygenLambda *l) {
  static TshareFe shares[TSHARE_PARTIES * TKEYGEN_ROW_NOISE], sum[TSHARE_PARTIES * TKEYGEN_ROW_NOISE];
  static uint64_t e[TSHARE_PARTIES][TKEYGEN_ROW_NOISE];
  static const unsigned set_log[2] = {TFHE_GLWE_NOISE, TFHE_LWE_NOISE};
  const uint64_t big = (uint64_t)1 << 62;
  unsigned s, j, k;
  int ok = 1;
  ok &= tshare_eq(tkeygen_lift(0u - (uint64_t)1), tshare_from_i64(-1)) &&
        tshare_eq(tkeygen_lift(big), tshare_from_u64(big)) &&
        tshare_eq(tkeygen_lift(0u - big), tshare_sub(tshare_from_u64(0), tshare_from_u64(big)));
  for (s = 0; s < 2; s++) {
    const uint64_t bound = (uint64_t)1 << (set_log[s] - 1u);
    unsigned above = 0;
    for (k = 0; k < TSHARE_PARTIES * TKEYGEN_ROW_NOISE; k++) sum[k] = tshare_from_u64(0);
    for (j = 0; j < TSHARE_PARTIES; j++) {
      tkeygen_noise(shares, e[j], TKEYGEN_ROW_NOISE, set_log[s], TKEYGEN_DEGREE_T, &party[j]);
      tkeygen_add(sum, shares, TKEYGEN_ROW_NOISE);
      for (k = 0; k < TKEYGEN_ROW_NOISE; k++) {
        const uint64_t m = e[j][k] >> 63 ? 0u - e[j][k] : e[j][k];
        ok &= m <= bound;
        above += (unsigned)(m > bound / 2u);
      }
    }
    ok &= above > 0;
    for (k = 0; k < TKEYGEN_ROW_NOISE; k++) {
      uint64_t t = 0;
      for (j = 0; j < TSHARE_PARTIES; j++) t += e[j][k];
      ok &= tshare_eq(tkeygen_at0(l->set[k % 10], sum, TKEYGEN_ROW_NOISE, k, tkeygen_subsets[k % 10], 3),
                      tkeygen_lift(t));
    }
    tkeygen_noise(shares, e[0], TKEYGEN_ROW_DEGREE, set_log[s], TKEYGEN_DEGREE_2T, &party[1]);
    for (k = 0; k < TKEYGEN_ROW_DEGREE; k++)
      ok &= tshare_eq(tkeygen_at0(l->all, shares, TKEYGEN_ROW_DEGREE, k, tkeygen_all, TSHARE_PARTIES),
                      tkeygen_lift(e[0][k]));
  }
  return ok;
}

/* (r5) A degree-t dealing is tshare_share and each set of 3 gives the
 * secret; a degree-2t dealing gives the secret from the 5 parties and from no
 * set of 3 (it is not on a degree-t polynomial). */
static int tkeygen_degree_rows(TfheDrbg party[TSHARE_PARTIES], const TkeygenLambda *l) {
  static TshareFe secret[TKEYGEN_ROW_DEGREE], low[TSHARE_PARTIES * TKEYGEN_ROW_DEGREE],
      plain[TSHARE_PARTIES * TKEYGEN_ROW_DEGREE], high[TSHARE_PARTIES * TKEYGEN_ROW_DEGREE];
  TfheDrbg a = party[0], b = party[0];
  unsigned k, s;
  int ok = tkeygen_degree(TKEYGEN_DEGREE_T) == 2 && tkeygen_degree(TKEYGEN_DEGREE_2T) == 4;
  for (k = 0; k < TKEYGEN_ROW_DEGREE; k++) secret[k] = tshare_random(&party[1]);
  tkeygen_deal(low, secret, TKEYGEN_ROW_DEGREE, TKEYGEN_DEGREE_T, &a);
  tshare_share(plain, secret, TKEYGEN_ROW_DEGREE, &b);
  ok &= memcmp(low, plain, sizeof low) == 0;
  tkeygen_deal(high, secret, TKEYGEN_ROW_DEGREE, TKEYGEN_DEGREE_2T, &party[2]);
  for (k = 0; k < TKEYGEN_ROW_DEGREE; k++) {
    ok &= tshare_eq(tkeygen_at0(l->all, high, TKEYGEN_ROW_DEGREE, k, tkeygen_all, TSHARE_PARTIES), secret[k]);
    for (s = 0; s < 10; s++) {
      ok &= tshare_eq(tkeygen_at0(l->set[s], low, TKEYGEN_ROW_DEGREE, k, tkeygen_subsets[s], 3), secret[k]);
      ok &= !tshare_eq(tkeygen_at0(l->set[s], high, TKEYGEN_ROW_DEGREE, k, tkeygen_subsets[s], 3), secret[k]);
    }
  }
  return ok;
}

static int tkeygen_regressions(void) {
  static const char seed[] = "charter-lang S6b U4a tkeygen!!!!";
  TfheDrbg party[TSHARE_PARTIES];
  TkeygenLambda l;
  int ok;
  tkeygen_parties(party, seed);
  ok = tkeygen_lambda(&l);
  ok &= tkeygen_toss_rows(party);
  ok &= tkeygen_bit_rows(party, &l);
  ok &= tkeygen_square_rows(party, &l);
  ok &= tkeygen_noise_rows(party, &l);
  ok &= tkeygen_degree_rows(party, &l);
  return ok;
}

/* The tkeygen opening rows (S6b U4b, W/S6-NOTES.md "## S6b plan" steps 6 and
 * 7, o1 to o5). After the U4a rows: they use tkeygen_parties, tkeygen_lambda,
 * tkeygen_at0 and tkeygen_subsets. */

/* The test keys: clear random bits and their shares (degree t, from a dealer
 * DRBG). The openings use the shares. The checks use the clear keys, after a
 * check that the shares of the parties 2, 4 and 5 give them. */
typedef struct TkeygenTest {
  TkeygenShares s;
  TkeygenWork w;
  uint64_t lwe[TFHE_LWE_N];
  uint64_t glwe[TFHE_POLY_N];
  TfheDrbg masks;
  TfheDrbg party[TSHARE_PARTIES];
} TkeygenTest;

/* |E| <= 5 2^(B - 1): the bound of the sum of the 5 party noises. */
static int tkeygen_small(int64_t e, unsigned b) {
  const int64_t bound = (int64_t)5 << (b - 1u);
  return e >= -bound && e <= bound;
}

/* 1 when the shares of the parties 2, 4 and 5 (set 8) give the clear bit of
 * each of the COUNT secrets. */
static int tkeygen_test_back(const TkeygenLambda *l, const TshareFe *shares, size_t count, const uint64_t *bit) {
  size_t j;
  int ok = 1;
  for (j = 0; j < count; j++)
    ok &= tshare_eq(tkeygen_at0(l->set[8], shares, count, j, tkeygen_subsets[8], 3), tshare_from_u64(bit[j]));
  return ok;
}

static int tkeygen_test_init(TkeygenTest *t) {
  static const char seed[] = "charter-lang S6b U4b openings!!!";
  TshareFe *secret = malloc(SQUASH_BIG_N * sizeof *secret);
  uint64_t *bit = malloc(SQUASH_BIG_N * sizeof *bit);
  TkeygenLambda l;
  TfheDrbg d;
  size_t j;
  int ok;
  if (secret == NULL || bit == NULL) {
    free(secret);
    free(bit);
    return 0;
  }
  tkeygen_parties(t->party, seed);
  tfhe_drbg_init(&t->masks, (const uint8_t *)"charter-lang S6b U4b coin toss!!");
  tfhe_drbg_init(&d, (const uint8_t *)"charter-lang S6b U4b the dealer!");
  tkeygen_work_init(&t->w);
  ok = tkeygen_lambda(&l);
  for (j = 0; j < TFHE_LWE_N; j++) {
    t->lwe[j] = tfhe_drbg_bytes(&d, 1) & 1u;
    secret[j] = tshare_from_u64(t->lwe[j]);
  }
  tshare_share(&t->s.lwe[0][0], secret, TFHE_LWE_N, &d);
  for (j = 0; j < TFHE_POLY_N; j++) {
    t->glwe[j] = tfhe_drbg_bytes(&d, 1) & 1u;
    secret[j] = tshare_from_u64(t->glwe[j]);
  }
  tshare_share(&t->s.glwe[0][0], secret, TFHE_POLY_N, &d);
  for (j = 0; j < SQUASH_BIG_N; j++) {
    bit[j] = tfhe_drbg_bytes(&d, 1) & 1u;
    secret[j] = tshare_from_u64(bit[j]);
  }
  tshare_share(&t->s.squash[0][0], secret, SQUASH_BIG_N, &d);
  ok &= tkeygen_test_back(&l, &t->s.lwe[0][0], TFHE_LWE_N, t->lwe);
  ok &= tkeygen_test_back(&l, &t->s.glwe[0][0], TFHE_POLY_N, t->glwe);
  ok &= tkeygen_test_back(&l, &t->s.squash[0][0], SQUASH_BIG_N, bit);
  free(secret);
  free(bit);
  return ok;
}

/* The first small key bit that is 1 (the GGSW rows use it). */
static size_t tkeygen_test_one(const TkeygenTest *t) {
  size_t i = 0;
  while (i + 1 < TFHE_LWE_N && t->lwe[i] == 0) i++;
  return i;
}

/* (o1) One KSK row (glwe bit 7, level 2): the phase under the small key is
 * bit 2^56 plus a noise of at most 5 2^44. (o4, LWE) The phase minus the
 * plaintext is the noise sum of the 5 dealers (exact). */
static int tkeygen_lwe_open_rows(TkeygenTest *t) {
  uint64_t ct[TFHE_LWE_N + 1], esum, phase;
  TshareFe plain[TSHARE_PARTIES];
  const TshareFe g = tshare_from_u64((uint64_t)1 << 56);
  unsigned i;
  for (i = 0; i < TSHARE_PARTIES; i++) plain[i] = tshare_mul(g, t->s.glwe[i][7]);
  tkeygen_lwe_row(ct, &esum, &t->s.lwe[0][0], TFHE_LWE_N, plain, TFHE_LWE_NOISE, &t->masks, t->party);
  phase = tfhe_lwe_phase(ct, t->lwe, TFHE_LWE_N) - (t->glwe[7] << 56);
  return phase == esum && esum != 0 && tkeygen_small((int64_t)esum, TFHE_LWE_NOISE);
}

/* GGSW I0 of the BSK (I0: tkeygen_test_one). (o2) Row 1 (a linear GLWE
 * opening, N 2048): the phase is s g at coefficient 0 plus a noise of at most
 * 5 2^16. (o3) Row 0 (the product opening): the phase is e - s g S. (o4,
 * GLWE) The phase minus the plaintext is the noise sum (exact). (o5) The mask
 * of each row is the coin-toss mask. */
static int tkeygen_glwe_open_rows(TkeygenTest *t) {
  uint64_t *ct = malloc(4 * TFHE_POLY_N * sizeof *ct), *prod = malloc(TFHE_POLY_N * sizeof *prod);
  const uint64_t g = (uint64_t)1 << (64 - TFHE_PBS_BASE_LOG);
  const size_t i0 = tkeygen_test_one(t);
  TfheDrbg m0;
  uint64_t want[2], nonzero = 0;
  unsigned row;
  size_t c;
  int ok = 1;
  if (ct == NULL || prod == NULL) {
    free(ct);
    free(prod);
    return 0;
  }
  tkeygen_load(&t->w, &t->s, TKEYGEN_KEY_GLWE);
  m0 = t->masks;
  tkeygen_bsk_ggsw(&t->w, ct, i0, &t->s, &t->masks, t->party);
  for (row = 0; row < 2; row++) {
    const uint64_t *a = ct + row * 2 * TFHE_POLY_N;
    tfhe_poly_mul_exact(prod, a, t->glwe);
    for (c = 0; c < TFHE_POLY_N; c++) {
      const uint64_t e = t->w.esum[row][c];
      want[0] = 0u - g * t->lwe[i0] * t->glwe[c];
      want[1] = c == 0 ? g * t->lwe[i0] : 0u;
      ok &= a[TFHE_POLY_N + c] - prod[c] - want[row] == e && tkeygen_small((int64_t)e, TFHE_GLWE_NOISE);
      ok &= a[c] == tfhe_uniform(&m0);
      nonzero |= e;
    }
  }
  free(ct);
  free(prod);
  return ok && t->lwe[i0] == 1 && nonzero != 0;
}

static int tkeygen_open_regressions(void) {
  TkeygenTest *t = calloc(1, sizeof *t);
  int ok;
  if (t == NULL) return 0;
  ok = tkeygen_test_init(t);
  ok &= tkeygen_lwe_open_rows(t);
  ok &= tkeygen_glwe_open_rows(t);
  free(t);
  return ok;
}

/* With `--tfhe-wasm FILE`, writes the TFHE kernel test module to FILE (the
   validity count of test/gate.sh) and runs no row. */
int main(int argc, char **argv) {
  int ok = 1;
  if (argc == 3 && strcmp(argv[1], "--tfhe-wasm") == 0) return tfhe_wasm_write(argv[2]) ? 0 : 1;
  if (argc == 3 && strcmp(argv[1], "--tfhe-client") == 0) return tfhe_client_write(argv[2]) ? 0 : 1;
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
  uint64_t small_key[TFHE_LWE_N] = {0};
  int fhe = tfhe_regressions(small_key);
  if (fhe) puts("tfhe regressions: passed");
  ok &= fhe;
  int shared = tshare_regressions(small_key);
  if (shared) puts("tshare regressions: passed");
  ok &= shared;
  int squashed = squash_regressions();
  if (squashed) puts("squash regressions: passed");
  ok &= squashed;
  int pbs_squashed = squash_pbs_regressions();
  if (pbs_squashed) puts("squash pbs regressions: passed");
  ok &= pbs_squashed;
  int tdec_ok = tdec_regressions();
  if (tdec_ok) puts("tdec regressions: passed");
  ok &= tdec_ok;
  int keygen = tkeygen_regressions();
  if (keygen) puts("tkeygen regressions: passed");
  ok &= keygen;
  int opened = tkeygen_open_regressions();
  if (opened) puts("tkeygen openings regressions: passed");
  ok &= opened;
  if (ok) puts("warning fix regressions: passed");
  return ok ? 0 : 1;
}
