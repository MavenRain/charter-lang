#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "front/base.h"

#define ARENA_CHUNK_BYTES ((size_t)1 << 16)

/* The header is 32 bytes, so data stays 16-byte aligned. */
struct ArenaChunk {
  ArenaChunk *next;
  size_t size;
  size_t used;
  size_t pad;
  unsigned char data[];
};

void arena_init(Arena *arena, size_t limit_bytes) {
  arena->head = NULL;
  arena->used_bytes = 0;
  arena->limit_bytes = limit_bytes;
}

static int arena_grow(Arena *arena, size_t need) {
  size_t size = need > ARENA_CHUNK_BYTES ? need : ARENA_CHUNK_BYTES;
  if (size > arena->limit_bytes - arena->used_bytes) return 0;
  ArenaChunk *chunk = calloc(1, sizeof(ArenaChunk) + size);
  if (chunk == NULL) return 0;
  chunk->next = arena->head;
  chunk->size = size;
  arena->head = chunk;
  arena->used_bytes += size;
  return 1;
}

void *arena_alloc(Arena *arena, size_t size) {
  size_t need = (size + 15u) & ~(size_t)15u;
  if (need < size) return NULL;
  int fits = arena->head != NULL && arena->head->size - arena->head->used >= need;
  if (!fits && !arena_grow(arena, need)) return NULL;
  void *block = arena->head->data + arena->head->used;
  arena->head->used += need;
  return block;
}

char *arena_strndup(Arena *arena, const char *text, size_t len) {
  char *copy = arena_alloc(arena, len + 1);
  if (copy == NULL) return NULL;
  if (len > 0) memcpy(copy, text, len);
  copy[len] = '\0';
  return copy;
}

void arena_release(Arena *arena) {
  ArenaChunk *chunk = arena->head;
  while (chunk != NULL) {
    ArenaChunk *next = chunk->next;
    free(chunk);
    chunk = next;
  }
  arena_init(arena, arena->limit_bytes);
}

void diag_init(Diag *diag) {
  memset(diag, 0, sizeof *diag);
}

int diag_fail(Diag *diag, const char *code, const char *def, const char *fmt, ...) {
  if (diag->set) return 0;
  diag->set = 1;
  diag->code = code;
  snprintf(diag->def, sizeof diag->def, "%s", def == NULL ? "-" : def);
  va_list args;
  va_start(args, fmt);
  vsnprintf(diag->msg, sizeof diag->msg, fmt, args);
  va_end(args);
  return 0;
}

static const char *copy_field(char *buf, size_t size, const char *text) {
  if (text == NULL) return NULL;
  snprintf(buf, size, "%s", text);
  return buf;
}

int diag_fail_at(Diag *diag, const char *code, const char *def, Span span, const char *expected,
                 const char *found, const char *fix, const char *fmt, ...) {
  if (diag->set) return 0;
  diag->set = 1;
  diag->code = code;
  snprintf(diag->def, sizeof diag->def, "%s", def == NULL ? "-" : def);
  va_list args;
  va_start(args, fmt);
  vsnprintf(diag->msg, sizeof diag->msg, fmt, args);
  va_end(args);
  diag->span = span;
  diag->expected = copy_field(diag->expected_buf, sizeof diag->expected_buf, expected);
  diag->found = copy_field(diag->found_buf, sizeof diag->found_buf, found);
  diag->fix = copy_field(diag->fix_buf, sizeof diag->fix_buf, fix);
  return 0;
}

void diag_default_span(Diag *diag, Span span) {
  if (diag->set && diag->span.line == 0) diag->span = span;
  if (diag->set && diag->span.file == NULL) diag->span.file = span.file;
}

void diag_attach(Diag *diag, const char *expected, const char *found, const char *fix) {
  diag->expected = expected != NULL ? expected : diag->expected;
  diag->found = found != NULL ? found : diag->found;
  diag->fix = fix != NULL ? fix : diag->fix;
}

void diag_print(const Diag *diag, FILE *out) {
  fprintf(out, "langc: %s: %s: %s\n", diag->code, diag->def, diag->msg);
}

/* Width of one valid UTF-8 scalar, or zero for an invalid byte sequence. */
static size_t json_utf8_width(const unsigned char *s) {
  size_t width = *s >= 0xc2 && *s <= 0xdf ? 2
               : *s >= 0xe0 && *s <= 0xef ? 3
               : *s >= 0xf0 && *s <= 0xf4 ? 4 : 0;
  for (size_t i = 1; i < width; i++) {
    if (s[i] < 0x80 || s[i] > 0xbf) return 0;
  }
  if ((*s == 0xe0 && s[1] < 0xa0) || (*s == 0xed && s[1] >= 0xa0)
      || (*s == 0xf0 && s[1] < 0x90) || (*s == 0xf4 && s[1] >= 0x90)) return 0;
  return width;
}

/* NULL prints as null. Control and invalid UTF-8 bytes print as \u00xx. */
static void json_string(FILE *out, const char *text) {
  if (text == NULL) {
    fputs("null", out);
    return;
  }
  fputc('"', out);
  for (const unsigned char *s = (const unsigned char *)text; *s != '\0'; s++) {
    if (*s >= 0x80) {
      size_t width = json_utf8_width(s);
      if (width == 0) {
        fprintf(out, "\\u%04x", (unsigned)*s);
      } else {
        fwrite(s, 1, width, out);
        s += width - 1;
      }
      continue;
    }
    int quote = *s == '"' || *s == '\\';
    int control = *s < 0x20;
    if (quote) fprintf(out, "\\%c", *s);
    if (control) fprintf(out, "\\u%04x", (unsigned)*s);
    if (!quote && !control) fputc(*s, out);
  }
  fputc('"', out);
}

/* A change to the input cannot remove these diagnostics. */
static int diag_retry(const char *code) {
  static const char *const FINAL[] = {"OOM", "IO", "IO_SIZE", "USAGE", "INTERNAL"};
  int final = strncmp(code, "EVAL_", 5) == 0;
  for (size_t i = 0; i < sizeof FINAL / sizeof FINAL[0]; i++) final |= strcmp(code, FINAL[i]) == 0;
  return !final;
}

void diag_print_json(const Diag *diag, FILE *out) {
  int warning = strncmp(diag->code, "W_", 2) == 0;
  fputs("{\"code\":", out);
  json_string(out, diag->code);
  fprintf(out, ",\"severity\":\"%s\",\"span\":", warning ? "warning" : "error");
  if (diag->span.line == 0) {
    fputs("null", out);
  } else {
    fputs("{\"file\":", out);
    json_string(out, diag->span.file);
    fprintf(out, ",\"line\":%d,\"col\":%d,\"end_line\":%d,\"end_col\":%d}", diag->span.line, diag->span.col,
            diag->span.end_line, diag->span.end_col);
  }
  fputs(",\"expected\":", out);
  json_string(out, diag->expected);
  fputs(",\"found\":", out);
  json_string(out, diag->found);
  fputs(",\"fix\":", out);
  json_string(out, diag->fix);
  fprintf(out, ",\"retry\":%s,\"message\":", diag_retry(diag->code) ? "true" : "false");
  json_string(out, diag->msg);
  fputs("}\n", out);
}
