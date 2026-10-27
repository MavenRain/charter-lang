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

void diag_print(const Diag *diag, FILE *out) {
  fprintf(out, "langc: %s: %s: %s\n", diag->code, diag->def, diag->msg);
}
