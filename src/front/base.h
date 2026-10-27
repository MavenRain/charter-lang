/* Arena allocation and the diagnostic sink. SHARED by the tcc kits. */
#ifndef LANG_FRONT_BASE_H
#define LANG_FRONT_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct ArenaChunk ArenaChunk;

/* Every compiler object lives in one arena. The arena frees all at once. */
typedef struct {
  ArenaChunk *head;
  size_t used_bytes;
  size_t limit_bytes;
} Arena;

void arena_init(Arena *arena, size_t limit_bytes);
/* Returns zeroed memory, or NULL when the limit is reached. */
void *arena_alloc(Arena *arena, size_t size);
char *arena_strndup(Arena *arena, const char *text, size_t len);
void arena_release(Arena *arena);

/* A source range. LINE 0 means no span. Lines and columns are 1-based;
   columns count code points; END_COL is the column after the range. */
typedef struct {
  const char *file;
  int line;
  int col;
  int end_line;
  int end_col;
} Span;

/* The first failure wins. Later failures do not overwrite it. EXPECTED,
   FOUND and FIX are NULL when absent; they point into the buffers below or
   to text that the caller keeps alive (diag_attach). Do not copy a Diag. */
typedef struct {
  int set;
  const char *code;
  char def[64];
  char msg[512];
  Span span;
  const char *expected;
  const char *found;
  const char *fix;
  char expected_buf[256];
  char found_buf[256];
  char fix_buf[256];
} Diag;

void diag_init(Diag *diag);
/* Records the failure and returns 0, so a caller can write
   `return diag_fail(...)`. DEF is NULL when no definition applies. */
int diag_fail(Diag *diag, const char *code, const char *def, const char *fmt, ...);
/* As diag_fail, and also records the span and the structured fields. The
   texts are copied (at most 255 bytes each). */
int diag_fail_at(Diag *diag, const char *code, const char *def, Span span, const char *expected,
                 const char *found, const char *fix, const char *fmt, ...);
/* Sets the span when the failure has none (the checker knows only the
   definition), and the file when the span has none (a name span from the
   checker). */
void diag_default_span(Diag *diag, Span span);
/* Points the structured fields at long texts that the caller keeps alive. */
void diag_attach(Diag *diag, const char *expected, const char *found, const char *fix);
/* Prints `langc: CODE: DEF: message`. */
void diag_print(const Diag *diag, FILE *out);
/* Prints one JSON object on one line: code, severity, span, expected, found,
   fix, retry, message. */
void diag_print_json(const Diag *diag, FILE *out);

#endif
