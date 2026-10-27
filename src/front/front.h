/* The front end entry point. SHARED by the tcc kits. */
#ifndef LANG_FRONT_FRONT_H
#define LANG_FRONT_FRONT_H

#include "front/parser.h"

#define SOURCE_MAX_BYTES ((size_t)1 << 20)

/* build/domain.c holds the bytes of domain/domain.lang (gen/embed.c). */
extern const unsigned char domain_source[];
extern const size_t domain_source_len;

/* The loaded declarations. DECLS holds the DOMAIN_COUNT domain declarations
   first, then the program. TOKS holds the program tokens and comments when
   LEXED is 1. After a parse failure DECLS holds the complete declarations
   before the failure. */
typedef struct {
  DeclList decls;
  size_t domain_count;
  TokenList toks;
  int lexed;
} Front;

/* Parses the embedded domain file, then the program, into OUT. Returns 1,
   or 0 after a diagnostic. */
int front_load(Arena *arena, const char *source, const char *text, size_t len, Front *out, Diag *diag);

#endif
