/* The front end entry point. SHARED by the tcc kits. */
#ifndef LANG_FRONT_FRONT_H
#define LANG_FRONT_FRONT_H

#include "front/parser.h"

#define SOURCE_MAX_BYTES ((size_t)1 << 20)

/* build/domain.c holds the bytes of domain/domain.lang (gen/embed.c). */
extern const unsigned char domain_source[];
extern const size_t domain_source_len;

/* Parses the embedded domain file, then the program, into one list. */
int front_load(Arena *arena, const char *source, const char *text, size_t len, DeclList *out, Diag *diag);

#endif
