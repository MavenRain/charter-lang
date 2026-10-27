#include <string.h>

#include "front/front.h"

int front_load(Arena *arena, const char *source, const char *text, size_t len, Front *out, Diag *diag) {
  TokenList domain_toks;
  memset(out, 0, sizeof *out);
  if (!lex_source(arena, "domain/domain.lang", (const char *)domain_source, domain_source_len, &domain_toks, diag)
      || !parse_source(arena, "domain/domain.lang", ORIGIN_DOMAIN, &domain_toks, &out->decls, diag))
    return 0;
  out->domain_count = out->decls.count;
  out->lexed = lex_source(arena, source, text, len, &out->toks, diag);
  return out->lexed && parse_source(arena, source, ORIGIN_PROGRAM, &out->toks, &out->decls, diag);
}
