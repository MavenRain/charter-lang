/* The parser. SHARED by the tcc kits. */
#ifndef LANG_FRONT_PARSER_H
#define LANG_FRONT_PARSER_H

#include "front/ast.h"
#include "front/lexer.h"

/* Appends the declarations of one source to LIST. Returns 1, or 0 after a
   diagnostic. */
int parse_source(Arena *arena, const char *source, Origin origin, const TokenList *toks, DeclList *list, Diag *diag);

#endif
