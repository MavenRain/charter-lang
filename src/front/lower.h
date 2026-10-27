/* The lowering from checked values to the IR, and the `langc ir` dump.
   SHARED by the tcc kits. */
#ifndef LANG_FRONT_LOWER_H
#define LANG_FRONT_LOWER_H

#include "front/core.h"
#include "ir.h"

/* Lowers each entry of the checked program M (a PROGRAM definition where
   entry_of holds) into PROG. Returns 1, or 0 after a diagnostic. */
int lower_program(Machine *m, IrProgram *prog);
/* Writes PROG as text: a `func` line for each entry, then one statement on
   each line. */
void ir_print(const IrProgram *prog, FILE *out);

#endif
