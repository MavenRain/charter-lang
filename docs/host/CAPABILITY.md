# TinyCC Wasm host capability

This file holds host facts only. Put the facts of your domain in the
`probe/CAPABILITY.md` of your language. Paths are relative to the host
kit, or to the root of a generated language. The numbers were measured
on 2026-10-08 on AArch64 Darwin.

## Toolchain

- TinyCC 0.9.28rc (AArch64 Darwin) builds `build/langc` with
  `-std=c99 -Wall -Werror` (`Makefile:4`). `PIN` has the exact version.
- `cc -Wall -Wextra -Wswitch-enum -Werror -fsyntax-only` checks the same
  sources (`make check-clang`, `Makefile:5`). Each switch on an enum names
  every case and has no default arm.
- `tcc -run gen/embed.c` turns `domain/domain.lang` into `build/domain.c`
  at build time (`Makefile:17`). The domain is part of the executable.
- The kit uses the C99 `uint64_t` type for `Nat`. Unsigned arithmetic in
  C wraps modulo 2^64, so the evaluator and the IR use explicit carry
  tests to find an overflow.
- `src/wasm.c` writes the Wasm binary format directly: the type,
  function, memory, global, export and code sections, with LEB128
  numbers. It needs no library. The gate validates each module with
  `wasm-validate` and `wasm-objdump -x`, and runs it in node.

## Values

- `Nat` is an unsigned 64-bit integer. The lexer refuses a literal larger
  than 18446744073709551615 (`test/parse/nat-range.lang`).
- `natAdd` and `natMul` trap on overflow. `natSub` stops at 0. A trap is
  lazy: it stops a computation only when the computation needs it.
  `README.md` gives the rule and the reason.
- There is no text type. The lexer refuses `"` (`test/parse/string.lang`).
- On Wasm, each value is a word and a trap flag. Only the entry result
  is strict.

## Overflow tests on Wasm

- `ADD_CARRY` is `a + b < a`, modulo 2^64 (`src/wasm.c:178`).
- `MUL_CARRY` is `b > (2^64 - 1) / max(a, 1)` with `i64.div_u`
  (`src/wasm.c:181`). The Wasm MVP has no 128-bit product. The test is
  exact: for a > 0, a * b <= 2^64 - 1 if and only if
  b <= floor((2^64 - 1) / a). For a = 0 the product is 0, and the test
  gives 0 for each b.
- `SUB` is `select(a - b, 0, a >= b)`.
- The differential grid holds the edge values (`test/grid.awk:8`). Node
  and `langc eval` agree: `scale 4294967296 4294967296` is `trap`,
  `scale 4294967295 4294967297` is 18446744073709551615, and
  `addPrice 18446744073709551615 1` is `trap`.

## Limits

- The checker and the evaluator stop at a depth of 2000
  (`src/front/check.c:10`, `src/front/core.h:16`). The parser stops at a
  nesting of 1000 (`src/front/parser.c:16`). These limits keep the C
  stack bounded. `test/gate.sh` checks a nesting of 1100 parentheses.
- The evaluator has a fuel of 20000000 steps (`src/front/core.h:17`).
  `langc eval examples/entries.lang square 4294967296` stops with
  `EVAL_FUEL` after 0.91 s user and 0.48 s system CPU time. For this
  reason the differential grid uses values of 2^32 and more only for
  entries with no loop.
- All memory of `langc` comes from one arena with a limit of 1 GiB
  (`src/main.c:11`). A run that reaches it stops with `OOM`.
  `langc eval test/ir/spine.lang foldOnes 4294967296` stops with `OOM`.
- The Wasm memory has a maximum of 16384 pages, which is 1 GiB
  (`src/wasm.c:27`). The allocator traps when `memory.grow` fails.
- The Wasm writer stops at a statement nesting of 2000 (`src/wasm.c:28`).
  The IR printer stops at 4000 (`src/front/lower.c:17`).
- A loop over a list spine has a fuel of 2^63 steps
  (`src/front/lower.c:688`). The heap limit stops the loop first.
- Source files are at most 1 MiB (`src/front/front.h:7`).

## Measured numbers

- `make check` runs 813 differential cases on 13 modules, with
  0 mismatches.
- `langc build examples/entries.lang` writes a module of 1366 bytes for ten
  entries.

## HOST-LIMIT reasons

The IR is first-order (`src/ir.h`). It has words, heap blocks, branches,
counted loops and bounded loops. It has no calls, no function values and
no stack of its own. Two programs need more than that. The lowering
refuses them with a HOST-LIMIT code. These are not defects.

- `REFUSE_RUNTIME_CLOSURE` (`src/front/lower.c:503`): a function value
  must exist at run time, for example as the result of a `fold`. The IR
  has no closures. `test/ir/closure.lang` is the gate case.
- `REFUSE_RUNTIME_TREE` (`src/front/lower.c:990`): a `fold` walks a value
  of a family with two or more recursive fields, and the value exists
  only at run time. A loop walks one spine. A tree needs recursion or an
  explicit stack. `test/ir/tree.lang` is the gate case.
