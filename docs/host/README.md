# TinyCC Wasm host kit

This kit compiles a small typed language to a WebAssembly MVP module.
One C99 program, `build/langc`, holds the parser, the checker, the
evaluator, the lowering to a first-order IR and the Wasm writer.
TinyCC builds it.

## Shared files

This kit and `hosts/tcc-evm` share these files. `TCC_SHARED` in the root
`Makefile` lists them:

- the source: the front end (`src/front/`), `src/ir.h`, `src/target.h`
  and `src/main.c`
- the domain and its embed tool: `domain/` and `gen/`
- the examples: `examples/`
- the shared tests: `test/parse/`, `test/check/`, `test/eval/`, `test/ir/`,
  `test/grid.awk`, `test/review.sh` and `test/fronttool.c`
- `.gitignore`

`make check` at the template root compares each shared entry in the two
kits with `diff -r`. It fails when a shared file is different in the two
kits or is missing from one kit. When you change a shared file, make the
same change in `hosts/tcc-evm`.

These files are specific to this kit:

- the target file: `src/wasm.c`
- the target test file: `test/run-wasm.mjs`
- the build and gate files: `Makefile`, `test/gate.sh` and `PIN`
- the docs: `README.md`, `FORMERS.md` and `docs/CAPABILITY.md`

## Build

From the template root:

```sh
make -C hosts/tcc-wasm build
make -C hosts/tcc-wasm check
make -C hosts/tcc-wasm check-clang
```

`build` runs `tcc -run gen/embed.c` to copy `domain/domain.lang` into
`build/domain.c`. Then it builds `build/langc` with
`tcc -std=c99 -Wall -Werror`. The domain is part of the executable.
`check-clang` compiles the same sources with
`cc -std=c99 -Wall -Wextra -Wswitch-enum -Werror -fsyntax-only`.
`check` does both steps, then runs `test/gate.sh`.
The gate needs `node`, `wasm-validate` and `wasm-objdump` on the `PATH`.
`PIN` records the tool versions of the last GREEN gate.
The build and the gate need no network access.

## Source language

A program is a sequence of `def NAME : TYPE := TERM`. A line comment
starts with `--`. Lambdas are `fun (x : A) => t`. There is no text type.

Core names: types `Nat Flag Prod Sum Option List Eq`, values
`flagYes flagNo pair first second inl inr either none some option nil cons
pure map bind fold unfold filter pack witness payload refl symm trans
transport cong`, Nat operations `natAdd natSub natMul natEq natLe`, and the
Flag eliminator `flagIf b yes no`. `Type 0 : Type 1` is the universe
chain. `Sigma (x : A) B` and `(x : A) * B` are dependent pairs.
`FORMERS.md` gives the status of each former.

The compiler enforces these rules:

| Rule | Code | The compiler refuses |
|---|---|---|
| R1 | `REFUSE_DATA` | a `family` declaration in a program |
| R2 | `REFUSE_AXIOM` | an `axiom` declaration |
| R3 | `REFUSE_REC` | `def rec`, or a definition that refers to itself or to a later definition |
| R4 | `REFUSE_NAME` | a core name, a domain name, a reserved name or a repeated name as a new definition |

## CLI

```sh
build/langc check PROG
build/langc eval PROG NAME [ARGS...]
build/langc ir PROG
build/langc abi PROG
build/langc build PROG -o OUT [--runtime]
```

- `check` prints `ok`, or refuses the program.
- `eval` prints the normal form of `NAME`. Each argument is a decimal
  number. When an entry traps, `eval` prints `trap` on stdout and an
  `EVAL_OVERFLOW` line on stderr, and the exit status is 0.
- `ir` prints the first-order IR. It has one `func` for each entry.
- `abi` prints the name of each entry, one for each line.
- `build` writes the Wasm module to `OUT`. On this target, `--runtime`
  gives the same bytes.

The exit status is 0 for success, 1 for a refused program and 2 for a
usage or IO error. A diagnostic on stderr has the form
`langc: CODE: DEF: message`.

## Entries

An entry is a top-level program definition whose declared type is `Nat`,
`Flag`, or a first-order function from `Nat` and `Flag` arguments to a
`Nat` or `Flag` result. `build` exports each entry by its name. Each
parameter and the result is an `i64`. Other definitions are not exported.

`Nat` is an unsigned 64-bit integer. `natAdd` and `natMul` trap on an
overflow past 2^64 - 1. `natSub` stops at 0. `Flag` is 0 or 1.

## Compilation

Compilation is partial evaluation. The compiler normalizes the body of
each entry with the parameters as free variables. Types and universes erase.
Proof contents erase, while their trap flags remain. A lambda stays only as the direct function argument of
`fold`, `unfold`, `map`, `bind`, `filter`, `either` or `option`. The
lowering puts its body into a loop or a branch. The lowering refuses two
programs with a HOST-LIMIT code (see `docs/CAPABILITY.md`):

- `REFUSE_RUNTIME_CLOSURE`: a function value must exist at run time.
- `REFUSE_RUNTIME_TREE`: a fold walks a tree that exists only at run time.

## Lazy traps

A trap is lazy. It stops a computation only when the computation needs
the value. `langc eval` and the Wasm module agree on this rule. The
lowering gives each value a word and a trap flag. A heap field keeps its
word and its flag. The entry result is the only strict point: when its
flag is set, the entry executes `unreachable`.

The lowering lowers a value one time in a block. The blocks in that
block use the same result, but the two arms of a branch do not share
results.

Strict traps are not correct here. Normalization at compile time drops
terms that are not read, for example `first (pair a b)` gives `a`. The
evaluator also computes both arms of `flagIf`. A strict trap would fire
in a term that the program does not use.

Decision record: the kit builder (Claude) made this decision. The
repository owner has not ruled on it.

## Wasm layout

- The module has one memory with a maximum of 16384 pages (1 GiB) and
  one mutable `i64` global, the heap pointer.
- Function 0 is the internal allocator `alloc (bytes : i32) -> i64`. It
  increases the heap pointer. When a block does not fit, it calls
  `memory.grow`. When the memory cannot grow past 1 GiB, it traps.
- Function 1 + K is entry K. Each entry first sets the heap pointer to 0,
  so each call starts with an empty heap.
- An entry traps when a `Flag` argument is larger than 1.
- A word is 8 bytes. A heap block holds the tag in word 0, the word of
  field K in word 1 + 2K and the trap flag of field K in word 2 + 2K.
- A tag switch is nested blocks and `br_table`. A tag out of range traps.

## Domain slot

`domain/domain.lang` holds the families and the operations of the domain.
Only this file can declare a `family` (rule R1). `domain/README.md` tells
how to replace the sample domain.

## Gate

`make -C hosts/tcc-wasm check` prints these lines when it is GREEN:

| Line | What the gate does |
|---|---|
| `examples: 10 checked, 0 failed` | `langc check` accepts each `examples/*.lang` file |
| `parse refusals: 9 checked` | each `test/parse` file fails with the code in `test/parse/expect.txt`; one file has 1100 nested parentheses |
| `check refusals: 19 checked` | each `test/check` mutant fails with the code in `test/check/expect.txt`; the `TYPE_REFL` message shows both normal forms |
| `evals: 32 checked` | `langc eval` gives each result in `test/eval/expect.txt` |
| `ir: 10 lowered` | `langc ir` lowers each example, with one `func` for each `abi` line |
| `wasm: 13 modules valid` | `langc build` writes a module for each example and for `test/ir/spine.lang`, `test/ir/lazy.lang` and `test/ir/proof-trap.lang`; `wasm-validate` and `wasm-objdump -x` accept it |
| `differential: 813 cases, 0 mismatches` | node runs each entry on the grid of `test/grid.awk`; each result is equal to the `langc eval` result, and a trap is equal to a trap |
| `gate: 0 failures` | the sum of all failures |

The gate also checks the usage and IO exit codes, five `eval` refusals,
`test/ir/closure.lang` (`REFUSE_RUNTIME_CLOSURE`), `test/ir/tree.lang`
(`REFUSE_RUNTIME_TREE`), the 13 cases of `test/ir/spine.lang`,
`pick 2 4 9` = `trap` on Wasm, and the absence of em-dashes and en-dashes
in the kit. `perl bin/doc-check.pl hosts/tcc-wasm` must report 0
problems.

## Known limits

- A `fold` over a bare `nil` cannot infer its type (`TYPE_INFER`). Use a
  definition with a declared `List` type.
- With no expected type, `either`, `map` and `cong` take the result type
  of the function at a fresh variable. A dependent result needs a
  declared type.
- A definition with a `List`, `Prod` or other non-scalar result is not an
  entry. `ir` and `abi` skip it.
- `langc eval` stops after 20000000 steps (`EVAL_FUEL`). The Wasm module
  has no step limit, so a large loop count can run on Wasm and stop in
  `eval`. The grid uses large values only for entries with no loop.
- The arena of `langc` and the Wasm memory each stop at 1 GiB.
- Source files are at most 1 MiB. `Nat` literals are at most
  18446744073709551615.
