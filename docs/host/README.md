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
The checks need `node`, `wasm-validate`, `wasm-objdump` and `wasm-interp` on the `PATH`.
`PIN` records the tool versions of the last GREEN gate.
The build and the gate need no network access.

## Source language

A program is a sequence of declarations in the Agda-like surface of
`SPEC.md` section 2. A definition is a signature line and a clause line,
for example `twice : (f : ℕ → ℕ) → ℕ → ℕ` and `twice f x = f (f x)`. A
line comment starts with `--`. Lambdas are `λ x → t` or `λ (x : A) → t`.
The parser also reads the ASCII aliases of `SPEC.md` section 2.3: `->`,
`\`, `fun x => t`, `*`, `Sigma (x : A) B` and `Nat`. There is no text type.

Core names (`BUILTINS` in `src/front/check.c`): types `ℕ` (core name
`Nat`), `Bool Unit Digest Key Sum Option Eq`, values `unit true false inl inr either
none some option pack witness payload pure map bind fold refl symm trans
transport cong`, Nat operations `natAdd natSub natMul natEq natLe`, and the
Bool eliminator `flagIf b yes no`. `Type 0 : Type 1` is the universe chain.
`(x : A) × B` is a dependent pair and `A × B` is a pair. `pack a b` makes
a pair, and `witness` and `payload` give its parts. `formers/tcc-wasm.md`
gives the status of each former.

The compiler enforces these rules:

| Rule | Code | The compiler refuses |
|---|---|---|
| R1 | `REFUSE_DATA` | a `data` declaration in a program |
| R2 | `REFUSE_AXIOM` | a `postulate` declaration |
| R3 | `REFUSE_REC` | `rec`, or a definition that refers to itself or to a later definition |
| R4 | `REFUSE_NAME` | a core name, a domain name, a reserved name or a repeated name as a new definition |

## CLI

```sh
build/langc check [--json] PROG
build/langc eval PROG NAME [ARGS...]
build/langc eval --words PROG NAME [WORDS...]
build/langc ir [--words] PROG
build/langc abi [--words] PROG
build/langc build [--words] PROG -o OUT [--runtime]
build/langc fmt PROG
```

- `check` prints `ok`, or refuses the program. `check --json` gives the
  diagnostics as JSON. `docs/DIAGNOSTICS.md` lists the codes.
- `fmt` prints the canonical text of the program (`SPEC.md` section 2.6).
- `eval` prints the normal form of `NAME`. Each argument is a decimal
  number. When an entry traps, `eval` prints `trap` on stdout and an
  `EVAL_OVERFLOW` line on stderr, and the exit status is 0.
- `ir` prints the first-order IR. It has one `func` for each entry.
- `abi` prints the name of each entry, one for each line.
- `build` writes the Wasm module to `OUT`. On this target, `--runtime`
  gives the same bytes.
- `--words` adds the stream entries: each program definition that is not
  an entry and has a stream form. `eval --words` reads the input words and
  prints the output words. In Wasm, a stream entry is `(n : i64) -> i64`.
  The module exports `memory`. The host writes the n input words from byte
  0, and the entry returns the byte address of the output (the count m,
  then the m words). A bad stream traps.

The exit status is 0 for success, 1 for a refused program and 2 for a
usage or IO error. A diagnostic on stderr has the form
`langc: CODE: DEF: message`.

## Entries

An entry is a top-level program definition whose declared type is `ℕ`,
`Bool`, or a first-order function from `ℕ` and `Bool` arguments to a
`ℕ` or `Bool` result. `build` exports each entry by its name. Each
parameter and the result is an `i64`. Other definitions are not exported.

`ℕ` is an unsigned 64-bit integer. `natAdd` and `natMul` trap on an
overflow past 2^64 - 1. `natSub` stops at 0. `Bool` is 0 or 1.

## Compilation

Compilation is partial evaluation. The compiler normalizes the body of
each entry with the parameters as free variables. Types and universes erase.
Proof contents erase, while their trap flags remain. A lambda stays only as the direct function argument of
`fold`, `map`, `bind`, `either` or `option`. The
lowering puts its body into a loop or a branch. The lowering refuses two
programs with a HOST-LIMIT code (see `docs/host/CAPABILITY.md`):

- `REFUSE_RUNTIME_CLOSURE`: a function value must exist at run time.
- `REFUSE_RUNTIME_TREE`: a fold or an ind walks a tree that exists only at run time.

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
terms that are not read, for example `witness (pack a b)` gives `a`. The
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
- An entry traps when a `Bool` argument is larger than 1.
- A word is 8 bytes. A heap block holds the tag in word 0, the word of
  field K in word 1 + 2K and the trap flag of field K in word 2 + 2K.
- A tag switch is nested blocks and `br_table`. A tag out of range traps.

## Domain slot

`domain/domain.lang` holds the data types and the operations of the
domain. Only this file can declare a data type (rule R1). `domain/README.md` tells
how the domain is organized.

## Gate

`make check` prints these lines when it is GREEN:

| Line | What the gate does |
|---|---|
| `examples: 15 checked, 0 failed` | `langc check` accepts each `examples/*.lang` file |
| `parse refusals: 9 checked` | each `test/parse` file fails with the code in `test/parse/expect.txt`; one file has 1100 nested parentheses |
| `check refusals: 21 checked` | each `test/check` mutant fails with the code in `test/check/expect.txt`; the `TYPE_REFL` message shows both normal forms |
| `evals: 33 checked` | `langc eval` gives each result in `test/eval/expect.txt` |
| `ir: 15 lowered` | `langc ir` lowers each example, with one `func` for each `abi` line |
| `wasm: 22 modules valid` | `langc build` writes a module for each example and for the 7 files `test/ir/spine.lang`, `lazy.lang`, `proof-trap.lang`, `nat-effects.lang`, `ind.lang`, `optind.lang` and `para.lang`; `wasm-validate` and `wasm-objdump -x` accept it |
| `differential: 1094 cases, 0 mismatches` | node runs each entry on the grid of `test/grid.awk`; each result is equal to the `langc eval` result, and a trap is equal to a trap |
| `words: 39 checked` | each line of `test/eval/words.txt` is `NAME [WORDS] => OUTPUT`; `langc eval --words test/eval/words.lang NAME WORDS` exits 0 and prints OUTPUT |
| `stream: 24 checked` | a smoke of the stream ABI: `langc build --words` makes each program def with a stream form an entry, and `run-wasm.mjs --words` prints its output words, or `trap` |
| `entry streams: 41 rows` | each row of `test/eval/stream.txt` is `FILE NAME [WORDS]`; `langc eval --words` and the `build --words` module of `examples/node.lang` or `examples/client.lang` print the same words, and a trap is equal to a trap; each `abi --words` name of the two files has a row |
| `fmt: 67 canonical, 3 non-canonical pairs` | `langc fmt` keeps each committed `.lang` file and each canonical `test/fmt` file the same; it is idempotent, and its output parses to the same terms; each non-canonical `test/fmt` input gives its expected canonical text |
| `json: 24 fixtures; diagnostics: 38 codes, 21 with a fixture, 17 with no fixture` | each `test/json` fixture gives the JSON shape of its code; each fixture code is in `docs/DIAGNOSTICS.md` |
| `gate: 0 failures` | the sum of all failures |

The gate also checks the usage and IO exit codes, five `eval` refusals,
`test/ir/closure.lang` (`REFUSE_RUNTIME_CLOSURE`), `test/ir/tree.lang`
(`REFUSE_RUNTIME_TREE`), the 5 cases of `test/ir/spine.lang`,
`pick 2 4 9` = `trap` on Wasm, and the absence of em-dashes and en-dashes.
Then `make check` runs `test/review.sh` and the domain regressions of
`build/fronttool`. Then `build/checktool` prints these 8 lines:
`poseidon2 regressions: passed` (with the HorizenLabs Poseidon2 BN254
t = 3 vector), `poseidon2 wasm regressions: passed`,
`hashOf eval regressions: passed`, `merkleRoot eval regressions: passed`,
`sha512 regressions: passed`, `ed25519 regressions: passed`,
`frost regressions: passed` (with the RFC 9591 Appendix E.1 signature) and
`warning fix regressions: passed`.

## Known limits

- With no expected type, `either`, `map` and `cong` take the result type
  of the function at a fresh variable. A dependent result needs a
  declared type.
- A definition with a pair, `Sum`, `Option` or other non-scalar result is
  not an entry. `ir` and `abi` skip it.
- `langc eval` stops after 20000000 steps (`EVAL_FUEL`). The Wasm module
  has no step limit, so a large loop count can run on Wasm and stop in
  `eval`. The grid uses large values only for entries with no loop.
- The arena of `langc` and the Wasm memory each stop at 1 GiB.
- Source files are at most 1 MiB. `Nat` literals are at most
  18446744073709551615.
