# Domain slot

The charter-lang domain (PLAN 3.1) replaces the kit sample domain.
`domain/domain.lang` holds the domain. At build time, `tcc -run
gen/embed.c` copies it into `build/domain.c`, so the domain is part of
`build/langc`. `langc` loads the domain first, then the program.

## What the file holds

- `data` declarations. Only this file can declare a data type. In a
  program, `data` is refused with `REFUSE_DATA` (rule R1).
- Operations, written in the language. Each operation is a signature
  line and a clause line, as in a program (`SPEC.md` section 2.1).
- Line comments that start with `--`.

Each data type, constructor, field and definition name in this file
becomes a core name. A program cannot use one of them as a new definition
name (rule R4, `REFUSE_NAME`).

## Data type syntax

```
data NAME (param : T)* : Type where
  ctor : (field : T) → (field : T) → NAME param*
  ctor : NAME param*
```

`SPEC.md` section 2.1 gives the full grammar.

- Each constructor is on its own line after the `data` line. A
  constructor gives its fields as named Pi binders and ends in the type
  that it makes.
- A data type with only nullary constructors is an enum.
- A data type with one constructor is a record. It gets one projection
  for each field name.
- A field can have the type of its own data type. Such a field is
  recursive.
- A parameter is an index (former F15). A constructor takes the indices
  first: `makeLot 3 250 : Lot 3` (a domain row in `test/fronttool.c`).
- A `fold` over a data type takes one argument for each constructor, in
  declaration order. A constant constructor takes a value. A constructor
  with fields takes a function. A recursive field arrives folded.

In the IR, a constructor value is a heap block. Word 0 is the constructor
index, in declaration order. Each field has a word and a trap flag.
A `fold` over a data type with one recursive field lowers to a loop.
A data type with two or more recursive fields cannot be folded at run
time (`REFUSE_RUNTIME_TREE`, see `docs/host/CAPABILITY.md`).

## The charter domain (S1)

| Data type | Kind | Use |
|---|---|---|
| `FreeMon A` | free monoid (rule R1, second class): `fmNil`, `fmCons` with `fmHead` and the recursive field `fmTail` | `fmAppend` and its monoid laws `fmUnitL`, `fmUnitR`, `fmAssoc`; kit regression subject: the spine loop in `test/ir/spine.lang`, `pileDepth` in `examples/base.lang` |
| `Tree` | two recursive fields | kit regression subject: the tree mutant `test/ir/tree.lang` |
| `DecE` | enum: `decRelease`, `decRefund`, `decHold` | escrow decisions and escrow ballots (PLAN 3.1) |
| `BallotA` | enum: `ballotAdopt`, `ballotReject` | amendment ballots |
| `DecA` | enum: `amendAdopt`, `amendReject`, `amendHold` | amendment decisions |
| `Bit` | enum: `bitZero`, `bitOne` | flags; `bitScale` in `examples/assets.lang` |
| `Address` | record: `addressKey` | an opaque key over a `ℕ` |

`CMon : Type 1` is a definition, not a data type: a named iterated Sigma
with the fields carrier, add, zero, assoc, unitL, unitR, comm, cancel,
monus, monusSound and monusComplete (PLAN 3.1, Q8). The projections are
`cmCarrier` to `cmMonusComplete`. `Voucher M` and `Claim M` are records
over `(M : CMon)` as iterated Sigma, with the projections
`voucherAddress`, `voucherAmount`, `voucherIndex`, `claimPayer`,
`claimPayee` and `claimAmount`. S1 declares no instance of `CMon` (PLAN
10, O8).

`data Tree` exists only for the tree mutant. The mutant checks that the
lowering refuses a fold over a run-time tree. Rule R1 lets only this file
declare a data type, so the data type must be here. FreeMon replaces
`Stack` at S2a; `Tree` stays (PLAN 10, O9, Q-S2a-1).

## How to replace the domain

1. Write your data types and definitions in `domain/domain.lang`. Keep
   the names apart from the core names in `docs/host/README.md`.
2. Change the examples and the tests that use the domain names:
   `examples/algebra.lang`, `examples/base.lang`, `examples/assets.lang`,
   `examples/laws.lang`, `test/eval/expect.txt`,
   `test/check/domain-name.lang`, `test/ir/spine.lang` and
   `test/ir/tree.lang`.
3. Keep a data type with two recursive fields for `test/ir/tree.lang`, or
   remove that file and its block in `test/gate.sh`.
4. Run `make check` in the repository root. The build makes
   `build/domain.c` again when `domain/domain.lang` changes.

## Hashes (S4 U3)

| Definition | Value | Ruling |
|---|---|---|
| `commit k` | `hashOf 2 Key k`: the commitment to the key `k` | Q-S4-7 |
| `prf k e u` | `hashOf 4 (Key × ℕ × ℕ) (pack k (pack e u))`: the PRF of the key `k` at `e` and `u` | Q-S4-7 |
| `chainZero` | `hashOf 1 (Eq ℕ 0 0) refl` = H_1([]): the first chain entry h_0. The stream form of `Eq ℕ 0 0` has 0 words. | Q-S4-5, Q-S4-9 |
| `Entry` | `ℕ × Digest × Digest × Digest × Sig`: the chain entry e_i = (i, h_{i-1}, op_i, Pi_i, sig_i), with op_i and Pi_i as digests | Q-S4-16 |
| `chainStep i prev opD piD sig` | `hashOf 1 Entry (pack i (pack prev (pack opD (pack piD sig))))`: the chain entry h_i | Q-S4-9, Q-S4-16 |

The chain step h_i hashes the entry, with op_i and Pi_i as digests (Q-S4-16). The core op `merkleRoot : FreeMon Digest → Digest` (Q-S4-6) gives the root of the Merkle tree of 16 levels over a list of digests.
