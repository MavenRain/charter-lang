# charter-lang specification (draft)

Status: draft before milestone M0. `charter-lang` is a working name.

Fill each section. The quoted line under each heading says what to write
there. Delete the quoted line when the section is complete.

## 1. Purpose

> Write here: what one program describes, what the compiler checks, and what
> it writes. Name the host and the target. Say that the core types and core
> operations are only those of `design/DESIGN.md`.

charter-lang is a language for <the domain>. Its type formers are F1 to F15 of
`formers/FORMERS.md`. Its core data types and core operations are only the
types and operations of `design/DESIGN.md` (the design).

## 2. Programs

A program is a UTF-8 file with a sequence of declarations. The surface is
Agda-like (PLAN Q9, USER ruling 2026-10-27). Each operation has one
canonical form. `langc fmt FILE` prints the canonical text (section 2.6).

### 2.1 Declarations

A definition is a signature line and a clause line:

```
twice : (f : ℕ → ℕ) → ℕ → ℕ
twice f x = f (f x)
```

The clause starts with the name of the signature above it. If the names
are not the same, or if a clause has no signature, the parser gives
`PARSE_CLAUSE_NAME`. Each name after the clause name is a bare binder:
`f x y = t` is the same term as `f = λ x y → t`. The clause `f = λ x → t`
parses, and `fmt` prints it as `f x = t`. An annotated lambda
`λ (x : A) → t` is a different term, and `fmt` keeps it.

The domain file (`domain/domain.lang`) can also declare a data type:

```
data Lot (size : ℕ) : Type where
  makeLot : (lotPrice : ℕ) → Lot size
```

- `data` declares a data type, with zero or more parameter groups. Each
  constructor is on its own line in the block. A constructor type must end
  in the data type applied to its parameters in order. If it does not, or
  if a field has no name, the parser gives `PARSE_CTOR_RESULT`. Each named
  Pi binder of a constructor type is a field: `(addressKey : ℕ)` gives the
  field `addressKey`. A field whose type is the data type itself is a
  recursive field. Its arguments must be the parameters of the data type,
  in order (uniform recursion, section 2.7). If they are not, the checker
  gives `DOMAIN_FAMILY`.

The parser also reads `rec name : T` and `postulate name : T`. The checker
refuses both in each file, `domain/domain.lang` too: `rec` gives
`REFUSE_REC` (rule R3) and `postulate` gives `REFUSE_AXIOM` (rule R2).

The compiler refuses these forms in a program: `data` (`REFUSE_DATA`),
`postulate` (`REFUSE_AXIOM`), and `rec` or a reference to the same or a
later definition (`REFUSE_REC`, rule R3). It also refuses a declaration
that uses a core name, a domain name, the reserved word `Text` or a name
that is already declared (`REFUSE_NAME`). Thus a program cannot add a data
type, an unproved fact or general recursion. Recursion comes only from
`fold` (F6) and `ind` (section 2.7). The compiler writes the target; a
program cannot.

### 2.2 Grammar

`×` binds tighter than `→`. Both nest to the right.

```
decl   := 'postulate' NAME ':' term
        | 'rec'? NAME ':' term NAME NAME* '=' term
        | 'data' NAME group* ':' 'Type' 'where' ctor+
ctor   := NAME ':' term
group  := '(' NAME+ ':' term ')'
term   := 'λ' (NAME | group)+ '→' term
        | prod ('→' term)?
prod   := group '→' term | group '×' prod | app ('×' prod)?
app    := atom atom*
atom   := NAME | NAT | 'Type' NAT | '(' term ')'
```

A NAME starts with an ASCII letter or `_`. The next characters are ASCII
letters, digits, `_` or `'`. The symbol `ℕ` is the name of the natural
numbers. A NAT is a decimal numeral from 0 to 2^64-1 (`LEX_NAT_RANGE` if
it is larger). The keywords are `rec`, `postulate`, `data`, `where`,
`Type`, `fun` and `Sigma`. A non-ASCII character other than `→`, `λ`, `×`
and `ℕ` gives `LEX_CHAR`.

### 2.3 Spellings and ASCII aliases

The grammar uses the canonical spellings. The parser also reads the ASCII
aliases in this table. An alias gives the same term as its canonical form.
`langc check` gives `W_NONCANON` on the first declaration that is not in
canonical form, with the canonical text as `fix`. `fmt` prints only
the canonical spellings.

| Term | Canonical spelling | ASCII alias |
|---|---|---|
| Pi | `(x : A) → B`, `A → B` | `->` for `→` |
| Lambda | `λ x → t`, `λ (x : A) → t` | `\` for `λ`; `fun x => t` |
| Sigma | `(x : A) × B`, `A × B` | `*` for `×`; `Sigma (x : A) B` |
| Natural numbers | `ℕ` | `Nat` |
| Universe | `Type n` | none |

The core names do not change: `ℕ` and `Nat` give the one core name `Nat`.
The value printer of `langc eval`, and some diagnostic messages, use the
ASCII spelling (`->`, `fun x =>`, `Sigma`, `Nat`). The parser reads that
text back through the aliases.

### 2.4 Layout rule

The surface has no keyword at the start of a definition, and an
application continues across lines. Thus the parser uses the columns:

- A declaration starts at column 1.
- A token that is the first token on its line, at a column less than or
  equal to the stop column, ends the current term (as the end of the file
  does). At the top level, the stop column is 1. Thus a term that continues
  on the next line must start that line at column 2 or more.
- In a `data` block, the first constructor sets the constructor column c
  (more than 1). A token at the start of a line at column c starts the next
  constructor. A token at the start of a line at a column less than c ends
  the block.
- A column counts code points, not bytes. `→` is one column.

### 2.5 Comments

A comment starts with `--` and continues to the end of the line. `fmt`
never drops a comment. In canonical form, each comment is a full line:

- A comment above a declaration is directly above it, with no blank line.
- A comment after the last declaration comes after one blank line.
- `fmt` moves an end-of-line comment, or a comment inside a declaration, to
  its own line above that declaration. `langc check` gives `W_NONCANON` for
  that input.

### 2.6 Canonical layout (`langc fmt`)

`langc fmt FILE` parses the file and prints the canonical text on stdout
(exit 0). A lex or parse error prints the diagnostic (exit 1). `fmt` does
not type-check. The canonical text has these properties:

- One line for each signature, each clause and each constructor. A
  constructor line starts with two spaces. `fmt` does not wrap a line.
- One blank line between declarations. No blank at the end of a line. The
  file ends in one newline.
- Only the canonical spellings of section 2.3.
- Parentheses only where the grammar needs them: a Pi, a Sigma or a lambda
  in a Pi domain or on the left of `×`, and an argument that is not an
  atom. For example, `(ℕ → ℕ) → ℕ` keeps its parentheses.
- One lambda for adjacent binders: `λ x y → t`, and
  `λ (g : ℕ → ℕ) (x : ℕ) → t`.
- One binder for each Pi: `(a k : ℕ) → ℕ` prints as
  `(a : ℕ) → (k : ℕ) → ℕ`.
- A definition whose body is a chain of bare-binder lambdas prints as a
  clause with arguments.

`langc check` compares the input with the canonical text one region at a
time. A region is the text from the end of the last line of the previous
declaration to the end of the last line of this declaration. The first
region that is not the same as its canonical text gives `W_NONCANON`. The
end of the file is the last region.

### 2.7 Induction and the Nat rules

`ind` is the dependent eliminator (S2a). Proofs use it. An `ind` on a
constant value reduces before lowering. `langc ir` refuses an `ind` that
stays on a run-time value (`REFUSE_RUNTIME_TREE`).

| Rule | Statement |
|---|---|
| `ind` on `ℕ` | `ind P z s n` with `P : ℕ → Type l`, `z : P 0` and `s : (k : ℕ) → P k → P (natAdd k 1)` has the type `P n`. It computes on a literal and on `natAdd k j` for a literal `j`. A bad motive gives `TYPE_MISMATCH`. |
| `ind` on a domain family | `ind P c1 .. cn x` with `x : F p1 .. pm` and `P : F p1 .. pm → Type l` has the type `P x`. There is one case for each constructor, in order: a Pi over each field, with `ih : P f` after each recursive field `f`, to `P (ctor p1 .. pm fields)`. It computes on a constructor value. |
| uniform recursion | A recursive field of `F` has the type `F p1 .. pm`, and each argument is the parameter of `F` at the same position. Another argument gives `DOMAIN_FAMILY`. `fold` and `ind` take the parameter instance, for example `FreeMon ℕ`. |
| `natAdd` | `natAdd x 0 = x`; `natAdd x (natAdd y j) = natAdd (natAdd x y) j` for a literal `j`. |
| `natLe` | `natLe 0 y = true`; `natLe (natAdd x 1) 0 = false`; `natLe (natAdd x 1) (natAdd y 1) = natLe x y`. |
| `natSub` | `natSub x 0 = x`; `natSub (natAdd x 1) (natAdd y 1) = natSub x y`. |

The `natLe` and `natSub` rows are the USER ruling Q-S2a-3 (`docs/PLAN.md`
section 11). The normalizer cancels a common literal offset in one step.
A closing rule applies only when the offsets agree with it: for a
variable `x`, the terms `natLe 3 x`, `natLe x 0` and `natSub x 3` stay
neutral (the `TYPE_REFL` rows in `test/fronttool.c`).

These symbolic successor rules are for type checking. Execution and Wasm
lowering retain the arithmetic operations that can overflow at the 64-bit
boundary, including operations whose numeric result a proof rule erases.
They evaluate definitions afresh rather than reuse proof-normalized values.
An `ind` on a symbolic successor stays neutral during lowering and is
refused as a run-time `ind`.

## 3. Type formers

> Write here: only the deviations from the formers. Do not copy the forms.
> Give each former whose status in `formers/tcc-wasm.md` is not DONE, and the
> open item (section 9) that records it.

The type formers are F1 to F15 of `formers/FORMERS.md`. This language uses
the tcc-wasm column of the realization matrix. `formers/tcc-wasm.md` gives
the host form of each former.

| ID | Status on tcc-wasm | Effect on this language | Open item |
|---|---|---|---|
| | | | |

## 4. Structures

> Write here: the carriers of Monad (F5), fold and unfold (F6, F7) and
> filter (F8) that the design uses. Name each carrier that the host does not
> give.

- **Monad**: `pure`, `map`, `bind` on <carriers>.
- **Algebra**: `fold` on <carriers>. `unfold` on <carriers>, or the reason
  that there is no `unfold`.
- **Filterable**: `filter` on <carriers>.

## 5. Core types

> Write here (DOMAIN SLOT): only the types of `design/DESIGN.md`. Give each
> type its meaning in the design and its definition in host forms. Mark each
> definition that a probe fact forces with "probe-forced".

| Type | Meaning (design section) | Definition |
|---|---|---|
| | | |

## 6. Core operations

> Write here (DOMAIN SLOT): only the operations of `design/DESIGN.md`. Give
> each operation its type and its meaning in the design.

| Operation | Type | Meaning (design section) |
|---|---|---|
| | | |

## 7. Target and instance encoding

> Write here: what the compiler writes. For a JSON target, give the instance
> rule and the encoding table. For a contract target, give the storage, the
> entries and the guards. Say how each proof erases.

An instance is a top-level definition whose type is a data type (F14).

| Type | Encoding |
|---|---|
| | |

## 8. Host and target

> Write here: the host, its pinned commit (`PIN`), the facts from
> `probe/CAPABILITY.md` that set the design, and the check that the compiler
> runs on its output (for example the axiom report).

## 9. Open items

The open items are in `docs/PLAN.md` section 10 (O-off-1 to O-off-8 and
O1 to O9). The Q items and their rulings are in `docs/PLAN.md` section 11.

## 10. Milestones

The milestones are the slices S0 to S10 in `docs/PLAN.md` section 9. Each
slice has its gate there. `README.md` gives the status of each piece.
