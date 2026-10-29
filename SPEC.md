# charter-lang specification (draft)

Status: draft before milestone M0. `charter-lang` is a working name.

Fill each section. The quoted line under each heading says what to write
there. Delete the quoted line when the section is complete.

## 1. Purpose

This section says what one program describes, what the compiler checks and
what the compiler writes. It names the host and the targets.

A charter-lang program describes a part of the Off-Chain EscrowDAO note (the
note): the constitution `kappa`, the escrow state, the 10 operations and
their laws, in the clear meaning. The constitution can amend itself, thus
the name. `build/langc` checks a program against the rulings R1 to R7 of
`docs/PLAN.md` section 1. Each type constructor is a cell monad or a cocell
comonad, as Cubical Type Theory represents them (R1). Each base type and
operation is one that the note needs (R2). The type formers are F1 to F15 of
`formers/FORMERS.md`. The core data types and core operations are only the
types and operations of `design/DESIGN.md` (the design).

The host is TinyCC (R3, section 8). The targets are Wasm for the client, the
member node and the public verifier, a ZK circuit IR and an FHE circuit IR
(R4, section 7). There is no native C target and no EVM target. The crypto
layer is concrete in v1: FHE, a PLONKish proof system, FROST threshold
signatures and Poseidon (R5, `docs/PLAN.md` section 4). The meaning ends at
the rail. A voucher is data only, and the compiler writes no rail verifier
(R6). R7 gives the agent items of `docs/PLAN.md` section 7.

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
| `ind` on `Option` | `ind P cn cs m` with `m : Option X`, `P : Option X → Type l`, `cn : P none` and `cs : (x : X) → P (some x)` has the type `P m` (Q-S2b-2). It computes on `none` and on `some x`. On another term it stays neutral. A bad motive gives `TYPE_MISMATCH`. `langc ir` refuses it on a run-time value (`test/ir/optind.lang`). |
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

This section gives only the deviations from the formers: each former whose
status in `formers/tcc-wasm.md` is not DONE, and the open item (section 9)
that records it. It does not copy the forms.

The type formers are F1 to F15 of `formers/FORMERS.md`. This language uses
the tcc-wasm column of the realization matrix. `formers/tcc-wasm.md` gives
the host form of each former. Rule R1 (`docs/PLAN.md` section 2) admits a
type constructor only as a cell monad (CM) or a cocell comonad (CC). Only
`domain/domain.lang` declares a family. A program that declares one gets
`REFUSE_DATA`, and a domain family that is not a cell signature or a free
monoid gets `REFUSE_CELL`.

| ID | Status on tcc-wasm | Effect on this language | Open item |
|---|---|---|---|
| F4 | PLANNED: no program name since S1 | A program cannot name `List`, `nil` or `cons` (`REFUSE_NAME`). The domain `FreeMon A` with `fmNil` and `fmCons` replaces it. | O9; Q-S2a-2 (a) |
| F7 | PLANNED: no program name since S1 | No `unfold`. The note has no coinductive data, and `docs/PLAN.md` 3.3 excludes coinductive streams. | none: an exclusion of `docs/PLAN.md` 3.3 |
| F8 | PLANNED: no program name since S1 | No `filter`. No note line needs one, and no core name replaces it. A removal from a keyed map is `nmapDel`. | none |
| F15 | PARTIAL: only the domain file can declare an indexed data type | The domain declares no indexed family at S2d. `Tally n` is an iterated Sigma, not a family. The base types `CtA e` to `SigShare e`, indexed by the epoch value, are open. | Q3 (S5) |

## 4. Structures

This section gives the carriers of Monad (F5), fold and unfold (F6, F7) and
filter (F8) that the design uses. It names each carrier that the host does
not give.

- **Monad**: `tRet` (pure) and `tBind` (bind) on the partial writer
  `T M Z = Option (Z × FreeMon (Voucher M))` (Q5, Q-S2b-2), with the
  Kleisli laws in `examples/kappa.lang`. The domain has no separate `map`.
- **Algebra**: `fold` (F6) on `FreeMon A`: `fmAppend`, the sums over a
  finite support and the transcript fold `tSem` (L287). The dependent `ind`
  on `ℕ`, on the host `Option` and on each domain family (section 2.7) gives
  the proofs and `faultBound`. There is no `unfold` (F7): the note has no
  coinductive data (`docs/PLAN.md` 3.3).
- **Filterable**: there is no `filter` (F8). No note line needs one.
- The host does not give `FreeMon` and `T`. `domain/domain.lang` defines
  both: `FreeMon A` is a domain family, and `T` is a composite of the host
  `Option` and `FreeMon`. The host gives Pi, Sigma, `ℕ`, `Bool` and
  `Option`.

## 5. Core types

Each row is a type of `design/DESIGN.md`: its meaning in the design and its
definition in host forms. "Probe-forced" marks a definition that a probe
fact forces. S2b gives the rows `Tally n` to `T M Z`. S2c gives the escrow
state, the rows `Receipt M` to `Op M`.

| Type | Meaning (design section) | Definition |
|---|---|---|
| `Tally n` | a tally `c : D_E + {bot} → ℕ` with `sum c = n` (Def 2.2, L236). It represents the orbit `X // Sym(M)` (Q7). | an iterated Sigma: the counts of Release, Refund, Hold and bot, and an `Eq ℕ` of their sum to `n` |
| `TallyA n` | an amendment tally `c : B_A + {bot} → ℕ` with `sum c = n` (L226) | an iterated Sigma: the counts of Adopt, Reject and bot, and an `Eq ℕ` of their sum to `n` |
| `Kappa` | the constitution `kappa = (M, t, tA, theta)` (Def 2.1, L234) | `(members : FreeMon Address) × (thr : ℕ) × (thrA : ℕ) × ((c : Tally (fmLength Address members)) → DecE)`. `n` is the length of `members`. The decidable check of `K_wf` is `kappaWellFormed` (Q1). |
| `KappaWf` | `K_wf`, the well-formed constitutions (L240 to L243; Q1 (a)) | `(k : Kappa) × Eq Bool (kappaWellFormed k) true`. `kappaWellFormed k` holds if the keys of `members` ascend and W1 and W2 hold. W3 holds by the type of `theta`. |
| `T M Z` | the partial writer `T Z = 1 + Z x List Voucher` (L285, L286; Q5) | `Option (Z × FreeMon (Voucher M))`. `none` is a stop. `some (z, o)` is a result `z` with the output `o`. Probe-forced: conv has no `Option` eta, thus the one CM form of Q5 has no proof of the right unit (Q-S2b-2). |
| `Receipt M` | a receipt `iota` of the rail: an opaque key and its value `nu(iota)` (L334) | `data Receipt (M : CMon)` with one constructor of a key `ℕ` and a value `cmCarrier M`; `receiptId` and `receiptNu` read them |
| `Ledger M` | a map `Address → A` for ledger and credit. An address that is not in the map has the value 0 of `A` | `FreeMon (ℕ × cmCarrier M)` keyed by `addressKey`. The keys ascend strictly, thus two maps with the same entries are the same list (`nmapGet`, `nmapSet`, `nmapDel`) |
| `Motion` | an open motion of `Gamma_A`: the proposed `kappa'` and the configuration `Y_j` of the amendment ballots (L390) | `Kappa × FreeMon (Option BallotA)` |
| `Vote` | the ballot `b` of `vote u b` (L358): an escrow verdict on the claim `u`, or an amendment ballot on the motion `u` | `data Vote` with `voteE : DecE → Vote` and `voteA : BallotA → Vote` |
| `St M` | the state `s`: `kappa`, the epoch, the position `pos` of the next entry, ledger, credit, the open claims, the spent receipt keys, `Gamma_E` and `Gamma_A`. `L = L_kappa` is not a field: the clear meaning computes it from `kappa` (Q7 (a)) | `Kappa × ℕ × ℕ × Ledger M × Ledger M × FreeMon (ℕ × Claim M) × FreeMon ℕ × FreeMon (ℕ × FreeMon (Option DecE)) × FreeMon (ℕ × Motion)`, made by `stMk` and read by `stKappa` to `stGammaA`. A settled claim and a closed motion leave their maps |
| `Escrow M` | the escrow part `pi_E s` (L405): ledger, credit, claims and spent | `Ledger M × Ledger M × FreeMon (ℕ × Claim M) × FreeMon ℕ`. `stEscrow` gives `pi_E s` |
| `Op M` | one transcript entry: one constructor for each operation of `docs/PLAN.md` 3.2 | `data Op (M : CMon)` with `opDeposit`, `opCast`, `opVote`, `opSettle`, `opWithdraw`, `opBalance`, `opMotion`, `opEnact`, `opAmend` and `opPropose`. The requester is a field. `opAmend` and `opPropose` have no field |

## 6. Core operations

Each row is an operation of `design/DESIGN.md`: its type and its meaning in
the design. The S2c operations (`stInit` to `voucherSum`) take `(M : CMon)`
first, and the Type column starts after it. A result `none` of
`T M (St M)` is a stop.

| Operation | Type | Meaning (design section) |
|---|---|---|
| `faultBound` | `ℕ → ℕ` | `f(n)`, the quotient of `n - 1` by 3, by a fold over `ℕ` (W1, L240) |
| `kappaW1Of`, `kappaW2Of` | `ℕ → ℕ → Bool`, `ℕ → ℕ → ℕ → Bool` | the decidable checks W1 (`n + f(n) < 2t` and `t <= n - f(n)`) and W2 (`t <= tA <= n`) (L240, L241) |
| `kappaWellFormed` | `Kappa → Bool` | the decidable check of `K_wf` (Q1) |
| `thetaThreshold` | `(n : ℕ) → ℕ → Tally n → DecE` | the threshold rule `theta_t` (Ex 2.5): Release if `c(Release) >= t`, Refund if `c(Refund) >= t`, else Hold |
| `tallyReady` | `(n : ℕ) → ℕ → Tally n → Bool` | `Ready_t(X)`: `n - c(bot) >= t` (Def 2.3) |
| `tauE`, `tauA` | `(xs : FreeMon (Option DecE)) → Tally (fmLength (Option DecE) xs)`, and the same form for `BallotA` and `TallyA` | `tau`, with `tau(X)(d)` the count of `d` in the vote vector `X` (Def 2.2, L236) |
| `kappaF` | `(k : Kappa) → (xs : FreeMon (Option DecE)) → Eq ℕ (fmLength (Option DecE) xs) (kappaN k) → DecE` | `F = theta o tau` (Def 2.4). It reads `xs` only through `tau`, thus W3 holds by construction (L243; Q7). |
| `amdThreshold`, `kappaAmd` | `(n : ℕ) → ℕ → TallyA n → DecA`, `(k : Kappa) → TallyA (kappaN k) → DecA` | the amendment rule `Amd_tA` (L395): Adopt if `c(Adopt) >= tA`, Reject if `c(Reject) > n - tA`, else Hold |
| `tRet`, `tNone`, `tEmit` | `Z → T M Z`, `T M Z`, `Voucher M → T M Z → T M Z`, each after `(M : CMon)` and `(Z : Type 0)` | `eta`, the stop, and `emit` with `emit v none = none` (L285, L286) |
| `tBind`, `tKleisli` | `T M Y → (Y → T M Z) → T M Z`, `(X → T M Y) → (Y → T M Z) → X → T M Z`, each after `(M : CMon)` and the type arguments | bind and the Kleisli composition `>=>` of `T` (L286 to L289) |
| `tSem` | `(M : CMon) → (X : Type 0) → (S : Type 0) → (X → S → T M S) → FreeMon X → S → T M S` | the transcript fold `sem` (L287): `sem eps = eta` and `sem (x :: w) = op x >=> sem w`. `tSemNil` and `tSemAppend` state Thm 3.1. |
| `stInit` | `Kappa → St M` | the start state `S_0` of `kappa`: epoch 0, position 0 and empty maps |
| `runDeposit` | `Address → Address → Receipt M → St M → T M (St M)` | deposit `p q iota` (L334, L347 to L349). A spent receipt stops. If not, the ledger of `p` gets `nu(iota)`, the claim `(p, q, nu(iota))` gets the index `pos` and the configuration `bot^M`, the key of `iota` is spent, and `pos` becomes `pos + 1` |
| `runCast` | `FreeMon (Option DecE) → St M → T M (St M)` | cast `X` (L353, L354): always defined, independent of open claims, with no entry or state change. `kappaF` supplies the clear verdict `theta(tau(X))` separately |
| `runVote` | `Address → ℕ → Vote → St M → T M (St M)` | vote `m u b` (L358, L541, L542): the member `m` puts `b` at its position in the configuration of `u`, and `pos` becomes `pos + 1`. A second vote of `m` replaces the first. A requester that is not in `M`, or an unknown `u`, stops |
| `runSettle` | `ℕ → St M → T M (St M)` | settle `c` (L547 to L555) with the current `kappa` (O-off-1). Release and Refund take `n` from the ledger of the payer `p`, add `n` to the credit of `r` (the payee `q` for Release, `p` for Refund) and close `c`. Hold makes an entry only. A claim that is not ready stops |
| `runWithdraw` | `Address → cmCarrier M → St M → T M (St M)` | withdraw `a n` (L380, L381, L559 to L563): `n` leaves the credit of `a`, and the voucher `(a, n, i)` goes to the output at the entry index `i` |
| `runBalance` | `Address → St M → T M (St M)` | balance `a` (L567). It makes no entry |
| `runMotion` | `Address → Kappa → St M → T M (St M)` | motion `m kappa'` (L390, L571, L572): `m` is a member and `kappa'` is in `K_wf`, else it stops. The motion index is the entry index, and `Y_j` is `bot^M` |
| `runEnact` | `ℕ → St M → T M (St M)` | enact `j` (L397 to L403) on `Amd_tA(Y_j)` of the current `kappa`. Adopt installs `kappa'`, the epoch becomes `e + 1`, and `clear_{M'}` sets each open configuration to `bot^{M'}` (O-off-2). Reject closes `j`. Hold keeps the state. Each verdict makes an entry. An unknown motion stops |
| `runAmend`, `runPropose` | `St M → T M (St M)` | amend (L411, L412) and propose `p ; q` (L415 to L417): the identity. propose is vacuous over the discrete `Obj_M` |
| `opStep` | `Op M → St M → T M (St M)` | the meaning of one entry. `tSem M (Op M) (St M) (opStep M)` is the meaning of a transcript (Thm 3.1) |
| `enactEscrow` | `(j : ℕ) → (s : St M) → Eq (T M (Escrow M)) (escrowOf M (runEnact M j s)) (escrowAs M (runEnact M j s) (stEscrow M s))` | Thm 4.3 (L405): enact does not change `pi_E s`. A general proof: ind on `DecA`, then on `Option` |
| `sumClaims`, `ledgerSum`, `voucherSum` | `FreeMon (ℕ × Claim M) → Address → cmCarrier M`, `Ledger M → cmCarrier M`, `FreeMon (Voucher M) → cmCarrier M` | the sums of Invariant I (the open claims of the payer `p`, Thm 4.1) and of Conservation (Thm 4.4) |

## 7. Target and instance encoding

This section says what the compiler writes and how each proof erases.
charter-lang has no JSON target and no contract target (R4).

`build/langc build FILE -o OUT` writes one Wasm 1.0 module (`src/wasm.c`).
The module has no import section. Function 0 is a bump allocator, and each
IR entry is an `i64` export (`design/DESIGN.md` 3.2). TinyCC has no Wasm
back end, thus `build/langc` writes each byte. The gate runs `wasm-validate`
on each module and a differential against `langc eval` (`test/gate.sh`).
At S2d the module comes from the kit IR, with the ops ADD, SUB, MUL, EQ,
LE, ADD_CARRY, MUL_CARRY and OR. S3 adds the stream entries for the clear meaning
of the domain, with the client and node entry points. The FHE circuit IR
(S5) and the ZK circuit IR (S7) are planned (`docs/PLAN.md` 5.2 and 5.3).

An instance is a top-level definition whose type is a data type (F14).

| Type | Encoding |
|---|---|
| `ℕ` | an `i64`. Wasm `i64` arithmetic wraps mod 2^64, thus `A = ℕ` has a 64-bit bound at the target points (Q8) |
| `Proof P`, `Sig_e m` | erased: the meaning is a `Trunc` (`docs/PLAN.md` 4.1, L490) |
| `Bool` | an `i64`, 0 or 1. In a word stream: one word |
| a data value (`DecE`, `BallotA`, `DecA`, `Bit`, `Address`, `Receipt M`, `Rule`, `Vote`, `Op M`) | in a word stream: the constructor index (from 0, in declaration order), then each field in declaration order. A family with one constructor keeps its tag word 0. Examples: `decHold` is `2`, `address 5` is `0 5`, `receipt 5 40` is `0 5 40` |
| `FreeMon A` | the data rule (Q-S3-6): `fmNil` is `0`; `fmCons` is `1`, the head, then the tail. The list `[x1, x2]` is `1 x1 1 x2 0` |
| `Option A` | `0` for `none`; `1`, then the value, for `some` |
| a Sigma or a record (`Voucher M`, `Claim M`, `Kappa`, `Motion`, `St M`) | each component in order, with no tag. `Voucher M` is 4 words and `Claim M` is 5 words |
| an `Eq ℕ` component | no word (erased). The decoder checks the equation. `Tally n` is 4 words (the counts of Release, Refund, Hold and bot), and their sum must be `n` |
| `cmCarrier M` | one word. Each entry sets `M = natCMon` (Q8), thus a stream has no type argument |
| `T M Z` | `0` for a stop; `1`, the `Z`, then the voucher list for a result |
| `Kappa` | the member list, `thr`, `thrA`, then the `Rule` (Q-S3-1). `ruleThreshold t` is `0 t`. The `t` of the rule is not tied to `thr`: `kappaWellFormed` checks the key order, W1 and W2 only |
| a function, a type, a universe (`CMon`), an `Eq` over a type that is not `ℕ` | no stream form. A def with such a parameter or result is not an entry |

A scalar entry has `ℕ` or `Bool` for each parameter and for the result. It
is an `i64` export with `i64` parameters. With the flag `--words`
(Q-S3-10), `langc ir`, `abi` and `build` also make each program def with a
stream form a stream entry (Q-S3-7). A stream entry has the Wasm type
`(n : i64) -> i64`, and the module exports its memory as `memory`
(Q-S3-11). The host writes the input stream (the stream of each parameter,
in order) from byte 0, and calls the entry with the word count `n`. The
heap starts at byte `8n`. The entry decodes the input, runs the body and
encodes the result at the end of the heap: the first word is the count
`m`, then the `m` words follow. The entry returns the byte address of the
output. The codec of a recursive family uses a stack on the heap
(Q-S3-12).

The input count must fit in the current memory before it is scaled by 8;
an oversized count traps. Each result component is strict, including an
erased `Eq ℕ` proof: overflow while computing the proof traps. In a module
with a stream entry, `memory` is reserved for the memory export. `build`
refuses a program entry with that name with `REFUSE_EXPORT`.

A bad stream traps (Q-S3-8). These streams are bad: a tag word that is not
a constructor index of its family, a short stream, a word left over, and a
false `Eq ℕ` component. `langc eval --words FILE NAME WORDS` is the
reference: it prints the output words on one line, or `trap`.
`examples/node.lang` has the node entry points (`nodeInit`, `nodeStep`,
`nodeFold`). `examples/client.lang` has the client entry points (the 10
run functions at `natCMon` and `clientVerdict`). The gate compares `langc
eval --words` and Wasm on each row of `test/eval/stream.txt`.

## 8. Host and target

This section gives the host, its pinned commit, the probe facts that set
the design and the checks that the compiler runs on its output.

The host is TinyCC (R3). `PIN` records the commit `mob@0fb54300` (tcc
0.9.28rc, 2026-09-04, AArch64 Darwin) and the gate tools: node v23.10.0,
`wasm-validate` and `wasm-objdump` 1.0.39. The kit is `tcc-wasm` of
lang-template 5265a2a. `docs/PLAN.md` section 8 gives the port sources and
their SHAs.

`probe/CAPABILITY.md` is the kit template, and its sections are not filled.
These probe facts set the design:
- TinyCC has no Wasm back end, thus `build/langc` writes the module bytes
  (`design/DESIGN.md` 3.2).
- Wasm `i64` arithmetic wraps mod 2^64 (`design/DESIGN.md` 3.2, Q8).
- The conversion check has Sigma eta but no `Option` eta (S2b probe), thus
  `T` is the composite of Q-S2b-2, not the one CM of Q5.
- The builtins have no division, thus `faultBound` computes `f(n)` by `ind`.

`make check` runs `test/gate.sh` (the parse and check refusals, `langc
eval`, `wasm-validate` on each module and the differential), then
`test/review.sh`, `build/fronttool` and `build/checktool`. `langc check`
refuses `postulate` (`REFUSE_AXIOM`) and `rec` (`REFUSE_REC`) in each file,
the domain file too (section 2.1). Thus a file that checks has no axiom,
and the compiler needs no separate axiom report.

## 9. Open items

The open items are in `docs/PLAN.md` section 10 (O-off-1 to O-off-8 and
O1 to O9). The Q items and their rulings are in `docs/PLAN.md` section 11.

## 10. Milestones

The milestones are the slices S0 to S10 in `docs/PLAN.md` section 9. Each
slice has its gate there. `README.md` gives the status of each piece.
