# charter-lang plan

This plan has 11 sections. `design/DESIGN.md` holds the USER ask (section
1) and the USER rulings (section 2). `Lnnn` is a line of
`design/OFFCHAIN-ESCROWDAO.html`, the design note snapshot. An item marked
(a) in section 11 is the recommended option. The USER ruled Q1, Q2, Q4, Q6,
Q8 and Q9 on 2026-10-27 (section 11 quotes each ruling). The other Q items
are OPEN.

## 1. Rulings and readings

| ID | Ruling | Source |
|---|---|---|
| R1 | Type constructors: only cell monads and their duals, as Cubical Type Theory represents them | DESIGN 1 (USER) |
| R2 | Base types and operations: only what the note needs | DESIGN 1 (USER) |
| R3 | Host: TinyCC | DESIGN 1 (USER) |
| R4 | Targets: Wasm (client, and also the member node and the public verifier), ZK circuit IR, FHE circuit IR. No native C target. No EVM | DESIGN 2 (USER) |
| R5 | Crypto in v1: all concrete (TFHE or BFV, a PLONKish proof system, FROST threshold signatures, Poseidon) | DESIGN 2 (USER) |
| R6 | Rail: the meaning ends at the rail. Vouchers are data only. No emitted rail verifier | DESIGN 2 (USER) |
| R7 | Agent adoption: the 6 items of the ask (section 7) | DESIGN 1 (USER) |

Claude readings (not USER rulings):
- The kit is `tcc-wasm`, because R4 makes Wasm the only executable target.
- The name: the constitution kappa that amends itself is the charter.
- The note is the only domain source. A base name that no note line needs
  is not admitted (section 3.3).

## 2. R1: type constructors

### 2.1 The precedent reading

charter-lang takes the reading of leaf-lang (PLAN 2.1), intent-lang (PLAN
2.2) and resolve-lang (PLAN 2). The ask in DESIGN 1 has no bracketed clause
about the ambient category. The reading below does not need one (Q1).

| Part | Cubical TT | R1 limit |
|---|---|---|
| Ambient | Pi, Sigma, `Path`, `PathP`, `I`, `i0`, `i1`, `transp`, `hcomp`, `U`, `Glue`, `ua`, the builtin `Unit` | none: the internal language of the category |
| CM, cell monad | a `family` with a type parameter: the parameter is the one field of one generator `eta : A -> T A`; each other constructor takes closed base data and arguments of type `T A`, or is a path in `T A` | else `REFUSE_CELL` |
| CC, cocell comonad | a `cofamily` with one observation `eps : D A -> A`; each other field has type `D A -> D A` or `D A -> E -> D A` with `E` closed data | else `REFUSE_CELL` |

A family with no type parameter is a base type, not a type constructor.
R2 limits it, not R1. Only `domain/domain.lang` declares a family or a
cofamily. A program that declares one gets `REFUSE_DATA`. `Partial` is not
a former: a system is legal only as the side of `hcomp` (quorum-lang 2.2).

### 2.2 Each type former the note needs

| Former | Note use | Status |
|---|---|---|
| Pi | functions, Kleisli arrows `S -> T S`, `ChoiceRule` (L234, L285) | ambient (Q2) |
| Pi from a finite base type | finite maps `M -> X`: `ledger`, `credit`, `Gamma`, `ballot` (L234, L256) | ambient Pi; not a constructor |
| Sigma | `kappa : K_wf` (L157, L260), `G = Sigma` (L251) | ambient (Q1) |
| Record | `Voucher`, `Claim`, `kappa`, `E_off`, `Gamma` (L228, L256, L257, L264) | named iterated Sigma (Q4) |
| `Path`, `I`, `transp`, `hcomp`, `U`, `Glue`, `ua` | the law statements in section 6 | ambient |
| `Option` | `X + {bot}`, `D_E + {bot}` (L158, L226, L234) | CM: `some` is the generator, `none` takes no argument |
| `T` (partial writer) | `T Z = 1 + Z x List Voucher` (L285, L286) | the composite `T M Z = Option (Z x FreeMon (Voucher M))`, a definition in `domain/domain.lang`; a dependent `ind` on `Option` for the Kleisli laws (Q5, Q-S2b-2) |
| `FreeMon` (List) | `List Claim`, `List Voucher`, `Op*` (L256, L285, L287) | rule R1 second class (Q-S2a-2 (a)), cons form in `domain/domain.lang`: `fmNil`, `fmCons`; `fmAppend` by `fold`; the unit and associativity laws are `Eq` proofs by `refl` and `ind` (S2a) |
| `FinSet` | `Fin Receipt`, `Set Nullifier`, coalitions `S` (L237, L256, L519) | CM in generator form (finite multiset shape with an idempotence path), or a sorted map in the meaning (S2 picks one; both are CM or base). S2b: the member set `M` of `kappa` is a `FreeMon Address` with strictly ascending keys, checked in `kappaWellFormed` (D40) |
| `Trunc` | the meaning of `Proof` and `Sig_e m` (L209, L210) | CM with one 1-cell `squash` |
| `Tally` | the orbit `X // Sym(M)` (L236, L251) | base type, no HIT (Q7) |
| `CtA`, `CtOneHot`, `CtBit`, `DecShare`, `SigShare` | `Ct_e`, `Share_e` (L207, L208, L520) | base types indexed by the epoch value (Q3) |
| `Nat`, `Bit` | section 3.1 | base types (Q6) |
| CC (`cofamily`) | none | R1 admits it; no family in `domain/domain.lang` uses it |
| binary `Sum`, `Either`, `Stream` | none | not admitted (no note line needs them) |
| `Lan`, `Agg`, `Gov` | L251 to L253 | not a former: erased at discrete `D` (Prop 2.6, L247) |

### 2.3 Enforcement

- `REFUSE_CELL` in `src/front/check.c`, ported from intent-lang and
  resolve-lang (S1). The test is in the `test/fronttool.c` domain
  regressions, because a program gets `REFUSE_DATA` before the criterion.
- `REFUSE_DATA` for a `family` or `cofamily` outside `domain/domain.lang`.
- `REFUSE_NAME` for a builtin cons `List`, `nil` or `cons`.

## 3. R2: base signature

### 3.1 Base types

| Name | Meaning | Operations | Cites |
|---|---|---|---|
| `DecE` | `D_E = B_E = {Release, Refund, Hold}` | equality, case | L226, L245, L364 to L369 |
| `BallotA`, `DecA` | `B_A = {Adopt, Reject}`, `D_A = {Adopt, Reject, Hold}` | equality, case | L226, L395, L399 to L402 |
| `Bit` | flags `closed`, `ok`, `z`, `(r, rf)`, `(ad, rj)` | equality, `+`, `bit * A`, case on a pair with `(1, 1)` excluded | L515, L551 to L554, L581 to L592 |
| `Nat` | epochs, positions, counts, thresholds | `+`, `-` (truncating), `<=`, `<`, `e + 1`, `f(n) = floor((n-1)/3)` | L229, L236, L246, L266, L321, L395 |
| `A` | monoid plus commutativity, cancellation and a decidable order with witness `monus`; `CMon` structure, Pi parameter (Q8) | `+`, `0`, partial `-` defined iff `n <= credit a`, `<=`, sum over finite support, `bit * A` | L227, L373, L381, L421, L605 |
| `Address` | opaque key | equality, map key | L256, L360 |
| `Receipt` | opaque, issued by the rail | `nu : Receipt -> A`, set membership, insert | L228, L256, L533 |
| `Voucher` | record `Address x A x Nat` | construct, sum of amounts | L228, L382, L421 |
| `Claim` | record `(p, q, n)` | projections | L257 |
| `Subj` | claim index or motion index; `B_u` is `B_E` or `B_A` | equality, case | L270, L513 |
| `Tally` | `c : D_E + {bot} -> Nat` with `sum c = n` | count, sum, lookup, `tau` | L236, L238 |
| `Kappa` | `(members, t, tA, theta)` in the clear (`members` is `M`, D40); in the representation `(root, t, tA, theta)` | projections, `wellFormed` (W1 to W3) | L234, L239 to L242, L511, L572 |
| `Op` | the 10 operations of section 3.2 | case | L298, L332 to L341 |
| `Digest`, `Nullifier`, `Key` | opaque values of the representation | equality | L496, L497, L522 |
| `CtA e`, `CtOneHot e`, `CtBit e` | ciphertexts under `pk_e` (Q3) | the FHE ops of section 5.3 | L207, L520, L549 to L560 |
| `DecShare e`, `SigShare e` | shares of `sk_e`, of the signing key of `vk_e` | combine over `S` in `A_t` | L198, L208, L551 |

Weakest structure for each use of `A`:

| Use of `A` | Note | Weakest level |
|---|---|---|
| `+` | L227, L374 | magma |
| `0` (start state, empty sum) | L374 | monoid |
| `<=` as `exists d. a + d = b` | L227, L375 | monoid (a preorder) |
| `<=` decided at run time (withdraw guard) | L605 | monoid plus decidable order |
| partial `-` (one value when `n <= c`) | L380, L381 | monoid plus commutativity, cancellation, decidable order |
| sum over finite support | L373, L421, L422 | monoid plus commutativity |
| `bit * A` (select `a` or `0`) | L551 to L554 | monoid |
| cancellation | L381 | monoid plus cancellation |
| Invariant I | L372 to L374 | monoid plus commutativity, cancellation |
| Cor 4.2 | L375, L376 | monoid plus commutativity |
| Conservation | L420 to L422 | monoid plus commutativity |
| radix `u64` in Wasm, FHE, ZK range checks | Q-C2, Q-C3 | `Nat` (target points only: S3, S5, S7) |

The declared level is the join of the rows: monoid plus commutativity,
cancellation and a decidable order. `Nat` appears only at the three target
points.

### 3.2 Operations

One line per operation: the primitive ops it needs (L298, L332 to L341).

- `deposit p q iota`: `nu`, set membership and insert on `spent`, `A` add
  into `ledger p`, list append, fresh claim index, new `Gamma_E` record
  with `X_c = bot^M` (L334, L347 to L349, L527).
- `cast X`: `theta o tau` at `X`: tally count, table lookup (L353, L354).
- `vote u b`: map update `Gamma[(u, m) |-> b]`, nullifier insert and
  replace (L358, L541, L542).
- `settle c`: nullifier set size `>= t` in the clear, tally sum, `theta`
  lookup giving `(r, rf)`, decrypt `z = r + rf`, `A` add and subtract,
  `bit * A`, claim removal, close flag (L547 to L555).
- `withdraw n`: `n <= credit a` under FHE, partial subtraction, voucher
  `(a, n, i)` with `i` the transcript position, signature check
  `sigValid a (n, head)` (L380, L381, L559 to L563, L605).
- `balance`: read `credit a`, key switch to `pk_a`, no entry (L567).
- `motion kappa'`: `wellFormed kappa'`, fresh motion index, `Gamma_A`
  append, ZK membership proof (L390, L571, L572).
- `enact j`: `Amd_tA` on `tau(Y_j)`, three-way case, install `kappa'`,
  `clear_M'`, `e + 1`, DKG, key switch of every credit, certify the new
  keys (L395, L403, L584 to L589).
- `amend`: identity, no entry (L411, L412).
- `propose p ; q`: vacuous over discrete `Obj_M` (L415 to L417).

### 3.3 Exclusions (normative)

charter-lang does not admit: floats or reals (L227, L229); strings (no note
line uses one); clocks and timestamps (L276); general recursion and loops
beyond the fold over `Op*`, finite sums (L287, L422) and the proof former
`ind` (S2a); `rec` and postulates in each file, the domain file too
(`REFUSE_REC`, `REFUSE_AXIOM`; SPEC 2.1); coinductive
streams; mutable global state and exceptions (partiality is `Option` in
`T`, L285); a comparison on ciphertexts for the settle guard (L376);
code that runs at a recipient (L382); non-discrete decision categories
(L226, L622); a functor between member sets (L623); network, messaging,
gas, block order and EVM storage (L161, L182); arithmetic on `A` beyond
`+`, partial `-`, order and `bit * A`; fair order, censorship resistance,
rail guarantees, turnout hiding and payee privacy (L631 to L634, L650).

## 4. Crypto layer

### 4.1 Representation types and meaning maps

| Type | Meaning | Cite |
|---|---|---|
| `Ct_e alpha` | `Dec_sk_e : Ct_e alpha -> alpha` | L207 |
| `Share_e alpha` | t-of-n sharing; reconstruct over `S` in `A_t` | L208 |
| `Proof P` | `P`, erased (`Trunc`) | L209, L490 |
| `Sig_e m` | exists `S` in `A_te`, `S` approves `m` (`Trunc` of a Sigma) | L210 |

The meaning maps are law-only (Q3 (a)): no program calls `Dec_sk_e`. Only a
coalition in `A_t` evaluates it (L199, L490).

### 4.2 Equations as oracles

- (1.1) `Dec_sk(Eval_f c) = f(Dec_sk c)` (L194): the FHE differential test
  at S5 compares each FHE circuit with the clear meaning.
- (1.2) `Check(e_i)` implies `sem(r_i) = sem(op_i) sem(r_{i-1})` (L196):
  the verifier test at S8.
- (1.3) `sk = sum_{i in S} lambda^S_i sk_i` (L198): the FROST test at S4
  and the threshold decryption test at S6.

### 4.3 What runs under FHE and what runs in the clear

- Under FHE: the tally `sumOver` of the one-hot ballots (L549), the
  `theta` lookup on the packed tally (L550), `r + rf` (L551), the credit
  updates `credit q + r*n` and `credit p + rf*n` (L552, L553), the
  comparison `n <= credit a` (L560), `amd tA ty` (L581).
- In the clear: `Ready_t` on the public nullifier set size (L547), the
  hash chain, the FROST check, the ZK verify.
- Decrypted outputs: `z` at settle (L551), the `ok` bit at withdraw
  (L560, L561), `(ad, rj)` at enact (L581). `balance` goes only to `a` by
  key switch (L567, L608).
- `Eval` is public and deterministic. So each member node and the public
  verifier recompute it (L459).

### 4.4 Concrete choices and leakage

Each concrete choice is a Q item in section 11: Q-C1 FROST ciphersuite,
Q-C2 FHE scheme and parameter set, Q-C3 proof system, Q-C4 hash, Q-C5 key
generation at enact, Q-C6 where the crypto runtime lives in Wasm, Q-C7
threshold decryption. The note states the leakage, and charter-lang keeps
it: turnout under `ell` (L634), past epochs readable by any `t_e` of their
members (L635), no payee or amount privacy (L650).

## 5. Targets

### 5.1 Wasm: client, member node, public verifier

- Writer: the kit `src/wasm.c` (Wasm 1.0 bytes, `i64` exports, no import
  section), extended at S3, S4, S5 and S8. TinyCC has no Wasm back end, so
  `build/langc` writes every byte (DESIGN 3.2).
- Client module (S5, S7): ballot encryption under `pk_e`, the nullifier
  `PRF_k(e, u)`, the witness for the vote and motion proofs.
- Member node and public verifier module (S8): the transcript fold
  `sem(w . op) = sem(w) >=> sem(op)` (L287), `Check(e_i)` recompute (hash
  chain `h_i = H(e_i)`, FHE `Eval` recompute, ZK verify, FROST verify;
  L196, L502, L606).
- Gate: wasm-validate on each module; differential against `langc eval` on
  the clear meaning (S3); the oracles of section 4.2.

### 5.2 ZK circuit IR

- Writer: port zkpolicy-lang `src/zkml.c`, `src/zkml.h` and
  `src/zkml-names.h` (1d263fb) to emit the zkml-lang Circuit IR (968dce4).
- Printer: `build/halo2print` (Halo2, KZG, BN254) under Q-C3 (a).
- Statements: vote, "exists m k. commit k in root and nf = PRF k (epoch,
  u) and beta encrypts one ballot of B_u" (L539, L540, L601, L602); motion
  membership (L571); decryption share proofs (L503, L603); proof of
  correct dealing (Q-C5 (a), L607).
- "beta encrypts one ballot" is an LWE well-formedness proof: arithmetic
  mod 2^64 in Fr with a quotient witness, 64-bit range checks and a
  one-hot check (Q-C3 (a)).

### 5.3 FHE circuit IR (new)

- A new text IR that `build/langc` prints. Its ops: radix `u64` add,
  `bit * A` (ciphertext bit times clear `A`), the comparison
  `n <= credit a`, `sumOver` of one-hot ballots, and PBS lookup tables for
  `theta o tau`, `Amd_tA` and the credit updates (L549 to L560, L581).
- The Wasm runtime (Q-C6) evaluates it. Each member node recomputes it.
- Gate: the differential of equation (1.1) on each FHE circuit against the
  clear meaning (S5).

## 6. Laws

The progress count "laws discharged" in `langc check --json` counts the
law definitions of a program as `"laws":"k of m"` (S2a): `m` is the number
of definitions whose type is `Eq ..` under zero or more Pi binders, and `k`
is the number of them that type-check. A postulate is not a law. S2b,
S2c and S2d state the rows of this table as law definitions (column Slice).

| Law | Statement | Cite | Slice |
|---|---|---|---|
| W1, W2 | `n + f(n) < 2t`, `t <= n - f(n)`, `t <= tA <= n` | L240, L241 | S2b. Discharged by examples/kappa.lang `w1Ex4`, `w2Ex4`, `w1Ex7`, `w2Ex7`, `wellFormed4`, `wellFormed7`, `wellFormedBad`, `w1False42`, `w1False44`, `w1False53`, `w2False435`, `w2False432` (domain `kappaW1Of`, `kappaW2Of`, `kappaWellFormed`) |
| W3 | `F(g.X) = F(X)` for each `g` in `Sym(M)`; holds by construction for `F = theta o tau` | L242, L243 | S2b. Discharged by examples/kappa.lang `w3Ex4` (`kappaF` on `x4` and `x4Perm`) and `fViaF4` |
| Orbit constancy | `F`, `Ready_t`, `Amd_tA` are constant on orbits | L238, L272, L396 | S2b. Discharged by examples/kappa.lang `w3Ex4` (`F`), `orbitReady4` (`Ready_t`), `orbitAmd4` and `orbitAmd7` (`Amd_tA`) |
| Kleisli laws of `T` | unit and associativity | L286 to L289 | S2b. Discharged by domain `tKUnitL`, `tKUnitR`, `tKAssoc` (from `tUnitL`, `tUnitR`, `tAssoc`) and examples/kappa.lang `kleisliUnitL`, `kleisliUnitR`, `kleisliAssoc`, `emitNone`, `bindPoint` |
| Thm 3.1 | `sem(w ++ w') = sem(w) >=> sem(w')`, `sem(eps) = eta` | L287 to L289 | S2b. Discharged by domain `tSemNil`, `tSemAppend`, `tSemCons` and examples/kappa.lang `semNil`, `semAppend`, `semPoint`, `semStop`. `tSemAppend` holds at each state `s`, because conv has no funext |
| Monoid laws | of `A` (with cancellation, L381) and of `FreeMon` | L227, L288 | S1, S2a |
| Invariant I | Thm 4.1 | L372 to L374 | S2c. Law points on one valid transcript from `S_0` (`iT1` to `iT6`, n = 4; D68): domain `sumClaims` and examples/escrow.lang `invIOf`, `iInv1` to `iInv6`, `iT1Ledger`, `iT1Claims`, `s1NotI` (the state `s1` is not reachable and fails the test). The mutant M1 of `runDeposit` is killed. The general proof is open |
| Cor 4.2 | `n <= ledger p` is derivable | L375, L376 | S2c. Law points on the same transcript (D68): examples/escrow.lang `corOf`, `iCor1` to `iCor6` |
| Conservation | Thm 4.4 | L420 to L422 | S2c. Law points on the same transcript (D68): domain `ledgerSum`, `voucherSum` and examples/escrow.lang `spentSum`, `consOf`, `iCons1` to `iCons6`, `iT5Spent`, `iT5Out`. The mutant M3 of `runWithdraw` is killed. The general proof is open |
| Thm 4.3 | `pi_E` commutes with `enact` | L405 | S2c. Discharged by domain `enactEscrow` (a general proof: ind on `DecA`, then on `Option`; D67) and examples/escrow.lang `adoptThm43`, `holdThm43`, `adoptEscrow`, `rejectEscrow`, `holdAEscrow`. The mutant M2 of `stAdopt` is killed by `adoptEpoch` |
| Thm 4.5 | `kappa` in `K_wf` and `L = L_kappa` along each valid `w` | L423 | S2c. Law points: examples/escrow.lang `adoptWf`, `iT6N`. `L = L_kappa` holds by construction: `St` has no `L` field, and the clear meaning computes `L` from `kappa` (Q7 (a)) |
| Prop 3.3, 3.4 | independent ops commute; one history | L316, L320 | S2d (tests). S2c law points: examples/escrow.lang `p33BalDep`, `p33Ledger`, `p33Spent` (Prop 3.3; each entry op writes `pos`, D69) and `q4Count`, `q7Count`, `p34Ex4`, `p34Ex7`, `p34T2` (Prop 3.4, the quorum lemma from W1, D70) |
| (1.1), (1.2), (1.3) | the oracles of section 4.2 | L194 to L198 | S4 to S8 |

## 7. Agent adoption

Each of the 6 items of the ask (DESIGN 1), with its deliverable, slice and
gate. leaf-lang 47a6f36 is the port source for `fmt`, `check --json`,
`AGENTS.md` and the README table.

| Item | Deliverable | Slice | Gate |
|---|---|---|---|
| 1. One canonical form per operation, `langc fmt` | canonical printer (port leaf `CMD_FMT`, src/main.c:44); `W_NONCANON` with a fix for each non-canonical input (Q9) | S1 | `fmt` is idempotent and round-trips on each example and on `test/fmt/` |
| 2. `langc check --json`, fix hints, counts | JSON diagnostics `code`, `span`, `expected`, `found`, `fix`, `retry` (port leaf :84 and `docs/DIAGNOSTICS.md`); counts `{parsed, typed, laws discharged}` (section 6) | S1 (shape, parsed, typed), S2 (laws) | each refusal code has a JSON shape test; counts are in each result |
| 3. SKILL.md, 3 to 5 graded examples | `skills/charter-lang/SKILL.md`, a grammar card, 5 graded examples (deposit and settle; vote and tally; withdraw; motion and enact; a refused program) | S9 | each example passes `check`; the refused one gives its code |
| 4. MCP server in TinyCC | `langc mcp`: a stdio MCP server in C that tcc builds; tools `check`, `fmt`, `list-base`, `show-law` | S9 | a stdio test drives `check` on each graded example |
| 5. AGENTS.md and README table | the routing rule and "When to reach for charter-lang" | S0, S9 | the table names the slice of each PLANNED row |
| 6. Token count vs Python and Rust | `docs/TOKEN-BASELINE.md`: one task (deposit, vote, settle, withdraw) in charter-lang, Python and Rust, counted by a fixed offline proxy (O7) | S9 | the counts and the method are in the file |

## 8. Port sources (SHA at S0)

| Repository | SHA | What charter-lang ports |
|---|---|---|
| lang-template | 5265a2a | the `tcc-wasm` kit (whole tree at S0) |
| leaf-lang | 47a6f36 | surface, `fmt`, `check --json`, `docs/DIAGNOSTICS.md`, AGENTS.md and README shape, PLAN 2.1 and 7 |
| quorum-lang | 09f7f59 | PLAN 2 (R1), PLAN 4.3 (FROST, RFC 9591), record form (its O15) |
| intent-lang | 67445ae | `REFUSE_CELL` criterion in check.c |
| resolve-lang | 632d819 | `REFUSE_CELL` criterion in check.c |
| zkpolicy-lang | 1d263fb | `src/zkml.c`, `src/zkml.h`, `src/zkml-names.h`; cubical kernel parts |
| zkml-lang | 968dce4 | Circuit IR and `build/halo2print` (used, not copied) |
| escrow-lang | 34203a2 | DENOTATIONAL-DESIGN sections 2, 3, 6; Prelude.esc sections 1 to 6; fixtures and mutants as seeds |
| agent-lang | 96e5473 | diagnostic fix text |
| dil-lang | 9e57528 | diagnostic fix text |

## 9. Slices

Each slice stages only. The USER commits. Each gate ends with `make check`
EXIT 0 (serial log with `echo "EXIT $?"`).

| Slice | Scope | Gate |
|---|---|---|
| S0 | seed from the `tcc-wasm` kit; DESIGN, PLAN, README, AGENTS | kit gate EXIT 0; dash scan clean |
| S1 | front end on the leaf surface (Q9); R1 cells and `REFUSE_CELL`, `REFUSE_DATA`; base enums, `Nat`, `Bit`, `A` as `CMon` (monoid plus commutativity, cancellation and a decidable order; Pi parameter, Q8), records (Q1, Q2, Q4, Q6); `langc fmt`; `langc check --json` with fix hints and counts parsed and typed | fmt round-trip; one JSON shape test per refusal code; R1 refusal rows; kit regressions pass |
| S2a | checker formers (O8, O9; USER 2026-10-27 "Split S2a/S2b (Recommended)"): a dependent `ind` for `Nat` and for each domain family; a recursive field with the uniform parameters of its family; `FreeMon` in place of `Stack` and `Tree`; the `Nat` instance of `CMon`; the `laws` count | rows for `ind` and uniform recursion in the tools; a mutant of each former is killed; kit regressions pass on `FreeMon` |
| S2b | domain prelude in the clear, part 1 (Q-S2b-1): `kappa` and W1 to W3; `Tally`, `theta` and `Amd` (Q7) with orbit constancy; `T` as the composite with a dependent `ind` on `Option` (Q5, Q-S2b-2) and the Kleisli laws; the transcript fold and Thm 3.1; law discharge of the S2b rows (section 6) | each S2b law row discharged on the examples; mutants of `theta`, W1 and the `Option` `ind` reduction are killed |
| S2c | domain prelude in the clear, part 2 (Q-S2b-1, Q-S2c-1): the state types; the 10 operations (3.2) and their `tSem` fit; Invariant I, Cor 4.2, Conservation, Thm 4.3, Thm 4.5; the SPEC 5 and 6 rows of the S2c types and operations; law discharge of the S2c rows (section 6) | each S2c law row discharged on the examples (Invariant I, Cor 4.2, Conservation and Thm 4.5 as law points, D68; Thm 4.3 as a general proof); the mutant of Invariant I is killed |
| S2d | domain prelude in the clear, part 3 (Q-S2c-1): Prop 3.3 and 3.4 (tests); O-off-1 to O-off-8 (Q10 (a)); SPEC stubs 1, 3, 4, 7 and 8; README and AGENTS | each S2d law row discharged on the examples; SPEC has no "Write here" quote |
| S3 | Wasm for the clear meaning (client and node entry points) | wasm-validate; differential against `langc eval`, 0 mismatches |
| S4 | Poseidon2 (Q-C4), Merkle root, PRF, hash chain; FROST verify (Q-C1) | published test vectors (RFC 9591 Appendix E; Poseidon2 reference vectors for the chosen field) |
| S5 | TFHE runtime (Q-C2, Q-C6) and the FHE circuit IR (5.3) | equation (1.1) differential on each FHE circuit; PBS time budget recorded |
| S6 | threshold decryption with noise flooding (Q-C7), key switch, key generation at enact (Q-C5) | equation (1.3) test for decryption; decrypt after key switch equals the clear value |
| S7 | ZK circuit IR writer (5.2) and the proof statements | each statement prints with `build/halo2print`; a false witness is refused |
| S8 | member node and public verifier in Wasm | equation (1.2) on recorded transcripts; a changed entry is refused |
| S9 | SKILL.md, `langc mcp`, token baseline, README table update | section 7 gates |
| S10 | close: STATUS, VALIDATION, final gate, O items closed or carried | full gate EXIT 0 |

S5 and S6 are the largest slices (Q-C2).

## 10. Open items

| ID | Item | Status |
|---|---|---|
| O-off-1 to O-off-8 | the note's open items (L647 to L654); Q10 (a) takes the note drafts | OPEN (S2d) |
| O1 | where the vote prover runs: the client Wasm module, or a native prover outside charter-lang (zkml-lang `make halo2-check` runs outside the sandbox) | OPEN (S7) |
| O2 | ZK verify in the Wasm verifier needs a BN254 pairing for KZG under Q-C3 (a); its cost is not measured | OPEN (S8) |
| O3 | under Q-C5 (a) the dealer sees `sk_e`; this departs from L490 and L499 | OPEN (S6) |
| O4 | PBS speed in Wasm is not measured; S5 sets a budget | OPEN (S5) |
| O5 | the 128-bit TFHE parameter set and its source (Q-C2); no local file to verify one | OPEN (S5) |
| O6 | a change of FHE scheme or proof system is not an `enact` and needs a proof that `sem` does not change (L636) | OPEN |
| O7 | token counter: a fixed offline proxy, as leaf-lang Q13 | OPEN (S9) |
| O8 | the `Nat` instance of `CMon`: its law fields need induction proofs that the kit checker cannot write yet (USER accepted this cost, Q8) | RULED 2026-10-27: "(a) Add `ind` former (Recommended)"; S2a |
| O9 | the domain keeps the kit data types `Stack` and `Tree` as kit regression subjects (spine lowering, `REFUSE_RUNTIME_TREE`, the large-stack review row); USER ruling 2026-10-27: "Keep Stack, Tree only (Recommended)" | RULED 2026-10-27: "(a) Lift for uniform params (Recommended)"; S2a: FreeMon replaces Stack; Q-S2a-1 USER 2026-10-27: "(a) Keep Tree (Recommended)": `Tree` stays the only kit subject; Q-S2a-2 USER 2026-10-27: "(a) R1 free-monoid class (Recommended)": R1 accepts a second class, one type parameter `A`, a constructor without fields and a constructor with exactly a field of type `A` and a uniform recursive field; the kit derives no pure, map or bind for it |

## 11. Q items

Each row: the question, (a) the recommended option, the other options,
the scope cost, the status. Rows Q1, Q2, Q4 to Q10, Q-S2a-3, Q-S2b-1, Q-S2b-2 and Q-S2c-1 are RULED
2026-10-27: the Status cell quotes the USER ruling verbatim. The other rows
are OPEN.

| ID | Question | (a) recommended | Other options | Scope cost | Status |
|---|---|---|---|---|---|
| Q1 | Sigma over `K_wf` (L157, L260) | ambient Sigma; `K_wf` is a Sigma over a decidable check | (b) indexed Env CC; (c) refuse | none (S1) | RULED 2026-10-27, (a): "Q1 =  use built-in Sigma" |
| Q2 | arrows `S -> T S` (L285) | ambient Pi; R1 limits declared constructors only | none | none (S1) | RULED 2026-10-27, (a): "Q2 = Use plain function types (Pi) for arrows)" |
| Q3 | `Ct_e`, `Share_e` (L207, L208) | base types `CtA e`, `CtOneHot e`, `CtBit e`, `DecShare e`, `SigShare e`, indexed by the epoch value; meaning maps law-only | (b) sealed identity CM `Ct : U -> U` (quorum `Hidden`); (c) quotient HIT | small (S5) | OPEN |
| Q4 | records (L228, L256, L257) | named iterated Sigma (quorum O15); CC stays admitted with no domain use | (b) leaf style, no record form | small (S1) | RULED 2026-10-27, (a): "Q4 = use iterated Sigma" |
| Q5 | `T` (L285, L286) | one CM in `domain/domain.lang`: generator `ret`, 0-cell `none`, operation `emit : Voucher -> T Z -> T Z`, 1-cell `emit v none = none`, set truncation; normal forms `1 + Z x List Voucher`; bind is the recursor; Kleisli laws by induction | (b) `Option` and `Writer` with a distributive law; (c) a defined composite `Option (Z x FreeMon Voucher)` | medium (S2) | RULED 2026-10-27, (a): "(a) One CM (Recommended)"; `T Z` needs the S2a uniform-parameter recursion (O9); form: Q-S2b-2 |
| Q6 | `Nat`, `Bit` | base types (closed data that R2 limits) | (b) `mu X. 1 + X` | none (S1) | RULED 2026-10-27, (a): "Q6 = Nat and Bit are base types" |
| Q7 | the orbit quotient (L251) | no HIT; `Tally` (Def 2.2, L236) represents the orbit; rules only as `theta : Tally -> D_E`, so W3 holds by construction (L243); Kan laws erased at discrete `D` (Prop 2.6) | (b) a set-quotient HIT | none (S2) | RULED 2026-10-27, (a): "(a) Tally, no HIT (Recommended)" |
| Q8 | `A` (L227) | `A = Nat` in the meaning; 64-bit bound in Wasm and FHE (radix `u64`); no overflow in `T` | (b) an abstract monoid with an instance per target | small (S1) | RULED 2026-10-27, not (a). After S0: "Q8 = Try to use general magma, semigroup, or monoid, in that order, before specializing to Nat for the asset type". In S1, Q8-form: "Structure as a Pi parameter"; Q8-laws: "Monoid + those laws (Recommended)". Result: `CMon` (3.1) |
| Q9 | surface | port the leaf surface: Unicode canonical, ASCII aliases with `W_NONCANON` | (b) ASCII only | small (S1) | RULED 2026-10-27, (a): "Q9 = reuse leaf-lang surface syntax" |
| Q10 | O-off-1 to O-off-8 | take the note drafts (L647 to L654) | (b) rule each | none (S2) | RULED 2026-10-27, (a): "(a) Take note drafts (Recommended)" |
| Q-S2a-3 | the Monus rules of `natCMon` (`monus`, the laws `monusSound` and `monusComplete`) | 5 rules in the normalizer: `natLe 0 y = true`, `natLe (natAdd x 1) 0 = false`, `natLe (natAdd x 1) (natAdd y 1) = natLe x y`, `natSub x 0 = x`, `natSub (natAdd x 1) (natAdd y 1) = natSub x y`; `monus b a = flagIf (natLe a b) (some (natSub b a)) none` (SPEC 2.7) | none recorded | small (S2a) | RULED 2026-10-27, (a): "(a) 5 natLe/natSub rules (Recommended)" |
| Q-S2b-1 | the S2b scope is larger than about 6 sessions | split: S2b takes `kappa`, W1 to W3, `Tally`, `theta`, `T`, the Kleisli laws, the transcript fold and Thm 3.1, the W rows and orbit constancy, the mutants of `theta` and W1; S2c takes the 10 operations, Invariant I, Cor 4.2, Conservation, Thm 4.3, Thm 4.5, Prop 3.3 and 3.4, O-off-1 to O-off-8 (Q10 (a)), SPEC stubs 1 and 3 to 8, the mutant of Invariant I | (b) one slice S2b | none (two slices, section 9) | RULED 2026-10-27, (a): "Split S2b/S2c (Recommended)" |
| Q-S2b-2 | the form of `T` (Q5): conv has Sigma eta but no `Option` eta (S2b probe), so the Kleisli right unit of the one CM has no proof | the composite `T M Z = Option (Z x FreeMon (Voucher M))` as a domain definition (the normal forms of Q5); `emit v none = none` holds by construction (Q7 precedent); `ret`, `none`, `emit` and `bind` are definitions; a new former: a dependent `ind` on the host `Option`, so the Kleisli laws are general proofs | (b) the one CM of Q5 (a) | medium (S2b): one former | RULED 2026-10-27, (a): "Composite + ind on Option (Recommended)" |
| Q-S2c-1 | the S2c scope (section 9) is larger than about 6 sessions (about 9) | split: S2c takes the state types, the 10 operations (3.2) and their `tSem` fit, Invariant I, Cor 4.2, Conservation, Thm 4.3, Thm 4.5, their law discharge (section 6), the SPEC 5 and 6 rows of the S2c types and operations, the mutant of Invariant I; S2d takes Prop 3.3 and 3.4 (tests), O-off-1 to O-off-8 (Q10 (a)), SPEC stubs 1, 3, 4, 7 and 8, README and AGENTS | (b) S2c takes the operations only, S2d takes the laws and the docs; (c) no split | none (two slices, section 9) | RULED 2026-10-27, (a): "(a) S2c ops+laws, S2d docs (Recommended)" |
| Q-C1 | FROST ciphersuite | FROST(Ed25519, SHA-512), RFC 9591, context "FROST-ED25519-SHA512-v1", Appendix E vectors, Pedersen DKG for `vk`; no EVM, so secp256k1 gives nothing | (b) FROST(secp256k1, SHA-256) (quorum) | one slice (S4) | OPEN |
| Q-C2 | FHE scheme and parameter set | threshold TFHE (CGGI, PBS, 64-bit torus); `A` as radix `u64`, 32 blocks of 2-bit message and 2-bit carry; the 128-bit set is OPEN (unverified candidate: tfhe-rs `PARAM_MESSAGE_2_CARRY_2_KS_PBS`), verified at S5 | (b) threshold BFV or BGV (no PBS; `theta` and `n <= credit a` become deep polynomial circuits) | largest (S5, S6) | OPEN |
| Q-C3 | proof system | Halo2 (KZG, BN254) by `build/halo2print`; LWE well-formedness of `beta` as mod 2^64 arithmetic in Fr with a quotient witness, 64-bit range checks and a one-hot check | (b) Plonky3 BabyBear by `build/plonky3print` (64-bit limbs in a 31-bit field); (c) LLZK only; (d) a lattice-native proof of knowledge outside zkml-lang (unverified) | one slice (S7) plus O2 | OPEN |
| Q-C4 | hash | Poseidon2 over BN254 Fr (t = 3) for the Merkle root, the PRF, the commitments and `h_i`; FROST keeps SHA-512 | (b) Poseidon2 BabyBear (with Q-C3 (b)); (c) SHA-256 for `h_i`, Poseidon2 in the circuit | part of S4 | OPEN |
| Q-C5 | TFHE key generation at enact (L499, L584) | a dealer per epoch with a ZK proof of correct dealing for the share layer; BSK and KSK correctness is a dealer trust assumption; the dealer sees `sk_e` (O3) | (b) full threshold TFHE key generation MPC among `M'` (matches L499, L584; research grade; more than two slices; needs a network protocol) | one slice (a); more than two (b) | OPEN |
| Q-C6 | where the crypto runtime lives in Wasm | charter-lang prelude code that `langc` lowers into each module (all bytes from the tcc-built `langc`; leaf Q9 (a) precedent); new IR ops at S4 | (b) hand-built Wasm kernels that C in `src/wasm.c` emits; (c) host imports (bends Wasm-only and TinyCC); (d) clang wasm32 and wasm-ld (bends TinyCC; Apple clang has no wasm32); (e) tfhe-rs in Wasm (bends both; unverified) | medium (S4, S5); PBS speed O4 | OPEN |
| Q-C7 | threshold decryption | noise flooding with a 40-bit statistical parameter; decrypt after a switch to a larger decryption set; each partial decryption carries a ZK share proof (Q-C3 system); numbers set with Q-C2 | (b) Renyi small flooding, a bound on decryptions per epoch key; (c) none (test only) | part of S6 | OPEN |

S1 depends on Q1, Q2, Q4, Q6, Q8 and Q9. S2 adds Q5, Q7 and Q10. S2a also needs the O8 and O9 rulings (section 10).
S2b and S2c follow Q-S2b-1; `T` follows Q-S2b-2. S2c and S2d follow Q-S2c-1.
