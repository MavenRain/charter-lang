# TinyCC Wasm realization

Paths below are relative to the root of charter-lang. `formers/FORMERS.md`
gives the host-neutral laws. `src/front/check.c` lines 83-115 are rows of
the builtin table. `src/front/check.c` lines 1034-1045 are rows of the
dropped kit names. The other `src/front/check.c` lines are the
elaboration. `src/front/parser.c` lines are the grammar.
`src/front/lower.c` lines are the lowering to the IR.

DONE means: `langc check` accepts the former, `langc eval` computes it,
and `langc build` lowers it to Wasm when its value is first-order at run
time. Types and universes erase on Wasm. Proof contents erase, while their
trap flags remain. PLANNED means: since S1, no program name gives the
former. The checker refuses the dropped kit name with the unknown-name
code and migration advice. `fix` names a replacement only when one name
can replace it; otherwise `fix` is `null` (`docs/DIAGNOSTICS.md`).

| ID | Former | Status | Where | Evidence |
|---|---|---|---|---|
| F1 | Product `A × B` | DONE | `src/front/parser.c:10`, `src/front/check.c:96`, `src/front/check.c:98`, `src/front/check.c:99`, `src/front/lower.c:1193` | `examples/formers.lang:5`, `examples/formers.lang:9`, `examples/formers.lang:12`, `examples/laws.lang:5`, `examples/laws.lang:20` |
| F2 | Coproduct | DONE | `src/front/check.c:86`, `src/front/check.c:92`, `src/front/check.c:93`, `src/front/check.c:100`, `src/front/lower.c:1206` | `examples/formers.lang:20`, `examples/formers.lang:23`, `examples/laws.lang:23` |
| F3 | Option | DONE | `src/front/check.c:87`, `src/front/check.c:94`, `src/front/check.c:95`, `src/front/check.c:101`, `src/front/lower.c:1208` | `examples/formers.lang:26`, `examples/formers.lang:29`, `examples/formers.lang:32` |
| F4 | List | PLANNED: no program name since S1 (PLAN 2.3). The message names `FreeMon` of `domain/domain.lang` (S2, Q5); `fix` is `null` | `src/front/check.c:1041`, `src/front/check.c:1042`, `src/front/check.c:1043` | No program form |
| F5 | Monad pure/map/bind | DONE over Option and Sum E | `src/front/check.c:102`, `src/front/check.c:103`, `src/front/check.c:104`, `src/front/lower.c:1087`, `src/front/lower.c:1102`, `src/front/lower.c:1196` | `examples/monad.lang:2`, `examples/monad.lang:5`, `examples/monad.lang:8`, `examples/monad.lang:11`, `examples/monad.lang:14`, `examples/laws.lang:14`, `examples/laws.lang:17` |
| F6 | Algebra fold | DONE over ℕ and domain data types. HOST-LIMIT: a run-time tree | `src/front/check.c:105`, `src/front/lower.c:1137`, `src/front/lower.c:1027`, `src/front/lower.c:1043`, `src/front/lower.c:1063` | `examples/algebra.lang:2`, `examples/algebra.lang:5`, `examples/base.lang:26`, `test/ir/spine.lang:3`, `test/ir/tree.lang:3` |
| F7 | Algebra unfold | PLANNED: no program name since S1 (PLAN 2.3) | `src/front/check.c:1045` | No program form |
| F8 | Filter | PLANNED: no program name since S1 (PLAN 2.3). No core name replaces it | `src/front/check.c:1044` | No program form |
| F9 | Non-dependent Pi | DONE. HOST-LIMIT: a function value at run time | `src/front/parser.c:362`, `src/front/check.c:1292`, `src/front/check.c:1294`, `src/front/lower.c:575` | `examples/functions.lang:5`, `examples/functions.lang:23`, `examples/laws.lang:8`, `examples/laws.lang:11`, `test/ir/closure.lang:3` |
| F10 | Dependent Pi | DONE over `Type 0` and over ℕ | `src/front/check.c:1294`, `src/front/check.c:1266`, `src/front/lower.c:1255` | `examples/functions.lang:8`, `examples/functions.lang:17`, `examples/equality.lang:17`, `examples/universes.lang:8` |
| F11 | Sigma | DONE | `src/front/check.c:1296`, `src/front/check.c:96`, `src/front/check.c:98`, `src/front/check.c:99`, `src/front/lower.c:1199`, `src/front/lower.c:1202` | `examples/sigma.lang:5`, `examples/sigma.lang:8`, `examples/sigma.lang:11`, `examples/sigma.lang:14` |
| F12 | Eq refl/symm/trans | DONE | `src/front/check.c:88`, `src/front/check.c:97`, `src/front/check.c:106`, `src/front/check.c:107`, `src/front/lower.c:1150` | `examples/equality.lang:8`, `examples/equality.lang:11`, `examples/equality.lang:14`, `test/check/bad-refl.lang:1`, `test/ir/proof-trap.lang:1` |
| F13 | Eq transport/cong | DONE | `src/front/check.c:108`, `src/front/check.c:109`, `src/front/lower.c:1162`, `src/front/lower.c:1228` | `examples/equality.lang:17`, `examples/equality.lang:20`, `test/ir/proof-trap.lang:4`, `test/ir/proof-trap.lang:16` |
| F14 | Universes | DONE for Type 0 and Type 1, without cumulativity | `src/front/check.c:1300`, `src/front/lower.c:1255` | `examples/universes.lang:2`, `examples/universes.lang:5`, `test/check/universe.lang:1`, `test/check/universe-range.lang:1` |
| F15 | Generic indexed family | PARTIAL: only the domain file can declare an indexed data type; the charter domain declares none at S1 | `SPEC.md:48`, `SPEC.md:49` | `test/fronttool.c:144` |

F4, F7 and F8: S1 removed the kit names `List`, `nil`, `cons`, `unfold`
and `filter` (PLAN 2.3 for `List`; leaf-lang S1 for `unfold` and `filter`). Their lowering code stays in the source as dead
core paths, for example `src/front/lower.c:869`,
`src/front/lower.c:921` and `src/front/lower.c:971`.

F6: a fold over a data type with one recursive field (for example `FreeMon ℕ`)
lowers to a loop over the spine. A constructor with two or more recursive
fields (for example `Tree`) needs a tree at run time. The lowering refuses
it with `REFUSE_RUNTIME_TREE` when the tree exists only at run time.
A fold over a closed tree works, because normalization folds it at
compile time.

F9: a lambda stays only as the direct function argument of an eliminator.
When a function value must exist at run time, the lowering refuses it
with `REFUSE_RUNTIME_CLOSURE`. Both refusals are HOST-LIMIT reasons, not
defects. `docs/host/CAPABILITY.md` gives the reasons.

F15: a domain data type can take index parameters, for example
`data Lot (size : ℕ) : Type where` with the constructor
`makeLot : (lotPrice : ℕ) → Lot size`. A constructor takes the indices
first (`makeLot 3 250 : Lot 3`). The checker keeps `Lot 3` and `Lot 4`
apart. The charter domain declares no indexed data type at S1: the `Lot`
domain row in `test/fronttool.c` keeps the former tested. A program
cannot declare a data type (rule R1). No test has a field
type that refers to an index. The index erases on Wasm.

The refusal mutants are in `test/check/`: R1 `data.lang`, R2 `axiom.lang`,
R3 `rec.lang`, `self.lang` and `later.lang`, R4 `core-name.lang`,
`domain-name.lang`, `reserved.lang` and `duplicate.lang`.
`test/check/expect.txt` gives the code for each mutant.
