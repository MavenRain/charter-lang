# Type formers

This file specifies the type formers of each language that starts from this
template. The specification does not depend on a host. A language has these
formers and no others. A language adds its core types and core operations
from `design/DESIGN.md`. It does not add a type former.

The forms below use one abstract syntax: the surface syntax of ledger-lang
`SPEC.md` sections 3 and 4 (commit 997fa7b). escrow-lang `SPEC.md` sections 2
and 3 (commit 279214c) write the same formers in assay forms. Each host file
(`hosts/mech/FORMERS.md`, `hosts/assay/FORMERS.md`, `hosts/tcc-json/FORMERS.md`,
`hosts/tcc-evm-contract/FORMERS.md`, `hosts/tcc-wasm/FORMERS.md`,
`hosts/tcc-evm/FORMERS.md`, `hosts/tcc-evm-dao/FORMERS.md`,
`hosts/tcc-evm-anchor/FORMERS.md`, `hosts/tcc-js/FORMERS.md`, `hosts/tcc-media/FORMERS.md`,
`hosts/tcc-webgpu/FORMERS.md`) gives the
host form of each former and its status. Section 5 of this file is the
realization matrix.

## 1. Notation

- `A`, `B`, `C` and `E` are data types. `S` is a seed type. `I` is an index
  type. `P` is a type function into `Type 0`.
- `a : A` means that the term `a` has the type `A`.
- `t[x := a]` is the term `t` with `a` in place of each free `x`.
- `=` in a law is equality of closed values. A host compares two closed
  values by its own method. mech compares the JSON encodings. assay uses
  kernel conversion.
- `Unit` is a type with one value, `unit`.
- A test is a function `p : A -> Option Unit`. The result `some unit` keeps
  the element. A host can use a type with two values in place of
  `Option Unit` (mech uses `Flag`, and `true` keeps).

## 2. Programs and refusal rules

A program is a sequence of definitions:

```
def NAME : TYPE := TERM
```

A definition can refer only to the definitions before it, to the core types
and operations, and to the forms of this file. The compiler applies these
refusal rules. They keep a program inside the former layer.

- **R1. No new data type.** The compiler refuses the host form that declares
  a data type (mech `mu`; assay `mu` and `nu`).
- **R2. No unproved fact.** The compiler refuses `axiom`. When the host kernel
  accepts an axiom, the compiler runs the host axiom report on its output. It
  refuses each axiom that the host file does not list as part of the target
  protocol.
- **R3. No general recursion.** The compiler refuses the host form for a
  recursive definition (`def rec`). Recursion comes only from F6 `fold` and
  F7 `unfold`. When F7 has the status HOST-LIMIT, recursion comes only from
  F6.
- **R4. No new core name.** The compiler refuses a definition whose name is
  a core type, a core operation, a prelude name or a reserved name.
- **R5. Host forms.** Each host adds the host forms that are not formers
  (mech: `poly`, `specialize`; assay: the contract forms). The host file
  gives the full list. `SPEC.md` section 2 copies it.

The compiler writes the target. A program cannot write a part of the target
directly.

## 3. Formers

Each former has a formation rule, introduction forms, elimination forms and
laws. A realization must satisfy each law that this section gives. A law
that a host cannot satisfy makes the status PARTIAL or HOST-LIMIT.

### F1 Product

- Formation: `Prod A B : Type 0` when `A : Type 0` and `B : Type 0`.
- Introduction: `pair a b : Prod A B` when `a : A` and `b : B`.
- Elimination: `first p : A` and `second p : B` when `p : Prod A B`.
- Laws: `first (pair a b) = a`. `second (pair a b) = b`.
  `pair (first p) (second p) = p`.

### F2 Coproduct

- Formation: `Sum A B : Type 0` when `A : Type 0` and `B : Type 0`.
- Introduction: `inl a : Sum A B` when `a : A`. `inr b : Sum A B` when
  `b : B`.
- Elimination: `either f g s : C` when `f : A -> C`, `g : B -> C` and
  `s : Sum A B`.
- Laws: `either f g (inl a) = f a`. `either f g (inr b) = g b`.

### F3 Option

- Formation: `Option A : Type 0` when `A : Type 0`.
- Introduction: `none : Option A`. `some a : Option A` when `a : A`.
- Elimination: `option z f o : C` when `z : C`, `f : A -> C` and
  `o : Option A`. The F5 and F8 forms also consume an option.
- Laws: `option z f none = z`. `option z f (some a) = f a`.
- A host can define `Option A` as `Sum Unit A`. Then `none` is `inl unit`,
  `some a` is `inr a`, and `option z f o = either (fun u => z) f o`.

### F4 List

- Formation: `List A : Type 0` when `A : Type 0`.
- Introduction: `nil : List A`. `cons a l : List A` when `a : A` and
  `l : List A`.
- Elimination: F6 `fold`. The F5 and F8 forms also consume a list.
- Laws: the F6 laws for the carrier `List A`.

### F5 Monad

- Instances: `Option`, `Sum E` and `List`. The declared type of the form
  selects the instance. Write `F` for the instance.
- Forms: `pure a : F A` when `a : A`. `map f t : F B` when `f : A -> B` and
  `t : F A`. `bind f t : F B` when `f : A -> F B` and `t : F A`.
- Laws:
  - Left identity: `bind f (pure a) = f a`.
  - Right identity: `bind pure t = t`.
  - Associativity: `bind g (bind f t) = bind (fun x => bind g (f x)) t`.
  - Map: `map f t = bind (fun x => pure (f x)) t`.
- For `Sum E`, `pure` is `inr`, and `bind f (inl e) = inl e`. For `List`,
  `bind` maps each element to a list and joins the lists in order.

### F6 Algebra fold

- Carriers: `Nat`, `List A`, and each recursive core type that the host
  column lists.
- Form over `Nat`: `fold f z n : C` when `f : C -> C`, `z : C` and
  `n : Nat`. Laws: `fold f z 0 = z`. `fold f z (n + 1) = f (fold f z n)`.
- Form over `List A`: `fold f z l : C` when `f : A -> C -> C`, `z : C` and
  `l : List A`. Laws: `fold f z nil = z`.
  `fold f z (cons a l) = f a (fold f z l)`. Thus `fold` consumes the
  elements from the right.
- Form over a core type with several constructors: `fold` takes one function
  for each constructor that has fields and one value for each constant
  constructor. A function receives the folded results of the recursive
  fields (ledger-lang `SPEC.md` lines 141 to 151, the fold over `Value`).
- Uniqueness: `fold f z` is the only function `h` with `h nil = z` and
  `h (cons a l) = f a (h l)`. The same holds for each carrier: `fold` is the
  unique algebra map out of the carrier. Each fold terminates, because it
  consumes one constructor at each step.

### F7 Algebra unfold

- Form into `List E`: `unfold g n s : List E` when
  `g : S -> Option (Prod E S)`, `n : Nat` and `s : S`. `n` is the step
  limit.
- Laws: `unfold g 0 s = nil`. When `g s = none`,
  `unfold g (n + 1) s = nil`. When `g s = some (pair e r)`,
  `unfold g (n + 1) s = cons e (unfold g n r)`.
- Form into `Nat`: `g : S -> Option S`, and the result is the number of
  steps.
- Form into a core type with several constructors: `g` gives one leg of a
  sum for each constructor. A seed that is left after `n` steps becomes the
  constant constructor that the host column names.
- The step limit makes each unfold terminate. A host that has no measure for
  the step limit cannot realize F7. Its status is HOST-LIMIT.

### F8 Filterable filter

- Carriers: `Option`, `List`, and each sequence core type that the host
  column lists. `Sum E` is not a carrier.
- Form: `filter p t : F A` when `p : A -> Option Unit` (a test, section 1)
  and `t : F A`.
- Laws: `filter p none = none`. `filter p (some a) = some a` when `p a`
  keeps, and `none` when it does not. `filter p nil = nil`.
  `filter p (cons a l) = cons a (filter p l)` when `p a` keeps, and
  `filter p l` when it does not.
- Thus `filter` keeps exactly the elements whose test keeps them, in their
  order.

### F9 Pi, not dependent

- Formation: `(x : A) -> B : Type 0` when `A` and `B` are data types and `B`
  does not refer to `x`. A type parameter comes first:
  `(T : Type 0) -> (x : T) -> B` is in `Type 1`.
- Introduction: `fun (x : A) => t` when `t : B` with `x : A` in scope.
- Elimination: the application `f a` when `f : (x : A) -> B` and `a : A`.
  An application gives one data type for each type parameter first, then
  the values.
- Laws: `(fun (x : A) => t) a = t[x := a]`. A function is not an instance
  and has no encoding.
- Rule: `B` cannot refer to a value parameter. That form is F10.

### F10 Pi, dependent

- Formation: `(x : A) -> B` when `B` can refer to `x`.
- Introduction: `fun (x : A) => t` when `t : B` with `x : A` in scope.
- Elimination: `f a : B[x := a]` when `f : (x : A) -> B` and `a : A`.
- Laws: `(fun (x : A) => t) a = t[x := a]`.
- Example: escrow-lang `settle` takes `L : Aggregation F`, so the type of a
  later argument depends on the value `F`.

### F11 Sigma

- Formation: `Sigma A B` when `B` can refer to a value of `A`. In binder
  form: `(x : A) * B`.
- Introduction: `pack a b : Sigma A B` when `a : A` and `b : B[x := a]`.
- Elimination: `witness s : A` and `payload s : B[x := witness s]` when
  `s : Sigma A B`.
- Laws: `witness (pack a b) = a`. `payload (pack a b) = b`.
  `pack (witness s) (payload s) = s`.
- A host that can build a Sigma value but cannot project it has the status
  PARTIAL. A record family that a match reads can replace a projected Sigma.
  The host file names each replacement.

### F12 Equality: refl, symm, trans

- Formation: `Eq A x y` when `A : Type 0`, `x : A` and `y : A`.
- Introduction: `refl x : Eq A x x`.
- Elimination: `symm e : Eq A y x` when `e : Eq A x y`.
  `trans d e : Eq A x z` when `d : Eq A x y` and `e : Eq A y z`.
- Rules: `Eq A x y` has an inhabitant only when `x = y`. A proof has no
  runtime content. It erases from the target, and a definition of an `Eq`
  type is not an instance.

### F13 Equality: transport and cong

- Elimination: `transport P e u : P y` when `e : Eq A x y` and `u : P x`.
  `cong f e : Eq B (f x) (f y)` when `f : A -> B` and `e : Eq A x y`.
- Laws: `transport P (refl x) u = u`. `cong f (refl x) = refl (f x)`.

### F14 Universes

- `Type 0` classifies the data types and the function types of data types.
- `Type 1` classifies `Type 0`, the function types with a type parameter,
  the type functions (for example `Option`), and each core family whose
  index is a type.
- There is no cumulativity. A type in `Type 0` is not a type in `Type 1`.
  There is no `Type 2` in a program.
- An instance is a top-level definition whose type is a data type. A
  definition of a type, of a function or of a proof is not an instance.

### F15 Indexed family

- Formation: `D i : Type 0` when `i : I` and `I` is a core data type. The
  index is a value, not a type, so F15 uses F10.
- Introduction: each constructor fixes the index or takes it as an argument:
  `mkD i x : D i`.
- Elimination: a match on `d : D i` gives the fields. Each field type uses
  the same `i`.
- Laws: a match on `mkD i x` gives `x`.
- Examples: ledger-lang `Ref k` (indexed by `k : Kind`) and escrow-lang
  `Aggregation F` (indexed by `F : ChoiceRule`).

## 4. Status words

| Word | Meaning |
|---|---|
| DONE | The host realizes the former and its laws. Tests or host checks cover it. |
| PARTIAL | The host realizes a restricted form. The cell names the restriction. |
| PLANNED | The host can realize the former, but the build does not have it yet. |
| HOST-LIMIT | The host cannot realize the former. The cell cites the probe fact. |

## 5. Realization matrix

Each cell gives the status and the source of the fact at the origin commit.
mech facts come from ledger-lang 997fa7b. assay facts come from escrow-lang
279214c. tcc-json facts come from `hosts/tcc-json` in this repository.
tcc-evm-contract facts come from `hosts/tcc-evm-contract` in this repository
at commit eaa4c74. The tcc-evm-contract front end is a copy of the tcc-wasm
front end. Its cells give the status in `langc check` and `langc eval`. The
EVM output of each former is PLANNED until slice K4
(`hosts/tcc-evm-contract/FORMERS.md:3-8`).
tcc-wasm and tcc-evm facts come from `hosts/tcc-wasm` and `hosts/tcc-evm` in
this repository. The two kits share the front end, so each former has the
same status in both kits.
tcc-evm-dao facts come from `hosts/tcc-evm-dao` in this repository at commit
eaa4c74. Its cells give the status in `langc check` and `langc eval`
(`hosts/tcc-evm-dao/FORMERS.md:5-6`).
tcc-evm-anchor facts come from `hosts/tcc-evm-anchor` in this repository at
commit 5bec924. Its cells give the status in the checker. No former runs on
the EVM: the runtime reads the outcomes from the table
(`hosts/tcc-evm-anchor/FORMERS.md:5-9`).
tcc-js facts come from `hosts/tcc-js` in this repository. Its front end is
the tcc-json front end with the `Str` primitive, so each former has the same
status as in tcc-json. The status also covers the JS module that
`langc build --js` writes (`hosts/tcc-js/FORMERS.md`).
tcc-media facts come from `hosts/tcc-media` in this repository. Its front
end adds media primitives to tcc-json and keeps the same type formers.
tcc-webgpu facts come from `hosts/tcc-webgpu` in this repository. Its front
end is the tcc-js front end with the `U32` and `Tile R C A` primitives, so
each former has the same status as in tcc-js. `U32` and `Tile R C A` are
host primitives, not formers (`hosts/tcc-webgpu/FORMERS.md`).
The host files cite the host kits in this repository. When a status
changes, update the host file and this matrix in the same change.

| ID | Former | mech (ledger-lang 997fa7b) | assay (escrow-lang 279214c) | tcc-json (this repository) | tcc-evm-contract (this repository) | tcc-wasm (this repository) | tcc-evm (this repository) | tcc-evm-dao (this repository) | tcc-evm-anchor (this repository) | tcc-js (this repository) | tcc-media (this repository) | tcc-webgpu (this repository) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 | Product | DONE: `compiler/runtime.mech:125`, `compiler/checker.mech:1-44` | DONE: built-in `prod`, `tuple`, `t.0`, `t.1` (`SPEC.md:53`) | DONE: `hosts/tcc-json/examples/formers.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/formers.lang:3`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/formers.lang:3` | DONE: `hosts/tcc-evm/examples/formers.lang:3` | DONE: built-in product, tuples, `.0` and `.1`: `hosts/tcc-evm-dao/domain/domain.lang:167,175,177` | DONE: built-in product, tuples, `.0` and `.1`; `Flag` and `AnchorPair`: `hosts/tcc-evm-anchor/domain/domain.lang:14,213` | DONE: `hosts/tcc-js/examples/formers.lang` | DONE: `hosts/tcc-media/examples/formers.lang` | DONE: `hosts/tcc-webgpu/examples/formers.lang` |
| F2 | Coproduct | DONE: `compiler/types.mech:111`, `compiler/checker.mech:57,1634` | DONE: `Sum A B` over built-in `sum` (`prelude/Prelude.asy:108-123`) | DONE: `hosts/tcc-json/examples/formers.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/formers.lang:8`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/formers.lang:8` | DONE: `hosts/tcc-evm/examples/formers.lang:8` | DONE: built-in `sum`; `Sum`, `pureSum`, `mapSum`, `bindSum`: `hosts/tcc-evm-dao/domain/domain.lang:108-119` | DONE: built-in `sum`; `Flag`, `flagNo`, `flagYes`, `flagAnd`: `hosts/tcc-evm-anchor/domain/domain.lang:14-20` | DONE: `hosts/tcc-js/examples/formers.lang` | DONE: `hosts/tcc-media/examples/formers.lang` | DONE: `hosts/tcc-webgpu/examples/formers.lang` |
| F3 | Option | DONE: `compiler/types.mech:108` | DONE: `Option A := sum (prod (), A)` (`prelude/Prelude.asy:79-106`) | DONE: `hosts/tcc-json/examples/formers.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/formers.lang:11`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/formers.lang:11` | DONE: `hosts/tcc-evm/examples/formers.lang:11` | DONE: `Option A` is a definition over `sum`; `none`, `pureOption`, `mapOption`, `bindOption`: `hosts/tcc-evm-dao/domain/domain.lang:79-93` | DONE: `Option A` is a definition over `sum`; `optionNone`, `optionPure`: `hosts/tcc-evm-anchor/domain/domain.lang:27-32` | DONE: `hosts/tcc-js/examples/formers.lang` | DONE: `hosts/tcc-media/examples/formers.lang` | DONE: `hosts/tcc-webgpu/examples/formers.lang` |
| F4 | List | DONE: `compiler/types.mech:109` | PARTIAL: one `mu` family for each element type; probe P2: a constructor of a family with a parameter cannot appear in a term (O8, `SPEC.md:267-275`) | DONE: `hosts/tcc-json/examples/formers.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/formers.lang:13`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/formers.lang:13` | DONE: `hosts/tcc-evm/examples/formers.lang:13` | PARTIAL: no generic `List`; one `mu` for each element type, `Ballots` and `Claims` (`hosts/tcc-evm-dao/domain/domain.lang:129,303`); probe P2: a constructor of a family with a parameter cannot appear in a term (`hosts/tcc-evm-dao/docs/CAPABILITY.md:26-30`) | PARTIAL: no generic `List`; one `mu` for each element type, `Candidates` and `Profile` (`hosts/tcc-evm-anchor/domain/domain.lang:101,130`) | DONE: `hosts/tcc-js/examples/formers.lang` | DONE: `hosts/tcc-media/examples/formers.lang` | DONE: `hosts/tcc-webgpu/examples/formers.lang` |
| F5 | Monad | DONE over `Option`, `List`, `Sum E`: `compiler/checker.mech:60-65,591-745` | DONE for each carrier: `Option`, `Sum E`, each list family (`SPEC.md:67-70`) | DONE over `Option`, `Sum E`, `List`: `hosts/tcc-json/examples/monad.lang` | DONE in `check` and `eval` over `Option`, `Sum E`, `List`: `hosts/tcc-evm-contract/examples/monad.lang:2`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE over `Option`, `Sum E`, `List`: `hosts/tcc-wasm/examples/monad.lang:2` | DONE over `Option`, `Sum E`, `List`: `hosts/tcc-evm/examples/monad.lang:2` | DONE over `Option` and `Sum` (`hosts/tcc-evm-dao/domain/domain.lang:84-93,110-119`). PARTIAL over lists: one set for `Ballots` and one for `Claims` (`hosts/tcc-evm-dao/domain/domain.lang:143-149,317-323`) | PARTIAL: over `Option` only: `optionPure`, `optionBind`, `optionMap` (`hosts/tcc-evm-anchor/domain/domain.lang:32-41`); the list families have no bind | DONE over `Option`, `Sum E`, `List`: `hosts/tcc-js/examples/monad.lang` | DONE over `Option`, `Sum E`, `List`: `hosts/tcc-media/examples/monad.lang` | DONE over `Option`, `Sum E`, `List`: `hosts/tcc-webgpu/examples/monad.lang` |
| F6 | Algebra fold | DONE over `Nat`, `List A`, `Text`, `Values`, `Attrs` and `Value` (five functions): `compiler/checker.mech:802-1088,1661-1957` | PARTIAL: each list family has a structural `def rec`; no fold over `Nat`, because built-in `Nat` has no eliminator (`SPEC.md:71-73`) | DONE over `Nat`, `List` and each family: `hosts/tcc-json/examples/algebra.lang` | DONE in `check` and `eval` over `Nat`, `List` and each domain family: `hosts/tcc-evm-contract/examples/algebra.lang:4`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE over `Nat`, `List` and each domain family: `hosts/tcc-wasm/examples/algebra.lang:4`. HOST-LIMIT: a tree at run time (`hosts/tcc-wasm/test/ir/tree.lang:3`) | DONE over `Nat`, `List` and each domain family: `hosts/tcc-evm/examples/algebra.lang:4`. HOST-LIMIT: a tree at run time (`hosts/tcc-evm/test/ir/tree.lang:3`) | PARTIAL: `foldBallots` and `foldClaims` (structural `def rec`), generic in the result type only (`hosts/tcc-evm-dao/domain/domain.lang:133,307`); no fold over `Nat` (`hosts/tcc-evm-dao/docs/CAPABILITY.md:33-34`) | PARTIAL: `candidatesFold` and `profileFold` (structural `def rec`), in the prelude only (`hosts/tcc-evm-anchor/domain/domain.lang:105,134`); a `def rec` in a program is `REFUSE_REC`; no fold over `Nat` | DONE over `Nat`, `List` and each family: `hosts/tcc-js/examples/algebra.lang` | DONE over `Nat`, `List` and each family: `hosts/tcc-media/examples/algebra.lang` | DONE over `Nat`, `List` and each family: `hosts/tcc-webgpu/examples/algebra.lang` |
| F7 | Algebra unfold | DONE into the same carriers, with a `Nat` step limit: `compiler/checker.mech:802-1088,1661-1957` | HOST-LIMIT: no structural measure and no `Nat` fuel (O9 RULED, `SPEC.md:276-279`) | DONE into `List`, with a `Nat` step limit: `hosts/tcc-json/examples/algebra.lang` | DONE in `check` and `eval` into `List`, with a `Nat` step limit: `hosts/tcc-evm-contract/examples/algebra.lang:7`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE into `List`, with a `Nat` step limit: `hosts/tcc-wasm/examples/algebra.lang:7` | DONE into `List`, with a `Nat` step limit: `hosts/tcc-evm/examples/algebra.lang:7` | HOST-LIMIT: no `unfold`; built-in `Nat` has no eliminator, so there is no `Nat` fuel; `nu` is a refused form (`hosts/tcc-evm-dao/docs/CAPABILITY.md:33-35`, `hosts/tcc-evm-dao/test/refusal.sh:40`) | HOST-LIMIT: the checker accepts only structural recursion, and built-in `Nat` has no eliminator, so an unfold has no measure and no fuel (`hosts/tcc-evm-anchor/docs/CAPABILITY.md:47`) | DONE into `List`, with a `Nat` step limit: `hosts/tcc-js/examples/algebra.lang` | DONE into `List`, with a `Nat` step limit: `hosts/tcc-media/examples/algebra.lang` | DONE into `List`, with a `Nat` step limit: `hosts/tcc-webgpu/examples/algebra.lang` |
| F8 | Filterable filter | DONE over `Option`, `List`, `Text`, `Values`, `Attrs`; no `Sum E` instance: `compiler/checker.mech:622-631` | DONE over `Option` and each list family; the test is `A -> Option (prod ())` (`SPEC.md:74-76`) | DONE over `Option` and `List`: `hosts/tcc-json/examples/monad.lang` | DONE in `check` and `eval` over `Option` and `List`: `hosts/tcc-evm-contract/examples/monad.lang:9`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE over `Option` and `List`: `hosts/tcc-wasm/examples/monad.lang:9` | DONE over `Option` and `List`: `hosts/tcc-evm/examples/monad.lang:9` | DONE over `Option`: `filterOption` (`hosts/tcc-evm-dao/domain/domain.lang:99`). PARTIAL over lists: `filterBallots`, `filterClaims` (`hosts/tcc-evm-dao/domain/domain.lang:153,327`) | PARTIAL: over `Profile` only: `profileFilter` (`hosts/tcc-evm-anchor/domain/domain.lang:140`) | DONE over `Option` and `List`: `hosts/tcc-js/examples/monad.lang` | DONE over `Option` and `List`: `hosts/tcc-media/examples/monad.lang` | DONE over `Option` and `List`: `hosts/tcc-webgpu/examples/monad.lang` |
| F9 | Pi, not dependent | DONE: `compiler/program.mech:190` ("B cannot refer to a value parameter"), `SPEC.md:61-68` | DONE: built-in (`SPEC.md:55`) | DONE: `hosts/tcc-json/examples/functions.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/functions.lang:2`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/functions.lang:2`. HOST-LIMIT: a function value at run time (`hosts/tcc-wasm/test/ir/closure.lang:3`) | DONE: `hosts/tcc-evm/examples/functions.lang:2`. HOST-LIMIT: a function value at run time (`hosts/tcc-evm/test/ir/closure.lang:3`) | DONE: `A -> B`: `hosts/tcc-evm-dao/domain/domain.lang:279` | DONE: `A -> B`; `rule : Tally -> Outcome` in each program: `hosts/tcc-evm-anchor/examples/programs/arrow-debreu.lang:14` | DONE: `hosts/tcc-js/examples/functions.lang` | DONE: `hosts/tcc-media/examples/functions.lang` | DONE: `hosts/tcc-webgpu/examples/functions.lang` |
| F10 | Pi, dependent | PLANNED: `docs/STATUS.md:133-137` | DONE in the kernel: `Aggregation F` (`SPEC.md:83-86,103`) | DONE: `hosts/tcc-json/examples/functions.lang` | DONE in `check` and `eval` over `Type 0` and over `Nat`: `hosts/tcc-evm-contract/examples/functions.lang:8`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE over `Type 0` and over `Nat`: `hosts/tcc-wasm/examples/functions.lang:8` | DONE over `Type 0` and over `Nat`: `hosts/tcc-evm/examples/functions.lang:8` | DONE: `(x : A) -> B` and the erased binder `(0 x : A)`; `cast`: `hosts/tcc-evm-dao/domain/domain.lang:246` | DONE: `(x : A) -> B` and the erased binder `(0 x : A)`: `hosts/tcc-evm-anchor/domain/domain.lang:105,248` | DONE: `hosts/tcc-js/examples/functions.lang` | DONE: `hosts/tcc-media/examples/functions.lang` | DONE: `hosts/tcc-webgpu/examples/functions.lang` |
| F11 | Sigma | PLANNED: reserved names only (`compiler/types.mech:214`, `SPEC.md:39,183`) | PARTIAL: built, never projected; the kernel refuses Sigma eta and has no Sigma pattern, so records are `mu` families read by `match` (O10, `SPEC.md:280-288`) | DONE: `hosts/tcc-json/examples/sigma.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/sigma.lang:3`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/sigma.lang:3` | DONE: `hosts/tcc-evm/examples/sigma.lang:3` | PARTIAL: built, never projected; no Sigma pattern and no Sigma eta, so `Config` and `Tally` are `mu` records (`hosts/tcc-evm-dao/docs/CAPABILITY.md:36-40`, `hosts/tcc-evm-dao/domain/domain.lang:183,186,251`) | DONE: `AnchorDAO F := (L : Aggregation F) * AnchorLog`, read by `.0` and `.1`, built by a pair in `anchor` and `amendDAO`: `hosts/tcc-evm-anchor/domain/domain.lang:215-216,221,251` | DONE: `hosts/tcc-js/examples/sigma.lang` | DONE: `hosts/tcc-media/examples/sigma.lang` | DONE: `hosts/tcc-webgpu/examples/sigma.lang` |
| F12 | Eq refl, symm, trans | DONE: `compiler/checker.mech:67-122` | PARTIAL: one `Eq` family for each index type in `Type 0` (`EqNat`, `EqDec`, `EqTally`; `SPEC.md:57`) | DONE: `hosts/tcc-json/examples/equality.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/equality.lang:4`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/equality.lang:4` | DONE: `hosts/tcc-evm/examples/equality.lang:4` | PARTIAL: one family for each index type (`EqNat`, `EqDec`, `EqTally`), each with symm and trans; no generic `Eq` (`hosts/tcc-evm-dao/domain/domain.lang:26,48,201`) | PARTIAL: one family, `EqOutcome`, with refl, symm and trans; no generic `Eq` (`hosts/tcc-evm-anchor/domain/domain.lang:174,285,290`) | DONE: `hosts/tcc-js/examples/equality.lang` | DONE: `hosts/tcc-media/examples/equality.lang` | DONE: `hosts/tcc-webgpu/examples/equality.lang` |
| F13 | Eq transport, cong | PLANNED: reserved names (`compiler/types.mech:214`, `docs/STATUS.md:133-137`) | PARTIAL: one `transport` and one `cong` for each `Eq` family (`SPEC.md:57`) | DONE: `hosts/tcc-json/examples/equality.lang` | DONE in `check` and `eval`: `hosts/tcc-evm-contract/examples/equality.lang:8`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE: `hosts/tcc-wasm/examples/equality.lang:8` | DONE: `hosts/tcc-evm/examples/equality.lang:8` | PARTIAL: one `transport` and one `cong` for each `Eq` family (`hosts/tcc-evm-dao/domain/domain.lang:29,43,51,65,204,218`) | PARTIAL: one `transport` and one `cong`, for `EqOutcome` only (`hosts/tcc-evm-anchor/domain/domain.lang:280,294`) | DONE: `hosts/tcc-js/examples/equality.lang` | DONE: `hosts/tcc-media/examples/equality.lang` | DONE: `hosts/tcc-webgpu/examples/equality.lang` |
| F14 | Universes | DONE: `compiler/parser.mech:69-83` | PARTIAL: `Type 0`; `Type 1` only as the type of a type function (`SPEC.md:58`) | DONE: `hosts/tcc-json/examples/universes.lang` | DONE in `check` and `eval` for `Type 0` and `Type 1`, without cumulativity: `hosts/tcc-evm-contract/examples/universes.lang:4`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | DONE for `Type 0` and `Type 1`, without cumulativity: `hosts/tcc-wasm/examples/universes.lang:4` | DONE for `Type 0` and `Type 1`, without cumulativity: `hosts/tcc-evm/examples/universes.lang:4` | PARTIAL: `Type 0` and `Type 1` only; no example program uses `Type 1` (`hosts/tcc-evm-dao/src/parser.c:304`, `hosts/tcc-evm-dao/test/refusal.sh:51`) | PARTIAL: `Type 0 : Type 1`; each formation takes the maximum universe; an explicit `Type 1` annotation has no type, `TYPE_UNIVERSE` (`hosts/tcc-evm-anchor/src/check.c:908`) | DONE: `hosts/tcc-js/examples/universes.lang` | DONE: `hosts/tcc-media/examples/universes.lang` | DONE: `hosts/tcc-webgpu/examples/universes.lang` |
| F15 | Indexed family | PARTIAL: domain only (`Ref k`, `compiler/parser.mech:186-190`); the generic former is PLANNED | DONE for a family with a fixed index type; no parameter (probe P2, `SPEC.md:60-62,103`) | DONE: a family with parameters in `domain/` (R1): `hosts/tcc-json/domain/domain.lang` | PARTIAL in `check` and `eval`: only the domain file declares an indexed family: `hosts/tcc-evm-contract/domain/domain.lang:8`. PLANNED: EVM output (`hosts/tcc-evm-contract/src/main.c:155`) | PARTIAL: only the domain file declares an indexed family: `hosts/tcc-wasm/domain/domain.lang:10` | PARTIAL: only the domain file declares an indexed family: `hosts/tcc-evm/domain/domain.lang:10` | PARTIAL, in `domain/` only: `EqNat` and `Aggregation` (indexed by `ChoiceRule`); a family with a parameter cannot appear in a term (`hosts/tcc-evm-dao/domain/domain.lang:26,235`, `hosts/tcc-evm-dao/docs/CAPABILITY.md:26`) | DONE: `EqOutcome` and `Aggregation` (indexed by `Constitution`): `hosts/tcc-evm-anchor/domain/domain.lang:174,182` | DONE: a family with parameters in `domain/` (R1): `hosts/tcc-js/domain/domain.lang` | DONE: a family with parameters in `domain/` (R1): `hosts/tcc-media/domain/domain.lang` | DONE: a family with parameters in `domain/` (R1): `hosts/tcc-webgpu/domain/domain.lang` |
