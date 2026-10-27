# charter-lang domain design

This file and `design/OFFCHAIN-ESCROWDAO.html` are the only design source
of charter-lang. Sections 1 and 2 hold USER text. Do not edit them.
Section 3 holds the facts that Claude collected at S0 (2026-10-27), with
cites. `docs/PLAN.md` gives the rulings, the readings, the slices and the
open questions.

The em-dash scan of the gate (`test/gate.sh` line 184) skips this file and
the note snapshot, because both hold verbatim text.

---

## 1. USER ask (2026-10-27, verbatim)

I want to write a new programming languages with the following characteristics:

For type constructors/higher-kinded types, admit only cell monads and their duals as represented computationally in Cubical Type Theory.

For base types and operations, admit only what is required to represent the following: https://claude.ai/artifact/RmB9LYqjgh5UPmSScpQJTY

The host language shall be TinyCC.  Use your judgment and provide multiple-choice options for the compilation target(s).

Finally, I'd like agents to reach for this language when it fits their use cases.  To that end, please mind the following criteria:

  The plan for making agents reach for the language includes:
  - one canonical form per operation and a langc fmt canonical printer;
  - langc check --json, giving fix hints and progress counts (parsed, typed, laws
    discharged);
  - a SKILL.md with 3 to 5 graded examples;
  - an MCP server written in TinyCC (langc mcp);
  - AGENTS.md and a README table saying when to use the language;
  - a token-count comparison against Python and Rust.

## 2. USER rulings (2026-10-27, verbatim)

## USER rulings 2026-10-27 (AskUserQuestion, answers verbatim)

- Targets: "Wasm, ZK circuit IR, FHE circuit IR, " Wasm also for the  Member node + public
  verifier: transcript fold, Check(e_i) recompute, threshold-sig check."
  (So: NO native C target. Wasm serves both the client and the member node / public verifier.)
- Crypto in v1: "All concrete" (option text: fix TFHE or BFV, a PLONKish proof system, FROST
  threshold sigs and Poseidon in v1).
- Rail: "No, meaning ends at rail (Recommended)". Vouchers are data only.

### 2.1 Claude readings (not USER text)

- The link in section 1 is the escrow-lang design note "Off-Chain
  EscrowDAO", dated 2026-10-26, artifact
  https://claude.ai/artifact/RmB9LYqjgh5UPmSScpQJTY. The snapshot
  `design/OFFCHAIN-ESCROWDAO.html` (666 lines) was copied on 2026-10-27.
  In this repository, `Lnnn` is a line of that file.
- The host kit is `tcc-wasm`. It follows from the ruling that Wasm is the
  only executable target. The C-only kits and the EVM kits do not fit.
- The name is Claude's call. The constitution kappa that amends itself is
  the charter.

## 3. Facts (collected at S0, 2026-10-27)

### 3.1 The note

The S0 unit checked each cite below against the snapshot.

- L194: equation (1.1), `Dec_sk(Eval_f c) = f(Dec_sk c)`.
- L196: equation (1.2), `Check(e_i)` implies
  `sem(r_i) = sem(op_i) sem(r_{i-1})`.
- L198: equation (1.3), `sk = sum_{i in S} lambda^S_i sk_i` for `S` in
  `A_t`.
- L207 to L212: the representation types `Ct_e`, `Share_e`, `Proof`
  (erased) and `Sig_e`, each with a meaning function.
- L226 to L230: the discrete categories `D_E`, `B_A`, `D_A`, the asset
  monoid `A`, `Voucher = Address x A x N`, and `f(n) = floor((n-1)/3)`.
- L234: Def 2.1 (configurations). L236: Def 2.2 (`Tally`). L237: Def 2.3
  (`Ready_t`). L239 to L242: Def 2.4 (`W1`, `W2`, `W3`). L245: the table
  `theta_t`. L247: Prop 2.6. L251: `G = Sigma`.
- L285 to L289: `T Z = 1 + Z x List Voucher` and Thm 3.1.
- L490: the sketch is not executable source and proof terms erase.
- L494: threshold TFHE with programmable bootstrapping. L495: FROST.
  L496: the Merkle root of member credentials. L497: the nullifier PRF.
  L499: DKG among the new members.
- L502: the entry `e_i = (i, h_{i-1}, op_i, Pi_i, sig_i)`. L503: `Pi_i`.
- L578 to L592: `enact` (L584 DKG, L585 key switch of every credit).
- L598 to L609: Table 7.4 (FHE, ZK and MPC roles).
- L647 to L654: the open items O-off-1 to O-off-8.

### 3.2 Template and kit

- lang-template 5265a2a. `bin/new-lang.sh charter-lang tcc-wasm` gave rc 0:
  a git repository on `main`, 16 untracked entries, no commit.
- Kit gate before any edit (`make -j 2 check`, EXIT 0): examples 10
  checked, 0 failed; parse refusals 9; check refusals 19; evals 32; ir 10
  lowered; wasm 13 modules valid; differential 813 cases, 0 mismatches;
  gate 0 failures; review regressions passed; domain regressions passed.
- `src/wasm.c` (387 lines) writes Wasm 1.0 bytes directly. Function 0 is a
  bump allocator. Each IR entry is an `i64` export. The module has no
  import section.
- The IR ops (`src/ir.h`) are ADD, SUB, MUL, EQ, LE, ADD_CARRY, MUL_CARRY
  and OR. Wasm `i64` arithmetic wraps mod 2^64. That is the 64-bit torus of
  TFHE.
- TinyCC has no Wasm back end. `build/langc` (C99, built by tcc) writes the
  module bytes itself.
- The gate needs node, wasm-validate and wasm-objdump (/opt/homebrew/bin).

### 3.3 Sibling repositories (port sources)

| Repository | SHA at S0 | Fact |
|---|---|---|
| leaf-lang | 47a6f36 | `langc fmt` (src/main.c:44) and `langc check --json` (:84) are built. AGENTS.md (38 lines) and the README table (:18) are the shape to port. Ambient formers: Pi, Sigma, Path, PathP, I, i0, i1, transp, hcomp, U, Glue, ua, Unit. Partial is not a leaf former. Leaf admits one CC (`Stream`). |
| quorum-lang | 09f7f59 | PLAN section 2 (lines 72 to 176) is the R1 reading. Its Q1 (b) refuses CC. PLAN 4.3: FROST(secp256k1, SHA-256), RFC 9591, Appendix E vectors, Pedersen DKG, slice S7, not built. |
| zkml-lang | 968dce4 | Printers `build/llzkprint`, `build/halo2print`, `build/plonky3print`. LLZK and Halo2 use BN254 only; Plonky3 uses BabyBear only (SPEC.md:192). Poseidon2 is only in the Plonky3 test config (src/plonky3.c:446), not a guest op. `frInst` has 8 limbs (domain.lang:766). |
| zkpolicy-lang | 1d263fb | `src/zkml.c` (785 lines), `src/zkml.h`, `src/zkml-names.h`: the Circuit IR writer to port. The cubical kernel with HITs, Glue and ua is in src/front. |
| escrow-lang | 34203a2 | The on-chain EscrowDAO, EVM only. design/DENOTATIONAL-DESIGN.md and prelude/Prelude.esc sections 1 to 6 are a domain skeleton. No file in it mentions the off-chain note. |
| intent-lang | 67445ae | R1 reading (PLAN 2.2) and `REFUSE_CELL` in check.c. |
| resolve-lang | 632d819 | R1 reading (PLAN 2) and `REFUSE_CELL` in check.c. |
| agent-lang | 96e5473 | Diagnostic fix text (parser.c). |
| dil-lang | 9e57528 | Diagnostic fix text (parser.c, check.c). |

### 3.4 Not available locally

- No TFHE source, paper or parameter file is under ~/Documents (depth 1)
  or ~/.cargo/registry/src. So S0 cannot verify a 128-bit TFHE parameter
  set. `docs/PLAN.md` Q-C2 keeps it OPEN.
- /usr/bin/clang has no wasm32 in `-print-targets`.
  /opt/homebrew/bin/wasm-ld and /opt/homebrew/bin/wat2wasm exist.
