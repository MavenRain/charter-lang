# AGENTS.md

## Routing rule

Use charter-lang for an escrow that a member set governs off chain:
encrypted ballots, a threshold verdict, credits under FHE, withdrawals as
vouchers and a constitution that amends itself. Do not use it for an
on-chain escrow (use escrow-lang) or for general-purpose code.

## Status (S3)

Built: the tcc-wasm kit pipeline (parse, check, IR, Wasm, differential);
the leaf-lang surface; `langc fmt` with one canonical form per operation;
`langc check --json` with fix hints and the counts parsed and typed; the
R1 refusals `REFUSE_CELL` and `REFUSE_DATA`; the base data of
`domain/domain.lang` (`DecE`, `BallotA`, `DecA`, `Bit`, `Address`, `CMon`,
`Voucher M`, `Claim M`, `FreeMon A`); the dependent eliminator `ind` for
`ℕ` and for each domain family; a recursive field with the uniform
parameters of its family; the R1 free monoid class; `natCMon` in
`examples/assets.lang`; the `laws` count of `langc check --json` (S2a).
S2b: the dependent `ind` on the host `Option`; in `domain/domain.lang`,
`Kappa` with the checks W1 and W2, `Tally`, `TallyA`, `tau`, `theta_t`,
`Amd_tA`, `F = theta o tau`, `T M Z` with its Kleisli laws, and the
transcript fold `tSem` with Thm 3.1; the S2b law rows of `docs/PLAN.md`
section 6 in `examples/kappa.lang`.
S2c: in `domain/domain.lang`, the escrow state `St M`, `Receipt M`,
`Ledger M`, `Motion`, `Vote`, `Escrow M`, the 10 operations (`runDeposit`
to `runEnact`, `Op M`, `opStep`) and Thm 4.3 as a general proof
(`enactEscrow`); in `examples/escrow.lang`, the S2c law rows of
`docs/PLAN.md` section 6: law points for Invariant I, Cor 4.2,
Conservation and Thm 4.5 on one valid transcript, and the S2c law points
of Prop 3.3 and 3.4.
S2d: in `examples/escrow.lang`, the Prop 3.3 tests on a view with `pos`
erased (D73) and the Prop 3.4 quorum law points (178 of 178 laws); the
open items O-off-1 to O-off-8 ruled (`docs/PLAN.md` section 10); `SPEC.md`
sections 1, 3, 4, 7 and 8 filled.
S3: the Wasm for the clear meaning; theta as the data type `Rule`
(Q-S3-1); each run-path `ind` lowered as its paramorphism; a word-stream
codec for each domain type with a stream form, and the stream entries of
`--words` (`SPEC.md` section 7); `langc eval --words`; the node entry
points in `examples/node.lang` and the client entry points in
`examples/client.lang`.

Planned (`docs/PLAN.md` sections 7 and 9). Do not cite these as built:
- the honest-signer part of Prop 3.4 (S8).
- the general proofs of Invariant I and Conservation (open).
- `skills/charter-lang/SKILL.md` with 3 to 5 graded examples (S9).
- `langc mcp`, an MCP server in C that tcc builds (S9).
- `docs/TOKEN-BASELINE.md`, token counts against Python and Rust (S9).

## Commands that work now

- `make check`: build `build/langc` with tcc and run the gate.
- `build/langc check PROG`: check a program.
- `build/langc check --json PROG`: the same check, with JSON diagnostics
  and a progress line.
- `build/langc fmt PROG`: print the canonical text of the program.
- `build/langc eval PROG NAME [ARGS...]`: print the normal form of `NAME`.
- `build/langc ir PROG` and `build/langc abi PROG`: print the IR and the
  entry names.
- `build/langc build PROG -o OUT`: write the Wasm module.

## Rules for a change

- `design/DESIGN.md` sections 1 and 2 are USER text. Do not edit them. Do
  not edit `design/OFFCHAIN-ESCROWDAO.html`.
- Admit no type constructor that `docs/PLAN.md` section 2 does not list.
- Admit no base name that `docs/PLAN.md` section 3 does not list.
- No em-dash or en-dash outside the two design files. The gate checks it.
