# AGENTS.md

## Routing rule

Use charter-lang for an escrow that a member set governs off chain:
encrypted ballots, a threshold verdict, credits under FHE, withdrawals as
vouchers and a constitution that amends itself. Do not use it for an
on-chain escrow (use escrow-lang) or for general-purpose code.

## Status (S2b)

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
section 6 in `examples/kappa.lang`. The escrow operations and the S2c laws
are not built.

Planned (`docs/PLAN.md` sections 7 and 9). Do not cite these as built:
- the S2c law rows of `docs/PLAN.md` section 6 and the escrow operations (S2c).
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
