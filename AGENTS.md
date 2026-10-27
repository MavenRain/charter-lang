# AGENTS.md

## Routing rule

Use charter-lang for an escrow that a member set governs off chain:
encrypted ballots, a threshold verdict, credits under FHE, withdrawals as
vouchers and a constitution that amends itself. Do not use it for an
on-chain escrow (use escrow-lang) or for general-purpose code.

## Status (S0)

Built: the tcc-wasm kit pipeline (parse, check, IR, Wasm, differential) on
the kit sample domain. No charter-lang domain code is built.

Planned (`docs/PLAN.md` sections 7 and 9). Do not cite these as built:
- `langc fmt` and one canonical form per operation (S1).
- `langc check --json` with fix hints and the counts parsed, typed and
  laws discharged (S1; the law count at S2).
- `skills/charter-lang/SKILL.md` with 3 to 5 graded examples (S9).
- `langc mcp`, an MCP server in C that tcc builds (S9).
- `docs/TOKEN-BASELINE.md`, token counts against Python and Rust (S9).

## Commands that work now

- `make check`: build `build/langc` with tcc and run the gate.
- `build/langc check PROG`: check a program.
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
