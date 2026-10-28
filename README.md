# charter-lang

charter-lang is a language for an escrow that a member set governs off
chain. A program states the meaning of the Off-Chain EscrowDAO note:
deposits, encrypted votes, settlement by a threshold of members,
withdrawals as vouchers, and a constitution that amends itself. The host
is TinyCC. The planned targets are Wasm (client, member node and public
verifier), a ZK circuit IR and an FHE circuit IR.

## Status (S2b)

S1, S2a and S2b are built. The front end has the leaf-lang surface. `langc fmt`
prints the one canonical form, and `langc check --json` gives a JSON
diagnostic with a fix hint and the counts parsed, typed and laws (the law
definitions that type-check, as `k of m`). Rule R1 is enforced: a domain
family is a cell signature or a free monoid, or it gets `REFUSE_CELL`, and
a program cannot declare data (`REFUSE_DATA`). The checker has the
dependent eliminator `ind` for `ℕ` and for each domain family, and a
recursive field with the uniform parameters of its family (`SPEC.md` 2.7).
`domain/domain.lang` has the base data: the enums `DecE`, `BallotA`,
`DecA` and `Bit`, `Address`, the asset structure `CMon`, the records
`Voucher M` and `Claim M`, and `FreeMon A` with its monoid laws.
`FreeMon A` replaces the kit `Stack`; the kit `Tree` stays as a regression
subject. `examples/assets.lang` has `natCMon`, the `ℕ` instance of `CMon`,
with its seven laws.

S2b adds the dependent `ind` on the host `Option` (`SPEC.md` 2.7) and
these definitions in `domain/domain.lang`: the constitution `Kappa` with
the checks W1 and W2, the tallies `Tally` and `TallyA` with `tau`, the
rules `theta_t` and `Amd_tA`, `F = theta o tau`, the partial writer
`T M Z = Option (Z × FreeMon (Voucher M))` with its Kleisli laws, and the
transcript fold `tSem` with Thm 3.1 (`SPEC.md` sections 5 and 6).
`examples/kappa.lang` discharges the S2b law rows of `docs/PLAN.md`
section 6 (54 of 54 laws). The escrow operations, the S2c laws and all
crypto are not built. `make check` passes. `docs/PLAN.md` section 9 gives
the slices.

## When to reach for charter-lang

| Task | charter-lang? |
|---|---|
| state an escrow with deposit, settle by vote, withdraw and amend, and check its laws | yes, PLANNED (S2b) |
| run the clear meaning of a transcript in Wasm | yes, PLANNED (S3) |
| tally encrypted ballots and update encrypted credits under threshold TFHE | yes, PLANNED (S5, S6) |
| prove membership and ballot well-formedness in a circuit | yes, PLANNED (S7) |
| verify a transcript as a member node or as a public verifier | yes, PLANNED (S8) |
| an on-chain escrow on EVM | no: use escrow-lang |
| general-purpose code, strings, clocks, payment on a rail | no: excluded (`docs/PLAN.md` 3.3) |

## Files

- `design/DESIGN.md`: the USER ask, the rulings and the S0 facts.
- `design/OFFCHAIN-ESCROWDAO.html`: the design note, the only domain
  source.
- `docs/PLAN.md`: rulings, the R1 reading, the base signature, the crypto
  layer, targets, laws, agent adoption, slices and questions.
- `AGENTS.md`: how an agent uses this repository.
- `SPEC.md`, `formers/`, `probe/`, `docs/STATUS.md`, `docs/VALIDATION.md`,
  `docs/host/README.md`: the kit files. The slices fill them.

## Build

`make check` builds `build/langc` with tcc and runs the gate. The gate
needs node, wasm-validate and wasm-objdump.

## License

MIT OR Apache-2.0.
