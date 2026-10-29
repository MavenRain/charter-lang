# charter-lang

charter-lang is a language for an escrow that a member set governs off
chain. A program states the meaning of the Off-Chain EscrowDAO note:
deposits, encrypted votes, settlement by a threshold of members,
withdrawals as vouchers, and a constitution that amends itself. The host
is TinyCC. The planned targets are Wasm (client, member node and public
verifier), a ZK circuit IR and an FHE circuit IR.

## Status (S3)

S1, S2a, S2b, S2c, S2d and S3 are built. The front end has the leaf-lang surface. `langc fmt`
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
section 6 (54 of 54 laws).

S2c adds the escrow state `St M` (`kappa`, the epoch, the entry position,
ledger, credit, the open claims, the spent receipt keys, `Gamma_E` and
`Gamma_A`; `SPEC.md` section 5) and the 10 operations of `docs/PLAN.md`
3.2 with their fit to `tSem` (`opStep`; `SPEC.md` section 6).
`examples/escrow.lang` discharges the S2c law rows of `docs/PLAN.md`
section 6 (152 of 152 laws). Thm 4.3 has a general proof (`enactEscrow`).
Invariant I, Cor 4.2, Conservation and Thm 4.5 have law points on one
valid transcript from `S_0`. Their general proofs are open.

S2d adds the tests of Prop 3.3 and 3.4 in `examples/escrow.lang` (178 of
178 laws). The Prop 3.3 tests compare a view of the state, with the
position `pos` erased (D73): two independent operations commute on the
view. Prop 3.4 has quorum law points, and its honest-signer part is a test
of S8. The open items O-off-1 to O-off-8 are ruled (`docs/PLAN.md` section
10, Q10 (a)). `SPEC.md` sections 1, 3, 4, 7 and 8 are filled. The crypto
parts are not built. `make check` passes. `docs/PLAN.md` section 9 gives
the slices.

S3 adds the Wasm for the clear meaning. `Kappa` holds theta as the data
type `Rule` (Q-S3-1). `langc build` lowers each run-path `ind` as its
paramorphism (Q-S3-5). Each domain type with a stream form has a codec in
the IR: a word stream in prefix order (`SPEC.md` section 7). With the flag
`--words`, `langc ir`, `abi` and `build` make each program def with a
stream form a stream entry, and `langc eval --words` prints the same
words. `examples/node.lang` has the node entry points (`nodeInit`,
`nodeStep`, `nodeFold`), and `examples/client.lang` has the client entry
points (the 10 run functions at `natCMon` and `clientVerdict`). The gate
compares `langc eval --words` and Wasm on 41 entry stream rows.

## When to reach for charter-lang

| Task | charter-lang? |
|---|---|
| state an escrow with deposit, settle by vote, withdraw and amend, and check its laws | yes (S2b to S2d) |
| run the clear meaning of a transcript in Wasm | yes (S3) |
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
needs node, wasm-validate, wasm-objdump and wasm-interp.

## License

MIT OR Apache-2.0.
