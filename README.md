# charter-lang

charter-lang is a language for an escrow that a member set governs off
chain. A program states the meaning of the Off-Chain EscrowDAO note:
deposits, encrypted votes, settlement by a threshold of members,
withdrawals as vouchers, and a constitution that amends itself. The host
is TinyCC. The planned targets are Wasm (client, member node and public
verifier), a ZK circuit IR and an FHE circuit IR.

## Status (S6b)

S1, S2a, S2b, S2c, S2d, S3, S4, S5, S6a and S6b are built. The front end has the leaf-lang surface. `langc fmt`
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

S4 adds the hash and the signature check. The core types `Digest` and
`Key` are elements of the BN254 scalar field. `hashOf tag T x` is the
Poseidon2 hash (BN254, t = 3, Q-C4) of the word stream of `x : T`
(`SPEC.md` section 7), with the domain tag `tag`, a literal 1 to 5
(Q-S4-1, Q-S4-2). `merkleRoot xs` gives the root of a Merkle tree of
fixed depth 16 over `xs : FreeMon Digest` (Q-S4-3). In
`domain/domain.lang`, `chainStep` gives the step of the hash chain over an
`Entry` (Q-S4-9, Q-S4-16). `frostVerify vk T msg sig` verifies the
signature `sig : Sig` on the word stream of `msg : T` under the group key
`vk : VKey`: FROST(Ed25519, SHA-512) with the cofactored check (Q-C1,
Q-S4-12, Q-S4-14). Verification rejects pure small-order public keys. Only
the verify is built (Q-S4-4). Each operation has a C meaning for
`langc eval`, and `langc build` emits Wasm kernels for
Poseidon2, SHA-512 and Ed25519 (Q-C6). The gate checks the published
vectors: the HorizenLabs Poseidon2 BN254 t = 3 vector and the RFC 9591
Appendix E.1 signature.

S5 adds the TFHE runtime and the FHE circuit IR. `src/front/tfhe.c` has
the C TFHE core: CGGI over the torus Z/2^64 with the tfhe-rs 1.8.0 set
`V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` (n 918, N 2048,
TUniform noise; Q-C2, Q-S5-1). `src/wasm.c` emits the Wasm TFHE kernels:
the negacyclic f64 FFT (Q-S5-2), the key switch, the modulus switch, the
blind rotation and the PBS. An encrypted value of `A` is a `u64` radix of
32 blocks of 2-bit message and 2-bit carry (Q-S5-7). `src/front/fhe.c`
gives the FHE circuit IR (`docs/PLAN.md` 5.3) as a C circuit table
(Q-S5-6): `tally4`, `tally3`, `theta`, `settle`, `credit`, `withdraw` and
`amd`, each with a static PBS count. `langc fhe N` prints the table. The
client module `build/tfhe-client.wasm` encrypts a ballot under the public
key (Q-S5-4, Q-S5-8) and casts it to the Q-S5-1 keys (Q-S5-9). The gate
runs the equation (1.1) differential on the full encrypted chain at N 7
(Q-S5-3, Q-S5-10): the cast is 113 PBS, and the 7 circuits are 1503 Wasm
PBS. One Wasm PBS takes 74.5 ms (arm64), and the budget is 138 ms (O4).

S6a adds the key shares, the squash set and the threshold decryption.
`src/front/tshare.c` (U1) shares a key over the 192-bit prime field
p = c x 2^13 + 1 (Q-S6-2, Q-S6-8) with n 5 and t 2 (Q-S6-9). The share
vector of each party has a SHA-512 commitment (Q-S6-4).
`src/front/squash.c` (U2) has the squash set to 2^128 (Q-S6-1) and the
squash PBS (Q-S6-12). `src/front/tdec.c` (U3) gives the threshold
decryption of a squash LWE. Each party in the set deals the shares of a
flood noise in [-2^106, 2^106), and the combine checks that the partials
are on one polynomial of degree t (Q-C7, Q-S6-14, Q-S6-15). The tests use
C test keys from a test dealer.

S6b adds the MPC key generation and the masked re-encryption at enact.
The 5 parties (n 5, t 2, Q-S6-9) are semi-honest (O10).
`src/front/tkeygen.c` (U4a) has the coin toss for the public masks, the
shared random bits for the key bits and the party noise TUniform(b - 1)
(Q-S6-10). U4b opens the shares into the KSK, the BSK, pk, the cast KSK
and the squash BSK. U4c runs the S5 chain and the threshold decryption
under the MPC keys (Q-S6-18). U5 does the masked re-encryption from
epoch e to epoch e+1 (Q-S6-6 (c), Q-S6-19 (b), Q-S6-20 (a)): the members
add a joint random r, the epoch e members decrypt m + r, and epoch e+1
gets Enc(m + r) - Enc(r). There is no switch key.

## When to reach for charter-lang

| Task | charter-lang? |
|---|---|
| state an escrow with deposit, settle by vote, withdraw and amend, and check its laws | yes (S2b to S2d) |
| run the clear meaning of a transcript in Wasm | yes (S3) |
| hash a value, make a Merkle root or a hash chain step, and verify a FROST signature, in `langc eval` and in Wasm | yes (S4) |
| tally encrypted ballots and update encrypted credits under TFHE, in C and in Wasm | yes (S5) |
| decrypt with a threshold of members | yes (S6a) |
| make the epoch keys at enact | yes (S6b) |
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
`make check-clang` compiles the same sources with clang and the repo
flags. `make check-squash` builds `build/squashtool` with `cc -O2` and
runs the full squash PBS rows and the tdec squash rows. It makes one
squash BSK (812 MB) and takes about 104 s on a quiet machine. It is not
part of `make check` (Q-S6-13).
`make check-mpc` builds `build/mpctool` with `cc -O2`. It makes two MPC
key sets (epoch e and epoch e+1). It runs the S5 chain and the tdec rows
under the MPC keys, then the re-encryption rows. It takes about 550 s to
630 s at load average 7 to 8, and the peak memory is 0.94 GiB to
1.13 GiB. It is not part of `make check` (Q-S6-17).

## License

MIT OR Apache-2.0.
