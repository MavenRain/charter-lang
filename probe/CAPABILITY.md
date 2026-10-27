# Host capability probe: tcc-wasm

Date: YYYY-MM-DD. Host tree: `<path>` at <commit>, read only. Driver:
`<host executable>` (built YYYY-MM-DD). <Say if other work loaded the
machine. Then each wall time is an upper bound.>

To run the probe again: <the command that runs all steps, and the command
that runs some steps>. Each step runs below `probe/guard.py`, which stops a
command above <N> MB resident memory or above its time limit. The probe
writes only below a new temporary directory. The largest process in the
probe used <N> MB.

## Questions

Each host must answer these questions. Each answer is one numbered section
below. An answer sets the status of a former in `formers/tcc-wasm.md`.

| Question | Section | Formers |
|---|---|---|
| Which commands check a file, print a normal form, build and run? | 1 | all |
| Does the host take several files, or must the driver join them? | 2 | all |
| Which recursion does the host accept, and how does it refuse the rest? | 3 | F6, F7 |
| Which `Nat` primitives exist? Does `Nat` have an eliminator? | 4 | F6, F7 |
| How does a result leave the host? | 5 | target |
| What do check and build cost (time and resident memory) at N = 100 and N = 1000? | 6 | all |
| Can a family take a parameter? Can a constructor of such a family appear in a term? | 7 | F4, F12, F15 |
| Can a program project a Sigma? Does the kernel accept Sigma eta? | 8 | F11 |
| How does a program use equality: transport, cong, an index type? | 9 | F12, F13 |
| How does the host report an axiom? | 10 | R2 |

## 1. Commands

| Job | Command | Result |
| --- | --- | --- |
| Check | `<command> FILE` | <exit codes and output> |
| Print normal form | `<command>` | <output> |
| Build | `<command>` | <output> |
| Run | `<command>` | <output> |

- <Limits of each command, for example one file only.>
- Not probed: <commands that the probe did not run>.

## 2. Several files

<Does the host accept several files or an import form? If not, which order
must the driver use to join them?>

## 3. Recursion and totality

<Which recursive definitions check. Which calls the host refuses, with the
exact error line.>

## 4. Nat

<The primitives. The result of a subtraction below zero. Whether a
definition can recurse on a `Nat`. The largest value that can leave the
host.>

## 5. How a result leaves the host

<The path of a result from the host to a file: printed text, a module
export, or a contract.>

## 6. Cost

| Step | N = 100 | N = 1000 |
| --- | --- | --- |
| Check | <s>, <MB> | <s>, <MB> |
| Build | <s>, <MB> | <s>, <MB> |
| Run | <s>, <MB> | <s>, <MB> |

## 7. Parametric families

<Whether a family can take a type parameter, and whether its constructors can
appear in a term. Name the probe file.>

## 8. Sigma projection and eta

<Whether `witness` and `payload` (or `.1` and `.2`) check, whether a Sigma
pattern parses, and whether the kernel identifies `pack (witness s)
(payload s)` with `s`.>

## 9. Equality

<How a program writes `Eq`, `transport` and `cong`. Whether one family can
serve each index type.>

## 10. Axiom detection

<The command that lists the axioms of a file. Its output for a file with no
axiom and for a file with one axiom.>

## Consequences for M0

1. <One rule for the build that a section above forces. Cite the section.>
