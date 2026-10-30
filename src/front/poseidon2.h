/* Poseidon2 over the BN254 scalar field Fr, width 3, S-box x^5: the
 * poseidon2_instance_bn256 of HorizenLabs/poseidon2 rev 055bde3f
 * (docs/PLAN.md 11 Q-C4 (a)). */
#ifndef LANG_POSEIDON2_H
#define LANG_POSEIDON2_H
#include <stddef.h>
#include <stdint.h>

/* Width 3; 4 + 4 external and 56 internal rounds (Poseidon2Params::new(3, 5, 8, 56, ...)). */
enum { POSEIDON2_T = 3, POSEIDON2_HALF_F = 4, POSEIDON2_ROUNDS_P = 56 };

/* An element of Fr, r = 0x30644e72...f0000001: 8 limbs of 32 bits, low limb
 * first, each limb in a u64 (TinyCC has no __int128, so each product of two
 * limbs fits a u64). The value is canonical: below r. */
enum { FR_LIMBS = 8, FR_WORDS = 4 };
typedef struct Fr {
  uint64_t limb[FR_LIMBS];
} Fr;

/* Reads the 4 stream words of a Digest, low word first. Returns 0 and leaves
 * OUT as it was when the value is not below r. */
int fr_from_words(Fr *out, const uint64_t words[FR_WORDS]);

/* Writes the 4 stream words of A, low word first. */
void fr_to_words(const Fr *a, uint64_t words[FR_WORDS]);

/* Reads "0x" and 64 hex digits, the form of the source constants. Returns 0
 * and leaves OUT as it was on any other text or a value not below r. */
int fr_from_hex(Fr *out, const char *hex);

int fr_equal(const Fr *a, const Fr *b);

/* Returns 1 when each round constant reads as a canonical element. */
int poseidon2_constants_ok(void);

/* Permutes the state in place. Each element must be canonical. */
void poseidon2_permute(Fr state[POSEIDON2_T]);

/* H(tag, words, n) (Q-S4-2 (a)): the sponge with rate 2 and capacity 1 over
 * N stream words, each word one element. DIGEST gets element 0 of the state. */
void poseidon2_hash(uint64_t tag, const uint64_t *words, size_t n, Fr *digest);

/* The constants of the Wasm kernel (src/wasm.c, Q-C6), one source with the C:
 * r, R^2 mod r, -r^-1 mod 2^32, and round constant K (below
 * POSEIDON2_CONSTANTS) in Montgomery form, in the order of the permutation:
 * 4 x 3 initial external, 56 internal, 4 x 3 terminal external, row by row.
 * A K at least POSEIDON2_CONSTANTS gives 0. */
enum { POSEIDON2_CONSTANTS = 2 * POSEIDON2_HALF_F * POSEIDON2_T + POSEIDON2_ROUNDS_P };
Fr fr_modulus(void);
Fr fr_r_squared(void);
uint64_t fr_n_prime(void);
Fr poseidon2_round_constant(unsigned k);
#endif
