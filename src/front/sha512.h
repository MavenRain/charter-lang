/* SHA-512 (FIPS 180-4 6.4) for the Ed25519 verify of FROST(Ed25519, SHA-512)
 * (RFC 9591 6.1, docs/PLAN.md 11 Q-C1 (a)). */
#ifndef LANG_SHA512_H
#define LANG_SHA512_H
#include <stddef.h>
#include <stdint.h>

enum { SHA512_BYTES = 64, SHA512_BLOCK = 128 };

/* The running state of one hash: the 8 chaining words, the bytes not yet in
 * a full block, and the message length in bytes. */
typedef struct Sha512 {
  uint64_t h[8];
  uint8_t block[SHA512_BLOCK];
  size_t fill;
  uint64_t length;
} Sha512;

void sha512_init(Sha512 *s);

/* Adds N bytes to the message. BYTES can be NULL when N is 0. */
void sha512_update(Sha512 *s, const uint8_t *bytes, size_t n);

/* Pads the message (FIPS 180-4 5.1.2) and writes the digest. */
void sha512_final(Sha512 *s, uint8_t digest[SHA512_BYTES]);

/* The digest of N bytes in one call. */
void sha512(const uint8_t *bytes, size_t n, uint8_t digest[SHA512_BYTES]);

/* K_t (FIPS 180-4 4.2.3) for t < 80 and word I of H(0) (5.3.5) for i < 8,
 * else 0: the one source of the constants of the Wasm kernel. */
uint64_t sha512_round_constant(unsigned t);
uint64_t sha512_initial_hash(unsigned i);
#endif
