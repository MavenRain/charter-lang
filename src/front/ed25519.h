/* Ed25519 verify (RFC 8032 5.1.7) with the cofactored group equation that
 * FROST(Ed25519, SHA-512) requires (RFC 9591 6.1, docs/PLAN.md 11 Q-C1 (a)),
 * in the TweetNaCl shape: a field element is 16 limbs of 16 bits over
 * p = 2^255 - 19, a point has extended coordinates (X : Y : Z : T). The code
 * is variable time: verify reads public values only. Signing, nonces,
 * aggregation and DKG are out of scope (S8 or Q-C5). */
#ifndef LANG_ED25519_H
#define LANG_ED25519_H
#include <stddef.h>
#include <stdint.h>

enum { ED25519_KEY_BYTES = 32, ED25519_SIG_BYTES = 64, ED25519_SCALAR_BYTES = 32 };

/* Returns 1 when each curve constant agrees with its definition: d =
 * -121665/121666, 2d, sqrt(-1), and the base point (y = 4/5, x even, on the
 * curve). */
int ed25519_constants_ok(void);

/* Limb I (16 bits, i < 16) of a curve constant, else 0: the one source of the
 * constants of the Wasm kernel. */
enum { ED25519_CONST_D, ED25519_CONST_D2, ED25519_CONST_SQRT_M1, ED25519_CONST_BASE_X, ED25519_CONST_BASE_Y,
       ED25519_CONSTS };
uint64_t ed25519_constant(unsigned which, unsigned i);

/* Byte K of L (k < 32), else 0. */
uint64_t ed25519_order_byte(unsigned k);

/* RFC 8032 5.1.7 verify of SIG = R || S on the N bytes of MSG under the
 * public key PK, k = SHA-512(R || PK || MSG) mod L. Returns 1 when
 * [8][S]B = [8]R + [8][k]A, else 0. Also 0 when S is not below L, R or PK
 * does not decode (RFC 8032 5.1.3: y not below p, no square root, or x = 0
 * with the sign bit set), or [8]PK is the identity. The latter rejects pure
 * small-order keys; a key with a nonzero prime-order part can have a torsion
 * component under the cofactored equation. MSG can be NULL when N is 0. */
int ed25519_verify(const uint8_t pk[ED25519_KEY_BYTES], const uint8_t *msg, size_t n,
                   const uint8_t sig[ED25519_SIG_BYTES]);

/* Writes the encoding of [S]B. */
void ed25519_base_mul(uint8_t out[ED25519_KEY_BYTES], const uint8_t s[ED25519_SCALAR_BYTES]);

/* Scalars mod L = 2^252 + 27742317777372353535851937790883648493: 32 bytes,
 * low byte first. Each operation takes any 32-byte input and writes a value
 * below L; OUT can be an input. */
int ed25519_scalar_canonical(const uint8_t s[ED25519_SCALAR_BYTES]);
void ed25519_scalar_reduce(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t wide[64]);
void ed25519_scalar_from_u32(uint8_t out[ED25519_SCALAR_BYTES], uint32_t v);
void ed25519_scalar_add(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES],
                        const uint8_t b[ED25519_SCALAR_BYTES]);
void ed25519_scalar_mul(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES],
                        const uint8_t b[ED25519_SCALAR_BYTES]);
void ed25519_scalar_negate(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES]);

/* A^(L - 2), the inverse of A when A is not 0 mod L. */
void ed25519_scalar_invert(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES]);
#endif
