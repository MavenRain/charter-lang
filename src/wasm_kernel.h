/* The kernel test module of the Wasm back end: Poseidon2 (S4 U2, Q-C6),
 * SHA-512 and Ed25519 verify (S4 U5). */
#ifndef LANG_WASM_KERNEL_H
#define LANG_WASM_KERNEL_H
#include <stdio.h>

/* Writes a module with the kernel of src/wasm.c and five stream entries
 * (the ABI of Q-S3-7), and exports `memory`:
 * - p2perm (12 words: 3 elements of 4 words, low word first) -> the 12 words
 *   of poseidon2_permute;
 * - p2hash (tag, w_1 .. w_m) -> the 4 words of poseidon2_hash(tag, w, m);
 * - ops (a, b, k) -> a xor b, a and b, a rotr k;
 * - sha512 (n, w_1 .. w_m) -> the SHA-512 digest of the first n bytes of w
 *   (8 bytes per word, little endian; n <= 8m, else a trap) as 8 words in
 *   the same byte order;
 * - ed25519 (n, vk 4 words, sig 8 words, w_1 .. w_m) -> the RFC 8032
 *   cofactored verify bit of the signature on the first n bytes of w (n <=
 *   8m, else a trap).
 * Returns 0 on a write error. */
int wasm_write_kernel_test(FILE *out, FILE *err);
/* Writes the TFHE kernel test module (S5 U2a): the FFT kernels of
 * src/front/tfhe.c in their C operation order, the twiddle tables of
 * tfhe_fft_init in a data section, three stream entries, and `memory`:
 * - fft (2048 poly words) -> the 2048 bits of tfhe_fft_forward (re, then im);
 * - ifft (the 2048 bits of a TfheFourier) -> tfhe_fft_backward_add into
 *   zeros;
 * - polymul (a 2048 words, b 2048 words) -> tfhe_poly_mul_fft (a, b).
 * Returns 0 on a write error. */
/* S5 U3b: the byte offset of the KSK words in the TFHE test module (the
   host `--load`s them there); the BSK doubles follow the KSK words. */
enum { WASM_TFHE_KSK = 0x800000 };

int wasm_write_tfhe_test(FILE *out, FILE *err);
/* S5 U5c: writes the TFHE client module (no server keys) with one stream
 * entry and `memory`: pkenc (seed 4 words, the 32 bytes low byte first;
 * pk_a 2048, pk_b 2048, m 16) -> (mask 2048, body 16), the tfhe_pke_encrypt
 * of a fresh DRBG of the seed. Returns 0 on a write error. */
int wasm_write_tfhe_client(FILE *out, FILE *err);
#endif
