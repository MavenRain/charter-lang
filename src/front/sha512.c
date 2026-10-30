/* SHA-512, FIPS 180-4 sections 4.1.3, 4.2.3, 5.1.2, 5.3.5 and 6.4. */
#include "front/sha512.h"

/* K, FIPS 180-4 4.2.3. */
static const uint64_t round_constant[80] = {
  0x428a2f98d728ae22u, 0x7137449123ef65cdu, 0xb5c0fbcfec4d3b2fu, 0xe9b5dba58189dbbcu,
  0x3956c25bf348b538u, 0x59f111f1b605d019u, 0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u,
  0xd807aa98a3030242u, 0x12835b0145706fbeu, 0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u,
  0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u, 0x9bdc06a725c71235u, 0xc19bf174cf692694u,
  0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u, 0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u,
  0x2de92c6f592b0275u, 0x4a7484aa6ea6e483u, 0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u,
  0x983e5152ee66dfabu, 0xa831c66d2db43210u, 0xb00327c898fb213fu, 0xbf597fc7beef0ee4u,
  0xc6e00bf33da88fc2u, 0xd5a79147930aa725u, 0x06ca6351e003826fu, 0x142929670a0e6e70u,
  0x27b70a8546d22ffcu, 0x2e1b21385c26c926u, 0x4d2c6dfc5ac42aedu, 0x53380d139d95b3dfu,
  0x650a73548baf63deu, 0x766a0abb3c77b2a8u, 0x81c2c92e47edaee6u, 0x92722c851482353bu,
  0xa2bfe8a14cf10364u, 0xa81a664bbc423001u, 0xc24b8b70d0f89791u, 0xc76c51a30654be30u,
  0xd192e819d6ef5218u, 0xd69906245565a910u, 0xf40e35855771202au, 0x106aa07032bbd1b8u,
  0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u, 0x2748774cdf8eeb99u, 0x34b0bcb5e19b48a8u,
  0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu, 0x5b9cca4f7763e373u, 0x682e6ff3d6b2b8a3u,
  0x748f82ee5defb2fcu, 0x78a5636f43172f60u, 0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
  0x90befffa23631e28u, 0xa4506cebde82bde9u, 0xbef9a3f7b2c67915u, 0xc67178f2e372532bu,
  0xca273eceea26619cu, 0xd186b8c721c0c207u, 0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u,
  0x06f067aa72176fbau, 0x0a637dc5a2c898a6u, 0x113f9804bef90daeu, 0x1b710b35131c471bu,
  0x28db77f523047d84u, 0x32caab7b40c72493u, 0x3c9ebe0a15c9bebcu, 0x431d67c49c100d4cu,
  0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au, 0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u
};

/* H(0), FIPS 180-4 5.3.5. */
static const uint64_t initial_hash[8] = {
  0x6a09e667f3bcc908u, 0xbb67ae8584caa73bu, 0x3c6ef372fe94f82bu, 0xa54ff53a5f1d36f1u,
  0x510e527fade682d1u, 0x9b05688c2b3e6c1fu, 0x1f83d9abfb41bd6bu, 0x5be0cd19137e2179u
};

/* ROTR^n, 0 < n < 64. */
static uint64_t rotr(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64u - n));
}

/* The functions of FIPS 180-4 4.1.3. */
static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (~x & z);
}

static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t big_sigma0(uint64_t x) {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

static uint64_t big_sigma1(uint64_t x) {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

static uint64_t small_sigma0(uint64_t x) {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

static uint64_t small_sigma1(uint64_t x) {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

static uint64_t load_be(const uint8_t *p) {
  uint64_t x = 0;
  unsigned i;
  for (i = 0; i < 8; i++)
    x = (x << 8) | p[i];
  return x;
}

static void store_be(uint8_t *p, uint64_t x) {
  unsigned i;
  for (i = 0; i < 8; i++)
    p[i] = (uint8_t)(x >> (56u - 8u * i));
}

/* FIPS 180-4 6.4.2: one 1024-bit block into the chaining words. */
static void compress(uint64_t h[8], const uint8_t block[SHA512_BLOCK]) {
  uint64_t w[80];
  uint64_t v[8];
  unsigned t;
  for (t = 0; t < 16; t++)
    w[t] = load_be(block + 8u * t);
  for (t = 16; t < 80; t++)
    w[t] = small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) + w[t - 16];
  for (t = 0; t < 8; t++)
    v[t] = h[t];
  for (t = 0; t < 80; t++) {
    uint64_t t1 = v[7] + big_sigma1(v[4]) + ch(v[4], v[5], v[6]) + round_constant[t] + w[t];
    uint64_t t2 = big_sigma0(v[0]) + maj(v[0], v[1], v[2]);
    v[7] = v[6];
    v[6] = v[5];
    v[5] = v[4];
    v[4] = v[3] + t1;
    v[3] = v[2];
    v[2] = v[1];
    v[1] = v[0];
    v[0] = t1 + t2;
  }
  for (t = 0; t < 8; t++)
    h[t] += v[t];
}

void sha512_init(Sha512 *s) {
  unsigned i;
  for (i = 0; i < 8; i++)
    s->h[i] = initial_hash[i];
  s->fill = 0;
  s->length = 0;
}

void sha512_update(Sha512 *s, const uint8_t *bytes, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    s->block[s->fill++] = bytes[i];
    if (s->fill == SHA512_BLOCK) {
      compress(s->h, s->block);
      s->fill = 0;
    }
  }
  s->length += n;
}

/* The bit length is 128 bits, high word first: (length >> 61, length << 3). */
void sha512_final(Sha512 *s, uint8_t digest[SHA512_BYTES]) {
  unsigned i;
  s->block[s->fill++] = 0x80u;
  if (s->fill > SHA512_BLOCK - 16u) {
    while (s->fill < SHA512_BLOCK)
      s->block[s->fill++] = 0;
    compress(s->h, s->block);
    s->fill = 0;
  }
  while (s->fill < SHA512_BLOCK - 16u)
    s->block[s->fill++] = 0;
  store_be(s->block + 112, s->length >> 61);
  store_be(s->block + 120, s->length << 3);
  compress(s->h, s->block);
  for (i = 0; i < 8; i++)
    store_be(digest + 8u * i, s->h[i]);
}

uint64_t sha512_round_constant(unsigned t) {
  return t < 80u ? round_constant[t] : 0;
}

uint64_t sha512_initial_hash(unsigned i) {
  return i < 8u ? initial_hash[i] : 0;
}

void sha512(const uint8_t *bytes, size_t n, uint8_t digest[SHA512_BYTES]) {
  Sha512 s;
  sha512_init(&s);
  sha512_update(&s, bytes, n);
  sha512_final(&s, digest);
}
