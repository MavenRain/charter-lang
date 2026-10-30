/* Ed25519 verify in the TweetNaCl shape (tweetnacl.c 20140427: car25519, M,
 * pack25519, unpackneg, add, modL). The right shifts of negative limbs are
 * arithmetic (implementation-defined in C99; TinyCC and clang shift
 * arithmetically); the code never shifts a negative value left. */
#include "front/ed25519.h"
#include "front/sha512.h"

enum { LIMBS = 16 };

/* sum limb[i] 2^(16 i) mod p. After a carry each limb is in [0, 2^16). */
typedef struct Fe {
  int64_t limb[LIMBS];
} Fe;

/* x = X/Z, y = Y/Z, x y = T/Z. */
typedef struct Point {
  Fe x, y, z, t;
} Point;

static const Fe fe_zero = {{0}};
static const Fe fe_one = {{1}};

/* d = -121665/121666 mod p = 0x52036cee...135978a3. */
static const Fe curve_d = {{0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                            0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203}};

/* 2d mod p. */
static const Fe curve_d2 = {{0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                             0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406}};

/* sqrt(-1) = 2^((p - 1) / 4) mod p. */
static const Fe sqrt_m1 = {{0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                            0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83}};

/* The base point B (RFC 8032 5.1): y = 4/5, x even. */
static const Fe base_x = {{0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                           0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169}};
static const Fe base_y = {{0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                           0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666}};

/* L, low byte first. */
static const int64_t order[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                  0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0x10};

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    if (a[i] != b[i])
      return 0;
  return 1;
}

/* Carries each limb into the next; the carry out of limb 15 (weight 2^256)
 * comes back into limb 0 times 38, as 2^256 = 38 mod p. */
static void fe_carry(Fe *o) {
  unsigned i;
  for (i = 0; i < LIMBS; i++) {
    int64_t c;
    o->limb[i] += 65536;
    c = o->limb[i] >> 16;
    if (i < LIMBS - 1)
      o->limb[i + 1] += c - 1;
    else
      o->limb[0] += 38 * (c - 1);
    o->limb[i] -= c * 65536;
  }
}

static void fe_add(Fe *o, const Fe *a, const Fe *b) {
  unsigned i;
  for (i = 0; i < LIMBS; i++)
    o->limb[i] = a->limb[i] + b->limb[i];
}

static void fe_sub(Fe *o, const Fe *a, const Fe *b) {
  unsigned i;
  for (i = 0; i < LIMBS; i++)
    o->limb[i] = a->limb[i] - b->limb[i];
}

static void fe_mul(Fe *o, const Fe *a, const Fe *b) {
  int64_t t[2 * LIMBS - 1] = {0};
  unsigned i, j;
  for (i = 0; i < LIMBS; i++)
    for (j = 0; j < LIMBS; j++)
      t[i + j] += a->limb[i] * b->limb[j];
  for (i = 0; i < LIMBS - 1; i++)
    t[i] += 38 * t[i + LIMBS];
  for (i = 0; i < LIMBS; i++)
    o->limb[i] = t[i];
  fe_carry(o);
  fe_carry(o);
}

static void fe_sq(Fe *o, const Fe *a) {
  fe_mul(o, a, a);
}

/* A^(p - 2): p - 2 = 2^255 - 21 has every bit from 254 down to 0 set but
 * bits 4 and 2. */
static void fe_invert(Fe *o, const Fe *a) {
  Fe c = *a;
  int i;
  for (i = 253; i >= 0; i--) {
    fe_sq(&c, &c);
    if (i != 2 && i != 4)
      fe_mul(&c, &c, a);
  }
  *o = c;
}

/* A^((p - 5) / 8) = A^(2^252 - 3): every bit from 251 down to 0 but bit 1. */
static void fe_pow2523(Fe *o, const Fe *a) {
  Fe c = *a;
  int i;
  for (i = 250; i >= 0; i--) {
    fe_sq(&c, &c);
    if (i != 1)
      fe_mul(&c, &c, a);
  }
  *o = c;
}

/* The canonical 32 bytes of N mod p, low byte first: two conditional
 * subtractions of p after three carries. */
static void fe_pack(uint8_t out[32], const Fe *n) {
  Fe t = *n;
  Fe m;
  int i, pass;
  fe_carry(&t);
  fe_carry(&t);
  fe_carry(&t);
  for (pass = 0; pass < 2; pass++) {
    int64_t borrow;
    m.limb[0] = t.limb[0] - 0xffed;
    for (i = 1; i < LIMBS - 1; i++) {
      m.limb[i] = t.limb[i] - 0xffff - ((m.limb[i - 1] >> 16) & 1);
      m.limb[i - 1] &= 0xffff;
    }
    m.limb[LIMBS - 1] = t.limb[LIMBS - 1] - 0x7fff - ((m.limb[LIMBS - 2] >> 16) & 1);
    borrow = (m.limb[LIMBS - 1] >> 16) & 1;
    m.limb[LIMBS - 2] &= 0xffff;
    if (!borrow)
      t = m;
  }
  for (i = 0; i < LIMBS; i++) {
    out[2 * i] = (uint8_t)(t.limb[i] & 0xff);
    out[2 * i + 1] = (uint8_t)((t.limb[i] >> 8) & 0xff);
  }
}

/* The low 255 bits of IN; the caller handles bit 255. */
static void fe_unpack(Fe *o, const uint8_t in[32]) {
  int i;
  for (i = 0; i < LIMBS; i++)
    o->limb[i] = in[2 * i] + ((int64_t)in[2 * i + 1] << 8);
  o->limb[LIMBS - 1] &= 0x7fff;
}

static int fe_equal(const Fe *a, const Fe *b) {
  uint8_t x[32], y[32];
  fe_pack(x, a);
  fe_pack(y, b);
  return bytes_equal(x, y, 32);
}

static unsigned fe_parity(const Fe *a) {
  uint8_t x[32];
  fe_pack(x, a);
  return x[0] & 1u;
}

/* add-2008-hwcd-3 for a = -1, the TweetNaCl add: complete, so it also
 * doubles. O can be P or Q. */
static void point_add(Point *o, const Point *p, const Point *q) {
  Fe a, b, c, d, t, e, f, g, h;
  fe_sub(&a, &p->y, &p->x);
  fe_sub(&t, &q->y, &q->x);
  fe_mul(&a, &a, &t);
  fe_add(&b, &p->x, &p->y);
  fe_add(&t, &q->x, &q->y);
  fe_mul(&b, &b, &t);
  fe_mul(&c, &p->t, &q->t);
  fe_mul(&c, &c, &curve_d2);
  fe_mul(&d, &p->z, &q->z);
  fe_add(&d, &d, &d);
  fe_sub(&e, &b, &a);
  fe_sub(&f, &d, &c);
  fe_add(&g, &d, &c);
  fe_add(&h, &b, &a);
  fe_mul(&o->x, &e, &f);
  fe_mul(&o->y, &h, &g);
  fe_mul(&o->z, &g, &f);
  fe_mul(&o->t, &e, &h);
}

/* [S]Q by double and add from bit 255 down. */
static void point_mul(Point *o, const Point *q, const uint8_t s[32]) {
  Point acc;
  int i;
  acc.x = fe_zero;
  acc.y = fe_one;
  acc.z = fe_one;
  acc.t = fe_zero;
  for (i = 255; i >= 0; i--) {
    point_add(&acc, &acc, &acc);
    if ((s[i / 8] >> (i % 8)) & 1)
      point_add(&acc, &acc, q);
  }
  *o = acc;
}

/* A pure torsion public key is killed by the cofactor. Without this check,
 * R = identity and S = 0 verifies under such a key for every message. */
static int point_small_order(const Point *p) {
  Point q = *p;
  int i;
  for (i = 0; i < 3; i++)
    point_add(&q, &q, &q);
  return fe_equal(&q.x, &fe_zero) && fe_equal(&q.y, &q.z);
}

static void base_point(Point *b) {
  b->x = base_x;
  b->y = base_y;
  b->z = fe_one;
  fe_mul(&b->t, &base_x, &base_y);
}

/* RFC 8032 5.1.2: y, with the parity of x in bit 255. */
static void point_encode(uint8_t out[32], const Point *p) {
  Fe zi, x, y;
  fe_invert(&zi, &p->z);
  fe_mul(&x, &p->x, &zi);
  fe_mul(&y, &p->y, &zi);
  fe_pack(out, &y);
  out[31] ^= (uint8_t)(fe_parity(&x) << 7);
}

/* RFC 8032 5.1.3 (the TweetNaCl unpackneg without the negation): x^2 = u/v
 * with u = y^2 - 1, v = d y^2 + 1; the candidate x = u v^3 (u v^7)^((p-5)/8),
 * times sqrt(-1) when v x^2 = -u. Returns 0 when y is not below p, when u/v
 * has no square root, or when x = 0 and the sign bit is set. */
static int point_decode(Point *p, const uint8_t in[32]) {
  Fe num, den, den2, den4, den6, t, chk;
  uint8_t canon[32];
  unsigned sign = in[31] >> 7;
  int i;
  fe_unpack(&p->y, in);
  fe_pack(canon, &p->y);
  for (i = 0; i < 31; i++)
    if (canon[i] != in[i])
      return 0;
  if (canon[31] != (in[31] & 0x7f))
    return 0;
  p->z = fe_one;
  fe_sq(&num, &p->y);
  fe_mul(&den, &num, &curve_d);
  fe_sub(&num, &num, &p->z);
  fe_add(&den, &p->z, &den);
  fe_sq(&den2, &den);
  fe_sq(&den4, &den2);
  fe_mul(&den6, &den4, &den2);
  fe_mul(&t, &den6, &num);
  fe_mul(&t, &t, &den);
  fe_pow2523(&t, &t);
  fe_mul(&t, &t, &num);
  fe_mul(&t, &t, &den);
  fe_mul(&t, &t, &den);
  fe_mul(&p->x, &t, &den);
  fe_sq(&chk, &p->x);
  fe_mul(&chk, &chk, &den);
  if (!fe_equal(&chk, &num))
    fe_mul(&p->x, &p->x, &sqrt_m1);
  fe_sq(&chk, &p->x);
  fe_mul(&chk, &chk, &den);
  if (!fe_equal(&chk, &num))
    return 0;
  if (sign && fe_equal(&p->x, &fe_zero))
    return 0;
  if (fe_parity(&p->x) != sign)
    fe_sub(&p->x, &fe_zero, &p->x);
  fe_mul(&p->t, &p->x, &p->y);
  return 1;
}

int ed25519_constants_ok(void) {
  static const Fe c121665 = {{0xdb41, 1}};
  static const Fe c121666 = {{0xdb42, 1}};
  static const Fe four = {{4}};
  static const Fe five = {{5}};
  Fe t, u, x2, y2;
  int ok;
  fe_mul(&t, &curve_d, &c121666);
  fe_add(&t, &t, &c121665);
  ok = fe_equal(&t, &fe_zero);
  fe_add(&t, &curve_d, &curve_d);
  ok &= fe_equal(&t, &curve_d2);
  fe_sq(&t, &sqrt_m1);
  fe_add(&t, &t, &fe_one);
  ok &= fe_equal(&t, &fe_zero);
  fe_mul(&t, &base_y, &five);
  ok &= fe_equal(&t, &four);
  ok &= fe_parity(&base_x) == 0;
  fe_sq(&x2, &base_x);
  fe_sq(&y2, &base_y);
  fe_sub(&t, &y2, &x2);
  fe_mul(&u, &x2, &y2);
  fe_mul(&u, &u, &curve_d);
  fe_add(&u, &u, &fe_one);
  ok &= fe_equal(&t, &u);
  return ok;
}

uint64_t ed25519_constant(unsigned which, unsigned i) {
  static const Fe *const table[ED25519_CONSTS] = {&curve_d, &curve_d2, &sqrt_m1, &base_x, &base_y};
  return which < ED25519_CONSTS && i < LIMBS ? (uint64_t)table[which]->limb[i] : 0;
}

uint64_t ed25519_order_byte(unsigned k) {
  return k < 32u ? (uint64_t)order[k] : 0;
}

/* X mod L, X = sum x[i] 256^i (TweetNaCl modL): limbs 63 down to 32 fold
 * with 2^256 = -16 (L - 2^252) mod L, then the top 4 bits of limb 31, then
 * one conditional subtraction of L. */
static void reduce_limbs(uint8_t out[32], int64_t x[64]) {
  int64_t carry;
  int i, j;
  for (i = 63; i >= 32; i--) {
    carry = 0;
    for (j = i - 32; j < i - 12; j++) {
      x[j] += carry - 16 * x[i] * order[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * order[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; j++)
    x[j] -= carry * order[j];
  for (i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8;
    out[i] = (uint8_t)(x[i] & 255);
  }
}

/* Byte K of L - MINUS (MINUS below 0xed only changes byte 0). */
static unsigned order_byte(int k, unsigned minus) {
  return k == 0 ? (unsigned)order[0] - minus : (unsigned)order[k];
}

int ed25519_scalar_canonical(const uint8_t s[ED25519_SCALAR_BYTES]) {
  int i;
  for (i = 31; i >= 0; i--)
    if (s[i] != order[i])
      return s[i] < order[i];
  return 0;
}

void ed25519_scalar_reduce(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t wide[64]) {
  int64_t x[64];
  int i;
  for (i = 0; i < 64; i++)
    x[i] = wide[i];
  reduce_limbs(out, x);
}

void ed25519_scalar_from_u32(uint8_t out[ED25519_SCALAR_BYTES], uint32_t v) {
  int i;
  for (i = 0; i < 32; i++)
    out[i] = i < 4 ? (uint8_t)(v >> (8 * i)) : 0;
}

void ed25519_scalar_add(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES],
                        const uint8_t b[ED25519_SCALAR_BYTES]) {
  int64_t x[64] = {0};
  int i;
  for (i = 0; i < 32; i++)
    x[i] = (int64_t)a[i] + b[i];
  reduce_limbs(out, x);
}

void ed25519_scalar_mul(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES],
                        const uint8_t b[ED25519_SCALAR_BYTES]) {
  int64_t x[64] = {0};
  int i, j;
  for (i = 0; i < 32; i++)
    for (j = 0; j < 32; j++)
      x[i + j] += (int64_t)a[i] * b[j];
  reduce_limbs(out, x);
}

/* A (L - 1) = -A mod L. */
void ed25519_scalar_negate(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES]) {
  uint8_t minus_one[32];
  int i;
  for (i = 0; i < 32; i++)
    minus_one[i] = (uint8_t)order_byte(i, 1);
  ed25519_scalar_mul(out, a, minus_one);
}

/* Square and multiply over the bits of L - 2, from bit 252 down. */
void ed25519_scalar_invert(uint8_t out[ED25519_SCALAR_BYTES], const uint8_t a[ED25519_SCALAR_BYTES]) {
  uint8_t acc[32] = {1};
  uint8_t base[32];
  int i;
  for (i = 0; i < 32; i++)
    base[i] = a[i];
  for (i = 252; i >= 0; i--) {
    ed25519_scalar_mul(acc, acc, acc);
    if ((order_byte(i / 8, 2) >> (i % 8)) & 1u)
      ed25519_scalar_mul(acc, acc, base);
  }
  for (i = 0; i < 32; i++)
    out[i] = acc[i];
}

void ed25519_base_mul(uint8_t out[ED25519_KEY_BYTES], const uint8_t s[ED25519_SCALAR_BYTES]) {
  Point b, p;
  base_point(&b);
  point_mul(&p, &b, s);
  point_encode(out, &p);
}

int ed25519_verify(const uint8_t pk[ED25519_KEY_BYTES], const uint8_t *msg, size_t n,
                   const uint8_t sig[ED25519_SIG_BYTES]) {
  Point a, r, b, lhs, rhs;
  uint8_t h[SHA512_BYTES], k[32], left[32], right[32];
  Sha512 s;
  int i;
  if (!ed25519_scalar_canonical(sig + 32) || !point_decode(&a, pk) || point_small_order(&a) ||
      !point_decode(&r, sig))
    return 0;
  sha512_init(&s);
  sha512_update(&s, sig, 32);
  sha512_update(&s, pk, 32);
  sha512_update(&s, msg, n);
  sha512_final(&s, h);
  ed25519_scalar_reduce(k, h);
  base_point(&b);
  point_mul(&lhs, &b, sig + 32);
  point_mul(&rhs, &a, k);
  point_add(&rhs, &r, &rhs);
  for (i = 0; i < 3; i++) {
    point_add(&lhs, &lhs, &lhs);
    point_add(&rhs, &rhs, &rhs);
  }
  point_encode(left, &lhs);
  point_encode(right, &rhs);
  return bytes_equal(left, right, 32);
}
