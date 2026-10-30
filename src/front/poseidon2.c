/* Poseidon2 over BN254 Fr, width 3, S-box x^5: poseidon2_instance_bn256 of
 * HorizenLabs/poseidon2 rev 055bde3f4782731ba5f5ce5888a440a94327eaf3
 * (plain_implementations/src/poseidon2/). The interface values are canonical
 * elements below r; the arithmetic works in Montgomery form, R = 2^256. */
#include "front/poseidon2.h"

#define LIMB_MASK 0xffffffffu

enum { T = POSEIDON2_T, N = FR_LIMBS, RATE = 2 };

/* r, low limb first. */
static const Fr modulus = {{0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
                            0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u}};

/* R^2 mod r = 2^512 mod r = 0x0216d0b17f4e44a5...1bb8e645ae216da7. */
static const Fr r_squared = {{0xae216da7u, 0x1bb8e645u, 0xe35c59e3u, 0x53fe3ab1u,
                              0x53bb8085u, 0x8c49833du, 0x7f4e44a5u, 0x0216d0b1u}};

static const Fr one = {{1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}};

/* -r^-1 mod 2^32: r = 1 - 2^28 mod 2^32, so r^-1 = 1 + 2^28 mod 2^32. */
static const uint64_t r_inverse_negated = 0xefffffffu;

/* The round constants RC3 of poseidon2_instance_bn256.rs, by row of RC3. */

/* RC3 rows 0 to 3: the first 4 external rounds. */
static const char *const initial_rc[POSEIDON2_HALF_F][T] = {
  {"0x1d066a255517b7fd8bddd3a93f7804ef7f8fcde48bb4c37a59a09a1a97052816",
   "0x29daefb55f6f2dc6ac3f089cebcc6120b7c6fef31367b68eb7238547d32c1610",
   "0x1f2cb1624a78ee001ecbd88ad959d7012572d76f08ec5c4f9e8b7ad7b0b4e1d1"},
  {"0x0aad2e79f15735f2bd77c0ed3d14aa27b11f092a53bbc6e1db0672ded84f31e5",
   "0x2252624f8617738cd6f661dd4094375f37028a98f1dece66091ccf1595b43f28",
   "0x1a24913a928b38485a65a84a291da1ff91c20626524b2b87d49f4f2c9018d735"},
  {"0x22fc468f1759b74d7bfc427b5f11ebb10a41515ddff497b14fd6dae1508fc47a",
   "0x1059ca787f1f89ed9cd026e9c9ca107ae61956ff0b4121d5efd65515617f6e4d",
   "0x02be9473358461d8f61f3536d877de982123011f0bf6f155a45cbbfae8b981ce"},
  {"0x0ec96c8e32962d462778a749c82ed623aba9b669ac5b8736a1ff3a441a5084a4",
   "0x292f906e073677405442d9553c45fa3f5a47a7cdb8c99f9648fb2e4d814df57e",
   "0x274982444157b86726c11b9a0f5e39a5cc611160a394ea460c63f0b2ffe5657e"}
};

/* RC3 rows 4 to 59, element 0: the 56 internal rounds (elements 1 and 2 of
 * these rows are 0). */
static const char *const internal_rc[POSEIDON2_ROUNDS_P] = {
  "0x1a1d063e54b1e764b63e1855bff015b8cedd192f47308731499573f23597d4b5",
  "0x26abc66f3fdf8e68839d10956259063708235dccc1aa3793b91b002c5b257c37",
  "0x0c7c64a9d887385381a578cfed5aed370754427aabca92a70b3c2b12ff4d7be8",
  "0x1cf5998769e9fab79e17f0b6d08b2d1eba2ebac30dc386b0edd383831354b495",
  "0x0f5e3a8566be31b7564ca60461e9e08b19828764a9669bc17aba0b97e66b0109",
  "0x18df6a9d19ea90d895e60e4db0794a01f359a53a180b7d4b42bf3d7a531c976e",
  "0x04f7bf2c5c0538ac6e4b782c3c6e601ad0ea1d3a3b9d25ef4e324055fa3123dc",
  "0x29c76ce22255206e3c40058523748531e770c0584aa2328ce55d54628b89ebe6",
  "0x198d425a45b78e85c053659ab4347f5d65b1b8e9c6108dbe00e0e945dbc5ff15",
  "0x25ee27ab6296cd5e6af3cc79c598a1daa7ff7f6878b3c49d49d3a9a90c3fdf74",
  "0x138ea8e0af41a1e024561001c0b6eb1505845d7d0c55b1b2c0f88687a96d1381",
  "0x306197fb3fab671ef6e7c2cba2eefd0e42851b5b9811f2ca4013370a01d95687",
  "0x1a0c7d52dc32a4432b66f0b4894d4f1a21db7565e5b4250486419eaf00e8f620",
  "0x2b46b418de80915f3ff86a8e5c8bdfccebfbe5f55163cd6caa52997da2c54a9f",
  "0x12d3e0dc0085873701f8b777b9673af9613a1af5db48e05bfb46e312b5829f64",
  "0x263390cf74dc3a8870f5002ed21d089ffb2bf768230f648dba338a5cb19b3a1f",
  "0x0a14f33a5fe668a60ac884b4ca607ad0f8abb5af40f96f1d7d543db52b003dcd",
  "0x28ead9c586513eab1a5e86509d68b2da27be3a4f01171a1dd847df829bc683b9",
  "0x1c6ab1c328c3c6430972031f1bdb2ac9888f0ea1abe71cffea16cda6e1a7416c",
  "0x1fc7e71bc0b819792b2500239f7f8de04f6decd608cb98a932346015c5b42c94",
  "0x03e107eb3a42b2ece380e0d860298f17c0c1e197c952650ee6dd85b93a0ddaa8",
  "0x2d354a251f381a4669c0d52bf88b772c46452ca57c08697f454505f6941d78cd",
  "0x094af88ab05d94baf687ef14bc566d1c522551d61606eda3d14b4606826f794b",
  "0x19705b783bf3d2dc19bcaeabf02f8ca5e1ab5b6f2e3195a9d52b2d249d1396f7",
  "0x09bf4acc3a8bce3f1fcc33fee54fc5b28723b16b7d740a3e60cef6852271200e",
  "0x1803f8200db6013c50f83c0c8fab62843413732f301f7058543a073f3f3b5e4e",
  "0x0f80afb5046244de30595b160b8d1f38bf6fb02d4454c0add41f7fef2faf3e5c",
  "0x126ee1f8504f15c3d77f0088c1cfc964abcfcf643f4a6fea7dc3f98219529d78",
  "0x23c203d10cfcc60f69bfb3d919552ca10ffb4ee63175ddf8ef86f991d7d0a591",
  "0x2a2ae15d8b143709ec0d09705fa3a6303dec1ee4eec2cf747c5a339f7744fb94",
  "0x07b60dee586ed6ef47e5c381ab6343ecc3d3b3006cb461bbb6b5d89081970b2b",
  "0x27316b559be3edfd885d95c494c1ae3d8a98a320baa7d152132cfe583c9311bd",
  "0x1d5c49ba157c32b8d8937cb2d3f84311ef834cc2a743ed662f5f9af0c0342e76",
  "0x2f8b124e78163b2f332774e0b850b5ec09c01bf6979938f67c24bd5940968488",
  "0x1e6843a5457416b6dc5b7aa09a9ce21b1d4cba6554e51d84665f75260113b3d5",
  "0x11cdf00a35f650c55fca25c9929c8ad9a68daf9ac6a189ab1f5bc79f21641d4b",
  "0x21632de3d3bbc5e42ef36e588158d6d4608b2815c77355b7e82b5b9b7eb560bc",
  "0x0de625758452efbd97b27025fbd245e0255ae48ef2a329e449d7b5c51c18498a",
  "0x2ad253c053e75213e2febfd4d976cc01dd9e1e1c6f0fb6b09b09546ba0838098",
  "0x1d6b169ed63872dc6ec7681ec39b3be93dd49cdd13c813b7d35702e38d60b077",
  "0x1660b740a143664bb9127c4941b67fed0be3ea70a24d5568c3a54e706cfef7fe",
  "0x0065a92d1de81f34114f4ca2deef76e0ceacdddb12cf879096a29f10376ccbfe",
  "0x1f11f065202535987367f823da7d672c353ebe2ccbc4869bcf30d50a5871040d",
  "0x26596f5c5dd5a5d1b437ce7b14a2c3dd3bd1d1a39b6759ba110852d17df0693e",
  "0x16f49bc727e45a2f7bf3056efcf8b6d38539c4163a5f1e706743db15af91860f",
  "0x1abe1deb45b3e3119954175efb331bf4568feaf7ea8b3dc5e1a4e7438dd39e5f",
  "0x0e426ccab66984d1d8993a74ca548b779f5db92aaec5f102020d34aea15fba59",
  "0x0e7c30c2e2e8957f4933bd1942053f1f0071684b902d534fa841924303f6a6c6",
  "0x0812a017ca92cf0a1622708fc7edff1d6166ded6e3528ead4c76e1f31d3fc69d",
  "0x21a5ade3df2bc1b5bba949d1db96040068afe5026edd7a9c2e276b47cf010d54",
  "0x01f3035463816c84ad711bf1a058c6c6bd101945f50e5afe72b1a5233f8749ce",
  "0x0b115572f038c0e2028c2aafc2d06a5e8bf2f9398dbd0fdf4dcaa82b0f0c1c8b",
  "0x1c38ec0b99b62fd4f0ef255543f50d2e27fc24db42bc910a3460613b6ef59e2f",
  "0x1c89c6d9666272e8425c3ff1f4ac737b2f5d314606a297d4b1d0b254d880c53e",
  "0x03326e643580356bf6d44008ae4c042a21ad4880097a5eb38b71e2311bb88f8f",
  "0x268076b0054fb73f67cee9ea0e51e3ad50f27a6434b5dceb5bdde2299910a4c9"
};

/* RC3 rows 60 to 63: the last 4 external rounds. */
static const char *const terminal_rc[POSEIDON2_HALF_F][T] = {
  {"0x1acd63c67fbc9ab1626ed93491bda32e5da18ea9d8e4f10178d04aa6f8747ad0",
   "0x19f8a5d670e8ab66c4e3144be58ef6901bf93375e2323ec3ca8c86cd2a28b5a5",
   "0x1c0dc443519ad7a86efa40d2df10a011068193ea51f6c92ae1cfbb5f7b9b6893"},
  {"0x14b39e7aa4068dbe50fe7190e421dc19fbeab33cb4f6a2c4180e4c3224987d3d",
   "0x1d449b71bd826ec58f28c63ea6c561b7b820fc519f01f021afb1e35e28b0795e",
   "0x1ea2c9a89baaddbb60fa97fe60fe9d8e89de141689d1252276524dc0a9e987fc"},
  {"0x0478d66d43535a8cb57e9c1c3d6a2bd7591f9a46a0e9c058134d5cefdb3c7ff1",
   "0x19272db71eece6a6f608f3b2717f9cd2662e26ad86c400b21cde5e4a7b00bebe",
   "0x14226537335cab33c749c746f09208abb2dd1bd66a87ef75039be846af134166"},
  {"0x01fd6af15956294f9dfe38c0d976a088b21c21e4a1c2e823f912f44961f9a9ce",
   "0x18e5abedd626ec307bca190b8b2cab1aaee2e62ed229ba5a5ad8518d4e5f2a57",
   "0x0fc1bbceba0590f5abbdffa6d3b35e3297c021a3a409926d0e2d54dc1c84fda6"}
};

/* a >= b. */
static int at_least(const uint64_t a[N], const uint64_t b[N]) {
  for (unsigned i = N; i-- > 0;)
    if (a[i] != b[i]) return a[i] > b[i];
  return 1;
}

/* a - b mod 2^256 in place. Each limb is below 2^32, so a negative limb
 * difference wraps to a value with bit 63 set. */
static void subtract(uint64_t a[N], const uint64_t b[N]) {
  uint64_t borrow = 0;
  for (unsigned i = 0; i < N; i++) {
    uint64_t d = a[i] - b[i] - borrow;
    borrow = d >> 63;
    a[i] = d & LIMB_MASK;
  }
}

/* a + b mod r. Both are below r < 2^254, so the sum has no carry out of the
 * top limb. The same sum serves the Montgomery form. */
static Fr add(Fr a, Fr b) {
  Fr s;
  uint64_t carry = 0;
  for (unsigned i = 0; i < N; i++) {
    uint64_t t = a.limb[i] + b.limb[i] + carry;
    s.limb[i] = t & LIMB_MASK;
    carry = t >> 32;
  }
  if (carry || at_least(s.limb, modulus.limb)) subtract(s.limb, modulus.limb);
  return s;
}

/* The Montgomery product a b R^-1 mod r (CIOS over 32-bit limbs). Each step
 * x + y z + c has x, y, z and c below 2^32, so it is at most 2^64 - 1. */
static Fr mont_mul(Fr a, Fr b) {
  uint64_t t[N + 2] = {0};
  Fr out;
  for (unsigned i = 0; i < N; i++) {
    uint64_t carry = 0;
    uint64_t s;
    uint64_t m;
    for (unsigned j = 0; j < N; j++) {
      s = t[j] + a.limb[j] * b.limb[i] + carry;
      t[j] = s & LIMB_MASK;
      carry = s >> 32;
    }
    s = t[N] + carry;
    t[N] = s & LIMB_MASK;
    t[N + 1] = s >> 32;
    m = (t[0] * r_inverse_negated) & LIMB_MASK;
    carry = (t[0] + m * modulus.limb[0]) >> 32;
    for (unsigned j = 1; j < N; j++) {
      s = t[j] + m * modulus.limb[j] + carry;
      t[j - 1] = s & LIMB_MASK;
      carry = s >> 32;
    }
    s = t[N] + carry;
    t[N - 1] = s & LIMB_MASK;
    t[N] = t[N + 1] + (s >> 32);
  }
  for (unsigned j = 0; j < N; j++)
    out.limb[j] = t[j];
  if (t[N] || at_least(out.limb, modulus.limb)) subtract(out.limb, modulus.limb);
  return out;
}

static Fr to_mont(Fr a) {
  return mont_mul(a, r_squared);
}

static Fr from_mont(Fr a) {
  return mont_mul(a, one);
}

/* The S-box x^5 (d = 5). */
static Fr sbox(Fr x) {
  Fr x2 = mont_mul(x, x);
  return mont_mul(x, mont_mul(x2, x2));
}

/* The external matrix circ(2, 1, 1) of t = 3 (matmul_external): each element
 * adds the sum of the state. */
static void external_linear(Fr s[T]) {
  Fr sum = add(add(s[0], s[1]), s[2]);
  for (unsigned i = 0; i < T; i++)
    s[i] = add(s[i], sum);
}

/* The internal matrix [[2, 1, 1], [1, 2, 1], [1, 1, 3]] (matmul_internal with
 * MAT_DIAG3_M_1 = [1, 1, 2]): s_i = d_i s_i + sum. */
static void internal_linear(Fr s[T]) {
  Fr sum = add(add(s[0], s[1]), s[2]);
  s[0] = add(s[0], sum);
  s[1] = add(s[1], sum);
  s[2] = add(add(s[2], s[2]), sum);
}

static int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int fr_from_hex(Fr *out, const char *hex) {
  Fr v = {{0}};
  if (hex[0] != '0' || hex[1] != 'x') return 0;
  for (unsigned k = 0; k < 64; k++) {
    int d = hex_digit(hex[2 + k]);
    unsigned bit = 4 * (63 - k);
    if (d < 0) return 0;
    v.limb[bit / 32] |= (uint64_t)d << (bit % 32);
  }
  if (hex[66] != '\0' || at_least(v.limb, modulus.limb)) return 0;
  *out = v;
  return 1;
}

int fr_from_words(Fr *out, const uint64_t words[FR_WORDS]) {
  Fr v;
  for (unsigned k = 0; k < FR_WORDS; k++) {
    v.limb[2 * k] = words[k] & LIMB_MASK;
    v.limb[2 * k + 1] = words[k] >> 32;
  }
  if (at_least(v.limb, modulus.limb)) return 0;
  *out = v;
  return 1;
}

void fr_to_words(const Fr *a, uint64_t words[FR_WORDS]) {
  for (unsigned k = 0; k < FR_WORDS; k++)
    words[k] = a->limb[2 * k] | a->limb[2 * k + 1] << 32;
}

int fr_equal(const Fr *a, const Fr *b) {
  for (unsigned i = 0; i < N; i++)
    if (a->limb[i] != b->limb[i]) return 0;
  return 1;
}

int poseidon2_constants_ok(void) {
  Fr c;
  int ok = 1;
  for (unsigned r = 0; r < POSEIDON2_HALF_F; r++)
    for (unsigned i = 0; i < T; i++)
      ok &= fr_from_hex(&c, initial_rc[r][i]) & fr_from_hex(&c, terminal_rc[r][i]);
  for (unsigned r = 0; r < POSEIDON2_ROUNDS_P; r++)
    ok &= fr_from_hex(&c, internal_rc[r]);
  return ok;
}

/* A round constant in Montgomery form (0 if it does not read; the test
 * checks poseidon2_constants_ok). */
static Fr constant(const char *hex) {
  Fr c = {{0}};
  fr_from_hex(&c, hex);
  return to_mont(c);
}

/* Each external round adds the constants and applies the S-box to each
 * element, then the external matrix. */
static void external_rounds(Fr s[T], const char *const rc[POSEIDON2_HALF_F][T]) {
  for (unsigned r = 0; r < POSEIDON2_HALF_F; r++) {
    for (unsigned i = 0; i < T; i++)
      s[i] = sbox(add(s[i], constant(rc[r][i])));
    external_linear(s);
  }
}

/* Poseidon2::permutation: the initial external matrix, 4 external rounds, 56
 * internal rounds (the constant and the S-box on element 0 only, then the
 * internal matrix), then 4 external rounds. */
void poseidon2_permute(Fr state[POSEIDON2_T]) {
  Fr s[T];
  for (unsigned i = 0; i < T; i++)
    s[i] = to_mont(state[i]);
  external_linear(s);
  external_rounds(s, initial_rc);
  for (unsigned r = 0; r < POSEIDON2_ROUNDS_P; r++) {
    s[0] = sbox(add(s[0], constant(internal_rc[r])));
    internal_linear(s);
  }
  external_rounds(s, terminal_rc);
  for (unsigned i = 0; i < T; i++)
    state[i] = from_mont(s[i]);
}

/* One stream word as an element: it is below 2^64, so below r. */
static Fr word(uint64_t w) {
  Fr v = {{0}};
  v.limb[0] = w & LIMB_MASK;
  v.limb[1] = w >> 32;
  return v;
}

/* Elements 0 and 1 are the rate and element 2 is the capacity, which starts
 * at tag * 2^64 + n. Each pair of words adds into the rate, then the state
 * permutes. The words pad with zeros to an even count of at least 2, so each
 * hash permutes at least once (the empty stream is one zero block). */
void poseidon2_hash(uint64_t tag, const uint64_t *words, size_t n, Fr *digest) {
  Fr state[T];
  size_t blocks = n == 0 ? 1 : n / RATE + n % RATE;
  state[0] = word(0);
  state[1] = word(0);
  state[2] = word((uint64_t)n);
  state[2].limb[2] = tag & LIMB_MASK;
  state[2].limb[3] = tag >> 32;
  for (size_t b = 0; b < blocks; b++) {
    for (unsigned i = 0; i < RATE; i++)
      if (RATE * b + i < n) state[i] = add(state[i], word(words[RATE * b + i]));
    poseidon2_permute(state);
  }
  *digest = state[0];
}

Fr fr_modulus(void) {
  return modulus;
}

Fr fr_r_squared(void) {
  return r_squared;
}

uint64_t fr_n_prime(void) {
  return r_inverse_negated;
}

Fr poseidon2_round_constant(unsigned k) {
  unsigned external = POSEIDON2_HALF_F * T;
  unsigned terminal = k - external - POSEIDON2_ROUNDS_P;
  Fr zero = {{0}};
  if (k < external) return constant(initial_rc[k / T][k % T]);
  if (k < external + POSEIDON2_ROUNDS_P) return constant(internal_rc[k - external]);
  return k < POSEIDON2_CONSTANTS ? constant(terminal_rc[terminal / T][terminal % T]) : zero;
}
