/* The MPC key generation base for S6b (docs/PLAN.md 11 Q-S6-10, Q-S6-16 (a);
 * W/S6-NOTES.md "## S6b plan", steps 1 to 5). Semi-honest parties P1 to P5 at
 * the points 1 to 5 and Shamir sharing over the tshare field F_p. One C
 * process holds the 5 parties: party j uses its own DRBG party[j - 1]. The
 * coin toss gives the joint seed of the public masks. A dealing has degree t
 * (for a linear opening) or 2t (for an opening with a product of two
 * shares). The zero sharing masks the opening of a product. The shared random
 * bits give the key bits. The party noise is TUniform(b - 1) (Q-S6-10). */
#ifndef LANG_TKEYGEN_H
#define LANG_TKEYGEN_H
#include <stddef.h>
#include <stdint.h>

#include "front/sha512.h"
#include "front/squash.h"
#include "front/tfhe.h"
#include "front/tshare.h"

enum {
  TKEYGEN_SEED_BYTES = 64 /* the seed of one party in the coin toss */
};

/* The degree of a dealing: t (TSHARE_THRESHOLD) or 2t. */
typedef enum TkeygenDegree { TKEYGEN_DEGREE_T, TKEYGEN_DEGREE_2T } TkeygenDegree;

/* The coin toss: the commitment of each party, then its seed (the reveal). */
typedef struct TkeygenToss {
  uint8_t commit[TSHARE_PARTIES][SHA512_BYTES];
  uint8_t seed[TSHARE_PARTIES][TKEYGEN_SEED_BYTES];
} TkeygenToss;

/* One try of a shared random bit (the values of the 5 parties). */
typedef struct TkeygenBit {
  TshareFe r[TSHARE_PARTIES];      /* r_i: a degree-t sharing of a uniform r */
  TshareFe opened[TSHARE_PARTIES]; /* r_i^2 + z_i, z a degree-2t zero sharing */
  TshareFe square;                 /* v = r^2, from the 5 opened shares */
  TshareFe bit[TSHARE_PARTIES];    /* b_i = (r_i c^-1 + 1) 2^-1, with c^2 = v */
} TkeygenBit;

/* The degree as a number: 2 or 4. */
unsigned tkeygen_degree(TkeygenDegree degree);

/* Party PARTY (1 to 5) draws its seed from D. It writes the seed and the
 * commitment SHA-512(party || seed), with the party number as 4 bytes, low
 * byte first. Returns 1, or 0 with no output for a bad party number. */
int tkeygen_toss_draw(TkeygenToss *toss, unsigned party, TfheDrbg *d);

/* 1 when each seed agrees with its commitment, else 0. */
int tkeygen_toss_check(const TkeygenToss *toss);

/* The joint seed SHA-512(seed_1 || ... || seed_5), and MASKS: the DRBG on its
 * first TFHE_SEED_BYTES bytes (all the public masks come from it). Returns 1,
 * or 0 with no output when a seed does not agree with its commitment. */
int tkeygen_toss_joint(uint8_t joint[SHA512_BYTES], TfheDrbg *masks, const TkeygenToss *toss);

/* Deals COUNT secrets with a polynomial of degree DEGREE, coefficients from D:
 * party i (1 to 5) gets shares[(i - 1) count + j] = f_j(i). For degree t, the
 * shares and the DRBG order are those of tshare_share. */
void tkeygen_deal(TshareFe *shares, const TshareFe *secret, size_t count, TkeygenDegree degree, TfheDrbg *d);

/* OUT[k] = OUT[k] + ONE[k] for k below 5 COUNT: each party adds the shares
 * that it gets from one dealer. */
void tkeygen_add(TshareFe *out, const TshareFe *one, size_t count);

/* The zero sharing: party j deals COUNT zeros with degree 2t from
 * party[j - 1], and ZERO (the layout of tshare_share) is the sum of the 5
 * dealings. */
void tkeygen_zero(TshareFe *zero, size_t count, TfheDrbg party[TSHARE_PARTIES]);

/* One try of a shared random bit. Party j deals a uniform r_j with degree t,
 * so r_i is a sharing of r = the sum of the r_j. The 5 parties open
 * v = r^2 from r_i^2 + z_i (z: tkeygen_zero). Without z, the 5 opened shares
 * give r up to its sign, and the sign is the bit. Then c = the square root of
 * v and b_i = (r_i c^-1 + 1) 2^-1: r / c is 1 or -1, so b is 1 or 0. Returns
 * 1, or 0 when v is 0 (the caller draws again). */
int tkeygen_bit_try(TkeygenBit *b, TfheDrbg party[TSHARE_PARTIES]);

/* COUNT shared random bits (tkeygen_bit_try again while it returns 0):
 * bits[(i - 1) count + j] is the share of party i of bit j (degree t). */
void tkeygen_bits(TshareFe *bits, size_t count, TfheDrbg party[TSHARE_PARTIES]);

/* E (a torus word: the integer e in [-2^63, 2^63)) in F_p: p - |e| for
 * e < 0. */
TshareFe tkeygen_lift(uint64_t e);

/* The party noise of one dealer (Q-S6-10): COUNT values TUniform(SET_LOG - 1)
 * from D (tfhe_tuniform: in [-2^(b - 1), 2^(b - 1)] for the set noise
 * b = SET_LOG), as torus words in E (the dealer keeps them). Each value is
 * lifted into F_p and dealt with DEGREE; SHARES has the layout of
 * tshare_share. */
void tkeygen_noise(TshareFe *shares, uint64_t *e, size_t count, unsigned set_log, TkeygenDegree degree,
                   TfheDrbg *d);

/* The openings (W/S6-NOTES.md "## S6b plan", steps 6 to 8). The public mask
 * of a row comes from the masks DRBG of the coin toss. The share of party i
 * of the body is <a, s_i> + m_i + the noise of the 5 dealers. The 5 parties
 * open the body (open_all, the Lagrange at 0), then the centered lift gives
 * the torus word. A product row (step 7) has m_i = -g s_k,i S_i: a local
 * product of 2 shares (degree 2t), so its noise has degree 2t too. */

/* The key shares of the 5 parties (degree t, [party][bit]). The key bits stay
 * as shares: only a test makes a key from them. squash[i] is the squash key
 * share of party i + 1, s[0] then s[1] (the tdec_partial form). */
typedef struct TkeygenShares {
  TshareFe lwe[TSHARE_PARTIES][TFHE_LWE_N];
  TshareFe glwe[TSHARE_PARTIES][TFHE_POLY_N];
  TshareFe pke[TSHARE_PARTIES][TFHE_BIG_N];
  TshareFe squash[TSHARE_PARTIES][SQUASH_BIG_N];
} TkeygenShares;

/* The key of a GLWE opening: the GLWE key (BSK), the reversed PKE key (pk)
 * or the 2 squash key polynomials (squash BSK). */
typedef enum TkeygenKey { TKEYGEN_KEY_GLWE, TKEYGEN_KEY_PKE, TKEYGEN_KEY_SQUASH } TkeygenKey;

/* The work memory of the GLWE openings (about 1.4 MB: put it on the heap). */
typedef struct TkeygenWork {
  TshareNtt ntt;
  TshareFe key[TSHARE_PARTIES][SQUASH_GLWE_K][TSHARE_N]; /* the key shares in the NTT form */
  unsigned key_count;                                    /* 1 (TFHE) or 2 (squash) */
  TshareFe mask[SQUASH_GLWE_K][TSHARE_N];                /* the mask of one row */
  TshareFe share[TSHARE_PARTIES][TSHARE_N];              /* the body shares of one row */
  TshareFe deal[TSHARE_PARTIES * TSHARE_N];              /* the noise of one dealer */
  TshareFe acc[TSHARE_N];
  TshareFe open[TSHARE_N];                   /* the opened body of one row */
  uint64_t e[TSHARE_N];                      /* the noise words of one dealer */
  uint64_t esum[SQUASH_GGSW_ROWS][TSHARE_N]; /* the noise sum of each row of the last GGSW */
} TkeygenWork;

/* V as an integer in (-p/2, p/2) (the centered lift), mod 2^64. */
uint64_t tkeygen_word64(TshareFe v);

/* V as an integer in (-p/2, p/2), mod 2^128. */
Squash128 tkeygen_word128(TshareFe v);

/* The shared random bits of all the keys: lwe, glwe, pke, then squash. */
void tkeygen_shares(TkeygenShares *s, TfheDrbg party[TSHARE_PARTIES]);

/* Sets the NTT tables of W. */
void tkeygen_work_init(TkeygenWork *w);

/* Puts the shares of KEY into W in the NTT form (5 or 10 NTTs). */
void tkeygen_load(TkeygenWork *w, const TkeygenShares *s, TkeygenKey key);

/* One LWE opening: N mask words from MASKS into CT, then the body CT[N].
 * KEY[(i - 1) N + j] is the share of party i of key bit j and PLAIN[i - 1]
 * its plaintext share. The noise is TUniform(SET_LOG - 1) of each dealer
 * (degree t); *ESUM is the sum (a torus word). */
void tkeygen_lwe_row(uint64_t *ct, uint64_t *esum, const TshareFe *key, size_t n, const TshareFe plain[TSHARE_PARTIES],
                     unsigned set_log, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]);

/* The KSK form of tfhe.c: row (j 4 + l) is an LWE under the small key of
 * in_j 2^(64 - 4 (l + 1)). IN has the layout [party][TFHE_BIG_N]: the glwe
 * shares (the KSK) or the pke shares (the cast KSK). */
void tkeygen_ksk(uint64_t *ksk, const TshareFe *in, const TkeygenShares *s, TfheDrbg *masks,
                 TfheDrbg party[TSHARE_PARTIES]);

/* GGSW I of the BSK into CT (4 N words; W has TKEYGEN_KEY_GLWE). Row 0: the
 * public mask A, body A S + e - s_i g S (a product opening). Its phase is the
 * phase of row 0 of tfhe_keys_generate (that row puts s_i g on the mask).
 * Row 1: body A S + e + s_i g at coefficient 0. w->esum[row]: the noise sums. */
void tkeygen_bsk_ggsw(TkeygenWork *w, uint64_t *ct, size_t i, const TkeygenShares *s, TfheDrbg *masks,
                      TfheDrbg party[TSHARE_PARTIES]);

/* Row ROW (0 to K) of level LEVEL (1 to 3) of the squash GGSW of bit I into
 * CT (SQUASH_GLWE_WORDS; W has TKEYGEN_KEY_SQUASH). Row r < K: body
 * A S + e - s_i g_l S_r (a product opening); row K: body + s_i g_l at
 * coefficient 0. w->esum[(LEVEL - 1) (K + 1) + ROW]: the noise sum. */
void tkeygen_squash_row(TkeygenWork *w, Squash128 *ct, size_t i, unsigned level, unsigned row,
                        const TkeygenShares *s, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]);

/* pk_a from MASKS and pk_b = pk_a rev(key) + e (W has TKEYGEN_KEY_PKE).
 * w->esum[0]: the noise sum. */
void tkeygen_pk(TkeygenWork *w, TfhePke *p, TfheDrbg *masks, TfheDrbg party[TSHARE_PARTIES]);

/* The public key set from the shares S: the KSK, the BSK (bsk and
 * bsk_fourier, the tfhe_keys_generate form), pk, the cast KSK and the squash
 * BSK, the masks in this order from MASKS. Each key bit stays as shares: the
 * secret key fields of K and P are 0. Release with tfhe_keys_release,
 * tfhe_pke_release and squash_bsk_release. Returns 1, or 0 (no memory). */
int tkeygen_keys(TfheKeys *k, TfhePke *p, SquashBsk *b, const TkeygenShares *s, const TfheFft *f, TfheDrbg *masks,
                 TfheDrbg party[TSHARE_PARTIES]);
#endif
