/* Threshold decryption of a squash LWE (S6 U3, docs/PLAN.md 11 Q-S6-14 (a)).
 * Each party holds Shamir shares (front/tshare.h) of the 4096 bits of the
 * squash LWE key, in the sample extract order: s[0][0 to 2047], then
 * s[1][0 to 2047]. For each decryption, each party in the set S also deals
 * the shares of a flood noise e, uniform in [-2^106, 2^106). The partial of
 * party i is <a, share_i> plus its shares of the noise of the dealers. The
 * combine gives <a, s> + E at 0, with E the sum of the noise of the dealers,
 * and checks that the partials are on one polynomial of degree t. With the
 * U2b noise bound B = 2^66, one honest dealer gives a statistical distance of
 * B / 2^107 = 2^-41 or less for each decryption. */
#ifndef LANG_TDEC_H
#define LANG_TDEC_H
#include "front/squash.h"
#include "front/tshare.h"

enum {
  TDEC_FLOOD_LOG = 106 /* e is in [-2^106, 2^106) */
};

/* The sum of mask[j] share[j] over F_p (j = 0 to 4095). Each mask word is
 * a value in [0, 2^128). */
TshareFe tdec_mask_product(const TshareFe share[SQUASH_BIG_N], const Squash128 mask[SQUASH_BIG_N]);

/* One flood noise e from D, lifted to F_p (p - |e| for e < 0), then shared:
 * party i (1 to 5) gets noise[i - 1]. */
void tdec_flood(TshareFe noise[TSHARE_PARTIES], TfheDrbg *d);

/* The partial of PARTY (1 to 5): tdec_mask_product of its key share and MASK,
 * plus noise[j 5 + PARTY - 1] for each dealer j (0 to DEALERS - 1). */
TshareFe tdec_partial(const TshareFe share[SQUASH_BIG_N], const Squash128 mask[SQUASH_BIG_N], const TshareFe *noise,
                      unsigned dealers, unsigned party);

/* Combines the M partials (partial[i] is from party subset[i]). Writes the
 * phase BODY - (<a, s> + E) mod 2^128 and returns 1. Returns 0 and writes
 * no phase when M is t or less, when the subset is bad, or when the partials
 * are not on one polynomial of degree t. */
int tdec_combine(Squash128 *phase, Squash128 body, const TshareFe *partial, const unsigned *subset, unsigned m);

/* The nearest v (0 to 31) to PHASE: Delta_128 = 2^123. */
unsigned tdec_decode(Squash128 phase);
#endif
