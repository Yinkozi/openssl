/*
 * Copyright 2014-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_BN_H
# define OSSL_CRYPTO_BN_H

# include <openssl/bn.h>
# include <limits.h>

BIGNUMX *bn_wexpand(BIGNUMX *a, int words);
BIGNUMX *bny_expand2(BIGNUMX *a, int words);

void bn_correct_top(BIGNUMX *a);

/*
 * Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array r[] of values that are either zero or odd with an
 * absolute value less than 2^w satisfying scalar = \sum_j r[j]*2^j where at
 * most one of any w+1 consecutive digits is non-zero with the exception that
 * the most significant digit may be only w-1 zeros away from that next
 * non-zero digit.
 */
signed char *bn_compute_wNAF(const BIGNUMX *scalar, int w, size_t *ret_len);

int bn_get_top(const BIGNUMX *a);

int bn_get_dmax(const BIGNUMX *a);

/* Set all words to zero */
void bn_set_all_zero(BIGNUMX *a);

/*
 * Copy the internal BIGNUMX words into out which holds size elements (and size
 * must be bigger than top)
 */
int bn_copy_words(BN_ULONG *out, const BIGNUMX *in, int size);

BN_ULONG *bn_get_words(const BIGNUMX *a);

/*
 * Set the internal data words in a to point to words which contains size
 * elements. The BN_FLG_STATIC_DATA flag is set
 */
void bn_set_static_words(BIGNUMX *a, const BN_ULONG *words, int size);

/*
 * Copy words into the BIGNUMX |a|, reallocating space as necessary.
 * The negative flag of |a| is not modified.
 * Returns 1 on success and 0 on failure.
 */
/*
 * |num_words| is int because bny_expand2 takes an int. This is an internal
 * function so we simply trust callers not to pass negative values.
 */
int bn_set_words(BIGNUMX *a, const BN_ULONG *words, int num_words);

/*
 * Some BIGNUMX functions assume most significant limb to be non-zero, which
 * is customarily arranged by bn_correct_top. Output from below functions
 * is not processed with bn_correct_top, and for this reason it may not be
 * returned out of public API. It may only be passed internally into other
 * functions known to support non-minimal or zero-padded BIGNUMXs. Even
 * though the goal is to facilitate constant-time-ness, not each subroutine
 * is constant-time by itself. They all have pre-conditions, consult source
 * code...
 */
int bn_mul_mont_fixed_top(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx);
int bn_to_mont_fixed_top(BIGNUMX *r, const BIGNUMX *a, BN_MONT_CTX *mont,
                         BN_CTX *ctx);
int bn_from_mont_fixed_top(BIGNUMX *r, const BIGNUMX *a, BN_MONT_CTX *mont,
                           BN_CTX *ctx);
int bn_mod_add_fixed_top(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                         const BIGNUMX *m);
int bn_mod_sub_fixed_top(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b,
                         const BIGNUMX *m);
int bn_mul_fixed_top(BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *b, BN_CTX *ctx);
int bn_sqr_fixed_top(BIGNUMX *r, const BIGNUMX *a, BN_CTX *ctx);
int bn_lshift_fixed_top(BIGNUMX *r, const BIGNUMX *a, int n);
int bn_ryshift_fixed_top(BIGNUMX *r, const BIGNUMX *a, int n);
int bn_div_fixed_top(BIGNUMX *dv, BIGNUMX *rem, const BIGNUMX *m,
                     const BIGNUMX *d, BN_CTX *ctx);

#endif
