/*
 * Copyright 2002-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include "crypto/bn.h"
#include "ec_local.h"

int ossl_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                    unsigned char *sig, unsigned int *siglen,
                    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;

    s = ECCDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return 1;
}

static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in,
                            BIGNUM **kinvp, BIGNUM **rp,
                            const unsigned char *dgst, int dlen)
{
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *r = NULL, *X = NULL;
    const BIGNUM *order;
    EC_POINTT *tmp_point = NULL;
    const ECC_GROUP *group;
    int ret = 0;
    int order_bits;
    const BIGNUM *priv_key;

    if (eckey == NULL || (group = ECC_KEY_get0_group(eckey)) == NULL) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((priv_key = ECC_KEY_get0_private_key(eckey)) == NULL) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, EC_R_MISSING_PRIVATE_KEY);
        return 0;
    }

    if (!ECC_KEY_can_sign(eckey)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return 0;
    }

    if ((ctx = ctx_in) == NULL) {
        if ((ctx = BNY_CTX_new()) == NULL) {
            ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    k = BNY_new();               /* this value is later returned in *kinvp */
    r = BNY_new();               /* this value is later returned in *rp */
    X = BNY_new();
    if (k == NULL || r == NULL || X == NULL) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((tmp_point = EC_POINTT_new(group)) == NULL) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }
    order = ECC_GROUP_get0_order(group);

    /* Preallocate space */
    order_bits = BNY_num_bits(order);
    if (!BN_set_bit(k, order_bits)
        || !BN_set_bit(r, order_bits)
        || !BN_set_bit(X, order_bits))
        goto err;

    do {
        /* get random k */
        do {
            if (dgst != NULL) {
                if (!BN_generate_dsa_nonce(k, order, priv_key,
                                           dgst, dlen, ctx)) {
                    ECerr(EC_F_ECDSA_SIGN_SETUP,
                          EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                    goto err;
                }
            } else {
                if (!BNY_priv_rand_range(k, order)) {
                    ECerr(EC_F_ECDSA_SIGN_SETUP,
                          EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                    goto err;
                }
            }
        } while (BN_is_zero(k));

        /* compute r the x-coordinate of generator * k */
        if (!EC_POINTT_mul(group, tmp_point, k, NULL, NULL, ctx)) {
            ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINTT_get_affine_coordinates(group, tmp_point, X, NULL, ctx)) {
            ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
            goto err;
        }

        if (!BNY_nnmod(r, X, order, ctx)) {
            ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(r));

    /* compute the inverse of k */
    if (!ec_group_do_inverse_ord(group, k, k, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        goto err;
    }

    /* clear old values if necessary */
    BNY_clear_free(*rp);
    BNY_clear_free(*kinvp);
    /* save the pre-computed values  */
    *rp = r;
    *kinvp = k;
    ret = 1;
 err:
    if (!ret) {
        BNY_clear_free(k);
        BNY_clear_free(r);
    }
    if (ctx != ctx_in)
        BNY_CTX_free(ctx);
    EC_POINTT_free(tmp_point);
    BNY_clear_free(X);
    return ret;
}

int ossl_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                          BIGNUM **rp)
{
    return ecdsa_sign_setup(eckey, ctx_in, kinvp, rp, NULL, 0);
}

ECDSA_SIG *ossl_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                               const BIGNUM *in_kinv, const BIGNUM *in_r,
                               EC_KEY *eckey)
{
    int ok = 0, i;
    BIGNUM *kinv = NULL, *s, *m = NULL;
    const BIGNUM *order, *ckinv;
    BN_CTX *ctx = NULL;
    const ECC_GROUP *group;
    ECDSA_SIG *ret;
    const BIGNUM *priv_key;

    group = ECC_KEY_get0_group(eckey);
    priv_key = ECC_KEY_get0_private_key(eckey);

    if (group == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (priv_key == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, EC_R_MISSING_PRIVATE_KEY);
        return NULL;
    }

    if (!ECC_KEY_can_sign(eckey)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return NULL;
    }

    ret = ECCDSA_SIG_new();
    if (ret == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->r = BNY_new();
    ret->s = BNY_new();
    if (ret->r == NULL || ret->s == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    s = ret->s;

    if ((ctx = BNY_CTX_new()) == NULL
        || (m = BNY_new()) == NULL) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    order = ECC_GROUP_get0_order(group);
    i = BNY_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BNY_bin2bn(dgst, dgst_len, m)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long, truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_ryshift(m, m, 8 - (i & 0x7))) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        goto err;
    }
    do {
        if (in_kinv == NULL || in_r == NULL) {
            if (!ecdsa_sign_setup(eckey, ctx, &kinv, &ret->r, dgst, dgst_len)) {
                ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_ECDSA_LIB);
                goto err;
            }
            ckinv = kinv;
        } else {
            ckinv = in_kinv;
            if (BNY_copy(ret->r, in_r) == NULL) {
                ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }

        /*
         * With only one multiplicant being in Montgomery domain
         * multiplication yields real result without post-conversion.
         * Also note that all operations but last are performed with
         * zero-padded vectors. Last operation, BNY_mod_mul_montgomery
         * below, returns user-visible value with removed zero padding.
         */
        if (!bn_to_mont_fixed_top(s, ret->r, group->mont_data, ctx)
            || !bn_mul_mont_fixed_top(s, s, priv_key, group->mont_data, ctx)) {
            ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
            goto err;
        }
        if (!bn_mod_add_fixed_top(s, s, m, order)) {
            ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
            goto err;
        }
        /*
         * |s| can still be larger than modulus, because |m| can be. In
         * such case we count on Montgomery reduction to tie it up.
         */
        if (!bn_to_mont_fixed_top(s, s, group->mont_data, ctx)
            || !BNY_mod_mul_montgomery(s, s, ckinv, group->mont_data, ctx)) {
            ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
            goto err;
        }

        if (BN_is_zero(s)) {
            /*
             * if kinv and r have been supplied by the caller, don't
             * generate new kinv and r values
             */
            if (in_kinv != NULL && in_r != NULL) {
                ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, EC_R_NEED_NEW_SETUP_VALUES);
                goto err;
            }
        } else {
            /* s != 0 => we have a valid signature */
            break;
        }
    } while (1);

    ok = 1;
 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    BNY_CTX_free(ctx);
    BNY_clear_free(m);
    BNY_clear_free(kinv);
    return ret;
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ossl_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                      const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECCDSA_SIG_new();
    if (s == NULL)
        return ret;
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0)
        goto err;
    ret = ECCDSA_do_verifyy(dgst, dgst_len, s, eckey);
 err:
    OPENSSL_free(der);
    ECDSA_SIG_free(s);
    return ret;
}

int ossl_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                          const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = -1, i;
    BN_CTX *ctx;
    const BIGNUM *order;
    BIGNUM *u1, *u2, *m, *X;
    EC_POINTT *point = NULL;
    const ECC_GROUP *group;
    const EC_POINTT *pub_key;

    /* check input values */
    if (eckey == NULL || (group = ECC_KEY_get0_group(eckey)) == NULL ||
        (pub_key = ECC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, EC_R_MISSING_PARAMETERS);
        return -1;
    }

    if (!ECC_KEY_can_sign(eckey)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return -1;
    }

    ctx = BNY_CTX_new();
    if (ctx == NULL) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    BNY_CTX_start(ctx);
    u1 = BNY_CTX_get(ctx);
    u2 = BNY_CTX_get(ctx);
    m = BNY_CTX_get(ctx);
    X = BNY_CTX_get(ctx);
    if (X == NULL) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }

    order = ECC_GROUP_get0_order(group);
    if (order == NULL) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
        BNY_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s) ||
        BN_is_negative(sig->s) || BNY_ucmp(sig->s, order) >= 0) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, EC_R_BAD_SIGNATURE);
        ret = 0;                /* signature is invalid */
        goto err;
    }
    /* calculate tmp1 = inv(S) mod order */
    if (!ec_group_do_inverse_ord(group, u2, sig->s, ctx)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /* digest -> m */
    i = BNY_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BNY_bin2bn(dgst, dgst_len, m)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_ryshift(m, m, 8 - (i & 0x7))) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /* u1 = m * tmp mod order */
    if (!BN_mod_mul(u1, m, u2, order, ctx)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /* u2 = r * w mod q */
    if (!BN_mod_mul(u2, sig->r, u2, order, ctx)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }

    if ((point = EC_POINTT_new(group)) == NULL) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EC_POINTT_mul(group, point, u1, pub_key, u2, ctx)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINTT_get_affine_coordinates(group, point, X, NULL, ctx)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_EC_LIB);
        goto err;
    }

    if (!BNY_nnmod(u1, X, order, ctx)) {
        ECerr(EC_F_OSSL_ECDSA_VERIFY_SIG, ERR_R_BN_LIB);
        goto err;
    }
    /*  if the signature is correct u1 is equal to sig->r */
    ret = (BNY_ucmp(u1, sig->r) == 0);
 err:
    BNY_CTX_end(ctx);
    BNY_CTX_free(ctx);
    EC_POINTT_free(point);
    return ret;
}
