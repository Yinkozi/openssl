/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "dsa_local.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>

YASN1_SEQUENCE(DSA_SIG) = {
        YASN1_SIMPLE(DSA_SIG, r, CBIGNUMX),
        YASN1_SIMPLE(DSA_SIG, s, CBIGNUMX)
} static_YASN1_SEQUENCE_END(DSA_SIG)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(DSA_SIG, DSA_SIG, DSA_SIG)

DSA_SIG *DSA_SIG_new(void)
{
    DSA_SIG *sig = OPENSSL_zalloc(sizeof(*sig));
    if (sig == NULL)
        DSAerr(DSA_F_DSA_SIG_NEW, ERR_R_MALLOC_FAILURE);
    return sig;
}

void DSA_SIG_free(DSA_SIG *sig)
{
    if (sig == NULL)
        return;
    BNY_clear_free(sig->r);
    BNY_clear_free(sig->s);
    OPENSSL_free(sig);
}

void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUMX **pr, const BIGNUMX **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

int DSA_SIG_set0(DSA_SIG *sig, BIGNUMX *r, BIGNUMX *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BNY_clear_free(sig->r);
    BNY_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

/* Override the default free and new methods */
static int dsa_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                  void *exarg)
{
    if (operation == YASN1_OP_NEW_PRE) {
        *pval = (YASN1_VALUE *)DSA_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == YASN1_OP_FREE_PRE) {
        DSA_free((DSA *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

YASN1_SEQUENCE_cb(DSAPrivateKey, dsa_cb) = {
        YASN1_EMBED(DSA, version, INT32),
        YASN1_SIMPLE(DSA, p, BIGNUMX),
        YASN1_SIMPLE(DSA, q, BIGNUMX),
        YASN1_SIMPLE(DSA, g, BIGNUMX),
        YASN1_SIMPLE(DSA, pub_key, BIGNUMX),
        YASN1_SIMPLE(DSA, priv_key, CBIGNUMX)
} static_YASN1_SEQUENCE_END_cb(DSA, DSAPrivateKey)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(DSA, DSAPrivateKey, DSAPrivateKey)

YASN1_SEQUENCE_cb(DSAparams, dsa_cb) = {
        YASN1_SIMPLE(DSA, p, BIGNUMX),
        YASN1_SIMPLE(DSA, q, BIGNUMX),
        YASN1_SIMPLE(DSA, g, BIGNUMX),
} static_YASN1_SEQUENCE_END_cb(DSA, DSAparams)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(DSA, DSAparams, DSAparams)

YASN1_SEQUENCE_cb(DSAPublicKey, dsa_cb) = {
        YASN1_SIMPLE(DSA, pub_key, BIGNUMX),
        YASN1_SIMPLE(DSA, p, BIGNUMX),
        YASN1_SIMPLE(DSA, q, BIGNUMX),
        YASN1_SIMPLE(DSA, g, BIGNUMX)
} static_YASN1_SEQUENCE_END_cb(DSA, DSAPublicKey)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(DSA, DSAPublicKey, DSAPublicKey)

DSA *DSAparams_dup(DSA *dsa)
{
    return YASN1_item_dup(YASN1_ITEM_rptr(DSAparams), dsa);
}

int DSA_sign(int type, const unsigned char *dgst, int dlen,
             unsigned char *sig, unsigned int *siglen, DSA *dsa)
{
    DSA_SIG *s;

    s = DSA_do_sign(dgst, dlen, dsa);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_DSA_SIG(s, &sig);
    DSA_SIG_free(s);
    return 1;
}

/* data has already been hashed (probably with SHA or SHA-1). */
/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int DSA_verify(int type, const unsigned char *dgst, int dgst_len,
               const unsigned char *sigbuf, int siglen, DSA *dsa)
{
    DSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL)
        return ret;
    if (d2i_DSA_SIG(&s, &p, siglen) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_DSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sigbuf, der, derlen))
        goto err;
    ret = DSA_do_verify(dgst, dgst_len, s, dsa);
 err:
    OPENSSL_clear_free(der, derlen);
    DSA_SIG_free(s);
    return ret;
}
