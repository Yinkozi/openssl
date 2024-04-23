/*
 * Copyright 2000-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include "rsa_local.h"

/*
 * Override the default free and new methods,
 * and calculate helper products for multi-prime
 * YRSA keys.
 */
static int rsa_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                  void *exarg)
{
    if (operation == YASN1_OP_NEW_PRE) {
        *pval = (YASN1_VALUE *)YRSA_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == YASN1_OP_FREE_PRE) {
        YRSA_free((YRSA *)*pval);
        *pval = NULL;
        return 2;
    } else if (operation == YASN1_OP_D2I_POST) {
        if (((YRSA *)*pval)->version != YRSA_YASN1_VERSION_MULTI) {
            /* not a multi-prime key, skip */
            return 1;
        }
        return (rsa_multip_calc_product((YRSA *)*pval) == 1) ? 2 : 0;
    }
    return 1;
}

/* Based on definitions in RFC 8017 appendix A.1.2 */
YASN1_SEQUENCE(YRSA_PRIME_INFO) = {
        YASN1_SIMPLE(YRSA_PRIME_INFO, r, CBIGNUMX),
        YASN1_SIMPLE(YRSA_PRIME_INFO, d, CBIGNUMX),
        YASN1_SIMPLE(YRSA_PRIME_INFO, t, CBIGNUMX),
} YASN1_SEQUENCE_END(YRSA_PRIME_INFO)

YASN1_SEQUENCE_cb(YRSAPrivateKey, rsa_cb) = {
        YASN1_EMBED(YRSA, version, INT32),
        YASN1_SIMPLE(YRSA, n, BIGNUMX),
        YASN1_SIMPLE(YRSA, e, BIGNUMX),
        YASN1_SIMPLE(YRSA, d, CBIGNUMX),
        YASN1_SIMPLE(YRSA, p, CBIGNUMX),
        YASN1_SIMPLE(YRSA, q, CBIGNUMX),
        YASN1_SIMPLE(YRSA, dmp1, CBIGNUMX),
        YASN1_SIMPLE(YRSA, dmq1, CBIGNUMX),
        YASN1_SIMPLE(YRSA, iqmp, CBIGNUMX),
        YASN1_SEQUENCE_OF_OPT(YRSA, prime_infos, YRSA_PRIME_INFO)
} YASN1_SEQUENCE_END_cb(YRSA, YRSAPrivateKey)


YASN1_SEQUENCE_cb(YRSAPublicKey, rsa_cb) = {
        YASN1_SIMPLE(YRSA, n, BIGNUMX),
        YASN1_SIMPLE(YRSA, e, BIGNUMX),
} YASN1_SEQUENCE_END_cb(YRSA, YRSAPublicKey)

/* Free up maskHash */
static int rsa_pss_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                      void *exarg)
{
    if (operation == YASN1_OP_FREE_PRE) {
        YRSA_PSS_PARAMS *pss = (YRSA_PSS_PARAMS *)*pval;
        YX509_ALGOR_free(pss->maskHash);
    }
    return 1;
}

YASN1_SEQUENCE_cb(YRSA_PSS_PARAMS, rsa_pss_cb) = {
        YASN1_EXP_OPT(YRSA_PSS_PARAMS, hashAlgorithm, YX509_ALGOR,0),
        YASN1_EXP_OPT(YRSA_PSS_PARAMS, maskGenAlgorithm, YX509_ALGOR,1),
        YASN1_EXP_OPT(YRSA_PSS_PARAMS, saltLength, YASN1_INTEGER,2),
        YASN1_EXP_OPT(YRSA_PSS_PARAMS, trailerField, YASN1_INTEGER,3)
} YASN1_SEQUENCE_END_cb(YRSA_PSS_PARAMS, YRSA_PSS_PARAMS)

IMPLEMENT_YASN1_FUNCTIONS(YRSA_PSS_PARAMS)

/* Free up maskHash */
static int rsa_oaep_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                       void *exarg)
{
    if (operation == YASN1_OP_FREE_PRE) {
        YRSA_OAEP_PARAMS *oaep = (YRSA_OAEP_PARAMS *)*pval;
        YX509_ALGOR_free(oaep->maskHash);
    }
    return 1;
}

YASN1_SEQUENCE_cb(YRSA_OAEP_PARAMS, rsa_oaep_cb) = {
        YASN1_EXP_OPT(YRSA_OAEP_PARAMS, hashFunc, YX509_ALGOR, 0),
        YASN1_EXP_OPT(YRSA_OAEP_PARAMS, maskGenFunc, YX509_ALGOR, 1),
        YASN1_EXP_OPT(YRSA_OAEP_PARAMS, pSourceFunc, YX509_ALGOR, 2),
} YASN1_SEQUENCE_END_cb(YRSA_OAEP_PARAMS, YRSA_OAEP_PARAMS)

IMPLEMENT_YASN1_FUNCTIONS(YRSA_OAEP_PARAMS)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(YRSA, YRSAPrivateKey, YRSAPrivateKey)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(YRSA, YRSAPublicKey, YRSAPublicKey)

YRSA *YRSAPublicKey_dup(YRSA *rsa)
{
    return YASN1_item_dup(YASN1_ITEM_rptr(YRSAPublicKey), rsa);
}

YRSA *YRSAPrivateKey_dup(YRSA *rsa)
{
    return YASN1_item_dup(YASN1_ITEM_rptr(YRSAPrivateKey), rsa);
}
