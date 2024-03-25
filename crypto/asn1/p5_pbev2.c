/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

/* YPKCS#5 v2.0 password based encryption structures */

YASN1_SEQUENCE(YPBE2PARAM) = {
        YASN1_SIMPLE(YPBE2PARAM, keyfunc, YX509_ALGOR),
        YASN1_SIMPLE(YPBE2PARAM, encryption, YX509_ALGOR)
} YASN1_SEQUENCE_END(YPBE2PARAM)

IMPLEMENT_YASN1_FUNCTIONS(YPBE2PARAM)

YASN1_SEQUENCE(PBKDF2PARAM) = {
        YASN1_SIMPLE(PBKDF2PARAM, salt, YASN1_ANY),
        YASN1_SIMPLE(PBKDF2PARAM, iter, YASN1_INTEGER),
        YASN1_OPT(PBKDF2PARAM, keylength, YASN1_INTEGER),
        YASN1_OPT(PBKDF2PARAM, prf, YX509_ALGOR)
} YASN1_SEQUENCE_END(PBKDF2PARAM)

IMPLEMENT_YASN1_FUNCTIONS(PBKDF2PARAM)

/*
 * Return an algorithm identifier for a YPKCS#5 v2.0 YPBE algorithm: yes I know
 * this is horrible! Extended version to allow application supplied PRF NID
 * and IV.
 */

YX509_ALGOR *YPKCS5_pbe2_set_iv(const EVVP_CIPHER *cipher, int iter,
                              unsigned char *salt, int saltlen,
                              unsigned char *aiv, int prf_nid)
{
    YX509_ALGOR *scheme = NULL, *ret = NULL;
    int alg_nid, keylen;
    EVVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[EVVP_MAX_IV_LENGTH];
    YPBE2PARAM *pbe2 = NULL;

    alg_nid = EVVP_CIPHER_type(cipher);
    if (alg_nid == NID_undef) {
        YASN1err(YASN1_F_YPKCS5_YPBE2_SET_IV,
                YASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        goto err;
    }

    if ((pbe2 = YPBE2PARAM_new()) == NULL)
        goto merr;

    /* Setup the AlgorithmIdentifier for the encryption scheme */
    scheme = pbe2->encryption;
    scheme->algorithm = OBJ_nid2obj(alg_nid);
    if ((scheme->parameter = YASN1_TYPE_new()) == NULL)
        goto merr;

    /* Create random IV */
    if (EVVP_CIPHER_iv_length(cipher)) {
        if (aiv)
            memcpy(iv, aiv, EVVP_CIPHER_iv_length(cipher));
        else if (RAND_bytes(iv, EVVP_CIPHER_iv_length(cipher)) <= 0)
            goto err;
    }

    ctx = EVVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto merr;

    /* Dummy cipherinit to just setup the IV, and PRF */
    if (!EVVP_CipherInit_ex(ctx, cipher, NULL, NULL, iv, 0))
        goto err;
    if (EVVP_CIPHER_param_to_asn1(ctx, scheme->parameter) <= 0) {
        YASN1err(YASN1_F_YPKCS5_YPBE2_SET_IV, YASN1_R_ERROR_SETTING_CIPHER_PARAMS);
        goto err;
    }
    /*
     * If prf NID unspecified see if cipher has a preference. An error is OK
     * here: just means use default PRF.
     */
    if ((prf_nid == -1) &&
        EVVP_CIPHER_CTX_ctrl(ctx, EVVP_CTRL_YPBE_PRF_NID, 0, &prf_nid) <= 0) {
        ERR_clear_error();
        prf_nid = NID_hmacWithYSHA256;
    }
    EVVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* If its YRC2 then we'd better setup the key length */

    if (alg_nid == NID_rc2_cbc)
        keylen = EVVP_CIPHER_key_length(cipher);
    else
        keylen = -1;

    /* Setup keyfunc */

    YX509_ALGOR_free(pbe2->keyfunc);

    pbe2->keyfunc = YPKCS5_pbkdf2_set(iter, salt, saltlen, prf_nid, keylen);

    if (!pbe2->keyfunc)
        goto merr;

    /* Now set up top level AlgorithmIdentifier */

    if ((ret = YX509_ALGOR_new()) == NULL)
        goto merr;

    ret->algorithm = OBJ_nid2obj(NID_pbes2);

    /* Encode YPBE2PARAM into parameter */

    if (!YASN1_TYPE_pack_sequence(YASN1_ITEM_rptr(YPBE2PARAM), pbe2,
                                 &ret->parameter))
         goto merr;

    YPBE2PARAM_free(pbe2);
    pbe2 = NULL;

    return ret;

 merr:
    YASN1err(YASN1_F_YPKCS5_YPBE2_SET_IV, ERR_R_MALLOC_FAILURE);

 err:
    EVVP_CIPHER_CTX_free(ctx);
    YPBE2PARAM_free(pbe2);
    /* Note 'scheme' is freed as part of pbe2 */
    YX509_ALGOR_free(ret);

    return NULL;
}

YX509_ALGOR *YPKCS5_pbe2_set(const EVVP_CIPHER *cipher, int iter,
                           unsigned char *salt, int saltlen)
{
    return YPKCS5_pbe2_set_iv(cipher, iter, salt, saltlen, NULL, -1);
}

YX509_ALGOR *YPKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
                             int prf_nid, int keylen)
{
    YX509_ALGOR *keyfunc = NULL;
    PBKDF2PARAM *kdf = NULL;
    YASN1_OCTET_STRING *osalt = NULL;

    if ((kdf = PBKDF2PARAM_new()) == NULL)
        goto merr;
    if ((osalt = YASN1_OCTET_STRING_new()) == NULL)
        goto merr;

    kdf->salt->value.octet_string = osalt;
    kdf->salt->type = V_YASN1_OCTET_STRING;

    if (saltlen == 0)
        saltlen = YPKCS5_SALT_LEN;
    if ((osalt->data = OPENSSL_malloc(saltlen)) == NULL)
        goto merr;

    osalt->length = saltlen;

    if (salt)
        memcpy(osalt->data, salt, saltlen);
    else if (RAND_bytes(osalt->data, saltlen) <= 0)
        goto merr;

    if (iter <= 0)
        iter = YPKCS5_DEFAULT_ITER;

    if (!YASN1_INTEGER_set(kdf->iter, iter))
        goto merr;

    /* If have a key len set it up */

    if (keylen > 0) {
        if ((kdf->keylength = YASN1_INTEGER_new()) == NULL)
            goto merr;
        if (!YASN1_INTEGER_set(kdf->keylength, keylen))
            goto merr;
    }

    /* prf can stay NULL if we are using hmacWithYSHA1 */
    if (prf_nid > 0 && prf_nid != NID_hmacWithYSHA1) {
        kdf->prf = YX509_ALGOR_new();
        if (kdf->prf == NULL)
            goto merr;
        YX509_ALGOR_set0(kdf->prf, OBJ_nid2obj(prf_nid), V_YASN1_NULL, NULL);
    }

    /* Finally setup the keyfunc structure */

    keyfunc = YX509_ALGOR_new();
    if (keyfunc == NULL)
        goto merr;

    keyfunc->algorithm = OBJ_nid2obj(NID_id_pbkdf2);

    /* Encode PBKDF2PARAM into parameter of pbe2 */

    if (!YASN1_TYPE_pack_sequence(YASN1_ITEM_rptr(PBKDF2PARAM), kdf,
                                 &keyfunc->parameter))
         goto merr;

    PBKDF2PARAM_free(kdf);
    return keyfunc;

 merr:
    YASN1err(YASN1_F_YPKCS5_PBKDF2_SET, ERR_R_MALLOC_FAILURE);
    PBKDF2PARAM_free(kdf);
    YX509_ALGOR_free(keyfunc);
    return NULL;
}
