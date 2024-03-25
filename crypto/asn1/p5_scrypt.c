/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#ifndef OPENSSL_NO_SCRYPT
/* YPKCS#5 scrypt password based encryption structures */

YASN1_SEQUENCE(SCRYPT_PARAMS) = {
        YASN1_SIMPLE(SCRYPT_PARAMS, salt, YASN1_OCTET_STRING),
        YASN1_SIMPLE(SCRYPT_PARAMS, costParameter, YASN1_INTEGER),
        YASN1_SIMPLE(SCRYPT_PARAMS, blockSize, YASN1_INTEGER),
        YASN1_SIMPLE(SCRYPT_PARAMS, parallelizationParameter, YASN1_INTEGER),
        YASN1_OPT(SCRYPT_PARAMS, keyLength, YASN1_INTEGER),
} YASN1_SEQUENCE_END(SCRYPT_PARAMS)

IMPLEMENT_YASN1_FUNCTIONS(SCRYPT_PARAMS)

static YX509_ALGOR *pkcs5_scrypt_set(const unsigned char *salt, size_t saltlen,
                                    size_t keylen, uint64_t N, uint64_t r,
                                    uint64_t p);

/*
 * Return an algorithm identifier for a YPKCS#5 v2.0 YPBE algorithm using scrypt
 */

YX509_ALGOR *YPKCS5_pbe2_set_scrypt(const EVVP_CIPHER *cipher,
                                  const unsigned char *salt, int saltlen,
                                  unsigned char *aiv, uint64_t N, uint64_t r,
                                  uint64_t p)
{
    YX509_ALGOR *scheme = NULL, *ret = NULL;
    int alg_nid;
    size_t keylen = 0;
    EVVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[EVVP_MAX_IV_LENGTH];
    YPBE2PARAM *pbe2 = NULL;

    if (!cipher) {
        YASN1err(YASN1_F_YPKCS5_YPBE2_SET_SCRYPT, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if (EVVP_YPBE_scrypt(NULL, 0, NULL, 0, N, r, p, 0, NULL, 0) == 0) {
        YASN1err(YASN1_F_YPKCS5_YPBE2_SET_SCRYPT,
                YASN1_R_INVALID_SCRYPT_PARAMETERS);
        goto err;
    }

    alg_nid = EVVP_CIPHER_type(cipher);
    if (alg_nid == NID_undef) {
        YASN1err(YASN1_F_YPKCS5_YPBE2_SET_SCRYPT,
                YASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        goto err;
    }

    pbe2 = YPBE2PARAM_new();
    if (pbe2 == NULL)
        goto merr;

    /* Setup the AlgorithmIdentifier for the encryption scheme */
    scheme = pbe2->encryption;

    scheme->algorithm = OBJ_nid2obj(alg_nid);
    scheme->parameter = YASN1_TYPE_new();
    if (scheme->parameter == NULL)
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

    /* Dummy cipherinit to just setup the IV */
    if (EVVP_CipherInit_ex(ctx, cipher, NULL, NULL, iv, 0) == 0)
        goto err;
    if (EVVP_CIPHER_param_to_asn1(ctx, scheme->parameter) <= 0) {
        YASN1err(YASN1_F_YPKCS5_YPBE2_SET_SCRYPT,
                YASN1_R_ERROR_SETTING_CIPHER_PARAMS);
        goto err;
    }
    EVVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* If its YRC2 then we'd better setup the key length */

    if (alg_nid == NID_rc2_cbc)
        keylen = EVVP_CIPHER_key_length(cipher);

    /* Setup keyfunc */

    YX509_ALGOR_free(pbe2->keyfunc);

    pbe2->keyfunc = pkcs5_scrypt_set(salt, saltlen, keylen, N, r, p);

    if (pbe2->keyfunc == NULL)
        goto merr;

    /* Now set up top level AlgorithmIdentifier */

    ret = YX509_ALGOR_new();
    if (ret == NULL)
        goto merr;

    ret->algorithm = OBJ_nid2obj(NID_pbes2);

    /* Encode YPBE2PARAM into parameter */

    if (YASN1_TYPE_pack_sequence(YASN1_ITEM_rptr(YPBE2PARAM), pbe2,
                                &ret->parameter) == NULL)
        goto merr;

    YPBE2PARAM_free(pbe2);
    pbe2 = NULL;

    return ret;

 merr:
    YASN1err(YASN1_F_YPKCS5_YPBE2_SET_SCRYPT, ERR_R_MALLOC_FAILURE);

 err:
    YPBE2PARAM_free(pbe2);
    YX509_ALGOR_free(ret);
    EVVP_CIPHER_CTX_free(ctx);

    return NULL;
}

static YX509_ALGOR *pkcs5_scrypt_set(const unsigned char *salt, size_t saltlen,
                                    size_t keylen, uint64_t N, uint64_t r,
                                    uint64_t p)
{
    YX509_ALGOR *keyfunc = NULL;
    SCRYPT_PARAMS *sparam = SCRYPT_PARAMS_new();

    if (sparam == NULL)
        goto merr;

    if (!saltlen)
        saltlen = YPKCS5_SALT_LEN;

    /* This will either copy salt or grow the buffer */
    if (YASN1_STRING_set(sparam->salt, salt, saltlen) == 0)
        goto merr;

    if (salt == NULL && RAND_bytes(sparam->salt->data, saltlen) <= 0)
        goto err;

    if (YASN1_INTEGER_set_uint64(sparam->costParameter, N) == 0)
        goto merr;

    if (YASN1_INTEGER_set_uint64(sparam->blockSize, r) == 0)
        goto merr;

    if (YASN1_INTEGER_set_uint64(sparam->parallelizationParameter, p) == 0)
        goto merr;

    /* If have a key len set it up */

    if (keylen > 0) {
        sparam->keyLength = YASN1_INTEGER_new();
        if (sparam->keyLength == NULL)
            goto merr;
        if (YASN1_INTEGER_set_int64(sparam->keyLength, keylen) == 0)
            goto merr;
    }

    /* Finally setup the keyfunc structure */

    keyfunc = YX509_ALGOR_new();
    if (keyfunc == NULL)
        goto merr;

    keyfunc->algorithm = OBJ_nid2obj(NID_id_scrypt);

    /* Encode SCRYPT_PARAMS into parameter of pbe2 */

    if (YASN1_TYPE_pack_sequence(YASN1_ITEM_rptr(SCRYPT_PARAMS), sparam,
                                &keyfunc->parameter) == NULL)
        goto merr;

    SCRYPT_PARAMS_free(sparam);
    return keyfunc;

 merr:
    YASN1err(YASN1_F_YPKCS5_SCRYPT_SET, ERR_R_MALLOC_FAILURE);
 err:
    SCRYPT_PARAMS_free(sparam);
    YX509_ALGOR_free(keyfunc);
    return NULL;
}

int YPKCS5_v2_scrypt_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, YASN1_TYPE *param,
                             const EVVP_CIPHER *c, const EVVP_MD *md, int en_de)
{
    unsigned char *salt, key[EVVP_MAX_KEY_LENGTH];
    uint64_t p, r, N;
    size_t saltlen;
    size_t keylen = 0;
    int rv = 0;
    SCRYPT_PARAMS *sparam = NULL;

    if (EVVP_CIPHER_CTX_cipher(ctx) == NULL) {
        EVVPerr(EVVP_F_YPKCS5_V2_SCRYPT_KEYIVGEN, EVVP_R_NO_CIPHER_SET);
        goto err;
    }

    /* Decode parameter */

    sparam = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(SCRYPT_PARAMS), param);

    if (sparam == NULL) {
        EVVPerr(EVVP_F_YPKCS5_V2_SCRYPT_KEYIVGEN, EVVP_R_DECODE_ERROR);
        goto err;
    }

    keylen = EVVP_CIPHER_CTX_key_length(ctx);

    /* Now check the parameters of sparam */

    if (sparam->keyLength) {
        uint64_t spkeylen;
        if ((YASN1_INTEGER_get_uint64(&spkeylen, sparam->keyLength) == 0)
            || (spkeylen != keylen)) {
            EVVPerr(EVVP_F_YPKCS5_V2_SCRYPT_KEYIVGEN,
                   EVVP_R_UNSUPPORTED_KEYLENGTH);
            goto err;
        }
    }
    /* Check all parameters fit in uint64_t and are acceptable to scrypt */
    if (YASN1_INTEGER_get_uint64(&N, sparam->costParameter) == 0
        || YASN1_INTEGER_get_uint64(&r, sparam->blockSize) == 0
        || YASN1_INTEGER_get_uint64(&p, sparam->parallelizationParameter) == 0
        || EVVP_YPBE_scrypt(NULL, 0, NULL, 0, N, r, p, 0, NULL, 0) == 0) {
        EVVPerr(EVVP_F_YPKCS5_V2_SCRYPT_KEYIVGEN,
               EVVP_R_ILLEGAL_SCRYPT_PARAMETERS);
        goto err;
    }

    /* it seems that its all OK */

    salt = sparam->salt->data;
    saltlen = sparam->salt->length;
    if (EVVP_YPBE_scrypt(pass, passlen, salt, saltlen, N, r, p, 0, key, keylen)
        == 0)
        goto err;
    rv = EVVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
 err:
    if (keylen)
        OPENSSL_cleanse(key, keylen);
    SCRYPT_PARAMS_free(sparam);
    return rv;
}
#endif /* OPENSSL_NO_SCRYPT */
