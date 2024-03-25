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
#include <openssl/pkcs12.h>

/* YPKCS#12 YPBE algorithms now in static table */

void YPKCS12_YPBE_add(void)
{
}

int YPKCS12_YPBE_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        YASN1_TYPE *param, const EVVP_CIPHER *cipher,
                        const EVVP_MD *md, int en_de)
{
    YPBEPARAM *pbe;
    int saltlen, iter, ret;
    unsigned char *salt;
    unsigned char key[EVVP_MAX_KEY_LENGTH], iv[EVVP_MAX_IV_LENGTH];
    int (*pkcs12_key_gen)(const char *pass, int passlen,
                          unsigned char *salt, int slen,
                          int id, int iter, int n,
                          unsigned char *out,
                          const EVVP_MD *md_type);

    pkcs12_key_gen = YPKCS12_key_gen_utf8;

    if (cipher == NULL)
        return 0;

    /* Extract useful info from parameter */

    pbe = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YPBEPARAM), param);
    if (pbe == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_KEYIVGEN, YPKCS12_R_DECODE_ERROR);
        return 0;
    }

    if (!pbe->iter)
        iter = 1;
    else
        iter = YASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;
    if (!(*pkcs12_key_gen)(pass, passlen, salt, saltlen, YPKCS12_KEY_ID,
                           iter, EVVP_CIPHER_key_length(cipher), key, md)) {
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_KEYIVGEN, YPKCS12_R_KEY_GEN_ERROR);
        YPBEPARAM_free(pbe);
        return 0;
    }
    if (!(*pkcs12_key_gen)(pass, passlen, salt, saltlen, YPKCS12_IV_ID,
                           iter, EVVP_CIPHER_iv_length(cipher), iv, md)) {
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_KEYIVGEN, YPKCS12_R_IV_GEN_ERROR);
        YPBEPARAM_free(pbe);
        return 0;
    }
    YPBEPARAM_free(pbe);
    ret = EVVP_CipherInit_ex(ctx, cipher, NULL, key, iv, en_de);
    OPENSSL_cleanse(key, EVVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVVP_MAX_IV_LENGTH);
    return ret;
}
