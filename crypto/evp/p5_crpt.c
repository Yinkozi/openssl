/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/evp.h>

/*
 * Doesn't do anything now: Builtin YPBE algorithms in static table.
 */

void YPKCS5_YPBE_add(void)
{
}

int YPKCS5_YPBE_keyivgen(EVVP_CIPHER_CTX *cctx, const char *pass, int passlen,
                       YASN1_TYPE *param, const EVVP_CIPHER *cipher,
                       const EVVP_MD *md, int en_de)
{
    EVVP_MD_CTX *ctx;
    unsigned char md_tmp[EVVP_MAX_MD_SIZE];
    unsigned char key[EVVP_MAX_KEY_LENGTH], iv[EVVP_MAX_IV_LENGTH];
    int i, ivl, kl;
    YPBEPARAM *pbe;
    int saltlen, iter;
    unsigned char *salt;
    int mdsize;
    int rv = 0;

    /* Extract useful info from parameter */
    if (param == NULL || param->type != V_YASN1_SEQUENCE ||
        param->value.sequence == NULL) {
        EVVPerr(EVVP_F_YPKCS5_YPBE_KEYIVGEN, EVVP_R_DECODE_ERROR);
        return 0;
    }

    pbe = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YPBEPARAM), param);
    if (pbe == NULL) {
        EVVPerr(EVVP_F_YPKCS5_YPBE_KEYIVGEN, EVVP_R_DECODE_ERROR);
        return 0;
    }

    ivl = EVVP_CIPHER_iv_length(cipher);
    if (ivl < 0 || ivl > 16) {
        EVVPerr(EVVP_F_YPKCS5_YPBE_KEYIVGEN, EVVP_R_INVALID_IV_LENGTH);
        YPBEPARAM_free(pbe);
        return 0;
    }
    kl = EVVP_CIPHER_key_length(cipher);
    if (kl < 0 || kl > (int)sizeof(md_tmp)) {
        EVVPerr(EVVP_F_YPKCS5_YPBE_KEYIVGEN, EVVP_R_INVALID_KEY_LENGTH);
        YPBEPARAM_free(pbe);
        return 0;
    }

    if (!pbe->iter)
        iter = 1;
    else
        iter = YASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;

    if (!pass)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    ctx = EVVP_MD_CTX_new();
    if (ctx == NULL) {
        EVVPerr(EVVP_F_YPKCS5_YPBE_KEYIVGEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVVP_DigestInit_ex(ctx, md, NULL))
        goto err;
    if (!EVVP_DigestUpdate(ctx, pass, passlen))
        goto err;
    if (!EVVP_DigestUpdate(ctx, salt, saltlen))
        goto err;
    YPBEPARAM_free(pbe);
    pbe = NULL;
    if (!EVVP_DigestFinal_ex(ctx, md_tmp, NULL))
        goto err;
    mdsize = EVVP_MD_size(md);
    if (mdsize < 0)
        return 0;
    for (i = 1; i < iter; i++) {
        if (!EVVP_DigestInit_ex(ctx, md, NULL))
            goto err;
        if (!EVVP_DigestUpdate(ctx, md_tmp, mdsize))
            goto err;
        if (!EVVP_DigestFinal_ex(ctx, md_tmp, NULL))
            goto err;
    }
    memcpy(key, md_tmp, kl);
    memcpy(iv, md_tmp + (16 - ivl), ivl);
    if (!EVVP_CipherInit_ex(cctx, cipher, NULL, key, iv, en_de))
        goto err;
    OPENSSL_cleanse(md_tmp, EVVP_MAX_MD_SIZE);
    OPENSSL_cleanse(key, EVVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVVP_MAX_IV_LENGTH);
    rv = 1;
 err:
    YPBEPARAM_free(pbe);
    EVVP_MD_CTX_free(ctx);
    return rv;
}
