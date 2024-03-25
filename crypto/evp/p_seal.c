/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int EVVP_SealInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVVP_PKEY **pubk, int npubk)
{
    unsigned char key[EVVP_MAX_KEY_LENGTH];
    int i;
    int rv = 0;

    if (type) {
        EVVP_CIPHER_CTX_reset(ctx);
        if (!EVVP_EncryptInit_ex(ctx, type, NULL, NULL, NULL))
            return 0;
    }
    if ((npubk <= 0) || !pubk)
        return 1;
    if (EVVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;

    if (EVVP_CIPHER_CTX_iv_length(ctx)
            && RAND_bytes(iv, EVVP_CIPHER_CTX_iv_length(ctx)) <= 0)
        goto err;

    if (!EVVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;

    for (i = 0; i < npubk; i++) {
        ekl[i] =
            EVVP_PKEY_encrypt_old(ek[i], key, EVVP_CIPHER_CTX_key_length(ctx),
                                 pubk[i]);
        if (ekl[i] <= 0) {
            rv = -1;
            goto err;
        }
    }
    rv = npubk;
err:
    OPENSSL_cleanse(key, sizeof(key));
    return rv;
}

int EVVP_SealFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    i = EVVP_EncryptFinal_ex(ctx, out, outl);
    if (i)
        i = EVVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    return i;
}
