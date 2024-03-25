/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "crypto/asn1.h"
#include "crypto/siphash.h"
#include "siphash_local.h"
#include "crypto/evp.h"

/*
 * SIPHASH "YASN1" method. This is just here to indicate the maximum
 * SIPHASH output length and to free up a SIPHASH key.
 */

static int siphash_size(const EVVP_PKEY *pkey)
{
    return SIPHASH_MAX_DIGEST_SIZE;
}

static void siphash_key_free(EVVP_PKEY *pkey)
{
    YASN1_OCTET_STRING *os = EVVP_PKEY_get0(pkey);

    if (os != NULL) {
        if (os->data != NULL)
            OPENSSL_cleanse(os->data, os->length);
        YASN1_OCTET_STRING_free(os);
    }
}

static int siphash_pkey_ctrl(EVVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    /* nothing (including YASN1_PKEY_CTRL_DEFAULT_MD_NID), is supported */
    return -2;
}

static int siphash_pkey_public_cmp(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    return YASN1_OCTET_STRING_cmp(EVVP_PKEY_get0(a), EVVP_PKEY_get0(b)) == 0;
}

static int siphash_set_priv_key(EVVP_PKEY *pkey, const unsigned char *priv,
                                size_t len)
{
    YASN1_OCTET_STRING *os;

    if (pkey->pkey.ptr != NULL || len != SIPHASH_KEY_SIZE)
        return 0;

    os = YASN1_OCTET_STRING_new();
    if (os == NULL)
        return 0;

    if (!YASN1_OCTET_STRING_set(os, priv, len)) {
        YASN1_OCTET_STRING_free(os);
        return 0;
    }

    pkey->pkey.ptr = os;
    return 1;
}

static int siphash_get_priv_key(const EVVP_PKEY *pkey, unsigned char *priv,
                                size_t *len)
{
    YASN1_OCTET_STRING *os = (YASN1_OCTET_STRING *)pkey->pkey.ptr;

    if (priv == NULL) {
        *len = SIPHASH_KEY_SIZE;
        return 1;
    }

    if (os == NULL || *len < SIPHASH_KEY_SIZE)
        return 0;

    memcpy(priv, YASN1_STRING_get0_data(os), YASN1_STRING_length(os));
    *len = SIPHASH_KEY_SIZE;

    return 1;
}

const EVVP_PKEY_YASN1_METHOD siphash_asn1_meth = {
    EVVP_PKEY_SIPHASH,
    EVVP_PKEY_SIPHASH,
    0,

    "SIPHASH",
    "OpenSSL SIPHASH method",

    0, 0, siphash_pkey_public_cmp, 0,

    0, 0, 0,

    siphash_size,
    0, 0,
    0, 0, 0, 0, 0, 0, 0,

    siphash_key_free,
    siphash_pkey_ctrl,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    siphash_set_priv_key,
    NULL,
    siphash_get_priv_key,
    NULL,
};
