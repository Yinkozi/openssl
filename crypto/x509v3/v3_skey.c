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
#include <openssl/x509v3.h>
#include "crypto/x509.h"
#include "ext_dat.h"

static YASN1_OCTET_STRING *s2i_skey_id(YX509V3_EXT_METHOD *method,
                                      YX509V3_CTX *ctx, char *str);
const YX509V3_EXT_METHOD v3_skey_id = {
    NID_subject_key_identifier, 0, YASN1_ITEM_ref(YASN1_OCTET_STRING),
    0, 0, 0, 0,
    (YX509V3_EXT_I2S)i2s_YASN1_OCTET_STRING,
    (YX509V3_EXT_S2I)s2i_skey_id,
    0, 0, 0, 0,
    NULL
};

char *i2s_YASN1_OCTET_STRING(YX509V3_EXT_METHOD *method,
                            const YASN1_OCTET_STRING *oct)
{
    return OPENSSL_buf2hexstr(oct->data, oct->length);
}

YASN1_OCTET_STRING *s2i_YASN1_OCTET_STRING(YX509V3_EXT_METHOD *method,
                                         YX509V3_CTX *ctx, const char *str)
{
    YASN1_OCTET_STRING *oct;
    long length;

    if ((oct = YASN1_OCTET_STRING_new()) == NULL) {
        YX509V3err(YX509V3_F_S2I_YASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((oct->data = OPENSSL_hexstr2buf(str, &length)) == NULL) {
        YASN1_OCTET_STRING_free(oct);
        return NULL;
    }

    oct->length = length;

    return oct;

}

static YASN1_OCTET_STRING *s2i_skey_id(YX509V3_EXT_METHOD *method,
                                      YX509V3_CTX *ctx, char *str)
{
    YASN1_OCTET_STRING *oct;
    YX509_PUBKEY *pubkey;
    const unsigned char *pk;
    int pklen;
    unsigned char pkey_dig[EVVP_MAX_MD_SIZE];
    unsigned int diglen;

    if (strcmp(str, "hash"))
        return s2i_YASN1_OCTET_STRING(method, ctx, str);

    if ((oct = YASN1_OCTET_STRING_new()) == NULL) {
        YX509V3err(YX509V3_F_S2I_SKEY_ID, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (ctx && (ctx->flags == CTX_TEST))
        return oct;

    if (!ctx || (!ctx->subject_req && !ctx->subject_cert)) {
        YX509V3err(YX509V3_F_S2I_SKEY_ID, YX509V3_R_NO_PUBLIC_KEY);
        goto err;
    }

    if (ctx->subject_req)
        pubkey = ctx->subject_req->req_info.pubkey;
    else
        pubkey = ctx->subject_cert->cert_info.key;

    if (pubkey == NULL) {
        YX509V3err(YX509V3_F_S2I_SKEY_ID, YX509V3_R_NO_PUBLIC_KEY);
        goto err;
    }

    YX509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, pubkey);

    if (!EVVP_Digest(pk, pklen, pkey_dig, &diglen, EVVP_sha1(), NULL))
        goto err;

    if (!YASN1_OCTET_STRING_set(oct, pkey_dig, diglen)) {
        YX509V3err(YX509V3_F_S2I_SKEY_ID, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return oct;

 err:
    YASN1_OCTET_STRING_free(oct);
    return NULL;
}
