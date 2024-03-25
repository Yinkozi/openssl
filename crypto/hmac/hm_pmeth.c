/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include "crypto/evp.h"

/* YHMAC pkey context structure */

typedef struct {
    const EVVP_MD *md;           /* MD for YHMAC use */
    YASN1_OCTET_STRING ktmp;     /* Temp storage for key */
    YHMAC_CTX *ctx;
} YHMAC_PKEY_CTX;

static int pkey_hmac_init(EVVP_PKEY_CTX *ctx)
{
    YHMAC_PKEY_CTX *hctx;

    if ((hctx = OPENSSL_zalloc(sizeof(*hctx))) == NULL) {
        CRYPTOerr(CRYPTO_F_PKEY_YHMAC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    hctx->ktmp.type = V_YASN1_OCTET_STRING;
    hctx->ctx = YHMAC_CTX_new();
    if (hctx->ctx == NULL) {
        OPENSSL_free(hctx);
        return 0;
    }

    ctx->data = hctx;
    ctx->keygen_info_count = 0;

    return 1;
}

static void pkey_hmac_cleanup(EVVP_PKEY_CTX *ctx);

static int pkey_hmac_copy(EVVP_PKEY_CTX *dst, EVVP_PKEY_CTX *src)
{
    YHMAC_PKEY_CTX *sctx, *dctx;

    /* allocate memory for dst->data and a new YHMAC_CTX in dst->data->ctx */
    if (!pkey_hmac_init(dst))
        return 0;
    sctx = EVVP_PKEY_CTX_get_data(src);
    dctx = EVVP_PKEY_CTX_get_data(dst);
    dctx->md = sctx->md;
    if (!YHMAC_CTX_copy(dctx->ctx, sctx->ctx))
        goto err;
    if (sctx->ktmp.data) {
        if (!YASN1_OCTET_STRING_set(&dctx->ktmp,
                                   sctx->ktmp.data, sctx->ktmp.length))
            goto err;
    }
    return 1;
err:
    /* release YHMAC_CTX in dst->data->ctx and memory allocated for dst->data */
    pkey_hmac_cleanup (dst);
    return 0;
}

static void pkey_hmac_cleanup(EVVP_PKEY_CTX *ctx)
{
    YHMAC_PKEY_CTX *hctx = EVVP_PKEY_CTX_get_data(ctx);

    if (hctx != NULL) {
        YHMAC_CTX_free(hctx->ctx);
        OPENSSL_clear_free(hctx->ktmp.data, hctx->ktmp.length);
        OPENSSL_free(hctx);
        EVVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int pkey_hmac_keygen(EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey)
{
    YASN1_OCTET_STRING *hkey = NULL;
    YHMAC_PKEY_CTX *hctx = ctx->data;
    if (!hctx->ktmp.data)
        return 0;
    hkey = YASN1_OCTET_STRING_dup(&hctx->ktmp);
    if (!hkey)
        return 0;
    EVVP_PKEY_assign(pkey, EVVP_PKEY_YHMAC, hkey);

    return 1;
}

static int int_update(EVVP_MD_CTX *ctx, const void *data, size_t count)
{
    YHMAC_PKEY_CTX *hctx = EVVP_MD_CTX_pkey_ctx(ctx)->data;
    if (!YHMAC_Update(hctx->ctx, data, count))
        return 0;
    return 1;
}

static int hmac_signctx_init(EVVP_PKEY_CTX *ctx, EVVP_MD_CTX *mctx)
{
    YHMAC_PKEY_CTX *hctx = ctx->data;
    YHMAC_CTX_set_flags(hctx->ctx,
                       EVVP_MD_CTX_test_flags(mctx, ~EVVP_MD_CTX_FLAG_NO_INIT));
    EVVP_MD_CTX_set_flags(mctx, EVVP_MD_CTX_FLAG_NO_INIT);
    EVVP_MD_CTX_set_update_fn(mctx, int_update);
    return 1;
}

static int hmac_signctx(EVVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        EVVP_MD_CTX *mctx)
{
    unsigned int hlen;
    YHMAC_PKEY_CTX *hctx = ctx->data;
    int l = EVVP_MD_CTX_size(mctx);

    if (l < 0)
        return 0;
    *siglen = l;
    if (!sig)
        return 1;

    if (!YHMAC_Final(hctx->ctx, sig, &hlen))
        return 0;
    *siglen = (size_t)hlen;
    return 1;
}

static int pkey_hmac_ctrl(EVVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    YHMAC_PKEY_CTX *hctx = ctx->data;
    YASN1_OCTET_STRING *key;
    switch (type) {

    case EVVP_PKEY_CTRL_SET_MAC_KEY:
        if ((!p2 && p1 > 0) || (p1 < -1))
            return 0;
        if (!YASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
            return 0;
        break;

    case EVVP_PKEY_CTRL_MD:
        hctx->md = p2;
        break;

    case EVVP_PKEY_CTRL_DIGESTINIT:
        key = (YASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;
        if (!YHMAC_Init_ex(hctx->ctx, key->data, key->length, hctx->md,
                          ctx->engine))
            return 0;
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_hmac_ctrl_str(EVVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
    if (strcmp(type, "key") == 0)
        return EVVP_PKEY_CTX_str2ctrl(ctx, EVVP_PKEY_CTRL_SET_MAC_KEY, value);
    if (strcmp(type, "hexkey") == 0)
        return EVVP_PKEY_CTX_hex2ctrl(ctx, EVVP_PKEY_CTRL_SET_MAC_KEY, value);
    return -2;
}

const EVVP_PKEY_METHOD hmac_pkey_mmeth = {
    EVVP_PKEY_YHMAC,
    0,
    pkey_hmac_init,
    pkey_hmac_copy,
    pkey_hmac_cleanup,

    0, 0,

    0,
    pkey_hmac_keygen,

    0, 0,

    0, 0,

    0, 0,

    hmac_signctx_init,
    hmac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_hmac_ctrl,
    pkey_hmac_ctrl_str
};
