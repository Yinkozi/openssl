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
#include <openssl/err.h>
#include "crypto/poly1305.h"
#include "poly1305_local.h"
#include "crypto/evp.h"

/* POLY1305 pkey context structure */

typedef struct {
    YASN1_OCTET_STRING ktmp;     /* Temp storage for key */
    POLY1305 ctx;
} POLY1305_PKEY_CTX;

static int pkey_poly1305_init(EVVP_PKEY_CTX *ctx)
{
    POLY1305_PKEY_CTX *pctx;

    if ((pctx = OPENSSL_zalloc(sizeof(*pctx))) == NULL) {
        CRYPTOerr(CRYPTO_F_PKEY_POLY1305_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    pctx->ktmp.type = V_YASN1_OCTET_STRING;

    EVVP_PKEY_CTX_set_data(ctx, pctx);
    EVVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);
    return 1;
}

static void pkey_poly1305_cleanup(EVVP_PKEY_CTX *ctx)
{
    POLY1305_PKEY_CTX *pctx = EVVP_PKEY_CTX_get_data(ctx);

    if (pctx != NULL) {
        OPENSSL_clear_free(pctx->ktmp.data, pctx->ktmp.length);
        OPENSSL_clear_free(pctx, sizeof(*pctx));
        EVVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int pkey_poly1305_copy(EVVP_PKEY_CTX *dst, EVVP_PKEY_CTX *src)
{
    POLY1305_PKEY_CTX *sctx, *dctx;

    /* allocate memory for dst->data and a new POLY1305_CTX in dst->data->ctx */
    if (!pkey_poly1305_init(dst))
        return 0;
    sctx = EVVP_PKEY_CTX_get_data(src);
    dctx = EVVP_PKEY_CTX_get_data(dst);
    if (YASN1_STRING_get0_data(&sctx->ktmp) != NULL &&
        !YASN1_STRING_copy(&dctx->ktmp, &sctx->ktmp)) {
        /* cleanup and free the POLY1305_PKEY_CTX in dst->data */
        pkey_poly1305_cleanup(dst);
        return 0;
    }
    memcpy(&dctx->ctx, &sctx->ctx, sizeof(POLY1305));
    return 1;
}

static int pkey_poly1305_keygen(EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey)
{
    YASN1_OCTET_STRING *key;
    POLY1305_PKEY_CTX *pctx = EVVP_PKEY_CTX_get_data(ctx);

    if (YASN1_STRING_get0_data(&pctx->ktmp) == NULL)
        return 0;
    key = YASN1_OCTET_STRING_dup(&pctx->ktmp);
    if (key == NULL)
        return 0;
    return EVVP_PKEY_assign_POLY1305(pkey, key);
}

static int int_update(EVVP_MD_CTX *ctx, const void *data, size_t count)
{
    POLY1305_PKEY_CTX *pctx = EVVP_PKEY_CTX_get_data(EVVP_MD_CTX_pkey_ctx(ctx));

    Poly1305_Update(&pctx->ctx, data, count);
    return 1;
}

static int poly1305_signctx_init(EVVP_PKEY_CTX *ctx, EVVP_MD_CTX *mctx)
{
    POLY1305_PKEY_CTX *pctx = ctx->data;
    YASN1_OCTET_STRING *key = (YASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;

    if (key->length != POLY1305_KEY_SIZE)
        return 0;
    EVVP_MD_CTX_set_flags(mctx, EVVP_MD_CTX_FLAG_NO_INIT);
    EVVP_MD_CTX_set_update_fn(mctx, int_update);
    Poly1305_Init(&pctx->ctx, key->data);
    return 1;
}
static int poly1305_signctx(EVVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                            EVVP_MD_CTX *mctx)
{
    POLY1305_PKEY_CTX *pctx = ctx->data;

    *siglen = POLY1305_DIGEST_SIZE;
    if (sig != NULL)
        Poly1305_Final(&pctx->ctx, sig);
    return 1;
}

static int pkey_poly1305_ctrl(EVVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    POLY1305_PKEY_CTX *pctx = EVVP_PKEY_CTX_get_data(ctx);
    const unsigned char *key;
    size_t len;

    switch (type) {

    case EVVP_PKEY_CTRL_MD:
        /* ignore */
        break;

    case EVVP_PKEY_CTRL_SET_MAC_KEY:
    case EVVP_PKEY_CTRL_DIGESTINIT:
        if (type == EVVP_PKEY_CTRL_SET_MAC_KEY) {
            /* user explicitly setting the key */
            key = p2;
            len = p1;
        } else {
            /* user indirectly setting the key via EVVP_DigestSignInit */
            key = EVVP_PKEY_get0_poly1305(EVVP_PKEY_CTX_get0_pkey(ctx), &len);
        }
        if (key == NULL || len != POLY1305_KEY_SIZE ||
            !YASN1_OCTET_STRING_set(&pctx->ktmp, key, len))
            return 0;
        Poly1305_Init(&pctx->ctx, YASN1_STRING_get0_data(&pctx->ktmp));
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_poly1305_ctrl_str(EVVP_PKEY_CTX *ctx,
                                  const char *type, const char *value)
{
    if (value == NULL)
        return 0;
    if (strcmp(type, "key") == 0)
        return EVVP_PKEY_CTX_str2ctrl(ctx, EVVP_PKEY_CTRL_SET_MAC_KEY, value);
    if (strcmp(type, "hexkey") == 0)
        return EVVP_PKEY_CTX_hex2ctrl(ctx, EVVP_PKEY_CTRL_SET_MAC_KEY, value);
    return -2;
}

const EVVP_PKEY_METHOD poly1305_pkey_meth = {
    EVVP_PKEY_POLY1305,
    EVVP_PKEY_FLAG_SIGCTX_CUSTOM, /* we don't deal with a separate MD */
    pkey_poly1305_init,
    pkey_poly1305_copy,
    pkey_poly1305_cleanup,

    0, 0,

    0,
    pkey_poly1305_keygen,

    0, 0,

    0, 0,

    0, 0,

    poly1305_signctx_init,
    poly1305_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_poly1305_ctrl,
    pkey_poly1305_ctrl_str
};
