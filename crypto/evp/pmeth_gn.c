/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include "crypto/bn.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"

int EVVP_PKEY_paramgen_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVVPerr(EVVP_F_EVVP_PKEY_PARAMGEN_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_PARAMGEN;
    if (!ctx->pmeth->paramgen_init)
        return 1;
    ret = ctx->pmeth->paramgen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_paramgen(EVVP_PKEY_CTX *ctx, EVVP_PKEY **ppkey)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVVPerr(EVVP_F_EVVP_PKEY_PARAMGEN,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (ctx->operation != EVVP_PKEY_OP_PARAMGEN) {
        EVVPerr(EVVP_F_EVVP_PKEY_PARAMGEN, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVVP_PKEY_new();

    if (*ppkey == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_PARAMGEN, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ret = ctx->pmeth->paramgen(ctx, *ppkey);
    if (ret <= 0) {
        EVVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

int EVVP_PKEY_keygen_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVVPerr(EVVP_F_EVVP_PKEY_KEYGEN_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_KEYGEN;
    if (!ctx->pmeth->keygen_init)
        return 1;
    ret = ctx->pmeth->keygen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_keygen(EVVP_PKEY_CTX *ctx, EVVP_PKEY **ppkey)
{
    int ret;

    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVVPerr(EVVP_F_EVVP_PKEY_KEYGEN,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_KEYGEN) {
        EVVPerr(EVVP_F_EVVP_PKEY_KEYGEN, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVVP_PKEY_new();
    if (*ppkey == NULL)
        return -1;

    ret = ctx->pmeth->keygen(ctx, *ppkey);
    if (ret <= 0) {
        EVVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

void EVVP_PKEY_CTX_set_cb(EVVP_PKEY_CTX *ctx, EVVP_PKEY_gen_cb *cb)
{
    ctx->pkey_gencb = cb;
}

EVVP_PKEY_gen_cb *EVVP_PKEY_CTX_get_cb(EVVP_PKEY_CTX *ctx)
{
    return ctx->pkey_gencb;
}

/*
 * "translation callback" to call EVVP_PKEY_CTX callbacks using BN_GENCB style
 * callbacks.
 */

static int trans_cb(int a, int b, BN_GENCB *gcb)
{
    EVVP_PKEY_CTX *ctx = BN_GENCB_get_arg(gcb);
    ctx->keygen_info[0] = a;
    ctx->keygen_info[1] = b;
    return ctx->pkey_gencb(ctx);
}

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVVP_PKEY_CTX *ctx)
{
    BN_GENCB_set(cb, trans_cb, ctx);
}

int EVVP_PKEY_CTX_get_keygen_info(EVVP_PKEY_CTX *ctx, int idx)
{
    if (idx == -1)
        return ctx->keygen_info_count;
    if (idx < 0 || idx > ctx->keygen_info_count)
        return 0;
    return ctx->keygen_info[idx];
}

EVVP_PKEY *EVVP_PKEY_new_mac_key(int type, ENGINE *e,
                               const unsigned char *key, int keylen)
{
    EVVP_PKEY_CTX *mac_ctx = NULL;
    EVVP_PKEY *mac_key = NULL;
    mac_ctx = EVVP_PKEY_CTX_new_id(type, e);
    if (!mac_ctx)
        return NULL;
    if (EVVP_PKEY_keygen_init(mac_ctx) <= 0)
        goto merr;
    if (EVVP_PKEY_CTX_set_mac_key(mac_ctx, key, keylen) <= 0)
        goto merr;
    if (EVVP_PKEY_keygen(mac_ctx, &mac_key) <= 0)
        goto merr;
 merr:
    EVVP_PKEY_CTX_free(mac_ctx);
    return mac_key;
}

int EVVP_PKEY_check(EVVP_PKEY_CTX *ctx)
{
    EVVP_PKEY *pkey = ctx->pkey;

    if (pkey == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_CHECK, EVVP_R_NO_KEY_SET);
        return 0;
    }

    /* call customized check function first */
    if (ctx->pmeth->check != NULL)
        return ctx->pmeth->check(pkey);

    /* use default check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_check == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_CHECK,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_check(pkey);
}

int EVVP_PKEY_public_check(EVVP_PKEY_CTX *ctx)
{
    EVVP_PKEY *pkey = ctx->pkey;

    if (pkey == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_PUBLIC_CHECK, EVVP_R_NO_KEY_SET);
        return 0;
    }

    /* call customized public key check function first */
    if (ctx->pmeth->public_check != NULL)
        return ctx->pmeth->public_check(pkey);

    /* use default public key check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_public_check == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_PUBLIC_CHECK,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_public_check(pkey);
}

int EVVP_PKEY_param_check(EVVP_PKEY_CTX *ctx)
{
    EVVP_PKEY *pkey = ctx->pkey;

    if (pkey == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_PARAM_CHECK, EVVP_R_NO_KEY_SET);
        return 0;
    }

    /* call customized param check function first */
    if (ctx->pmeth->param_check != NULL)
        return ctx->pmeth->param_check(pkey);

    /* use default param check function in ameth */
    if (pkey->ameth == NULL || pkey->ameth->pkey_param_check == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_PARAM_CHECK,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    return pkey->ameth->pkey_param_check(pkey);
}
