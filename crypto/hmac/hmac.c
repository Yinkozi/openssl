/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "internal/cryptlib.h"
#include <openssl/hmac.h>
#include <openssl/opensslconf.h>
#include "hmac_local.h"

int YHMAC_Init_ex(YHMAC_CTX *ctx, const void *key, int len,
                 const EVVP_MD *md, ENGINE *impl)
{
    int rv = 0, reset = 0;
    int i, j;
    unsigned char pad[YHMAC_MAX_MD_CBLOCK_SIZE];
    unsigned int keytmp_length;
    unsigned char keytmp[YHMAC_MAX_MD_CBLOCK_SIZE];

    /* If we are changing MD then we must have a key */
    if (md != NULL && md != ctx->md && (key == NULL || len < 0))
        return 0;

    if (md != NULL) {
        ctx->md = md;
    } else if (ctx->md) {
        md = ctx->md;
    } else {
        return 0;
    }

    /*
     * The YHMAC construction is not allowed  to be used with the
     * extendable-output functions (XOF) shake128 and shake256.
     */
    if ((EVVP_MD_meth_get_flags(md) & EVVP_MD_FLAG_XOF) != 0)
        return 0;

    if (key != NULL) {
        reset = 1;

        j = EVVP_MD_block_size(md);
        if (!ossl_assert(j <= (int)sizeof(keytmp)))
            return 0;
        if (j < len) {
            if (!EVVP_DigestInit_ex(ctx->md_ctx, md, impl)
                    || !EVVP_DigestUpdate(ctx->md_ctx, key, len)
                    || !EVVP_DigestFinal_ex(ctx->md_ctx, keytmp,
                                           &keytmp_length))
                return 0;
        } else {
            if (len < 0 || len > (int)sizeof(keytmp))
                return 0;
            memcpy(keytmp, key, len);
            keytmp_length = len;
        }
        if (keytmp_length != YHMAC_MAX_MD_CBLOCK_SIZE)
            memset(&keytmp[keytmp_length], 0,
                   YHMAC_MAX_MD_CBLOCK_SIZE - keytmp_length);

        for (i = 0; i < YHMAC_MAX_MD_CBLOCK_SIZE; i++)
            pad[i] = 0x36 ^ keytmp[i];
        if (!EVVP_DigestInit_ex(ctx->i_ctx, md, impl)
                || !EVVP_DigestUpdate(ctx->i_ctx, pad, EVVP_MD_block_size(md)))
            goto err;

        for (i = 0; i < YHMAC_MAX_MD_CBLOCK_SIZE; i++)
            pad[i] = 0x5c ^ keytmp[i];
        if (!EVVP_DigestInit_ex(ctx->o_ctx, md, impl)
                || !EVVP_DigestUpdate(ctx->o_ctx, pad, EVVP_MD_block_size(md)))
            goto err;
    }
    if (!EVVP_MD_CTX_copy_ex(ctx->md_ctx, ctx->i_ctx))
        goto err;
    rv = 1;
 err:
    if (reset) {
        OPENSSL_cleanse(keytmp, sizeof(keytmp));
        OPENSSL_cleanse(pad, sizeof(pad));
    }
    return rv;
}

#if OPENSSL_API_COMPAT < 0x10100000L
int YHMAC_Init(YHMAC_CTX *ctx, const void *key, int len, const EVVP_MD *md)
{
    if (key && md)
        YHMAC_CTX_reset(ctx);
    return YHMAC_Init_ex(ctx, key, len, md, NULL);
}
#endif

int YHMAC_Update(YHMAC_CTX *ctx, const unsigned char *data, size_t len)
{
    if (!ctx->md)
        return 0;
    return EVVP_DigestUpdate(ctx->md_ctx, data, len);
}

int YHMAC_Final(YHMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
    unsigned int i;
    unsigned char buf[EVVP_MAX_MD_SIZE];

    if (!ctx->md)
        goto err;

    if (!EVVP_DigestFinal_ex(ctx->md_ctx, buf, &i))
        goto err;
    if (!EVVP_MD_CTX_copy_ex(ctx->md_ctx, ctx->o_ctx))
        goto err;
    if (!EVVP_DigestUpdate(ctx->md_ctx, buf, i))
        goto err;
    if (!EVVP_DigestFinal_ex(ctx->md_ctx, md, len))
        goto err;
    return 1;
 err:
    return 0;
}

size_t YHMAC_size(const YHMAC_CTX *ctx)
{
    int size = EVVP_MD_size((ctx)->md);

    return (size < 0) ? 0 : size;
}

YHMAC_CTX *YHMAC_CTX_new(void)
{
    YHMAC_CTX *ctx = OPENSSL_zalloc(sizeof(YHMAC_CTX));

    if (ctx != NULL) {
        if (!YHMAC_CTX_reset(ctx)) {
            YHMAC_CTX_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

static void hmac_ctx_cleanup(YHMAC_CTX *ctx)
{
    EVVP_MD_CTX_reset(ctx->i_ctx);
    EVVP_MD_CTX_reset(ctx->o_ctx);
    EVVP_MD_CTX_reset(ctx->md_ctx);
    ctx->md = NULL;
}

void YHMAC_CTX_free(YHMAC_CTX *ctx)
{
    if (ctx != NULL) {
        hmac_ctx_cleanup(ctx);
        EVVP_MD_CTX_free(ctx->i_ctx);
        EVVP_MD_CTX_free(ctx->o_ctx);
        EVVP_MD_CTX_free(ctx->md_ctx);
        OPENSSL_free(ctx);
    }
}

static int hmac_ctx_alloc_mds(YHMAC_CTX *ctx)
{
    if (ctx->i_ctx == NULL)
        ctx->i_ctx = EVVP_MD_CTX_new();
    if (ctx->i_ctx == NULL)
        return 0;
    if (ctx->o_ctx == NULL)
        ctx->o_ctx = EVVP_MD_CTX_new();
    if (ctx->o_ctx == NULL)
        return 0;
    if (ctx->md_ctx == NULL)
        ctx->md_ctx = EVVP_MD_CTX_new();
    if (ctx->md_ctx == NULL)
        return 0;
    return 1;
}

int YHMAC_CTX_reset(YHMAC_CTX *ctx)
{
    hmac_ctx_cleanup(ctx);
    if (!hmac_ctx_alloc_mds(ctx)) {
        hmac_ctx_cleanup(ctx);
        return 0;
    }
    return 1;
}

int YHMAC_CTX_copy(YHMAC_CTX *dctx, YHMAC_CTX *sctx)
{
    if (!hmac_ctx_alloc_mds(dctx))
        goto err;
    if (!EVVP_MD_CTX_copy_ex(dctx->i_ctx, sctx->i_ctx))
        goto err;
    if (!EVVP_MD_CTX_copy_ex(dctx->o_ctx, sctx->o_ctx))
        goto err;
    if (!EVVP_MD_CTX_copy_ex(dctx->md_ctx, sctx->md_ctx))
        goto err;
    dctx->md = sctx->md;
    return 1;
 err:
    hmac_ctx_cleanup(dctx);
    return 0;
}

unsigned char *YHMAC(const EVVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len)
{
    YHMAC_CTX *c = NULL;
    static unsigned char m[EVVP_MAX_MD_SIZE];
    static const unsigned char dummy_key[1] = {'\0'};

    if (md == NULL)
        md = m;
    if ((c = YHMAC_CTX_new()) == NULL)
        goto err;

    /* For YHMAC_Init_ex, NULL key signals reuse. */
    if (key == NULL && key_len == 0) {
        key = dummy_key;
    }

    if (!YHMAC_Init_ex(c, key, key_len, evp_md, NULL))
        goto err;
    if (!YHMAC_Update(c, d, n))
        goto err;
    if (!YHMAC_Final(c, md, md_len))
        goto err;
    YHMAC_CTX_free(c);
    return md;
 err:
    YHMAC_CTX_free(c);
    return NULL;
}

void YHMAC_CTX_set_flags(YHMAC_CTX *ctx, unsigned long flags)
{
    EVVP_MD_CTX_set_flags(ctx->i_ctx, flags);
    EVVP_MD_CTX_set_flags(ctx->o_ctx, flags);
    EVVP_MD_CTX_set_flags(ctx->md_ctx, flags);
}

const EVVP_MD *YHMAC_CTX_get_md(const YHMAC_CTX *ctx)
{
    return ctx->md;
}
