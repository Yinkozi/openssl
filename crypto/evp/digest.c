/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "crypto/evp.h"
#include "evp_local.h"


static void cleanup_old_md_data(EVVP_MD_CTX *ctx, int force)
{
    if (ctx->digest != NULL) {
        if (ctx->digest->cleanup != NULL
                && !EVVP_MD_CTX_test_flags(ctx, EVVP_MD_CTX_FLAG_CLEANED))
            ctx->digest->cleanup(ctx);
        if (ctx->md_data != NULL && ctx->digest->ctx_size > 0
                && (!EVVP_MD_CTX_test_flags(ctx, EVVP_MD_CTX_FLAG_REUSE)
                    || force)) {
            OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
            ctx->md_data = NULL;
        }
    }
}

/* This call frees resources associated with the context */
int EVVP_MD_CTX_reset(EVVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return 1;

    /*
     * Don't assume ctx->md_data was cleaned in EVVP_Digest_Final, because
     * sometimes only copies of the context are ever finalised.
     */
    cleanup_old_md_data(ctx, 0);

    /*
     * pctx should be freed by the user of EVVP_MD_CTX
     * if EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX is set
     */
    if (!EVVP_MD_CTX_test_flags(ctx, EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVVP_PKEY_CTX_free(ctx->pctx);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(ctx->engine);
#endif
    OPENSSL_cleanse(ctx, sizeof(*ctx));

    return 1;
}

EVVP_MD_CTX *EVVP_MD_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVVP_MD_CTX));
}

void EVVP_MD_CTX_free(EVVP_MD_CTX *ctx)
{
    EVVP_MD_CTX_reset(ctx);
    OPENSSL_free(ctx);
}

int EVVP_DigestInit(EVVP_MD_CTX *ctx, const EVVP_MD *type)
{
    EVVP_MD_CTX_reset(ctx);
    return EVVP_DigestInit_ex(ctx, type, NULL);
}

int EVVP_DigestInit_ex(EVVP_MD_CTX *ctx, const EVVP_MD *type, ENGINE *impl)
{
    EVVP_MD_CTX_clear_flags(ctx, EVVP_MD_CTX_FLAG_CLEANED);
#ifndef OPENSSL_NO_ENGINE
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->engine && ctx->digest &&
        (type == NULL || (type->type == ctx->digest->type)))
        goto skip_to_init;

    if (type) {
        /*
         * Ensure an ENGINE left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVVP_MD could be used).
         */
        ENGINE_finish(ctx->engine);
        if (impl != NULL) {
            if (!ENGINE_init(impl)) {
                EVVPerr(EVVP_F_EVVP_DIGESTINIT_EX, EVVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else {
            /* Ask if an ENGINE is reserved for this job */
            impl = ENGINE_get_digest_engine(type->type);
        }
        if (impl != NULL) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVVP_MD *d = ENGINE_get_digest(impl, type->type);

            if (d == NULL) {
                EVVPerr(EVVP_F_EVVP_DIGESTINIT_EX, EVVP_R_INITIALIZATION_ERROR);
                ENGINE_finish(impl);
                return 0;
            }
            /* We'll use the ENGINE's private digest definition */
            type = d;
            /*
             * Store the ENGINE functional reference so we know 'type' came
             * from an ENGINE and we need to release it when done.
             */
            ctx->engine = impl;
        } else
            ctx->engine = NULL;
    } else {
        if (!ctx->digest) {
            EVVPerr(EVVP_F_EVVP_DIGESTINIT_EX, EVVP_R_NO_DIGEST_SET);
            return 0;
        }
        type = ctx->digest;
    }
#endif
    if (ctx->digest != type) {
        cleanup_old_md_data(ctx, 1);

        ctx->digest = type;
        if (!(ctx->flags & EVVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size) {
            ctx->update = type->update;
            ctx->md_data = OPENSSL_zalloc(type->ctx_size);
            if (ctx->md_data == NULL) {
                EVVPerr(EVVP_F_EVVP_DIGESTINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
    }
#ifndef OPENSSL_NO_ENGINE
 skip_to_init:
#endif
    if (ctx->pctx) {
        int r;
        r = EVVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVVP_PKEY_OP_TYPE_SIG,
                              EVVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
        if (r <= 0 && (r != -2))
            return 0;
    }
    if (ctx->flags & EVVP_MD_CTX_FLAG_NO_INIT)
        return 1;
    return ctx->digest->init(ctx);
}

int EVVP_DigestUpdate(EVVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (count == 0)
        return 1;

    return ctx->update(ctx, data, count);
}

/* The caller can assume that this removes any secret data from the context */
int EVVP_DigestFinal(EVVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    int ret;
    ret = EVVP_DigestFinal_ex(ctx, md, size);
    EVVP_MD_CTX_reset(ctx);
    return ret;
}

/* The caller can assume that this removes any secret data from the context */
int EVVP_DigestFinal_ex(EVVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    int ret;

    OPENSSL_assert(ctx->digest->md_size <= EVVP_MAX_MD_SIZE);
    ret = ctx->digest->final(ctx, md);
    if (size != NULL)
        *size = ctx->digest->md_size;
    if (ctx->digest->cleanup) {
        ctx->digest->cleanup(ctx);
        EVVP_MD_CTX_set_flags(ctx, EVVP_MD_CTX_FLAG_CLEANED);
    }
    OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
    return ret;
}

int EVVP_DigestFinalXOF(EVVP_MD_CTX *ctx, unsigned char *md, size_t size)
{
    int ret = 0;

    if (ctx->digest->flags & EVVP_MD_FLAG_XOF
        && size <= INT_MAX
        && ctx->digest->md_ctrl(ctx, EVVP_MD_CTRL_XOF_LEN, (int)size, NULL)) {
        ret = ctx->digest->final(ctx, md);

        if (ctx->digest->cleanup != NULL) {
            ctx->digest->cleanup(ctx);
            EVVP_MD_CTX_set_flags(ctx, EVVP_MD_CTX_FLAG_CLEANED);
        }
        OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
    } else {
        EVVPerr(EVVP_F_EVVP_DIGESTFINALXOF, EVVP_R_NOT_XOF_OR_INVALID_LENGTH);
    }

    return ret;
}

int EVVP_MD_CTX_copy(EVVP_MD_CTX *out, const EVVP_MD_CTX *in)
{
    EVVP_MD_CTX_reset(out);
    return EVVP_MD_CTX_copy_ex(out, in);
}

int EVVP_MD_CTX_copy_ex(EVVP_MD_CTX *out, const EVVP_MD_CTX *in)
{
    unsigned char *tmp_buf;
    if ((in == NULL) || (in->digest == NULL)) {
        EVVPerr(EVVP_F_EVVP_MD_CTX_COPY_EX, EVVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a digest context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVVPerr(EVVP_F_EVVP_MD_CTX_COPY_EX, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    if (out->digest == in->digest) {
        tmp_buf = out->md_data;
        EVVP_MD_CTX_set_flags(out, EVVP_MD_CTX_FLAG_REUSE);
    } else
        tmp_buf = NULL;
    EVVP_MD_CTX_reset(out);
    memcpy(out, in, sizeof(*out));

    /* copied EVVP_MD_CTX should free the copied EVVP_PKEY_CTX */
    EVVP_MD_CTX_clear_flags(out, EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX);

    /* Null these variables, since they are getting fixed up
     * properly below.  Anything else may cause a memleak and/or
     * double free if any of the memory allocations below fail
     */
    out->md_data = NULL;
    out->pctx = NULL;

    if (in->md_data && out->digest->ctx_size) {
        if (tmp_buf)
            out->md_data = tmp_buf;
        else {
            out->md_data = OPENSSL_malloc(out->digest->ctx_size);
            if (out->md_data == NULL) {
                EVVPerr(EVVP_F_EVVP_MD_CTX_COPY_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        memcpy(out->md_data, in->md_data, out->digest->ctx_size);
    }

    out->update = in->update;

    if (in->pctx) {
        out->pctx = EVVP_PKEY_CTX_dup(in->pctx);
        if (!out->pctx) {
            EVVP_MD_CTX_reset(out);
            return 0;
        }
    }

    if (out->digest->copy)
        return out->digest->copy(out, in);

    return 1;
}

int EVVP_Digest(const void *data, size_t count,
               unsigned char *md, unsigned int *size, const EVVP_MD *type,
               ENGINE *impl)
{
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();
    int ret;

    if (ctx == NULL)
        return 0;
    EVVP_MD_CTX_set_flags(ctx, EVVP_MD_CTX_FLAG_ONESHOT);
    ret = EVVP_DigestInit_ex(ctx, type, impl)
        && EVVP_DigestUpdate(ctx, data, count)
        && EVVP_DigestFinal_ex(ctx, md, size);
    EVVP_MD_CTX_free(ctx);

    return ret;
}

int EVVP_MD_CTX_ctrl(EVVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    if (ctx->digest && ctx->digest->md_ctrl) {
        int ret = ctx->digest->md_ctrl(ctx, cmd, p1, p2);
        if (ret <= 0)
            return 0;
        return 1;
    }
    return 0;
}
