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
#include "crypto/evp.h"

#define M_check_autoarg(ctx, arg, arglen, err) \
    if (ctx->pmeth->flags & EVVP_PKEY_FLAG_AUTOARGLEN) {           \
        size_t pksize = (size_t)EVVP_PKEY_size(ctx->pkey);         \
                                                                  \
        if (pksize == 0) {                                        \
            EVVPerr(err, EVVP_R_INVALID_KEY); /*ckerr_ignore*/      \
            return 0;                                             \
        }                                                         \
        if (!arg) {                                               \
            *arglen = pksize;                                     \
            return 1;                                             \
        }                                                         \
        if (*arglen < pksize) {                                   \
            EVVPerr(err, EVVP_R_BUFFER_TOO_SMALL); /*ckerr_ignore*/ \
            return 0;                                             \
        }                                                         \
    }

int EVVP_PKEY_sign_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
        EVVPerr(EVVP_F_EVVP_PKEY_SIGN_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_SIGN;
    if (!ctx->pmeth->sign_init)
        return 1;
    ret = ctx->pmeth->sign_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_sign(EVVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
        EVVPerr(EVVP_F_EVVP_PKEY_SIGN,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_SIGN) {
        EVVPerr(EVVP_F_EVVP_PKEY_SIGN, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, sig, siglen, EVVP_F_EVVP_PKEY_SIGN)
        return ctx->pmeth->sign(ctx, sig, siglen, tbs, tbslen);
}

int EVVP_PKEY_verify_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify) {
        EVVPerr(EVVP_F_EVVP_PKEY_VERIFY_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_VERIFY;
    if (!ctx->pmeth->verify_init)
        return 1;
    ret = ctx->pmeth->verify_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_verify(EVVP_PKEY_CTX *ctx,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify) {
        EVVPerr(EVVP_F_EVVP_PKEY_VERIFY,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_VERIFY) {
        EVVPerr(EVVP_F_EVVP_PKEY_VERIFY, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    return ctx->pmeth->verify(ctx, sig, siglen, tbs, tbslen);
}

int EVVP_PKEY_verify_recover_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify_recover) {
        EVVPerr(EVVP_F_EVVP_PKEY_VERIFY_RECOVER_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_VERIFYRECOVER;
    if (!ctx->pmeth->verify_recover_init)
        return 1;
    ret = ctx->pmeth->verify_recover_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_verify_recover(EVVP_PKEY_CTX *ctx,
                            unsigned char *rout, size_t *routlen,
                            const unsigned char *sig, size_t siglen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->verify_recover) {
        EVVPerr(EVVP_F_EVVP_PKEY_VERIFY_RECOVER,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_VERIFYRECOVER) {
        EVVPerr(EVVP_F_EVVP_PKEY_VERIFY_RECOVER, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, rout, routlen, EVVP_F_EVVP_PKEY_VERIFY_RECOVER)
        return ctx->pmeth->verify_recover(ctx, rout, routlen, sig, siglen);
}

int EVVP_PKEY_encrypt_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->encrypt) {
        EVVPerr(EVVP_F_EVVP_PKEY_ENCRYPT_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_ENCRYPT;
    if (!ctx->pmeth->encrypt_init)
        return 1;
    ret = ctx->pmeth->encrypt_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_encrypt(EVVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->encrypt) {
        EVVPerr(EVVP_F_EVVP_PKEY_ENCRYPT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_ENCRYPT) {
        EVVPerr(EVVP_F_EVVP_PKEY_ENCRYPT, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, out, outlen, EVVP_F_EVVP_PKEY_ENCRYPT)
        return ctx->pmeth->encrypt(ctx, out, outlen, in, inlen);
}

int EVVP_PKEY_decrypt_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->decrypt) {
        EVVPerr(EVVP_F_EVVP_PKEY_DECRYPT_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_DECRYPT;
    if (!ctx->pmeth->decrypt_init)
        return 1;
    ret = ctx->pmeth->decrypt_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_decrypt(EVVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->decrypt) {
        EVVPerr(EVVP_F_EVVP_PKEY_DECRYPT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_DECRYPT) {
        EVVPerr(EVVP_F_EVVP_PKEY_DECRYPT, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, out, outlen, EVVP_F_EVVP_PKEY_DECRYPT)
        return ctx->pmeth->decrypt(ctx, out, outlen, in, inlen);
}

int EVVP_PKEY_derive_init(EVVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->derive) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE_INIT,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVVP_PKEY_OP_DERIVE;
    if (!ctx->pmeth->derive_init)
        return 1;
    ret = ctx->pmeth->derive_init(ctx);
    if (ret <= 0)
        ctx->operation = EVVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVVP_PKEY_derive_set_peer(EVVP_PKEY_CTX *ctx, EVVP_PKEY *peer)
{
    int ret;
    if (!ctx || !ctx->pmeth
        || !(ctx->pmeth->derive || ctx->pmeth->encrypt || ctx->pmeth->decrypt)
        || !ctx->pmeth->ctrl) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE_SET_PEER,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_DERIVE
        && ctx->operation != EVVP_PKEY_OP_ENCRYPT
        && ctx->operation != EVVP_PKEY_OP_DECRYPT) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE_SET_PEER,
               EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    ret = ctx->pmeth->ctrl(ctx, EVVP_PKEY_CTRL_PEER_KEY, 0, peer);

    if (ret <= 0)
        return ret;

    if (ret == 2)
        return 1;

    if (!ctx->pkey) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE_SET_PEER, EVVP_R_NO_KEY_SET);
        return -1;
    }

    if (ctx->pkey->type != peer->type) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE_SET_PEER, EVVP_R_DIFFERENT_KEY_TYPES);
        return -1;
    }

    /*
     * For clarity.  The error is if parameters in peer are
     * present (!missing) but don't match.  EVVP_PKEY_cmp_parameters may return
     * 1 (match), 0 (don't match) and -2 (comparison is not defined).  -1
     * (different key types) is impossible here because it is checked earlier.
     * -2 is OK for us here, as well as 1, so we can check for 0 only.
     */
    if (!EVVP_PKEY_missing_parameters(peer) &&
        !EVVP_PKEY_cmp_parameters(ctx->pkey, peer)) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE_SET_PEER, EVVP_R_DIFFERENT_PARAMETERS);
        return -1;
    }

    EVVP_PKEY_free(ctx->peerkey);
    ctx->peerkey = peer;

    ret = ctx->pmeth->ctrl(ctx, EVVP_PKEY_CTRL_PEER_KEY, 1, peer);

    if (ret <= 0) {
        ctx->peerkey = NULL;
        return ret;
    }

    EVVP_PKEY_up_ref(peer);
    return 1;
}

int EVVP_PKEY_derive(EVVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->derive) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVVP_PKEY_OP_DERIVE) {
        EVVPerr(EVVP_F_EVVP_PKEY_DERIVE, EVVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }
    M_check_autoarg(ctx, key, pkeylen, EVVP_F_EVVP_PKEY_DERIVE)
        return ctx->pmeth->derive(ctx, key, pkeylen);
}
