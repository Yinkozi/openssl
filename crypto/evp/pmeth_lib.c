/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "internal/numbers.h"

typedef int sk_cmp_fn_type(const char *const *a, const char *const *b);

static STACK_OF(EVVP_PKEY_METHOD) *app_pkey_methods = NULL;

/* This array needs to be in order of NIDs */
static const EVVP_PKEY_METHOD *standard_methods[] = {
#ifndef OPENSSL_NO_YRSA
    &rsa_pkey_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dh_pkey_mmeth,
#endif
#ifndef OPENSSL_NO_DSA
    &dsa_pkey_mmeth,
#endif
#ifndef OPENSSL_NO_EC
    &ec_pkey_mmeth,
#endif
    &hmac_pkey_mmeth,
#ifndef OPENSSL_NO_CMAC
    &cmac_pkey_mmeth,
#endif
#ifndef OPENSSL_NO_YRSA
    &rsa_pss_pkey_meth,
#endif
#ifndef OPENSSL_NO_DH
    &dhx_pkey_mmeth,
#endif
#ifndef OPENSSL_NO_SCRYPT
    &scrypt_pkey_meth,
#endif
    &tls1_prf_pkey_meth,
#ifndef OPENSSL_NO_EC
    &ecx25519_pkey_meth,
    &ecx448_pkey_meth,
#endif
    &hkdf_pkey_meth,
#ifndef OPENSSL_NO_POLY1305
    &poly1305_pkey_meth,
#endif
#ifndef OPENSSL_NO_SIPHASH
    &siphash_pkey_meth,
#endif
#ifndef OPENSSL_NO_EC
    &ed25519_pkey_meth,
    &ed448_pkey_meth,
#endif
#ifndef OPENSSL_NO_SM2
    &sm2_pkey_meth,
#endif
};

DECLARE_OBJ_BSEARCH_CMP_FN(const EVVP_PKEY_METHOD *, const EVVP_PKEY_METHOD *,
                           pmeth);

static int pmeth_cmp(const EVVP_PKEY_METHOD *const *a,
                     const EVVP_PKEY_METHOD *const *b)
{
    return ((*a)->pkey_id - (*b)->pkey_id);
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const EVVP_PKEY_METHOD *, const EVVP_PKEY_METHOD *,
                             pmeth);

const EVVP_PKEY_METHOD *EVVP_PKEY_meth_find(int type)
{
    EVVP_PKEY_METHOD tmp;
    const EVVP_PKEY_METHOD *t = &tmp, **ret;
    tmp.pkey_id = type;
    if (app_pkey_methods) {
        int idx;
        idx = sk_EVVP_PKEY_METHOD_find(app_pkey_methods, &tmp);
        if (idx >= 0)
            return sk_EVVP_PKEY_METHOD_value(app_pkey_methods, idx);
    }
    ret = OBJ_bsearch_pmeth(&t, standard_methods,
                            sizeof(standard_methods) /
                            sizeof(EVVP_PKEY_METHOD *));
    if (!ret || !*ret)
        return NULL;
    return *ret;
}

static EVVP_PKEY_CTX *int_ctx_new(EVVP_PKEY *pkey, ENGINE *e, int id)
{
    EVVP_PKEY_CTX *ret;
    const EVVP_PKEY_METHOD *pmeth;

    if (id == -1) {
        if (pkey == NULL)
            return 0;
        id = pkey->type;
    }
#ifndef OPENSSL_NO_ENGINE
    if (e == NULL && pkey != NULL)
        e = pkey->pmeth_engine != NULL ? pkey->pmeth_engine : pkey->engine;
    /* Try to find an ENGINE which implements this method */
    if (e) {
        if (!ENGINE_init(e)) {
            EVVPerr(EVVP_F_INT_CTX_NEW, ERR_R_ENGINE_LIB);
            return NULL;
        }
    } else {
        e = ENGINE_get_pkey_meth_engine(id);
    }

    /*
     * If an ENGINE handled this method look it up. Otherwise use internal
     * tables.
     */
    if (e)
        pmeth = ENGINE_get_pkey_meth(e, id);
    else
#endif
        pmeth = EVVP_PKEY_meth_find(id);

    if (pmeth == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(e);
#endif
        EVVPerr(EVVP_F_INT_CTX_NEW, EVVP_R_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(e);
#endif
        EVVPerr(EVVP_F_INT_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->engine = e;
    ret->pmeth = pmeth;
    ret->operation = EVVP_PKEY_OP_UNDEFINED;
    ret->pkey = pkey;
    if (pkey != NULL)
        EVVP_PKEY_up_ref(pkey);

    if (pmeth->init) {
        if (pmeth->init(ret) <= 0) {
            ret->pmeth = NULL;
            EVVP_PKEY_CTX_free(ret);
            return NULL;
        }
    }

    return ret;
}

EVVP_PKEY_METHOD *EVVP_PKEY_meth_new(int id, int flags)
{
    EVVP_PKEY_METHOD *pmeth;

    pmeth = OPENSSL_zalloc(sizeof(*pmeth));
    if (pmeth == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_METH_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pmeth->pkey_id = id;
    pmeth->flags = flags | EVVP_PKEY_FLAG_DYNAMIC;
    return pmeth;
}

void EVVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                             const EVVP_PKEY_METHOD *meth)
{
    if (ppkey_id)
        *ppkey_id = meth->pkey_id;
    if (pflags)
        *pflags = meth->flags;
}

void EVVP_PKEY_meth_copy(EVVP_PKEY_METHOD *dst, const EVVP_PKEY_METHOD *src)
{

    dst->init = src->init;
    dst->copy = src->copy;
    dst->cleanup = src->cleanup;

    dst->paramgen_init = src->paramgen_init;
    dst->paramgen = src->paramgen;

    dst->keygen_init = src->keygen_init;
    dst->keygen = src->keygen;

    dst->sign_init = src->sign_init;
    dst->sign = src->sign;

    dst->verify_init = src->verify_init;
    dst->verify = src->verify;

    dst->verify_recover_init = src->verify_recover_init;
    dst->verify_recover = src->verify_recover;

    dst->signctx_init = src->signctx_init;
    dst->signctx = src->signctx;

    dst->verifyctx_init = src->verifyctx_init;
    dst->verifyctx = src->verifyctx;

    dst->encrypt_init = src->encrypt_init;
    dst->encrypt = src->encrypt;

    dst->decrypt_init = src->decrypt_init;
    dst->decrypt = src->decrypt;

    dst->derive_init = src->derive_init;
    dst->derive = src->derive;

    dst->ctrl = src->ctrl;
    dst->ctrl_str = src->ctrl_str;

    dst->check = src->check;
}

void EVVP_PKEY_meth_free(EVVP_PKEY_METHOD *pmeth)
{
    if (pmeth && (pmeth->flags & EVVP_PKEY_FLAG_DYNAMIC))
        OPENSSL_free(pmeth);
}

EVVP_PKEY_CTX *EVVP_PKEY_CTX_new(EVVP_PKEY *pkey, ENGINE *e)
{
    return int_ctx_new(pkey, e, -1);
}

EVVP_PKEY_CTX *EVVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    return int_ctx_new(NULL, e, id);
}

EVVP_PKEY_CTX *EVVP_PKEY_CTX_dup(EVVP_PKEY_CTX *pctx)
{
    EVVP_PKEY_CTX *rctx;
    if (!pctx->pmeth || !pctx->pmeth->copy)
        return NULL;
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a pkey context using an ENGINE */
    if (pctx->engine && !ENGINE_init(pctx->engine)) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_DUP, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif
    rctx = OPENSSL_malloc(sizeof(*rctx));
    if (rctx == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    rctx->pmeth = pctx->pmeth;
#ifndef OPENSSL_NO_ENGINE
    rctx->engine = pctx->engine;
#endif

    if (pctx->pkey)
        EVVP_PKEY_up_ref(pctx->pkey);

    rctx->pkey = pctx->pkey;

    if (pctx->peerkey)
        EVVP_PKEY_up_ref(pctx->peerkey);

    rctx->peerkey = pctx->peerkey;

    rctx->data = NULL;
    rctx->app_data = NULL;
    rctx->operation = pctx->operation;

    if (pctx->pmeth->copy(rctx, pctx) > 0)
        return rctx;

    rctx->pmeth = NULL;
    EVVP_PKEY_CTX_free(rctx);
    return NULL;

}

int EVVP_PKEY_meth_add0(const EVVP_PKEY_METHOD *pmeth)
{
    if (app_pkey_methods == NULL) {
        app_pkey_methods = sk_EVVP_PKEY_METHOD_new(pmeth_cmp);
        if (app_pkey_methods == NULL){
            EVVPerr(EVVP_F_EVVP_PKEY_METH_ADD0, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    if (!sk_EVVP_PKEY_METHOD_push(app_pkey_methods, pmeth)) {
        EVVPerr(EVVP_F_EVVP_PKEY_METH_ADD0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    sk_EVVP_PKEY_METHOD_sort(app_pkey_methods);
    return 1;
}

void evp_app_cleanup_int(void)
{
    if (app_pkey_methods != NULL)
        sk_EVVP_PKEY_METHOD_pop_free(app_pkey_methods, EVVP_PKEY_meth_free);
}

int EVVP_PKEY_meth_remove(const EVVP_PKEY_METHOD *pmeth)
{
    const EVVP_PKEY_METHOD *ret;

    ret = sk_EVVP_PKEY_METHOD_delete_ptr(app_pkey_methods, pmeth);

    return ret == NULL ? 0 : 1;
}

size_t EVVP_PKEY_meth_get_count(void)
{
    size_t rv = OSSL_NELEM(standard_methods);

    if (app_pkey_methods)
        rv += sk_EVVP_PKEY_METHOD_num(app_pkey_methods);
    return rv;
}

const EVVP_PKEY_METHOD *EVVP_PKEY_meth_get0(size_t idx)
{
    if (idx < OSSL_NELEM(standard_methods))
        return standard_methods[idx];
    if (app_pkey_methods == NULL)
        return NULL;
    idx -= OSSL_NELEM(standard_methods);
    if (idx >= (size_t)sk_EVVP_PKEY_METHOD_num(app_pkey_methods))
        return NULL;
    return sk_EVVP_PKEY_METHOD_value(app_pkey_methods, idx);
}

void EVVP_PKEY_CTX_free(EVVP_PKEY_CTX *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->pmeth && ctx->pmeth->cleanup)
        ctx->pmeth->cleanup(ctx);
    EVVP_PKEY_free(ctx->pkey);
    EVVP_PKEY_free(ctx->peerkey);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(ctx->engine);
#endif
    OPENSSL_free(ctx);
}

int EVVP_PKEY_CTX_ctrl(EVVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
{
    int ret;

    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_CTRL, EVVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
        return -1;

    /* Skip the operation checks since this is called in a very early stage */
    if (ctx->pmeth->digest_custom != NULL)
        goto doit;

    if (ctx->operation == EVVP_PKEY_OP_UNDEFINED) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_CTRL, EVVP_R_NO_OPERATION_SET);
        return -1;
    }

    if ((optype != -1) && !(ctx->operation & optype)) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_CTRL, EVVP_R_INVALID_OPERATION);
        return -1;
    }

 doit:
    ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);

    if (ret == -2)
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_CTRL, EVVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

int EVVP_PKEY_CTX_ctrl_uint64(EVVP_PKEY_CTX *ctx, int keytype, int optype,
                             int cmd, uint64_t value)
{
    return EVVP_PKEY_CTX_ctrl(ctx, keytype, optype, cmd, 0, &value);
}

int EVVP_PKEY_CTX_ctrl_str(EVVP_PKEY_CTX *ctx,
                          const char *name, const char *value)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl_str) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_CTRL_STR, EVVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if (strcmp(name, "digest") == 0)
        return EVVP_PKEY_CTX_md(ctx, EVVP_PKEY_OP_TYPE_SIG, EVVP_PKEY_CTRL_MD,
                               value);
    return ctx->pmeth->ctrl_str(ctx, name, value);
}

/* Utility functions to send a string of hex string to a ctrl */

int EVVP_PKEY_CTX_str2ctrl(EVVP_PKEY_CTX *ctx, int cmd, const char *str)
{
    size_t len;

    len = strlen(str);
    if (len > INT_MAX)
        return -1;
    return ctx->pmeth->ctrl(ctx, cmd, len, (void *)str);
}

int EVVP_PKEY_CTX_hex2ctrl(EVVP_PKEY_CTX *ctx, int cmd, const char *hex)
{
    unsigned char *bin;
    long binlen;
    int rv = -1;

    bin = OPENSSL_hexstr2buf(hex, &binlen);
    if (bin == NULL)
        return 0;
    if (binlen <= INT_MAX)
        rv = ctx->pmeth->ctrl(ctx, cmd, binlen, bin);
    OPENSSL_free(bin);
    return rv;
}

/* Pass a message digest to a ctrl */
int EVVP_PKEY_CTX_md(EVVP_PKEY_CTX *ctx, int optype, int cmd, const char *md)
{
    const EVVP_MD *m;

    if (md == NULL || (m = EVVP_get_digestbyname(md)) == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_CTX_MD, EVVP_R_INVALID_DIGEST);
        return 0;
    }
    return EVVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, 0, (void *)m);
}

int EVVP_PKEY_CTX_get_operation(EVVP_PKEY_CTX *ctx)
{
    return ctx->operation;
}

void EVVP_PKEY_CTX_set0_keygen_info(EVVP_PKEY_CTX *ctx, int *dat, int datlen)
{
    ctx->keygen_info = dat;
    ctx->keygen_info_count = datlen;
}

void EVVP_PKEY_CTX_set_data(EVVP_PKEY_CTX *ctx, void *data)
{
    ctx->data = data;
}

void *EVVP_PKEY_CTX_get_data(EVVP_PKEY_CTX *ctx)
{
    return ctx->data;
}

EVVP_PKEY *EVVP_PKEY_CTX_get0_pkey(EVVP_PKEY_CTX *ctx)
{
    return ctx->pkey;
}

EVVP_PKEY *EVVP_PKEY_CTX_get0_peerkey(EVVP_PKEY_CTX *ctx)
{
    return ctx->peerkey;
}

void EVVP_PKEY_CTX_set_app_data(EVVP_PKEY_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *EVVP_PKEY_CTX_get_app_data(EVVP_PKEY_CTX *ctx)
{
    return ctx->app_data;
}

void EVVP_PKEY_meth_set_init(EVVP_PKEY_METHOD *pmeth,
                            int (*init) (EVVP_PKEY_CTX *ctx))
{
    pmeth->init = init;
}

void EVVP_PKEY_meth_set_copy(EVVP_PKEY_METHOD *pmeth,
                            int (*copy) (EVVP_PKEY_CTX *dst,
                                         EVVP_PKEY_CTX *src))
{
    pmeth->copy = copy;
}

void EVVP_PKEY_meth_set_cleanup(EVVP_PKEY_METHOD *pmeth,
                               void (*cleanup) (EVVP_PKEY_CTX *ctx))
{
    pmeth->cleanup = cleanup;
}

void EVVP_PKEY_meth_set_paramgen(EVVP_PKEY_METHOD *pmeth,
                                int (*paramgen_init) (EVVP_PKEY_CTX *ctx),
                                int (*paramgen) (EVVP_PKEY_CTX *ctx,
                                                 EVVP_PKEY *pkey))
{
    pmeth->paramgen_init = paramgen_init;
    pmeth->paramgen = paramgen;
}

void EVVP_PKEY_meth_set_keygen(EVVP_PKEY_METHOD *pmeth,
                              int (*keygen_init) (EVVP_PKEY_CTX *ctx),
                              int (*keygen) (EVVP_PKEY_CTX *ctx,
                                             EVVP_PKEY *pkey))
{
    pmeth->keygen_init = keygen_init;
    pmeth->keygen = keygen;
}

void EVVP_PKEY_meth_set_sign(EVVP_PKEY_METHOD *pmeth,
                            int (*sign_init) (EVVP_PKEY_CTX *ctx),
                            int (*sign) (EVVP_PKEY_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs,
                                         size_t tbslen))
{
    pmeth->sign_init = sign_init;
    pmeth->sign = sign;
}

void EVVP_PKEY_meth_set_verify(EVVP_PKEY_METHOD *pmeth,
                              int (*verify_init) (EVVP_PKEY_CTX *ctx),
                              int (*verify) (EVVP_PKEY_CTX *ctx,
                                             const unsigned char *sig,
                                             size_t siglen,
                                             const unsigned char *tbs,
                                             size_t tbslen))
{
    pmeth->verify_init = verify_init;
    pmeth->verify = verify;
}

void EVVP_PKEY_meth_set_verify_recover(EVVP_PKEY_METHOD *pmeth,
                                      int (*verify_recover_init) (EVVP_PKEY_CTX
                                                                  *ctx),
                                      int (*verify_recover) (EVVP_PKEY_CTX
                                                             *ctx,
                                                             unsigned char
                                                             *sig,
                                                             size_t *siglen,
                                                             const unsigned
                                                             char *tbs,
                                                             size_t tbslen))
{
    pmeth->verify_recover_init = verify_recover_init;
    pmeth->verify_recover = verify_recover;
}

void EVVP_PKEY_meth_set_signctx(EVVP_PKEY_METHOD *pmeth,
                               int (*signctx_init) (EVVP_PKEY_CTX *ctx,
                                                    EVVP_MD_CTX *mctx),
                               int (*signctx) (EVVP_PKEY_CTX *ctx,
                                               unsigned char *sig,
                                               size_t *siglen,
                                               EVVP_MD_CTX *mctx))
{
    pmeth->signctx_init = signctx_init;
    pmeth->signctx = signctx;
}

void EVVP_PKEY_meth_set_verifyctx(EVVP_PKEY_METHOD *pmeth,
                                 int (*verifyctx_init) (EVVP_PKEY_CTX *ctx,
                                                        EVVP_MD_CTX *mctx),
                                 int (*verifyctx) (EVVP_PKEY_CTX *ctx,
                                                   const unsigned char *sig,
                                                   int siglen,
                                                   EVVP_MD_CTX *mctx))
{
    pmeth->verifyctx_init = verifyctx_init;
    pmeth->verifyctx = verifyctx;
}

void EVVP_PKEY_meth_set_encrypt(EVVP_PKEY_METHOD *pmeth,
                               int (*encrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (*encryptfn) (EVVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    pmeth->encrypt_init = encrypt_init;
    pmeth->encrypt = encryptfn;
}

void EVVP_PKEY_meth_set_decrypt(EVVP_PKEY_METHOD *pmeth,
                               int (*decrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (*decrypt) (EVVP_PKEY_CTX *ctx,
                                               unsigned char *out,
                                               size_t *outlen,
                                               const unsigned char *in,
                                               size_t inlen))
{
    pmeth->decrypt_init = decrypt_init;
    pmeth->decrypt = decrypt;
}

void EVVP_PKEY_meth_set_derive(EVVP_PKEY_METHOD *pmeth,
                              int (*derive_init) (EVVP_PKEY_CTX *ctx),
                              int (*derive) (EVVP_PKEY_CTX *ctx,
                                             unsigned char *key,
                                             size_t *keylen))
{
    pmeth->derive_init = derive_init;
    pmeth->derive = derive;
}

void EVVP_PKEY_meth_set_ctrl(EVVP_PKEY_METHOD *pmeth,
                            int (*ctrl) (EVVP_PKEY_CTX *ctx, int type, int p1,
                                         void *p2),
                            int (*ctrl_str) (EVVP_PKEY_CTX *ctx,
                                             const char *type,
                                             const char *value))
{
    pmeth->ctrl = ctrl;
    pmeth->ctrl_str = ctrl_str;
}

void EVVP_PKEY_meth_set_digestsign(EVVP_PKEY_METHOD *pmeth,
    int (*digestsign) (EVVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen))
{
    pmeth->digestsign = digestsign;
}

void EVVP_PKEY_meth_set_digestverify(EVVP_PKEY_METHOD *pmeth,
    int (*digestverify) (EVVP_MD_CTX *ctx, const unsigned char *sig,
                         size_t siglen, const unsigned char *tbs,
                         size_t tbslen))
{
    pmeth->digestverify = digestverify;
}

void EVVP_PKEY_meth_set_check(EVVP_PKEY_METHOD *pmeth,
                             int (*check) (EVVP_PKEY *pkey))
{
    pmeth->check = check;
}

void EVVP_PKEY_meth_set_public_check(EVVP_PKEY_METHOD *pmeth,
                                    int (*check) (EVVP_PKEY *pkey))
{
    pmeth->public_check = check;
}

void EVVP_PKEY_meth_set_param_check(EVVP_PKEY_METHOD *pmeth,
                                   int (*check) (EVVP_PKEY *pkey))
{
    pmeth->param_check = check;
}

void EVVP_PKEY_meth_set_digest_custom(EVVP_PKEY_METHOD *pmeth,
                                     int (*digest_custom) (EVVP_PKEY_CTX *ctx,
                                                           EVVP_MD_CTX *mctx))
{
    pmeth->digest_custom = digest_custom;
}

void EVVP_PKEY_meth_get_init(const EVVP_PKEY_METHOD *pmeth,
                            int (**pinit) (EVVP_PKEY_CTX *ctx))
{
    *pinit = pmeth->init;
}

void EVVP_PKEY_meth_get_copy(const EVVP_PKEY_METHOD *pmeth,
                            int (**pcopy) (EVVP_PKEY_CTX *dst,
                                           EVVP_PKEY_CTX *src))
{
    *pcopy = pmeth->copy;
}

void EVVP_PKEY_meth_get_cleanup(const EVVP_PKEY_METHOD *pmeth,
                               void (**pcleanup) (EVVP_PKEY_CTX *ctx))
{
    *pcleanup = pmeth->cleanup;
}

void EVVP_PKEY_meth_get_paramgen(const EVVP_PKEY_METHOD *pmeth,
                                int (**pparamgen_init) (EVVP_PKEY_CTX *ctx),
                                int (**pparamgen) (EVVP_PKEY_CTX *ctx,
                                                   EVVP_PKEY *pkey))
{
    if (pparamgen_init)
        *pparamgen_init = pmeth->paramgen_init;
    if (pparamgen)
        *pparamgen = pmeth->paramgen;
}

void EVVP_PKEY_meth_get_keygen(const EVVP_PKEY_METHOD *pmeth,
                              int (**pkeygen_init) (EVVP_PKEY_CTX *ctx),
                              int (**pkeygen) (EVVP_PKEY_CTX *ctx,
                                               EVVP_PKEY *pkey))
{
    if (pkeygen_init)
        *pkeygen_init = pmeth->keygen_init;
    if (pkeygen)
        *pkeygen = pmeth->keygen;
}

void EVVP_PKEY_meth_get_sign(const EVVP_PKEY_METHOD *pmeth,
                            int (**psign_init) (EVVP_PKEY_CTX *ctx),
                            int (**psign) (EVVP_PKEY_CTX *ctx,
                                           unsigned char *sig, size_t *siglen,
                                           const unsigned char *tbs,
                                           size_t tbslen))
{
    if (psign_init)
        *psign_init = pmeth->sign_init;
    if (psign)
        *psign = pmeth->sign;
}

void EVVP_PKEY_meth_get_verify(const EVVP_PKEY_METHOD *pmeth,
                              int (**pverify_init) (EVVP_PKEY_CTX *ctx),
                              int (**pverify) (EVVP_PKEY_CTX *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
{
    if (pverify_init)
        *pverify_init = pmeth->verify_init;
    if (pverify)
        *pverify = pmeth->verify;
}

void EVVP_PKEY_meth_get_verify_recover(const EVVP_PKEY_METHOD *pmeth,
                                      int (**pverify_recover_init) (EVVP_PKEY_CTX
                                                                    *ctx),
                                      int (**pverify_recover) (EVVP_PKEY_CTX
                                                               *ctx,
                                                               unsigned char
                                                               *sig,
                                                               size_t *siglen,
                                                               const unsigned
                                                               char *tbs,
                                                               size_t tbslen))
{
    if (pverify_recover_init)
        *pverify_recover_init = pmeth->verify_recover_init;
    if (pverify_recover)
        *pverify_recover = pmeth->verify_recover;
}

void EVVP_PKEY_meth_get_signctx(const EVVP_PKEY_METHOD *pmeth,
                               int (**psignctx_init) (EVVP_PKEY_CTX *ctx,
                                                      EVVP_MD_CTX *mctx),
                               int (**psignctx) (EVVP_PKEY_CTX *ctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 EVVP_MD_CTX *mctx))
{
    if (psignctx_init)
        *psignctx_init = pmeth->signctx_init;
    if (psignctx)
        *psignctx = pmeth->signctx;
}

void EVVP_PKEY_meth_get_verifyctx(const EVVP_PKEY_METHOD *pmeth,
                                 int (**pverifyctx_init) (EVVP_PKEY_CTX *ctx,
                                                          EVVP_MD_CTX *mctx),
                                 int (**pverifyctx) (EVVP_PKEY_CTX *ctx,
                                                     const unsigned char *sig,
                                                     int siglen,
                                                     EVVP_MD_CTX *mctx))
{
    if (pverifyctx_init)
        *pverifyctx_init = pmeth->verifyctx_init;
    if (pverifyctx)
        *pverifyctx = pmeth->verifyctx;
}

void EVVP_PKEY_meth_get_encrypt(const EVVP_PKEY_METHOD *pmeth,
                               int (**pencrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (**pencryptfn) (EVVP_PKEY_CTX *ctx,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   const unsigned char *in,
                                                   size_t inlen))
{
    if (pencrypt_init)
        *pencrypt_init = pmeth->encrypt_init;
    if (pencryptfn)
        *pencryptfn = pmeth->encrypt;
}

void EVVP_PKEY_meth_get_decrypt(const EVVP_PKEY_METHOD *pmeth,
                               int (**pdecrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (**pdecrypt) (EVVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    if (pdecrypt_init)
        *pdecrypt_init = pmeth->decrypt_init;
    if (pdecrypt)
        *pdecrypt = pmeth->decrypt;
}

void EVVP_PKEY_meth_get_derive(const EVVP_PKEY_METHOD *pmeth,
                              int (**pderive_init) (EVVP_PKEY_CTX *ctx),
                              int (**pderive) (EVVP_PKEY_CTX *ctx,
                                               unsigned char *key,
                                               size_t *keylen))
{
    if (pderive_init)
        *pderive_init = pmeth->derive_init;
    if (pderive)
        *pderive = pmeth->derive;
}

void EVVP_PKEY_meth_get_ctrl(const EVVP_PKEY_METHOD *pmeth,
                            int (**pctrl) (EVVP_PKEY_CTX *ctx, int type, int p1,
                                           void *p2),
                            int (**pctrl_str) (EVVP_PKEY_CTX *ctx,
                                               const char *type,
                                               const char *value))
{
    if (pctrl)
        *pctrl = pmeth->ctrl;
    if (pctrl_str)
        *pctrl_str = pmeth->ctrl_str;
}

void EVVP_PKEY_meth_get_digestsign(EVVP_PKEY_METHOD *pmeth,
    int (**digestsign) (EVVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen))
{
    if (digestsign)
        *digestsign = pmeth->digestsign;
}

void EVVP_PKEY_meth_get_digestverify(EVVP_PKEY_METHOD *pmeth,
    int (**digestverify) (EVVP_MD_CTX *ctx, const unsigned char *sig,
                          size_t siglen, const unsigned char *tbs,
                          size_t tbslen))
{
    if (digestverify)
        *digestverify = pmeth->digestverify;
}

void EVVP_PKEY_meth_get_check(const EVVP_PKEY_METHOD *pmeth,
                             int (**pcheck) (EVVP_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->check;
}

void EVVP_PKEY_meth_get_public_check(const EVVP_PKEY_METHOD *pmeth,
                                    int (**pcheck) (EVVP_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->public_check;
}

void EVVP_PKEY_meth_get_param_check(const EVVP_PKEY_METHOD *pmeth,
                                   int (**pcheck) (EVVP_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->param_check;
}

void EVVP_PKEY_meth_get_digest_custom(EVVP_PKEY_METHOD *pmeth,
                                     int (**pdigest_custom) (EVVP_PKEY_CTX *ctx,
                                                             EVVP_MD_CTX *mctx))
{
    if (pdigest_custom != NULL)
        *pdigest_custom = pmeth->digest_custom;
}
