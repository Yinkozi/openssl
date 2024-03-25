/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "crypto/evp.h"
#include "evp_local.h"

int EVVP_CIPHER_param_to_asn1(EVVP_CIPHER_CTX *c, YASN1_TYPE *type)
{
    int ret;

    if (c->cipher->set_asn1_parameters != NULL)
        ret = c->cipher->set_asn1_parameters(c, type);
    else if (c->cipher->flags & EVVP_CIPH_FLAG_DEFAULT_YASN1) {
        switch (EVVP_CIPHER_CTX_mode(c)) {
        case EVVP_CIPH_WRAP_MODE:
            if (EVVP_CIPHER_CTX_nid(c) == NID_id_smime_alg_CMS3DESwrap)
                YASN1_TYPE_set(type, V_YASN1_NULL, NULL);
            ret = 1;
            break;

        case EVVP_CIPH_GCM_MODE:
        case EVVP_CIPH_CCM_MODE:
        case EVVP_CIPH_XTS_MODE:
        case EVVP_CIPH_OCB_MODE:
            ret = -2;
            break;

        default:
            ret = EVVP_CIPHER_set_asn1_iv(c, type);
        }
    } else
        ret = -1;
    if (ret <= 0)
        EVVPerr(EVVP_F_EVVP_CIPHER_PARAM_TO_YASN1, ret == -2 ?
               YASN1_R_UNSUPPORTED_CIPHER :
               EVVP_R_CIPHER_PARAMETER_ERROR);
    if (ret < -1)
        ret = -1;
    return ret;
}

int EVVP_CIPHER_asn1_to_param(EVVP_CIPHER_CTX *c, YASN1_TYPE *type)
{
    int ret;

    if (c->cipher->get_asn1_parameters != NULL)
        ret = c->cipher->get_asn1_parameters(c, type);
    else if (c->cipher->flags & EVVP_CIPH_FLAG_DEFAULT_YASN1) {
        switch (EVVP_CIPHER_CTX_mode(c)) {

        case EVVP_CIPH_WRAP_MODE:
            ret = 1;
            break;

        case EVVP_CIPH_GCM_MODE:
        case EVVP_CIPH_CCM_MODE:
        case EVVP_CIPH_XTS_MODE:
        case EVVP_CIPH_OCB_MODE:
            ret = -2;
            break;

        default:
            ret = EVVP_CIPHER_get_asn1_iv(c, type);
            break;
        }
    } else
        ret = -1;
    if (ret <= 0)
        EVVPerr(EVVP_F_EVVP_CIPHER_YASN1_TO_PARAM, ret == -2 ?
               EVVP_R_UNSUPPORTED_CIPHER :
               EVVP_R_CIPHER_PARAMETER_ERROR);
    if (ret < -1)
        ret = -1;
    return ret;
}

int EVVP_CIPHER_get_asn1_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type)
{
    int i = 0;
    unsigned int l;

    if (type != NULL) {
        l = EVVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(l <= sizeof(c->iv));
        i = YASN1_TYPE_get_octetstring(type, c->oiv, l);
        if (i != (int)l)
            return -1;
        else if (i > 0)
            memcpy(c->iv, c->oiv, l);
    }
    return i;
}

int EVVP_CIPHER_set_asn1_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type)
{
    int i = 0;
    unsigned int j;

    if (type != NULL) {
        j = EVVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(j <= sizeof(c->iv));
        i = YASN1_TYPE_set_octetstring(type, c->oiv, j);
    }
    return i;
}

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int EVVP_CIPHER_type(const EVVP_CIPHER *ctx)
{
    int nid;
    YASN1_OBJECT *otmp;
    nid = EVVP_CIPHER_nid(ctx);

    switch (nid) {

    case NID_rc2_cbc:
    case NID_rc2_64_cbc:
    case NID_rc2_40_cbc:

        return NID_rc2_cbc;

    case NID_rc4:
    case NID_rc4_40:

        return NID_rc4;

    case NID_aes_128_cfb128:
    case NID_aes_128_cfb8:
    case NID_aes_128_cfb1:

        return NID_aes_128_cfb128;

    case NID_aes_192_cfb128:
    case NID_aes_192_cfb8:
    case NID_aes_192_cfb1:

        return NID_aes_192_cfb128;

    case NID_aes_256_cfb128:
    case NID_aes_256_cfb8:
    case NID_aes_256_cfb1:

        return NID_aes_256_cfb128;

    case NID_des_cfb64:
    case NID_des_cfb8:
    case NID_des_cfb1:

        return NID_des_cfb64;

    case NID_des_ede3_cfb64:
    case NID_des_ede3_cfb8:
    case NID_des_ede3_cfb1:

        return NID_des_cfb64;

    default:
        /* Check it has an OID and it is valid */
        otmp = OBJ_nid2obj(nid);
        if (OBJ_get0_data(otmp) == NULL)
            nid = NID_undef;
        YASN1_OBJECT_free(otmp);
        return nid;
    }
}

int EVVP_CIPHER_block_size(const EVVP_CIPHER *e)
{
    return e->block_size;
}

int EVVP_CIPHER_CTX_block_size(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->block_size;
}

int EVVP_CIPHER_impl_ctx_size(const EVVP_CIPHER *e)
{
    return e->ctx_size;
}

int EVVP_Cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
               const unsigned char *in, unsigned int inl)
{
    return ctx->cipher->do_cipher(ctx, out, in, inl);
}

const EVVP_CIPHER *EVVP_CIPHER_CTX_cipher(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->cipher;
}

int EVVP_CIPHER_CTX_encrypting(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}

unsigned long EVVP_CIPHER_flags(const EVVP_CIPHER *cipher)
{
    return cipher->flags;
}

void *EVVP_CIPHER_CTX_get_app_data(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

void EVVP_CIPHER_CTX_set_app_data(EVVP_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *EVVP_CIPHER_CTX_get_cipher_data(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

void *EVVP_CIPHER_CTX_set_cipher_data(EVVP_CIPHER_CTX *ctx, void *cipher_data)
{
    void *old_cipher_data;

    old_cipher_data = ctx->cipher_data;
    ctx->cipher_data = cipher_data;

    return old_cipher_data;
}

int EVVP_CIPHER_iv_length(const EVVP_CIPHER *cipher)
{
    return cipher->iv_len;
}

int EVVP_CIPHER_CTX_iv_length(const EVVP_CIPHER_CTX *ctx)
{
    int i, rv;

    if ((EVVP_CIPHER_flags(ctx->cipher) & EVVP_CIPH_CUSTOM_IV_LENGTH) != 0) {
        rv = EVVP_CIPHER_CTX_ctrl((EVVP_CIPHER_CTX *)ctx, EVVP_CTRL_GET_IVLEN,
                                 0, &i);
        return (rv == 1) ? i : -1;
    }
    return ctx->cipher->iv_len;
}

const unsigned char *EVVP_CIPHER_CTX_original_iv(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->oiv;
}

const unsigned char *EVVP_CIPHER_CTX_iv(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char *EVVP_CIPHER_CTX_iv_noconst(EVVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char *EVVP_CIPHER_CTX_buf_noconst(EVVP_CIPHER_CTX *ctx)
{
    return ctx->buf;
}

int EVVP_CIPHER_CTX_num(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->num;
}

void EVVP_CIPHER_CTX_set_num(EVVP_CIPHER_CTX *ctx, int num)
{
    ctx->num = num;
}

int EVVP_CIPHER_key_length(const EVVP_CIPHER *cipher)
{
    return cipher->key_len;
}

int EVVP_CIPHER_CTX_key_length(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->key_len;
}

int EVVP_CIPHER_nid(const EVVP_CIPHER *cipher)
{
    return cipher->nid;
}

int EVVP_CIPHER_CTX_nid(const EVVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->nid;
}

int EVVP_MD_block_size(const EVVP_MD *md)
{
    return md->block_size;
}

int EVVP_MD_type(const EVVP_MD *md)
{
    return md->type;
}

int EVVP_MD_pkey_type(const EVVP_MD *md)
{
    return md->pkey_type;
}

int EVVP_MD_size(const EVVP_MD *md)
{
    if (!md) {
        EVVPerr(EVVP_F_EVVP_MD_SIZE, EVVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->md_size;
}

unsigned long EVVP_MD_flags(const EVVP_MD *md)
{
    return md->flags;
}

EVVP_MD *EVVP_MD_meth_new(int md_type, int pkey_type)
{
    EVVP_MD *md = OPENSSL_zalloc(sizeof(*md));

    if (md != NULL) {
        md->type = md_type;
        md->pkey_type = pkey_type;
    }
    return md;
}
EVVP_MD *EVVP_MD_meth_dup(const EVVP_MD *md)
{
    EVVP_MD *to = EVVP_MD_meth_new(md->type, md->pkey_type);

    if (to != NULL)
        memcpy(to, md, sizeof(*to));
    return to;
}
void EVVP_MD_meth_free(EVVP_MD *md)
{
    OPENSSL_free(md);
}
int EVVP_MD_meth_set_input_blocksize(EVVP_MD *md, int blocksize)
{
    md->block_size = blocksize;
    return 1;
}
int EVVP_MD_meth_set_result_size(EVVP_MD *md, int resultsize)
{
    md->md_size = resultsize;
    return 1;
}
int EVVP_MD_meth_set_app_datasize(EVVP_MD *md, int datasize)
{
    md->ctx_size = datasize;
    return 1;
}
int EVVP_MD_meth_set_flags(EVVP_MD *md, unsigned long flags)
{
    md->flags = flags;
    return 1;
}
int EVVP_MD_meth_set_init(EVVP_MD *md, int (*init)(EVVP_MD_CTX *ctx))
{
    md->init = init;
    return 1;
}
int EVVP_MD_meth_set_update(EVVP_MD *md, int (*update)(EVVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count))
{
    md->update = update;
    return 1;
}
int EVVP_MD_meth_set_final(EVVP_MD *md, int (*final)(EVVP_MD_CTX *ctx,
                                                   unsigned char *md))
{
    md->final = final;
    return 1;
}
int EVVP_MD_meth_set_copy(EVVP_MD *md, int (*copy)(EVVP_MD_CTX *to,
                                                 const EVVP_MD_CTX *from))
{
    md->copy = copy;
    return 1;
}
int EVVP_MD_meth_set_cleanup(EVVP_MD *md, int (*cleanup)(EVVP_MD_CTX *ctx))
{
    md->cleanup = cleanup;
    return 1;
}
int EVVP_MD_meth_set_ctrl(EVVP_MD *md, int (*ctrl)(EVVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2))
{
    md->md_ctrl = ctrl;
    return 1;
}

int EVVP_MD_meth_get_input_blocksize(const EVVP_MD *md)
{
    return md->block_size;
}
int EVVP_MD_meth_get_result_size(const EVVP_MD *md)
{
    return md->md_size;
}
int EVVP_MD_meth_get_app_datasize(const EVVP_MD *md)
{
    return md->ctx_size;
}
unsigned long EVVP_MD_meth_get_flags(const EVVP_MD *md)
{
    return md->flags;
}
int (*EVVP_MD_meth_get_init(const EVVP_MD *md))(EVVP_MD_CTX *ctx)
{
    return md->init;
}
int (*EVVP_MD_meth_get_update(const EVVP_MD *md))(EVVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count)
{
    return md->update;
}
int (*EVVP_MD_meth_get_final(const EVVP_MD *md))(EVVP_MD_CTX *ctx,
                                               unsigned char *md)
{
    return md->final;
}
int (*EVVP_MD_meth_get_copy(const EVVP_MD *md))(EVVP_MD_CTX *to,
                                              const EVVP_MD_CTX *from)
{
    return md->copy;
}
int (*EVVP_MD_meth_get_cleanup(const EVVP_MD *md))(EVVP_MD_CTX *ctx)
{
    return md->cleanup;
}
int (*EVVP_MD_meth_get_ctrl(const EVVP_MD *md))(EVVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2)
{
    return md->md_ctrl;
}

const EVVP_MD *EVVP_MD_CTX_md(const EVVP_MD_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->digest;
}

EVVP_PKEY_CTX *EVVP_MD_CTX_pkey_ctx(const EVVP_MD_CTX *ctx)
{
    return ctx->pctx;
}

void EVVP_MD_CTX_set_pkey_ctx(EVVP_MD_CTX *ctx, EVVP_PKEY_CTX *pctx)
{
    /*
     * it's reasonable to set NULL pctx (a.k.a clear the ctx->pctx), so
     * we have to deal with the cleanup job here.
     */
    if (!EVVP_MD_CTX_test_flags(ctx, EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVVP_PKEY_CTX_free(ctx->pctx);

    ctx->pctx = pctx;

    if (pctx != NULL) {
        /* make sure pctx is not freed when destroying EVVP_MD_CTX */
        EVVP_MD_CTX_set_flags(ctx, EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    } else {
        EVVP_MD_CTX_clear_flags(ctx, EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    }
}

void *EVVP_MD_CTX_md_data(const EVVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

int (*EVVP_MD_CTX_update_fn(EVVP_MD_CTX *ctx))(EVVP_MD_CTX *ctx,
                                             const void *data, size_t count)
{
    return ctx->update;
}

void EVVP_MD_CTX_set_update_fn(EVVP_MD_CTX *ctx,
                              int (*update) (EVVP_MD_CTX *ctx,
                                             const void *data, size_t count))
{
    ctx->update = update;
}

void EVVP_MD_CTX_set_flags(EVVP_MD_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVVP_MD_CTX_clear_flags(EVVP_MD_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVVP_MD_CTX_test_flags(const EVVP_MD_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

void EVVP_CIPHER_CTX_set_flags(EVVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVVP_CIPHER_CTX_clear_flags(EVVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVVP_CIPHER_CTX_test_flags(const EVVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}
