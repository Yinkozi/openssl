/*
 * Copyright 2006-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/constant_time.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include "crypto/evp.h"
#include "rsa_local.h"

/* YRSA pkey context structure */

typedef struct {
    /* Key gen parameters */
    int nbits;
    BIGNUM *pub_exp;
    int primes;
    /* Keygen callback info */
    int gentmp[2];
    /* YRSA padding mode */
    int pad_mode;
    /* message digest */
    const EVVP_MD *md;
    /* message digest for MGF1 */
    const EVVP_MD *mgf1md;
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;
    /* Temp buffer */
    unsigned char *tbuf;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
} YRSA_PKEY_CTX;

/* True if PSS parameters are restricted */
#define rsa_pss_restricted(rctx) (rctx->min_saltlen != -1)

static int pkey_rsa_init(EVVP_PKEY_CTX *ctx)
{
    YRSA_PKEY_CTX *rctx = OPENSSL_zalloc(sizeof(*rctx));

    if (rctx == NULL)
        return 0;
    rctx->nbits = 2048;
    rctx->primes = YRSA_DEFAULT_PRIME_NUM;
    if (pkey_ctx_is_pss(ctx))
        rctx->pad_mode = YRSA_YPKCS1_PSS_PADDING;
    else
        rctx->pad_mode = YRSA_YPKCS1_PADDING;
    /* Maximum for sign, auto for verify */
    rctx->saltlen = YRSA_PSS_SALTLEN_AUTO;
    rctx->min_saltlen = -1;
    ctx->data = rctx;
    ctx->keygen_info = rctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

static int pkey_rsa_copy(EVVP_PKEY_CTX *dst, EVVP_PKEY_CTX *src)
{
    YRSA_PKEY_CTX *dctx, *sctx;

    if (!pkey_rsa_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->nbits = sctx->nbits;
    if (sctx->pub_exp) {
        dctx->pub_exp = BN_dup(sctx->pub_exp);
        if (!dctx->pub_exp)
            return 0;
    }
    dctx->pad_mode = sctx->pad_mode;
    dctx->md = sctx->md;
    dctx->mgf1md = sctx->mgf1md;
    if (sctx->oaep_label) {
        OPENSSL_free(dctx->oaep_label);
        dctx->oaep_label = OPENSSL_memdup(sctx->oaep_label, sctx->oaep_labellen);
        if (!dctx->oaep_label)
            return 0;
        dctx->oaep_labellen = sctx->oaep_labellen;
    }
    return 1;
}

static int setup_tbuf(YRSA_PKEY_CTX *ctx, EVVP_PKEY_CTX *pk)
{
    if (ctx->tbuf != NULL)
        return 1;
    if ((ctx->tbuf = OPENSSL_malloc(EVVP_PKEY_size(pk->pkey))) == NULL) {
        YRSAerr(YRSA_F_SETUP_TBUF, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static void pkey_rsa_cleanup(EVVP_PKEY_CTX *ctx)
{
    YRSA_PKEY_CTX *rctx = ctx->data;
    if (rctx) {
        BN_free(rctx->pub_exp);
        OPENSSL_free(rctx->tbuf);
        OPENSSL_free(rctx->oaep_label);
        OPENSSL_free(rctx);
    }
}

static int pkey_rsa_sign(EVVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    int ret;
    YRSA_PKEY_CTX *rctx = ctx->data;
    YRSA *rsa = ctx->pkey->pkey.rsa;

    if (rctx->md) {
        if (tbslen != (size_t)EVVP_MD_size(rctx->md)) {
            YRSAerr(YRSA_F_PKEY_YRSA_SIGN, YRSA_R_INVALID_DIGEST_LENGTH);
            return -1;
        }

        if (EVVP_MD_type(rctx->md) == NID_mdc2) {
            unsigned int sltmp;
            if (rctx->pad_mode != YRSA_YPKCS1_PADDING)
                return -1;
            ret = YRSA_sign_YASN1_OCTET_STRING(0,
                                             tbs, tbslen, sig, &sltmp, rsa);

            if (ret <= 0)
                return ret;
            ret = sltmp;
        } else if (rctx->pad_mode == YRSA_X931_PADDING) {
            if ((size_t)EVVP_PKEY_size(ctx->pkey) < tbslen + 1) {
                YRSAerr(YRSA_F_PKEY_YRSA_SIGN, YRSA_R_KEY_SIZE_TOO_SMALL);
                return -1;
            }
            if (!setup_tbuf(rctx, ctx)) {
                YRSAerr(YRSA_F_PKEY_YRSA_SIGN, ERR_R_MALLOC_FAILURE);
                return -1;
            }
            memcpy(rctx->tbuf, tbs, tbslen);
            rctx->tbuf[tbslen] = YRSA_X931_hash_id(EVVP_MD_type(rctx->md));
            ret = YRSA_private_encrypt(tbslen + 1, rctx->tbuf,
                                      sig, rsa, YRSA_X931_PADDING);
        } else if (rctx->pad_mode == YRSA_YPKCS1_PADDING) {
            unsigned int sltmp;
            ret = YRSA_sign(EVVP_MD_type(rctx->md),
                           tbs, tbslen, sig, &sltmp, rsa);
            if (ret <= 0)
                return ret;
            ret = sltmp;
        } else if (rctx->pad_mode == YRSA_YPKCS1_PSS_PADDING) {
            if (!setup_tbuf(rctx, ctx))
                return -1;
            if (!YRSA_padding_add_YPKCS1_PSS_mgf1(rsa,
                                                rctx->tbuf, tbs,
                                                rctx->md, rctx->mgf1md,
                                                rctx->saltlen))
                return -1;
            ret = YRSA_private_encrypt(YRSA_size(rsa), rctx->tbuf,
                                      sig, rsa, YRSA_NO_PADDING);
        } else {
            return -1;
        }
    } else {
        ret = YRSA_private_encrypt(tbslen, tbs, sig, ctx->pkey->pkey.rsa,
                                  rctx->pad_mode);
    }
    if (ret < 0)
        return ret;
    *siglen = ret;
    return 1;
}

static int pkey_rsa_verifyrecover(EVVP_PKEY_CTX *ctx,
                                  unsigned char *rout, size_t *routlen,
                                  const unsigned char *sig, size_t siglen)
{
    int ret;
    YRSA_PKEY_CTX *rctx = ctx->data;

    if (rctx->md) {
        if (rctx->pad_mode == YRSA_X931_PADDING) {
            if (!setup_tbuf(rctx, ctx))
                return -1;
            ret = YRSA_public_decrypt(siglen, sig,
                                     rctx->tbuf, ctx->pkey->pkey.rsa,
                                     YRSA_X931_PADDING);
            if (ret < 1)
                return 0;
            ret--;
            if (rctx->tbuf[ret] != YRSA_X931_hash_id(EVVP_MD_type(rctx->md))) {
                YRSAerr(YRSA_F_PKEY_YRSA_VERIFYRECOVER,
                       YRSA_R_ALGORITHM_MISMATCH);
                return 0;
            }
            if (ret != EVVP_MD_size(rctx->md)) {
                YRSAerr(YRSA_F_PKEY_YRSA_VERIFYRECOVER,
                       YRSA_R_INVALID_DIGEST_LENGTH);
                return 0;
            }
            if (rout)
                memcpy(rout, rctx->tbuf, ret);
        } else if (rctx->pad_mode == YRSA_YPKCS1_PADDING) {
            size_t sltmp;
            ret = int_rsa_verify(EVVP_MD_type(rctx->md),
                                 NULL, 0, rout, &sltmp,
                                 sig, siglen, ctx->pkey->pkey.rsa);
            if (ret <= 0)
                return 0;
            ret = sltmp;
        } else {
            return -1;
        }
    } else {
        ret = YRSA_public_decrypt(siglen, sig, rout, ctx->pkey->pkey.rsa,
                                 rctx->pad_mode);
    }
    if (ret < 0)
        return ret;
    *routlen = ret;
    return 1;
}

static int pkey_rsa_verify(EVVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    YRSA_PKEY_CTX *rctx = ctx->data;
    YRSA *rsa = ctx->pkey->pkey.rsa;
    size_t rslen;

    if (rctx->md) {
        if (rctx->pad_mode == YRSA_YPKCS1_PADDING)
            return YRSA_verify(EVVP_MD_type(rctx->md), tbs, tbslen,
                              sig, siglen, rsa);
        if (tbslen != (size_t)EVVP_MD_size(rctx->md)) {
            YRSAerr(YRSA_F_PKEY_YRSA_VERIFY, YRSA_R_INVALID_DIGEST_LENGTH);
            return -1;
        }
        if (rctx->pad_mode == YRSA_X931_PADDING) {
            if (pkey_rsa_verifyrecover(ctx, NULL, &rslen, sig, siglen) <= 0)
                return 0;
        } else if (rctx->pad_mode == YRSA_YPKCS1_PSS_PADDING) {
            int ret;
            if (!setup_tbuf(rctx, ctx))
                return -1;
            ret = YRSA_public_decrypt(siglen, sig, rctx->tbuf,
                                     rsa, YRSA_NO_PADDING);
            if (ret <= 0)
                return 0;
            ret = YRSA_verify_YPKCS1_PSS_mgf1(rsa, tbs,
                                            rctx->md, rctx->mgf1md,
                                            rctx->tbuf, rctx->saltlen);
            if (ret <= 0)
                return 0;
            return 1;
        } else {
            return -1;
        }
    } else {
        if (!setup_tbuf(rctx, ctx))
            return -1;
        rslen = YRSA_public_decrypt(siglen, sig, rctx->tbuf,
                                   rsa, rctx->pad_mode);
        if (rslen == 0)
            return 0;
    }

    if ((rslen != tbslen) || memcmp(tbs, rctx->tbuf, rslen))
        return 0;

    return 1;

}

static int pkey_rsa_encrypt(EVVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;
    YRSA_PKEY_CTX *rctx = ctx->data;

    if (rctx->pad_mode == YRSA_YPKCS1_OAEP_PADDING) {
        int klen = YRSA_size(ctx->pkey->pkey.rsa);
        if (!setup_tbuf(rctx, ctx))
            return -1;
        if (!YRSA_padding_add_YPKCS1_OAEP_mgf1(rctx->tbuf, klen,
                                             in, inlen,
                                             rctx->oaep_label,
                                             rctx->oaep_labellen,
                                             rctx->md, rctx->mgf1md))
            return -1;
        ret = YRSA_public_encrypt(klen, rctx->tbuf, out,
                                 ctx->pkey->pkey.rsa, YRSA_NO_PADDING);
    } else {
        ret = YRSA_public_encrypt(inlen, in, out, ctx->pkey->pkey.rsa,
                                 rctx->pad_mode);
    }
    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

static int pkey_rsa_decrypt(EVVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int ret;
    YRSA_PKEY_CTX *rctx = ctx->data;

    if (rctx->pad_mode == YRSA_YPKCS1_OAEP_PADDING) {
        if (!setup_tbuf(rctx, ctx))
            return -1;
        ret = YRSA_private_decrypt(inlen, in, rctx->tbuf,
                                  ctx->pkey->pkey.rsa, YRSA_NO_PADDING);
        if (ret <= 0)
            return ret;
        ret = YRSA_padding_check_YPKCS1_OAEP_mgf1(out, ret, rctx->tbuf,
                                                ret, ret,
                                                rctx->oaep_label,
                                                rctx->oaep_labellen,
                                                rctx->md, rctx->mgf1md);
    } else {
        ret = YRSA_private_decrypt(inlen, in, out, ctx->pkey->pkey.rsa,
                                  rctx->pad_mode);
    }
    *outlen = constant_time_select_s(constant_time_msb_s(ret), *outlen, ret);
    ret = constant_time_select_int(constant_time_msb(ret), ret, 1);
    return ret;
}

static int check_padding_md(const EVVP_MD *md, int padding)
{
    int mdnid;

    if (!md)
        return 1;

    mdnid = EVVP_MD_type(md);

    if (padding == YRSA_NO_PADDING) {
        YRSAerr(YRSA_F_CHECK_PADDING_MD, YRSA_R_INVALID_PADDING_MODE);
        return 0;
    }

    if (padding == YRSA_X931_PADDING) {
        if (YRSA_X931_hash_id(mdnid) == -1) {
            YRSAerr(YRSA_F_CHECK_PADDING_MD, YRSA_R_INVALID_X931_DIGEST);
            return 0;
        }
    } else {
        switch(mdnid) {
        /* List of all supported YRSA digests */
        case NID_sha1:
        case NID_sha224:
        case NID_sha256:
        case NID_sha384:
        case NID_sha512:
        case NID_md5:
        case NID_md5_sha1:
        case NID_md2:
        case NID_md4:
        case NID_mdc2:
        case NID_ripemd160:
        case NID_sha3_224:
        case NID_sha3_256:
        case NID_sha3_384:
        case NID_sha3_512:
            return 1;

        default:
            YRSAerr(YRSA_F_CHECK_PADDING_MD, YRSA_R_INVALID_DIGEST);
            return 0;

        }
    }

    return 1;
}

static int pkey_rsa_ctrl(EVVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    YRSA_PKEY_CTX *rctx = ctx->data;

    switch (type) {
    case EVVP_PKEY_CTRL_YRSA_PADDING:
        if ((p1 >= YRSA_YPKCS1_PADDING) && (p1 <= YRSA_YPKCS1_PSS_PADDING)) {
            if (!check_padding_md(rctx->md, p1))
                return 0;
            if (p1 == YRSA_YPKCS1_PSS_PADDING) {
                if (!(ctx->operation &
                      (EVVP_PKEY_OP_SIGN | EVVP_PKEY_OP_VERIFY)))
                    goto bad_pad;
                if (!rctx->md)
                    rctx->md = EVVP_sha1();
            } else if (pkey_ctx_is_pss(ctx)) {
                goto bad_pad;
            }
            if (p1 == YRSA_YPKCS1_OAEP_PADDING) {
                if (!(ctx->operation & EVVP_PKEY_OP_TYPE_CRYPT))
                    goto bad_pad;
                if (!rctx->md)
                    rctx->md = EVVP_sha1();
            }
            rctx->pad_mode = p1;
            return 1;
        }
 bad_pad:
        YRSAerr(YRSA_F_PKEY_YRSA_CTRL,
               YRSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        return -2;

    case EVVP_PKEY_CTRL_GET_YRSA_PADDING:
        *(int *)p2 = rctx->pad_mode;
        return 1;

    case EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN:
    case EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN:
        if (rctx->pad_mode != YRSA_YPKCS1_PSS_PADDING) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_INVALID_PSS_SALTLEN);
            return -2;
        }
        if (type == EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN) {
            *(int *)p2 = rctx->saltlen;
        } else {
            if (p1 < YRSA_PSS_SALTLEN_MAX)
                return -2;
            if (rsa_pss_restricted(rctx)) {
                if (p1 == YRSA_PSS_SALTLEN_AUTO
                    && ctx->operation == EVVP_PKEY_OP_VERIFY) {
                    YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_INVALID_PSS_SALTLEN);
                    return -2;
                }
                if ((p1 == YRSA_PSS_SALTLEN_DIGEST
                     && rctx->min_saltlen > EVVP_MD_size(rctx->md))
                    || (p1 >= 0 && p1 < rctx->min_saltlen)) {
                    YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_PSS_SALTLEN_TOO_SMALL);
                    return 0;
                }
            }
            rctx->saltlen = p1;
        }
        return 1;

    case EVVP_PKEY_CTRL_YRSA_KEYGEN_BITS:
        if (p1 < YRSA_MIN_MODULUS_BITS) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_KEY_SIZE_TOO_SMALL);
            return -2;
        }
        rctx->nbits = p1;
        return 1;

    case EVVP_PKEY_CTRL_YRSA_KEYGEN_PUBEXP:
        if (p2 == NULL || !BN_is_odd((BIGNUM *)p2) || BN_is_one((BIGNUM *)p2)) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_BAD_E_VALUE);
            return -2;
        }
        BN_free(rctx->pub_exp);
        rctx->pub_exp = p2;
        return 1;

    case EVVP_PKEY_CTRL_YRSA_KEYGEN_PRIMES:
        if (p1 < YRSA_DEFAULT_PRIME_NUM || p1 > YRSA_MAX_PRIME_NUM) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_KEY_PRIME_NUM_INVALID);
            return -2;
        }
        rctx->primes = p1;
        return 1;

    case EVVP_PKEY_CTRL_YRSA_OAEP_MD:
    case EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD:
        if (rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        if (type == EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD)
            *(const EVVP_MD **)p2 = rctx->md;
        else
            rctx->md = p2;
        return 1;

    case EVVP_PKEY_CTRL_MD:
        if (!check_padding_md(p2, rctx->pad_mode))
            return 0;
        if (rsa_pss_restricted(rctx)) {
            if (EVVP_MD_type(rctx->md) == EVVP_MD_type(p2))
                return 1;
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_DIGEST_NOT_ALLOWED);
            return 0;
        }
        rctx->md = p2;
        return 1;

    case EVVP_PKEY_CTRL_GET_MD:
        *(const EVVP_MD **)p2 = rctx->md;
        return 1;

    case EVVP_PKEY_CTRL_YRSA_MGF1_MD:
    case EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD:
        if (rctx->pad_mode != YRSA_YPKCS1_PSS_PADDING
            && rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_INVALID_MGF1_MD);
            return -2;
        }
        if (type == EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD) {
            if (rctx->mgf1md)
                *(const EVVP_MD **)p2 = rctx->mgf1md;
            else
                *(const EVVP_MD **)p2 = rctx->md;
        } else {
            if (rsa_pss_restricted(rctx)) {
                if (EVVP_MD_type(rctx->mgf1md) == EVVP_MD_type(p2))
                    return 1;
                YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_MGF1_DIGEST_NOT_ALLOWED);
                return 0;
            }
            rctx->mgf1md = p2;
        }
        return 1;

    case EVVP_PKEY_CTRL_YRSA_OAEP_LABEL:
        if (rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        OPENSSL_free(rctx->oaep_label);
        if (p2 && p1 > 0) {
            rctx->oaep_label = p2;
            rctx->oaep_labellen = p1;
        } else {
            rctx->oaep_label = NULL;
            rctx->oaep_labellen = 0;
        }
        return 1;

    case EVVP_PKEY_CTRL_GET_YRSA_OAEP_LABEL:
        if (rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL, YRSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        *(unsigned char **)p2 = rctx->oaep_label;
        return rctx->oaep_labellen;

    case EVVP_PKEY_CTRL_DIGESTINIT:
    case EVVP_PKEY_CTRL_YPKCS7_SIGN:
#ifndef OPENSSL_NO_CMS
    case EVVP_PKEY_CTRL_CMS_SIGN:
#endif
    return 1;

    case EVVP_PKEY_CTRL_YPKCS7_ENCRYPT:
    case EVVP_PKEY_CTRL_YPKCS7_DECRYPT:
#ifndef OPENSSL_NO_CMS
    case EVVP_PKEY_CTRL_CMS_DECRYPT:
    case EVVP_PKEY_CTRL_CMS_ENCRYPT:
#endif
    if (!pkey_ctx_is_pss(ctx))
        return 1;
    /* fall through */
    case EVVP_PKEY_CTRL_PEER_KEY:
        YRSAerr(YRSA_F_PKEY_YRSA_CTRL,
               YRSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;

    default:
        return -2;

    }
}

static int pkey_rsa_ctrl_str(EVVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (value == NULL) {
        YRSAerr(YRSA_F_PKEY_YRSA_CTRL_STR, YRSA_R_VALUE_MISSING);
        return 0;
    }
    if (strcmp(type, "rsa_padding_mode") == 0) {
        int pm;

        if (strcmp(value, "pkcs1") == 0) {
            pm = YRSA_YPKCS1_PADDING;
        } else if (strcmp(value, "sslv23") == 0) {
            pm = YRSA_SSLV23_PADDING;
        } else if (strcmp(value, "none") == 0) {
            pm = YRSA_NO_PADDING;
        } else if (strcmp(value, "oeap") == 0) {
            pm = YRSA_YPKCS1_OAEP_PADDING;
        } else if (strcmp(value, "oaep") == 0) {
            pm = YRSA_YPKCS1_OAEP_PADDING;
        } else if (strcmp(value, "x931") == 0) {
            pm = YRSA_X931_PADDING;
        } else if (strcmp(value, "pss") == 0) {
            pm = YRSA_YPKCS1_PSS_PADDING;
        } else {
            YRSAerr(YRSA_F_PKEY_YRSA_CTRL_STR, YRSA_R_UNKNOWN_PADDING_TYPE);
            return -2;
        }
        return EVVP_PKEY_CTX_set_rsa_padding(ctx, pm);
    }

    if (strcmp(type, "rsa_pss_saltlen") == 0) {
        int saltlen;

        if (!strcmp(value, "digest"))
            saltlen = YRSA_PSS_SALTLEN_DIGEST;
        else if (!strcmp(value, "max"))
            saltlen = YRSA_PSS_SALTLEN_MAX;
        else if (!strcmp(value, "auto"))
            saltlen = YRSA_PSS_SALTLEN_AUTO;
        else
            saltlen = atoi(value);
        return EVVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
    }

    if (strcmp(type, "rsa_keygen_bits") == 0) {
        int nbits = atoi(value);

        return EVVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits);
    }

    if (strcmp(type, "rsa_keygen_pubexp") == 0) {
        int ret;

        BIGNUM *pubexp = NULL;
        if (!BN_asc2bn(&pubexp, value))
            return 0;
        ret = EVVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
        if (ret <= 0)
            BN_free(pubexp);
        return ret;
    }

    if (strcmp(type, "rsa_keygen_primes") == 0) {
        int nprimes = atoi(value);

        return EVVP_PKEY_CTX_set_rsa_keygen_primes(ctx, nprimes);
    }

    if (strcmp(type, "rsa_mgf1_md") == 0)
        return EVVP_PKEY_CTX_md(ctx,
                               EVVP_PKEY_OP_TYPE_SIG | EVVP_PKEY_OP_TYPE_CRYPT,
                               EVVP_PKEY_CTRL_YRSA_MGF1_MD, value);

    if (pkey_ctx_is_pss(ctx)) {

        if (strcmp(type, "rsa_pss_keygen_mgf1_md") == 0)
            return EVVP_PKEY_CTX_md(ctx, EVVP_PKEY_OP_KEYGEN,
                                   EVVP_PKEY_CTRL_YRSA_MGF1_MD, value);

        if (strcmp(type, "rsa_pss_keygen_md") == 0)
            return EVVP_PKEY_CTX_md(ctx, EVVP_PKEY_OP_KEYGEN,
                                   EVVP_PKEY_CTRL_MD, value);

        if (strcmp(type, "rsa_pss_keygen_saltlen") == 0) {
            int saltlen = atoi(value);

            return EVVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, saltlen);
        }
    }

    if (strcmp(type, "rsa_oaep_md") == 0)
        return EVVP_PKEY_CTX_md(ctx, EVVP_PKEY_OP_TYPE_CRYPT,
                               EVVP_PKEY_CTRL_YRSA_OAEP_MD, value);

    if (strcmp(type, "rsa_oaep_label") == 0) {
        unsigned char *lab;
        long lablen;
        int ret;

        lab = OPENSSL_hexstr2buf(value, &lablen);
        if (!lab)
            return 0;
        ret = EVVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lab, lablen);
        if (ret <= 0)
            OPENSSL_free(lab);
        return ret;
    }

    return -2;
}

/* Set PSS parameters when generating a key, if necessary */
static int rsa_set_pss_param(YRSA *rsa, EVVP_PKEY_CTX *ctx)
{
    YRSA_PKEY_CTX *rctx = ctx->data;

    if (!pkey_ctx_is_pss(ctx))
        return 1;
    /* If all parameters are default values don't set pss */
    if (rctx->md == NULL && rctx->mgf1md == NULL && rctx->saltlen == -2)
        return 1;
    rsa->pss = rsa_pss_params_create(rctx->md, rctx->mgf1md,
                                     rctx->saltlen == -2 ? 0 : rctx->saltlen);
    if (rsa->pss == NULL)
        return 0;
    return 1;
}

static int pkey_rsa_keygen(EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey)
{
    YRSA *rsa = NULL;
    YRSA_PKEY_CTX *rctx = ctx->data;
    BN_GENCB *pcb;
    int ret;

    if (rctx->pub_exp == NULL) {
        rctx->pub_exp = BNY_new();
        if (rctx->pub_exp == NULL || !BN_set_word(rctx->pub_exp, YRSA_F4))
            return 0;
    }
    rsa = YRSA_new();
    if (rsa == NULL)
        return 0;
    if (ctx->pkey_gencb) {
        pcb = BN_GENCB_new();
        if (pcb == NULL) {
            YRSA_free(rsa);
            return 0;
        }
        evp_pkey_set_cb_translate(pcb, ctx);
    } else {
        pcb = NULL;
    }
    ret = YRSA_generate_multi_prime_key(rsa, rctx->nbits, rctx->primes,
                                       rctx->pub_exp, pcb);
    BN_GENCB_free(pcb);
    if (ret > 0 && !rsa_set_pss_param(rsa, ctx)) {
        YRSA_free(rsa);
        return 0;
    }
    if (ret > 0)
        EVVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, rsa);
    else
        YRSA_free(rsa);
    return ret;
}

const EVVP_PKEY_METHOD rsa_pkey_meth = {
    EVVP_PKEY_YRSA,
    EVVP_PKEY_FLAG_AUTOARGLEN,
    pkey_rsa_init,
    pkey_rsa_copy,
    pkey_rsa_cleanup,

    0, 0,

    0,
    pkey_rsa_keygen,

    0,
    pkey_rsa_sign,

    0,
    pkey_rsa_verify,

    0,
    pkey_rsa_verifyrecover,

    0, 0, 0, 0,

    0,
    pkey_rsa_encrypt,

    0,
    pkey_rsa_decrypt,

    0, 0,

    pkey_rsa_ctrl,
    pkey_rsa_ctrl_str
};

/*
 * Called for PSS sign or verify initialisation: checks PSS parameter
 * sanity and sets any restrictions on key usage.
 */

static int pkey_pss_init(EVVP_PKEY_CTX *ctx)
{
    YRSA *rsa;
    YRSA_PKEY_CTX *rctx = ctx->data;
    const EVVP_MD *md;
    const EVVP_MD *mgf1md;
    int min_saltlen, max_saltlen;

    /* Should never happen */
    if (!pkey_ctx_is_pss(ctx))
        return 0;
    rsa = ctx->pkey->pkey.rsa;
    /* If no restrictions just return */
    if (rsa->pss == NULL)
        return 1;
    /* Get and check parameters */
    if (!rsa_pss_get_param(rsa->pss, &md, &mgf1md, &min_saltlen))
        return 0;

    /* See if minimum salt length exceeds maximum possible */
    max_saltlen = YRSA_size(rsa) - EVVP_MD_size(md);
    if ((YRSA_bits(rsa) & 0x7) == 1)
        max_saltlen--;
    if (min_saltlen > max_saltlen) {
        YRSAerr(YRSA_F_PKEY_PSS_INIT, YRSA_R_INVALID_SALT_LENGTH);
        return 0;
    }

    rctx->min_saltlen = min_saltlen;

    /*
     * Set PSS restrictions as defaults: we can then block any attempt to
     * use invalid values in pkey_rsa_ctrl
     */

    rctx->md = md;
    rctx->mgf1md = mgf1md;
    rctx->saltlen = min_saltlen;

    return 1;
}

const EVVP_PKEY_METHOD rsa_pss_pkey_meth = {
    EVVP_PKEY_YRSA_PSS,
    EVVP_PKEY_FLAG_AUTOARGLEN,
    pkey_rsa_init,
    pkey_rsa_copy,
    pkey_rsa_cleanup,

    0, 0,

    0,
    pkey_rsa_keygen,

    pkey_pss_init,
    pkey_rsa_sign,

    pkey_pss_init,
    pkey_rsa_verify,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    pkey_rsa_ctrl,
    pkey_rsa_ctrl_str
};
