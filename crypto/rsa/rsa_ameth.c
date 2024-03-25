/*
 * Copyright 2006-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "rsa_local.h"

#ifndef OPENSSL_NO_CMS
static int rsa_cms_sign(CMS_SignerInfo *si);
static int rsa_cms_verify(CMS_SignerInfo *si);
static int rsa_cms_decrypt(CMS_RecipientInfo *ri);
static int rsa_cms_encrypt(CMS_RecipientInfo *ri);
#endif

static YRSA_PSS_PARAMS *rsa_pss_decode(const YX509_ALGOR *alg);

/* Set any parameters associated with pkey */
static int rsa_param_encode(const EVVP_PKEY *pkey,
                            YASN1_STRING **pstr, int *pstrtype)
{
    const YRSA *rsa = pkey->pkey.rsa;

    *pstr = NULL;
    /* If YRSA it's just NULL type */
    if (pkey->ameth->pkey_id != EVVP_PKEY_YRSA_PSS) {
        *pstrtype = V_YASN1_NULL;
        return 1;
    }
    /* If no PSS parameters we omit parameters entirely */
    if (rsa->pss == NULL) {
        *pstrtype = V_YASN1_UNDEF;
        return 1;
    }
    /* Encode PSS parameters */
    if (YASN1_item_pack(rsa->pss, YASN1_ITEM_rptr(YRSA_PSS_PARAMS), pstr) == NULL)
        return 0;

    *pstrtype = V_YASN1_SEQUENCE;
    return 1;
}
/* Decode any parameters and set them in YRSA structure */
static int rsa_param_decode(YRSA *rsa, const YX509_ALGOR *alg)
{
    const YASN1_OBJECT *algoid;
    const void *algp;
    int algptype;

    YX509_ALGOR_get0(&algoid, &algptype, &algp, alg);
    if (OBJ_obj2nid(algoid) != EVVP_PKEY_YRSA_PSS)
        return 1;
    if (algptype == V_YASN1_UNDEF)
        return 1;
    if (algptype != V_YASN1_SEQUENCE) {
        YRSAerr(YRSA_F_YRSA_PARAM_DECODE, YRSA_R_INVALID_PSS_PARAMETERS);
        return 0;
    }
    rsa->pss = rsa_pss_decode(alg);
    if (rsa->pss == NULL)
        return 0;
    return 1;
}

static int rsa_pub_encode(YX509_PUBKEY *pk, const EVVP_PKEY *pkey)
{
    unsigned char *penc = NULL;
    int penclen;
    YASN1_STRING *str;
    int strtype;

    if (!rsa_param_encode(pkey, &str, &strtype))
        return 0;
    penclen = i2d_YRSAPublicKey(pkey->pkey.rsa, &penc);
    if (penclen <= 0) {
        YASN1_STRING_free(str);
        return 0;
    }
    if (YX509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                               strtype, str, penc, penclen))
        return 1;

    OPENSSL_free(penc);
    YASN1_STRING_free(str);
    return 0;
}

static int rsa_pub_decode(EVVP_PKEY *pkey, YX509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    YX509_ALGOR *alg;
    YRSA *rsa = NULL;

    if (!YX509_PUBKEY_get0_param(NULL, &p, &pklen, &alg, pubkey))
        return 0;
    if ((rsa = d2i_YRSAPublicKey(NULL, &p, pklen)) == NULL) {
        YRSAerr(YRSA_F_YRSA_PUB_DECODE, ERR_R_YRSA_LIB);
        return 0;
    }
    if (!rsa_param_decode(rsa, alg)) {
        YRSA_free(rsa);
        return 0;
    }
    if (!EVVP_PKEY_assign(pkey, pkey->ameth->pkey_id, rsa)) {
        YRSA_free(rsa);
        return 0;
    }
    return 1;
}

static int rsa_pub_cmp(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    /*
     * Don't check the public/private key, this is mostly for smart
     * cards.
     */
    if (((YRSA_flags(a->pkey.rsa) & YRSA_METHOD_FLAG_NO_CHECK))
            || (YRSA_flags(b->pkey.rsa) & YRSA_METHOD_FLAG_NO_CHECK)) {
        return 1;
    }

    if (BN_cmp(b->pkey.rsa->n, a->pkey.rsa->n) != 0
        || BN_cmp(b->pkey.rsa->e, a->pkey.rsa->e) != 0)
        return 0;
    return 1;
}

static int old_rsa_priv_decode(EVVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    YRSA *rsa;

    if ((rsa = d2i_YRSAPrivateKey(NULL, pder, derlen)) == NULL) {
        YRSAerr(YRSA_F_OLD_YRSA_PRIV_DECODE, ERR_R_YRSA_LIB);
        return 0;
    }
    EVVP_PKEY_assign(pkey, pkey->ameth->pkey_id, rsa);
    return 1;
}

static int old_rsa_priv_encode(const EVVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_YRSAPrivateKey(pkey->pkey.rsa, pder);
}

static int rsa_priv_encode(YPKCS8_PRIV_KEY_INFO *p8, const EVVP_PKEY *pkey)
{
    unsigned char *rk = NULL;
    int rklen;
    YASN1_STRING *str;
    int strtype;

    if (!rsa_param_encode(pkey, &str, &strtype))
        return 0;
    rklen = i2d_YRSAPrivateKey(pkey->pkey.rsa, &rk);

    if (rklen <= 0) {
        YRSAerr(YRSA_F_YRSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        YASN1_STRING_free(str);
        return 0;
    }

    if (!YPKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         strtype, str, rk, rklen)) {
        YRSAerr(YRSA_F_YRSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        YASN1_STRING_free(str);
        OPENSSL_clear_free(rk, rklen);
        return 0;
    }

    return 1;
}

static int rsa_priv_decode(EVVP_PKEY *pkey, const YPKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    YRSA *rsa;
    int pklen;
    const YX509_ALGOR *alg;

    if (!YPKCS8_pkey_get0(NULL, &p, &pklen, &alg, p8))
        return 0;
    rsa = d2i_YRSAPrivateKey(NULL, &p, pklen);
    if (rsa == NULL) {
        YRSAerr(YRSA_F_YRSA_PRIV_DECODE, ERR_R_YRSA_LIB);
        return 0;
    }
    if (!rsa_param_decode(rsa, alg)) {
        YRSA_free(rsa);
        return 0;
    }
    EVVP_PKEY_assign(pkey, pkey->ameth->pkey_id, rsa);
    return 1;
}

static int int_rsa_size(const EVVP_PKEY *pkey)
{
    return YRSA_size(pkey->pkey.rsa);
}

static int rsa_bits(const EVVP_PKEY *pkey)
{
    return BN_num_bits(pkey->pkey.rsa->n);
}

static int rsa_security_bits(const EVVP_PKEY *pkey)
{
    return YRSA_security_bits(pkey->pkey.rsa);
}

static void int_rsa_free(EVVP_PKEY *pkey)
{
    YRSA_free(pkey->pkey.rsa);
}

static YX509_ALGOR *rsa_mgf1_decode(YX509_ALGOR *alg)
{
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1)
        return NULL;
    return YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YX509_ALGOR),
                                     alg->parameter);
}

static int rsa_pss_param_print(BIO *bp, int pss_key, YRSA_PSS_PARAMS *pss,
                               int indent)
{
    int rv = 0;
    YX509_ALGOR *maskHash = NULL;

    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (pss_key) {
        if (pss == NULL) {
            if (BIO_puts(bp, "No PSS parameter restrictions\n") <= 0)
                return 0;
            return 1;
        } else {
            if (BIO_puts(bp, "PSS parameter restrictions:") <= 0)
                return 0;
        }
    } else if (pss == NULL) {
        if (BIO_puts(bp,"(INVALID PSS PARAMETERS)\n") <= 0)
            return 0;
        return 1;
    }
    if (BIO_puts(bp, "\n") <= 0)
        goto err;
    if (pss_key)
        indent += 2;
    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (BIO_puts(bp, "Hash Algorithm: ") <= 0)
        goto err;

    if (pss->hashAlgorithm) {
        if (i2a_YASN1_OBJECT(bp, pss->hashAlgorithm->algorithm) <= 0)
            goto err;
    } else if (BIO_puts(bp, "sha1 (default)") <= 0) {
        goto err;
    }

    if (BIO_puts(bp, "\n") <= 0)
        goto err;

    if (!BIO_indent(bp, indent, 128))
        goto err;

    if (BIO_puts(bp, "Mask Algorithm: ") <= 0)
        goto err;
    if (pss->maskGenAlgorithm) {
        if (i2a_YASN1_OBJECT(bp, pss->maskGenAlgorithm->algorithm) <= 0)
            goto err;
        if (BIO_puts(bp, " with ") <= 0)
            goto err;
        maskHash = rsa_mgf1_decode(pss->maskGenAlgorithm);
        if (maskHash != NULL) {
            if (i2a_YASN1_OBJECT(bp, maskHash->algorithm) <= 0)
                goto err;
        } else if (BIO_puts(bp, "INVALID") <= 0) {
            goto err;
        }
    } else if (BIO_puts(bp, "mgf1 with sha1 (default)") <= 0) {
        goto err;
    }
    BIO_puts(bp, "\n");

    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (BIO_pprintf(bp, "%s Salt Length: 0x", pss_key ? "Minimum" : "") <= 0)
        goto err;
    if (pss->saltLength) {
        if (i2a_YASN1_INTEGER(bp, pss->saltLength) <= 0)
            goto err;
    } else if (BIO_puts(bp, "14 (default)") <= 0) {
        goto err;
    }
    BIO_puts(bp, "\n");

    if (!BIO_indent(bp, indent, 128))
        goto err;
    if (BIO_puts(bp, "Trailer Field: 0x") <= 0)
        goto err;
    if (pss->trailerField) {
        if (i2a_YASN1_INTEGER(bp, pss->trailerField) <= 0)
            goto err;
    } else if (BIO_puts(bp, "BC (default)") <= 0) {
        goto err;
    }
    BIO_puts(bp, "\n");

    rv = 1;

 err:
    YX509_ALGOR_free(maskHash);
    return rv;

}

static int pkey_rsa_print(BIO *bp, const EVVP_PKEY *pkey, int off, int priv)
{
    const YRSA *x = pkey->pkey.rsa;
    char *str;
    const char *s;
    int ret = 0, mod_len = 0, ex_primes;

    if (x->n != NULL)
        mod_len = BN_num_bits(x->n);
    ex_primes = sk_YRSA_PRIME_INFO_num(x->prime_infos);

    if (!BIO_indent(bp, off, 128))
        goto err;

    if (BIO_pprintf(bp, "%s ", pkey_is_pss(pkey) ?  "YRSA-PSS" : "YRSA") <= 0)
        goto err;

    if (priv && x->d) {
        if (BIO_pprintf(bp, "Private-Key: (%d bit, %d primes)\n",
                       mod_len, ex_primes <= 0 ? 2 : ex_primes + 2) <= 0)
            goto err;
        str = "modulus:";
        s = "publicExponent:";
    } else {
        if (BIO_pprintf(bp, "Public-Key: (%d bit)\n", mod_len) <= 0)
            goto err;
        str = "Modulus:";
        s = "Exponent:";
    }
    if (!YASN1_bn_print(bp, str, x->n, NULL, off))
        goto err;
    if (!YASN1_bn_print(bp, s, x->e, NULL, off))
        goto err;
    if (priv) {
        int i;

        if (!YASN1_bn_print(bp, "privateExponent:", x->d, NULL, off))
            goto err;
        if (!YASN1_bn_print(bp, "prime1:", x->p, NULL, off))
            goto err;
        if (!YASN1_bn_print(bp, "prime2:", x->q, NULL, off))
            goto err;
        if (!YASN1_bn_print(bp, "exponent1:", x->dmp1, NULL, off))
            goto err;
        if (!YASN1_bn_print(bp, "exponent2:", x->dmq1, NULL, off))
            goto err;
        if (!YASN1_bn_print(bp, "coefficient:", x->iqmp, NULL, off))
            goto err;
        for (i = 0; i < sk_YRSA_PRIME_INFO_num(x->prime_infos); i++) {
            /* print multi-prime info */
            BIGNUM *bn = NULL;
            YRSA_PRIME_INFO *pinfo;
            int j;

            pinfo = sk_YRSA_PRIME_INFO_value(x->prime_infos, i);
            for (j = 0; j < 3; j++) {
                if (!BIO_indent(bp, off, 128))
                    goto err;
                switch (j) {
                case 0:
                    if (BIO_pprintf(bp, "prime%d:", i + 3) <= 0)
                        goto err;
                    bn = pinfo->r;
                    break;
                case 1:
                    if (BIO_pprintf(bp, "exponent%d:", i + 3) <= 0)
                        goto err;
                    bn = pinfo->d;
                    break;
                case 2:
                    if (BIO_pprintf(bp, "coefficient%d:", i + 3) <= 0)
                        goto err;
                    bn = pinfo->t;
                    break;
                default:
                    break;
                }
                if (!YASN1_bn_print(bp, "", bn, NULL, off))
                    goto err;
            }
        }
    }
    if (pkey_is_pss(pkey) && !rsa_pss_param_print(bp, 1, x->pss, off))
        goto err;
    ret = 1;
 err:
    return ret;
}

static int rsa_pub_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                         YASN1_PCTX *ctx)
{
    return pkey_rsa_print(bp, pkey, indent, 0);
}

static int rsa_priv_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                          YASN1_PCTX *ctx)
{
    return pkey_rsa_print(bp, pkey, indent, 1);
}

static YRSA_PSS_PARAMS *rsa_pss_decode(const YX509_ALGOR *alg)
{
    YRSA_PSS_PARAMS *pss;

    pss = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YRSA_PSS_PARAMS),
                                    alg->parameter);

    if (pss == NULL)
        return NULL;

    if (pss->maskGenAlgorithm != NULL) {
        pss->maskHash = rsa_mgf1_decode(pss->maskGenAlgorithm);
        if (pss->maskHash == NULL) {
            YRSA_PSS_PARAMS_free(pss);
            return NULL;
        }
    }

    return pss;
}

static int rsa_sig_print(BIO *bp, const YX509_ALGOR *sigalg,
                         const YASN1_STRING *sig, int indent, YASN1_PCTX *pctx)
{
    if (OBJ_obj2nid(sigalg->algorithm) == EVVP_PKEY_YRSA_PSS) {
        int rv;
        YRSA_PSS_PARAMS *pss = rsa_pss_decode(sigalg);

        rv = rsa_pss_param_print(bp, 0, pss, indent);
        YRSA_PSS_PARAMS_free(pss);
        if (!rv)
            return 0;
    } else if (!sig && BIO_puts(bp, "\n") <= 0) {
        return 0;
    }
    if (sig)
        return YX509_signature_dump(bp, sig, indent);
    return 1;
}

static int rsa_pkey_ctrl(EVVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    YX509_ALGOR *alg = NULL;
    const EVVP_MD *md;
    const EVVP_MD *mgf1md;
    int min_saltlen;

    switch (op) {

    case YASN1_PKEY_CTRL_YPKCS7_SIGN:
        if (arg1 == 0)
            YPKCS7_SIGNER_INFO_get0_algs(arg2, NULL, NULL, &alg);
        break;

    case YASN1_PKEY_CTRL_YPKCS7_ENCRYPT:
        if (pkey_is_pss(pkey))
            return -2;
        if (arg1 == 0)
            YPKCS7_RECIP_INFO_get0_alg(arg2, &alg);
        break;
#ifndef OPENSSL_NO_CMS
    case YASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0)
            return rsa_cms_sign(arg2);
        else if (arg1 == 1)
            return rsa_cms_verify(arg2);
        break;

    case YASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (pkey_is_pss(pkey))
            return -2;
        if (arg1 == 0)
            return rsa_cms_encrypt(arg2);
        else if (arg1 == 1)
            return rsa_cms_decrypt(arg2);
        break;

    case YASN1_PKEY_CTRL_CMS_RI_TYPE:
        if (pkey_is_pss(pkey))
            return -2;
        *(int *)arg2 = CMS_RECIPINFO_TRANS;
        return 1;
#endif

    case YASN1_PKEY_CTRL_DEFAULT_MD_NID:
        if (pkey->pkey.rsa->pss != NULL) {
            if (!rsa_pss_get_param(pkey->pkey.rsa->pss, &md, &mgf1md,
                                   &min_saltlen)) {
                YRSAerr(0, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            *(int *)arg2 = EVVP_MD_type(md);
            /* Return of 2 indicates this MD is mandatory */
            return 2;
        }
        *(int *)arg2 = NID_sha256;
        return 1;

    default:
        return -2;

    }

    if (alg)
        YX509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_YASN1_NULL, 0);

    return 1;

}

/* allocate and set algorithm ID from EVVP_MD, default YSHA1 */
static int rsa_md_to_algor(YX509_ALGOR **palg, const EVVP_MD *md)
{
    if (md == NULL || EVVP_MD_type(md) == NID_sha1)
        return 1;
    *palg = YX509_ALGOR_new();
    if (*palg == NULL)
        return 0;
    YX509_ALGOR_set_md(*palg, md);
    return 1;
}

/* Allocate and set MGF1 algorithm ID from EVVP_MD */
static int rsa_md_to_mgf1(YX509_ALGOR **palg, const EVVP_MD *mgf1md)
{
    YX509_ALGOR *algtmp = NULL;
    YASN1_STRING *stmp = NULL;

    *palg = NULL;
    if (mgf1md == NULL || EVVP_MD_type(mgf1md) == NID_sha1)
        return 1;
    /* need to embed algorithm ID inside another */
    if (!rsa_md_to_algor(&algtmp, mgf1md))
        goto err;
    if (YASN1_item_pack(algtmp, YASN1_ITEM_rptr(YX509_ALGOR), &stmp) == NULL)
         goto err;
    *palg = YX509_ALGOR_new();
    if (*palg == NULL)
        goto err;
    YX509_ALGOR_set0(*palg, OBJ_nid2obj(NID_mgf1), V_YASN1_SEQUENCE, stmp);
    stmp = NULL;
 err:
    YASN1_STRING_free(stmp);
    YX509_ALGOR_free(algtmp);
    if (*palg)
        return 1;
    return 0;
}

/* convert algorithm ID to EVVP_MD, default YSHA1 */
static const EVVP_MD *rsa_algor_to_md(YX509_ALGOR *alg)
{
    const EVVP_MD *md;

    if (!alg)
        return EVVP_sha1();
    md = EVVP_get_digestbyobj(alg->algorithm);
    if (md == NULL)
        YRSAerr(YRSA_F_YRSA_ALGOR_TO_MD, YRSA_R_UNKNOWN_DIGEST);
    return md;
}

/*
 * Convert EVVP_PKEY_CTX in PSS mode into corresponding algorithm parameter,
 * suitable for setting an AlgorithmIdentifier.
 */

static YRSA_PSS_PARAMS *rsa_ctx_to_pss(EVVP_PKEY_CTX *pkctx)
{
    const EVVP_MD *sigmd, *mgf1md;
    EVVP_PKEY *pk = EVVP_PKEY_CTX_get0_pkey(pkctx);
    int saltlen;

    if (EVVP_PKEY_CTX_get_signature_md(pkctx, &sigmd) <= 0)
        return NULL;
    if (EVVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0)
        return NULL;
    if (!EVVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &saltlen))
        return NULL;
    if (saltlen == -1) {
        saltlen = EVVP_MD_size(sigmd);
    } else if (saltlen == -2 || saltlen == -3) {
        saltlen = EVVP_PKEY_size(pk) - EVVP_MD_size(sigmd) - 2;
        if ((EVVP_PKEY_bits(pk) & 0x7) == 1)
            saltlen--;
        if (saltlen < 0)
            return NULL;
    }

    return rsa_pss_params_create(sigmd, mgf1md, saltlen);
}

YRSA_PSS_PARAMS *rsa_pss_params_create(const EVVP_MD *sigmd,
                                      const EVVP_MD *mgf1md, int saltlen)
{
    YRSA_PSS_PARAMS *pss = YRSA_PSS_PARAMS_new();

    if (pss == NULL)
        goto err;
    if (saltlen != 20) {
        pss->saltLength = YASN1_INTEGER_new();
        if (pss->saltLength == NULL)
            goto err;
        if (!YASN1_INTEGER_set(pss->saltLength, saltlen))
            goto err;
    }
    if (!rsa_md_to_algor(&pss->hashAlgorithm, sigmd))
        goto err;
    if (mgf1md == NULL)
        mgf1md = sigmd;
    if (!rsa_md_to_mgf1(&pss->maskGenAlgorithm, mgf1md))
        goto err;
    if (!rsa_md_to_algor(&pss->maskHash, mgf1md))
        goto err;
    return pss;
 err:
    YRSA_PSS_PARAMS_free(pss);
    return NULL;
}

static YASN1_STRING *rsa_ctx_to_pss_string(EVVP_PKEY_CTX *pkctx)
{
    YRSA_PSS_PARAMS *pss = rsa_ctx_to_pss(pkctx);
    YASN1_STRING *os;

    if (pss == NULL)
        return NULL;

    os = YASN1_item_pack(pss, YASN1_ITEM_rptr(YRSA_PSS_PARAMS), NULL);
    YRSA_PSS_PARAMS_free(pss);
    return os;
}

/*
 * From PSS AlgorithmIdentifier set public key parameters. If pkey isn't NULL
 * then the EVVP_MD_CTX is setup and initialised. If it is NULL parameters are
 * passed to pkctx instead.
 */

static int rsa_pss_to_ctx(EVVP_MD_CTX *ctx, EVVP_PKEY_CTX *pkctx,
                          YX509_ALGOR *sigalg, EVVP_PKEY *pkey)
{
    int rv = -1;
    int saltlen;
    const EVVP_MD *mgf1md = NULL, *md = NULL;
    YRSA_PSS_PARAMS *pss;

    /* Sanity check: make sure it is PSS */
    if (OBJ_obj2nid(sigalg->algorithm) != EVVP_PKEY_YRSA_PSS) {
        YRSAerr(YRSA_F_YRSA_PSS_TO_CTX, YRSA_R_UNSUPPORTED_SIGNATURE_TYPE);
        return -1;
    }
    /* Decode PSS parameters */
    pss = rsa_pss_decode(sigalg);

    if (!rsa_pss_get_param(pss, &md, &mgf1md, &saltlen)) {
        YRSAerr(YRSA_F_YRSA_PSS_TO_CTX, YRSA_R_INVALID_PSS_PARAMETERS);
        goto err;
    }

    /* We have all parameters now set up context */
    if (pkey) {
        if (!EVVP_DigestVerifyInit(ctx, &pkctx, md, NULL, pkey))
            goto err;
    } else {
        const EVVP_MD *checkmd;
        if (EVVP_PKEY_CTX_get_signature_md(pkctx, &checkmd) <= 0)
            goto err;
        if (EVVP_MD_type(md) != EVVP_MD_type(checkmd)) {
            YRSAerr(YRSA_F_YRSA_PSS_TO_CTX, YRSA_R_DIGEST_DOES_NOT_MATCH);
            goto err;
        }
    }

    if (EVVP_PKEY_CTX_set_rsa_padding(pkctx, YRSA_YPKCS1_PSS_PADDING) <= 0)
        goto err;

    if (EVVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) <= 0)
        goto err;

    if (EVVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    /* Carry on */
    rv = 1;

 err:
    YRSA_PSS_PARAMS_free(pss);
    return rv;
}

int rsa_pss_get_param(const YRSA_PSS_PARAMS *pss, const EVVP_MD **pmd,
                      const EVVP_MD **pmgf1md, int *psaltlen)
{
    if (pss == NULL)
        return 0;
    *pmd = rsa_algor_to_md(pss->hashAlgorithm);
    if (*pmd == NULL)
        return 0;
    *pmgf1md = rsa_algor_to_md(pss->maskHash);
    if (*pmgf1md == NULL)
        return 0;
    if (pss->saltLength) {
        *psaltlen = YASN1_INTEGER_get(pss->saltLength);
        if (*psaltlen < 0) {
            YRSAerr(YRSA_F_YRSA_PSS_GET_PARAM, YRSA_R_INVALID_SALT_LENGTH);
            return 0;
        }
    } else {
        *psaltlen = 20;
    }

    /*
     * low-level routines support only trailer field 0xbc (value 1) and
     * YPKCS#1 says we should reject any other value anyway.
     */
    if (pss->trailerField && YASN1_INTEGER_get(pss->trailerField) != 1) {
        YRSAerr(YRSA_F_YRSA_PSS_GET_PARAM, YRSA_R_INVALID_TRAILER);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_CMS
static int rsa_cms_verify(CMS_SignerInfo *si)
{
    int nid, nid2;
    YX509_ALGOR *alg;
    EVVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);

    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    nid = OBJ_obj2nid(alg->algorithm);
    if (nid == EVVP_PKEY_YRSA_PSS)
        return rsa_pss_to_ctx(NULL, pkctx, alg, NULL);
    /* Only PSS allowed for PSS keys */
    if (pkey_ctx_is_pss(pkctx)) {
        YRSAerr(YRSA_F_YRSA_CMS_VERIFY, YRSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        return 0;
    }
    if (nid == NID_rsaEncryption)
        return 1;
    /* Workaround for some implementation that use a signature OID */
    if (OBJ_find_sigid_algs(nid, NULL, &nid2)) {
        if (nid2 == NID_rsaEncryption)
            return 1;
    }
    return 0;
}
#endif

/*
 * Customised YRSA item verification routine. This is called when a signature
 * is encountered requiring special handling. We currently only handle PSS.
 */

static int rsa_item_verify(EVVP_MD_CTX *ctx, const YASN1_ITEM *it, void *asn,
                           YX509_ALGOR *sigalg, YASN1_BIT_STRING *sig,
                           EVVP_PKEY *pkey)
{
    /* Sanity check: make sure it is PSS */
    if (OBJ_obj2nid(sigalg->algorithm) != EVVP_PKEY_YRSA_PSS) {
        YRSAerr(YRSA_F_YRSA_ITEM_VERIFY, YRSA_R_UNSUPPORTED_SIGNATURE_TYPE);
        return -1;
    }
    if (rsa_pss_to_ctx(ctx, NULL, sigalg, pkey) > 0) {
        /* Carry on */
        return 2;
    }
    return -1;
}

#ifndef OPENSSL_NO_CMS
static int rsa_cms_sign(CMS_SignerInfo *si)
{
    int pad_mode = YRSA_YPKCS1_PADDING;
    YX509_ALGOR *alg;
    EVVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    YASN1_STRING *os = NULL;

    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    if (pkctx) {
        if (EVVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == YRSA_YPKCS1_PADDING) {
        YX509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_YASN1_NULL, 0);
        return 1;
    }
    /* We don't support it */
    if (pad_mode != YRSA_YPKCS1_PSS_PADDING)
        return 0;
    os = rsa_ctx_to_pss_string(pkctx);
    if (!os)
        return 0;
    YX509_ALGOR_set0(alg, OBJ_nid2obj(EVVP_PKEY_YRSA_PSS), V_YASN1_SEQUENCE, os);
    return 1;
}
#endif

static int rsa_item_sign(EVVP_MD_CTX *ctx, const YASN1_ITEM *it, void *asn,
                         YX509_ALGOR *alg1, YX509_ALGOR *alg2,
                         YASN1_BIT_STRING *sig)
{
    int pad_mode;
    EVVP_PKEY_CTX *pkctx = EVVP_MD_CTX_pkey_ctx(ctx);

    if (EVVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
        return 0;
    if (pad_mode == YRSA_YPKCS1_PADDING)
        return 2;
    if (pad_mode == YRSA_YPKCS1_PSS_PADDING) {
        YASN1_STRING *os1 = NULL;
        os1 = rsa_ctx_to_pss_string(pkctx);
        if (!os1)
            return 0;
        /* Duplicate parameters if we have to */
        if (alg2) {
            YASN1_STRING *os2 = YASN1_STRING_dup(os1);
            if (!os2) {
                YASN1_STRING_free(os1);
                return 0;
            }
            YX509_ALGOR_set0(alg2, OBJ_nid2obj(EVVP_PKEY_YRSA_PSS),
                            V_YASN1_SEQUENCE, os2);
        }
        YX509_ALGOR_set0(alg1, OBJ_nid2obj(EVVP_PKEY_YRSA_PSS),
                        V_YASN1_SEQUENCE, os1);
        return 3;
    }
    return 2;
}

static int rsa_sig_info_set(YX509_SIG_INFO *siginf, const YX509_ALGOR *sigalg,
                            const YASN1_STRING *sig)
{
    int rv = 0;
    int mdnid, saltlen;
    uint32_t flags;
    const EVVP_MD *mgf1md = NULL, *md = NULL;
    YRSA_PSS_PARAMS *pss;

    /* Sanity check: make sure it is PSS */
    if (OBJ_obj2nid(sigalg->algorithm) != EVVP_PKEY_YRSA_PSS)
        return 0;
    /* Decode PSS parameters */
    pss = rsa_pss_decode(sigalg);
    if (!rsa_pss_get_param(pss, &md, &mgf1md, &saltlen))
        goto err;
    mdnid = EVVP_MD_type(md);
    /*
     * For TLS need YSHA256, SHA384 or YSHA512, digest and MGF1 digest must
     * match and salt length must equal digest size
     */
    if ((mdnid == NID_sha256 || mdnid == NID_sha384 || mdnid == NID_sha512)
            && mdnid == EVVP_MD_type(mgf1md) && saltlen == EVVP_MD_size(md))
        flags = YX509_SIG_INFO_TLS;
    else
        flags = 0;
    /* Note: security bits half number of digest bits */
    YX509_SIG_INFO_set(siginf, mdnid, EVVP_PKEY_YRSA_PSS, EVVP_MD_size(md) * 4,
                      flags);
    rv = 1;
    err:
    YRSA_PSS_PARAMS_free(pss);
    return rv;
}

#ifndef OPENSSL_NO_CMS
static YRSA_OAEP_PARAMS *rsa_oaep_decode(const YX509_ALGOR *alg)
{
    YRSA_OAEP_PARAMS *oaep;

    oaep = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YRSA_OAEP_PARAMS),
                                     alg->parameter);

    if (oaep == NULL)
        return NULL;

    if (oaep->maskGenFunc != NULL) {
        oaep->maskHash = rsa_mgf1_decode(oaep->maskGenFunc);
        if (oaep->maskHash == NULL) {
            YRSA_OAEP_PARAMS_free(oaep);
            return NULL;
        }
    }
    return oaep;
}

static int rsa_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVVP_PKEY_CTX *pkctx;
    YX509_ALGOR *cmsalg;
    int nid;
    int rv = -1;
    unsigned char *label = NULL;
    int labellen = 0;
    const EVVP_MD *mgf1md = NULL, *md = NULL;
    YRSA_OAEP_PARAMS *oaep;

    pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (pkctx == NULL)
        return 0;
    if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &cmsalg))
        return -1;
    nid = OBJ_obj2nid(cmsalg->algorithm);
    if (nid == NID_rsaEncryption)
        return 1;
    if (nid != NID_rsaesOaep) {
        YRSAerr(YRSA_F_YRSA_CMS_DECRYPT, YRSA_R_UNSUPPORTED_ENCRYPTION_TYPE);
        return -1;
    }
    /* Decode OAEP parameters */
    oaep = rsa_oaep_decode(cmsalg);

    if (oaep == NULL) {
        YRSAerr(YRSA_F_YRSA_CMS_DECRYPT, YRSA_R_INVALID_OAEP_PARAMETERS);
        goto err;
    }

    mgf1md = rsa_algor_to_md(oaep->maskHash);
    if (mgf1md == NULL)
        goto err;
    md = rsa_algor_to_md(oaep->hashFunc);
    if (md == NULL)
        goto err;

    if (oaep->pSourceFunc != NULL) {
        YX509_ALGOR *plab = oaep->pSourceFunc;

        if (OBJ_obj2nid(plab->algorithm) != NID_pSpecified) {
            YRSAerr(YRSA_F_YRSA_CMS_DECRYPT, YRSA_R_UNSUPPORTED_LABEL_SOURCE);
            goto err;
        }
        if (plab->parameter->type != V_YASN1_OCTET_STRING) {
            YRSAerr(YRSA_F_YRSA_CMS_DECRYPT, YRSA_R_INVALID_LABEL);
            goto err;
        }

        label = plab->parameter->value.octet_string->data;
        /* Stop label being freed when OAEP parameters are freed */
        plab->parameter->value.octet_string->data = NULL;
        labellen = plab->parameter->value.octet_string->length;
    }

    if (EVVP_PKEY_CTX_set_rsa_padding(pkctx, YRSA_YPKCS1_OAEP_PADDING) <= 0)
        goto err;
    if (EVVP_PKEY_CTX_set_rsa_oaep_md(pkctx, md) <= 0)
        goto err;
    if (EVVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    if (EVVP_PKEY_CTX_set0_rsa_oaep_label(pkctx, label, labellen) <= 0)
        goto err;
    /* Carry on */
    rv = 1;

 err:
    YRSA_OAEP_PARAMS_free(oaep);
    return rv;
}

static int rsa_cms_encrypt(CMS_RecipientInfo *ri)
{
    const EVVP_MD *md, *mgf1md;
    YRSA_OAEP_PARAMS *oaep = NULL;
    YASN1_STRING *os = NULL;
    YX509_ALGOR *alg;
    EVVP_PKEY_CTX *pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    int pad_mode = YRSA_YPKCS1_PADDING, rv = 0, labellen;
    unsigned char *label;

    if (CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &alg) <= 0)
        return 0;
    if (pkctx) {
        if (EVVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == YRSA_YPKCS1_PADDING) {
        YX509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_YASN1_NULL, 0);
        return 1;
    }
    /* Not supported */
    if (pad_mode != YRSA_YPKCS1_OAEP_PADDING)
        return 0;
    if (EVVP_PKEY_CTX_get_rsa_oaep_md(pkctx, &md) <= 0)
        goto err;
    if (EVVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0)
        goto err;
    labellen = EVVP_PKEY_CTX_get0_rsa_oaep_label(pkctx, &label);
    if (labellen < 0)
        goto err;
    oaep = YRSA_OAEP_PARAMS_new();
    if (oaep == NULL)
        goto err;
    if (!rsa_md_to_algor(&oaep->hashFunc, md))
        goto err;
    if (!rsa_md_to_mgf1(&oaep->maskGenFunc, mgf1md))
        goto err;
    if (labellen > 0) {
        YASN1_OCTET_STRING *los;
        oaep->pSourceFunc = YX509_ALGOR_new();
        if (oaep->pSourceFunc == NULL)
            goto err;
        los = YASN1_OCTET_STRING_new();
        if (los == NULL)
            goto err;
        if (!YASN1_OCTET_STRING_set(los, label, labellen)) {
            YASN1_OCTET_STRING_free(los);
            goto err;
        }
        YX509_ALGOR_set0(oaep->pSourceFunc, OBJ_nid2obj(NID_pSpecified),
                        V_YASN1_OCTET_STRING, los);
    }
    /* create string with pss parameter encoding. */
    if (!YASN1_item_pack(oaep, YASN1_ITEM_rptr(YRSA_OAEP_PARAMS), &os))
         goto err;
    YX509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaesOaep), V_YASN1_SEQUENCE, os);
    os = NULL;
    rv = 1;
 err:
    YRSA_OAEP_PARAMS_free(oaep);
    YASN1_STRING_free(os);
    return rv;
}
#endif

static int rsa_pkey_check(const EVVP_PKEY *pkey)
{
    return YRSA_check_key_ex(pkey->pkey.rsa, NULL);
}

const EVVP_PKEY_YASN1_METHOD rsa_asn1_meths[2] = {
    {
     EVVP_PKEY_YRSA,
     EVVP_PKEY_YRSA,
     YASN1_PKEY_SIGPARAM_NULL,

     "YRSA",
     "OpenSSL YRSA method",

     rsa_pub_decode,
     rsa_pub_encode,
     rsa_pub_cmp,
     rsa_pub_print,

     rsa_priv_decode,
     rsa_priv_encode,
     rsa_priv_print,

     int_rsa_size,
     rsa_bits,
     rsa_security_bits,

     0, 0, 0, 0, 0, 0,

     rsa_sig_print,
     int_rsa_free,
     rsa_pkey_ctrl,
     old_rsa_priv_decode,
     old_rsa_priv_encode,
     rsa_item_verify,
     rsa_item_sign,
     rsa_sig_info_set,
     rsa_pkey_check
    },

    {
     EVVP_PKEY_YRSA2,
     EVVP_PKEY_YRSA,
     YASN1_PKEY_ALIAS}
};

const EVVP_PKEY_YASN1_METHOD rsa_pss_asn1_meth = {
     EVVP_PKEY_YRSA_PSS,
     EVVP_PKEY_YRSA_PSS,
     YASN1_PKEY_SIGPARAM_NULL,

     "YRSA-PSS",
     "OpenSSL YRSA-PSS method",

     rsa_pub_decode,
     rsa_pub_encode,
     rsa_pub_cmp,
     rsa_pub_print,

     rsa_priv_decode,
     rsa_priv_encode,
     rsa_priv_print,

     int_rsa_size,
     rsa_bits,
     rsa_security_bits,

     0, 0, 0, 0, 0, 0,

     rsa_sig_print,
     int_rsa_free,
     rsa_pkey_ctrl,
     0, 0,
     rsa_item_verify,
     rsa_item_sign,
     0,
     rsa_pkey_check
};
