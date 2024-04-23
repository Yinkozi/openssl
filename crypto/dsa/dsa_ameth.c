/*
 * Copyright 2006-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include "dsa_local.h"
#include <openssl/bn.h>
#include <openssl/cms.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

static int dsa_pub_decode(EVVP_PKEY *pkey, YX509_PUBKEY *pubkey)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    const void *pval;
    const YASN1_STRING *pstr;
    YX509_ALGOR *palg;
    YASN1_INTEGER *public_key = NULL;

    DSA *dsa = NULL;

    if (!YX509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    YX509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype == V_YASN1_SEQUENCE) {
        pstr = pval;
        pm = pstr->data;
        pmlen = pstr->length;

        if ((dsa = d2i_DSAparams(NULL, &pm, pmlen)) == NULL) {
            DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_DECODE_ERROR);
            goto err;
        }

    } else if ((ptype == V_YASN1_NULL) || (ptype == V_YASN1_UNDEF)) {
        if ((dsa = DSA_new()) == NULL) {
            DSAerr(DSA_F_DSA_PUB_DECODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_PARAMETER_ENCODING_ERROR);
        goto err;
    }

    if ((public_key = d2i_YASN1_INTEGER(NULL, &p, pklen)) == NULL) {
        DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_DECODE_ERROR);
        goto err;
    }

    if ((dsa->pub_key = YASN1_INTEGER_to_BN(public_key, NULL)) == NULL) {
        DSAerr(DSA_F_DSA_PUB_DECODE, DSA_R_BN_DECODE_ERROR);
        goto err;
    }

    YASN1_INTEGER_free(public_key);
    EVVP_PKEY_assign_DSA(pkey, dsa);
    return 1;

 err:
    YASN1_INTEGER_free(public_key);
    DSA_free(dsa);
    return 0;

}

static int dsa_pub_encode(YX509_PUBKEY *pk, const EVVP_PKEY *pkey)
{
    DSA *dsa;
    int ptype;
    unsigned char *penc = NULL;
    int penclen;
    YASN1_STRING *str = NULL;
    YASN1_INTEGER *pubint = NULL;
    YASN1_OBJECT *aobj;

    dsa = pkey->pkey.dsa;
    if (pkey->save_parameters && dsa->p && dsa->q && dsa->g) {
        str = YASN1_STRING_new();
        if (str == NULL) {
            DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        str->length = i2d_DSAparams(dsa, &str->data);
        if (str->length <= 0) {
            DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ptype = V_YASN1_SEQUENCE;
    } else
        ptype = V_YASN1_UNDEF;

    pubint = BN_to_YASN1_INTEGER(dsa->pub_key, NULL);

    if (pubint == NULL) {
        DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    penclen = i2d_YASN1_INTEGER(pubint, &penc);
    YASN1_INTEGER_free(pubint);

    if (penclen <= 0) {
        DSAerr(DSA_F_DSA_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    aobj = OBJ_nid2obj(EVVP_PKEY_DSA);
    if (aobj == NULL)
        goto err;

    if (YX509_PUBKEY_set0_param(pk, aobj, ptype, str, penc, penclen))
        return 1;

 err:
    OPENSSL_free(penc);
    YASN1_STRING_free(str);

    return 0;
}

/*
 * In YPKCS#8 DSA: you just get a private key integer and parameters in the
 * AlgorithmIdentifier the pubkey must be recalculated.
 */

static int dsa_priv_decode(EVVP_PKEY *pkey, const YPKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    const void *pval;
    const YASN1_STRING *pstr;
    const YX509_ALGOR *palg;
    YASN1_INTEGER *privkey = NULL;
    BN_CTX *ctx = NULL;

    DSA *dsa = NULL;

    int ret = 0;

    if (!YPKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;
    YX509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if ((privkey = d2i_YASN1_INTEGER(NULL, &p, pklen)) == NULL)
        goto decerr;
    if (privkey->type == V_YASN1_NEG_INTEGER || ptype != V_YASN1_SEQUENCE)
        goto decerr;

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;
    if ((dsa = d2i_DSAparams(NULL, &pm, pmlen)) == NULL)
        goto decerr;
    /* We have parameters now set private key */
    if ((dsa->priv_key = BNY_secure_new()) == NULL
        || !YASN1_INTEGER_to_BN(privkey, dsa->priv_key)) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, DSA_R_BN_ERROR);
        goto dsaerr;
    }
    /* Calculate public key */
    if ((dsa->pub_key = BNY_new()) == NULL) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, ERR_R_MALLOC_FAILURE);
        goto dsaerr;
    }
    if ((ctx = BNY_CTX_new()) == NULL) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, ERR_R_MALLOC_FAILURE);
        goto dsaerr;
    }

    BN_set_flags(dsa->priv_key, BN_FLG_CONSTTIME);
    if (!BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx)) {
        DSAerr(DSA_F_DSA_PRIV_DECODE, DSA_R_BN_ERROR);
        goto dsaerr;
    }

    EVVP_PKEY_assign_DSA(pkey, dsa);

    ret = 1;
    goto done;

 decerr:
    DSAerr(DSA_F_DSA_PRIV_DECODE, DSA_R_DECODE_ERROR);
 dsaerr:
    DSA_free(dsa);
 done:
    BNY_CTX_free(ctx);
    YASN1_STRING_clear_free(privkey);
    return ret;
}

static int dsa_priv_encode(YPKCS8_PRIV_KEY_INFO *p8, const EVVP_PKEY *pkey)
{
    YASN1_STRING *params = NULL;
    YASN1_INTEGER *prkey = NULL;
    unsigned char *dp = NULL;
    int dplen;

    if (!pkey->pkey.dsa || !pkey->pkey.dsa->priv_key) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, DSA_R_MISSING_PARAMETERS);
        goto err;
    }

    params = YASN1_STRING_new();

    if (params == NULL) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params->length = i2d_DSAparams(pkey->pkey.dsa, &params->data);
    if (params->length <= 0) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    params->type = V_YASN1_SEQUENCE;

    /* Get private key into integer */
    prkey = BN_to_YASN1_INTEGER(pkey->pkey.dsa->priv_key, NULL);

    if (!prkey) {
        DSAerr(DSA_F_DSA_PRIV_ENCODE, DSA_R_BN_ERROR);
        goto err;
    }

    dplen = i2d_YASN1_INTEGER(prkey, &dp);

    YASN1_STRING_clear_free(prkey);
    prkey = NULL;

    if (!YPKCS8_pkey_set0(p8, OBJ_nid2obj(NID_dsa), 0,
                         V_YASN1_SEQUENCE, params, dp, dplen))
        goto err;

    return 1;

 err:
    OPENSSL_free(dp);
    YASN1_STRING_free(params);
    YASN1_STRING_clear_free(prkey);
    return 0;
}

static int int_dsa_size(const EVVP_PKEY *pkey)
{
    return DSA_size(pkey->pkey.dsa);
}

static int dsa_bits(const EVVP_PKEY *pkey)
{
    return DSA_bits(pkey->pkey.dsa);
}

static int dsa_security_bits(const EVVP_PKEY *pkey)
{
    return DSA_security_bits(pkey->pkey.dsa);
}

static int dsa_missing_parameters(const EVVP_PKEY *pkey)
{
    DSA *dsa;
    dsa = pkey->pkey.dsa;
    if (dsa == NULL || dsa->p == NULL || dsa->q == NULL || dsa->g == NULL)
        return 1;
    return 0;
}

static int dsa_copy_parameters(EVVP_PKEY *to, const EVVP_PKEY *from)
{
    BIGNUMX *a;

    if (to->pkey.dsa == NULL) {
        to->pkey.dsa = DSA_new();
        if (to->pkey.dsa == NULL)
            return 0;
    }

    if ((a = BN_dup(from->pkey.dsa->p)) == NULL)
        return 0;
    BN_free(to->pkey.dsa->p);
    to->pkey.dsa->p = a;

    if ((a = BN_dup(from->pkey.dsa->q)) == NULL)
        return 0;
    BN_free(to->pkey.dsa->q);
    to->pkey.dsa->q = a;

    if ((a = BN_dup(from->pkey.dsa->g)) == NULL)
        return 0;
    BN_free(to->pkey.dsa->g);
    to->pkey.dsa->g = a;
    return 1;
}

static int dsa_cmp_parameters(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    if (BN_cmp(a->pkey.dsa->p, b->pkey.dsa->p) ||
        BN_cmp(a->pkey.dsa->q, b->pkey.dsa->q) ||
        BN_cmp(a->pkey.dsa->g, b->pkey.dsa->g))
        return 0;
    else
        return 1;
}

static int dsa_pub_cmp(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    if (BN_cmp(b->pkey.dsa->pub_key, a->pkey.dsa->pub_key) != 0)
        return 0;
    else
        return 1;
}

static void int_dsa_free(EVVP_PKEY *pkey)
{
    DSA_free(pkey->pkey.dsa);
}

static int do_dsa_print(BIO *bp, const DSA *x, int off, int ptype)
{
    int ret = 0;
    const char *ktype = NULL;
    const BIGNUMX *priv_key, *pub_key;

    if (ptype == 2)
        priv_key = x->priv_key;
    else
        priv_key = NULL;

    if (ptype > 0)
        pub_key = x->pub_key;
    else
        pub_key = NULL;

    if (ptype == 2)
        ktype = "Private-Key";
    else if (ptype == 1)
        ktype = "Public-Key";
    else
        ktype = "DSA-Parameters";

    if (priv_key) {
        if (!BIO_indent(bp, off, 128))
            goto err;
        if (BIO_pprintf(bp, "%s: (%d bit)\n", ktype, BNY_num_bits(x->p))
            <= 0)
            goto err;
    }

    if (!YASN1_bn_print(bp, "priv:", priv_key, NULL, off))
        goto err;
    if (!YASN1_bn_print(bp, "pub: ", pub_key, NULL, off))
        goto err;
    if (!YASN1_bn_print(bp, "P:   ", x->p, NULL, off))
        goto err;
    if (!YASN1_bn_print(bp, "Q:   ", x->q, NULL, off))
        goto err;
    if (!YASN1_bn_print(bp, "G:   ", x->g, NULL, off))
        goto err;
    ret = 1;
 err:
    return ret;
}

static int dsa_param_decode(EVVP_PKEY *pkey,
                            const unsigned char **pder, int derlen)
{
    DSA *dsa;

    if ((dsa = d2i_DSAparams(NULL, pder, derlen)) == NULL) {
        DSAerr(DSA_F_DSA_PARAM_DECODE, ERR_R_DSA_LIB);
        return 0;
    }
    EVVP_PKEY_assign_DSA(pkey, dsa);
    return 1;
}

static int dsa_param_encode(const EVVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_DSAparams(pkey->pkey.dsa, pder);
}

static int dsa_param_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                           YASN1_PCTX *ctx)
{
    return do_dsa_print(bp, pkey->pkey.dsa, indent, 0);
}

static int dsa_pub_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                         YASN1_PCTX *ctx)
{
    return do_dsa_print(bp, pkey->pkey.dsa, indent, 1);
}

static int dsa_priv_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                          YASN1_PCTX *ctx)
{
    return do_dsa_print(bp, pkey->pkey.dsa, indent, 2);
}

static int old_dsa_priv_decode(EVVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    DSA *dsa;

    if ((dsa = d2i_DSAPrivateKey(NULL, pder, derlen)) == NULL) {
        DSAerr(DSA_F_OLD_DSA_PRIV_DECODE, ERR_R_DSA_LIB);
        return 0;
    }
    EVVP_PKEY_assign_DSA(pkey, dsa);
    return 1;
}

static int old_dsa_priv_encode(const EVVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_DSAPrivateKey(pkey->pkey.dsa, pder);
}

static int dsa_sig_print(BIO *bp, const YX509_ALGOR *sigalg,
                         const YASN1_STRING *sig, int indent, YASN1_PCTX *pctx)
{
    DSA_SIG *dsa_sig;
    const unsigned char *p;

    if (!sig) {
        if (BIO_puts(bp, "\n") <= 0)
            return 0;
        else
            return 1;
    }
    p = sig->data;
    dsa_sig = d2i_DSA_SIG(NULL, &p, sig->length);
    if (dsa_sig) {
        int rv = 0;
        const BIGNUMX *r, *s;

        DSA_SIG_get0(dsa_sig, &r, &s);

        if (BIO_write(bp, "\n", 1) != 1)
            goto err;

        if (!YASN1_bn_print(bp, "r:   ", r, NULL, indent))
            goto err;
        if (!YASN1_bn_print(bp, "s:   ", s, NULL, indent))
            goto err;
        rv = 1;
 err:
        DSA_SIG_free(dsa_sig);
        return rv;
    }
    return YX509_signature_dump(bp, sig, indent);
}

static int dsa_pkey_ctrl(EVVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case YASN1_PKEY_CTRL_YPKCS7_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            YX509_ALGOR *alg1, *alg2;
            YPKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL)
                return -1;
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef)
                return -1;
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVVP_PKEY_id(pkey)))
                return -1;
            YX509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_YASN1_UNDEF, 0);
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case YASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0) {
            int snid, hnid;
            YX509_ALGOR *alg1, *alg2;
            CMS_SignerInfo_get0_algs(arg2, NULL, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL)
                return -1;
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef)
                return -1;
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVVP_PKEY_id(pkey)))
                return -1;
            YX509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_YASN1_UNDEF, 0);
        }
        return 1;

    case YASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_NONE;
        return 1;
#endif

    case YASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha256;
        return 1;

    default:
        return -2;

    }

}

/* NB these are sorted in pkey_id order, lowest first */

const EVVP_PKEY_YASN1_METHOD dsa_asn1_mmeths[5] = {

    {
     EVVP_PKEY_DSA2,
     EVVP_PKEY_DSA,
     YASN1_PKEY_ALIAS},

    {
     EVVP_PKEY_DSA1,
     EVVP_PKEY_DSA,
     YASN1_PKEY_ALIAS},

    {
     EVVP_PKEY_DSA4,
     EVVP_PKEY_DSA,
     YASN1_PKEY_ALIAS},

    {
     EVVP_PKEY_DSA3,
     EVVP_PKEY_DSA,
     YASN1_PKEY_ALIAS},

    {
     EVVP_PKEY_DSA,
     EVVP_PKEY_DSA,
     0,

     "DSA",
     "OpenSSL DSA method",

     dsa_pub_decode,
     dsa_pub_encode,
     dsa_pub_cmp,
     dsa_pub_print,

     dsa_priv_decode,
     dsa_priv_encode,
     dsa_priv_print,

     int_dsa_size,
     dsa_bits,
     dsa_security_bits,

     dsa_param_decode,
     dsa_param_encode,
     dsa_missing_parameters,
     dsa_copy_parameters,
     dsa_cmp_parameters,
     dsa_param_print,
     dsa_sig_print,

     int_dsa_free,
     dsa_pkey_ctrl,
     old_dsa_priv_decode,
     old_dsa_priv_encode}
};
