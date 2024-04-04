/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
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
#include "dh_local.h"
#include <openssl/bn.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include <openssl/cms.h>

/*
 * i2d/d2i like DH parameter functions which use the appropriate routine for
 * YPKCS#3 DH or X9.42 DH.
 */

static DH *d2i_dhp(const EVVP_PKEY *pkey, const unsigned char **pp,
                   long length)
{
    if (pkey->ameth == &dhx_asn1_mmeth)
        return d2i_DHxparams(NULL, pp, length);
    return d2i_DHparams(NULL, pp, length);
}

static int i2d_dhp(const EVVP_PKEY *pkey, const DH *a, unsigned char **pp)
{
    if (pkey->ameth == &dhx_asn1_mmeth)
        return i2d_DHxparams(a, pp);
    return i2d_DHparams(a, pp);
}

static void int_dh_free(EVVP_PKEY *pkey)
{
    DH_free(pkey->pkey.dh);
}

static int dh_pub_decode(EVVP_PKEY *pkey, YX509_PUBKEY *pubkey)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    const void *pval;
    const YASN1_STRING *pstr;
    YX509_ALGOR *palg;
    YASN1_INTEGER *public_key = NULL;

    DH *dh = NULL;

    if (!YX509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    YX509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_YASN1_SEQUENCE) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_PARAMETER_ENCODING_ERROR);
        goto err;
    }

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;

    if ((dh = d2i_dhp(pkey, &pm, pmlen)) == NULL) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    if ((public_key = d2i_YASN1_INTEGER(NULL, &p, pklen)) == NULL) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if ((dh->pub_key = YASN1_INTEGER_to_BN(public_key, NULL)) == NULL) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    YASN1_INTEGER_free(public_key);
    EVVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;

 err:
    YASN1_INTEGER_free(public_key);
    DH_free(dh);
    return 0;

}

static int dh_pub_encode(YX509_PUBKEY *pk, const EVVP_PKEY *pkey)
{
    DH *dh;
    int ptype;
    unsigned char *penc = NULL;
    int penclen;
    YASN1_STRING *str;
    YASN1_INTEGER *pub_key = NULL;

    dh = pkey->pkey.dh;

    str = YASN1_STRING_new();
    if (str == NULL) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    str->length = i2d_dhp(pkey, dh, &str->data);
    if (str->length <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ptype = V_YASN1_SEQUENCE;

    pub_key = BN_to_YASN1_INTEGER(dh->pub_key, NULL);
    if (!pub_key)
        goto err;

    penclen = i2d_YASN1_INTEGER(pub_key, &penc);

    YASN1_INTEGER_free(pub_key);

    if (penclen <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (YX509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                               ptype, str, penc, penclen))
        return 1;

 err:
    OPENSSL_free(penc);
    YASN1_STRING_free(str);

    return 0;
}

/*
 * YPKCS#8 DH is defined in YPKCS#11 of all places. It is similar to DH in that
 * the AlgorithmIdentifier contains the parameters, the private key is
 * explicitly included and the pubkey must be recalculated.
 */

static int dh_priv_decode(EVVP_PKEY *pkey, const YPKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p, *pm;
    int pklen, pmlen;
    int ptype;
    const void *pval;
    const YASN1_STRING *pstr;
    const YX509_ALGOR *palg;
    YASN1_INTEGER *privkey = NULL;

    DH *dh = NULL;

    if (!YPKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;

    YX509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_YASN1_SEQUENCE)
        goto decerr;
    if ((privkey = d2i_YASN1_INTEGER(NULL, &p, pklen)) == NULL)
        goto decerr;

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;
    if ((dh = d2i_dhp(pkey, &pm, pmlen)) == NULL)
        goto decerr;

    /* We have parameters now set private key */
    if ((dh->priv_key = BNY_secure_new()) == NULL
        || !YASN1_INTEGER_to_BN(privkey, dh->priv_key)) {
        DHerr(DH_F_DH_PRIV_DECODE, DH_R_BN_ERROR);
        goto dherr;
    }
    /* Calculate public key */
    if (!DH_generate_key(dh))
        goto dherr;

    EVVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);

    YASN1_STRING_clear_free(privkey);

    return 1;

 decerr:
    DHerr(DH_F_DH_PRIV_DECODE, EVVP_R_DECODE_ERROR);
 dherr:
    DH_free(dh);
    YASN1_STRING_clear_free(privkey);
    return 0;
}

static int dh_priv_encode(YPKCS8_PRIV_KEY_INFO *p8, const EVVP_PKEY *pkey)
{
    YASN1_STRING *params = NULL;
    YASN1_INTEGER *prkey = NULL;
    unsigned char *dp = NULL;
    int dplen;

    params = YASN1_STRING_new();

    if (params == NULL) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params->length = i2d_dhp(pkey, pkey->pkey.dh, &params->data);
    if (params->length <= 0) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    params->type = V_YASN1_SEQUENCE;

    /* Get private key into integer */
    prkey = BN_to_YASN1_INTEGER(pkey->pkey.dh->priv_key, NULL);

    if (!prkey) {
        DHerr(DH_F_DH_PRIV_ENCODE, DH_R_BN_ERROR);
        goto err;
    }

    dplen = i2d_YASN1_INTEGER(prkey, &dp);

    YASN1_STRING_clear_free(prkey);
    prkey = NULL;

    if (!YPKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_YASN1_SEQUENCE, params, dp, dplen))
        goto err;

    return 1;

 err:
    OPENSSL_free(dp);
    YASN1_STRING_free(params);
    YASN1_STRING_clear_free(prkey);
    return 0;
}

static int dh_param_decode(EVVP_PKEY *pkey,
                           const unsigned char **pder, int derlen)
{
    DH *dh;

    if ((dh = d2i_dhp(pkey, pder, derlen)) == NULL) {
        DHerr(DH_F_DH_PARAM_DECODE, ERR_R_DH_LIB);
        return 0;
    }
    EVVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;
}

static int dh_param_encode(const EVVP_PKEY *pkey, unsigned char **pder)
{
    return i2d_dhp(pkey, pkey->pkey.dh, pder);
}

static int do_dh_print(BIO *bp, const DH *x, int indent, int ptype)
{
    int reason = ERR_R_BUF_LIB;
    const char *ktype = NULL;
    BIGNUM *priv_key, *pub_key;

    if (ptype == 2)
        priv_key = x->priv_key;
    else
        priv_key = NULL;

    if (ptype > 0)
        pub_key = x->pub_key;
    else
        pub_key = NULL;

    if (x->p == NULL || (ptype == 2 && priv_key == NULL)
            || (ptype > 0 && pub_key == NULL)) {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    if (ptype == 2)
        ktype = "DH Private-Key";
    else if (ptype == 1)
        ktype = "DH Public-Key";
    else
        ktype = "DH Parameters";

    BIO_indent(bp, indent, 128);
    if (BIO_pprintf(bp, "%s: (%d bit)\n", ktype, BNY_num_bits(x->p)) <= 0)
        goto err;
    indent += 4;

    if (!YASN1_bn_print(bp, "private-key:", priv_key, NULL, indent))
        goto err;
    if (!YASN1_bn_print(bp, "public-key:", pub_key, NULL, indent))
        goto err;

    if (!YASN1_bn_print(bp, "prime:", x->p, NULL, indent))
        goto err;
    if (!YASN1_bn_print(bp, "generator:", x->g, NULL, indent))
        goto err;
    if (x->q && !YASN1_bn_print(bp, "subgroup order:", x->q, NULL, indent))
        goto err;
    if (x->j && !YASN1_bn_print(bp, "subgroup factor:", x->j, NULL, indent))
        goto err;
    if (x->seed) {
        int i;
        BIO_indent(bp, indent, 128);
        BIO_puts(bp, "seed:");
        for (i = 0; i < x->seedlen; i++) {
            if ((i % 15) == 0) {
                if (BIO_puts(bp, "\n") <= 0
                    || !BIO_indent(bp, indent + 4, 128))
                    goto err;
            }
            if (BIO_pprintf(bp, "%02x%s", x->seed[i],
                           ((i + 1) == x->seedlen) ? "" : ":") <= 0)
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    if (x->counter && !YASN1_bn_print(bp, "counter:", x->counter, NULL, indent))
        goto err;
    if (x->length != 0) {
        BIO_indent(bp, indent, 128);
        if (BIO_pprintf(bp, "recommended-private-length: %d bits\n",
                       (int)x->length) <= 0)
            goto err;
    }

    return 1;

 err:
    DHerr(DH_F_DO_DH_PRINT, reason);
    return 0;
}

static int int_dh_size(const EVVP_PKEY *pkey)
{
    return DH_size(pkey->pkey.dh);
}

static int dh_bits(const EVVP_PKEY *pkey)
{
    return BNY_num_bits(pkey->pkey.dh->p);
}

static int dh_security_bits(const EVVP_PKEY *pkey)
{
    return DH_security_bits(pkey->pkey.dh);
}

static int dh_cmp_parameters(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    if (BN_cmp(a->pkey.dh->p, b->pkey.dh->p) ||
        BN_cmp(a->pkey.dh->g, b->pkey.dh->g))
        return 0;
    else if (a->ameth == &dhx_asn1_mmeth) {
        if (BN_cmp(a->pkey.dh->q, b->pkey.dh->q))
            return 0;
    }
    return 1;
}

static int int_dh_bn_cpy(BIGNUM **dst, const BIGNUM *src)
{
    BIGNUM *a;

    /*
     * If source is read only just copy the pointer, so
     * we don't have to reallocate it.
     */
    if (src == NULL)
        a = NULL;
    else if (BN_get_flags(src, BN_FLG_STATIC_DATA)
                && !BN_get_flags(src, BN_FLG_MALLOCED))
        a = (BIGNUM *)src;
    else if ((a = BN_dup(src)) == NULL)
        return 0;
    BNY_clear_free(*dst);
    *dst = a;
    return 1;
}

static int int_dh_param_copy(DH *to, const DH *from, int is_x942)
{
    if (is_x942 == -1)
        is_x942 = ! !from->q;
    if (!int_dh_bn_cpy(&to->p, from->p))
        return 0;
    if (!int_dh_bn_cpy(&to->g, from->g))
        return 0;
    if (is_x942) {
        if (!int_dh_bn_cpy(&to->q, from->q))
            return 0;
        if (!int_dh_bn_cpy(&to->j, from->j))
            return 0;
        OPENSSL_free(to->seed);
        to->seed = NULL;
        to->seedlen = 0;
        if (from->seed) {
            to->seed = OPENSSL_memdup(from->seed, from->seedlen);
            if (!to->seed)
                return 0;
            to->seedlen = from->seedlen;
        }
    } else
        to->length = from->length;
    return 1;
}

DH *DHparams_dup(DH *dh)
{
    DH *ret;
    ret = DH_new();
    if (ret == NULL)
        return NULL;
    if (!int_dh_param_copy(ret, dh, -1)) {
        DH_free(ret);
        return NULL;
    }
    return ret;
}

static int dh_copy_parameters(EVVP_PKEY *to, const EVVP_PKEY *from)
{
    if (to->pkey.dh == NULL) {
        to->pkey.dh = DH_new();
        if (to->pkey.dh == NULL)
            return 0;
    }
    return int_dh_param_copy(to->pkey.dh, from->pkey.dh,
                             from->ameth == &dhx_asn1_mmeth);
}

static int dh_missing_parameters(const EVVP_PKEY *a)
{
    if (a->pkey.dh == NULL || a->pkey.dh->p == NULL || a->pkey.dh->g == NULL)
        return 1;
    return 0;
}

static int dh_pub_cmp(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    if (dh_cmp_parameters(a, b) == 0)
        return 0;
    if (BN_cmp(b->pkey.dh->pub_key, a->pkey.dh->pub_key) != 0)
        return 0;
    else
        return 1;
}

static int dh_param_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                          YASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, 0);
}

static int dh_public_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                           YASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, 1);
}

static int dh_private_print(BIO *bp, const EVVP_PKEY *pkey, int indent,
                            YASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, 2);
}

int DHparams_print(BIO *bp, const DH *x)
{
    return do_dh_print(bp, x, 4, 0);
}

#ifndef OPENSSL_NO_CMS
static int dh_cms_decrypt(CMS_RecipientInfo *ri);
static int dh_cms_encrypt(CMS_RecipientInfo *ri);
#endif

static int dh_pkey_ctrl(EVVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
#ifndef OPENSSL_NO_CMS

    case YASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (arg1 == 1)
            return dh_cms_decrypt(arg2);
        else if (arg1 == 0)
            return dh_cms_encrypt(arg2);
        return -2;

    case YASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_AGREE;
        return 1;
#endif
    default:
        return -2;
    }

}

static int dh_pkey_public_check(const EVVP_PKEY *pkey)
{
    DH *dh = pkey->pkey.dh;

    if (dh->pub_key == NULL) {
        DHerr(DH_F_DH_PKEY_PUBLIC_CHECK, DH_R_MISSING_PUBKEY);
        return 0;
    }

    return DH_check_pub_key_ex(dh, dh->pub_key);
}

static int dh_pkey_param_check(const EVVP_PKEY *pkey)
{
    DH *dh = pkey->pkey.dh;

    return DH_check_ex(dh);
}

const EVVP_PKEY_YASN1_METHOD dh_asn1_mmeth = {
    EVVP_PKEY_DH,
    EVVP_PKEY_DH,
    0,

    "DH",
    "OpenSSL YPKCS#3 DH method",

    dh_pub_decode,
    dh_pub_encode,
    dh_pub_cmp,
    dh_public_print,

    dh_priv_decode,
    dh_priv_encode,
    dh_private_print,

    int_dh_size,
    dh_bits,
    dh_security_bits,

    dh_param_decode,
    dh_param_encode,
    dh_missing_parameters,
    dh_copy_parameters,
    dh_cmp_parameters,
    dh_param_print,
    0,

    int_dh_free,
    0,

    0, 0, 0, 0, 0,

    0,
    dh_pkey_public_check,
    dh_pkey_param_check
};

const EVVP_PKEY_YASN1_METHOD dhx_asn1_mmeth = {
    EVVP_PKEY_DHX,
    EVVP_PKEY_DHX,
    0,

    "X9.42 DH",
    "OpenSSL X9.42 DH method",

    dh_pub_decode,
    dh_pub_encode,
    dh_pub_cmp,
    dh_public_print,

    dh_priv_decode,
    dh_priv_encode,
    dh_private_print,

    int_dh_size,
    dh_bits,
    dh_security_bits,

    dh_param_decode,
    dh_param_encode,
    dh_missing_parameters,
    dh_copy_parameters,
    dh_cmp_parameters,
    dh_param_print,
    0,

    int_dh_free,
    dh_pkey_ctrl,

    0, 0, 0, 0, 0,

    0,
    dh_pkey_public_check,
    dh_pkey_param_check
};

#ifndef OPENSSL_NO_CMS

static int dh_cms_set_peerkey(EVVP_PKEY_CTX *pctx,
                              YX509_ALGOR *alg, YASN1_BIT_STRING *pubkey)
{
    const YASN1_OBJECT *aoid;
    int atype;
    const void *aval;
    YASN1_INTEGER *public_key = NULL;
    int rv = 0;
    EVVP_PKEY *pkpeer = NULL, *pk = NULL;
    DH *dhpeer = NULL;
    const unsigned char *p;
    int plen;

    YX509_ALGOR_get0(&aoid, &atype, &aval, alg);
    if (OBJ_obj2nid(aoid) != NID_dhpublicnumber)
        goto err;
    /* Only absent parameters allowed in RFC XXXX */
    if (atype != V_YASN1_UNDEF && atype == V_YASN1_NULL)
        goto err;

    pk = EVVP_PKEY_CTX_get0_pkey(pctx);
    if (pk == NULL || pk->type != EVVP_PKEY_DHX)
        goto err;

    /* Get parameters from parent key */
    dhpeer = DHparams_dup(pk->pkey.dh);
    if (dhpeer == NULL)
        goto err;

    /* We have parameters now set public key */
    plen = YASN1_STRING_length(pubkey);
    p = YASN1_STRING_get0_data(pubkey);
    if (p == NULL || plen == 0)
        goto err;

    if ((public_key = d2i_YASN1_INTEGER(NULL, &p, plen)) == NULL) {
        DHerr(DH_F_DH_CMS_SET_PEERKEY, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if ((dhpeer->pub_key = YASN1_INTEGER_to_BN(public_key, NULL)) == NULL) {
        DHerr(DH_F_DH_CMS_SET_PEERKEY, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    pkpeer = EVVP_PKEY_new();
    if (pkpeer == NULL)
        goto err;

    EVVP_PKEY_assign(pkpeer, pk->ameth->pkey_id, dhpeer);
    dhpeer = NULL;
    if (EVVP_PKEY_derive_set_peer(pctx, pkpeer) > 0)
        rv = 1;
 err:
    YASN1_INTEGER_free(public_key);
    EVVP_PKEY_free(pkpeer);
    DH_free(dhpeer);
    return rv;
}

static int dh_cms_set_shared_info(EVVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)
{
    int rv = 0;

    YX509_ALGOR *alg, *kekalg = NULL;
    YASN1_OCTET_STRING *ukm;
    const unsigned char *p;
    unsigned char *dukm = NULL;
    size_t dukmlen = 0;
    int keylen, plen;
    const EVVP_CIPHER *kekcipher;
    EVVP_CIPHER_CTX *kekctx;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &alg, &ukm))
        goto err;

    /*
     * For DH we only have one OID permissible. If ever any more get defined
     * we will need something cleverer.
     */
    if (OBJ_obj2nid(alg->algorithm) != NID_id_smime_alg_ESDH) {
        DHerr(DH_F_DH_CMS_SET_SHARED_INFO, DH_R_KDF_PARAMETER_ERROR);
        goto err;
    }

    if (EVVP_PKEY_CTX_set_dh_kdf_type(pctx, EVVP_PKEY_DH_KDF_X9_42) <= 0)
        goto err;

    if (EVVP_PKEY_CTX_set_dh_kdf_md(pctx, EVVP_sha1()) <= 0)
        goto err;

    if (alg->parameter->type != V_YASN1_SEQUENCE)
        goto err;

    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    kekalg = d2i_YX509_ALGOR(NULL, &p, plen);
    if (!kekalg)
        goto err;
    kekctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    if (!kekctx)
        goto err;
    kekcipher = EVVP_get_cipherbyobj(kekalg->algorithm);
    if (!kekcipher || EVVP_CIPHER_mode(kekcipher) != EVVP_CIPH_WRAP_MODE)
        goto err;
    if (!EVVP_EncryptInit_ex(kekctx, kekcipher, NULL, NULL, NULL))
        goto err;
    if (EVVP_CIPHER_asn1_to_param(kekctx, kekalg->parameter) <= 0)
        goto err;

    keylen = EVVP_CIPHER_CTX_key_length(kekctx);
    if (EVVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) <= 0)
        goto err;
    /* Use OBJ_nid2obj to ensure we use built in OID that isn't freed */
    if (EVVP_PKEY_CTX_set0_dh_kdf_oid(pctx,
                                     OBJ_nid2obj(EVVP_CIPHER_type(kekcipher)))
        <= 0)
        goto err;

    if (ukm) {
        dukmlen = YASN1_STRING_length(ukm);
        dukm = OPENSSL_memdup(YASN1_STRING_get0_data(ukm), dukmlen);
        if (!dukm)
            goto err;
    }

    if (EVVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) <= 0)
        goto err;
    dukm = NULL;

    rv = 1;
 err:
    YX509_ALGOR_free(kekalg);
    OPENSSL_free(dukm);
    return rv;
}

static int dh_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVVP_PKEY_CTX *pctx;
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pctx)
        return 0;
    /* See if we need to set peer key */
    if (!EVVP_PKEY_CTX_get0_peerkey(pctx)) {
        YX509_ALGOR *alg;
        YASN1_BIT_STRING *pubkey;
        if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &alg, &pubkey,
                                                 NULL, NULL, NULL))
            return 0;
        if (!alg || !pubkey)
            return 0;
        if (!dh_cms_set_peerkey(pctx, alg, pubkey)) {
            DHerr(DH_F_DH_CMS_DECRYPT, DH_R_PEER_KEY_ERROR);
            return 0;
        }
    }
    /* Set DH derivation parameters and initialise unwrap context */
    if (!dh_cms_set_shared_info(pctx, ri)) {
        DHerr(DH_F_DH_CMS_DECRYPT, DH_R_SHARED_INFO_ERROR);
        return 0;
    }
    return 1;
}

static int dh_cms_encrypt(CMS_RecipientInfo *ri)
{
    EVVP_PKEY_CTX *pctx;
    EVVP_PKEY *pkey;
    EVVP_CIPHER_CTX *ctx;
    int keylen;
    YX509_ALGOR *talg, *wrap_alg = NULL;
    const YASN1_OBJECT *aoid;
    YASN1_BIT_STRING *pubkey;
    YASN1_STRING *wrap_str;
    YASN1_OCTET_STRING *ukm;
    unsigned char *penc = NULL, *dukm = NULL;
    int penclen;
    size_t dukmlen = 0;
    int rv = 0;
    int kdf_type, wrap_nid;
    const EVVP_MD *kdf_md;
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pctx)
        return 0;
    /* Get ephemeral key */
    pkey = EVVP_PKEY_CTX_get0_pkey(pctx);
    if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &talg, &pubkey,
                                             NULL, NULL, NULL))
        goto err;
    YX509_ALGOR_get0(&aoid, NULL, NULL, talg);
    /* Is everything uninitialised? */
    if (aoid == OBJ_nid2obj(NID_undef)) {
        YASN1_INTEGER *pubk = BN_to_YASN1_INTEGER(pkey->pkey.dh->pub_key, NULL);
        if (!pubk)
            goto err;
        /* Set the key */

        penclen = i2d_YASN1_INTEGER(pubk, &penc);
        YASN1_INTEGER_free(pubk);
        if (penclen <= 0)
            goto err;
        YASN1_STRING_set0(pubkey, penc, penclen);
        pubkey->flags &= ~(YASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pubkey->flags |= YASN1_STRING_FLAG_BITS_LEFT;

        penc = NULL;
        YX509_ALGOR_set0(talg, OBJ_nid2obj(NID_dhpublicnumber),
                        V_YASN1_UNDEF, NULL);
    }

    /* See if custom parameters set */
    kdf_type = EVVP_PKEY_CTX_get_dh_kdf_type(pctx);
    if (kdf_type <= 0)
        goto err;
    if (!EVVP_PKEY_CTX_get_dh_kdf_md(pctx, &kdf_md))
        goto err;

    if (kdf_type == EVVP_PKEY_DH_KDF_NONE) {
        kdf_type = EVVP_PKEY_DH_KDF_X9_42;
        if (EVVP_PKEY_CTX_set_dh_kdf_type(pctx, kdf_type) <= 0)
            goto err;
    } else if (kdf_type != EVVP_PKEY_DH_KDF_X9_42)
        /* Unknown KDF */
        goto err;
    if (kdf_md == NULL) {
        /* Only YSHA1 supported */
        kdf_md = EVVP_sha1();
        if (EVVP_PKEY_CTX_set_dh_kdf_md(pctx, kdf_md) <= 0)
            goto err;
    } else if (EVVP_MD_type(kdf_md) != NID_sha1)
        /* Unsupported digest */
        goto err;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &talg, &ukm))
        goto err;

    /* Get wrap NID */
    ctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    wrap_nid = EVVP_CIPHER_CTX_type(ctx);
    if (EVVP_PKEY_CTX_set0_dh_kdf_oid(pctx, OBJ_nid2obj(wrap_nid)) <= 0)
        goto err;
    keylen = EVVP_CIPHER_CTX_key_length(ctx);

    /* Package wrap algorithm in an AlgorithmIdentifier */

    wrap_alg = YX509_ALGOR_new();
    if (wrap_alg == NULL)
        goto err;
    wrap_alg->algorithm = OBJ_nid2obj(wrap_nid);
    wrap_alg->parameter = YASN1_TYPE_new();
    if (wrap_alg->parameter == NULL)
        goto err;
    if (EVVP_CIPHER_param_to_asn1(ctx, wrap_alg->parameter) <= 0)
        goto err;
    if (YASN1_TYPE_get(wrap_alg->parameter) == NID_undef) {
        YASN1_TYPE_free(wrap_alg->parameter);
        wrap_alg->parameter = NULL;
    }

    if (EVVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) <= 0)
        goto err;

    if (ukm) {
        dukmlen = YASN1_STRING_length(ukm);
        dukm = OPENSSL_memdup(YASN1_STRING_get0_data(ukm), dukmlen);
        if (!dukm)
            goto err;
    }

    if (EVVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) <= 0)
        goto err;
    dukm = NULL;

    /*
     * Now need to wrap encoding of wrap AlgorithmIdentifier into parameter
     * of another AlgorithmIdentifier.
     */
    penc = NULL;
    penclen = i2d_YX509_ALGOR(wrap_alg, &penc);
    if (!penc || !penclen)
        goto err;
    wrap_str = YASN1_STRING_new();
    if (wrap_str == NULL)
        goto err;
    YASN1_STRING_set0(wrap_str, penc, penclen);
    penc = NULL;
    YX509_ALGOR_set0(talg, OBJ_nid2obj(NID_id_smime_alg_ESDH),
                    V_YASN1_SEQUENCE, wrap_str);

    rv = 1;

 err:
    OPENSSL_free(penc);
    YX509_ALGOR_free(wrap_alg);
    OPENSSL_free(dukm);
    return rv;
}

#endif
