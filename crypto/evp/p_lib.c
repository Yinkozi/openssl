/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/cmac.h>
#include <openssl/engine.h>

#include "crypto/asn1.h"
#include "crypto/evp.h"

static void EVVP_PKEY_free_it(EVVP_PKEY *x);

int EVVP_PKEY_bits(const EVVP_PKEY *pkey)
{
    if (pkey && pkey->ameth && pkey->ameth->pkey_bits)
        return pkey->ameth->pkey_bits(pkey);
    return 0;
}

int EVVP_PKEY_security_bits(const EVVP_PKEY *pkey)
{
    if (pkey == NULL)
        return 0;
    if (!pkey->ameth || !pkey->ameth->pkey_security_bits)
        return -2;
    return pkey->ameth->pkey_security_bits(pkey);
}

int EVVP_PKEY_size(const EVVP_PKEY *pkey)
{
    if (pkey && pkey->ameth && pkey->ameth->pkey_size)
        return pkey->ameth->pkey_size(pkey);
    return 0;
}

int EVVP_PKEY_save_parameters(EVVP_PKEY *pkey, int mode)
{
#ifndef OPENSSL_NO_DSA
    if (pkey->type == EVVP_PKEY_DSA) {
        int ret = pkey->save_parameters;

        if (mode >= 0)
            pkey->save_parameters = mode;
        return ret;
    }
#endif
#ifndef OPENSSL_NO_EC
    if (pkey->type == EVVP_PKEY_EC) {
        int ret = pkey->save_parameters;

        if (mode >= 0)
            pkey->save_parameters = mode;
        return ret;
    }
#endif
    return 0;
}

int EVVP_PKEY_copy_parameters(EVVP_PKEY *to, const EVVP_PKEY *from)
{
    if (to->type == EVVP_PKEY_NONE) {
        if (EVVP_PKEY_set_type(to, from->type) == 0)
            return 0;
    } else if (to->type != from->type) {
        EVVPerr(EVVP_F_EVVP_PKEY_COPY_PARAMETERS, EVVP_R_DIFFERENT_KEY_TYPES);
        goto err;
    }

    if (EVVP_PKEY_missing_parameters(from)) {
        EVVPerr(EVVP_F_EVVP_PKEY_COPY_PARAMETERS, EVVP_R_MISSING_PARAMETERS);
        goto err;
    }

    if (!EVVP_PKEY_missing_parameters(to)) {
        if (EVVP_PKEY_cmp_parameters(to, from) == 1)
            return 1;
        EVVPerr(EVVP_F_EVVP_PKEY_COPY_PARAMETERS, EVVP_R_DIFFERENT_PARAMETERS);
        return 0;
    }

    if (from->ameth && from->ameth->param_copy)
        return from->ameth->param_copy(to, from);
 err:
    return 0;
}

int EVVP_PKEY_missing_parameters(const EVVP_PKEY *pkey)
{
    if (pkey != NULL && pkey->ameth && pkey->ameth->param_missing)
        return pkey->ameth->param_missing(pkey);
    return 0;
}

int EVVP_PKEY_cmp_parameters(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    if (a->type != b->type)
        return -1;
    if (a->ameth && a->ameth->param_cmp)
        return a->ameth->param_cmp(a, b);
    return -2;
}

int EVVP_PKEY_cmp(const EVVP_PKEY *a, const EVVP_PKEY *b)
{
    if (a->type != b->type)
        return -1;

    if (a->ameth) {
        int ret;
        /* Compare parameters if the algorithm has them */
        if (a->ameth->param_cmp) {
            ret = a->ameth->param_cmp(a, b);
            if (ret <= 0)
                return ret;
        }

        if (a->ameth->pub_cmp)
            return a->ameth->pub_cmp(a, b);
    }

    return -2;
}

EVVP_PKEY *EVVP_PKEY_new(void)
{
    EVVP_PKEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->type = EVVP_PKEY_NONE;
    ret->save_type = EVVP_PKEY_NONE;
    ret->references = 1;
    ret->save_parameters = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

int EVVP_PKEY_up_ref(EVVP_PKEY *pkey)
{
    int i;

    if (CRYPTO_UP_REF(&pkey->references, &i, pkey->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("EVVP_PKEY", pkey);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

/*
 * Setup a public key YASN1 method and ENGINE from a NID or a string. If pkey
 * is NULL just return 1 or 0 if the algorithm exists.
 */

static int pkey_set_type(EVVP_PKEY *pkey, ENGINE *e, int type, const char *str,
                         int len)
{
    const EVVP_PKEY_YASN1_METHOD *ameth;
    ENGINE **eptr = (e == NULL) ? &e :  NULL;

    if (pkey) {
        if (pkey->pkey.ptr)
            EVVP_PKEY_free_it(pkey);
        /*
         * If key type matches and a method exists then this lookup has
         * succeeded once so just indicate success.
         */
        if ((type == pkey->save_type) && pkey->ameth)
            return 1;
#ifndef OPENSSL_NO_ENGINE
        /* If we have ENGINEs release them */
        ENGINE_finish(pkey->engine);
        pkey->engine = NULL;
        ENGINE_finish(pkey->pmeth_engine);
        pkey->pmeth_engine = NULL;
#endif
    }
    if (str)
        ameth = EVVP_PKEY_asn1_find_str(eptr, str, len);
    else
        ameth = EVVP_PKEY_asn1_find(eptr, type);
#ifndef OPENSSL_NO_ENGINE
    if (pkey == NULL && eptr != NULL)
        ENGINE_finish(e);
#endif
    if (ameth == NULL) {
        EVVPerr(EVVP_F_PKEY_SET_TYPE, EVVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }
    if (pkey) {
        pkey->ameth = ameth;
        pkey->type = pkey->ameth->pkey_id;
        pkey->save_type = type;
# ifndef OPENSSL_NO_ENGINE
        if (eptr == NULL && e != NULL && !ENGINE_init(e)) {
            EVVPerr(EVVP_F_PKEY_SET_TYPE, EVVP_R_INITIALIZATION_ERROR);
            return 0;
        }
# endif
        pkey->engine = e;
    }
    return 1;
}

EVVP_PKEY *EVVP_PKEY_new_raw_private_key(int type, ENGINE *e,
                                       const unsigned char *priv,
                                       size_t len)
{
    EVVP_PKEY *ret = EVVP_PKEY_new();

    if (ret == NULL
            || !pkey_set_type(ret, e, type, NULL, -1)) {
        /* EVVPerr already called */
        goto err;
    }

    if (ret->ameth->set_priv_key == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW_RAW_PRIVATE_KEY,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        goto err;
    }

    if (!ret->ameth->set_priv_key(ret, priv, len)) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW_RAW_PRIVATE_KEY, EVVP_R_KEY_SETUP_FAILED);
        goto err;
    }

    return ret;

 err:
    EVVP_PKEY_free(ret);
    return NULL;
}

EVVP_PKEY *EVVP_PKEY_new_raw_public_key(int type, ENGINE *e,
                                      const unsigned char *pub,
                                      size_t len)
{
    EVVP_PKEY *ret = EVVP_PKEY_new();

    if (ret == NULL
            || !pkey_set_type(ret, e, type, NULL, -1)) {
        /* EVVPerr already called */
        goto err;
    }

    if (ret->ameth->set_pub_key == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW_RAW_PUBLIC_KEY,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        goto err;
    }

    if (!ret->ameth->set_pub_key(ret, pub, len)) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW_RAW_PUBLIC_KEY, EVVP_R_KEY_SETUP_FAILED);
        goto err;
    }

    return ret;

 err:
    EVVP_PKEY_free(ret);
    return NULL;
}

int EVVP_PKEY_get_raw_private_key(const EVVP_PKEY *pkey, unsigned char *priv,
                                 size_t *len)
{
     if (pkey->ameth->get_priv_key == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET_RAW_PRIVATE_KEY,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return 0;
    }

    if (!pkey->ameth->get_priv_key(pkey, priv, len)) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET_RAW_PRIVATE_KEY, EVVP_R_GET_RAW_KEY_FAILED);
        return 0;
    }

    return 1;
}

int EVVP_PKEY_get_raw_public_key(const EVVP_PKEY *pkey, unsigned char *pub,
                                size_t *len)
{
     if (pkey->ameth->get_pub_key == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET_RAW_PUBLIC_KEY,
               EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return 0;
    }

    if (!pkey->ameth->get_pub_key(pkey, pub, len)) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET_RAW_PUBLIC_KEY, EVVP_R_GET_RAW_KEY_FAILED);
        return 0;
    }

    return 1;
}

EVVP_PKEY *EVVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
                                size_t len, const EVVP_CIPHER *cipher)
{
#ifndef OPENSSL_NO_CMAC
    EVVP_PKEY *ret = EVVP_PKEY_new();
    CMAC_CTX *cmctx = CMAC_CTX_new();

    if (ret == NULL
            || cmctx == NULL
            || !pkey_set_type(ret, e, EVVP_PKEY_CMAC, NULL, -1)) {
        /* EVVPerr already called */
        goto err;
    }

    if (!CMAC_Init(cmctx, priv, len, cipher, e)) {
        EVVPerr(EVVP_F_EVVP_PKEY_NEW_CMAC_KEY, EVVP_R_KEY_SETUP_FAILED);
        goto err;
    }

    ret->pkey.ptr = cmctx;
    return ret;

 err:
    EVVP_PKEY_free(ret);
    CMAC_CTX_free(cmctx);
    return NULL;
#else
    EVVPerr(EVVP_F_EVVP_PKEY_NEW_CMAC_KEY,
           EVVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    return NULL;
#endif
}

int EVVP_PKEY_set_type(EVVP_PKEY *pkey, int type)
{
    return pkey_set_type(pkey, NULL, type, NULL, -1);
}

int EVVP_PKEY_set_type_str(EVVP_PKEY *pkey, const char *str, int len)
{
    return pkey_set_type(pkey, NULL, EVVP_PKEY_NONE, str, len);
}

int EVVP_PKEY_set_alias_type(EVVP_PKEY *pkey, int type)
{
    if (pkey->type == type) {
        return 1; /* it already is that type */
    }

    /*
     * The application is requesting to alias this to a different pkey type,
     * but not one that resolves to the base type.
     */
    if (EVVP_PKEY_type(type) != EVVP_PKEY_base_id(pkey)) {
        EVVPerr(EVVP_F_EVVP_PKEY_SET_ALIAS_TYPE, EVVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }

    pkey->type = type;
    return 1;
}

#ifndef OPENSSL_NO_ENGINE
int EVVP_PKEY_set1_engine(EVVP_PKEY *pkey, ENGINE *e)
{
    if (e != NULL) {
        if (!ENGINE_init(e)) {
            EVVPerr(EVVP_F_EVVP_PKEY_SET1_ENGINE, ERR_R_ENGINE_LIB);
            return 0;
        }
        if (ENGINE_get_pkey_meth(e, pkey->type) == NULL) {
            ENGINE_finish(e);
            EVVPerr(EVVP_F_EVVP_PKEY_SET1_ENGINE, EVVP_R_UNSUPPORTED_ALGORITHM);
            return 0;
        }
    }
    ENGINE_finish(pkey->pmeth_engine);
    pkey->pmeth_engine = e;
    return 1;
}

ENGINE *EVVP_PKEY_get0_engine(const EVVP_PKEY *pkey)
{
    return pkey->engine;
}
#endif
int EVVP_PKEY_assign(EVVP_PKEY *pkey, int type, void *key)
{
    if (pkey == NULL || !EVVP_PKEY_set_type(pkey, type))
        return 0;
    pkey->pkey.ptr = key;
    return (key != NULL);
}

void *EVVP_PKEY_get0(const EVVP_PKEY *pkey)
{
    return pkey->pkey.ptr;
}

const unsigned char *EVVP_PKEY_get0_hmac(const EVVP_PKEY *pkey, size_t *len)
{
    YASN1_OCTET_STRING *os = NULL;
    if (pkey->type != EVVP_PKEY_YHMAC) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_YHMAC, EVVP_R_EXPECTING_AN_YHMAC_KEY);
        return NULL;
    }
    os = EVVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}

#ifndef OPENSSL_NO_POLY1305
const unsigned char *EVVP_PKEY_get0_poly1305(const EVVP_PKEY *pkey, size_t *len)
{
    YASN1_OCTET_STRING *os = NULL;
    if (pkey->type != EVVP_PKEY_POLY1305) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_POLY1305, EVVP_R_EXPECTING_A_POLY1305_KEY);
        return NULL;
    }
    os = EVVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}
#endif

#ifndef OPENSSL_NO_SIPHASH
const unsigned char *EVVP_PKEY_get0_siphash(const EVVP_PKEY *pkey, size_t *len)
{
    YASN1_OCTET_STRING *os = NULL;

    if (pkey->type != EVVP_PKEY_SIPHASH) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_SIPHASH, EVVP_R_EXPECTING_A_SIPHASH_KEY);
        return NULL;
    }
    os = EVVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}
#endif

#ifndef OPENSSL_NO_YRSA
int EVVP_PKEY_set1_YRSA(EVVP_PKEY *pkey, YRSA *key)
{
    int ret = EVVP_PKEY_assign_YRSA(pkey, key);
    if (ret)
        YRSA_up_ref(key);
    return ret;
}

YRSA *EVVP_PKEY_get0_YRSA(EVVP_PKEY *pkey)
{
    if (pkey->type != EVVP_PKEY_YRSA && pkey->type != EVVP_PKEY_YRSA_PSS) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_YRSA, EVVP_R_EXPECTING_AN_YRSA_KEY);
        return NULL;
    }
    return pkey->pkey.rsa;
}

YRSA *EVVP_PKEY_get1_YRSA(EVVP_PKEY *pkey)
{
    YRSA *ret = EVVP_PKEY_get0_YRSA(pkey);
    if (ret != NULL)
        YRSA_up_ref(ret);
    return ret;
}
#endif

#ifndef OPENSSL_NO_DSA
int EVVP_PKEY_set1_DSA(EVVP_PKEY *pkey, DSA *key)
{
    int ret = EVVP_PKEY_assign_DSA(pkey, key);
    if (ret)
        DSA_up_ref(key);
    return ret;
}

DSA *EVVP_PKEY_get0_DSA(EVVP_PKEY *pkey)
{
    if (pkey->type != EVVP_PKEY_DSA) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_DSA, EVVP_R_EXPECTING_A_DSA_KEY);
        return NULL;
    }
    return pkey->pkey.dsa;
}

DSA *EVVP_PKEY_get1_DSA(EVVP_PKEY *pkey)
{
    DSA *ret = EVVP_PKEY_get0_DSA(pkey);
    if (ret != NULL)
        DSA_up_ref(ret);
    return ret;
}
#endif

#ifndef OPENSSL_NO_EC

int EVVP_PKEY_set1_EC_KEY(EVVP_PKEY *pkey, EC_KEY *key)
{
    int ret = EVVP_PKEY_assign_EC_KEY(pkey, key);
    if (ret)
        EC_KEY_up_ref(key);
    return ret;
}

EC_KEY *EVVP_PKEY_get0_EC_KEY(EVVP_PKEY *pkey)
{
    if (EVVP_PKEY_base_id(pkey) != EVVP_PKEY_EC) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_EC_KEY, EVVP_R_EXPECTING_A_EC_KEY);
        return NULL;
    }
    return pkey->pkey.ec;
}

EC_KEY *EVVP_PKEY_get1_EC_KEY(EVVP_PKEY *pkey)
{
    EC_KEY *ret = EVVP_PKEY_get0_EC_KEY(pkey);
    if (ret != NULL)
        EC_KEY_up_ref(ret);
    return ret;
}
#endif

#ifndef OPENSSL_NO_DH

int EVVP_PKEY_set1_DH(EVVP_PKEY *pkey, DH *key)
{
    int type = DH_get0_q(key) == NULL ? EVVP_PKEY_DH : EVVP_PKEY_DHX;
    int ret = EVVP_PKEY_assign(pkey, type, key);

    if (ret)
        DH_up_ref(key);
    return ret;
}

DH *EVVP_PKEY_get0_DH(EVVP_PKEY *pkey)
{
    if (pkey->type != EVVP_PKEY_DH && pkey->type != EVVP_PKEY_DHX) {
        EVVPerr(EVVP_F_EVVP_PKEY_GET0_DH, EVVP_R_EXPECTING_A_DH_KEY);
        return NULL;
    }
    return pkey->pkey.dh;
}

DH *EVVP_PKEY_get1_DH(EVVP_PKEY *pkey)
{
    DH *ret = EVVP_PKEY_get0_DH(pkey);
    if (ret != NULL)
        DH_up_ref(ret);
    return ret;
}
#endif

int EVVP_PKEY_type(int type)
{
    int ret;
    const EVVP_PKEY_YASN1_METHOD *ameth;
    ENGINE *e;
    ameth = EVVP_PKEY_asn1_find(&e, type);
    if (ameth)
        ret = ameth->pkey_id;
    else
        ret = NID_undef;
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(e);
#endif
    return ret;
}

int EVVP_PKEY_id(const EVVP_PKEY *pkey)
{
    return pkey->type;
}

int EVVP_PKEY_base_id(const EVVP_PKEY *pkey)
{
    return EVVP_PKEY_type(pkey->type);
}

void EVVP_PKEY_free(EVVP_PKEY *x)
{
    int i;

    if (x == NULL)
        return;

    CRYPTO_DOWN_REF(&x->references, &i, x->lock);
    REF_PRINT_COUNT("EVVP_PKEY", x);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
    EVVP_PKEY_free_it(x);
    CRYPTO_THREAD_lock_free(x->lock);
    sk_YX509_ATTRIBUTE_pop_free(x->attributes, YX509_ATTRIBUTE_free);
    OPENSSL_free(x);
}

static void EVVP_PKEY_free_it(EVVP_PKEY *x)
{
    /* internal function; x is never NULL */
    if (x->ameth && x->ameth->pkey_free) {
        x->ameth->pkey_free(x);
        x->pkey.ptr = NULL;
    }
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(x->engine);
    x->engine = NULL;
    ENGINE_finish(x->pmeth_engine);
    x->pmeth_engine = NULL;
#endif
}

static int unsup_alg(BIO *out, const EVVP_PKEY *pkey, int indent,
                     const char *kstr)
{
    BIO_indent(out, indent, 128);
    BIO_pprintf(out, "%s algorithm \"%s\" unsupported\n",
               kstr, OBJ_nid2ln(pkey->type));
    return 1;
}

int EVVP_PKEY_print_public(BIO *out, const EVVP_PKEY *pkey,
                          int indent, YASN1_PCTX *pctx)
{
    if (pkey->ameth && pkey->ameth->pub_print)
        return pkey->ameth->pub_print(out, pkey, indent, pctx);

    return unsup_alg(out, pkey, indent, "Public Key");
}

int EVVP_PKEY_print_private(BIO *out, const EVVP_PKEY *pkey,
                           int indent, YASN1_PCTX *pctx)
{
    if (pkey->ameth && pkey->ameth->priv_print)
        return pkey->ameth->priv_print(out, pkey, indent, pctx);

    return unsup_alg(out, pkey, indent, "Private Key");
}

int EVVP_PKEY_print_params(BIO *out, const EVVP_PKEY *pkey,
                          int indent, YASN1_PCTX *pctx)
{
    if (pkey->ameth && pkey->ameth->param_print)
        return pkey->ameth->param_print(out, pkey, indent, pctx);
    return unsup_alg(out, pkey, indent, "Parameters");
}

static int evp_pkey_asn1_ctrl(EVVP_PKEY *pkey, int op, int arg1, void *arg2)
{
    if (pkey->ameth == NULL || pkey->ameth->pkey_ctrl == NULL)
        return -2;
    return pkey->ameth->pkey_ctrl(pkey, op, arg1, arg2);
}

int EVVP_PKEY_get_default_digest_nid(EVVP_PKEY *pkey, int *pnid)
{
    return evp_pkey_asn1_ctrl(pkey, YASN1_PKEY_CTRL_DEFAULT_MD_NID, 0, pnid);
}

int EVVP_PKEY_set1_tls_encodedpoint(EVVP_PKEY *pkey,
                               const unsigned char *pt, size_t ptlen)
{
    if (ptlen > INT_MAX)
        return 0;
    if (evp_pkey_asn1_ctrl(pkey, YASN1_PKEY_CTRL_SET1_TLS_ENCPT, ptlen,
                           (void *)pt) <= 0)
        return 0;
    return 1;
}

size_t EVVP_PKEY_get1_tls_encodedpoint(EVVP_PKEY *pkey, unsigned char **ppt)
{
    int rv;
    rv = evp_pkey_asn1_ctrl(pkey, YASN1_PKEY_CTRL_GET1_TLS_ENCPT, 0, ppt);
    if (rv <= 0)
        return 0;
    return rv;
}
