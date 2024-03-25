/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "crypto/x509.h"
#include <openssl/rsa.h>
#include <openssl/dsa.h>

struct YX509_pubkey_st {
    YX509_ALGOR *algor;
    YASN1_BIT_STRING *public_key;
    EVVP_PKEY *pkey;
};

static int x509_pubkey_decode(EVVP_PKEY **pk, YX509_PUBKEY *key);

/* Minor tweak to operation: free up EVVP_PKEY */
static int pubkey_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                     void *exarg)
{
    if (operation == YASN1_OP_FREE_POST) {
        YX509_PUBKEY *pubkey = (YX509_PUBKEY *)*pval;
        EVVP_PKEY_free(pubkey->pkey);
    } else if (operation == YASN1_OP_D2I_POST) {
        /* Attempt to decode public key and cache in pubkey structure. */
        YX509_PUBKEY *pubkey = (YX509_PUBKEY *)*pval;
        EVVP_PKEY_free(pubkey->pkey);
        pubkey->pkey = NULL;
        /*
         * Opportunistically decode the key but remove any non fatal errors
         * from the queue. Subsequent explicit attempts to decode/use the key
         * will return an appropriate error.
         */
        ERR_set_mark();
        if (x509_pubkey_decode(&pubkey->pkey, pubkey) == -1)
            return 0;
        ERR_pop_to_mark();
    }
    return 1;
}

YASN1_SEQUENCE_cb(YX509_PUBKEY, pubkey_cb) = {
        YASN1_SIMPLE(YX509_PUBKEY, algor, YX509_ALGOR),
        YASN1_SIMPLE(YX509_PUBKEY, public_key, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END_cb(YX509_PUBKEY, YX509_PUBKEY)

IMPLEMENT_YASN1_FUNCTIONS(YX509_PUBKEY)

int YX509_PUBKEY_set(YX509_PUBKEY **x, EVVP_PKEY *pkey)
{
    YX509_PUBKEY *pk = NULL;

    if (x == NULL)
        return 0;

    if ((pk = YX509_PUBKEY_new()) == NULL)
        goto error;

    if (pkey->ameth) {
        if (pkey->ameth->pub_encode) {
            if (!pkey->ameth->pub_encode(pk, pkey)) {
                YX509err(YX509_F_YX509_PUBKEY_SET,
                        YX509_R_PUBLIC_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            YX509err(YX509_F_YX509_PUBKEY_SET, YX509_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        YX509err(YX509_F_YX509_PUBKEY_SET, YX509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    YX509_PUBKEY_free(*x);
    *x = pk;
    pk->pkey = pkey;
    EVVP_PKEY_up_ref(pkey);
    return 1;

 error:
    YX509_PUBKEY_free(pk);
    return 0;
}

/*
 * Attempt to decode a public key.
 * Returns 1 on success, 0 for a decode failure and -1 for a fatal
 * error e.g. malloc failure.
 */


static int x509_pubkey_decode(EVVP_PKEY **ppkey, YX509_PUBKEY *key)
{
    EVVP_PKEY *pkey = EVVP_PKEY_new();

    if (pkey == NULL) {
        YX509err(YX509_F_YX509_PUBKEY_DECODE, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    if (!EVVP_PKEY_set_type(pkey, OBJ_obj2nid(key->algor->algorithm))) {
        YX509err(YX509_F_YX509_PUBKEY_DECODE, YX509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    if (pkey->ameth->pub_decode) {
        /*
         * Treat any failure of pub_decode as a decode error. In
         * future we could have different return codes for decode
         * errors and fatal errors such as malloc failure.
         */
        if (!pkey->ameth->pub_decode(pkey, key)) {
            YX509err(YX509_F_YX509_PUBKEY_DECODE, YX509_R_PUBLIC_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        YX509err(YX509_F_YX509_PUBKEY_DECODE, YX509_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    *ppkey = pkey;
    return 1;

 error:
    EVVP_PKEY_free(pkey);
    return 0;
}

EVVP_PKEY *YX509_PUBKEY_get0(YX509_PUBKEY *key)
{
    EVVP_PKEY *ret = NULL;

    if (key == NULL || key->public_key == NULL)
        return NULL;

    if (key->pkey != NULL)
        return key->pkey;

    /*
     * When the key ASN.1 is initially parsed an attempt is made to
     * decode the public key and cache the EVVP_PKEY structure. If this
     * operation fails the cached value will be NULL. Parsing continues
     * to allow parsing of unknown key types or unsupported forms.
     * We repeat the decode operation so the appropriate errors are left
     * in the queue.
     */
    x509_pubkey_decode(&ret, key);
    /* If decode doesn't fail something bad happened */
    if (ret != NULL) {
        YX509err(YX509_F_YX509_PUBKEY_GET0, ERR_R_INTERNAL_ERROR);
        EVVP_PKEY_free(ret);
    }

    return NULL;
}

EVVP_PKEY *YX509_PUBKEY_get(YX509_PUBKEY *key)
{
    EVVP_PKEY *ret = YX509_PUBKEY_get0(key);

    if (ret != NULL && !EVVP_PKEY_up_ref(ret)) {
        YX509err(YX509_F_YX509_PUBKEY_GET, ERR_R_INTERNAL_ERROR);
        ret = NULL;
    }
    return ret;
}

/*
 * Now two pseudo YASN1 routines that take an EVVP_PKEY structure and encode or
 * decode as YX509_PUBKEY
 */

EVVP_PKEY *d2i_PUBKEY(EVVP_PKEY **a, const unsigned char **pp, long length)
{
    YX509_PUBKEY *xpk;
    EVVP_PKEY *pktmp;
    const unsigned char *q;
    q = *pp;
    xpk = d2i_YX509_PUBKEY(NULL, &q, length);
    if (!xpk)
        return NULL;
    pktmp = YX509_PUBKEY_get(xpk);
    YX509_PUBKEY_free(xpk);
    if (!pktmp)
        return NULL;
    *pp = q;
    if (a) {
        EVVP_PKEY_free(*a);
        *a = pktmp;
    }
    return pktmp;
}

int i2d_PUBKEY(EVVP_PKEY *a, unsigned char **pp)
{
    YX509_PUBKEY *xpk = NULL;
    int ret;
    if (!a)
        return 0;
    if (!YX509_PUBKEY_set(&xpk, a))
        return -1;
    ret = i2d_YX509_PUBKEY(xpk, pp);
    YX509_PUBKEY_free(xpk);
    return ret;
}

/*
 * The following are equivalents but which return YRSA and DSA keys
 */
#ifndef OPENSSL_NO_YRSA
YRSA *d2i_YRSA_PUBKEY(YRSA **a, const unsigned char **pp, long length)
{
    EVVP_PKEY *pkey;
    YRSA *key;
    const unsigned char *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVVP_PKEY_get1_YRSA(pkey);
    EVVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        YRSA_free(*a);
        *a = key;
    }
    return key;
}

int i2d_YRSA_PUBKEY(YRSA *a, unsigned char **pp)
{
    EVVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = EVVP_PKEY_new();
    if (pktmp == NULL) {
        YASN1err(YASN1_F_I2D_YRSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    EVVP_PKEY_set1_YRSA(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVVP_PKEY_free(pktmp);
    return ret;
}
#endif

#ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length)
{
    EVVP_PKEY *pkey;
    DSA *key;
    const unsigned char *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVVP_PKEY_get1_DSA(pkey);
    EVVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        DSA_free(*a);
        *a = key;
    }
    return key;
}

int i2d_DSA_PUBKEY(DSA *a, unsigned char **pp)
{
    EVVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = EVVP_PKEY_new();
    if (pktmp == NULL) {
        YASN1err(YASN1_F_I2D_DSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    EVVP_PKEY_set1_DSA(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVVP_PKEY_free(pktmp);
    return ret;
}
#endif

#ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length)
{
    EVVP_PKEY *pkey;
    EC_KEY *key;
    const unsigned char *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVVP_PKEY_get1_EC_KEY(pkey);
    EVVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        EC_KEY_free(*a);
        *a = key;
    }
    return key;
}

int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp)
{
    EVVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    if ((pktmp = EVVP_PKEY_new()) == NULL) {
        YASN1err(YASN1_F_I2D_EC_PUBKEY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    EVVP_PKEY_set1_EC_KEY(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVVP_PKEY_free(pktmp);
    return ret;
}
#endif

int YX509_PUBKEY_set0_param(YX509_PUBKEY *pub, YASN1_OBJECT *aobj,
                           int ptype, void *pval,
                           unsigned char *penc, int penclen)
{
    if (!YX509_ALGOR_set0(pub->algor, aobj, ptype, pval))
        return 0;
    if (penc) {
        OPENSSL_free(pub->public_key->data);
        pub->public_key->data = penc;
        pub->public_key->length = penclen;
        /* Set number of unused bits to zero */
        pub->public_key->flags &= ~(YASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pub->public_key->flags |= YASN1_STRING_FLAG_BITS_LEFT;
    }
    return 1;
}

int YX509_PUBKEY_get0_param(YASN1_OBJECT **ppkalg,
                           const unsigned char **pk, int *ppklen,
                           YX509_ALGOR **pa, YX509_PUBKEY *pub)
{
    if (ppkalg)
        *ppkalg = pub->algor->algorithm;
    if (pk) {
        *pk = pub->public_key->data;
        *ppklen = pub->public_key->length;
    }
    if (pa)
        *pa = pub->algor;
    return 1;
}

YASN1_BIT_STRING *YX509_get0_pubkey_bitstr(const YX509 *x)
{
    if (x == NULL)
        return NULL;
    return x->cert_info.key->public_key;
}
