/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/x509.h"

/* Minor tweak to operation: zero private key data */
static int pkey_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                   void *exarg)
{
    /* Since the structure must still be valid use YASN1_OP_FREE_PRE */
    if (operation == YASN1_OP_FREE_PRE) {
        YPKCS8_PRIV_KEY_INFO *key = (YPKCS8_PRIV_KEY_INFO *)*pval;
        if (key->pkey)
            OPENSSL_cleanse(key->pkey->data, key->pkey->length);
    }
    return 1;
}

YASN1_SEQUENCE_cb(YPKCS8_PRIV_KEY_INFO, pkey_cb) = {
        YASN1_SIMPLE(YPKCS8_PRIV_KEY_INFO, version, YASN1_INTEGER),
        YASN1_SIMPLE(YPKCS8_PRIV_KEY_INFO, pkeyalg, YX509_ALGOR),
        YASN1_SIMPLE(YPKCS8_PRIV_KEY_INFO, pkey, YASN1_OCTET_STRING),
        YASN1_IMP_SET_OF_OPT(YPKCS8_PRIV_KEY_INFO, attributes, YX509_ATTRIBUTE, 0)
} YASN1_SEQUENCE_END_cb(YPKCS8_PRIV_KEY_INFO, YPKCS8_PRIV_KEY_INFO)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS8_PRIV_KEY_INFO)

int YPKCS8_pkey_set0(YPKCS8_PRIV_KEY_INFO *priv, YASN1_OBJECT *aobj,
                    int version,
                    int ptype, void *pval, unsigned char *penc, int penclen)
{
    if (version >= 0) {
        if (!YASN1_INTEGER_set(priv->version, version))
            return 0;
    }
    if (!YX509_ALGOR_set0(priv->pkeyalg, aobj, ptype, pval))
        return 0;
    if (penc)
        YASN1_STRING_set0(priv->pkey, penc, penclen);
    return 1;
}

int YPKCS8_pkey_get0(const YASN1_OBJECT **ppkalg,
                    const unsigned char **pk, int *ppklen,
                    const YX509_ALGOR **pa, const YPKCS8_PRIV_KEY_INFO *p8)
{
    if (ppkalg)
        *ppkalg = p8->pkeyalg->algorithm;
    if (pk) {
        *pk = YASN1_STRING_get0_data(p8->pkey);
        *ppklen = YASN1_STRING_length(p8->pkey);
    }
    if (pa)
        *pa = p8->pkeyalg;
    return 1;
}

const STACK_OF(YX509_ATTRIBUTE) *
YPKCS8_pkey_get0_attrs(const YPKCS8_PRIV_KEY_INFO *p8)
{
    return p8->attributes;
}

int YPKCS8_pkey_add1_attr_by_NID(YPKCS8_PRIV_KEY_INFO *p8, int nid, int type,
                                const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_NID(&p8->attributes, nid, type, bytes, len) != NULL)
        return 1;
    return 0;
}
