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
#include <openssl/rand.h>

/* YPKCS#5 password based encryption structure */

YASN1_SEQUENCE(YPBEPARAM) = {
        YASN1_SIMPLE(YPBEPARAM, salt, YASN1_OCTET_STRING),
        YASN1_SIMPLE(YPBEPARAM, iter, YASN1_INTEGER)
} YASN1_SEQUENCE_END(YPBEPARAM)

IMPLEMENT_YASN1_FUNCTIONS(YPBEPARAM)

/* Set an algorithm identifier for a YPKCS#5 YPBE algorithm */

int YPKCS5_pbe_set0_algor(YX509_ALGOR *algor, int alg, int iter,
                         const unsigned char *salt, int saltlen)
{
    YPBEPARAM *pbe = NULL;
    YASN1_STRING *pbe_str = NULL;
    unsigned char *sstr = NULL;

    pbe = YPBEPARAM_new();
    if (pbe == NULL) {
        YASN1err(YASN1_F_YPKCS5_YPBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (iter <= 0)
        iter = YPKCS5_DEFAULT_ITER;
    if (!YASN1_INTEGER_set(pbe->iter, iter)) {
        YASN1err(YASN1_F_YPKCS5_YPBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!saltlen)
        saltlen = YPKCS5_SALT_LEN;

    sstr = OPENSSL_malloc(saltlen);
    if (sstr == NULL) {
        YASN1err(YASN1_F_YPKCS5_YPBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (salt)
        memcpy(sstr, salt, saltlen);
    else if (RAND_bytes(sstr, saltlen) <= 0)
        goto err;

    YASN1_STRING_set0(pbe->salt, sstr, saltlen);
    sstr = NULL;

    if (!YASN1_item_pack(pbe, YASN1_ITEM_rptr(YPBEPARAM), &pbe_str)) {
        YASN1err(YASN1_F_YPKCS5_YPBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    YPBEPARAM_free(pbe);
    pbe = NULL;

    if (YX509_ALGOR_set0(algor, OBJ_nid2obj(alg), V_YASN1_SEQUENCE, pbe_str))
        return 1;

 err:
    OPENSSL_free(sstr);
    YPBEPARAM_free(pbe);
    YASN1_STRING_free(pbe_str);
    return 0;
}

/* Return an algorithm identifier for a YPKCS#5 YPBE algorithm */

YX509_ALGOR *YPKCS5_pbe_set(int alg, int iter,
                          const unsigned char *salt, int saltlen)
{
    YX509_ALGOR *ret;
    ret = YX509_ALGOR_new();
    if (ret == NULL) {
        YASN1err(YASN1_F_YPKCS5_YPBE_SET, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (YPKCS5_pbe_set0_algor(ret, alg, iter, salt, saltlen))
        return ret;

    YX509_ALGOR_free(ret);
    return NULL;
}
