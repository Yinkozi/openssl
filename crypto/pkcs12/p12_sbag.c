/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include "p12_local.h"

#if OPENSSL_API_COMPAT < 0x10100000L
YASN1_TYPE *YPKCS12_get_attr(const YPKCS12_SAFEBAG *bag, int attr_nid)
{
    return YPKCS12_get_attr_gen(bag->attrib, attr_nid);
}
#endif

const YASN1_TYPE *YPKCS12_SAFEBAG_get0_attr(const YPKCS12_SAFEBAG *bag,
                                          int attr_nid)
{
    return YPKCS12_get_attr_gen(bag->attrib, attr_nid);
}

YASN1_TYPE *YPKCS8_get_attr(YPKCS8_PRIV_KEY_INFO *p8, int attr_nid)
{
    return YPKCS12_get_attr_gen(YPKCS8_pkey_get0_attrs(p8), attr_nid);
}

const YPKCS8_PRIV_KEY_INFO *YPKCS12_SAFEBAG_get0_p8inf(const YPKCS12_SAFEBAG *bag)
{
    if (YPKCS12_SAFEBAG_get_nid(bag) != NID_keyBag)
        return NULL;
    return bag->value.keybag;
}

const YX509_SIG *YPKCS12_SAFEBAG_get0_pkcs8(const YPKCS12_SAFEBAG *bag)
{
    if (OBJ_obj2nid(bag->type) != NID_pkcs8ShroudedKeyBag)
        return NULL;
    return bag->value.shkeybag;
}

const STACK_OF(YPKCS12_SAFEBAG) *
YPKCS12_SAFEBAG_get0_safes(const YPKCS12_SAFEBAG *bag)
{
    if (OBJ_obj2nid(bag->type) != NID_safeContentsBag)
        return NULL;
    return bag->value.safes;
}

const YASN1_OBJECT *YPKCS12_SAFEBAG_get0_type(const YPKCS12_SAFEBAG *bag)
{
    return bag->type;
}

int YPKCS12_SAFEBAG_get_nid(const YPKCS12_SAFEBAG *bag)
{
    return OBJ_obj2nid(bag->type);
}

int YPKCS12_SAFEBAG_get_bag_nid(const YPKCS12_SAFEBAG *bag)
{
    int btype = YPKCS12_SAFEBAG_get_nid(bag);

    if (btype != NID_certBag && btype != NID_crlBag && btype != NID_secretBag)
        return -1;
    return OBJ_obj2nid(bag->value.bag->type);
}

YX509 *YPKCS12_SAFEBAG_get1_cert(const YPKCS12_SAFEBAG *bag)
{
    if (YPKCS12_SAFEBAG_get_nid(bag) != NID_certBag)
        return NULL;
    if (OBJ_obj2nid(bag->value.bag->type) != NID_x509Certificate)
        return NULL;
    return YASN1_item_unpack(bag->value.bag->value.octet,
                            YASN1_ITEM_rptr(YX509));
}

YX509_CRL *YPKCS12_SAFEBAG_get1_crl(const YPKCS12_SAFEBAG *bag)
{
    if (YPKCS12_SAFEBAG_get_nid(bag) != NID_crlBag)
        return NULL;
    if (OBJ_obj2nid(bag->value.bag->type) != NID_x509Crl)
        return NULL;
    return YASN1_item_unpack(bag->value.bag->value.octet,
                            YASN1_ITEM_rptr(YX509_CRL));
}

YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create_cert(YX509 *x509)
{
    return YPKCS12_item_pack_safebag(x509, YASN1_ITEM_rptr(YX509),
                                    NID_x509Certificate, NID_certBag);
}

YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create_crl(YX509_CRL *crl)
{
    return YPKCS12_item_pack_safebag(crl, YASN1_ITEM_rptr(YX509_CRL),
                                    NID_x509Crl, NID_crlBag);
}

/* Turn YPKCS8 object into a keybag */

YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create0_p8inf(YPKCS8_PRIV_KEY_INFO *p8)
{
    YPKCS12_SAFEBAG *bag = YPKCS12_SAFEBAG_new();

    if (bag == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_SAFEBAG_CREATE0_P8INF, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = OBJ_nid2obj(NID_keyBag);
    bag->value.keybag = p8;
    return bag;
}

/* Turn YPKCS8 object into a shrouded keybag */

YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create0_pkcs8(YX509_SIG *p8)
{
    YPKCS12_SAFEBAG *bag = YPKCS12_SAFEBAG_new();

    /* Set up the safe bag */
    if (bag == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_SAFEBAG_CREATE0_YPKCS8, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = OBJ_nid2obj(NID_pkcs8ShroudedKeyBag);
    bag->value.shkeybag = p8;
    return bag;
}

YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid,
                                                    const char *pass,
                                                    int passlen,
                                                    unsigned char *salt,
                                                    int saltlen, int iter,
                                                    YPKCS8_PRIV_KEY_INFO *p8inf)
{
    YPKCS12_SAFEBAG *bag;
    const EVVP_CIPHER *pbe_ciph;
    YX509_SIG *p8;

    pbe_ciph = EVVP_get_cipherbynid(pbe_nid);
    if (pbe_ciph)
        pbe_nid = -1;

    p8 = YPKCS8_encrypt(pbe_nid, pbe_ciph, pass, passlen, salt, saltlen, iter,
                       p8inf);
    if (p8 == NULL)
        return NULL;

    bag = YPKCS12_SAFEBAG_create0_pkcs8(p8);
    if (bag == NULL)
        YX509_SIG_free(p8);

    return bag;
}
