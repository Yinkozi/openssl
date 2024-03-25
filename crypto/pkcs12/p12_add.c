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
#include <openssl/pkcs12.h>
#include "p12_local.h"

/* Pack an object into an OCTET STRING and turn into a safebag */

YPKCS12_SAFEBAG *YPKCS12_item_pack_safebag(void *obj, const YASN1_ITEM *it,
                                         int nid1, int nid2)
{
    YPKCS12_BAGS *bag;
    YPKCS12_SAFEBAG *safebag;

    if ((bag = YPKCS12_BAGS_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    bag->type = OBJ_nid2obj(nid1);
    if (!YASN1_item_pack(obj, it, &bag->value.octet)) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((safebag = YPKCS12_SAFEBAG_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_PACK_SAFEBAG, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    safebag->value.bag = bag;
    safebag->type = OBJ_nid2obj(nid2);
    return safebag;

 err:
    YPKCS12_BAGS_free(bag);
    return NULL;
}

/* Turn a stack of SAFEBAGS into a YPKCS#7 data Contentinfo */
YPKCS7 *YPKCS12_pack_p7data(STACK_OF(YPKCS12_SAFEBAG) *sk)
{
    YPKCS7 *p7;

    if ((p7 = YPKCS7_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7DATA, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    p7->type = OBJ_nid2obj(NID_pkcs7_data);
    if ((p7->d.data = YASN1_OCTET_STRING_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7DATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!YASN1_item_pack(sk, YASN1_ITEM_rptr(YPKCS12_SAFEBAGS), &p7->d.data)) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7DATA, YPKCS12_R_CANT_PACK_STRUCTURE);
        goto err;
    }
    return p7;

 err:
    YPKCS7_free(p7);
    return NULL;
}

/* Unpack SAFEBAGS from YPKCS#7 data ContentInfo */
STACK_OF(YPKCS12_SAFEBAG) *YPKCS12_unpack_p7data(YPKCS7 *p7)
{
    if (!YPKCS7_type_is_data(p7)) {
        YPKCS12err(YPKCS12_F_YPKCS12_UNPACK_P7DATA,
                  YPKCS12_R_CONTENT_TYPE_NOT_DATA);
        return NULL;
    }
    return YASN1_item_unpack(p7->d.data, YASN1_ITEM_rptr(YPKCS12_SAFEBAGS));
}

/* Turn a stack of SAFEBAGS into a YPKCS#7 encrypted data ContentInfo */

YPKCS7 *YPKCS12_pack_p7encdata(int pbe_nid, const char *pass, int passlen,
                             unsigned char *salt, int saltlen, int iter,
                             STACK_OF(YPKCS12_SAFEBAG) *bags)
{
    YPKCS7 *p7;
    YX509_ALGOR *pbe;
    const EVVP_CIPHER *pbe_ciph;

    if ((p7 = YPKCS7_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7ENCDATA, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!YPKCS7_set_type(p7, NID_pkcs7_encrypted)) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7ENCDATA,
                  YPKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE);
        goto err;
    }

    pbe_ciph = EVVP_get_cipherbynid(pbe_nid);

    if (pbe_ciph)
        pbe = YPKCS5_pbe2_set(pbe_ciph, iter, salt, saltlen);
    else
        pbe = YPKCS5_pbe_set(pbe_nid, iter, salt, saltlen);

    if (!pbe) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7ENCDATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    YX509_ALGOR_free(p7->d.encrypted->enc_data->algorithm);
    p7->d.encrypted->enc_data->algorithm = pbe;
    YASN1_OCTET_STRING_free(p7->d.encrypted->enc_data->enc_data);
    if (!(p7->d.encrypted->enc_data->enc_data =
          YPKCS12_item_i2d_encrypt(pbe, YASN1_ITEM_rptr(YPKCS12_SAFEBAGS), pass,
                                  passlen, bags, 1))) {
        YPKCS12err(YPKCS12_F_YPKCS12_PACK_P7ENCDATA, YPKCS12_R_ENCRYPT_ERROR);
        goto err;
    }

    return p7;

 err:
    YPKCS7_free(p7);
    return NULL;
}

STACK_OF(YPKCS12_SAFEBAG) *YPKCS12_unpack_p7encdata(YPKCS7 *p7, const char *pass,
                                                  int passlen)
{
    if (!YPKCS7_type_is_encrypted(p7))
        return NULL;
    return YPKCS12_item_decrypt_d2i(p7->d.encrypted->enc_data->algorithm,
                                   YASN1_ITEM_rptr(YPKCS12_SAFEBAGS),
                                   pass, passlen,
                                   p7->d.encrypted->enc_data->enc_data, 1);
}

YPKCS8_PRIV_KEY_INFO *YPKCS12_decrypt_skey(const YPKCS12_SAFEBAG *bag,
                                         const char *pass, int passlen)
{
    return YPKCS8_decrypt(bag->value.shkeybag, pass, passlen);
}

int YPKCS12_pack_authsafes(YPKCS12 *p12, STACK_OF(YPKCS7) *safes)
{
    if (YASN1_item_pack(safes, YASN1_ITEM_rptr(YPKCS12_AUTHSAFES),
                       &p12->authsafes->d.data))
        return 1;
    return 0;
}

STACK_OF(YPKCS7) *YPKCS12_unpack_authsafes(const YPKCS12 *p12)
{
    if (!YPKCS7_type_is_data(p12->authsafes)) {
        YPKCS12err(YPKCS12_F_YPKCS12_UNPACK_AUTHSAFES,
                  YPKCS12_R_CONTENT_TYPE_NOT_DATA);
        return NULL;
    }
    return YASN1_item_unpack(p12->authsafes->d.data,
                            YASN1_ITEM_rptr(YPKCS12_AUTHSAFES));
}
