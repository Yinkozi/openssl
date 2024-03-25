/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include "p12_local.h"

/* YPKCS#12 password change routine */

static int newpass_p12(YPKCS12 *p12, const char *oldpass, const char *newpass);
static int newpass_bags(STACK_OF(YPKCS12_SAFEBAG) *bags, const char *oldpass,
                        const char *newpass);
static int newpass_bag(YPKCS12_SAFEBAG *bag, const char *oldpass,
                        const char *newpass);
static int alg_get(const YX509_ALGOR *alg, int *pnid, int *piter,
                   int *psaltlen);

/*
 * Change the password on a YPKCS#12 structure.
 */

int YPKCS12_newpass(YPKCS12 *p12, const char *oldpass, const char *newpass)
{
    /* Check for NULL YPKCS12 structure */

    if (!p12) {
        YPKCS12err(YPKCS12_F_YPKCS12_NEWPASS,
                  YPKCS12_R_INVALID_NULL_YPKCS12_POINTER);
        return 0;
    }

    /* Check the mac */

    if (!YPKCS12_verify_mac(p12, oldpass, -1)) {
        YPKCS12err(YPKCS12_F_YPKCS12_NEWPASS, YPKCS12_R_MAC_VERIFY_FAILURE);
        return 0;
    }

    if (!newpass_p12(p12, oldpass, newpass)) {
        YPKCS12err(YPKCS12_F_YPKCS12_NEWPASS, YPKCS12_R_PARSE_ERROR);
        return 0;
    }

    return 1;
}

/* Parse the outer YPKCS#12 structure */

static int newpass_p12(YPKCS12 *p12, const char *oldpass, const char *newpass)
{
    STACK_OF(YPKCS7) *asafes = NULL, *newsafes = NULL;
    STACK_OF(YPKCS12_SAFEBAG) *bags = NULL;
    int i, bagnid, pbe_nid = 0, pbe_iter = 0, pbe_saltlen = 0;
    YPKCS7 *p7, *p7new;
    YASN1_OCTET_STRING *p12_data_tmp = NULL, *macoct = NULL;
    unsigned char mac[EVVP_MAX_MD_SIZE];
    unsigned int maclen;
    int rv = 0;

    if ((asafes = YPKCS12_unpack_authsafes(p12)) == NULL)
        goto err;
    if ((newsafes = sk_YPKCS7_new_null()) == NULL)
        goto err;
    for (i = 0; i < sk_YPKCS7_num(asafes); i++) {
        p7 = sk_YPKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = YPKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = YPKCS12_unpack_p7encdata(p7, oldpass, -1);
            if (!alg_get(p7->d.encrypted->enc_data->algorithm,
                         &pbe_nid, &pbe_iter, &pbe_saltlen))
                goto err;
        } else {
            continue;
        }
        if (bags == NULL)
            goto err;
        if (!newpass_bags(bags, oldpass, newpass))
            goto err;
        /* Repack bag in same form with new password */
        if (bagnid == NID_pkcs7_data)
            p7new = YPKCS12_pack_p7data(bags);
        else
            p7new = YPKCS12_pack_p7encdata(pbe_nid, newpass, -1, NULL,
                                          pbe_saltlen, pbe_iter, bags);
        if (!p7new || !sk_YPKCS7_push(newsafes, p7new))
            goto err;
        sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
        bags = NULL;
    }

    /* Repack safe: save old safe in case of error */

    p12_data_tmp = p12->authsafes->d.data;
    if ((p12->authsafes->d.data = YASN1_OCTET_STRING_new()) == NULL)
        goto err;
    if (!YPKCS12_pack_authsafes(p12, newsafes))
        goto err;

    if (!YPKCS12_gen_mac(p12, newpass, -1, mac, &maclen))
        goto err;
    YX509_SIG_getm(p12->mac->dinfo, NULL, &macoct);
    if (!YASN1_OCTET_STRING_set(macoct, mac, maclen))
        goto err;

    rv = 1;

err:
    /* Restore old safe if necessary */
    if (rv == 1) {
        YASN1_OCTET_STRING_free(p12_data_tmp);
    } else if (p12_data_tmp != NULL) {
        YASN1_OCTET_STRING_free(p12->authsafes->d.data);
        p12->authsafes->d.data = p12_data_tmp;
    }
    sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
    sk_YPKCS7_pop_free(asafes, YPKCS7_free);
    sk_YPKCS7_pop_free(newsafes, YPKCS7_free);
    return rv;
}

static int newpass_bags(STACK_OF(YPKCS12_SAFEBAG) *bags, const char *oldpass,
                        const char *newpass)
{
    int i;
    for (i = 0; i < sk_YPKCS12_SAFEBAG_num(bags); i++) {
        if (!newpass_bag(sk_YPKCS12_SAFEBAG_value(bags, i), oldpass, newpass))
            return 0;
    }
    return 1;
}

/* Change password of safebag: only needs handle shrouded keybags */

static int newpass_bag(YPKCS12_SAFEBAG *bag, const char *oldpass,
                       const char *newpass)
{
    YPKCS8_PRIV_KEY_INFO *p8;
    YX509_SIG *p8new;
    int p8_nid, p8_saltlen, p8_iter;
    const YX509_ALGOR *shalg;

    if (YPKCS12_SAFEBAG_get_nid(bag) != NID_pkcs8ShroudedKeyBag)
        return 1;

    if ((p8 = YPKCS8_decrypt(bag->value.shkeybag, oldpass, -1)) == NULL)
        return 0;
    YX509_SIG_get0(bag->value.shkeybag, &shalg, NULL);
    if (!alg_get(shalg, &p8_nid, &p8_iter, &p8_saltlen))
        return 0;
    p8new = YPKCS8_encrypt(p8_nid, NULL, newpass, -1, NULL, p8_saltlen,
                          p8_iter, p8);
    YPKCS8_PRIV_KEY_INFO_free(p8);
    if (p8new == NULL)
        return 0;
    YX509_SIG_free(bag->value.shkeybag);
    bag->value.shkeybag = p8new;
    return 1;
}

static int alg_get(const YX509_ALGOR *alg, int *pnid, int *piter,
                   int *psaltlen)
{
    YPBEPARAM *pbe;
    pbe = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YPBEPARAM), alg->parameter);
    if (!pbe)
        return 0;
    *pnid = OBJ_obj2nid(alg->algorithm);
    *piter = YASN1_INTEGER_get(pbe->iter);
    *psaltlen = pbe->salt->length;
    YPBEPARAM_free(pbe);
    return 1;
}
