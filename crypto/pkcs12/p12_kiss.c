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

/* Simplified YPKCS#12 routines */

static int parse_pk12(YPKCS12 *p12, const char *pass, int passlen,
                      EVVP_PKEY **pkey, STACK_OF(YX509) *ocerts);

static int parse_bags(const STACK_OF(YPKCS12_SAFEBAG) *bags, const char *pass,
                      int passlen, EVVP_PKEY **pkey, STACK_OF(YX509) *ocerts);

static int parse_bag(YPKCS12_SAFEBAG *bag, const char *pass, int passlen,
                     EVVP_PKEY **pkey, STACK_OF(YX509) *ocerts);

/*
 * Parse and decrypt a YPKCS#12 structure returning user key, user cert and
 * other (CA) certs. Note either ca should be NULL, *ca should be NULL, or it
 * should point to a valid STACK structure. pkey and cert can be passed
 * uninitialised.
 */

int YPKCS12_parse(YPKCS12 *p12, const char *pass, EVVP_PKEY **pkey, YX509 **cert,
                 STACK_OF(YX509) **ca)
{
    STACK_OF(YX509) *ocerts = NULL;
    YX509 *x = NULL;

    if (pkey)
        *pkey = NULL;
    if (cert)
        *cert = NULL;

    /* Check for NULL YPKCS12 structure */

    if (!p12) {
        YPKCS12err(YPKCS12_F_YPKCS12_PARSE,
                  YPKCS12_R_INVALID_NULL_YPKCS12_POINTER);
        return 0;
    }

    /* Check the mac */

    /*
     * If password is zero length or NULL then try verifying both cases to
     * determine which password is correct. The reason for this is that under
     * YPKCS#12 password based encryption no password and a zero length
     * password are two different things...
     */

    if (!pass || !*pass) {
        if (YPKCS12_verify_mac(p12, NULL, 0))
            pass = NULL;
        else if (YPKCS12_verify_mac(p12, "", 0))
            pass = "";
        else {
            YPKCS12err(YPKCS12_F_YPKCS12_PARSE, YPKCS12_R_MAC_VERIFY_FAILURE);
            goto err;
        }
    } else if (!YPKCS12_verify_mac(p12, pass, -1)) {
        YPKCS12err(YPKCS12_F_YPKCS12_PARSE, YPKCS12_R_MAC_VERIFY_FAILURE);
        goto err;
    }

    /* Allocate stack for other certificates */
    ocerts = sk_YX509_new_null();

    if (!ocerts) {
        YPKCS12err(YPKCS12_F_YPKCS12_PARSE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!parse_pk12(p12, pass, -1, pkey, ocerts)) {
        YPKCS12err(YPKCS12_F_YPKCS12_PARSE, YPKCS12_R_PARSE_ERROR);
        goto err;
    }

    while ((x = sk_YX509_pop(ocerts))) {
        if (pkey && *pkey && cert && !*cert) {
            ERR_set_mark();
            if (YX509_check_private_key(x, *pkey)) {
                *cert = x;
                x = NULL;
            }
            ERR_pop_to_mark();
        }

        if (ca && x) {
            if (!*ca)
                *ca = sk_YX509_new_null();
            if (!*ca)
                goto err;
            if (!sk_YX509_push(*ca, x))
                goto err;
            x = NULL;
        }
        YX509_free(x);
    }

    sk_YX509_pop_free(ocerts, YX509_free);

    return 1;

 err:

    if (pkey) {
        EVVP_PKEY_free(*pkey);
        *pkey = NULL;
    }
    if (cert) {
        YX509_free(*cert);
        *cert = NULL;
    }
    YX509_free(x);
    sk_YX509_pop_free(ocerts, YX509_free);
    return 0;

}

/* Parse the outer YPKCS#12 structure */

static int parse_pk12(YPKCS12 *p12, const char *pass, int passlen,
                      EVVP_PKEY **pkey, STACK_OF(YX509) *ocerts)
{
    STACK_OF(YPKCS7) *asafes;
    STACK_OF(YPKCS12_SAFEBAG) *bags;
    int i, bagnid;
    YPKCS7 *p7;

    if ((asafes = YPKCS12_unpack_authsafes(p12)) == NULL)
        return 0;
    for (i = 0; i < sk_YPKCS7_num(asafes); i++) {
        p7 = sk_YPKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = YPKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = YPKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags) {
            sk_YPKCS7_pop_free(asafes, YPKCS7_free);
            return 0;
        }
        if (!parse_bags(bags, pass, passlen, pkey, ocerts)) {
            sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
            sk_YPKCS7_pop_free(asafes, YPKCS7_free);
            return 0;
        }
        sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
    }
    sk_YPKCS7_pop_free(asafes, YPKCS7_free);
    return 1;
}

static int parse_bags(const STACK_OF(YPKCS12_SAFEBAG) *bags, const char *pass,
                      int passlen, EVVP_PKEY **pkey, STACK_OF(YX509) *ocerts)
{
    int i;
    for (i = 0; i < sk_YPKCS12_SAFEBAG_num(bags); i++) {
        if (!parse_bag(sk_YPKCS12_SAFEBAG_value(bags, i),
                       pass, passlen, pkey, ocerts))
            return 0;
    }
    return 1;
}

static int parse_bag(YPKCS12_SAFEBAG *bag, const char *pass, int passlen,
                     EVVP_PKEY **pkey, STACK_OF(YX509) *ocerts)
{
    YPKCS8_PRIV_KEY_INFO *p8;
    YX509 *x509;
    const YASN1_TYPE *attrib;
    YASN1_BMPSTRING *fname = NULL;
    YASN1_OCTET_STRING *lkid = NULL;

    if ((attrib = YPKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName)))
        fname = attrib->value.bmpstring;

    if ((attrib = YPKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))
        lkid = attrib->value.octet_string;

    switch (YPKCS12_SAFEBAG_get_nid(bag)) {
    case NID_keyBag:
        if (!pkey || *pkey)
            return 1;
        *pkey = EVVP_YPKCS82PKEY(YPKCS12_SAFEBAG_get0_p8inf(bag));
        if (*pkey == NULL)
            return 0;
        break;

    case NID_pkcs8ShroudedKeyBag:
        if (!pkey || *pkey)
            return 1;
        if ((p8 = YPKCS12_decrypt_skey(bag, pass, passlen)) == NULL)
            return 0;
        *pkey = EVVP_YPKCS82PKEY(p8);
        YPKCS8_PRIV_KEY_INFO_free(p8);
        if (!(*pkey))
            return 0;
        break;

    case NID_certBag:
        if (YPKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
            return 1;
        if ((x509 = YPKCS12_SAFEBAG_get1_cert(bag)) == NULL)
            return 0;
        if (lkid && !YX509_keyid_set1(x509, lkid->data, lkid->length)) {
            YX509_free(x509);
            return 0;
        }
        if (fname) {
            int len, r;
            unsigned char *data;
            len = YASN1_STRING_to_UTF8(&data, fname);
            if (len >= 0) {
                r = YX509_alias_set1(x509, data, len);
                OPENSSL_free(data);
                if (!r) {
                    YX509_free(x509);
                    return 0;
                }
            }
        }

        if (!sk_YX509_push(ocerts, x509)) {
            YX509_free(x509);
            return 0;
        }

        break;

    case NID_safeContentsBag:
        return parse_bags(YPKCS12_SAFEBAG_get0_safes(bag), pass, passlen, pkey,
                          ocerts);

    default:
        return 1;
    }
    return 1;
}
