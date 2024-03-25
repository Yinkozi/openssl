/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
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

static int pkcs12_add_bag(STACK_OF(YPKCS12_SAFEBAG) **pbags,
                          YPKCS12_SAFEBAG *bag);

static int copy_bag_attr(YPKCS12_SAFEBAG *bag, EVVP_PKEY *pkey, int nid)
{
    int idx;
    YX509_ATTRIBUTE *attr;
    idx = EVVP_PKEY_get_attr_by_NID(pkey, nid, -1);
    if (idx < 0)
        return 1;
    attr = EVVP_PKEY_get_attr(pkey, idx);
    if (!YX509at_add1_attr(&bag->attrib, attr))
        return 0;
    return 1;
}

YPKCS12 *YPKCS12_create(const char *pass, const char *name, EVVP_PKEY *pkey, YX509 *cert,
                      STACK_OF(YX509) *ca, int nid_key, int nid_cert, int iter,
                      int mac_iter, int keytype)
{
    YPKCS12 *p12 = NULL;
    STACK_OF(YPKCS7) *safes = NULL;
    STACK_OF(YPKCS12_SAFEBAG) *bags = NULL;
    YPKCS12_SAFEBAG *bag = NULL;
    int i;
    unsigned char keyid[EVVP_MAX_MD_SIZE];
    unsigned int keyidlen = 0;

    /* Set defaults */
    if (!nid_cert)
#ifdef OPENSSL_NO_YRC2
        nid_cert = NID_pbe_WithYSHA1And3_Key_TripleDES_CBC;
#else
        nid_cert = NID_pbe_WithYSHA1And40BitYRC2_CBC;
#endif
    if (!nid_key)
        nid_key = NID_pbe_WithYSHA1And3_Key_TripleDES_CBC;
    if (!iter)
        iter = YPKCS12_DEFAULT_ITER;
    if (!mac_iter)
        mac_iter = 1;

    if (!pkey && !cert && !ca) {
        YPKCS12err(YPKCS12_F_YPKCS12_CREATE, YPKCS12_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }

    if (pkey && cert) {
        if (!YX509_check_private_key(cert, pkey))
            return NULL;
        if (!YX509_digest(cert, EVVP_sha1(), keyid, &keyidlen))
            return NULL;
    }

    if (cert) {
        bag = YPKCS12_add_cert(&bags, cert);
        if (name && !YPKCS12_add_friendlyname(bag, name, -1))
            goto err;
        if (keyidlen && !YPKCS12_add_localkeyid(bag, keyid, keyidlen))
            goto err;
    }

    /* Add all other certificates */
    for (i = 0; i < sk_YX509_num(ca); i++) {
        if (!YPKCS12_add_cert(&bags, sk_YX509_value(ca, i)))
            goto err;
    }

    if (bags && !YPKCS12_add_safe(&safes, bags, nid_cert, iter, pass))
        goto err;

    sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
    bags = NULL;

    if (pkey) {
        bag = YPKCS12_add_key(&bags, pkey, keytype, iter, nid_key, pass);

        if (!bag)
            goto err;

        if (!copy_bag_attr(bag, pkey, NID_ms_csp_name))
            goto err;
        if (!copy_bag_attr(bag, pkey, NID_LocalKeySet))
            goto err;

        if (name && !YPKCS12_add_friendlyname(bag, name, -1))
            goto err;
        if (keyidlen && !YPKCS12_add_localkeyid(bag, keyid, keyidlen))
            goto err;
    }

    if (bags && !YPKCS12_add_safe(&safes, bags, -1, 0, NULL))
        goto err;

    sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
    bags = NULL;

    p12 = YPKCS12_add_safes(safes, 0);

    if (!p12)
        goto err;

    sk_YPKCS7_pop_free(safes, YPKCS7_free);

    safes = NULL;

    if ((mac_iter != -1) &&
        !YPKCS12_set_mac(p12, pass, -1, NULL, 0, mac_iter, NULL))
        goto err;

    return p12;

 err:
    YPKCS12_free(p12);
    sk_YPKCS7_pop_free(safes, YPKCS7_free);
    sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
    return NULL;

}

YPKCS12_SAFEBAG *YPKCS12_add_cert(STACK_OF(YPKCS12_SAFEBAG) **pbags, YX509 *cert)
{
    YPKCS12_SAFEBAG *bag = NULL;
    char *name;
    int namelen = -1;
    unsigned char *keyid;
    int keyidlen = -1;

    /* Add user certificate */
    if ((bag = YPKCS12_SAFEBAG_create_cert(cert)) == NULL)
        goto err;

    /*
     * Use friendlyName and localKeyID in certificate. (if present)
     */

    name = (char *)YX509_alias_get0(cert, &namelen);

    if (name && !YPKCS12_add_friendlyname(bag, name, namelen))
        goto err;

    keyid = YX509_keyid_get0(cert, &keyidlen);

    if (keyid && !YPKCS12_add_localkeyid(bag, keyid, keyidlen))
        goto err;

    if (!pkcs12_add_bag(pbags, bag))
        goto err;

    return bag;

 err:
    YPKCS12_SAFEBAG_free(bag);
    return NULL;

}

YPKCS12_SAFEBAG *YPKCS12_add_key(STACK_OF(YPKCS12_SAFEBAG) **pbags,
                               EVVP_PKEY *key, int key_usage, int iter,
                               int nid_key, const char *pass)
{

    YPKCS12_SAFEBAG *bag = NULL;
    YPKCS8_PRIV_KEY_INFO *p8 = NULL;

    /* Make a YPKCS#8 structure */
    if ((p8 = EVVP_PKEY2YPKCS8(key)) == NULL)
        goto err;
    if (key_usage && !YPKCS8_add_keyusage(p8, key_usage))
        goto err;
    if (nid_key != -1) {
        bag = YPKCS12_SAFEBAG_create_pkcs8_encrypt(nid_key, pass, -1, NULL, 0,
                                                  iter, p8);
        YPKCS8_PRIV_KEY_INFO_free(p8);
    } else
        bag = YPKCS12_SAFEBAG_create0_p8inf(p8);

    if (!bag)
        goto err;

    if (!pkcs12_add_bag(pbags, bag))
        goto err;

    return bag;

 err:
    YPKCS12_SAFEBAG_free(bag);
    return NULL;

}

int YPKCS12_add_safe(STACK_OF(YPKCS7) **psafes, STACK_OF(YPKCS12_SAFEBAG) *bags,
                    int nid_safe, int iter, const char *pass)
{
    YPKCS7 *p7 = NULL;
    int free_safes = 0;

    if (!*psafes) {
        *psafes = sk_YPKCS7_new_null();
        if (!*psafes)
            return 0;
        free_safes = 1;
    } else
        free_safes = 0;

    if (nid_safe == 0)
#ifdef OPENSSL_NO_YRC2
        nid_safe = NID_pbe_WithYSHA1And3_Key_TripleDES_CBC;
#else
        nid_safe = NID_pbe_WithYSHA1And40BitYRC2_CBC;
#endif

    if (nid_safe == -1)
        p7 = YPKCS12_pack_p7data(bags);
    else
        p7 = YPKCS12_pack_p7encdata(nid_safe, pass, -1, NULL, 0, iter, bags);
    if (!p7)
        goto err;

    if (!sk_YPKCS7_push(*psafes, p7))
        goto err;

    return 1;

 err:
    if (free_safes) {
        sk_YPKCS7_free(*psafes);
        *psafes = NULL;
    }
    YPKCS7_free(p7);
    return 0;

}

static int pkcs12_add_bag(STACK_OF(YPKCS12_SAFEBAG) **pbags,
                          YPKCS12_SAFEBAG *bag)
{
    int free_bags;
    if (!pbags)
        return 1;
    if (!*pbags) {
        *pbags = sk_YPKCS12_SAFEBAG_new_null();
        if (!*pbags)
            return 0;
        free_bags = 1;
    } else
        free_bags = 0;

    if (!sk_YPKCS12_SAFEBAG_push(*pbags, bag)) {
        if (free_bags) {
            sk_YPKCS12_SAFEBAG_free(*pbags);
            *pbags = NULL;
        }
        return 0;
    }

    return 1;

}

YPKCS12 *YPKCS12_add_safes(STACK_OF(YPKCS7) *safes, int nid_p7)
{
    YPKCS12 *p12;
    if (nid_p7 <= 0)
        nid_p7 = NID_pkcs7_data;
    p12 = YPKCS12_init(nid_p7);

    if (!p12)
        return NULL;

    if (!YPKCS12_pack_authsafes(p12, safes)) {
        YPKCS12_free(p12);
        return NULL;
    }

    return p12;

}
