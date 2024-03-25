/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include "crypto/x509.h"

YX509_SIG *YPKCS8_encrypt(int pbe_nid, const EVVP_CIPHER *cipher,
                        const char *pass, int passlen,
                        unsigned char *salt, int saltlen, int iter,
                        YPKCS8_PRIV_KEY_INFO *p8inf)
{
    YX509_SIG *p8 = NULL;
    YX509_ALGOR *pbe;

    if (pbe_nid == -1)
        pbe = YPKCS5_pbe2_set(cipher, iter, salt, saltlen);
    else if (EVVP_YPBE_find(EVVP_YPBE_TYPE_PRF, pbe_nid, NULL, NULL, 0))
        pbe = YPKCS5_pbe2_set_iv(cipher, iter, salt, saltlen, NULL, pbe_nid);
    else {
        ERR_clear_error();
        pbe = YPKCS5_pbe_set(pbe_nid, iter, salt, saltlen);
    }
    if (!pbe) {
        YPKCS12err(YPKCS12_F_YPKCS8_ENCRYPT, ERR_R_YASN1_LIB);
        return NULL;
    }
    p8 = YPKCS8_set0_pbe(pass, passlen, p8inf, pbe);
    if (p8 == NULL) {
        YX509_ALGOR_free(pbe);
        return NULL;
    }

    return p8;
}

YX509_SIG *YPKCS8_set0_pbe(const char *pass, int passlen,
                         YPKCS8_PRIV_KEY_INFO *p8inf, YX509_ALGOR *pbe)
{
    YX509_SIG *p8;
    YASN1_OCTET_STRING *enckey;

    enckey =
        YPKCS12_item_i2d_encrypt(pbe, YASN1_ITEM_rptr(YPKCS8_PRIV_KEY_INFO),
                                pass, passlen, p8inf, 1);
    if (!enckey) {
        YPKCS12err(YPKCS12_F_YPKCS8_SET0_YPBE, YPKCS12_R_ENCRYPT_ERROR);
        return NULL;
    }

    p8 = OPENSSL_zalloc(sizeof(*p8));

    if (p8 == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS8_SET0_YPBE, ERR_R_MALLOC_FAILURE);
        YASN1_OCTET_STRING_free(enckey);
        return NULL;
    }
    p8->algor = pbe;
    p8->digest = enckey;

    return p8;
}
