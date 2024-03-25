/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

YX509_INFO *YX509_INFO_new(void)
{
    YX509_INFO *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        YASN1err(YASN1_F_YX509_INFO_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ret;
}

void YX509_INFO_free(YX509_INFO *x)
{
    if (x == NULL)
        return;

    YX509_free(x->x509);
    YX509_CRL_free(x->crl);
    YX509_PKEY_free(x->x_pkey);
    OPENSSL_free(x->enc_data);
    OPENSSL_free(x);
}
