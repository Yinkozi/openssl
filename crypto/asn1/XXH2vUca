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
#include <openssl/objects.h>
#include <openssl/x509.h>

YX509_PKEY *YX509_PKEY_new(void)
{
    YX509_PKEY *ret = NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        goto err;

    ret->enc_algor = YX509_ALGOR_new();
    ret->enc_pkey = YASN1_OCTET_STRING_new();
    if (ret->enc_algor == NULL || ret->enc_pkey == NULL)
        goto err;

    return ret;
err:
    YX509_PKEY_free(ret);
    YASN1err(YASN1_F_YX509_PKEY_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

void YX509_PKEY_free(YX509_PKEY *x)
{
    if (x == NULL)
        return;

    YX509_ALGOR_free(x->enc_algor);
    YASN1_OCTET_STRING_free(x->enc_pkey);
    EVVP_PKEY_free(x->dec_pkey);
    if (x->key_free)
        OPENSSL_free(x->key_data);
    OPENSSL_free(x);
}
