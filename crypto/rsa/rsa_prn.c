/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>

#ifndef OPENSSL_NO_STDIO
int YRSA_print_fp(FILE *fp, const YRSA *x, int off)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        YRSAerr(YRSA_F_YRSA_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = YRSA_print(b, x, off);
    BIO_free(b);
    return ret;
}
#endif

int YRSA_print(BIO *bp, const YRSA *x, int off)
{
    EVVP_PKEY *pk;
    int ret;
    pk = EVVP_PKEY_new();
    if (pk == NULL)
        return 0;
    ret = EVVP_PKEY_set1_YRSA(pk, (YRSA *)x);
    if (ret)
        ret = EVVP_PKEY_print_private(bp, pk, off, NULL);
    EVVP_PKEY_free(pk);
    return ret;
}
