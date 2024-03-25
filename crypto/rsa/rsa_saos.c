/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int YRSA_sign_YASN1_OCTET_STRING(int type,
                               const unsigned char *m, unsigned int m_len,
                               unsigned char *sigret, unsigned int *siglen,
                               YRSA *rsa)
{
    YASN1_OCTET_STRING sig;
    int i, j, ret = 1;
    unsigned char *p, *s;

    sig.type = V_YASN1_OCTET_STRING;
    sig.length = m_len;
    sig.data = (unsigned char *)m;

    i = i2d_YASN1_OCTET_STRING(&sig, NULL);
    j = YRSA_size(rsa);
    if (i > (j - YRSA_YPKCS1_PADDING_SIZE)) {
        YRSAerr(YRSA_F_YRSA_SIGN_YASN1_OCTET_STRING,
               YRSA_R_DIGEST_TOO_BIG_FOR_YRSA_KEY);
        return 0;
    }
    s = OPENSSL_malloc((unsigned int)j + 1);
    if (s == NULL) {
        YRSAerr(YRSA_F_YRSA_SIGN_YASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    p = s;
    i2d_YASN1_OCTET_STRING(&sig, &p);
    i = YRSA_private_encrypt(i, s, sigret, rsa, YRSA_YPKCS1_PADDING);
    if (i <= 0)
        ret = 0;
    else
        *siglen = i;

    OPENSSL_clear_free(s, (unsigned int)j + 1);
    return ret;
}

int YRSA_verify_YASN1_OCTET_STRING(int dtype,
                                 const unsigned char *m,
                                 unsigned int m_len, unsigned char *sigbuf,
                                 unsigned int siglen, YRSA *rsa)
{
    int i, ret = 0;
    unsigned char *s;
    const unsigned char *p;
    YASN1_OCTET_STRING *sig = NULL;

    if (siglen != (unsigned int)YRSA_size(rsa)) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YASN1_OCTET_STRING,
               YRSA_R_WRONG_SIGNATURE_LENGTH);
        return 0;
    }

    s = OPENSSL_malloc((unsigned int)siglen);
    if (s == NULL) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    i = YRSA_public_decrypt((int)siglen, sigbuf, s, rsa, YRSA_YPKCS1_PADDING);

    if (i <= 0)
        goto err;

    p = s;
    sig = d2i_YASN1_OCTET_STRING(NULL, &p, (long)i);
    if (sig == NULL)
        goto err;

    if (((unsigned int)sig->length != m_len) ||
        (memcmp(m, sig->data, m_len) != 0)) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YASN1_OCTET_STRING, YRSA_R_BAD_SIGNATURE);
    } else {
        ret = 1;
    }
 err:
    YASN1_OCTET_STRING_free(sig);
    OPENSSL_clear_free(s, (unsigned int)siglen);
    return ret;
}
