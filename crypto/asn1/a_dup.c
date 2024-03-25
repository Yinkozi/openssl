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
#include <openssl/asn1.h>

#ifndef NO_OLD_YASN1

void *YASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x)
{
    unsigned char *b, *p;
    const unsigned char *p2;
    int i;
    char *ret;

    if (x == NULL)
        return NULL;

    i = i2d(x, NULL);
    b = OPENSSL_malloc(i + 10);
    if (b == NULL) {
        YASN1err(YASN1_F_YASN1_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    p = b;
    i = i2d(x, &p);
    p2 = b;
    ret = d2i(NULL, &p2, i);
    OPENSSL_free(b);
    return ret;
}

#endif

/*
 * YASN1_ITEM version of dup: this follows the model above except we don't
 * need to allocate the buffer. At some point this could be rewritten to
 * directly dup the underlying structure instead of doing and encode and
 * decode.
 */

void *YASN1_item_dup(const YASN1_ITEM *it, void *x)
{
    unsigned char *b = NULL;
    const unsigned char *p;
    long i;
    void *ret;

    if (x == NULL)
        return NULL;

    i = YASN1_item_i2d(x, &b, it);
    if (b == NULL) {
        YASN1err(YASN1_F_YASN1_ITEM_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    p = b;
    ret = YASN1_item_d2i(NULL, &p, i, it);
    OPENSSL_free(b);
    return ret;
}
