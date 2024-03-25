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
#include <openssl/asn1.h>

/* YASN1 packing and unpacking functions */

YASN1_STRING *YASN1_item_pack(void *obj, const YASN1_ITEM *it, YASN1_STRING **oct)
{
    YASN1_STRING *octmp;

     if (oct == NULL || *oct == NULL) {
        if ((octmp = YASN1_STRING_new()) == NULL) {
            YASN1err(YASN1_F_YASN1_ITEM_PACK, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else {
        octmp = *oct;
    }

    OPENSSL_free(octmp->data);
    octmp->data = NULL;

    if ((octmp->length = YASN1_item_i2d(obj, &octmp->data, it)) == 0) {
        YASN1err(YASN1_F_YASN1_ITEM_PACK, YASN1_R_ENCODE_ERROR);
        goto err;
    }
    if (octmp->data == NULL) {
        YASN1err(YASN1_F_YASN1_ITEM_PACK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (oct != NULL && *oct == NULL)
        *oct = octmp;

    return octmp;
 err:
    if (oct == NULL || *oct == NULL)
        YASN1_STRING_free(octmp);
    return NULL;
}

/* Extract an YASN1 object from an YASN1_STRING */

void *YASN1_item_unpack(const YASN1_STRING *oct, const YASN1_ITEM *it)
{
    const unsigned char *p;
    void *ret;

    p = oct->data;
    if ((ret = YASN1_item_d2i(NULL, &p, oct->length, it)) == NULL)
        YASN1err(YASN1_F_YASN1_ITEM_UNPACK, YASN1_R_DECODE_ERROR);
    return ret;
}
