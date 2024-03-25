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
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include "crypto/asn1.h"

YASN1_OBJECT *OBJ_dup(const YASN1_OBJECT *o)
{
    YASN1_OBJECT *r;

    if (o == NULL)
        return NULL;
    /* If object isn't dynamic it's an internal OID which is never freed */
    if (!(o->flags & YASN1_OBJECT_FLAG_DYNAMIC))
        return (YASN1_OBJECT *)o;

    r = YASN1_OBJECT_new();
    if (r == NULL) {
        OBJerr(OBJ_F_OBJ_DUP, ERR_R_YASN1_LIB);
        return NULL;
    }

    /* Set dynamic flags so everything gets freed up on error */

    r->flags = o->flags | (YASN1_OBJECT_FLAG_DYNAMIC |
                           YASN1_OBJECT_FLAG_DYNAMIC_STRINGS |
                           YASN1_OBJECT_FLAG_DYNAMIC_DATA);

    if (o->length > 0 && (r->data = OPENSSL_memdup(o->data, o->length)) == NULL)
        goto err;

    r->length = o->length;
    r->nid = o->nid;

    if (o->ln != NULL && (r->ln = OPENSSL_strdup(o->ln)) == NULL)
        goto err;

    if (o->sn != NULL && (r->sn = OPENSSL_strdup(o->sn)) == NULL)
        goto err;

    return r;
 err:
    YASN1_OBJECT_free(r);
    OBJerr(OBJ_F_OBJ_DUP, ERR_R_MALLOC_FAILURE);
    return NULL;
}

int OBJ_cmp(const YASN1_OBJECT *a, const YASN1_OBJECT *b)
{
    int ret;

    ret = (a->length - b->length);
    if (ret)
        return ret;
    return memcmp(a->data, b->data, a->length);
}
