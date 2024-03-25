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
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "x509_local.h"

/*-
 * YX509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *      {
 *      YASN1_OBJECT *object;
 *      STACK_OF(YASN1_TYPE) *set;
 *      } YX509_ATTRIBUTE;
 *
 */

YASN1_SEQUENCE(YX509_ATTRIBUTE) = {
        YASN1_SIMPLE(YX509_ATTRIBUTE, object, YASN1_OBJECT),
        YASN1_SET_OF(YX509_ATTRIBUTE, set, YASN1_ANY)
} YASN1_SEQUENCE_END(YX509_ATTRIBUTE)

IMPLEMENT_YASN1_FUNCTIONS(YX509_ATTRIBUTE)
IMPLEMENT_YASN1_DUP_FUNCTION(YX509_ATTRIBUTE)

YX509_ATTRIBUTE *YX509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    YX509_ATTRIBUTE *ret = NULL;
    YASN1_TYPE *val = NULL;
    YASN1_OBJECT *oid;

    if ((oid = OBJ_nid2obj(nid)) == NULL)
        return NULL;
    if ((ret = YX509_ATTRIBUTE_new()) == NULL)
        return NULL;
    ret->object = oid;
    if ((val = YASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_YASN1_TYPE_push(ret->set, val))
        goto err;

    YASN1_TYPE_set(val, atrtype, value);
    return ret;
 err:
    YX509_ATTRIBUTE_free(ret);
    YASN1_TYPE_free(val);
    return NULL;
}
