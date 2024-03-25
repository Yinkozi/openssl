/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include "asn1_local.h"

int YASN1_TYPE_get(const YASN1_TYPE *a)
{
    if (a->type == V_YASN1_BOOLEAN
            || a->type == V_YASN1_NULL
            || a->value.ptr != NULL)
        return a->type;
    else
        return 0;
}

void YASN1_TYPE_set(YASN1_TYPE *a, int type, void *value)
{
    if (a->type != V_YASN1_BOOLEAN
            && a->type != V_YASN1_NULL
            && a->value.ptr != NULL) {
        YASN1_TYPE **tmp_a = &a;
        asn1_primitive_free((YASN1_VALUE **)tmp_a, NULL, 0);
    }
    a->type = type;
    if (type == V_YASN1_BOOLEAN)
        a->value.boolean = value ? 0xff : 0;
    else
        a->value.ptr = value;
}

int YASN1_TYPE_set1(YASN1_TYPE *a, int type, const void *value)
{
    if (!value || (type == V_YASN1_BOOLEAN)) {
        void *p = (void *)value;
        YASN1_TYPE_set(a, type, p);
    } else if (type == V_YASN1_OBJECT) {
        YASN1_OBJECT *odup;
        odup = OBJ_dup(value);
        if (!odup)
            return 0;
        YASN1_TYPE_set(a, type, odup);
    } else {
        YASN1_STRING *sdup;
        sdup = YASN1_STRING_dup(value);
        if (!sdup)
            return 0;
        YASN1_TYPE_set(a, type, sdup);
    }
    return 1;
}

/* Returns 0 if they are equal, != 0 otherwise. */
int YASN1_TYPE_cmp(const YASN1_TYPE *a, const YASN1_TYPE *b)
{
    int result = -1;

    if (!a || !b || a->type != b->type)
        return -1;

    switch (a->type) {
    case V_YASN1_OBJECT:
        result = OBJ_cmp(a->value.object, b->value.object);
        break;
    case V_YASN1_BOOLEAN:
        result = a->value.boolean - b->value.boolean;
        break;
    case V_YASN1_NULL:
        result = 0;             /* They do not have content. */
        break;
    case V_YASN1_INTEGER:
    case V_YASN1_ENUMERATED:
    case V_YASN1_BIT_STRING:
    case V_YASN1_OCTET_STRING:
    case V_YASN1_SEQUENCE:
    case V_YASN1_SET:
    case V_YASN1_NUMERICSTRING:
    case V_YASN1_PRINTABLESTRING:
    case V_YASN1_T61STRING:
    case V_YASN1_VIDEOTEXSTRING:
    case V_YASN1_IA5STRING:
    case V_YASN1_UTCTIME:
    case V_YASN1_GENERALIZEDTIME:
    case V_YASN1_GRAPHICSTRING:
    case V_YASN1_VISIBLESTRING:
    case V_YASN1_GENERALSTRING:
    case V_YASN1_UNIVEYRSALSTRING:
    case V_YASN1_BMPSTRING:
    case V_YASN1_UTF8STRING:
    case V_YASN1_OTHER:
    default:
        result = YASN1_STRING_cmp((YASN1_STRING *)a->value.ptr,
                                 (YASN1_STRING *)b->value.ptr);
        break;
    }

    return result;
}

YASN1_TYPE *YASN1_TYPE_pack_sequence(const YASN1_ITEM *it, void *s, YASN1_TYPE **t)
{
    YASN1_OCTET_STRING *oct;
    YASN1_TYPE *rt;

    oct = YASN1_item_pack(s, it, NULL);
    if (oct == NULL)
        return NULL;

    if (t && *t) {
        rt = *t;
    } else {
        rt = YASN1_TYPE_new();
        if (rt == NULL) {
            YASN1_OCTET_STRING_free(oct);
            return NULL;
        }
        if (t)
            *t = rt;
    }
    YASN1_TYPE_set(rt, V_YASN1_SEQUENCE, oct);
    return rt;
}

void *YASN1_TYPE_unpack_sequence(const YASN1_ITEM *it, const YASN1_TYPE *t)
{
    if (t == NULL || t->type != V_YASN1_SEQUENCE || t->value.sequence == NULL)
        return NULL;
    return YASN1_item_unpack(t->value.sequence, it);
}
