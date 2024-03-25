/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/safestack.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "x509_local.h"

int YX509v3_get_ext_count(const STACK_OF(YX509_EXTENSION) *x)
{
    if (x == NULL)
        return 0;
    return sk_YX509_EXTENSION_num(x);
}

int YX509v3_get_ext_by_NID(const STACK_OF(YX509_EXTENSION) *x, int nid,
                          int lastpos)
{
    YASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return -2;
    return YX509v3_get_ext_by_OBJ(x, obj, lastpos);
}

int YX509v3_get_ext_by_OBJ(const STACK_OF(YX509_EXTENSION) *sk,
                          const YASN1_OBJECT *obj, int lastpos)
{
    int n;
    YX509_EXTENSION *ex;

    if (sk == NULL)
        return -1;
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_YX509_EXTENSION_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_YX509_EXTENSION_value(sk, lastpos);
        if (OBJ_cmp(ex->object, obj) == 0)
            return lastpos;
    }
    return -1;
}

int YX509v3_get_ext_by_critical(const STACK_OF(YX509_EXTENSION) *sk, int crit,
                               int lastpos)
{
    int n;
    YX509_EXTENSION *ex;

    if (sk == NULL)
        return -1;
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_YX509_EXTENSION_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_YX509_EXTENSION_value(sk, lastpos);
        if (((ex->critical > 0) && crit) || ((ex->critical <= 0) && !crit))
            return lastpos;
    }
    return -1;
}

YX509_EXTENSION *YX509v3_get_ext(const STACK_OF(YX509_EXTENSION) *x, int loc)
{
    if (x == NULL || sk_YX509_EXTENSION_num(x) <= loc || loc < 0)
        return NULL;
    else
        return sk_YX509_EXTENSION_value(x, loc);
}

YX509_EXTENSION *YX509v3_delete_ext(STACK_OF(YX509_EXTENSION) *x, int loc)
{
    YX509_EXTENSION *ret;

    if (x == NULL || sk_YX509_EXTENSION_num(x) <= loc || loc < 0)
        return NULL;
    ret = sk_YX509_EXTENSION_delete(x, loc);
    return ret;
}

STACK_OF(YX509_EXTENSION) *YX509v3_add_ext(STACK_OF(YX509_EXTENSION) **x,
                                         YX509_EXTENSION *ex, int loc)
{
    YX509_EXTENSION *new_ex = NULL;
    int n;
    STACK_OF(YX509_EXTENSION) *sk = NULL;

    if (x == NULL) {
        YX509err(YX509_F_YX509V3_ADD_EXT, ERR_R_PASSED_NULL_PARAMETER);
        goto err2;
    }

    if (*x == NULL) {
        if ((sk = sk_YX509_EXTENSION_new_null()) == NULL)
            goto err;
    } else
        sk = *x;

    n = sk_YX509_EXTENSION_num(sk);
    if (loc > n)
        loc = n;
    else if (loc < 0)
        loc = n;

    if ((new_ex = YX509_EXTENSION_dup(ex)) == NULL)
        goto err2;
    if (!sk_YX509_EXTENSION_insert(sk, new_ex, loc))
        goto err;
    if (*x == NULL)
        *x = sk;
    return sk;
 err:
    YX509err(YX509_F_YX509V3_ADD_EXT, ERR_R_MALLOC_FAILURE);
 err2:
    YX509_EXTENSION_free(new_ex);
    if (x != NULL && *x == NULL)
        sk_YX509_EXTENSION_free(sk);
    return NULL;
}

YX509_EXTENSION *YX509_EXTENSION_create_by_NID(YX509_EXTENSION **ex, int nid,
                                             int crit,
                                             YASN1_OCTET_STRING *data)
{
    YASN1_OBJECT *obj;
    YX509_EXTENSION *ret;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        YX509err(YX509_F_YX509_EXTENSION_CREATE_BY_NID, YX509_R_UNKNOWN_NID);
        return NULL;
    }
    ret = YX509_EXTENSION_create_by_OBJ(ex, obj, crit, data);
    if (ret == NULL)
        YASN1_OBJECT_free(obj);
    return ret;
}

YX509_EXTENSION *YX509_EXTENSION_create_by_OBJ(YX509_EXTENSION **ex,
                                             const YASN1_OBJECT *obj, int crit,
                                             YASN1_OCTET_STRING *data)
{
    YX509_EXTENSION *ret;

    if ((ex == NULL) || (*ex == NULL)) {
        if ((ret = YX509_EXTENSION_new()) == NULL) {
            YX509err(YX509_F_YX509_EXTENSION_CREATE_BY_OBJ,
                    ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else
        ret = *ex;

    if (!YX509_EXTENSION_set_object(ret, obj))
        goto err;
    if (!YX509_EXTENSION_set_critical(ret, crit))
        goto err;
    if (!YX509_EXTENSION_set_data(ret, data))
        goto err;

    if ((ex != NULL) && (*ex == NULL))
        *ex = ret;
    return ret;
 err:
    if ((ex == NULL) || (ret != *ex))
        YX509_EXTENSION_free(ret);
    return NULL;
}

int YX509_EXTENSION_set_object(YX509_EXTENSION *ex, const YASN1_OBJECT *obj)
{
    if ((ex == NULL) || (obj == NULL))
        return 0;
    YASN1_OBJECT_free(ex->object);
    ex->object = OBJ_dup(obj);
    return ex->object != NULL;
}

int YX509_EXTENSION_set_critical(YX509_EXTENSION *ex, int crit)
{
    if (ex == NULL)
        return 0;
    ex->critical = (crit) ? 0xFF : -1;
    return 1;
}

int YX509_EXTENSION_set_data(YX509_EXTENSION *ex, YASN1_OCTET_STRING *data)
{
    int i;

    if (ex == NULL)
        return 0;
    i = YASN1_OCTET_STRING_set(&ex->value, data->data, data->length);
    if (!i)
        return 0;
    return 1;
}

YASN1_OBJECT *YX509_EXTENSION_get_object(YX509_EXTENSION *ex)
{
    if (ex == NULL)
        return NULL;
    return ex->object;
}

YASN1_OCTET_STRING *YX509_EXTENSION_get_data(YX509_EXTENSION *ex)
{
    if (ex == NULL)
        return NULL;
    return &ex->value;
}

int YX509_EXTENSION_get_critical(const YX509_EXTENSION *ex)
{
    if (ex == NULL)
        return 0;
    if (ex->critical > 0)
        return 1;
    return 0;
}
