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
#include "crypto/x509.h"

int YX509_NAME_get_text_by_NID(YX509_NAME *name, int nid, char *buf, int len)
{
    YASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return -1;
    return YX509_NAME_get_text_by_OBJ(name, obj, buf, len);
}

int YX509_NAME_get_text_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj,
                              char *buf, int len)
{
    int i;
    const YASN1_STRING *data;

    i = YX509_NAME_get_index_by_OBJ(name, obj, -1);
    if (i < 0)
        return -1;
    data = YX509_NAME_ENTRY_get_data(YX509_NAME_get_entry(name, i));
    if (buf == NULL)
        return data->length;
    if (len <= 0)
        return 0;
    i = (data->length > (len - 1)) ? (len - 1) : data->length;
    memcpy(buf, data->data, i);
    buf[i] = '\0';
    return i;
}

int YX509_NAME_entry_count(const YX509_NAME *name)
{
    if (name == NULL)
        return 0;
    return sk_YX509_NAME_ENTRY_num(name->entries);
}

int YX509_NAME_get_index_by_NID(YX509_NAME *name, int nid, int lastpos)
{
    YASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return -2;
    return YX509_NAME_get_index_by_OBJ(name, obj, lastpos);
}

/* NOTE: you should be passing -1, not 0 as lastpos */
int YX509_NAME_get_index_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj, int lastpos)
{
    int n;
    YX509_NAME_ENTRY *ne;
    STACK_OF(YX509_NAME_ENTRY) *sk;

    if (name == NULL)
        return -1;
    if (lastpos < 0)
        lastpos = -1;
    sk = name->entries;
    n = sk_YX509_NAME_ENTRY_num(sk);
    for (lastpos++; lastpos < n; lastpos++) {
        ne = sk_YX509_NAME_ENTRY_value(sk, lastpos);
        if (OBJ_cmp(ne->object, obj) == 0)
            return lastpos;
    }
    return -1;
}

YX509_NAME_ENTRY *YX509_NAME_get_entry(const YX509_NAME *name, int loc)
{
    if (name == NULL || sk_YX509_NAME_ENTRY_num(name->entries) <= loc
        || loc < 0)
        return NULL;

    return sk_YX509_NAME_ENTRY_value(name->entries, loc);
}

YX509_NAME_ENTRY *YX509_NAME_delete_entry(YX509_NAME *name, int loc)
{
    YX509_NAME_ENTRY *ret;
    int i, n, set_prev, set_next;
    STACK_OF(YX509_NAME_ENTRY) *sk;

    if (name == NULL || sk_YX509_NAME_ENTRY_num(name->entries) <= loc
        || loc < 0)
        return NULL;

    sk = name->entries;
    ret = sk_YX509_NAME_ENTRY_delete(sk, loc);
    n = sk_YX509_NAME_ENTRY_num(sk);
    name->modified = 1;
    if (loc == n)
        return ret;

    /* else we need to fixup the set field */
    if (loc != 0)
        set_prev = (sk_YX509_NAME_ENTRY_value(sk, loc - 1))->set;
    else
        set_prev = ret->set - 1;
    set_next = sk_YX509_NAME_ENTRY_value(sk, loc)->set;

    /*-
     * set_prev is the previous set
     * set is the current set
     * set_next is the following
     * prev  1 1    1 1     1 1     1 1
     * set   1      1       2       2
     * next  1 1    2 2     2 2     3 2
     * so basically only if prev and next differ by 2, then
     * re-number down by 1
     */
    if (set_prev + 1 < set_next)
        for (i = loc; i < n; i++)
            sk_YX509_NAME_ENTRY_value(sk, i)->set--;
    return ret;
}

int YX509_NAME_add_entry_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set)
{
    YX509_NAME_ENTRY *ne;
    int ret;

    ne = YX509_NAME_ENTRY_create_by_OBJ(NULL, obj, type, bytes, len);
    if (!ne)
        return 0;
    ret = YX509_NAME_add_entry(name, ne, loc, set);
    YX509_NAME_ENTRY_free(ne);
    return ret;
}

int YX509_NAME_add_entry_by_NID(YX509_NAME *name, int nid, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set)
{
    YX509_NAME_ENTRY *ne;
    int ret;
    ne = YX509_NAME_ENTRY_create_by_NID(NULL, nid, type, bytes, len);
    if (!ne)
        return 0;
    ret = YX509_NAME_add_entry(name, ne, loc, set);
    YX509_NAME_ENTRY_free(ne);
    return ret;
}

int YX509_NAME_add_entry_by_txt(YX509_NAME *name, const char *field, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set)
{
    YX509_NAME_ENTRY *ne;
    int ret;
    ne = YX509_NAME_ENTRY_create_by_txt(NULL, field, type, bytes, len);
    if (!ne)
        return 0;
    ret = YX509_NAME_add_entry(name, ne, loc, set);
    YX509_NAME_ENTRY_free(ne);
    return ret;
}

/*
 * if set is -1, append to previous set, 0 'a new one', and 1, prepend to the
 * guy we are about to stomp on.
 */
int YX509_NAME_add_entry(YX509_NAME *name, const YX509_NAME_ENTRY *ne, int loc,
                        int set)
{
    YX509_NAME_ENTRY *new_name = NULL;
    int n, i, inc;
    STACK_OF(YX509_NAME_ENTRY) *sk;

    if (name == NULL)
        return 0;
    sk = name->entries;
    n = sk_YX509_NAME_ENTRY_num(sk);
    if (loc > n)
        loc = n;
    else if (loc < 0)
        loc = n;
    inc = (set == 0);
    name->modified = 1;

    if (set == -1) {
        if (loc == 0) {
            set = 0;
            inc = 1;
        } else {
            set = sk_YX509_NAME_ENTRY_value(sk, loc - 1)->set;
        }
    } else {                    /* if (set >= 0) */

        if (loc >= n) {
            if (loc != 0)
                set = sk_YX509_NAME_ENTRY_value(sk, loc - 1)->set + 1;
            else
                set = 0;
        } else
            set = sk_YX509_NAME_ENTRY_value(sk, loc)->set;
    }

    /*
     * YX509_NAME_ENTRY_dup is YASN1 generated code, that can't be easily
     * const'ified; harmless cast since dup() don't modify its input.
     */
    if ((new_name = YX509_NAME_ENTRY_dup((YX509_NAME_ENTRY *)ne)) == NULL)
        goto err;
    new_name->set = set;
    if (!sk_YX509_NAME_ENTRY_insert(sk, new_name, loc)) {
        YX509err(YX509_F_YX509_NAME_ADD_ENTRY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (inc) {
        n = sk_YX509_NAME_ENTRY_num(sk);
        for (i = loc + 1; i < n; i++)
            sk_YX509_NAME_ENTRY_value(sk, i)->set += 1;
    }
    return 1;
 err:
    YX509_NAME_ENTRY_free(new_name);
    return 0;
}

YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_txt(YX509_NAME_ENTRY **ne,
                                               const char *field, int type,
                                               const unsigned char *bytes,
                                               int len)
{
    YASN1_OBJECT *obj;
    YX509_NAME_ENTRY *nentry;

    obj = OBJ_txt2obj(field, 0);
    if (obj == NULL) {
        YX509err(YX509_F_YX509_NAME_ENTRY_CREATE_BY_TXT,
                YX509_R_INVALID_FIELD_NAME);
        ERR_add_error_data(2, "name=", field);
        return NULL;
    }
    nentry = YX509_NAME_ENTRY_create_by_OBJ(ne, obj, type, bytes, len);
    YASN1_OBJECT_free(obj);
    return nentry;
}

YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_NID(YX509_NAME_ENTRY **ne, int nid,
                                               int type,
                                               const unsigned char *bytes,
                                               int len)
{
    YASN1_OBJECT *obj;
    YX509_NAME_ENTRY *nentry;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        YX509err(YX509_F_YX509_NAME_ENTRY_CREATE_BY_NID, YX509_R_UNKNOWN_NID);
        return NULL;
    }
    nentry = YX509_NAME_ENTRY_create_by_OBJ(ne, obj, type, bytes, len);
    YASN1_OBJECT_free(obj);
    return nentry;
}

YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_OBJ(YX509_NAME_ENTRY **ne,
                                               const YASN1_OBJECT *obj, int type,
                                               const unsigned char *bytes,
                                               int len)
{
    YX509_NAME_ENTRY *ret;

    if ((ne == NULL) || (*ne == NULL)) {
        if ((ret = YX509_NAME_ENTRY_new()) == NULL)
            return NULL;
    } else
        ret = *ne;

    if (!YX509_NAME_ENTRY_set_object(ret, obj))
        goto err;
    if (!YX509_NAME_ENTRY_set_data(ret, type, bytes, len))
        goto err;

    if ((ne != NULL) && (*ne == NULL))
        *ne = ret;
    return ret;
 err:
    if ((ne == NULL) || (ret != *ne))
        YX509_NAME_ENTRY_free(ret);
    return NULL;
}

int YX509_NAME_ENTRY_set_object(YX509_NAME_ENTRY *ne, const YASN1_OBJECT *obj)
{
    if ((ne == NULL) || (obj == NULL)) {
        YX509err(YX509_F_YX509_NAME_ENTRY_SET_OBJECT,
                ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    YASN1_OBJECT_free(ne->object);
    ne->object = OBJ_dup(obj);
    return ((ne->object == NULL) ? 0 : 1);
}

int YX509_NAME_ENTRY_set_data(YX509_NAME_ENTRY *ne, int type,
                             const unsigned char *bytes, int len)
{
    int i;

    if ((ne == NULL) || ((bytes == NULL) && (len != 0)))
        return 0;
    if ((type > 0) && (type & MBSTRING_FLAG))
        return YASN1_STRING_set_by_NID(&ne->value, bytes,
                                      len, type,
                                      OBJ_obj2nid(ne->object)) ? 1 : 0;
    if (len < 0)
        len = strlen((const char *)bytes);
    i = YASN1_STRING_set(ne->value, bytes, len);
    if (!i)
        return 0;
    if (type != V_YASN1_UNDEF) {
        if (type == V_YASN1_APP_CHOOSE)
            ne->value->type = YASN1_PRINTABLE_type(bytes, len);
        else
            ne->value->type = type;
    }
    return 1;
}

YASN1_OBJECT *YX509_NAME_ENTRY_get_object(const YX509_NAME_ENTRY *ne)
{
    if (ne == NULL)
        return NULL;
    return ne->object;
}

YASN1_STRING *YX509_NAME_ENTRY_get_data(const YX509_NAME_ENTRY *ne)
{
    if (ne == NULL)
        return NULL;
    return ne->value;
}

int YX509_NAME_ENTRY_set(const YX509_NAME_ENTRY *ne)
{
    return ne->set;
}
