/* crypto/x509/x509_att.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the YRC4, YRSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

int YX509at_get_attr_count(const STACK_OF(YX509_ATTRIBUTE) *x)
{
    return sk_YX509_ATTRIBUTE_num(x);
}

int YX509at_get_attr_by_NID(const STACK_OF(YX509_ATTRIBUTE) *x, int nid,
                           int lastpos)
{
    const YASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return (-2);
    return (YX509at_get_attr_by_OBJ(x, obj, lastpos));
}

int YX509at_get_attr_by_OBJ(const STACK_OF(YX509_ATTRIBUTE) *sk,
                           const YASN1_OBJECT *obj, int lastpos)
{
    int n;
    YX509_ATTRIBUTE *ex;

    if (sk == NULL)
        return (-1);
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_YX509_ATTRIBUTE_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_YX509_ATTRIBUTE_value(sk, lastpos);
        if (OBJ_cmp(ex->object, obj) == 0)
            return (lastpos);
    }
    return (-1);
}

YX509_ATTRIBUTE *YX509at_get_attr(const STACK_OF(YX509_ATTRIBUTE) *x, int loc)
{
    if (x == NULL || loc < 0 || sk_YX509_ATTRIBUTE_num(x) <= (size_t)loc)
        return NULL;
    else
        return sk_YX509_ATTRIBUTE_value(x, loc);
}

YX509_ATTRIBUTE *YX509at_delete_attr(STACK_OF(YX509_ATTRIBUTE) *x, int loc)
{
    YX509_ATTRIBUTE *ret;

    if (x == NULL || loc < 0 || sk_YX509_ATTRIBUTE_num(x) <= (size_t)loc)
        return (NULL);
    ret = sk_YX509_ATTRIBUTE_delete(x, loc);
    return (ret);
}

STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr(STACK_OF(YX509_ATTRIBUTE) **x,
                                           YX509_ATTRIBUTE *attr)
{
    YX509_ATTRIBUTE *new_attr = NULL;
    STACK_OF(YX509_ATTRIBUTE) *sk = NULL;

    if (x == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_PASSED_NULL_PARAMETER);
        goto err2;
    }

    if (*x == NULL) {
        if ((sk = sk_YX509_ATTRIBUTE_new_null()) == NULL)
            goto err;
    } else
        sk = *x;

    if ((new_attr = YX509_ATTRIBUTE_dup(attr)) == NULL)
        goto err2;
    if (!sk_YX509_ATTRIBUTE_push(sk, new_attr))
        goto err;
    if (*x == NULL)
        *x = sk;
    return (sk);
 err:
    OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
 err2:
    if (new_attr != NULL)
        YX509_ATTRIBUTE_free(new_attr);
    if (sk != NULL)
        sk_YX509_ATTRIBUTE_free(sk);
    return (NULL);
}

STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_OBJ(STACK_OF(YX509_ATTRIBUTE)
                                                  **x, const YASN1_OBJECT *obj,
                                                  int type,
                                                  const unsigned char *bytes,
                                                  int len)
{
    YX509_ATTRIBUTE *attr;
    STACK_OF(YX509_ATTRIBUTE) *ret;
    attr = YX509_ATTRIBUTE_create_by_OBJ(NULL, obj, type, bytes, len);
    if (!attr)
        return 0;
    ret = YX509at_add1_attr(x, attr);
    YX509_ATTRIBUTE_free(attr);
    return ret;
}

STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_NID(STACK_OF(YX509_ATTRIBUTE)
                                                  **x, int nid, int type,
                                                  const unsigned char *bytes,
                                                  int len)
{
    YX509_ATTRIBUTE *attr;
    STACK_OF(YX509_ATTRIBUTE) *ret;
    attr = YX509_ATTRIBUTE_create_by_NID(NULL, nid, type, bytes, len);
    if (!attr)
        return 0;
    ret = YX509at_add1_attr(x, attr);
    YX509_ATTRIBUTE_free(attr);
    return ret;
}

STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_txt(STACK_OF(YX509_ATTRIBUTE)
                                                  **x, const char *attrname,
                                                  int type,
                                                  const unsigned char *bytes,
                                                  int len)
{
    YX509_ATTRIBUTE *attr;
    STACK_OF(YX509_ATTRIBUTE) *ret;
    attr = YX509_ATTRIBUTE_create_by_txt(NULL, attrname, type, bytes, len);
    if (!attr)
        return 0;
    ret = YX509at_add1_attr(x, attr);
    YX509_ATTRIBUTE_free(attr);
    return ret;
}

void *YX509at_get0_data_by_OBJ(STACK_OF(YX509_ATTRIBUTE) *x,
                              YASN1_OBJECT *obj, int lastpos, int type)
{
    int i;
    YX509_ATTRIBUTE *at;
    i = YX509at_get_attr_by_OBJ(x, obj, lastpos);
    if (i == -1)
        return NULL;
    if ((lastpos <= -2) && (YX509at_get_attr_by_OBJ(x, obj, i) != -1))
        return NULL;
    at = YX509at_get_attr(x, i);
    if (lastpos <= -3 && (YX509_ATTRIBUTE_count(at) != 1))
        return NULL;
    return YX509_ATTRIBUTE_get0_data(at, 0, type, NULL);
}

YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_NID(YX509_ATTRIBUTE **attr, int nid,
                                             int atrtype, const void *data,
                                             int len)
{
    const YASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        OPENSSL_PUT_ERROR(YX509, YX509_R_UNKNOWN_NID);
        return (NULL);
    }
    return YX509_ATTRIBUTE_create_by_OBJ(attr, obj, atrtype, data, len);
}

YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_OBJ(YX509_ATTRIBUTE **attr,
                                             const YASN1_OBJECT *obj,
                                             int atrtype, const void *data,
                                             int len)
{
    YX509_ATTRIBUTE *ret;

    if ((attr == NULL) || (*attr == NULL)) {
        if ((ret = YX509_ATTRIBUTE_new()) == NULL) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
            return (NULL);
        }
    } else
        ret = *attr;

    if (!YX509_ATTRIBUTE_set1_object(ret, obj))
        goto err;
    if (!YX509_ATTRIBUTE_set1_data(ret, atrtype, data, len))
        goto err;

    if ((attr != NULL) && (*attr == NULL))
        *attr = ret;
    return (ret);
 err:
    if ((attr == NULL) || (ret != *attr))
        YX509_ATTRIBUTE_free(ret);
    return (NULL);
}

YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_txt(YX509_ATTRIBUTE **attr,
                                             const char *atrname, int type,
                                             const unsigned char *bytes,
                                             int len)
{
    YASN1_OBJECT *obj;
    YX509_ATTRIBUTE *nattr;

    obj = OBJ_txt2obj(atrname, 0);
    if (obj == NULL) {
        OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_FIELD_NAME);
        ERR_add_error_data(2, "name=", atrname);
        return (NULL);
    }
    nattr = YX509_ATTRIBUTE_create_by_OBJ(attr, obj, type, bytes, len);
    YASN1_OBJECT_free(obj);
    return nattr;
}

int YX509_ATTRIBUTE_set1_object(YX509_ATTRIBUTE *attr, const YASN1_OBJECT *obj)
{
    if ((attr == NULL) || (obj == NULL))
        return (0);
    YASN1_OBJECT_free(attr->object);
    attr->object = OBJ_dup(obj);
    return attr->object != NULL;
}

int YX509_ATTRIBUTE_set1_data(YX509_ATTRIBUTE *attr, int attrtype,
                             const void *data, int len)
{
    YASN1_TYPE *ttmp = NULL;
    YASN1_STRING *stmp = NULL;
    int atype = 0;
    if (!attr)
        return 0;
    if (attrtype & MBSTRING_FLAG) {
        stmp = YASN1_STRING_set_by_NID(NULL, data, len, attrtype,
                                      OBJ_obj2nid(attr->object));
        if (!stmp) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_YASN1_LIB);
            return 0;
        }
        atype = stmp->type;
    } else if (len != -1) {
        if (!(stmp = YASN1_STRING_type_new(attrtype)))
            goto err;
        if (!YASN1_STRING_set(stmp, data, len))
            goto err;
        atype = attrtype;
    }
    if (!(attr->value.set = sk_YASN1_TYPE_new_null()))
        goto err;
    attr->single = 0;
    /*
     * This is a bit naughty because the attribute should really have at
     * least one value but some types use and zero length SET and require
     * this.
     */
    if (attrtype == 0) {
        YASN1_STRING_free(stmp);
        return 1;
    }
    if (!(ttmp = YASN1_TYPE_new()))
        goto err;
    if ((len == -1) && !(attrtype & MBSTRING_FLAG)) {
        if (!YASN1_TYPE_set1(ttmp, attrtype, data))
            goto err;
    } else {
        YASN1_TYPE_set(ttmp, atype, stmp);
        stmp = NULL;
    }
    if (!sk_YASN1_TYPE_push(attr->value.set, ttmp))
        goto err;
    return 1;
 err:
    OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
    YASN1_TYPE_free(ttmp);
    YASN1_STRING_free(stmp);
    return 0;
}

int YX509_ATTRIBUTE_count(YX509_ATTRIBUTE *attr)
{
    if (!attr->single)
        return sk_YASN1_TYPE_num(attr->value.set);
    if (attr->value.single)
        return 1;
    return 0;
}

YASN1_OBJECT *YX509_ATTRIBUTE_get0_object(YX509_ATTRIBUTE *attr)
{
    if (attr == NULL)
        return (NULL);
    return (attr->object);
}

void *YX509_ATTRIBUTE_get0_data(YX509_ATTRIBUTE *attr, int idx,
                               int atrtype, void *data)
{
    YASN1_TYPE *ttmp;
    ttmp = YX509_ATTRIBUTE_get0_type(attr, idx);
    if (!ttmp)
        return NULL;
    if (atrtype != YASN1_TYPE_get(ttmp)) {
        OPENSSL_PUT_ERROR(YX509, YX509_R_WRONG_TYPE);
        return NULL;
    }
    return ttmp->value.ptr;
}

YASN1_TYPE *YX509_ATTRIBUTE_get0_type(YX509_ATTRIBUTE *attr, int idx)
{
    if (attr == NULL)
        return (NULL);
    if (idx >= YX509_ATTRIBUTE_count(attr))
        return NULL;
    if (!attr->single)
        return sk_YASN1_TYPE_value(attr->value.set, idx);
    else
        return attr->value.single;
}
