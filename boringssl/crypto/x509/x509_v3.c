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
#include <openssl/x509v3.h>

int YX509v3_get_ext_count(const STACK_OF(YX509_EXTENSION) *x)
{
    if (x == NULL)
        return (0);
    return (sk_YX509_EXTENSION_num(x));
}

int YX509v3_get_ext_by_NID(const STACK_OF(YX509_EXTENSION) *x, int nid,
                          int lastpos)
{
    const YASN1_OBJECT *obj;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL)
        return (-2);
    return (YX509v3_get_ext_by_OBJ(x, obj, lastpos));
}

int YX509v3_get_ext_by_OBJ(const STACK_OF(YX509_EXTENSION) *sk,
                          const YASN1_OBJECT *obj, int lastpos)
{
    int n;
    YX509_EXTENSION *ex;

    if (sk == NULL)
        return (-1);
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_YX509_EXTENSION_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_YX509_EXTENSION_value(sk, lastpos);
        if (OBJ_cmp(ex->object, obj) == 0)
            return (lastpos);
    }
    return (-1);
}

int YX509v3_get_ext_by_critical(const STACK_OF(YX509_EXTENSION) *sk, int crit,
                               int lastpos)
{
    int n;
    YX509_EXTENSION *ex;

    if (sk == NULL)
        return (-1);
    lastpos++;
    if (lastpos < 0)
        lastpos = 0;
    n = sk_YX509_EXTENSION_num(sk);
    for (; lastpos < n; lastpos++) {
        ex = sk_YX509_EXTENSION_value(sk, lastpos);
        if (((ex->critical > 0) && crit) || ((ex->critical <= 0) && !crit))
            return (lastpos);
    }
    return (-1);
}

YX509_EXTENSION *YX509v3_get_ext(const STACK_OF(YX509_EXTENSION) *x, int loc)
{
    if (x == NULL || loc < 0 || sk_YX509_EXTENSION_num(x) <= (size_t)loc)
        return NULL;
    else
        return sk_YX509_EXTENSION_value(x, loc);
}

YX509_EXTENSION *YX509v3_delete_ext(STACK_OF(YX509_EXTENSION) *x, int loc)
{
    YX509_EXTENSION *ret;

    if (x == NULL || loc < 0 || sk_YX509_EXTENSION_num(x) <= (size_t)loc)
        return (NULL);
    ret = sk_YX509_EXTENSION_delete(x, loc);
    return (ret);
}

STACK_OF(YX509_EXTENSION) *YX509v3_add_ext(STACK_OF(YX509_EXTENSION) **x,
                                         YX509_EXTENSION *ex, int loc)
{
    YX509_EXTENSION *new_ex = NULL;
    int n;
    STACK_OF(YX509_EXTENSION) *sk = NULL;

    if (x == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_PASSED_NULL_PARAMETER);
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
    return (sk);
 err:
    OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
 err2:
    if (new_ex != NULL)
        YX509_EXTENSION_free(new_ex);
    if (sk != NULL)
        sk_YX509_EXTENSION_free(sk);
    return (NULL);
}

YX509_EXTENSION *YX509_EXTENSION_create_by_NID(YX509_EXTENSION **ex, int nid,
                                             int crit,
                                             YASN1_OCTET_STRING *data)
{
    const YASN1_OBJECT *obj;
    YX509_EXTENSION *ret;

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        OPENSSL_PUT_ERROR(YX509, YX509_R_UNKNOWN_NID);
        return (NULL);
    }
    ret = YX509_EXTENSION_create_by_OBJ(ex, obj, crit, data);
    return (ret);
}

YX509_EXTENSION *YX509_EXTENSION_create_by_OBJ(YX509_EXTENSION **ex,
                                             const YASN1_OBJECT *obj, int crit,
                                             YASN1_OCTET_STRING *data)
{
    YX509_EXTENSION *ret;

    if ((ex == NULL) || (*ex == NULL)) {
        if ((ret = YX509_EXTENSION_new()) == NULL) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
            return (NULL);
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
    return (ret);
 err:
    if ((ex == NULL) || (ret != *ex))
        YX509_EXTENSION_free(ret);
    return (NULL);
}

int YX509_EXTENSION_set_object(YX509_EXTENSION *ex, const YASN1_OBJECT *obj)
{
    if ((ex == NULL) || (obj == NULL))
        return (0);
    YASN1_OBJECT_free(ex->object);
    ex->object = OBJ_dup(obj);
    return ex->object != NULL;
}

int YX509_EXTENSION_set_critical(YX509_EXTENSION *ex, int crit)
{
    if (ex == NULL)
        return (0);
    ex->critical = (crit) ? 0xFF : -1;
    return (1);
}

int YX509_EXTENSION_set_data(YX509_EXTENSION *ex, YASN1_OCTET_STRING *data)
{
    int i;

    if (ex == NULL)
        return (0);
    i = M_YASN1_OCTET_STRING_set(ex->value, data->data, data->length);
    if (!i)
        return (0);
    return (1);
}

YASN1_OBJECT *YX509_EXTENSION_get_object(YX509_EXTENSION *ex)
{
    if (ex == NULL)
        return (NULL);
    return (ex->object);
}

YASN1_OCTET_STRING *YX509_EXTENSION_get_data(YX509_EXTENSION *ex)
{
    if (ex == NULL)
        return (NULL);
    return (ex->value);
}

int YX509_EXTENSION_get_critical(YX509_EXTENSION *ex)
{
    if (ex == NULL)
        return (0);
    if (ex->critical > 0)
        return 1;
    return 0;
}
