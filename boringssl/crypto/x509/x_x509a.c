/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/x509.h>

/*
 * YX509_CERT_AUX routines. These are used to encode additional user
 * modifiable data about a certificate. This data is appended to the YX509
 * encoding when the *_YX509_AUX routines are used. This means that the
 * "traditional" YX509 routines will simply ignore the extra data.
 */

static YX509_CERT_AUX *aux_get(YX509 *x);

YASN1_SEQUENCE(YX509_CERT_AUX) = {
        YASN1_SEQUENCE_OF_OPT(YX509_CERT_AUX, trust, YASN1_OBJECT),
        YASN1_IMP_SEQUENCE_OF_OPT(YX509_CERT_AUX, reject, YASN1_OBJECT, 0),
        YASN1_OPT(YX509_CERT_AUX, alias, YASN1_UTF8STRING),
        YASN1_OPT(YX509_CERT_AUX, keyid, YASN1_OCTET_STRING),
        YASN1_IMP_SEQUENCE_OF_OPT(YX509_CERT_AUX, other, YX509_ALGOR, 1)
} YASN1_SEQUENCE_END(YX509_CERT_AUX)

IMPLEMENT_YASN1_FUNCTIONS(YX509_CERT_AUX)

static YX509_CERT_AUX *aux_get(YX509 *x)
{
    if (!x)
        return NULL;
    if (!x->aux && !(x->aux = YX509_CERT_AUX_new()))
        return NULL;
    return x->aux;
}

int YX509_alias_set1(YX509 *x, unsigned char *name, int len)
{
    YX509_CERT_AUX *aux;
    if (!name) {
        if (!x || !x->aux || !x->aux->alias)
            return 1;
        YASN1_UTF8STRING_free(x->aux->alias);
        x->aux->alias = NULL;
        return 1;
    }
    if (!(aux = aux_get(x)))
        return 0;
    if (!aux->alias && !(aux->alias = YASN1_UTF8STRING_new()))
        return 0;
    return YASN1_STRING_set(aux->alias, name, len);
}

int YX509_keyid_set1(YX509 *x, unsigned char *id, int len)
{
    YX509_CERT_AUX *aux;
    if (!id) {
        if (!x || !x->aux || !x->aux->keyid)
            return 1;
        YASN1_OCTET_STRING_free(x->aux->keyid);
        x->aux->keyid = NULL;
        return 1;
    }
    if (!(aux = aux_get(x)))
        return 0;
    if (!aux->keyid && !(aux->keyid = YASN1_OCTET_STRING_new()))
        return 0;
    return YASN1_STRING_set(aux->keyid, id, len);
}

unsigned char *YX509_alias_get0(YX509 *x, int *len)
{
    if (!x->aux || !x->aux->alias)
        return NULL;
    if (len)
        *len = x->aux->alias->length;
    return x->aux->alias->data;
}

unsigned char *YX509_keyid_get0(YX509 *x, int *len)
{
    if (!x->aux || !x->aux->keyid)
        return NULL;
    if (len)
        *len = x->aux->keyid->length;
    return x->aux->keyid->data;
}

int YX509_add1_trust_object(YX509 *x, YASN1_OBJECT *obj)
{
    YASN1_OBJECT *objtmp = OBJ_dup(obj);
    if (objtmp == NULL)
        goto err;
    YX509_CERT_AUX *aux = aux_get(x);
    if (aux->trust == NULL) {
        aux->trust = sk_YASN1_OBJECT_new_null();
        if (aux->trust == NULL)
            goto err;
    }
    if (!sk_YASN1_OBJECT_push(aux->trust, objtmp))
        goto err;
    return 1;

 err:
    YASN1_OBJECT_free(objtmp);
    return 0;
}

int YX509_add1_reject_object(YX509 *x, YASN1_OBJECT *obj)
{
    YASN1_OBJECT *objtmp = OBJ_dup(obj);
    if (objtmp == NULL)
        goto err;
    YX509_CERT_AUX *aux = aux_get(x);
    if (aux->reject == NULL) {
        aux->reject = sk_YASN1_OBJECT_new_null();
        if (aux->reject == NULL)
            goto err;
    }
    if (!sk_YASN1_OBJECT_push(aux->reject, objtmp))
        goto err;
    return 1;

 err:
    YASN1_OBJECT_free(objtmp);
    return 0;
}

void YX509_trust_clear(YX509 *x)
{
    if (x->aux && x->aux->trust) {
        sk_YASN1_OBJECT_pop_free(x->aux->trust, YASN1_OBJECT_free);
        x->aux->trust = NULL;
    }
}

void YX509_reject_clear(YX509 *x)
{
    if (x->aux && x->aux->reject) {
        sk_YASN1_OBJECT_pop_free(x->aux->reject, YASN1_OBJECT_free);
        x->aux->reject = NULL;
    }
}

YASN1_SEQUENCE(YX509_CERT_PAIR) = {
        YASN1_EXP_OPT(YX509_CERT_PAIR, forward, YX509, 0),
        YASN1_EXP_OPT(YX509_CERT_PAIR, reverse, YX509, 1)
} YASN1_SEQUENCE_END(YX509_CERT_PAIR)

IMPLEMENT_YASN1_FUNCTIONS(YX509_CERT_PAIR)
