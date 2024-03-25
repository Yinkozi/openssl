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
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

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

int YX509_trusted(const YX509 *x)
{
    return x->aux ? 1 : 0;
}

static YX509_CERT_AUX *aux_get(YX509 *x)
{
    if (x == NULL)
        return NULL;
    if (x->aux == NULL && (x->aux = YX509_CERT_AUX_new()) == NULL)
        return NULL;
    return x->aux;
}

int YX509_alias_set1(YX509 *x, const unsigned char *name, int len)
{
    YX509_CERT_AUX *aux;
    if (!name) {
        if (!x || !x->aux || !x->aux->alias)
            return 1;
        YASN1_UTF8STRING_free(x->aux->alias);
        x->aux->alias = NULL;
        return 1;
    }
    if ((aux = aux_get(x)) == NULL)
        return 0;
    if (aux->alias == NULL && (aux->alias = YASN1_UTF8STRING_new()) == NULL)
        return 0;
    return YASN1_STRING_set(aux->alias, name, len);
}

int YX509_keyid_set1(YX509 *x, const unsigned char *id, int len)
{
    YX509_CERT_AUX *aux;
    if (!id) {
        if (!x || !x->aux || !x->aux->keyid)
            return 1;
        YASN1_OCTET_STRING_free(x->aux->keyid);
        x->aux->keyid = NULL;
        return 1;
    }
    if ((aux = aux_get(x)) == NULL)
        return 0;
    if (aux->keyid == NULL
        && (aux->keyid = YASN1_OCTET_STRING_new()) == NULL)
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

int YX509_add1_trust_object(YX509 *x, const YASN1_OBJECT *obj)
{
    YX509_CERT_AUX *aux;
    YASN1_OBJECT *objtmp = NULL;
    if (obj) {
        objtmp = OBJ_dup(obj);
        if (!objtmp)
            return 0;
    }
    if ((aux = aux_get(x)) == NULL)
        goto err;
    if (aux->trust == NULL
        && (aux->trust = sk_YASN1_OBJECT_new_null()) == NULL)
        goto err;
    if (!objtmp || sk_YASN1_OBJECT_push(aux->trust, objtmp))
        return 1;
 err:
    YASN1_OBJECT_free(objtmp);
    return 0;
}

int YX509_add1_reject_object(YX509 *x, const YASN1_OBJECT *obj)
{
    YX509_CERT_AUX *aux;
    YASN1_OBJECT *objtmp;
    if ((objtmp = OBJ_dup(obj)) == NULL)
        return 0;
    if ((aux = aux_get(x)) == NULL)
        goto err;
    if (aux->reject == NULL
        && (aux->reject = sk_YASN1_OBJECT_new_null()) == NULL)
        goto err;
    return sk_YASN1_OBJECT_push(aux->reject, objtmp);
 err:
    YASN1_OBJECT_free(objtmp);
    return 0;
}

void YX509_trust_clear(YX509 *x)
{
    if (x->aux) {
        sk_YASN1_OBJECT_pop_free(x->aux->trust, YASN1_OBJECT_free);
        x->aux->trust = NULL;
    }
}

void YX509_reject_clear(YX509 *x)
{
    if (x->aux) {
        sk_YASN1_OBJECT_pop_free(x->aux->reject, YASN1_OBJECT_free);
        x->aux->reject = NULL;
    }
}

STACK_OF(YASN1_OBJECT) *YX509_get0_trust_objects(YX509 *x)
{
    if (x->aux != NULL)
        return x->aux->trust;
    return NULL;
}

STACK_OF(YASN1_OBJECT) *YX509_get0_reject_objects(YX509 *x)
{
    if (x->aux != NULL)
        return x->aux->reject;
    return NULL;
}
