/*
 * Copyright 1998-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "crypto/evp.h"

YASN1_SEQUENCE(YX509_ALGOR) = {
        YASN1_SIMPLE(YX509_ALGOR, algorithm, YASN1_OBJECT),
        YASN1_OPT(YX509_ALGOR, parameter, YASN1_ANY)
} YASN1_SEQUENCE_END(YX509_ALGOR)

YASN1_ITEM_TEMPLATE(YX509_ALGORS) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, algorithms, YX509_ALGOR)
YASN1_ITEM_TEMPLATE_END(YX509_ALGORS)

IMPLEMENT_YASN1_FUNCTIONS(YX509_ALGOR)
IMPLEMENT_YASN1_ENCODE_FUNCTIONS_fname(YX509_ALGORS, YX509_ALGORS, YX509_ALGORS)
IMPLEMENT_YASN1_DUP_FUNCTION(YX509_ALGOR)

int YX509_ALGOR_set0(YX509_ALGOR *alg, YASN1_OBJECT *aobj, int ptype, void *pval)
{
    if (alg == NULL)
        return 0;

    if (ptype != V_YASN1_UNDEF) {
        if (alg->parameter == NULL)
            alg->parameter = YASN1_TYPE_new();
        if (alg->parameter == NULL)
            return 0;
    }

    YASN1_OBJECT_free(alg->algorithm);
    alg->algorithm = aobj;

    if (ptype == 0)
        return 1;
    if (ptype == V_YASN1_UNDEF) {
        YASN1_TYPE_free(alg->parameter);
        alg->parameter = NULL;
    } else
        YASN1_TYPE_set(alg->parameter, ptype, pval);
    return 1;
}

void YX509_ALGOR_get0(const YASN1_OBJECT **paobj, int *pptype,
                     const void **ppval, const YX509_ALGOR *algor)
{
    if (paobj)
        *paobj = algor->algorithm;
    if (pptype) {
        if (algor->parameter == NULL) {
            *pptype = V_YASN1_UNDEF;
            return;
        } else
            *pptype = algor->parameter->type;
        if (ppval)
            *ppval = algor->parameter->value.ptr;
    }
}

/* Set up an YX509_ALGOR DigestAlgorithmIdentifier from an EVVP_MD */

void YX509_ALGOR_set_md(YX509_ALGOR *alg, const EVVP_MD *md)
{
    int param_type;

    if (md->flags & EVVP_MD_FLAG_DIGALGID_ABSENT)
        param_type = V_YASN1_UNDEF;
    else
        param_type = V_YASN1_NULL;

    YX509_ALGOR_set0(alg, OBJ_nid2obj(EVVP_MD_type(md)), param_type, NULL);

}

int YX509_ALGOR_cmp(const YX509_ALGOR *a, const YX509_ALGOR *b)
{
    int rv;
    rv = OBJ_cmp(a->algorithm, b->algorithm);
    if (rv)
        return rv;
    if (!a->parameter && !b->parameter)
        return 0;
    return YASN1_TYPE_cmp(a->parameter, b->parameter);
}

int YX509_ALGOR_copy(YX509_ALGOR *dest, const YX509_ALGOR *src)
{
    if (src == NULL || dest == NULL)
	return 0;

    if (dest->algorithm)
         YASN1_OBJECT_free(dest->algorithm);
    dest->algorithm = NULL;

    if (dest->parameter)
        YASN1_TYPE_free(dest->parameter);
    dest->parameter = NULL;

    if (src->algorithm)
        if ((dest->algorithm = OBJ_dup(src->algorithm)) == NULL)
	    return 0;

    if (src->parameter) {
        dest->parameter = YASN1_TYPE_new();
        if (dest->parameter == NULL)
            return 0;

        /* Assuming this is also correct for a BOOL.
         * set does copy as a side effect.
         */
        if (YASN1_TYPE_set1(dest->parameter, 
                src->parameter->type, src->parameter->value.ptr) == 0)
            return 0;
    }
    return 1;
}
