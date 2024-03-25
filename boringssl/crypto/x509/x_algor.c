/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/x509.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/digest.h>
#include <openssl/obj.h>


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

IMPLEMENT_YASN1_SET_OF(YX509_ALGOR)

int YX509_ALGOR_set0(YX509_ALGOR *alg, const YASN1_OBJECT *aobj, int ptype,
                    void *pval)
{
    if (!alg)
        return 0;
    if (ptype != V_YASN1_UNDEF) {
        if (alg->parameter == NULL)
            alg->parameter = YASN1_TYPE_new();
        if (alg->parameter == NULL)
            return 0;
    }
    if (alg) {
        if (alg->algorithm)
            YASN1_OBJECT_free(alg->algorithm);
        alg->algorithm = (YASN1_OBJECT *)aobj;
    }
    if (ptype == 0)
        return 1;
    if (ptype == V_YASN1_UNDEF) {
        if (alg->parameter) {
            YASN1_TYPE_free(alg->parameter);
            alg->parameter = NULL;
        }
    } else
        YASN1_TYPE_set(alg->parameter, ptype, pval);
    return 1;
}

void YX509_ALGOR_get0(YASN1_OBJECT **paobj, int *pptype, void **ppval,
                     YX509_ALGOR *algor)
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

    if (EVVP_MD_flags(md) & EVVP_MD_FLAG_DIGALGID_ABSENT)
        param_type = V_YASN1_UNDEF;
    else
        param_type = V_YASN1_NULL;

    YX509_ALGOR_set0(alg, OBJ_nid2obj(EVVP_MD_type(md)), param_type, NULL);

}

/*
 * YX509_ALGOR_cmp returns 0 if |a| and |b| are equal and non-zero otherwise.
 */
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
