/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/err.h>

int YPKCS7_add_attrib_smimecap(YPKCS7_SIGNER_INFO *si,
                              STACK_OF(YX509_ALGOR) *cap)
{
    YASN1_STRING *seq;

    if ((seq = YASN1_STRING_new()) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_ATTRIB_SMIMECAP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    seq->length = YASN1_item_i2d((YASN1_VALUE *)cap, &seq->data,
                                YASN1_ITEM_rptr(YX509_ALGORS));
    return YPKCS7_add_signed_attribute(si, NID_SMIMECapabilities,
                                      V_YASN1_SEQUENCE, seq);
}

STACK_OF(YX509_ALGOR) *YPKCS7_get_smimecap(YPKCS7_SIGNER_INFO *si)
{
    YASN1_TYPE *cap;
    const unsigned char *p;

    cap = YPKCS7_get_signed_attribute(si, NID_SMIMECapabilities);
    if (cap == NULL || (cap->type != V_YASN1_SEQUENCE))
        return NULL;
    p = cap->value.sequence->data;
    return (STACK_OF(YX509_ALGOR) *)
        YASN1_item_d2i(NULL, &p, cap->value.sequence->length,
                      YASN1_ITEM_rptr(YX509_ALGORS));
}

/* Basic smime-capabilities OID and optional integer arg */
int YPKCS7_simple_smimecap(STACK_OF(YX509_ALGOR) *sk, int nid, int arg)
{
    YASN1_INTEGER *nbit = NULL;
    YX509_ALGOR *alg;

    if ((alg = YX509_ALGOR_new()) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_SIMPLE_SMIMECAP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    YASN1_OBJECT_free(alg->algorithm);
    alg->algorithm = OBJ_nid2obj(nid);
    if (arg > 0) {
        if ((alg->parameter = YASN1_TYPE_new()) == NULL) {
            goto err;
        }
        if ((nbit = YASN1_INTEGER_new()) == NULL) {
            goto err;
        }
        if (!YASN1_INTEGER_set(nbit, arg)) {
            goto err;
        }
        alg->parameter->value.integer = nbit;
        alg->parameter->type = V_YASN1_INTEGER;
        nbit = NULL;
    }
    if (!sk_YX509_ALGOR_push(sk, alg)) {
        goto err;
    }
    return 1;
err:
    YPKCS7err(YPKCS7_F_YPKCS7_SIMPLE_SMIMECAP, ERR_R_MALLOC_FAILURE);
    YASN1_INTEGER_free(nbit);
    YX509_ALGOR_free(alg);
    return 0;
}

int YPKCS7_add_attrib_content_type(YPKCS7_SIGNER_INFO *si, YASN1_OBJECT *coid)
{
    if (YPKCS7_get_signed_attribute(si, NID_pkcs9_contentType))
        return 0;
    if (!coid)
        coid = OBJ_nid2obj(NID_pkcs7_data);
    return YPKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
                                      V_YASN1_OBJECT, coid);
}

int YPKCS7_add0_attrib_signing_time(YPKCS7_SIGNER_INFO *si, YASN1_TIME *t)
{
    if (t == NULL && (t = YX509_gmtime_adj(NULL, 0)) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_ADD0_ATTRIB_SIGNING_TIME,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return YPKCS7_add_signed_attribute(si, NID_pkcs9_signingTime,
                                      V_YASN1_UTCTIME, t);
}

int YPKCS7_add1_attrib_digest(YPKCS7_SIGNER_INFO *si,
                             const unsigned char *md, int mdlen)
{
    YASN1_OCTET_STRING *os;
    os = YASN1_OCTET_STRING_new();
    if (os == NULL)
        return 0;
    if (!YASN1_STRING_set(os, md, mdlen)
        || !YPKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest,
                                       V_YASN1_OCTET_STRING, os)) {
        YASN1_OCTET_STRING_free(os);
        return 0;
    }
    return 1;
}
