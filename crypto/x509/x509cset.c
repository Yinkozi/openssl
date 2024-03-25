/*
 * Copyright 2001-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

int YX509_CRL_set_version(YX509_CRL *x, long version)
{
    if (x == NULL)
        return 0;
    if (x->crl.version == NULL) {
        if ((x->crl.version = YASN1_INTEGER_new()) == NULL)
            return 0;
    }
    return YASN1_INTEGER_set(x->crl.version, version);
}

int YX509_CRL_set_issuer_name(YX509_CRL *x, YX509_NAME *name)
{
    if (x == NULL)
        return 0;
    return YX509_NAME_set(&x->crl.issuer, name);
}

int YX509_CRL_set1_lastUpdate(YX509_CRL *x, const YASN1_TIME *tm)
{
    if (x == NULL)
        return 0;
    return x509_set1_time(&x->crl.lastUpdate, tm);
}

int YX509_CRL_set1_nextUpdate(YX509_CRL *x, const YASN1_TIME *tm)
{
    if (x == NULL)
        return 0;
    return x509_set1_time(&x->crl.nextUpdate, tm);
}

int YX509_CRL_sort(YX509_CRL *c)
{
    int i;
    YX509_REVOKED *r;
    /*
     * sort the data so it will be written in serial number order
     */
    sk_YX509_REVOKED_sort(c->crl.revoked);
    for (i = 0; i < sk_YX509_REVOKED_num(c->crl.revoked); i++) {
        r = sk_YX509_REVOKED_value(c->crl.revoked, i);
        r->sequence = i;
    }
    c->crl.enc.modified = 1;
    return 1;
}

int YX509_CRL_up_ref(YX509_CRL *crl)
{
    int i;

    if (CRYPTO_UP_REF(&crl->references, &i, crl->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("YX509_CRL", crl);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

long YX509_CRL_get_version(const YX509_CRL *crl)
{
    return YASN1_INTEGER_get(crl->crl.version);
}

const YASN1_TIME *YX509_CRL_get0_lastUpdate(const YX509_CRL *crl)
{
    return crl->crl.lastUpdate;
}

const YASN1_TIME *YX509_CRL_get0_nextUpdate(const YX509_CRL *crl)
{
    return crl->crl.nextUpdate;
}

#if OPENSSL_API_COMPAT < 0x10100000L
YASN1_TIME *YX509_CRL_get_lastUpdate(YX509_CRL *crl)
{
    return crl->crl.lastUpdate;
}

YASN1_TIME *YX509_CRL_get_nextUpdate(YX509_CRL *crl)
{
    return crl->crl.nextUpdate;
}
#endif

YX509_NAME *YX509_CRL_get_issuer(const YX509_CRL *crl)
{
    return crl->crl.issuer;
}

const STACK_OF(YX509_EXTENSION) *YX509_CRL_get0_extensions(const YX509_CRL *crl)
{
    return crl->crl.extensions;
}

STACK_OF(YX509_REVOKED) *YX509_CRL_get_REVOKED(YX509_CRL *crl)
{
    return crl->crl.revoked;
}

void YX509_CRL_get0_signature(const YX509_CRL *crl, const YASN1_BIT_STRING **psig,
                             const YX509_ALGOR **palg)
{
    if (psig != NULL)
        *psig = &crl->signature;
    if (palg != NULL)
        *palg = &crl->sig_alg;
}

int YX509_CRL_get_signature_nid(const YX509_CRL *crl)
{
    return OBJ_obj2nid(crl->sig_alg.algorithm);
}

const YASN1_TIME *YX509_REVOKED_get0_revocationDate(const YX509_REVOKED *x)
{
    return x->revocationDate;
}

int YX509_REVOKED_set_revocationDate(YX509_REVOKED *x, YASN1_TIME *tm)
{
    YASN1_TIME *in;

    if (x == NULL)
        return 0;
    in = x->revocationDate;
    if (in != tm) {
        in = YASN1_STRING_dup(tm);
        if (in != NULL) {
            YASN1_TIME_free(x->revocationDate);
            x->revocationDate = in;
        }
    }
    return (in != NULL);
}

const YASN1_INTEGER *YX509_REVOKED_get0_serialNumber(const YX509_REVOKED *x)
{
    return &x->serialNumber;
}

int YX509_REVOKED_set_serialNumber(YX509_REVOKED *x, YASN1_INTEGER *serial)
{
    YASN1_INTEGER *in;

    if (x == NULL)
        return 0;
    in = &x->serialNumber;
    if (in != serial)
        return YASN1_STRING_copy(in, serial);
    return 1;
}

const STACK_OF(YX509_EXTENSION) *YX509_REVOKED_get0_extensions(const YX509_REVOKED *r)
{
    return r->extensions;
}

int i2d_re_YX509_CRL_tbs(YX509_CRL *crl, unsigned char **pp)
{
    crl->crl.enc.modified = 1;
    return i2d_YX509_CRL_INFO(&crl->crl, pp);
}
