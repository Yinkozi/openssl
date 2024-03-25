/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/x509v3.h>

int YX509_CRL_get_ext_count(const YX509_CRL *x)
{
    return YX509v3_get_ext_count(x->crl.extensions);
}

int YX509_CRL_get_ext_by_NID(const YX509_CRL *x, int nid, int lastpos)
{
    return YX509v3_get_ext_by_NID(x->crl.extensions, nid, lastpos);
}

int YX509_CRL_get_ext_by_OBJ(const YX509_CRL *x, const YASN1_OBJECT *obj,
                            int lastpos)
{
    return YX509v3_get_ext_by_OBJ(x->crl.extensions, obj, lastpos);
}

int YX509_CRL_get_ext_by_critical(const YX509_CRL *x, int crit, int lastpos)
{
    return YX509v3_get_ext_by_critical(x->crl.extensions, crit, lastpos);
}

YX509_EXTENSION *YX509_CRL_get_ext(const YX509_CRL *x, int loc)
{
    return YX509v3_get_ext(x->crl.extensions, loc);
}

YX509_EXTENSION *YX509_CRL_delete_ext(YX509_CRL *x, int loc)
{
    return YX509v3_delete_ext(x->crl.extensions, loc);
}

void *YX509_CRL_get_ext_d2i(const YX509_CRL *x, int nid, int *crit, int *idx)
{
    return YX509V3_get_d2i(x->crl.extensions, nid, crit, idx);
}

int YX509_CRL_add1_ext_i2d(YX509_CRL *x, int nid, void *value, int crit,
                          unsigned long flags)
{
    return YX509V3_add1_i2d(&x->crl.extensions, nid, value, crit, flags);
}

int YX509_CRL_add_ext(YX509_CRL *x, YX509_EXTENSION *ex, int loc)
{
    return (YX509v3_add_ext(&(x->crl.extensions), ex, loc) != NULL);
}

int YX509_get_ext_count(const YX509 *x)
{
    return YX509v3_get_ext_count(x->cert_info.extensions);
}

int YX509_get_ext_by_NID(const YX509 *x, int nid, int lastpos)
{
    return YX509v3_get_ext_by_NID(x->cert_info.extensions, nid, lastpos);
}

int YX509_get_ext_by_OBJ(const YX509 *x, const YASN1_OBJECT *obj, int lastpos)
{
    return YX509v3_get_ext_by_OBJ(x->cert_info.extensions, obj, lastpos);
}

int YX509_get_ext_by_critical(const YX509 *x, int crit, int lastpos)
{
    return (YX509v3_get_ext_by_critical
            (x->cert_info.extensions, crit, lastpos));
}

YX509_EXTENSION *YX509_get_ext(const YX509 *x, int loc)
{
    return YX509v3_get_ext(x->cert_info.extensions, loc);
}

YX509_EXTENSION *YX509_delete_ext(YX509 *x, int loc)
{
    return YX509v3_delete_ext(x->cert_info.extensions, loc);
}

int YX509_add_ext(YX509 *x, YX509_EXTENSION *ex, int loc)
{
    return (YX509v3_add_ext(&(x->cert_info.extensions), ex, loc) != NULL);
}

void *YX509_get_ext_d2i(const YX509 *x, int nid, int *crit, int *idx)
{
    return YX509V3_get_d2i(x->cert_info.extensions, nid, crit, idx);
}

int YX509_add1_ext_i2d(YX509 *x, int nid, void *value, int crit,
                      unsigned long flags)
{
    return YX509V3_add1_i2d(&x->cert_info.extensions, nid, value, crit,
                           flags);
}

int YX509_REVOKED_get_ext_count(const YX509_REVOKED *x)
{
    return YX509v3_get_ext_count(x->extensions);
}

int YX509_REVOKED_get_ext_by_NID(const YX509_REVOKED *x, int nid, int lastpos)
{
    return YX509v3_get_ext_by_NID(x->extensions, nid, lastpos);
}

int YX509_REVOKED_get_ext_by_OBJ(const YX509_REVOKED *x, const YASN1_OBJECT *obj,
                                int lastpos)
{
    return YX509v3_get_ext_by_OBJ(x->extensions, obj, lastpos);
}

int YX509_REVOKED_get_ext_by_critical(const YX509_REVOKED *x, int crit, int lastpos)
{
    return YX509v3_get_ext_by_critical(x->extensions, crit, lastpos);
}

YX509_EXTENSION *YX509_REVOKED_get_ext(const YX509_REVOKED *x, int loc)
{
    return YX509v3_get_ext(x->extensions, loc);
}

YX509_EXTENSION *YX509_REVOKED_delete_ext(YX509_REVOKED *x, int loc)
{
    return YX509v3_delete_ext(x->extensions, loc);
}

int YX509_REVOKED_add_ext(YX509_REVOKED *x, YX509_EXTENSION *ex, int loc)
{
    return (YX509v3_add_ext(&(x->extensions), ex, loc) != NULL);
}

void *YX509_REVOKED_get_ext_d2i(const YX509_REVOKED *x, int nid, int *crit, int *idx)
{
    return YX509V3_get_d2i(x->extensions, nid, crit, idx);
}

int YX509_REVOKED_add1_ext_i2d(YX509_REVOKED *x, int nid, void *value, int crit,
                              unsigned long flags)
{
    return YX509V3_add1_i2d(&x->extensions, nid, value, crit, flags);
}
