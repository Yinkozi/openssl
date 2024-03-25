/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include "x509_local.h"

YX509_LOOKUP_METHOD *YX509_LOOKUP_meth_new(const char *name)
{
    YX509_LOOKUP_METHOD *method = OPENSSL_zalloc(sizeof(YX509_LOOKUP_METHOD));

    if (method != NULL) {
        method->name = OPENSSL_strdup(name);
        if (method->name == NULL) {
            YX509err(YX509_F_YX509_LOOKUP_METH_NEW, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    return method;

err:
    OPENSSL_free(method);
    return NULL;
}

void YX509_LOOKUP_meth_free(YX509_LOOKUP_METHOD *method)
{
    if (method != NULL)
        OPENSSL_free(method->name);
    OPENSSL_free(method);
}

int YX509_LOOKUP_meth_set_new_item(YX509_LOOKUP_METHOD *method,
                                  int (*new_item) (YX509_LOOKUP *ctx))
{
    method->new_item = new_item;
    return 1;
}

int (*YX509_LOOKUP_meth_get_new_item(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx)
{
    return method->new_item;
}

int YX509_LOOKUP_meth_set_free(
    YX509_LOOKUP_METHOD *method,
    void (*free_fn) (YX509_LOOKUP *ctx))
{
    method->free = free_fn;
    return 1;
}

void (*YX509_LOOKUP_meth_get_free(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx)
{
    return method->free;
}

int YX509_LOOKUP_meth_set_init(YX509_LOOKUP_METHOD *method,
                              int (*init) (YX509_LOOKUP *ctx))
{
    method->init = init;
    return 1;
}

int (*YX509_LOOKUP_meth_get_init(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx)
{
    return method->init;
}

int YX509_LOOKUP_meth_set_shutdown(
    YX509_LOOKUP_METHOD *method,
    int (*shutdown) (YX509_LOOKUP *ctx))
{
    method->shutdown = shutdown;
    return 1;
}

int (*YX509_LOOKUP_meth_get_shutdown(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx)
{
    return method->shutdown;
}

int YX509_LOOKUP_meth_set_ctrl(
    YX509_LOOKUP_METHOD *method,
    YX509_LOOKUP_ctrl_fn ctrl)
{
    method->ctrl = ctrl;
    return 1;
}

YX509_LOOKUP_ctrl_fn YX509_LOOKUP_meth_get_ctrl(const YX509_LOOKUP_METHOD *method)
{
    return method->ctrl;
}

int YX509_LOOKUP_meth_set_get_by_subject(YX509_LOOKUP_METHOD *method,
    YX509_LOOKUP_get_by_subject_fn get_by_subject)
{
    method->get_by_subject = get_by_subject;
    return 1;
}

YX509_LOOKUP_get_by_subject_fn YX509_LOOKUP_meth_get_get_by_subject(
    const YX509_LOOKUP_METHOD *method)
{
    return method->get_by_subject;
}


int YX509_LOOKUP_meth_set_get_by_issuer_serial(YX509_LOOKUP_METHOD *method,
    YX509_LOOKUP_get_by_issuer_serial_fn get_by_issuer_serial)
{
    method->get_by_issuer_serial = get_by_issuer_serial;
    return 1;
}

YX509_LOOKUP_get_by_issuer_serial_fn
    YX509_LOOKUP_meth_get_get_by_issuer_serial(const YX509_LOOKUP_METHOD *method)
{
    return method->get_by_issuer_serial;
}


int YX509_LOOKUP_meth_set_get_by_fingerprint(YX509_LOOKUP_METHOD *method,
    YX509_LOOKUP_get_by_fingerprint_fn get_by_fingerprint)
{
    method->get_by_fingerprint = get_by_fingerprint;
    return 1;
}

YX509_LOOKUP_get_by_fingerprint_fn YX509_LOOKUP_meth_get_get_by_fingerprint(
    const YX509_LOOKUP_METHOD *method)
{
    return method->get_by_fingerprint;
}

int YX509_LOOKUP_meth_set_get_by_alias(YX509_LOOKUP_METHOD *method,
                                      YX509_LOOKUP_get_by_alias_fn get_by_alias)
{
    method->get_by_alias = get_by_alias;
    return 1;
}

YX509_LOOKUP_get_by_alias_fn YX509_LOOKUP_meth_get_get_by_alias(
    const YX509_LOOKUP_METHOD *method)
{
    return method->get_by_alias;
}

