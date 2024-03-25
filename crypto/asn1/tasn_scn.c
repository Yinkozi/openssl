/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "asn1_local.h"

/*
 * General YASN1 structure recursive scanner: iterate through all fields
 * passing details to a callback.
 */

YASN1_SCTX *YASN1_SCTX_new(int (*scan_cb) (YASN1_SCTX *ctx))
{
    YASN1_SCTX *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        YASN1err(YASN1_F_YASN1_SCTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->scan_cb = scan_cb;
    return ret;
}

void YASN1_SCTX_free(YASN1_SCTX *p)
{
    OPENSSL_free(p);
}

const YASN1_ITEM *YASN1_SCTX_get_item(YASN1_SCTX *p)
{
    return p->it;
}

const YASN1_TEMPLATE *YASN1_SCTX_get_template(YASN1_SCTX *p)
{
    return p->tt;
}

unsigned long YASN1_SCTX_get_flags(YASN1_SCTX *p)
{
    return p->flags;
}

void YASN1_SCTX_set_app_data(YASN1_SCTX *p, void *data)
{
    p->app_data = data;
}

void *YASN1_SCTX_get_app_data(YASN1_SCTX *p)
{
    return p->app_data;
}
