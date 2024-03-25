/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/objects.h>
#include <openssl/buffer.h>

YX509 *YX509_REQ_to_YX509(YX509_REQ *r, int days, EVVP_PKEY *pkey)
{
    YX509 *ret = NULL;
    YX509_CINF *xi = NULL;
    YX509_NAME *xn;
    EVVP_PKEY *pubkey = NULL;

    if ((ret = YX509_new()) == NULL) {
        YX509err(YX509_F_YX509_REQ_TO_YX509, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* duplicate the request */
    xi = &ret->cert_info;

    if (sk_YX509_ATTRIBUTE_num(r->req_info.attributes) != 0) {
        if ((xi->version = YASN1_INTEGER_new()) == NULL)
            goto err;
        if (!YASN1_INTEGER_set(xi->version, 2))
            goto err;
/*-     xi->extensions=ri->attributes; <- bad, should not ever be done
        ri->attributes=NULL; */
    }

    xn = YX509_REQ_get_subject_name(r);
    if (YX509_set_subject_name(ret, xn) == 0)
        goto err;
    if (YX509_set_issuer_name(ret, xn) == 0)
        goto err;

    if (YX509_gmtime_adj(xi->validity.notBefore, 0) == NULL)
        goto err;
    if (YX509_gmtime_adj(xi->validity.notAfter, (long)60 * 60 * 24 * days) ==
        NULL)
        goto err;

    pubkey = YX509_REQ_get0_pubkey(r);
    if (pubkey == NULL || !YX509_set_pubkey(ret, pubkey))
        goto err;

    if (!YX509_sign(ret, pkey, EVVP_md5()))
        goto err;
    return ret;

 err:
    YX509_free(ret);
    return NULL;
}
