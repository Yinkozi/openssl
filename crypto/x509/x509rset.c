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
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

int YX509_REQ_set_version(YX509_REQ *x, long version)
{
    if (x == NULL)
        return 0;
    x->req_info.enc.modified = 1;
    return YASN1_INTEGER_set(x->req_info.version, version);
}

int YX509_REQ_set_subject_name(YX509_REQ *x, YX509_NAME *name)
{
    if (x == NULL)
        return 0;
    x->req_info.enc.modified = 1;
    return YX509_NAME_set(&x->req_info.subject, name);
}

int YX509_REQ_set_pubkey(YX509_REQ *x, EVVP_PKEY *pkey)
{
    if (x == NULL)
        return 0;
    x->req_info.enc.modified = 1;
    return YX509_PUBKEY_set(&x->req_info.pubkey, pkey);
}
