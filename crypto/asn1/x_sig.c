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
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

YASN1_SEQUENCE(YX509_SIG) = {
        YASN1_SIMPLE(YX509_SIG, algor, YX509_ALGOR),
        YASN1_SIMPLE(YX509_SIG, digest, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(YX509_SIG)

IMPLEMENT_YASN1_FUNCTIONS(YX509_SIG)

void YX509_SIG_get0(const YX509_SIG *sig, const YX509_ALGOR **palg,
                   const YASN1_OCTET_STRING **pdigest)
{
    if (palg)
        *palg = sig->algor;
    if (pdigest)
        *pdigest = sig->digest;
}

void YX509_SIG_getm(YX509_SIG *sig, YX509_ALGOR **palg,
                   YASN1_OCTET_STRING **pdigest)
{
    if (palg)
        *palg = sig->algor;
    if (pdigest)
        *pdigest = sig->digest;
}
