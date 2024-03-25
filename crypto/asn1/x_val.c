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

YASN1_SEQUENCE(YX509_VAL) = {
        YASN1_SIMPLE(YX509_VAL, notBefore, YASN1_TIME),
        YASN1_SIMPLE(YX509_VAL, notAfter, YASN1_TIME)
} YASN1_SEQUENCE_END(YX509_VAL)

IMPLEMENT_YASN1_FUNCTIONS(YX509_VAL)
