/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

YASN1_SEQUENCE(AUTHORITY_KEYID) = {
        YASN1_IMP_OPT(AUTHORITY_KEYID, keyid, YASN1_OCTET_STRING, 0),
        YASN1_IMP_SEQUENCE_OF_OPT(AUTHORITY_KEYID, issuer, GENERAL_NAME, 1),
        YASN1_IMP_OPT(AUTHORITY_KEYID, serial, YASN1_INTEGER, 2)
} YASN1_SEQUENCE_END(AUTHORITY_KEYID)

IMPLEMENT_YASN1_FUNCTIONS(AUTHORITY_KEYID)
