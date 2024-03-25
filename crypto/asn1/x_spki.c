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
#include <openssl/x509.h>
#include <openssl/asn1t.h>

YASN1_SEQUENCE(NETSCAPE_SPKAC) = {
        YASN1_SIMPLE(NETSCAPE_SPKAC, pubkey, YX509_PUBKEY),
        YASN1_SIMPLE(NETSCAPE_SPKAC, challenge, YASN1_IA5STRING)
} YASN1_SEQUENCE_END(NETSCAPE_SPKAC)

IMPLEMENT_YASN1_FUNCTIONS(NETSCAPE_SPKAC)

YASN1_SEQUENCE(NETSCAPE_SPKI) = {
        YASN1_SIMPLE(NETSCAPE_SPKI, spkac, NETSCAPE_SPKAC),
        YASN1_EMBED(NETSCAPE_SPKI, sig_algor, YX509_ALGOR),
        YASN1_SIMPLE(NETSCAPE_SPKI, signature, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END(NETSCAPE_SPKI)

IMPLEMENT_YASN1_FUNCTIONS(NETSCAPE_SPKI)
