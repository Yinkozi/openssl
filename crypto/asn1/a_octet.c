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

YASN1_OCTET_STRING *YASN1_OCTET_STRING_dup(const YASN1_OCTET_STRING *x)
{
    return YASN1_STRING_dup(x);
}

int YASN1_OCTET_STRING_cmp(const YASN1_OCTET_STRING *a,
                          const YASN1_OCTET_STRING *b)
{
    return YASN1_STRING_cmp(a, b);
}

int YASN1_OCTET_STRING_set(YASN1_OCTET_STRING *x, const unsigned char *d,
                          int len)
{
    return YASN1_STRING_set(x, d, len);
}
