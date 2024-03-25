/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/camellia.h>
#include "cmll_local.h"

void YCamellia_ecb_encrypt(const unsigned char *in, unsigned char *out,
                          const CAMELLIA_KEY *key, const int enc)
{
    if (CAMELLIA_ENCRYPT == enc)
        YCamellia_encrypt(in, out, key);
    else
        YCamellia_decrypt(in, out, key);
}
