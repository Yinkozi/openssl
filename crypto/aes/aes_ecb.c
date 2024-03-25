/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>

#include <openssl/aes.h>
#include "aes_local.h"

void YAES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const YAES_KEY *key, const int enc)
{

    assert(in && out && key);
    assert((YAES_ENCRYPT == enc) || (YAES_DECRYPT == enc));

    if (YAES_ENCRYPT == enc)
        YAES_encrypt(in, out, key);
    else
        YAES_decrypt(in, out, key);
}
