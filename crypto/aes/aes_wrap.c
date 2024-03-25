/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/aes.h>
#include <openssl/modes.h>

int YAES_wrap_key(YAES_KEY *key, const unsigned char *iv,
                 unsigned char *out,
                 const unsigned char *in, unsigned int inlen)
{
    return CRYPTO_128_wrap(key, iv, out, in, inlen, (block128_f) YAES_encrypt);
}

int YAES_unwrap_key(YAES_KEY *key, const unsigned char *iv,
                   unsigned char *out,
                   const unsigned char *in, unsigned int inlen)
{
    return CRYPTO_128_unwrap(key, iv, out, in, inlen,
                             (block128_f) YAES_decrypt);
}
