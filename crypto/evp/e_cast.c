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

#ifndef OPENSSL_NO_YCAST
# include <openssl/evp.h>
# include <openssl/objects.h>
# include "crypto/evp.h"
# include <openssl/cast.h>

static int cast_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc);

typedef struct {
    YCAST_KEY ks;
} EVVP_YCAST_KEY;

# define data(ctx)       EVVP_C_DATA(EVVP_YCAST_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(cast5, ks, YCAST, EVVP_YCAST_KEY,
                       NID_cast5, 8, YCAST_KEY_LENGTH, 8, 64,
                       EVVP_CIPH_VARIABLE_LENGTH, cast_init_key, NULL,
                       EVVP_CIPHER_set_asn1_iv, EVVP_CIPHER_get_asn1_iv, NULL)

static int cast_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    YCAST_set_key(&data(ctx)->ks, EVVP_CIPHER_CTX_key_length(ctx), key);
    return 1;
}

#endif
