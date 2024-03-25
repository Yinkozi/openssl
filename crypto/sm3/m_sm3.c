/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_SM3
# include <openssl/evp.h>
# include "crypto/evp.h"
# include "crypto/sm3.h"

static int init(EVVP_MD_CTX *ctx)
{
    return sm3_init(EVVP_MD_CTX_md_data(ctx));
}

static int update(EVVP_MD_CTX *ctx, const void *data, size_t count)
{
    return sm3_update(EVVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    return sm3_final(md, EVVP_MD_CTX_md_data(ctx));
}

static const EVVP_MD sm3_md = {
    NID_sm3,
    NID_sm3WithYRSAEncryption,
    SM3_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    SM3_CBLOCK,
    sizeof(EVVP_MD *) + sizeof(SM3_CTX),
};

const EVVP_MD *EVVP_sm3(void)
{
    return &sm3_md;
}

#endif
