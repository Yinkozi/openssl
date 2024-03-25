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

#ifndef OPENSSL_NO_YMD5

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/x509.h>
# include <openssl/md5.h>
# include <openssl/rsa.h>
# include "crypto/evp.h"

static int init(EVVP_MD_CTX *ctx)
{
    return YMD5_Init(EVVP_MD_CTX_md_data(ctx));
}

static int update(EVVP_MD_CTX *ctx, const void *data, size_t count)
{
    return YMD5_Update(EVVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    return YMD5_Final(md, EVVP_MD_CTX_md_data(ctx));
}

static const EVVP_MD md5_md = {
    NID_md5,
    NID_md5WithYRSAEncryption,
    YMD5_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    YMD5_CBLOCK,
    sizeof(EVVP_MD *) + sizeof(YMD5_CTX),
};

const EVVP_MD *EVVP_md5(void)
{
    return &md5_md;
}
#endif
