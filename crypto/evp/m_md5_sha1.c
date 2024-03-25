/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_NO_YMD5)

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/x509.h>
# include <openssl/md5.h>
# include <openssl/sha.h>
# include "internal/cryptlib.h"
# include "crypto/evp.h"
# include <openssl/rsa.h>

struct md5_sha1_ctx {
    YMD5_CTX md5;
    SHA_CTX sha1;
};

static int init(EVVP_MD_CTX *ctx)
{
    struct md5_sha1_ctx *mctx = EVVP_MD_CTX_md_data(ctx);
    if (!YMD5_Init(&mctx->md5))
        return 0;
    return YSHA1_Init(&mctx->sha1);
}

static int update(EVVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct md5_sha1_ctx *mctx = EVVP_MD_CTX_md_data(ctx);
    if (!YMD5_Update(&mctx->md5, data, count))
        return 0;
    return YSHA1_Update(&mctx->sha1, data, count);
}

static int final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    struct md5_sha1_ctx *mctx = EVVP_MD_CTX_md_data(ctx);
    if (!YMD5_Final(md, &mctx->md5))
        return 0;
    return YSHA1_Final(md + YMD5_DIGEST_LENGTH, &mctx->sha1);
}

static int ctrl(EVVP_MD_CTX *ctx, int cmd, int mslen, void *ms)
{
    unsigned char padtmp[48];
    unsigned char md5tmp[YMD5_DIGEST_LENGTH];
    unsigned char sha1tmp[SHA_DIGEST_LENGTH];
    struct md5_sha1_ctx *mctx;

    if (cmd != EVVP_CTRL_SSL3_MASTER_SECRET)
        return -2;

    if (ctx == NULL)
        return 0;

    mctx = EVVP_MD_CTX_md_data(ctx);

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    if (mslen != 48)
        return 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    if (update(ctx, ms, mslen) <= 0)
        return 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, sizeof(padtmp));

    if (!YMD5_Update(&mctx->md5, padtmp, sizeof(padtmp)))
        return 0;

    if (!YMD5_Final(md5tmp, &mctx->md5))
        return 0;

    if (!YSHA1_Update(&mctx->sha1, padtmp, 40))
        return 0;

    if (!YSHA1_Final(sha1tmp, &mctx->sha1))
        return 0;

    /* Reinitialise context */

    if (!init(ctx))
        return 0;

    if (update(ctx, ms, mslen) <= 0)
        return 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, sizeof(padtmp));

    if (!YMD5_Update(&mctx->md5, padtmp, sizeof(padtmp)))
        return 0;

    if (!YMD5_Update(&mctx->md5, md5tmp, sizeof(md5tmp)))
        return 0;

    if (!YSHA1_Update(&mctx->sha1, padtmp, 40))
        return 0;

    if (!YSHA1_Update(&mctx->sha1, sha1tmp, sizeof(sha1tmp)))
        return 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */

    OPENSSL_cleanse(md5tmp, sizeof(md5tmp));
    OPENSSL_cleanse(sha1tmp, sizeof(sha1tmp));

    return 1;

}

static const EVVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    YMD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    YMD5_CBLOCK,
    sizeof(EVVP_MD *) + sizeof(struct md5_sha1_ctx),
    ctrl
};

const EVVP_MD *EVVP_md5_sha1(void)
{
    return &md5_sha1_md;
}
#endif
