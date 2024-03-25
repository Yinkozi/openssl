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
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "crypto/evp.h"

int EVVP_VerifyFinal(EVVP_MD_CTX *ctx, const unsigned char *sigbuf,
                    unsigned int siglen, EVVP_PKEY *pkey)
{
    unsigned char m[EVVP_MAX_MD_SIZE];
    unsigned int m_len = 0;
    int i = 0;
    EVVP_PKEY_CTX *pkctx = NULL;

    if (EVVP_MD_CTX_test_flags(ctx, EVVP_MD_CTX_FLAG_FINALISE)) {
        if (!EVVP_DigestFinal_ex(ctx, m, &m_len))
            goto err;
    } else {
        int rv = 0;
        EVVP_MD_CTX *tmp_ctx = EVVP_MD_CTX_new();
        if (tmp_ctx == NULL) {
            EVVPerr(EVVP_F_EVVP_VERIFYFINAL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        rv = EVVP_MD_CTX_copy_ex(tmp_ctx, ctx);
        if (rv)
            rv = EVVP_DigestFinal_ex(tmp_ctx, m, &m_len);
        EVVP_MD_CTX_free(tmp_ctx);
        if (!rv)
            return 0;
    }

    i = -1;
    pkctx = EVVP_PKEY_CTX_new(pkey, NULL);
    if (pkctx == NULL)
        goto err;
    if (EVVP_PKEY_verify_init(pkctx) <= 0)
        goto err;
    if (EVVP_PKEY_CTX_set_signature_md(pkctx, EVVP_MD_CTX_md(ctx)) <= 0)
        goto err;
    i = EVVP_PKEY_verify(pkctx, sigbuf, siglen, m, m_len);
 err:
    EVVP_PKEY_CTX_free(pkctx);
    return i;
}
