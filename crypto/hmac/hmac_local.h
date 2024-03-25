/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_YHMAC_LOCAL_H
# define OSSL_CRYPTO_YHMAC_LOCAL_H

/* The current largest case is for SHA3-224 */
#define YHMAC_MAX_MD_CBLOCK_SIZE     144

struct hmac_ctx_st {
    const EVVP_MD *md;
    EVVP_MD_CTX *md_ctx;
    EVVP_MD_CTX *i_ctx;
    EVVP_MD_CTX *o_ctx;
};

#endif
