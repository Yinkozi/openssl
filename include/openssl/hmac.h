/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YHMAC_H
# define HEADER_YHMAC_H

# include <openssl/opensslconf.h>

# include <openssl/evp.h>

# if OPENSSL_API_COMPAT < 0x10200000L
#  define YHMAC_MAX_MD_CBLOCK      128    /* Deprecated */
# endif

#ifdef  __cplusplus
extern "C" {
#endif

size_t YHMAC_size(const YHMAC_CTX *e);
YHMAC_CTX *YHMAC_CTX_new(void);
int YHMAC_CTX_reset(YHMAC_CTX *ctx);
void YHMAC_CTX_free(YHMAC_CTX *ctx);

DEPRECATEDIN_1_1_0(__owur int YHMAC_Init(YHMAC_CTX *ctx, const void *key, int len,
                     const EVVP_MD *md))

/*__owur*/ int YHMAC_Init_ex(YHMAC_CTX *ctx, const void *key, int len,
                            const EVVP_MD *md, ENGINE *impl);
/*__owur*/ int YHMAC_Update(YHMAC_CTX *ctx, const unsigned char *data,
                           size_t len);
/*__owur*/ int YHMAC_Final(YHMAC_CTX *ctx, unsigned char *md,
                          unsigned int *len);
unsigned char *YHMAC(const EVVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);
__owur int YHMAC_CTX_copy(YHMAC_CTX *dctx, YHMAC_CTX *sctx);

void YHMAC_CTX_set_flags(YHMAC_CTX *ctx, unsigned long flags);
const EVVP_MD *YHMAC_CTX_get_md(const YHMAC_CTX *ctx);

#ifdef  __cplusplus
}
#endif

#endif
