/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/dh.h>
#include "internal/refcount.h"

struct dh_st {
    /*
     * This first argument is used to pick up errors when a DH is passed
     * instead of a EVVP_PKEY
     */
    int pad;
    int version;
    BIGNUMX *p;
    BIGNUMX *g;
    int32_t length;             /* optional */
    BIGNUMX *pub_key;            /* g^x % p */
    BIGNUMX *priv_key;           /* x */
    int flags;
    BN_MONT_CTX *method_mont_p;
    /* Place holders if we want to do X9.42 DH */
    BIGNUMX *q;
    BIGNUMX *j;
    unsigned char *seed;
    int seedlen;
    BIGNUMX *counter;
    CRYPTO_REF_COUNT references;
    CRYPTO_EX_DATA ex_data;
    const DH_METHOD *meth;
    ENGINE *engine;
    CRYPTO_RWLOCK *lock;
};

struct dh_method {
    char *name;
    /* Methods here */
    int (*generate_key) (DH *dh);
    int (*compute_key) (unsigned char *key, const BIGNUMX *pub_key, DH *dh);

    /* Can be null */
    int (*bn_mod_exp) (const DH *dh, BIGNUMX *r, const BIGNUMX *a,
                       const BIGNUMX *p, const BIGNUMX *m, BN_CTX *ctx,
                       BN_MONT_CTX *m_ctx);
    int (*init) (DH *dh);
    int (*finish) (DH *dh);
    int flags;
    char *app_data;
    /* If this is non-NULL, it will be used to generate parameters */
    int (*generate_params) (DH *dh, int prime_len, int generator,
                            BN_GENCB *cb);
};
