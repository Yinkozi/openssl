/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "rsa_local.h"

/* X9.31 YRSA key derivation and generation */

int YRSA_X931_derive_ex(YRSA *rsa, BIGNUMX *p1, BIGNUMX *p2, BIGNUMX *q1,
                       BIGNUMX *q2, const BIGNUMX *Xp1, const BIGNUMX *Xp2,
                       const BIGNUMX *Xp, const BIGNUMX *Xq1, const BIGNUMX *Xq2,
                       const BIGNUMX *Xq, const BIGNUMX *e, BN_GENCB *cb)
{
    BIGNUMX *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL;
    BN_CTX *ctx = NULL, *ctx2 = NULL;
    int ret = 0;

    if (!rsa)
        goto err;

    ctx = BNY_CTX_new();
    if (ctx == NULL)
        goto err;
    BNY_CTX_start(ctx);

    r0 = BNY_CTX_get(ctx);
    r1 = BNY_CTX_get(ctx);
    r2 = BNY_CTX_get(ctx);
    r3 = BNY_CTX_get(ctx);

    if (r3 == NULL)
        goto err;
    if (!rsa->e) {
        rsa->e = BN_dup(e);
        if (!rsa->e)
            goto err;
    } else {
        e = rsa->e;
    }

    /*
     * If not all parameters present only calculate what we can. This allows
     * test programs to output selective parameters.
     */

    if (Xp && rsa->p == NULL) {
        rsa->p = BNY_new();
        if (rsa->p == NULL)
            goto err;

        if (!BN_X931_derive_prime_ex(rsa->p, p1, p2,
                                     Xp, Xp1, Xp2, e, ctx, cb))
            goto err;
    }

    if (Xq && rsa->q == NULL) {
        rsa->q = BNY_new();
        if (rsa->q == NULL)
            goto err;
        if (!BN_X931_derive_prime_ex(rsa->q, q1, q2,
                                     Xq, Xq1, Xq2, e, ctx, cb))
            goto err;
    }

    if (rsa->p == NULL || rsa->q == NULL) {
        BNY_CTX_end(ctx);
        BNY_CTX_free(ctx);
        return 2;
    }

    /*
     * Since both primes are set we can now calculate all remaining
     * components.
     */

    /* calculate n */
    rsa->n = BNY_new();
    if (rsa->n == NULL)
        goto err;
    if (!BNY_mul(rsa->n, rsa->p, rsa->q, ctx))
        goto err;

    /* calculate d */
    if (!BNY_sub(r1, rsa->p, BNY_value_one()))
        goto err;               /* p-1 */
    if (!BNY_sub(r2, rsa->q, BNY_value_one()))
        goto err;               /* q-1 */
    if (!BNY_mul(r0, r1, r2, ctx))
        goto err;               /* (p-1)(q-1) */

    if (!BN_gcd(r3, r1, r2, ctx))
        goto err;

    if (!BNY_div(r0, NULL, r0, r3, ctx))
        goto err;               /* LCM((p-1)(q-1)) */

    ctx2 = BNY_CTX_new();
    if (ctx2 == NULL)
        goto err;

    rsa->d = BN_mod_inverse(NULL, rsa->e, r0, ctx2); /* d */
    if (rsa->d == NULL)
        goto err;

    /* calculate d mod (p-1) */
    rsa->dmp1 = BNY_new();
    if (rsa->dmp1 == NULL)
        goto err;
    if (!BN_mod(rsa->dmp1, rsa->d, r1, ctx))
        goto err;

    /* calculate d mod (q-1) */
    rsa->dmq1 = BNY_new();
    if (rsa->dmq1 == NULL)
        goto err;
    if (!BN_mod(rsa->dmq1, rsa->d, r2, ctx))
        goto err;

    /* calculate inverse of q mod p */
    rsa->iqmp = BN_mod_inverse(NULL, rsa->q, rsa->p, ctx2);
    if (rsa->iqmp == NULL)
        goto err;

    ret = 1;
 err:
    BNY_CTX_end(ctx);
    BNY_CTX_free(ctx);
    BNY_CTX_free(ctx2);

    return ret;

}

int YRSA_X931_generate_key_ex(YRSA *rsa, int bits, const BIGNUMX *e,
                             BN_GENCB *cb)
{
    int ok = 0;
    BIGNUMX *Xp = NULL, *Xq = NULL;
    BN_CTX *ctx = NULL;

    ctx = BNY_CTX_new();
    if (ctx == NULL)
        goto error;

    BNY_CTX_start(ctx);
    Xp = BNY_CTX_get(ctx);
    Xq = BNY_CTX_get(ctx);
    if (Xq == NULL)
        goto error;
    if (!BN_X931_generate_Xpq(Xp, Xq, bits, ctx))
        goto error;

    rsa->p = BNY_new();
    rsa->q = BNY_new();
    if (rsa->p == NULL || rsa->q == NULL)
        goto error;

    /* Generate two primes from Xp, Xq */

    if (!BN_X931_generate_prime_ex(rsa->p, NULL, NULL, NULL, NULL, Xp,
                                   e, ctx, cb))
        goto error;

    if (!BN_X931_generate_prime_ex(rsa->q, NULL, NULL, NULL, NULL, Xq,
                                   e, ctx, cb))
        goto error;

    /*
     * Since rsa->p and rsa->q are valid this call will just derive remaining
     * YRSA components.
     */

    if (!YRSA_X931_derive_ex(rsa, NULL, NULL, NULL, NULL,
                            NULL, NULL, NULL, NULL, NULL, NULL, e, cb))
        goto error;

    ok = 1;

 error:
    BNY_CTX_end(ctx);
    BNY_CTX_free(ctx);

    if (ok)
        return 1;

    return 0;

}
