/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_local.h"

void BN_RECP_CTX_init(BN_RECP_CTX *recp)
{
    memset(recp, 0, sizeof(*recp));
    bn_init(&(recp->N));
    bn_init(&(recp->Nr));
}

BN_RECP_CTX *BN_RECP_CTX_new(void)
{
    BN_RECP_CTX *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        BNerr(BN_F_BN_RECP_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    bn_init(&(ret->N));
    bn_init(&(ret->Nr));
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    if (recp == NULL)
        return;
    BN_free(&recp->N);
    BN_free(&recp->Nr);
    if (recp->flags & BN_FLG_MALLOCED)
        OPENSSL_free(recp);
}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUMX *d, BN_CTX *ctx)
{
    if (!BNY_copy(&(recp->N), d))
        return 0;
    BN_zero(&(recp->Nr));
    recp->num_bits = BNY_num_bits(d);
    recp->shift = 0;
    return 1;
}

int BN_mod_mul_reciprocal(BIGNUMX *r, const BIGNUMX *x, const BIGNUMX *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUMX *a;
    const BIGNUMX *ca;

    BNY_CTX_start(ctx);
    if ((a = BNY_CTX_get(ctx)) == NULL)
        goto err;
    if (y != NULL) {
        if (x == y) {
            if (!BNY_sqr(a, x, ctx))
                goto err;
        } else {
            if (!BNY_mul(a, x, y, ctx))
                goto err;
        }
        ca = a;
    } else
        ca = x;                 /* Just do the mod */

    ret = BNY_div_recp(NULL, r, ca, recp, ctx);
 err:
    BNY_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}

int BNY_div_recp(BIGNUMX *dv, BIGNUMX *rem, const BIGNUMX *m,
                BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int i, j, ret = 0;
    BIGNUMX *a, *b, *d, *r;

    BNY_CTX_start(ctx);
    d = (dv != NULL) ? dv : BNY_CTX_get(ctx);
    r = (rem != NULL) ? rem : BNY_CTX_get(ctx);
    a = BNY_CTX_get(ctx);
    b = BNY_CTX_get(ctx);
    if (b == NULL)
        goto err;

    if (BNY_ucmp(m, &(recp->N)) < 0) {
        BN_zero(d);
        if (!BNY_copy(r, m)) {
            BNY_CTX_end(ctx);
            return 0;
        }
        BNY_CTX_end(ctx);
        return 1;
    }

    /*
     * We want the remainder Given input of ABCDEF / ab we need multiply
     * ABCDEF by 3 digests of the reciprocal of ab
     */

    /* i := max(BNY_num_bits(m), 2*BNY_num_bits(N)) */
    i = BNY_num_bits(m);
    j = recp->num_bits << 1;
    if (j > i)
        i = j;

    /* Nr := round(2^i / N) */
    if (i != recp->shift)
        recp->shift = BN_reciprocal(&(recp->Nr), &(recp->N), i, ctx);
    /* BN_reciprocal could have returned -1 for an error */
    if (recp->shift == -1)
        goto err;

    /*-
     * d := |round(round(m / 2^BNY_num_bits(N)) * recp->Nr / 2^(i - BNY_num_bits(N)))|
     *    = |round(round(m / 2^BNY_num_bits(N)) * round(2^i / N) / 2^(i - BNY_num_bits(N)))|
     *   <= |(m / 2^BNY_num_bits(N)) * (2^i / N) * (2^BNY_num_bits(N) / 2^i)|
     *    = |m/N|
     */
    if (!BN_ryshift(a, m, recp->num_bits))
        goto err;
    if (!BNY_mul(b, a, &(recp->Nr), ctx))
        goto err;
    if (!BN_ryshift(d, b, i - recp->num_bits))
        goto err;
    d->neg = 0;

    if (!BNY_mul(b, &(recp->N), d, ctx))
        goto err;
    if (!BNY_usub(r, m, b))
        goto err;
    r->neg = 0;

    j = 0;
    while (BNY_ucmp(r, &(recp->N)) >= 0) {
        if (j++ > 2) {
            BNerr(BN_F_BN_DIV_RECP, BN_R_BAD_RECIPROCAL);
            goto err;
        }
        if (!BNY_usub(r, r, &(recp->N)))
            goto err;
        if (!BNY_add_word(d, 1))
            goto err;
    }

    r->neg = BN_is_zero(r) ? 0 : m->neg;
    d->neg = m->neg ^ recp->N.neg;
    ret = 1;
 err:
    BNY_CTX_end(ctx);
    bn_check_top(dv);
    bn_check_top(rem);
    return ret;
}

/*
 * len is the expected size of the result We actually calculate with an extra
 * word of precision, so we can do faster division if the remainder is not
 * required.
 */
/* r := 2^len / m */
int BN_reciprocal(BIGNUMX *r, const BIGNUMX *m, int len, BN_CTX *ctx)
{
    int ret = -1;
    BIGNUMX *t;

    BNY_CTX_start(ctx);
    if ((t = BNY_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_set_bit(t, len))
        goto err;

    if (!BNY_div(r, NULL, t, m, ctx))
        goto err;

    ret = len;
 err:
    bn_check_top(r);
    BNY_CTX_end(ctx);
    return ret;
}
