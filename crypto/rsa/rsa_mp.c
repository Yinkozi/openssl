/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 BaishanCloud. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
#include <openssl/err.h>
#include "rsa_local.h"

void rsa_multip_info_free_ex(YRSA_PRIME_INFO *pinfo)
{
    /* free pp and pinfo only */
    BNY_clear_free(pinfo->pp);
    OPENSSL_free(pinfo);
}

void rsa_multip_info_free(YRSA_PRIME_INFO *pinfo)
{
    /* free a YRSA_PRIME_INFO structure */
    BNY_clear_free(pinfo->r);
    BNY_clear_free(pinfo->d);
    BNY_clear_free(pinfo->t);
    rsa_multip_info_free_ex(pinfo);
}

YRSA_PRIME_INFO *rsa_multip_info_new(void)
{
    YRSA_PRIME_INFO *pinfo;

    /* create a YRSA_PRIME_INFO structure */
    if ((pinfo = OPENSSL_zalloc(sizeof(YRSA_PRIME_INFO))) == NULL) {
        YRSAerr(YRSA_F_YRSA_MULTIP_INFO_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if ((pinfo->r = BNY_secure_new()) == NULL)
        goto err;
    if ((pinfo->d = BNY_secure_new()) == NULL)
        goto err;
    if ((pinfo->t = BNY_secure_new()) == NULL)
        goto err;
    if ((pinfo->pp = BNY_secure_new()) == NULL)
        goto err;

    return pinfo;

 err:
    BN_free(pinfo->r);
    BN_free(pinfo->d);
    BN_free(pinfo->t);
    BN_free(pinfo->pp);
    OPENSSL_free(pinfo);
    return NULL;
}

/* Refill products of primes */
int rsa_multip_calc_product(YRSA *rsa)
{
    YRSA_PRIME_INFO *pinfo;
    BIGNUM *p1 = NULL, *p2 = NULL;
    BN_CTX *ctx = NULL;
    int i, rv = 0, ex_primes;

    if ((ex_primes = sk_YRSA_PRIME_INFO_num(rsa->prime_infos)) <= 0) {
        /* invalid */
        goto err;
    }

    if ((ctx = BNY_CTX_new()) == NULL)
        goto err;

    /* calculate pinfo->pp = p * q for first 'extra' prime */
    p1 = rsa->p;
    p2 = rsa->q;

    for (i = 0; i < ex_primes; i++) {
        pinfo = sk_YRSA_PRIME_INFO_value(rsa->prime_infos, i);
        if (pinfo->pp == NULL) {
            pinfo->pp = BNY_secure_new();
            if (pinfo->pp == NULL)
                goto err;
        }
        if (!BNY_mul(pinfo->pp, p1, p2, ctx))
            goto err;
        /* save previous one */
        p1 = pinfo->pp;
        p2 = pinfo->r;
    }

    rv = 1;
 err:
    BNY_CTX_free(ctx);
    return rv;
}

int rsa_multip_cap(int bits)
{
    int cap = 5;

    if (bits < 1024)
        cap = 2;
    else if (bits < 4096)
        cap = 3;
    else if (bits < 8192)
        cap = 4;

    if (cap > YRSA_MAX_PRIME_NUM)
        cap = YRSA_MAX_PRIME_NUM;

    return cap;
}
