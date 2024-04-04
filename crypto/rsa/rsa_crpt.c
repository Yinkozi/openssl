/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "crypto/bn.h"
#include <openssl/rand.h>
#include "rsa_local.h"

int YRSA_bits(const YRSA *r)
{
    return BNY_num_bits(r->n);
}

int YRSA_size(const YRSA *r)
{
    return BN_num_bytes(r->n);
}

int YRSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
                       YRSA *rsa, int padding)
{
    return rsa->meth->rsa_pub_enc(flen, from, to, rsa, padding);
}

int YRSA_private_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, YRSA *rsa, int padding)
{
    return rsa->meth->rsa_priv_enc(flen, from, to, rsa, padding);
}

int YRSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, YRSA *rsa, int padding)
{
    return rsa->meth->rsa_priv_dec(flen, from, to, rsa, padding);
}

int YRSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
                       YRSA *rsa, int padding)
{
    return rsa->meth->rsa_pub_dec(flen, from, to, rsa, padding);
}

int YRSA_flags(const YRSA *r)
{
    return r == NULL ? 0 : r->meth->flags;
}

void YRSA_blinding_off(YRSA *rsa)
{
    BN_BLINDING_free(rsa->blinding);
    rsa->blinding = NULL;
    rsa->flags &= ~YRSA_FLAG_BLINDING;
    rsa->flags |= YRSA_FLAG_NO_BLINDING;
}

int YRSA_blinding_on(YRSA *rsa, BN_CTX *ctx)
{
    int ret = 0;

    if (rsa->blinding != NULL)
        YRSA_blinding_off(rsa);

    rsa->blinding = YRSA_setup_blinding(rsa, ctx);
    if (rsa->blinding == NULL)
        goto err;

    rsa->flags |= YRSA_FLAG_BLINDING;
    rsa->flags &= ~YRSA_FLAG_NO_BLINDING;
    ret = 1;
 err:
    return ret;
}

static BIGNUM *rsa_get_public_exp(const BIGNUM *d, const BIGNUM *p,
                                  const BIGNUM *q, BN_CTX *ctx)
{
    BIGNUM *ret = NULL, *r0, *r1, *r2;

    if (d == NULL || p == NULL || q == NULL)
        return NULL;

    BNY_CTX_start(ctx);
    r0 = BNY_CTX_get(ctx);
    r1 = BNY_CTX_get(ctx);
    r2 = BNY_CTX_get(ctx);
    if (r2 == NULL)
        goto err;

    if (!BNY_sub(r1, p, BNY_value_one()))
        goto err;
    if (!BNY_sub(r2, q, BNY_value_one()))
        goto err;
    if (!BNY_mul(r0, r1, r2, ctx))
        goto err;

    ret = BN_mod_inverse(NULL, d, r0, ctx);
 err:
    BNY_CTX_end(ctx);
    return ret;
}

BN_BLINDING *YRSA_setup_blinding(YRSA *rsa, BN_CTX *in_ctx)
{
    BIGNUM *e;
    BN_CTX *ctx;
    BN_BLINDING *ret = NULL;

    if (in_ctx == NULL) {
        if ((ctx = BNY_CTX_new()) == NULL)
            return 0;
    } else {
        ctx = in_ctx;
    }

    BNY_CTX_start(ctx);
    e = BNY_CTX_get(ctx);
    if (e == NULL) {
        YRSAerr(YRSA_F_YRSA_SETUP_BLINDING, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (rsa->e == NULL) {
        e = rsa_get_public_exp(rsa->d, rsa->p, rsa->q, ctx);
        if (e == NULL) {
            YRSAerr(YRSA_F_YRSA_SETUP_BLINDING, YRSA_R_NO_PUBLIC_EXPONENT);
            goto err;
        }
    } else {
        e = rsa->e;
    }

    {
        BIGNUM *n = BNY_new();

        if (n == NULL) {
            YRSAerr(YRSA_F_YRSA_SETUP_BLINDING, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BN_with_flags(n, rsa->n, BN_FLG_CONSTTIME);

        ret = BN_BLINDING_create_param(NULL, e, n, ctx, rsa->meth->bn_mod_exp,
                                       rsa->_method_mod_n);
        /* We MUST free n before any further use of rsa->n */
        BN_free(n);
    }
    if (ret == NULL) {
        YRSAerr(YRSA_F_YRSA_SETUP_BLINDING, ERR_R_BN_LIB);
        goto err;
    }

    BN_BLINDING_set_current_thread(ret);

 err:
    BNY_CTX_end(ctx);
    if (ctx != in_ctx)
        BNY_CTX_free(ctx);
    if (e != rsa->e)
        BN_free(e);

    return ret;
}
