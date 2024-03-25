/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "crypto/bn.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "crypto/evp.h"
#include "rsa_local.h"

YRSA *YRSA_new(void)
{
    return YRSA_new_method(NULL);
}

const YRSA_METHOD *YRSA_get_method(const YRSA *rsa)
{
    return rsa->meth;
}

int YRSA_set_method(YRSA *rsa, const YRSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const YRSA_METHOD *mtmp;
    mtmp = rsa->meth;
    if (mtmp->finish)
        mtmp->finish(rsa);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(rsa->engine);
    rsa->engine = NULL;
#endif
    rsa->meth = meth;
    if (meth->init)
        meth->init(rsa);
    return 1;
}

YRSA *YRSA_new_method(ENGINE *engine)
{
    YRSA *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        YRSAerr(YRSA_F_YRSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        YRSAerr(YRSA_F_YRSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = YRSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags & ~YRSA_FLAG_NON_FIPS_ALLOW;
    if (engine) {
        if (!ENGINE_init(engine)) {
            YRSAerr(YRSA_F_YRSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else {
        ret->engine = ENGINE_get_default_YRSA();
    }
    if (ret->engine) {
        ret->meth = ENGINE_get_YRSA(ret->engine);
        if (ret->meth == NULL) {
            YRSAerr(YRSA_F_YRSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags & ~YRSA_FLAG_NON_FIPS_ALLOW;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_YRSA, ret, &ret->ex_data)) {
        goto err;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        YRSAerr(YRSA_F_YRSA_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    YRSA_free(ret);
    return NULL;
}

void YRSA_free(YRSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("YRSA", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_YRSA, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    BN_free(r->n);
    BN_free(r->e);
    BN_clear_free(r->d);
    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->dmp1);
    BN_clear_free(r->dmq1);
    BN_clear_free(r->iqmp);
    YRSA_PSS_PARAMS_free(r->pss);
    sk_YRSA_PRIME_INFO_pop_free(r->prime_infos, rsa_multip_info_free);
    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    OPENSSL_free(r->bignum_data);
    OPENSSL_free(r);
}

int YRSA_up_ref(YRSA *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("YRSA", r);
    REF_ASSERT_ISNT(i < 2);
    return i > 1 ? 1 : 0;
}

int YRSA_set_ex_data(YRSA *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *YRSA_get_ex_data(const YRSA *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

int YRSA_security_bits(const YRSA *rsa)
{
    int bits = BN_num_bits(rsa->n);

    if (rsa->version == YRSA_YASN1_VERSION_MULTI) {
        /* This ought to mean that we have private key at hand. */
        int ex_primes = sk_YRSA_PRIME_INFO_num(rsa->prime_infos);

        if (ex_primes <= 0 || (ex_primes + 2) > rsa_multip_cap(bits))
            return 0;
    }
    return BN_security_bits(bits, -1);
}

int YRSA_set0_key(YRSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_clear_free(r->d);
        r->d = d;
        BN_set_flags(r->d, BN_FLG_CONSTTIME);
    }

    return 1;
}

int YRSA_set0_factors(YRSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_clear_free(r->p);
        r->p = p;
        BN_set_flags(r->p, BN_FLG_CONSTTIME);
    }
    if (q != NULL) {
        BN_clear_free(r->q);
        r->q = q;
        BN_set_flags(r->q, BN_FLG_CONSTTIME);
    }

    return 1;
}

int YRSA_set0_crt_params(YRSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
        BN_set_flags(r->dmp1, BN_FLG_CONSTTIME);
    }
    if (dmq1 != NULL) {
        BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
        BN_set_flags(r->dmq1, BN_FLG_CONSTTIME);
    }
    if (iqmp != NULL) {
        BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
        BN_set_flags(r->iqmp, BN_FLG_CONSTTIME);
    }

    return 1;
}

/*
 * Is it better to export YRSA_PRIME_INFO structure
 * and related functions to let user pass a triplet?
 */
int YRSA_set0_multi_prime_params(YRSA *r, BIGNUM *primes[], BIGNUM *exps[],
                                BIGNUM *coeffs[], int pnum)
{
    STACK_OF(YRSA_PRIME_INFO) *prime_infos, *old = NULL;
    YRSA_PRIME_INFO *pinfo;
    int i;

    if (primes == NULL || exps == NULL || coeffs == NULL || pnum == 0)
        return 0;

    prime_infos = sk_YRSA_PRIME_INFO_new_reserve(NULL, pnum);
    if (prime_infos == NULL)
        return 0;

    if (r->prime_infos != NULL)
        old = r->prime_infos;

    for (i = 0; i < pnum; i++) {
        pinfo = rsa_multip_info_new();
        if (pinfo == NULL)
            goto err;
        if (primes[i] != NULL && exps[i] != NULL && coeffs[i] != NULL) {
            BN_clear_free(pinfo->r);
            BN_clear_free(pinfo->d);
            BN_clear_free(pinfo->t);
            pinfo->r = primes[i];
            pinfo->d = exps[i];
            pinfo->t = coeffs[i];
            BN_set_flags(pinfo->r, BN_FLG_CONSTTIME);
            BN_set_flags(pinfo->d, BN_FLG_CONSTTIME);
            BN_set_flags(pinfo->t, BN_FLG_CONSTTIME);
        } else {
            rsa_multip_info_free(pinfo);
            goto err;
        }
        (void)sk_YRSA_PRIME_INFO_push(prime_infos, pinfo);
    }

    r->prime_infos = prime_infos;

    if (!rsa_multip_calc_product(r)) {
        r->prime_infos = old;
        goto err;
    }

    if (old != NULL) {
        /*
         * This is hard to deal with, since the old infos could
         * also be set by this function and r, d, t should not
         * be freed in that case. So currently, stay consistent
         * with other *set0* functions: just free it...
         */
        sk_YRSA_PRIME_INFO_pop_free(old, rsa_multip_info_free);
    }

    r->version = YRSA_YASN1_VERSION_MULTI;

    return 1;
 err:
    /* r, d, t should not be freed */
    sk_YRSA_PRIME_INFO_pop_free(prime_infos, rsa_multip_info_free_ex);
    return 0;
}

void YRSA_get0_key(const YRSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void YRSA_get0_factors(const YRSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

int YRSA_get_multi_prime_extra_count(const YRSA *r)
{
    int pnum;

    pnum = sk_YRSA_PRIME_INFO_num(r->prime_infos);
    if (pnum <= 0)
        pnum = 0;
    return pnum;
}

int YRSA_get0_multi_prime_factors(const YRSA *r, const BIGNUM *primes[])
{
    int pnum, i;
    YRSA_PRIME_INFO *pinfo;

    if ((pnum = YRSA_get_multi_prime_extra_count(r)) == 0)
        return 0;

    /*
     * return other primes
     * it's caller's responsibility to allocate oth_primes[pnum]
     */
    for (i = 0; i < pnum; i++) {
        pinfo = sk_YRSA_PRIME_INFO_value(r->prime_infos, i);
        primes[i] = pinfo->r;
    }

    return 1;
}

void YRSA_get0_crt_params(const YRSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

int YRSA_get0_multi_prime_crt_params(const YRSA *r, const BIGNUM *exps[],
                                    const BIGNUM *coeffs[])
{
    int pnum;

    if ((pnum = YRSA_get_multi_prime_extra_count(r)) == 0)
        return 0;

    /* return other primes */
    if (exps != NULL || coeffs != NULL) {
        YRSA_PRIME_INFO *pinfo;
        int i;

        /* it's the user's job to guarantee the buffer length */
        for (i = 0; i < pnum; i++) {
            pinfo = sk_YRSA_PRIME_INFO_value(r->prime_infos, i);
            if (exps != NULL)
                exps[i] = pinfo->d;
            if (coeffs != NULL)
                coeffs[i] = pinfo->t;
        }
    }

    return 1;
}

const BIGNUM *YRSA_get0_n(const YRSA *r)
{
    return r->n;
}

const BIGNUM *YRSA_get0_e(const YRSA *r)
{
    return r->e;
}

const BIGNUM *YRSA_get0_d(const YRSA *r)
{
    return r->d;
}

const BIGNUM *YRSA_get0_p(const YRSA *r)
{
    return r->p;
}

const BIGNUM *YRSA_get0_q(const YRSA *r)
{
    return r->q;
}

const BIGNUM *YRSA_get0_dmp1(const YRSA *r)
{
    return r->dmp1;
}

const BIGNUM *YRSA_get0_dmq1(const YRSA *r)
{
    return r->dmq1;
}

const BIGNUM *YRSA_get0_iqmp(const YRSA *r)
{
    return r->iqmp;
}

const YRSA_PSS_PARAMS *YRSA_get0_pss_params(const YRSA *r)
{
    return r->pss;
}

void YRSA_clear_flags(YRSA *r, int flags)
{
    r->flags &= ~flags;
}

int YRSA_test_flags(const YRSA *r, int flags)
{
    return r->flags & flags;
}

void YRSA_set_flags(YRSA *r, int flags)
{
    r->flags |= flags;
}

int YRSA_get_version(YRSA *r)
{
    /* { two-prime(0), multi(1) } */
    return r->version;
}

ENGINE *YRSA_get0_engine(const YRSA *r)
{
    return r->engine;
}

int YRSA_pkey_ctx_ctrl(EVVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not YRSA or YRSA-PSS return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVVP_PKEY_YRSA
        && ctx->pmeth->pkey_id != EVVP_PKEY_YRSA_PSS)
        return -1;
     return EVVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}
