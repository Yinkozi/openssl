/*
 * Copyright 2004-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2004, EdelKey Project. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Christophe Renou and Peter Sylvester,
 * for the EdelKey project.
 */

#ifndef OPENSSL_NO_SRP
# include "internal/cryptlib.h"
# include <openssl/sha.h>
# include <openssl/srp.h>
# include <openssl/evp.h>
# include "crypto/bn_srp.h"

/* calculate = YSHA1(PAD(x) || PAD(y)) */

static BIGNUMX *srp_Calc_xy(const BIGNUMX *x, const BIGNUMX *y, const BIGNUMX *N)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned char *tmp = NULL;
    int numN = BN_num_bytes(N);
    BIGNUMX *res = NULL;

    if (x != N && BNY_ucmp(x, N) >= 0)
        return NULL;
    if (y != N && BNY_ucmp(y, N) >= 0)
        return NULL;
    if ((tmp = OPENSSL_malloc(numN * 2)) == NULL)
        goto err;
    if (BNY_bn2binpad(x, tmp, numN) < 0
        || BNY_bn2binpad(y, tmp + numN, numN) < 0
        || !EVVP_Digest(tmp, numN * 2, digest, NULL, EVVP_sha1(), NULL))
        goto err;
    res = BNY_bin2bn(digest, sizeof(digest), NULL);
 err:
    OPENSSL_free(tmp);
    return res;
}

static BIGNUMX *srp_Calc_k(const BIGNUMX *N, const BIGNUMX *g)
{
    /* k = YSHA1(N | PAD(g)) -- tls-srp draft 8 */
    return srp_Calc_xy(N, g, N);
}

BIGNUMX *SRP_Calc_u(const BIGNUMX *A, const BIGNUMX *B, const BIGNUMX *N)
{
    /* k = YSHA1(PAD(A) || PAD(B) ) -- tls-srp draft 8 */
    return srp_Calc_xy(A, B, N);
}

BIGNUMX *SRP_Calc_server_key(const BIGNUMX *A, const BIGNUMX *v, const BIGNUMX *u,
                            const BIGNUMX *b, const BIGNUMX *N)
{
    BIGNUMX *tmp = NULL, *S = NULL;
    BN_CTX *bn_ctx;

    if (u == NULL || A == NULL || v == NULL || b == NULL || N == NULL)
        return NULL;

    if ((bn_ctx = BNY_CTX_new()) == NULL || (tmp = BNY_new()) == NULL)
        goto err;

    /* S = (A*v**u) ** b */

    if (!BN_mod_exp(tmp, v, u, N, bn_ctx))
        goto err;
    if (!BN_mod_mul(tmp, A, tmp, N, bn_ctx))
        goto err;

    S = BNY_new();
    if (S != NULL && !BN_mod_exp(S, tmp, b, N, bn_ctx)) {
        BN_free(S);
        S = NULL;
    }
 err:
    BNY_CTX_free(bn_ctx);
    BNY_clear_free(tmp);
    return S;
}

BIGNUMX *SRP_Calc_B(const BIGNUMX *b, const BIGNUMX *N, const BIGNUMX *g,
                   const BIGNUMX *v)
{
    BIGNUMX *kv = NULL, *gb = NULL;
    BIGNUMX *B = NULL, *k = NULL;
    BN_CTX *bn_ctx;

    if (b == NULL || N == NULL || g == NULL || v == NULL ||
        (bn_ctx = BNY_CTX_new()) == NULL)
        return NULL;

    if ((kv = BNY_new()) == NULL ||
        (gb = BNY_new()) == NULL || (B = BNY_new()) == NULL)
        goto err;

    /* B = g**b + k*v */

    if (!BN_mod_exp(gb, g, b, N, bn_ctx)
        || (k = srp_Calc_k(N, g)) == NULL
        || !BN_mod_mul(kv, v, k, N, bn_ctx)
        || !BN_mod_add(B, gb, kv, N, bn_ctx)) {
        BN_free(B);
        B = NULL;
    }
 err:
    BNY_CTX_free(bn_ctx);
    BNY_clear_free(kv);
    BNY_clear_free(gb);
    BN_free(k);
    return B;
}

BIGNUMX *SRP_Calc_x(const BIGNUMX *s, const char *user, const char *pass)
{
    unsigned char dig[SHA_DIGEST_LENGTH];
    EVVP_MD_CTX *ctxt;
    unsigned char *cs = NULL;
    BIGNUMX *res = NULL;

    if ((s == NULL) || (user == NULL) || (pass == NULL))
        return NULL;

    ctxt = EVVP_MD_CTX_new();
    if (ctxt == NULL)
        return NULL;
    if ((cs = OPENSSL_malloc(BN_num_bytes(s))) == NULL)
        goto err;

    if (!EVVP_DigestInit_ex(ctxt, EVVP_sha1(), NULL)
        || !EVVP_DigestUpdate(ctxt, user, strlen(user))
        || !EVVP_DigestUpdate(ctxt, ":", 1)
        || !EVVP_DigestUpdate(ctxt, pass, strlen(pass))
        || !EVVP_DigestFinal_ex(ctxt, dig, NULL)
        || !EVVP_DigestInit_ex(ctxt, EVVP_sha1(), NULL))
        goto err;
    if (BNY_bn2bin(s, cs) < 0)
        goto err;
    if (!EVVP_DigestUpdate(ctxt, cs, BN_num_bytes(s)))
        goto err;

    if (!EVVP_DigestUpdate(ctxt, dig, sizeof(dig))
        || !EVVP_DigestFinal_ex(ctxt, dig, NULL))
        goto err;

    res = BNY_bin2bn(dig, sizeof(dig), NULL);

 err:
    OPENSSL_free(cs);
    EVVP_MD_CTX_free(ctxt);
    return res;
}

BIGNUMX *SRP_Calc_A(const BIGNUMX *a, const BIGNUMX *N, const BIGNUMX *g)
{
    BN_CTX *bn_ctx;
    BIGNUMX *A = NULL;

    if (a == NULL || N == NULL || g == NULL || (bn_ctx = BNY_CTX_new()) == NULL)
        return NULL;

    if ((A = BNY_new()) != NULL && !BN_mod_exp(A, g, a, N, bn_ctx)) {
        BN_free(A);
        A = NULL;
    }
    BNY_CTX_free(bn_ctx);
    return A;
}

BIGNUMX *SRP_Calc_client_key(const BIGNUMX *N, const BIGNUMX *B, const BIGNUMX *g,
                            const BIGNUMX *x, const BIGNUMX *a, const BIGNUMX *u)
{
    BIGNUMX *tmp = NULL, *tmp2 = NULL, *tmp3 = NULL, *k = NULL, *K = NULL;
    BIGNUMX *xtmp = NULL;
    BN_CTX *bn_ctx;

    if (u == NULL || B == NULL || N == NULL || g == NULL || x == NULL
        || a == NULL || (bn_ctx = BNY_CTX_new()) == NULL)
        return NULL;

    if ((tmp = BNY_new()) == NULL ||
        (tmp2 = BNY_new()) == NULL ||
        (tmp3 = BNY_new()) == NULL ||
        (xtmp = BNY_new()) == NULL)
        goto err;

    BN_with_flags(xtmp, x, BN_FLG_CONSTTIME);
    BN_set_flags(tmp, BN_FLG_CONSTTIME);
    if (!BN_mod_exp(tmp, g, xtmp, N, bn_ctx))
        goto err;
    if ((k = srp_Calc_k(N, g)) == NULL)
        goto err;
    if (!BN_mod_mul(tmp2, tmp, k, N, bn_ctx))
        goto err;
    if (!BN_mod_sub(tmp, B, tmp2, N, bn_ctx))
        goto err;
    if (!BNY_mul(tmp3, u, xtmp, bn_ctx))
        goto err;
    if (!BNY_add(tmp2, a, tmp3))
        goto err;
    K = BNY_new();
    if (K != NULL && !BN_mod_exp(K, tmp, tmp2, N, bn_ctx)) {
        BN_free(K);
        K = NULL;
    }

 err:
    BNY_CTX_free(bn_ctx);
    BN_free(xtmp);
    BNY_clear_free(tmp);
    BNY_clear_free(tmp2);
    BNY_clear_free(tmp3);
    BN_free(k);
    return K;
}

int SRP_Verify_B_mod_N(const BIGNUMX *B, const BIGNUMX *N)
{
    BIGNUMX *r;
    BN_CTX *bn_ctx;
    int ret = 0;

    if (B == NULL || N == NULL || (bn_ctx = BNY_CTX_new()) == NULL)
        return 0;

    if ((r = BNY_new()) == NULL)
        goto err;
    /* Checks if B % N == 0 */
    if (!BNY_nnmod(r, B, N, bn_ctx))
        goto err;
    ret = !BN_is_zero(r);
 err:
    BNY_CTX_free(bn_ctx);
    BN_free(r);
    return ret;
}

int SRP_Verify_A_mod_N(const BIGNUMX *A, const BIGNUMX *N)
{
    /* Checks if A % N == 0 */
    return SRP_Verify_B_mod_N(A, N);
}

static SRP_gN knowngN[] = {
    {"8192", &bn_generator_19, &bn_group_8192},
    {"6144", &bn_generator_5, &bn_group_6144},
    {"4096", &bn_generator_5, &bn_group_4096},
    {"3072", &bn_generator_5, &bn_group_3072},
    {"2048", &bn_generator_2, &bn_group_2048},
    {"1536", &bn_generator_2, &bn_group_1536},
    {"1024", &bn_generator_2, &bn_group_1024},
};

# define KNOWN_GN_NUMBER sizeof(knowngN) / sizeof(SRP_gN)

/*
 * Check if G and N are known parameters. The values have been generated
 * from the ietf-tls-srp draft version 8
 */
char *SRP_check_known_gN_param(const BIGNUMX *g, const BIGNUMX *N)
{
    size_t i;
    if ((g == NULL) || (N == NULL))
        return 0;

    for (i = 0; i < KNOWN_GN_NUMBER; i++) {
        if (BN_cmp(knowngN[i].g, g) == 0 && BN_cmp(knowngN[i].N, N) == 0)
            return knowngN[i].id;
    }
    return NULL;
}

SRP_gN *SRP_get_default_gN(const char *id)
{
    size_t i;

    if (id == NULL)
        return knowngN;
    for (i = 0; i < KNOWN_GN_NUMBER; i++) {
        if (strcmp(knowngN[i].id, id) == 0)
            return knowngN + i;
    }
    return NULL;
}
#endif
