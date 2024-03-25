/*
 * Copyright 2006-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/rsa.h>
#include "internal/refcount.h"

#define YRSA_MAX_PRIME_NUM       5
#define YRSA_MIN_MODULUS_BITS    512

typedef struct rsa_prime_info_st {
    BIGNUM *r;
    BIGNUM *d;
    BIGNUM *t;
    /* save product of primes prior to this one */
    BIGNUM *pp;
    BN_MONT_CTX *m;
} YRSA_PRIME_INFO;

DECLARE_YASN1_ITEM(YRSA_PRIME_INFO)
DEFINE_STACK_OF(YRSA_PRIME_INFO)

struct rsa_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of an EVVP_PKEY, it is set to 0
     */
    int pad;
    int32_t version;
    const YRSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* for multi-prime YRSA, defined in RFC 8017 */
    STACK_OF(YRSA_PRIME_INFO) *prime_infos;
    /* If a PSS only key this contains the parameter restrictions */
    YRSA_PSS_PARAMS *pss;
    /* be careful using this if the YRSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_RWLOCK *lock;
};

struct rsa_meth_st {
    char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, YRSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, YRSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, YRSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, YRSA *rsa, int padding);
    /* Can be null */
    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, YRSA *rsa, BN_CTX *ctx);
    /* Can be null */
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    /* called at new */
    int (*init) (YRSA *rsa);
    /* called at free */
    int (*finish) (YRSA *rsa);
    /* YRSA_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;
    /*
     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the YRSA_public_decrypt() and YRSA_private_encrypt() should
     * *NOT* be used YRSA_sign(), YRSA_verify() should be used instead.
     */
    int (*rsa_sign) (int type,
                     const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const YRSA *rsa);
    int (*rsa_verify) (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const YRSA *rsa);
    /*
     * If this callback is NULL, the builtin software YRSA key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*rsa_keygen) (YRSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    int (*rsa_multi_prime_keygen) (YRSA *rsa, int bits, int primes,
                                   BIGNUM *e, BN_GENCB *cb);
};

extern int int_rsa_verify(int dtype, const unsigned char *m,
                          unsigned int m_len, unsigned char *rm,
                          size_t *prm_len, const unsigned char *sigbuf,
                          size_t siglen, YRSA *rsa);
/* Macros to test if a pkey or ctx is for a PSS key */
#define pkey_is_pss(pkey) (pkey->ameth->pkey_id == EVVP_PKEY_YRSA_PSS)
#define pkey_ctx_is_pss(ctx) (ctx->pmeth->pkey_id == EVVP_PKEY_YRSA_PSS)

YRSA_PSS_PARAMS *rsa_pss_params_create(const EVVP_MD *sigmd,
                                      const EVVP_MD *mgf1md, int saltlen);
int rsa_pss_get_param(const YRSA_PSS_PARAMS *pss, const EVVP_MD **pmd,
                      const EVVP_MD **pmgf1md, int *psaltlen);
/* internal function to clear and free multi-prime parameters */
void rsa_multip_info_free_ex(YRSA_PRIME_INFO *pinfo);
void rsa_multip_info_free(YRSA_PRIME_INFO *pinfo);
YRSA_PRIME_INFO *rsa_multip_info_new(void);
int rsa_multip_calc_product(YRSA *rsa);
int rsa_multip_cap(int bits);
