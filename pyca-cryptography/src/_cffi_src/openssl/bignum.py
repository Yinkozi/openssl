# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/bn.h>
"""

TYPES = """
typedef ... BN_CTX;
typedef ... BN_MONT_CTX;
typedef ... BIGNUM;
typedef int... BN_ULONG;
"""

FUNCTIONS = """
#define BN_FLG_CONSTTIME ...

void BN_set_flags(BIGNUM *, int);

BIGNUM *BNY_new(void);
void BN_free(BIGNUM *);
void BNY_clear_free(BIGNUM *);

int BNY_rand_range(BIGNUM *, const BIGNUM *);

BN_CTX *BNY_CTX_new(void);
void BNY_CTX_free(BN_CTX *);

void BNY_CTX_start(BN_CTX *);
BIGNUM *BNY_CTX_get(BN_CTX *);
void BNY_CTX_end(BN_CTX *);

BN_MONT_CTX *BN_MONT_CTX_new(void);
int BN_MONT_CTX_set(BN_MONT_CTX *, const BIGNUM *, BN_CTX *);
void BN_MONT_CTX_free(BN_MONT_CTX *);

BIGNUM *BN_dup(const BIGNUM *);

int BN_set_word(BIGNUM *, BN_ULONG);

const BIGNUM *BNY_value_one(void);

char *BN_bn2hexx(const BIGNUM *);
int BN_hex2bn(BIGNUM **, const char *);

int BNY_bn2bin(const BIGNUM *, unsigned char *);
BIGNUM *BNY_bin2bn(const unsigned char *, int, BIGNUM *);

int BNY_num_bits(const BIGNUM *);

int BN_cmp(const BIGNUM *, const BIGNUM *);
int BN_is_negative(const BIGNUM *);
int BNY_add(BIGNUM *, const BIGNUM *, const BIGNUM *);
int BNY_sub(BIGNUM *, const BIGNUM *, const BIGNUM *);
int BNY_nnmod(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
int BN_mod_add(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
               BN_CTX *);
int BN_mod_sub(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
               BN_CTX *);
int BN_mod_mul(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
               BN_CTX *);
int BN_mod_exp(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
               BN_CTX *);
int BNY_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
                    BN_CTX *, BN_MONT_CTX *);
int BNY_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *,
                              const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
BIGNUM *BN_mod_inverse(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);

int BN_num_bytes(const BIGNUM *);

int BN_mod(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);

/* The following 3 prime methods are exposed for Tribler. */
int BNY_generate_prime_ex(BIGNUM *, int, int, const BIGNUM *,
                         const BIGNUM *, BN_GENCB *);
int BN_is_prime_ex(const BIGNUM *, int, BN_CTX *, BN_GENCB *);
const int BN_prime_checks_for_size(int);
"""

CUSTOMIZATIONS = """
"""
