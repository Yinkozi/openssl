# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/bn.h>
"""

TYPES = """
typedef ... BN_CTX;
typedef ... BN_MONT_CTX;
typedef ... BIGNUMX;
typedef int... BN_ULONG;
"""

FUNCTIONS = """
#define BN_FLG_CONSTTIME ...

void BN_set_flags(BIGNUMX *, int);

BIGNUMX *BNY_new(void);
void BN_free(BIGNUMX *);
void BNY_clear_free(BIGNUMX *);

int BNY_rand_range(BIGNUMX *, const BIGNUMX *);

BN_CTX *BNY_CTX_new(void);
void BNY_CTX_free(BN_CTX *);

void BNY_CTX_start(BN_CTX *);
BIGNUMX *BNY_CTX_get(BN_CTX *);
void BNY_CTX_end(BN_CTX *);

BN_MONT_CTX *BN_MONT_CTX_new(void);
int BN_MONT_CTX_set(BN_MONT_CTX *, const BIGNUMX *, BN_CTX *);
void BN_MONT_CTX_free(BN_MONT_CTX *);

BIGNUMX *BN_dup(const BIGNUMX *);

int BN_set_word(BIGNUMX *, BN_ULONG);

const BIGNUMX *BNY_value_one(void);

char *BN_bn2hexx(const BIGNUMX *);
int BN_hex2bn(BIGNUMX **, const char *);

int BNY_bn2bin(const BIGNUMX *, unsigned char *);
BIGNUMX *BNY_bin2bn(const unsigned char *, int, BIGNUMX *);

int BNY_num_bits(const BIGNUMX *);

int BN_cmp(const BIGNUMX *, const BIGNUMX *);
int BN_is_negative(const BIGNUMX *);
int BNY_add(BIGNUMX *, const BIGNUMX *, const BIGNUMX *);
int BNY_sub(BIGNUMX *, const BIGNUMX *, const BIGNUMX *);
int BNY_nnmod(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, BN_CTX *);
int BN_mod_add(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, const BIGNUMX *,
               BN_CTX *);
int BN_mod_sub(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, const BIGNUMX *,
               BN_CTX *);
int BN_mod_mul(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, const BIGNUMX *,
               BN_CTX *);
int BN_mod_exp(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, const BIGNUMX *,
               BN_CTX *);
int BNY_mod_exp_mont(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, const BIGNUMX *,
                    BN_CTX *, BN_MONT_CTX *);
int BNY_mod_exp_mont_consttime(BIGNUMX *, const BIGNUMX *, const BIGNUMX *,
                              const BIGNUMX *, BN_CTX *, BN_MONT_CTX *);
BIGNUMX *BN_mod_inverse(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, BN_CTX *);

int BN_num_bytes(const BIGNUMX *);

int BN_mod(BIGNUMX *, const BIGNUMX *, const BIGNUMX *, BN_CTX *);

/* The following 3 prime methods are exposed for Tribler. */
int BNY_generate_prime_ex(BIGNUMX *, int, int, const BIGNUMX *,
                         const BIGNUMX *, BN_GENCB *);
int BN_is_prime_ex(const BIGNUMX *, int, BN_CTX *, BN_GENCB *);
const int BN_prime_checks_for_size(int);
"""

CUSTOMIZATIONS = """
"""
