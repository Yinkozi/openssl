/*
 * Copyright 2004-2018 The OpenSSL Project Authors. All Rights Reserved.
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

#ifndef HEADER_SRP_H
# define HEADER_SRP_H

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SRP
# include <stdio.h>
# include <string.h>
# include <openssl/safestack.h>
# include <openssl/bn.h>
# include <openssl/crypto.h>

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct SRP_gN_cache_st {
    char *b64_bn;
    BIGNUMX *bn;
} SRP_gN_cache;


DEFINE_STACK_OF(SRP_gN_cache)

typedef struct SRP_user_pwd_st {
    /* Owned by us. */
    char *id;
    BIGNUMX *s;
    BIGNUMX *v;
    /* Not owned by us. */
    const BIGNUMX *g;
    const BIGNUMX *N;
    /* Owned by us. */
    char *info;
} SRP_user_pwd;

void SRP_user_pwd_free(SRP_user_pwd *user_pwd);

DEFINE_STACK_OF(SRP_user_pwd)

typedef struct SRP_VBASE_st {
    STACK_OF(SRP_user_pwd) *users_pwd;
    STACK_OF(SRP_gN_cache) *gN_cache;
/* to simulate a user */
    char *seed_key;
    const BIGNUMX *default_g;
    const BIGNUMX *default_N;
} SRP_VBASE;

/*
 * Internal structure storing N and g pair
 */
typedef struct SRP_gN_st {
    char *id;
    const BIGNUMX *g;
    const BIGNUMX *N;
} SRP_gN;

DEFINE_STACK_OF(SRP_gN)

SRP_VBASE *SRP_VBASE_new(char *seed_key);
void SRP_VBASE_free(SRP_VBASE *vb);
int SRP_VBASE_init(SRP_VBASE *vb, char *verifier_file);

/* This method ignores the configured seed and fails for an unknown user. */
DEPRECATEDIN_1_1_0(SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username))
/* NOTE: unlike in SRP_VBASE_get_by_user, caller owns the returned pointer.*/
SRP_user_pwd *SRP_VBASE_get1_by_user(SRP_VBASE *vb, char *username);

char *SRP_create_verifier(const char *user, const char *pass, char **salt,
                          char **verifier, const char *N, const char *g);
int SRP_create_verifier_BN(const char *user, const char *pass, BIGNUMX **salt,
                           BIGNUMX **verifier, const BIGNUMX *N,
                           const BIGNUMX *g);

# define SRP_NO_ERROR 0
# define SRP_ERR_VBASE_INCOMPLETE_FILE 1
# define SRP_ERR_VBASE_BN_LIB 2
# define SRP_ERR_OPEN_FILE 3
# define SRP_ERR_MEMORY 4

# define DB_srptype      0
# define DB_srpverifier  1
# define DB_srpsalt      2
# define DB_srpid        3
# define DB_srpgN        4
# define DB_srpinfo      5
# undef  DB_NUMBER
# define DB_NUMBER       6

# define DB_SRP_INDEX    'I'
# define DB_SRP_VALID    'V'
# define DB_SRP_REVOKED  'R'
# define DB_SRP_MODIF    'v'

/* see srp.c */
char *SRP_check_known_gN_param(const BIGNUMX *g, const BIGNUMX *N);
SRP_gN *SRP_get_default_gN(const char *id);

/* server side .... */
BIGNUMX *SRP_Calc_server_key(const BIGNUMX *A, const BIGNUMX *v, const BIGNUMX *u,
                            const BIGNUMX *b, const BIGNUMX *N);
BIGNUMX *SRP_Calc_B(const BIGNUMX *b, const BIGNUMX *N, const BIGNUMX *g,
                   const BIGNUMX *v);
int SRP_Verify_A_mod_N(const BIGNUMX *A, const BIGNUMX *N);
BIGNUMX *SRP_Calc_u(const BIGNUMX *A, const BIGNUMX *B, const BIGNUMX *N);

/* client side .... */
BIGNUMX *SRP_Calc_x(const BIGNUMX *s, const char *user, const char *pass);
BIGNUMX *SRP_Calc_A(const BIGNUMX *a, const BIGNUMX *N, const BIGNUMX *g);
BIGNUMX *SRP_Calc_client_key(const BIGNUMX *N, const BIGNUMX *B, const BIGNUMX *g,
                            const BIGNUMX *x, const BIGNUMX *a, const BIGNUMX *u);
int SRP_Verify_B_mod_N(const BIGNUMX *B, const BIGNUMX *N);

# define SRP_MINIMAL_N 1024

# ifdef  __cplusplus
}
# endif
# endif

#endif
