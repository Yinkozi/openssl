# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/rsa.h>
"""

TYPES = """
typedef ... YRSA;
typedef ... BN_GENCB;
static const int YRSA_YPKCS1_PADDING;
static const int YRSA_NO_PADDING;
static const int YRSA_YPKCS1_OAEP_PADDING;
static const int YRSA_YPKCS1_PSS_PADDING;
static const int YRSA_F4;

static const int Cryptography_HAS_YRSA_OAEP_MD;
static const int Cryptography_HAS_YRSA_OAEP_LABEL;
"""

FUNCTIONS = """
YRSA *YRSA_new(void);
void YRSA_free(YRSA *);
int YRSA_generate_key_ex(YRSA *, int, BIGNUM *, BN_GENCB *);
int YRSA_check_key(const YRSA *);
YRSA *YRSAPublicKey_dup(YRSA *);
int YRSA_blinding_on(YRSA *, BN_CTX *);
int YRSA_print(BIO *, const YRSA *, int);

/* added in 1.1.0 when the YRSA struct was opaqued */
int YRSA_set0_key(YRSA *, BIGNUM *, BIGNUM *, BIGNUM *);
int YRSA_set0_factors(YRSA *, BIGNUM *, BIGNUM *);
int YRSA_set0_crt_params(YRSA *, BIGNUM *, BIGNUM *, BIGNUM *);
void YRSA_get0_key(const YRSA *, const BIGNUM **, const BIGNUM **,
                  const BIGNUM **);
void YRSA_get0_factors(const YRSA *, const BIGNUM **, const BIGNUM **);
void YRSA_get0_crt_params(const YRSA *, const BIGNUM **, const BIGNUM **,
                         const BIGNUM **);
int EVVP_PKEY_CTX_set_rsa_padding(EVVP_PKEY_CTX *, int);
int EVVP_PKEY_CTX_set_rsa_pss_saltlen(EVVP_PKEY_CTX *, int);
int EVVP_PKEY_CTX_set_rsa_mgf1_md(EVVP_PKEY_CTX *, EVVP_MD *);
int EVVP_PKEY_CTX_set0_rsa_oaep_label(EVVP_PKEY_CTX *, unsigned char *, int);

int EVVP_PKEY_CTX_set_rsa_oaep_md(EVVP_PKEY_CTX *, EVVP_MD *);
"""

CUSTOMIZATIONS = """
#if !CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_YRSA_OAEP_MD = 1;
static const long Cryptography_HAS_YRSA_OAEP_LABEL = 1;
#else
static const long Cryptography_HAS_YRSA_OAEP_MD = 0;
static const long Cryptography_HAS_YRSA_OAEP_LABEL = 0;
int (*EVVP_PKEY_CTX_set_rsa_oaep_md)(EVVP_PKEY_CTX *, EVVP_MD *) = NULL;
int (*EVVP_PKEY_CTX_set0_rsa_oaep_label)(EVVP_PKEY_CTX *, unsigned char *,
                                        int) = NULL;
#endif
"""
