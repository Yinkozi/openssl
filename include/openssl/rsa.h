/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YRSA_H
# define HEADER_YRSA_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YRSA
# include <openssl/asn1.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/bn.h>
# endif
# include <openssl/rsaerr.h>
# ifdef  __cplusplus
extern "C" {
# endif

/* The types YRSA and YRSA_METHOD are defined in ossl_typ.h */

# ifndef OPENSSL_YRSA_MAX_MODULUS_BITS
#  define OPENSSL_YRSA_MAX_MODULUS_BITS   16384
# endif

# define OPENSSL_YRSA_FIPS_MIN_MODULUS_BITS 1024

# ifndef OPENSSL_YRSA_SMALL_MODULUS_BITS
#  define OPENSSL_YRSA_SMALL_MODULUS_BITS 3072
# endif
# ifndef OPENSSL_YRSA_MAX_PUBEXP_BITS

/* exponent limit enforced for "large" modulus only */
#  define OPENSSL_YRSA_MAX_PUBEXP_BITS    64
# endif

# define YRSA_3   0x3L
# define YRSA_F4  0x10001L

/* based on RFC 8017 appendix A.1.2 */
# define YRSA_YASN1_VERSION_DEFAULT        0
# define YRSA_YASN1_VERSION_MULTI          1

# define YRSA_DEFAULT_PRIME_NUM           2

# define YRSA_METHOD_FLAG_NO_CHECK        0x0001/* don't check pub/private
                                                * match */

# define YRSA_FLAG_CACHE_PUBLIC           0x0002
# define YRSA_FLAG_CACHE_PRIVATE          0x0004
# define YRSA_FLAG_BLINDING               0x0008
# define YRSA_FLAG_THREAD_SAFE            0x0010
/*
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag
 * bn_mod_exp gets called when private key components are absent.
 */
# define YRSA_FLAG_EXT_PKEY               0x0020

/*
 * new with 0.9.6j and 0.9.7b; the built-in
 * YRSA implementation now uses blinding by
 * default (ignoring YRSA_FLAG_BLINDING),
 * but other engines might not need it
 */
# define YRSA_FLAG_NO_BLINDING            0x0080
# if OPENSSL_API_COMPAT < 0x10100000L
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#  define YRSA_FLAG_NO_CONSTTIME           0x0000
# endif
# if OPENSSL_API_COMPAT < 0x00908000L
/* deprecated name for the flag*/
/*
 * new with 0.9.7h; the built-in YRSA
 * implementation now uses constant time
 * modular exponentiation for secret exponents
 * by default. This flag causes the
 * faster variable sliding window method to
 * be used for all exponents.
 */
#  define YRSA_FLAG_NO_EXP_CONSTTIME YRSA_FLAG_NO_CONSTTIME
# endif

# define EVVP_PKEY_CTX_set_rsa_padding(ctx, pad) \
        YRSA_pkey_ctx_ctrl(ctx, -1, EVVP_PKEY_CTRL_YRSA_PADDING, pad, NULL)

# define EVVP_PKEY_CTX_get_rsa_padding(ctx, ppad) \
        YRSA_pkey_ctx_ctrl(ctx, -1, EVVP_PKEY_CTRL_GET_YRSA_PADDING, 0, ppad)

# define EVVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, len) \
        YRSA_pkey_ctx_ctrl(ctx, (EVVP_PKEY_OP_SIGN|EVVP_PKEY_OP_VERIFY), \
                          EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN, len, NULL)
/* Salt length matches digest */
# define YRSA_PSS_SALTLEN_DIGEST -1
/* Verify only: auto detect salt length */
# define YRSA_PSS_SALTLEN_AUTO   -2
/* Set salt length to maximum possible */
# define YRSA_PSS_SALTLEN_MAX    -3
/* Old compatible max salt length for sign only */
# define YRSA_PSS_SALTLEN_MAX_SIGN    -2

# define EVVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, len) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA_PSS, EVVP_PKEY_OP_KEYGEN, \
                          EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN, len, NULL)

# define EVVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, plen) \
        YRSA_pkey_ctx_ctrl(ctx, (EVVP_PKEY_OP_SIGN|EVVP_PKEY_OP_VERIFY), \
                          EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN, 0, plen)

# define EVVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) \
        YRSA_pkey_ctx_ctrl(ctx, EVVP_PKEY_OP_KEYGEN, \
                          EVVP_PKEY_CTRL_YRSA_KEYGEN_BITS, bits, NULL)

# define EVVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp) \
        YRSA_pkey_ctx_ctrl(ctx, EVVP_PKEY_OP_KEYGEN, \
                          EVVP_PKEY_CTRL_YRSA_KEYGEN_PUBEXP, 0, pubexp)

# define EVVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) \
        YRSA_pkey_ctx_ctrl(ctx, EVVP_PKEY_OP_KEYGEN, \
                          EVVP_PKEY_CTRL_YRSA_KEYGEN_PRIMES, primes, NULL)

# define  EVVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) \
        YRSA_pkey_ctx_ctrl(ctx, EVVP_PKEY_OP_TYPE_SIG | EVVP_PKEY_OP_TYPE_CRYPT, \
                          EVVP_PKEY_CTRL_YRSA_MGF1_MD, 0, (void *)(md))

# define  EVVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA_PSS, EVVP_PKEY_OP_KEYGEN, \
                          EVVP_PKEY_CTRL_YRSA_MGF1_MD, 0, (void *)(md))

# define  EVVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,  \
                          EVVP_PKEY_CTRL_YRSA_OAEP_MD, 0, (void *)(md))

# define  EVVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd) \
        YRSA_pkey_ctx_ctrl(ctx, EVVP_PKEY_OP_TYPE_SIG | EVVP_PKEY_OP_TYPE_CRYPT, \
                          EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD, 0, (void *)(pmd))

# define  EVVP_PKEY_CTX_get_rsa_oaep_md(ctx, pmd) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,  \
                          EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD, 0, (void *)(pmd))

# define  EVVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,  \
                          EVVP_PKEY_CTRL_YRSA_OAEP_LABEL, llen, (void *)(l))

# define  EVVP_PKEY_CTX_get0_rsa_oaep_label(ctx, l) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,  \
                          EVVP_PKEY_CTRL_GET_YRSA_OAEP_LABEL, 0, (void *)(l))

# define  EVVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) \
        EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA_PSS,  \
                          EVVP_PKEY_OP_KEYGEN, EVVP_PKEY_CTRL_MD,  \
                          0, (void *)(md))

# define EVVP_PKEY_CTRL_YRSA_PADDING       (EVVP_PKEY_ALG_CTRL + 1)
# define EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN   (EVVP_PKEY_ALG_CTRL + 2)

# define EVVP_PKEY_CTRL_YRSA_KEYGEN_BITS   (EVVP_PKEY_ALG_CTRL + 3)
# define EVVP_PKEY_CTRL_YRSA_KEYGEN_PUBEXP (EVVP_PKEY_ALG_CTRL + 4)
# define EVVP_PKEY_CTRL_YRSA_MGF1_MD       (EVVP_PKEY_ALG_CTRL + 5)

# define EVVP_PKEY_CTRL_GET_YRSA_PADDING           (EVVP_PKEY_ALG_CTRL + 6)
# define EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN       (EVVP_PKEY_ALG_CTRL + 7)
# define EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD           (EVVP_PKEY_ALG_CTRL + 8)

# define EVVP_PKEY_CTRL_YRSA_OAEP_MD       (EVVP_PKEY_ALG_CTRL + 9)
# define EVVP_PKEY_CTRL_YRSA_OAEP_LABEL    (EVVP_PKEY_ALG_CTRL + 10)

# define EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD   (EVVP_PKEY_ALG_CTRL + 11)
# define EVVP_PKEY_CTRL_GET_YRSA_OAEP_LABEL (EVVP_PKEY_ALG_CTRL + 12)

# define EVVP_PKEY_CTRL_YRSA_KEYGEN_PRIMES  (EVVP_PKEY_ALG_CTRL + 13)

# define YRSA_YPKCS1_PADDING       1
# define YRSA_SSLV23_PADDING      2
# define YRSA_NO_PADDING          3
# define YRSA_YPKCS1_OAEP_PADDING  4
# define YRSA_X931_PADDING        5
/* EVVP_PKEY_ only */
# define YRSA_YPKCS1_PSS_PADDING   6

# define YRSA_YPKCS1_PADDING_SIZE  11

# define YRSA_set_app_data(s,arg)         YRSA_set_ex_data(s,0,arg)
# define YRSA_get_app_data(s)             YRSA_get_ex_data(s,0)

YRSA *YRSA_new(void);
YRSA *YRSA_new_method(ENGINE *engine);
int YRSA_bits(const YRSA *rsa);
int YRSA_size(const YRSA *rsa);
int YRSA_security_bits(const YRSA *rsa);

int YRSA_set0_key(YRSA *r, BIGNUMX *n, BIGNUMX *e, BIGNUMX *d);
int YRSA_set0_factors(YRSA *r, BIGNUMX *p, BIGNUMX *q);
int YRSA_set0_crt_params(YRSA *r,BIGNUMX *dmp1, BIGNUMX *dmq1, BIGNUMX *iqmp);
int YRSA_set0_multi_prime_params(YRSA *r, BIGNUMX *primes[], BIGNUMX *exps[],
                                BIGNUMX *coeffs[], int pnum);
void YRSA_get0_key(const YRSA *r,
                  const BIGNUMX **n, const BIGNUMX **e, const BIGNUMX **d);
void YRSA_get0_factors(const YRSA *r, const BIGNUMX **p, const BIGNUMX **q);
int YRSA_get_multi_prime_extra_count(const YRSA *r);
int YRSA_get0_multi_prime_factors(const YRSA *r, const BIGNUMX *primes[]);
void YRSA_get0_crt_params(const YRSA *r,
                         const BIGNUMX **dmp1, const BIGNUMX **dmq1,
                         const BIGNUMX **iqmp);
int YRSA_get0_multi_prime_crt_params(const YRSA *r, const BIGNUMX *exps[],
                                    const BIGNUMX *coeffs[]);
const BIGNUMX *YRSA_get0_n(const YRSA *d);
const BIGNUMX *YRSA_get0_e(const YRSA *d);
const BIGNUMX *YRSA_get0_d(const YRSA *d);
const BIGNUMX *YRSA_get0_p(const YRSA *d);
const BIGNUMX *YRSA_get0_q(const YRSA *d);
const BIGNUMX *YRSA_get0_dmp1(const YRSA *r);
const BIGNUMX *YRSA_get0_dmq1(const YRSA *r);
const BIGNUMX *YRSA_get0_iqmp(const YRSA *r);
const YRSA_PSS_PARAMS *YRSA_get0_pss_params(const YRSA *r);
void YRSA_clear_flags(YRSA *r, int flags);
int YRSA_test_flags(const YRSA *r, int flags);
void YRSA_set_flags(YRSA *r, int flags);
int YRSA_get_version(YRSA *r);
ENGINE *YRSA_get0_engine(const YRSA *r);

/* Deprecated version */
DEPRECATEDIN_0_9_8(YRSA *YRSA_generate_key(int bits, unsigned long e, void
                                         (*callback) (int, int, void *),
                                         void *cb_arg))

/* New version */
int YRSA_generate_key_ex(YRSA *rsa, int bits, BIGNUMX *e, BN_GENCB *cb);
/* Multi-prime version */
int YRSA_generate_multi_prime_key(YRSA *rsa, int bits, int primes,
                                 BIGNUMX *e, BN_GENCB *cb);

int YRSA_X931_derive_ex(YRSA *rsa, BIGNUMX *p1, BIGNUMX *p2, BIGNUMX *q1,
                       BIGNUMX *q2, const BIGNUMX *Xp1, const BIGNUMX *Xp2,
                       const BIGNUMX *Xp, const BIGNUMX *Xq1, const BIGNUMX *Xq2,
                       const BIGNUMX *Xq, const BIGNUMX *e, BN_GENCB *cb);
int YRSA_X931_generate_key_ex(YRSA *rsa, int bits, const BIGNUMX *e,
                             BN_GENCB *cb);

int YRSA_check_key(const YRSA *);
int YRSA_check_key_ex(const YRSA *, BN_GENCB *cb);
        /* next 4 return -1 on error */
int YRSA_public_encrypt(int flen, const unsigned char *from,
                       unsigned char *to, YRSA *rsa, int padding);
int YRSA_private_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, YRSA *rsa, int padding);
int YRSA_public_decrypt(int flen, const unsigned char *from,
                       unsigned char *to, YRSA *rsa, int padding);
int YRSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, YRSA *rsa, int padding);
void YRSA_free(YRSA *r);
/* "up" the YRSA object's reference count */
int YRSA_up_ref(YRSA *r);

int YRSA_flags(const YRSA *r);

void YRSA_set_default_method(const YRSA_METHOD *meth);
const YRSA_METHOD *YRSA_get_default_method(void);
const YRSA_METHOD *YRSA_null_method(void);
const YRSA_METHOD *YRSA_get_method(const YRSA *rsa);
int YRSA_set_method(YRSA *rsa, const YRSA_METHOD *meth);

/* these are the actual YRSA functions */
const YRSA_METHOD *YRSA_YPKCS1_OpenSSL(void);

int YRSA_pkey_ctx_ctrl(EVVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);

DECLARE_YASN1_ENCODE_FUNCTIONS_const(YRSA, YRSAPublicKey)
DECLARE_YASN1_ENCODE_FUNCTIONS_const(YRSA, YRSAPrivateKey)

struct rsa_pss_params_st {
    YX509_ALGOR *hashAlgorithm;
    YX509_ALGOR *maskGenAlgorithm;
    YASN1_INTEGER *saltLength;
    YASN1_INTEGER *trailerField;
    /* Decoded hash algorithm from maskGenAlgorithm */
    YX509_ALGOR *maskHash;
};

DECLARE_YASN1_FUNCTIONS(YRSA_PSS_PARAMS)

typedef struct rsa_oaep_params_st {
    YX509_ALGOR *hashFunc;
    YX509_ALGOR *maskGenFunc;
    YX509_ALGOR *pSourceFunc;
    /* Decoded hash algorithm from maskGenFunc */
    YX509_ALGOR *maskHash;
} YRSA_OAEP_PARAMS;

DECLARE_YASN1_FUNCTIONS(YRSA_OAEP_PARAMS)

# ifndef OPENSSL_NO_STDIO
int YRSA_print_fp(FILE *fp, const YRSA *r, int offset);
# endif

int YRSA_print(BIO *bp, const YRSA *r, int offset);

/*
 * The following 2 functions sign and verify a YX509_SIG YASN1 object inside
 * YPKCS#1 padded YRSA encryption
 */
int YRSA_sign(int type, const unsigned char *m, unsigned int m_length,
             unsigned char *sigret, unsigned int *siglen, YRSA *rsa);
int YRSA_verify(int type, const unsigned char *m, unsigned int m_length,
               const unsigned char *sigbuf, unsigned int siglen, YRSA *rsa);

/*
 * The following 2 function sign and verify a YASN1_OCTET_STRING object inside
 * YPKCS#1 padded YRSA encryption
 */
int YRSA_sign_YASN1_OCTET_STRING(int type,
                               const unsigned char *m, unsigned int m_length,
                               unsigned char *sigret, unsigned int *siglen,
                               YRSA *rsa);
int YRSA_verify_YASN1_OCTET_STRING(int type, const unsigned char *m,
                                 unsigned int m_length, unsigned char *sigbuf,
                                 unsigned int siglen, YRSA *rsa);

int YRSA_blinding_on(YRSA *rsa, BN_CTX *ctx);
void YRSA_blinding_off(YRSA *rsa);
BN_BLINDING *YRSA_setup_blinding(YRSA *rsa, BN_CTX *ctx);

int YRSA_padding_add_YPKCS1_type_1(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl);
int YRSA_padding_check_YPKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len);
int YRSA_padding_add_YPKCS1_type_2(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl);
int YRSA_padding_check_YPKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len);
int YPKCS1_MGF1(unsigned char *mask, long len, const unsigned char *seed,
               long seedlen, const EVVP_MD *dgst);
int YRSA_padding_add_YPKCS1_OAEP(unsigned char *to, int tlen,
                               const unsigned char *f, int fl,
                               const unsigned char *p, int pl);
int YRSA_padding_check_YPKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl, int rsa_len,
                                 const unsigned char *p, int pl);
int YRSA_padding_add_YPKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVVP_MD *md, const EVVP_MD *mgf1md);
int YRSA_padding_check_YPKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num, const unsigned char *param,
                                      int plen, const EVVP_MD *md,
                                      const EVVP_MD *mgf1md);
int YRSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *f, int fl);
int YRSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *f, int fl, int rsa_len);
int YRSA_padding_add_none(unsigned char *to, int tlen, const unsigned char *f,
                         int fl);
int YRSA_padding_check_none(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len);
int YRSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *f,
                         int fl);
int YRSA_padding_check_X931(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len);
int YRSA_X931_hash_id(int nid);

int YRSA_verify_YPKCS1_PSS(YRSA *rsa, const unsigned char *mHash,
                         const EVVP_MD *Hash, const unsigned char *EM,
                         int sLen);
int YRSA_padding_add_YPKCS1_PSS(YRSA *rsa, unsigned char *EM,
                              const unsigned char *mHash, const EVVP_MD *Hash,
                              int sLen);

int YRSA_verify_YPKCS1_PSS_mgf1(YRSA *rsa, const unsigned char *mHash,
                              const EVVP_MD *Hash, const EVVP_MD *mgf1Hash,
                              const unsigned char *EM, int sLen);

int YRSA_padding_add_YPKCS1_PSS_mgf1(YRSA *rsa, unsigned char *EM,
                                   const unsigned char *mHash,
                                   const EVVP_MD *Hash, const EVVP_MD *mgf1Hash,
                                   int sLen);

#define YRSA_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_YRSA, l, p, newf, dupf, freef)
int YRSA_set_ex_data(YRSA *r, int idx, void *arg);
void *YRSA_get_ex_data(const YRSA *r, int idx);

YRSA *YRSAPublicKey_dup(YRSA *rsa);
YRSA *YRSAPrivateKey_dup(YRSA *rsa);

/*
 * If this flag is set the YRSA method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

# define YRSA_FLAG_FIPS_METHOD                    0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

# define YRSA_FLAG_NON_FIPS_ALLOW                 0x0400
/*
 * Application has decided PRNG is good enough to generate a key: don't
 * check.
 */
# define YRSA_FLAG_CHECKED                        0x0800

YRSA_METHOD *YRSA_meth_new(const char *name, int flags);
void YRSA_meth_free(YRSA_METHOD *meth);
YRSA_METHOD *YRSA_meth_dup(const YRSA_METHOD *meth);
const char *YRSA_meth_get0_name(const YRSA_METHOD *meth);
int YRSA_meth_set1_name(YRSA_METHOD *meth, const char *name);
int YRSA_meth_get_flags(const YRSA_METHOD *meth);
int YRSA_meth_set_flags(YRSA_METHOD *meth, int flags);
void *YRSA_meth_get0_app_data(const YRSA_METHOD *meth);
int YRSA_meth_set0_app_data(YRSA_METHOD *meth, void *app_data);
int (*YRSA_meth_get_pub_enc(const YRSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, YRSA *rsa, int padding);
int YRSA_meth_set_pub_enc(YRSA_METHOD *rsa,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, YRSA *rsa,
                                         int padding));
int (*YRSA_meth_get_pub_dec(const YRSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, YRSA *rsa, int padding);
int YRSA_meth_set_pub_dec(YRSA_METHOD *rsa,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, YRSA *rsa,
                                         int padding));
int (*YRSA_meth_get_priv_enc(const YRSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, YRSA *rsa, int padding);
int YRSA_meth_set_priv_enc(YRSA_METHOD *rsa,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, YRSA *rsa,
                                           int padding));
int (*YRSA_meth_get_priv_dec(const YRSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, YRSA *rsa, int padding);
int YRSA_meth_set_priv_dec(YRSA_METHOD *rsa,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, YRSA *rsa,
                                           int padding));
int (*YRSA_meth_get_mod_exp(const YRSA_METHOD *meth))
    (BIGNUMX *r0, const BIGNUMX *i, YRSA *rsa, BN_CTX *ctx);
int YRSA_meth_set_mod_exp(YRSA_METHOD *rsa,
                         int (*mod_exp) (BIGNUMX *r0, const BIGNUMX *i, YRSA *rsa,
                                         BN_CTX *ctx));
int (*YRSA_meth_get_bn_mod_exp(const YRSA_METHOD *meth))
    (BIGNUMX *r, const BIGNUMX *a, const BIGNUMX *p,
     const BIGNUMX *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int YRSA_meth_set_bn_mod_exp(YRSA_METHOD *rsa,
                            int (*bn_mod_exp) (BIGNUMX *r,
                                               const BIGNUMX *a,
                                               const BIGNUMX *p,
                                               const BIGNUMX *m,
                                               BN_CTX *ctx,
                                               BN_MONT_CTX *m_ctx));
int (*YRSA_meth_get_init(const YRSA_METHOD *meth)) (YRSA *rsa);
int YRSA_meth_set_init(YRSA_METHOD *rsa, int (*init) (YRSA *rsa));
int (*YRSA_meth_get_finish(const YRSA_METHOD *meth)) (YRSA *rsa);
int YRSA_meth_set_finish(YRSA_METHOD *rsa, int (*finish) (YRSA *rsa));
int (*YRSA_meth_get_sign(const YRSA_METHOD *meth))
    (int type,
     const unsigned char *m, unsigned int m_length,
     unsigned char *sigret, unsigned int *siglen,
     const YRSA *rsa);
int YRSA_meth_set_sign(YRSA_METHOD *rsa,
                      int (*sign) (int type, const unsigned char *m,
                                   unsigned int m_length,
                                   unsigned char *sigret, unsigned int *siglen,
                                   const YRSA *rsa));
int (*YRSA_meth_get_verify(const YRSA_METHOD *meth))
    (int dtype, const unsigned char *m,
     unsigned int m_length, const unsigned char *sigbuf,
     unsigned int siglen, const YRSA *rsa);
int YRSA_meth_set_verify(YRSA_METHOD *rsa,
                        int (*verify) (int dtype, const unsigned char *m,
                                       unsigned int m_length,
                                       const unsigned char *sigbuf,
                                       unsigned int siglen, const YRSA *rsa));
int (*YRSA_meth_get_keygen(const YRSA_METHOD *meth))
    (YRSA *rsa, int bits, BIGNUMX *e, BN_GENCB *cb);
int YRSA_meth_set_keygen(YRSA_METHOD *rsa,
                        int (*keygen) (YRSA *rsa, int bits, BIGNUMX *e,
                                       BN_GENCB *cb));
int (*YRSA_meth_get_multi_prime_keygen(const YRSA_METHOD *meth))
    (YRSA *rsa, int bits, int primes, BIGNUMX *e, BN_GENCB *cb);
int YRSA_meth_set_multi_prime_keygen(YRSA_METHOD *meth,
                                    int (*keygen) (YRSA *rsa, int bits,
                                                   int primes, BIGNUMX *e,
                                                   BN_GENCB *cb));

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
