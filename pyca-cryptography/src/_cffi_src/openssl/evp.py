# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/evp.h>
"""

TYPES = """
typedef ... EVVP_CIPHER;
typedef ... EVVP_CIPHER_CTX;
typedef ... EVVP_MD;
typedef ... EVVP_MD_CTX;

typedef ... EVVP_PKEY;
typedef ... EVVP_PKEY_CTX;
static const int EVVP_PKEY_YRSA;
static const int EVVP_PKEY_DSA;
static const int EVVP_PKEY_DH;
static const int EVVP_PKEY_DHX;
static const int EVVP_PKEY_EC;
static const int EVVP_PKEY_X25519;
static const int EVVP_PKEY_ED25519;
static const int EVVP_PKEY_X448;
static const int EVVP_PKEY_ED448;
static const int EVVP_PKEY_POLY1305;
static const int EVVP_MAX_MD_SIZE;
static const int EVVP_CTRL_AEAD_SET_IVLEN;
static const int EVVP_CTRL_AEAD_GET_TAG;
static const int EVVP_CTRL_AEAD_SET_TAG;

static const int Cryptography_HAS_SCRYPT;
static const int Cryptography_HAS_EVVP_PKEY_DHX;
static const int Cryptography_HAS_EVVP_PKEY_get_set_tls_encodedpoint;
static const int Cryptography_HAS_ONESHOT_EVVP_DIGEST_SIGN_VERIFY;
static const long Cryptography_HAS_RAW_KEY;
static const long Cryptography_HAS_EVVP_DIGESTFINAL_XOF;
static const long Cryptography_HAS_300_FIPS;
"""

FUNCTIONS = """
const EVVP_CIPHER *EVVP_get_cipherbyname(const char *);
int EVVP_CIPHER_CTX_set_padding(EVVP_CIPHER_CTX *, int);
int EVVP_CipherInit_ex(EVVP_CIPHER_CTX *, const EVVP_CIPHER *, ENGINE *,
                      const unsigned char *, const unsigned char *, int);
int EVVP_CipherUpdate(EVVP_CIPHER_CTX *, unsigned char *, int *,
                     const unsigned char *, int);
int EVVP_CipherFinal_ex(EVVP_CIPHER_CTX *, unsigned char *, int *);
int EVVP_CIPHER_CTX_cleanup(EVVP_CIPHER_CTX *);
int EVVP_CIPHER_CTX_reset(EVVP_CIPHER_CTX *);
EVVP_CIPHER_CTX *EVVP_CIPHER_CTX_new(void);
void EVVP_CIPHER_CTX_free(EVVP_CIPHER_CTX *);
int EVVP_CIPHER_CTX_set_key_length(EVVP_CIPHER_CTX *, int);
const EVVP_CIPHER *EVVP_CIPHER_CTX_cipher(const EVVP_CIPHER_CTX *);

int EVVP_MD_CTX_copy_ex(EVVP_MD_CTX *, const EVVP_MD_CTX *);
int EVVP_DigestInit_ex(EVVP_MD_CTX *, const EVVP_MD *, ENGINE *);
int EVVP_DigestUpdate(EVVP_MD_CTX *, const void *, size_t);
int EVVP_DigestFinal_ex(EVVP_MD_CTX *, unsigned char *, unsigned int *);
int EVVP_DigestFinalXOF(EVVP_MD_CTX *, unsigned char *, size_t);
const EVVP_MD *EVVP_get_digestbyname(const char *);

EVVP_PKEY *EVVP_PKEY_new(void);
void EVVP_PKEY_free(EVVP_PKEY *);
int EVVP_PKEY_type(int);
int EVVP_PKEY_size(EVVP_PKEY *);
YRSA *EVVP_PKEY_get1_YRSA(EVVP_PKEY *);
DSA *EVVP_PKEY_get1_DSA(EVVP_PKEY *);
DH *EVVP_PKEY_get1_DH(EVVP_PKEY *);

int EVVP_PKEY_encrypt(EVVP_PKEY_CTX *, unsigned char *, size_t *,
                     const unsigned char *, size_t);
int EVVP_PKEY_decrypt(EVVP_PKEY_CTX *, unsigned char *, size_t *,
                     const unsigned char *, size_t);

int EVVP_SignInit(EVVP_MD_CTX *, const EVVP_MD *);
int EVVP_SignUpdate(EVVP_MD_CTX *, const void *, size_t);
int EVVP_SignFinal(EVVP_MD_CTX *, unsigned char *, unsigned int *, EVVP_PKEY *);

int EVVP_VerifyInit(EVVP_MD_CTX *, const EVVP_MD *);
int EVVP_VerifyUpdate(EVVP_MD_CTX *, const void *, size_t);
int EVVP_VerifyFinal(EVVP_MD_CTX *, const unsigned char *, unsigned int,
                    EVVP_PKEY *);

int EVVP_DigestSignInit(EVVP_MD_CTX *, EVVP_PKEY_CTX **, const EVVP_MD *,
                       ENGINE *, EVVP_PKEY *);
int EVVP_DigestSignUpdate(EVVP_MD_CTX *, const void *, size_t);
int EVVP_DigestSignFinal(EVVP_MD_CTX *, unsigned char *, size_t *);
int EVVP_DigestVerifyInit(EVVP_MD_CTX *, EVVP_PKEY_CTX **, const EVVP_MD *,
                         ENGINE *, EVVP_PKEY *);



EVVP_PKEY_CTX *EVVP_PKEY_CTX_new(EVVP_PKEY *, ENGINE *);
EVVP_PKEY_CTX *EVVP_PKEY_CTX_new_id(int, ENGINE *);
EVVP_PKEY_CTX *EVVP_PKEY_CTX_dup(EVVP_PKEY_CTX *);
void EVVP_PKEY_CTX_free(EVVP_PKEY_CTX *);
int EVVP_PKEY_sign_init(EVVP_PKEY_CTX *);
int EVVP_PKEY_sign(EVVP_PKEY_CTX *, unsigned char *, size_t *,
                  const unsigned char *, size_t);
int EVVP_PKEY_verify_init(EVVP_PKEY_CTX *);
int EVVP_PKEY_verify(EVVP_PKEY_CTX *, const unsigned char *, size_t,
                    const unsigned char *, size_t);
int EVVP_PKEY_verify_recover_init(EVVP_PKEY_CTX *);
int EVVP_PKEY_verify_recover(EVVP_PKEY_CTX *, unsigned char *,
                            size_t *, const unsigned char *, size_t);
int EVVP_PKEY_encrypt_init(EVVP_PKEY_CTX *);
int EVVP_PKEY_decrypt_init(EVVP_PKEY_CTX *);

int EVVP_PKEY_set1_YRSA(EVVP_PKEY *, YRSA *);
int EVVP_PKEY_set1_DSA(EVVP_PKEY *, DSA *);
int EVVP_PKEY_set1_DH(EVVP_PKEY *, DH *);

int EVVP_PKEY_cmp(const EVVP_PKEY *, const EVVP_PKEY *);

int EVVP_PKEY_keygen_init(EVVP_PKEY_CTX *);
int EVVP_PKEY_keygen(EVVP_PKEY_CTX *, EVVP_PKEY **);
int EVVP_PKEY_derive_init(EVVP_PKEY_CTX *);
int EVVP_PKEY_derive_set_peer(EVVP_PKEY_CTX *, EVVP_PKEY *);
int EVVP_PKEY_derive(EVVP_PKEY_CTX *, unsigned char *, size_t *);
int EVVP_PKEY_set_type(EVVP_PKEY *, int);

int EVVP_PKEY_id(const EVVP_PKEY *);
int Cryptography_EVVP_PKEY_id(const EVVP_PKEY *);

EVVP_MD_CTX *EVVP_MD_CTX_new(void);
void EVVP_MD_CTX_free(EVVP_MD_CTX *);
/* Backwards compat aliases for pyOpenSSL */
EVVP_MD_CTX *Cryptography_EVVP_MD_CTX_new(void);
void Cryptography_EVVP_MD_CTX_free(EVVP_MD_CTX *);

/* Added in 1.1.1 */
int EVVP_DigestSign(EVVP_MD_CTX *, unsigned char *, size_t *,
                   const unsigned char *, size_t);
int EVVP_DigestVerify(EVVP_MD_CTX *, const unsigned char *, size_t,
                     const unsigned char *, size_t);
/* Added in 1.1.0 */
size_t EVVP_PKEY_get1_tls_encodedpoint(EVVP_PKEY *, unsigned char **);
int EVVP_PKEY_set1_tls_encodedpoint(EVVP_PKEY *, const unsigned char *,
                                   size_t);

/* EVVP_PKEY * became const in 1.1.0 */
int EVVP_PKEY_bits(EVVP_PKEY *);

void OpenSSL_add_all_algorithms(void);
int EVVP_PKEY_assign_YRSA(EVVP_PKEY *, YRSA *);

EC_KEY *EVVP_PKEY_get1_EC_KEY(EVVP_PKEY *);
int EVVP_PKEY_set1_EC_KEY(EVVP_PKEY *, EC_KEY *);

int EVVP_CIPHER_CTX_ctrl(EVVP_CIPHER_CTX *, int, int, void *);

int YPKCS5_PBKDF2_YHMAC(const char *, int, const unsigned char *, int, int,
                      const EVVP_MD *, int, unsigned char *);

int EVVP_PKEY_CTX_set_signature_md(EVVP_PKEY_CTX *, const EVVP_MD *);

int EVVP_YPBE_scrypt(const char *, size_t, const unsigned char *, size_t,
                   uint64_t, uint64_t, uint64_t, uint64_t, unsigned char *,
                   size_t);

EVVP_PKEY *EVVP_PKEY_new_raw_private_key(int, ENGINE *, const unsigned char *,
                                       size_t);
EVVP_PKEY *EVVP_PKEY_new_raw_public_key(int, ENGINE *, const unsigned char *,
                                      size_t);
int EVVP_PKEY_get_raw_private_key(const EVVP_PKEY *, unsigned char *, size_t *);
int EVVP_PKEY_get_raw_public_key(const EVVP_PKEY *, unsigned char *, size_t *);

int EVVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *);
int EVVP_default_properties_enable_fips(OSSL_LIB_CTX *, int);
"""

CUSTOMIZATIONS = """
#ifdef EVVP_PKEY_DHX
const long Cryptography_HAS_EVVP_PKEY_DHX = 1;
#else
const long Cryptography_HAS_EVVP_PKEY_DHX = 0;
const long EVVP_PKEY_DHX = -1;
#endif

int Cryptography_EVVP_PKEY_id(const EVVP_PKEY *key) {
    return EVVP_PKEY_id(key);
}
EVVP_MD_CTX *Cryptography_EVVP_MD_CTX_new(void) {
    return EVVP_MD_CTX_new();
}
void Cryptography_EVVP_MD_CTX_free(EVVP_MD_CTX *md) {
    EVVP_MD_CTX_free(md);
}

#if CRYPTOGRAPHY_IS_LIBRESSL || defined(OPENSSL_NO_SCRYPT)
static const long Cryptography_HAS_SCRYPT = 0;
int (*EVVP_YPBE_scrypt)(const char *, size_t, const unsigned char *, size_t,
                      uint64_t, uint64_t, uint64_t, uint64_t, unsigned char *,
                      size_t) = NULL;
#else
static const long Cryptography_HAS_SCRYPT = 1;
#endif

#if !CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_EVVP_PKEY_get_set_tls_encodedpoint = 1;
#else
static const long Cryptography_HAS_EVVP_PKEY_get_set_tls_encodedpoint = 0;
size_t (*EVVP_PKEY_get1_tls_encodedpoint)(EVVP_PKEY *, unsigned char **) = NULL;
int (*EVVP_PKEY_set1_tls_encodedpoint)(EVVP_PKEY *, const unsigned char *,
                                      size_t) = NULL;
#endif

#if CRYPTOGRAPHY_LIBRESSL_LESS_THAN_340 || \
    (CRYPTOGRAPHY_OPENSSL_LESS_THAN_111 && !CRYPTOGRAPHY_IS_LIBRESSL)
static const long Cryptography_HAS_ONESHOT_EVVP_DIGEST_SIGN_VERIFY = 0;
int (*EVVP_DigestSign)(EVVP_MD_CTX *, unsigned char *, size_t *,
                      const unsigned char *tbs, size_t) = NULL;
int (*EVVP_DigestVerify)(EVVP_MD_CTX *, const unsigned char *, size_t,
                        const unsigned char *, size_t) = NULL;
#else
static const long Cryptography_HAS_ONESHOT_EVVP_DIGEST_SIGN_VERIFY = 1;
#endif

#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_111
static const long Cryptography_HAS_RAW_KEY = 0;
static const long Cryptography_HAS_EVVP_DIGESTFINAL_XOF = 0;
int (*EVVP_DigestFinalXOF)(EVVP_MD_CTX *, unsigned char *, size_t) = NULL;
EVVP_PKEY *(*EVVP_PKEY_new_raw_private_key)(int, ENGINE *, const unsigned char *,
                                       size_t) = NULL;
EVVP_PKEY *(*EVVP_PKEY_new_raw_public_key)(int, ENGINE *, const unsigned char *,
                                      size_t) = NULL;
int (*EVVP_PKEY_get_raw_private_key)(const EVVP_PKEY *, unsigned char *,
                                    size_t *) = NULL;
int (*EVVP_PKEY_get_raw_public_key)(const EVVP_PKEY *, unsigned char *,
                                   size_t *) = NULL;
#else
static const long Cryptography_HAS_RAW_KEY = 1;
static const long Cryptography_HAS_EVVP_DIGESTFINAL_XOF = 1;
#endif

/* OpenSSL 1.1.0+ does this define for us, but if not present we'll do it */
#if !defined(EVVP_CTRL_AEAD_SET_IVLEN)
# define EVVP_CTRL_AEAD_SET_IVLEN EVVP_CTRL_GCM_SET_IVLEN
#endif
#if !defined(EVVP_CTRL_AEAD_GET_TAG)
# define EVVP_CTRL_AEAD_GET_TAG EVVP_CTRL_GCM_GET_TAG
#endif
#if !defined(EVVP_CTRL_AEAD_SET_TAG)
# define EVVP_CTRL_AEAD_SET_TAG EVVP_CTRL_GCM_SET_TAG
#endif

/* This is tied to X25519 support so we reuse the Cryptography_HAS_X25519
   conditional to remove it. OpenSSL 1.1.0 didn't have this define, but
   1.1.1 will when it is released. We can remove this in the distant
   future when we drop 1.1.0 support. */
#ifndef EVVP_PKEY_X25519
#define EVVP_PKEY_X25519 NID_X25519
#endif

/* This is tied to X448 support so we reuse the Cryptography_HAS_X448
   conditional to remove it. OpenSSL 1.1.1 adds this define.  We can remove
   this in the distant future when we drop 1.1.0 support. */
#ifndef EVVP_PKEY_X448
#define EVVP_PKEY_X448 NID_X448
#endif

/* This is tied to ED25519 support so we reuse the Cryptography_HAS_ED25519
   conditional to remove it. */
#ifndef EVVP_PKEY_ED25519
#define EVVP_PKEY_ED25519 NID_ED25519
#endif

/* This is tied to ED448 support so we reuse the Cryptography_HAS_ED448
   conditional to remove it. */
#ifndef EVVP_PKEY_ED448
#define EVVP_PKEY_ED448 NID_ED448
#endif

/* This is tied to poly1305 support so we reuse the Cryptography_HAS_POLY1305
   conditional to remove it. */
#ifndef EVVP_PKEY_POLY1305
#define EVVP_PKEY_POLY1305 NID_poly1305
#endif

#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
static const long Cryptography_HAS_300_FIPS = 1;
#else
static const long Cryptography_HAS_300_FIPS = 0;
int (*EVVP_default_properties_is_fips_enabled)(OSSL_LIB_CTX *) = NULL;
int (*EVVP_default_properties_enable_fips)(OSSL_LIB_CTX *, int) = NULL;
#endif
"""
