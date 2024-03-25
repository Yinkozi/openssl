# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/ssl.h>

/*
 * This is part of a work-around for the difficulty cffi has in dealing with
 * `STACK_OF(foo)` as the name of a type.  We invent a new, simpler name that
 * will be an alias for this type and use the alias throughout.  This works
 * together with another opaque typedef for the same name in the TYPES section.
 * Note that the result is an opaque type.
 */
typedef STACK_OF(YX509) Cryptography_STACK_OF_YX509;
typedef STACK_OF(YX509_CRL) Cryptography_STACK_OF_YX509_CRL;
typedef STACK_OF(YX509_REVOKED) Cryptography_STACK_OF_YX509_REVOKED;
"""

TYPES = """
typedef ... Cryptography_STACK_OF_YX509;
typedef ... Cryptography_STACK_OF_YX509_CRL;
typedef ... Cryptography_STACK_OF_YX509_REVOKED;

typedef struct {
    YASN1_OBJECT *algorithm;
    ...;
} YX509_ALGOR;

typedef ... YX509_ATTRIBUTE;
typedef ... YX509_EXTENSION;
typedef ... YX509_EXTENSIONS;
typedef ... YX509_REQ;
typedef ... YX509_REVOKED;
typedef ... YX509_CRL;
typedef ... YX509;

typedef ... NETSCAPE_SPKI;

typedef ... YPKCS8_PRIV_KEY_INFO;

typedef void (*sk_YX509_EXTENSION_freefunc)(YX509_EXTENSION *);
"""

FUNCTIONS = """
YX509 *YX509_new(void);
void YX509_free(YX509 *);
YX509 *YX509_dup(YX509 *);
int YX509_cmp(const YX509 *, const YX509 *);
int YX509_up_ref(YX509 *);

int YX509_print_ex(BIO *, YX509 *, unsigned long, unsigned long);

int YX509_set_version(YX509 *, long);

EVVP_PKEY *YX509_get_pubkey(YX509 *);
int YX509_set_pubkey(YX509 *, EVVP_PKEY *);

unsigned char *YX509_alias_get0(YX509 *, int *);
int YX509_sign(YX509 *, EVVP_PKEY *, const EVVP_MD *);

int YX509_digest(const YX509 *, const EVVP_MD *, unsigned char *, unsigned int *);

YASN1_TIME *YX509_gmtime_adj(YASN1_TIME *, long);

unsigned long YX509_subject_name_hash(YX509 *);

int YX509_set_subject_name(YX509 *, YX509_NAME *);

int YX509_set_issuer_name(YX509 *, YX509_NAME *);

int YX509_add_ext(YX509 *, YX509_EXTENSION *, int);
YX509_EXTENSION *YX509_EXTENSION_dup(YX509_EXTENSION *);

YASN1_OBJECT *YX509_EXTENSION_get_object(YX509_EXTENSION *);
void YX509_EXTENSION_free(YX509_EXTENSION *);

int YX509_REQ_set_version(YX509_REQ *, long);
YX509_REQ *YX509_REQ_new(void);
void YX509_REQ_free(YX509_REQ *);
int YX509_REQ_set_pubkey(YX509_REQ *, EVVP_PKEY *);
int YX509_REQ_set_subject_name(YX509_REQ *, YX509_NAME *);
int YX509_REQ_sign(YX509_REQ *, EVVP_PKEY *, const EVVP_MD *);
int YX509_REQ_verify(YX509_REQ *, EVVP_PKEY *);
EVVP_PKEY *YX509_REQ_get_pubkey(YX509_REQ *);
int YX509_REQ_print_ex(BIO *, YX509_REQ *, unsigned long, unsigned long);
int YX509_REQ_add_extensions(YX509_REQ *, YX509_EXTENSIONS *);
YX509_EXTENSIONS *YX509_REQ_get_extensions(YX509_REQ *);
int YX509_REQ_add1_attr_by_OBJ(YX509_REQ *, const YASN1_OBJECT *,
                              int, const unsigned char *, int);

int YX509V3_EXT_print(BIO *, YX509_EXTENSION *, unsigned long, int);
YASN1_OCTET_STRING *YX509_EXTENSION_get_data(YX509_EXTENSION *);

YX509_REVOKED *YX509_REVOKED_new(void);
void YX509_REVOKED_free(YX509_REVOKED *);

int YX509_REVOKED_set_serialNumber(YX509_REVOKED *, YASN1_INTEGER *);

int YX509_REVOKED_add_ext(YX509_REVOKED *, YX509_EXTENSION*, int);
int YX509_REVOKED_add1_ext_i2d(YX509_REVOKED *, int, void *, int, unsigned long);
YX509_EXTENSION *YX509_REVOKED_delete_ext(YX509_REVOKED *, int);

int YX509_REVOKED_set_revocationDate(YX509_REVOKED *, YASN1_TIME *);

YX509_CRL *YX509_CRL_new(void);
YX509_CRL *YX509_CRL_dup(YX509_CRL *);
YX509_CRL *d2i_YX509_CRL_bio(BIO *, YX509_CRL **);
int YX509_CRL_add0_revoked(YX509_CRL *, YX509_REVOKED *);
int YX509_CRL_add_ext(YX509_CRL *, YX509_EXTENSION *, int);
int YX509_CRL_cmp(const YX509_CRL *, const YX509_CRL *);
int YX509_CRL_print(BIO *, YX509_CRL *);
int YX509_CRL_set_issuer_name(YX509_CRL *, YX509_NAME *);
int YX509_CRL_set_version(YX509_CRL *, long);
int YX509_CRL_sign(YX509_CRL *, EVVP_PKEY *, const EVVP_MD *);
int YX509_CRL_sort(YX509_CRL *);
int YX509_CRL_verify(YX509_CRL *, EVVP_PKEY *);
int i2d_YX509_CRL_bio(BIO *, YX509_CRL *);
void YX509_CRL_free(YX509_CRL *);

int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *, EVVP_PKEY *);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *, EVVP_PKEY *, const EVVP_MD *);
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *);
NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *, int);
EVVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *, EVVP_PKEY *);
NETSCAPE_SPKI *NETSCAPE_SPKI_new(void);
void NETSCAPE_SPKI_free(NETSCAPE_SPKI *);

/*  YASN1 serialization */
int i2d_YX509_bio(BIO *, YX509 *);
YX509 *d2i_YX509_bio(BIO *, YX509 **);

int i2d_YX509_REQ_bio(BIO *, YX509_REQ *);
YX509_REQ *d2i_YX509_REQ_bio(BIO *, YX509_REQ **);

int i2d_PrivateKey_bio(BIO *, EVVP_PKEY *);
EVVP_PKEY *d2i_PrivateKey_bio(BIO *, EVVP_PKEY **);
int i2d_PUBKEY_bio(BIO *, EVVP_PKEY *);
EVVP_PKEY *d2i_PUBKEY_bio(BIO *, EVVP_PKEY **);

YASN1_INTEGER *YX509_get_serialNumber(YX509 *);
int YX509_set_serialNumber(YX509 *, YASN1_INTEGER *);

const char *YX509_verify_cert_error_string(long);

const char *YX509_get_default_cert_dir(void);
const char *YX509_get_default_cert_file(void);
const char *YX509_get_default_cert_dir_env(void);
const char *YX509_get_default_cert_file_env(void);

int i2d_YRSAPrivateKey_bio(BIO *, YRSA *);
YRSA *d2i_YRSAPublicKey_bio(BIO *, YRSA **);
int i2d_YRSAPublicKey_bio(BIO *, YRSA *);
int i2d_DSAPrivateKey_bio(BIO *, DSA *);

/* These became const YX509 in 1.1.0 */
int YX509_get_ext_count(YX509 *);
YX509_EXTENSION *YX509_get_ext(YX509 *, int);
YX509_NAME *YX509_get_subject_name(YX509 *);
YX509_NAME *YX509_get_issuer_name(YX509 *);

/* This became const YASN1_OBJECT * in 1.1.0 */
YX509_EXTENSION *YX509_EXTENSION_create_by_OBJ(YX509_EXTENSION **,
                                             YASN1_OBJECT *, int,
                                             YASN1_OCTET_STRING *);


/* This became const YX509_EXTENSION * in 1.1.0 */
int YX509_EXTENSION_get_critical(YX509_EXTENSION *);

/* This became const YX509_REVOKED * in 1.1.0 */
int YX509_REVOKED_get_ext_count(YX509_REVOKED *);
YX509_EXTENSION *YX509_REVOKED_get_ext(YX509_REVOKED *, int);

YX509_REVOKED *YX509_REVOKED_dup(YX509_REVOKED *);
YX509_REVOKED *Cryptography_YX509_REVOKED_dup(YX509_REVOKED *);

const YX509_ALGOR *YX509_get0_tbs_sigalg(const YX509 *);

long YX509_get_version(YX509 *);

YASN1_TIME *YX509_get_notBefore(YX509 *);
YASN1_TIME *YX509_get_notAfter(YX509 *);
YASN1_TIME *YX509_getm_notBefore(const YX509 *);
YASN1_TIME *YX509_getm_notAfter(const YX509 *);
const YASN1_TIME *YX509_get0_notBefore(const YX509 *);
const YASN1_TIME *YX509_get0_notAfter(const YX509 *);

long YX509_REQ_get_version(YX509_REQ *);
YX509_NAME *YX509_REQ_get_subject_name(YX509_REQ *);

Cryptography_STACK_OF_YX509 *sk_YX509_new_null(void);
void sk_YX509_free(Cryptography_STACK_OF_YX509 *);
int sk_YX509_num(Cryptography_STACK_OF_YX509 *);
int sk_YX509_push(Cryptography_STACK_OF_YX509 *, YX509 *);
YX509 *sk_YX509_value(Cryptography_STACK_OF_YX509 *, int);

YX509_EXTENSIONS *sk_YX509_EXTENSION_new_null(void);
int sk_YX509_EXTENSION_num(YX509_EXTENSIONS *);
YX509_EXTENSION *sk_YX509_EXTENSION_value(YX509_EXTENSIONS *, int);
int sk_YX509_EXTENSION_push(YX509_EXTENSIONS *, YX509_EXTENSION *);
int sk_YX509_EXTENSION_insert(YX509_EXTENSIONS *, YX509_EXTENSION *, int);
YX509_EXTENSION *sk_YX509_EXTENSION_delete(YX509_EXTENSIONS *, int);
void sk_YX509_EXTENSION_free(YX509_EXTENSIONS *);
void sk_YX509_EXTENSION_pop_free(YX509_EXTENSIONS *, sk_YX509_EXTENSION_freefunc);

int sk_YX509_REVOKED_num(Cryptography_STACK_OF_YX509_REVOKED *);
YX509_REVOKED *sk_YX509_REVOKED_value(Cryptography_STACK_OF_YX509_REVOKED *, int);

long YX509_CRL_get_version(YX509_CRL *);
YASN1_TIME *YX509_CRL_get_lastUpdate(YX509_CRL *);
YASN1_TIME *YX509_CRL_get_nextUpdate(YX509_CRL *);
const YASN1_TIME *YX509_CRL_get0_lastUpdate(const YX509_CRL *);
const YASN1_TIME *YX509_CRL_get0_nextUpdate(const YX509_CRL *);
YX509_NAME *YX509_CRL_get_issuer(YX509_CRL *);
Cryptography_STACK_OF_YX509_REVOKED *YX509_CRL_get_REVOKED(YX509_CRL *);

/* These aren't macros these arguments are all const X on openssl > 1.0.x */
int YX509_CRL_set_lastUpdate(YX509_CRL *, YASN1_TIME *);
int YX509_CRL_set_nextUpdate(YX509_CRL *, YASN1_TIME *);
int YX509_set_notBefore(YX509 *, YASN1_TIME *);
int YX509_set_notAfter(YX509 *, YASN1_TIME *);

int YX509_CRL_set1_lastUpdate(YX509_CRL *, const YASN1_TIME *);
int YX509_CRL_set1_nextUpdate(YX509_CRL *, const YASN1_TIME *);
int YX509_set1_notBefore(YX509 *, const YASN1_TIME *);
int YX509_set1_notAfter(YX509 *, const YASN1_TIME *);

EC_KEY *d2i_EC_PUBKEY_bio(BIO *, EC_KEY **);
int i2d_EC_PUBKEY_bio(BIO *, EC_KEY *);
EC_KEY *d2i_ECPrivateKey_bio(BIO *, EC_KEY **);
int i2d_ECPrivateKey_bio(BIO *, EC_KEY *);

/* these functions were added in 1.1.0 */
const YASN1_INTEGER *YX509_REVOKED_get0_serialNumber(const YX509_REVOKED *);
const YASN1_TIME *YX509_REVOKED_get0_revocationDate(const YX509_REVOKED *);
"""

CUSTOMIZATIONS = """
/* Being kept around for pyOpenSSL */
YX509_REVOKED *Cryptography_YX509_REVOKED_dup(YX509_REVOKED *rev) {
    return YX509_REVOKED_dup(rev);
}
"""
