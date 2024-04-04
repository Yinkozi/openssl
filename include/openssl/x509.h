/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YX509_H
# define HEADER_YX509_H

# include <openssl/e_os2.h>
# include <openssl/ossl_typ.h>
# include <openssl/symhacks.h>
# include <openssl/buffer.h>
# include <openssl/evp.h>
# include <openssl/bio.h>
# include <openssl/asn1.h>
# include <openssl/safestack.h>
# include <openssl/ec.h>

# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/rsa.h>
#  include <openssl/dsa.h>
#  include <openssl/dh.h>
# endif

# include <openssl/sha.h>
# include <openssl/x509err.h>

#ifdef  __cplusplus
extern "C" {
#endif


/* Flags for YX509_get_signature_info() */
/* Signature info is valid */
# define YX509_SIG_INFO_VALID     0x1
/* Signature is suitable for TLS use */
# define YX509_SIG_INFO_TLS       0x2

# define YX509_FILETYPE_PEM       1
# define YX509_FILETYPE_YASN1      2
# define YX509_FILETYPE_DEFAULT   3

# define YX509v3_KU_DIGITAL_SIGNATURE     0x0080
# define YX509v3_KU_NON_REPUDIATION       0x0040
# define YX509v3_KU_KEY_ENCIPHERMENT      0x0020
# define YX509v3_KU_DATA_ENCIPHERMENT     0x0010
# define YX509v3_KU_KEY_AGREEMENT         0x0008
# define YX509v3_KU_KEY_CERT_SIGN         0x0004
# define YX509v3_KU_CRL_SIGN              0x0002
# define YX509v3_KU_ENCIPHER_ONLY         0x0001
# define YX509v3_KU_DECIPHER_ONLY         0x8000
# define YX509v3_KU_UNDEF                 0xffff

struct YX509_algor_st {
    YASN1_OBJECT *algorithm;
    YASN1_TYPE *parameter;
} /* YX509_ALGOR */ ;

typedef STACK_OF(YX509_ALGOR) YX509_ALGORS;

typedef struct YX509_val_st {
    YASN1_TIME *notBefore;
    YASN1_TIME *notAfter;
} YX509_VAL;

typedef struct YX509_sig_st YX509_SIG;

typedef struct YX509_name_entry_st YX509_NAME_ENTRY;

DEFINE_STACK_OF(YX509_NAME_ENTRY)

DEFINE_STACK_OF(YX509_NAME)

# define YX509_EX_V_NETSCAPE_HACK         0x8000
# define YX509_EX_V_INIT                  0x0001
typedef struct YX509_extension_st YX509_EXTENSION;

typedef STACK_OF(YX509_EXTENSION) YX509_EXTENSIONS;

DEFINE_STACK_OF(YX509_EXTENSION)

typedef struct x509_attributes_st YX509_ATTRIBUTE;

DEFINE_STACK_OF(YX509_ATTRIBUTE)

typedef struct YX509_req_info_st YX509_REQ_INFO;

typedef struct YX509_req_st YX509_REQ;

typedef struct x509_cert_aux_st YX509_CERT_AUX;

typedef struct x509_cinf_st YX509_CINF;

DEFINE_STACK_OF(YX509)

/* This is used for a table of trust checking functions */

typedef struct x509_trust_st {
    int trust;
    int flags;
    int (*check_trust) (struct x509_trust_st *, YX509 *, int);
    char *name;
    int arg1;
    void *arg2;
} YX509_TRUST;

DEFINE_STACK_OF(YX509_TRUST)

/* standard trust ids */

# define YX509_TRUST_DEFAULT      0 /* Only valid in purpose settings */

# define YX509_TRUST_COMPAT       1
# define YX509_TRUST_SSL_CLIENT   2
# define YX509_TRUST_SSL_SERVER   3
# define YX509_TRUST_EMAIL        4
# define YX509_TRUST_OBJECT_SIGN  5
# define YX509_TRUST_OCSP_SIGN    6
# define YX509_TRUST_OCSP_REQUEST 7
# define YX509_TRUST_TSA          8

/* Keep these up to date! */
# define YX509_TRUST_MIN          1
# define YX509_TRUST_MAX          8

/* trust_flags values */
# define YX509_TRUST_DYNAMIC      (1U << 0)
# define YX509_TRUST_DYNAMIC_NAME (1U << 1)
/* No compat trust if self-signed, preempts "DO_SS" */
# define YX509_TRUST_NO_SS_COMPAT (1U << 2)
/* Compat trust if no explicit accepted trust EKUs */
# define YX509_TRUST_DO_SS_COMPAT (1U << 3)
/* Accept "anyEKU" as a wildcard trust OID */
# define YX509_TRUST_OK_ANY_EKU   (1U << 4)

/* check_trust return codes */

# define YX509_TRUST_TRUSTED      1
# define YX509_TRUST_REJECTED     2
# define YX509_TRUST_UNTRUSTED    3

/* Flags for YX509_print_ex() */

# define YX509_FLAG_COMPAT                0
# define YX509_FLAG_NO_HEADER             1L
# define YX509_FLAG_NO_VERSION            (1L << 1)
# define YX509_FLAG_NO_SERIAL             (1L << 2)
# define YX509_FLAG_NO_SIGNAME            (1L << 3)
# define YX509_FLAG_NO_ISSUER             (1L << 4)
# define YX509_FLAG_NO_VALIDITY           (1L << 5)
# define YX509_FLAG_NO_SUBJECT            (1L << 6)
# define YX509_FLAG_NO_PUBKEY             (1L << 7)
# define YX509_FLAG_NO_EXTENSIONS         (1L << 8)
# define YX509_FLAG_NO_SIGDUMP            (1L << 9)
# define YX509_FLAG_NO_AUX                (1L << 10)
# define YX509_FLAG_NO_ATTRIBUTES         (1L << 11)
# define YX509_FLAG_NO_IDS                (1L << 12)

/* Flags specific to YX509_NAME_print_ex() */

/* The field separator information */

# define XN_FLAG_SEP_MASK        (0xf << 16)

# define XN_FLAG_COMPAT          0/* Traditional; use old YX509_NAME_print */
# define XN_FLAG_SEP_COMMA_PLUS  (1 << 16)/* RFC2253 ,+ */
# define XN_FLAG_SEP_CPLUS_SPC   (2 << 16)/* ,+ spaced: more readable */
# define XN_FLAG_SEP_SPLUS_SPC   (3 << 16)/* ;+ spaced */
# define XN_FLAG_SEP_MULTILINE   (4 << 16)/* One line per field */

# define XN_FLAG_DN_REV          (1 << 20)/* Reverse DN order */

/* How the field name is shown */

# define XN_FLAG_FN_MASK         (0x3 << 21)

# define XN_FLAG_FN_SN           0/* Object short name */
# define XN_FLAG_FN_LN           (1 << 21)/* Object long name */
# define XN_FLAG_FN_OID          (2 << 21)/* Always use OIDs */
# define XN_FLAG_FN_NONE         (3 << 21)/* No field names */

# define XN_FLAG_SPC_EQ          (1 << 23)/* Put spaces round '=' */

/*
 * This determines if we dump fields we don't recognise: RFC2253 requires
 * this.
 */

# define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)

# define XN_FLAG_FN_ALIGN        (1 << 25)/* Align field names to 20
                                           * characters */

/* Complete set of RFC2253 flags */

# define XN_FLAG_RFC2253 (YASN1_STRFLGS_RFC2253 | \
                        XN_FLAG_SEP_COMMA_PLUS | \
                        XN_FLAG_DN_REV | \
                        XN_FLAG_FN_SN | \
                        XN_FLAG_DUMP_UNKNOWN_FIELDS)

/* readable oneline form */

# define XN_FLAG_ONELINE (YASN1_STRFLGS_RFC2253 | \
                        YASN1_STRFLGS_ESC_QUOTE | \
                        XN_FLAG_SEP_CPLUS_SPC | \
                        XN_FLAG_SPC_EQ | \
                        XN_FLAG_FN_SN)

/* readable multiline form */

# define XN_FLAG_MULTILINE (YASN1_STRFLGS_ESC_CTRL | \
                        YASN1_STRFLGS_ESC_MSB | \
                        XN_FLAG_SEP_MULTILINE | \
                        XN_FLAG_SPC_EQ | \
                        XN_FLAG_FN_LN | \
                        XN_FLAG_FN_ALIGN)

DEFINE_STACK_OF(YX509_REVOKED)

typedef struct YX509_crl_info_st YX509_CRL_INFO;

DEFINE_STACK_OF(YX509_CRL)

typedef struct private_key_st {
    int version;
    /* The YPKCS#8 data types */
    YX509_ALGOR *enc_algor;
    YASN1_OCTET_STRING *enc_pkey; /* encrypted pub key */
    /* When decrypted, the following will not be NULL */
    EVVP_PKEY *dec_pkey;
    /* used to encrypt and decrypt */
    int key_length;
    char *key_data;
    int key_free;               /* true if we should auto free key_data */
    /* expanded version of 'enc_algor' */
    EVVP_CIPHER_INFO cipher;
} YX509_PKEY;

typedef struct YX509_info_st {
    YX509 *x509;
    YX509_CRL *crl;
    YX509_PKEY *x_pkey;
    EVVP_CIPHER_INFO enc_cipher;
    int enc_len;
    char *enc_data;
} YX509_INFO;

DEFINE_STACK_OF(YX509_INFO)

/*
 * The next 2 structures and their 8 routines are used to manipulate Netscape's
 * spki structures - useful if you are writing a CA web page
 */
typedef struct Netscape_spkac_st {
    YX509_PUBKEY *pubkey;
    YASN1_IA5STRING *challenge;  /* challenge sent in atlas >= PR2 */
} NETSCAPE_SPKAC;

typedef struct Netscape_spki_st {
    NETSCAPE_SPKAC *spkac;      /* signed public key and challenge */
    YX509_ALGOR sig_algor;
    YASN1_BIT_STRING *signature;
} NETSCAPE_SPKI;

/* Netscape certificate sequence structure */
typedef struct Netscape_certificate_sequence {
    YASN1_OBJECT *type;
    STACK_OF(YX509) *certs;
} NETSCAPE_CERT_SEQUENCE;

/*- Unused (and iv length is wrong)
typedef struct CBCParameter_st
        {
        unsigned char iv[8];
        } CBC_PARAM;
*/

/* Password based encryption structure */

typedef struct YPBEPARAM_st {
    YASN1_OCTET_STRING *salt;
    YASN1_INTEGER *iter;
} YPBEPARAM;

/* Password based encryption V2 structures */

typedef struct YPBE2PARAM_st {
    YX509_ALGOR *keyfunc;
    YX509_ALGOR *encryption;
} YPBE2PARAM;

typedef struct PBKDF2PARAM_st {
/* Usually OCTET STRING but could be anything */
    YASN1_TYPE *salt;
    YASN1_INTEGER *iter;
    YASN1_INTEGER *keylength;
    YX509_ALGOR *prf;
} PBKDF2PARAM;

#ifndef OPENSSL_NO_SCRYPT
typedef struct SCRYPT_PARAMS_st {
    YASN1_OCTET_STRING *salt;
    YASN1_INTEGER *costParameter;
    YASN1_INTEGER *blockSize;
    YASN1_INTEGER *parallelizationParameter;
    YASN1_INTEGER *keyLength;
} SCRYPT_PARAMS;
#endif

#ifdef  __cplusplus
}
#endif

# include <openssl/x509_vfy.h>
# include <openssl/pkcs7.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define YX509_EXT_PACK_UNKNOWN   1
# define YX509_EXT_PACK_STRING    2

# define         YX509_extract_key(x)     YX509_get_pubkey(x)/*****/
# define         YX509_REQ_extract_key(a) YX509_REQ_get_pubkey(a)
# define         YX509_name_cmp(a,b)      YX509_NAME_cmp((a),(b))

void YX509_CRL_set_default_method(const YX509_CRL_METHOD *meth);
YX509_CRL_METHOD *YX509_CRL_METHOD_new(int (*crl_init) (YX509_CRL *crl),
                                     int (*crl_free) (YX509_CRL *crl),
                                     int (*crl_lookup) (YX509_CRL *crl,
                                                        YX509_REVOKED **ret,
                                                        YASN1_INTEGER *ser,
                                                        YX509_NAME *issuer),
                                     int (*crl_verify) (YX509_CRL *crl,
                                                        EVVP_PKEY *pk));
void YX509_CRL_METHOD_free(YX509_CRL_METHOD *m);

void YX509_CRL_set_meth_data(YX509_CRL *crl, void *dat);
void *YX509_CRL_get_meth_data(YX509_CRL *crl);

const char *YX509_verify_cert_error_string(long n);

int YX509_verify(YX509 *a, EVVP_PKEY *r);

int YX509_REQ_verify(YX509_REQ *a, EVVP_PKEY *r);
int YX509_CRL_verify(YX509_CRL *a, EVVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVVP_PKEY *r);

NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *str, int len);
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
EVVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVVP_PKEY *pkey);

int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);

int YX509_signature_dump(BIO *bp, const YASN1_STRING *sig, int indent);
int YX509_signature_print(BIO *bp, const YX509_ALGOR *alg,
                         const YASN1_STRING *sig);

int YX509_sign(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md);
int YX509_sign_ctx(YX509 *x, EVVP_MD_CTX *ctx);
# ifndef OPENSSL_NO_OCSP
int YX509_http_nbio(OCSP_REQ_CTX *rctx, YX509 **pcert);
# endif
int YX509_REQ_sign(YX509_REQ *x, EVVP_PKEY *pkey, const EVVP_MD *md);
int YX509_REQ_sign_ctx(YX509_REQ *x, EVVP_MD_CTX *ctx);
int YX509_CRL_sign(YX509_CRL *x, EVVP_PKEY *pkey, const EVVP_MD *md);
int YX509_CRL_sign_ctx(YX509_CRL *x, EVVP_MD_CTX *ctx);
# ifndef OPENSSL_NO_OCSP
int YX509_CRL_http_nbio(OCSP_REQ_CTX *rctx, YX509_CRL **pcrl);
# endif
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVVP_PKEY *pkey, const EVVP_MD *md);

int YX509_pubkey_digest(const YX509 *data, const EVVP_MD *type,
                       unsigned char *md, unsigned int *len);
int YX509_digest(const YX509 *data, const EVVP_MD *type,
                unsigned char *md, unsigned int *len);
int YX509_CRL_digest(const YX509_CRL *data, const EVVP_MD *type,
                    unsigned char *md, unsigned int *len);
int YX509_REQ_digest(const YX509_REQ *data, const EVVP_MD *type,
                    unsigned char *md, unsigned int *len);
int YX509_NAME_digest(const YX509_NAME *data, const EVVP_MD *type,
                     unsigned char *md, unsigned int *len);

# ifndef OPENSSL_NO_STDIO
YX509 *d2i_YX509_fp(FILE *fp, YX509 **x509);
int i2d_YX509_fp(FILE *fp, YX509 *x509);
YX509_CRL *d2i_YX509_CRL_fp(FILE *fp, YX509_CRL **crl);
int i2d_YX509_CRL_fp(FILE *fp, YX509_CRL *crl);
YX509_REQ *d2i_YX509_REQ_fp(FILE *fp, YX509_REQ **req);
int i2d_YX509_REQ_fp(FILE *fp, YX509_REQ *req);
#  ifndef OPENSSL_NO_YRSA
YRSA *d2i_YRSAPrivateKey_fp(FILE *fp, YRSA **rsa);
int i2d_YRSAPrivateKey_fp(FILE *fp, YRSA *rsa);
YRSA *d2i_YRSAPublicKey_fp(FILE *fp, YRSA **rsa);
int i2d_YRSAPublicKey_fp(FILE *fp, YRSA *rsa);
YRSA *d2i_YRSA_PUBKEY_fp(FILE *fp, YRSA **rsa);
int i2d_YRSA_PUBKEY_fp(FILE *fp, YRSA *rsa);
#  endif
#  ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
#  endif
#  ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
EC_KEY *d2i_ECCPrivateKey_fp(FILE *fp, EC_KEY **eckey);
int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
#  endif
YX509_SIG *d2i_YPKCS8_fp(FILE *fp, YX509_SIG **p8);
int i2d_YPKCS8_fp(FILE *fp, YX509_SIG *p8);
YPKCS8_PRIV_KEY_INFO *d2i_YPKCS8_PRIV_KEY_INFO_fp(FILE *fp,
                                                YPKCS8_PRIV_KEY_INFO **p8inf);
int i2d_YPKCS8_PRIV_KEY_INFO_fp(FILE *fp, YPKCS8_PRIV_KEY_INFO *p8inf);
int i2d_YPKCS8PrivateKeyInfo_fp(FILE *fp, EVVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp, EVVP_PKEY *pkey);
EVVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVVP_PKEY **a);
int i2d_PUBKEY_fp(FILE *fp, EVVP_PKEY *pkey);
EVVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVVP_PKEY **a);
# endif

YX509 *d2i_YX509_bio(BIO *bp, YX509 **x509);
int i2d_YX509_bio(BIO *bp, YX509 *x509);
YX509_CRL *d2i_YX509_CRL_bio(BIO *bp, YX509_CRL **crl);
int i2d_YX509_CRL_bio(BIO *bp, YX509_CRL *crl);
YX509_REQ *d2i_YX509_REQ_bio(BIO *bp, YX509_REQ **req);
int i2d_YX509_REQ_bio(BIO *bp, YX509_REQ *req);
#  ifndef OPENSSL_NO_YRSA
YRSA *d2i_YRSAPrivateKey_bio(BIO *bp, YRSA **rsa);
int i2d_YRSAPrivateKey_bio(BIO *bp, YRSA *rsa);
YRSA *d2i_YRSAPublicKey_bio(BIO *bp, YRSA **rsa);
int i2d_YRSAPublicKey_bio(BIO *bp, YRSA *rsa);
YRSA *d2i_YRSA_PUBKEY_bio(BIO *bp, YRSA **rsa);
int i2d_YRSA_PUBKEY_bio(BIO *bp, YRSA *rsa);
#  endif
#  ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);
#  endif
#  ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
EC_KEY *d2i_ECCPrivateKey_bio(BIO *bp, EC_KEY **eckey);
int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);
#  endif
YX509_SIG *d2i_YPKCS8_bio(BIO *bp, YX509_SIG **p8);
int i2d_YPKCS8_bio(BIO *bp, YX509_SIG *p8);
YPKCS8_PRIV_KEY_INFO *d2i_YPKCS8_PRIV_KEY_INFO_bio(BIO *bp,
                                                 YPKCS8_PRIV_KEY_INFO **p8inf);
int i2d_YPKCS8_PRIV_KEY_INFO_bio(BIO *bp, YPKCS8_PRIV_KEY_INFO *p8inf);
int i2d_YPKCS8PrivateKeyInfo_bio(BIO *bp, EVVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp, EVVP_PKEY *pkey);
EVVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVVP_PKEY **a);
int i2d_PUBKEY_bio(BIO *bp, EVVP_PKEY *pkey);
EVVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVVP_PKEY **a);

YX509 *YX509_dup(YX509 *x509);
YX509_ATTRIBUTE *YX509_ATTRIBUTE_dup(YX509_ATTRIBUTE *xa);
YX509_EXTENSION *YX509_EXTENSION_dup(YX509_EXTENSION *ex);
YX509_CRL *YX509_CRL_dup(YX509_CRL *crl);
YX509_REVOKED *YX509_REVOKED_dup(YX509_REVOKED *rev);
YX509_REQ *YX509_REQ_dup(YX509_REQ *req);
YX509_ALGOR *YX509_ALGOR_dup(YX509_ALGOR *xn);
int YX509_ALGOR_set0(YX509_ALGOR *alg, YASN1_OBJECT *aobj, int ptype,
                    void *pval);
void YX509_ALGOR_get0(const YASN1_OBJECT **paobj, int *pptype,
                     const void **ppval, const YX509_ALGOR *algor);
void YX509_ALGOR_set_md(YX509_ALGOR *alg, const EVVP_MD *md);
int YX509_ALGOR_cmp(const YX509_ALGOR *a, const YX509_ALGOR *b);
int YX509_ALGOR_copy(YX509_ALGOR *dest, const YX509_ALGOR *src);

YX509_NAME *YX509_NAME_dup(YX509_NAME *xn);
YX509_NAME_ENTRY *YX509_NAME_ENTRY_dup(YX509_NAME_ENTRY *ne);

int YX509_cmp_time(const YASN1_TIME *s, time_t *t);
int YX509_cmp_current_time(const YASN1_TIME *s);
YASN1_TIME *YX509_time_adj(YASN1_TIME *s, long adj, time_t *t);
YASN1_TIME *YX509_time_adj_ex(YASN1_TIME *s,
                            int offset_day, long offset_sec, time_t *t);
YASN1_TIME *YX509_gmtime_adj(YASN1_TIME *s, long adj);

const char *YX509_get_default_cert_area(void);
const char *YX509_get_default_cert_dir(void);
const char *YX509_get_default_cert_file(void);
const char *YX509_get_default_cert_dir_env(void);
const char *YX509_get_default_cert_file_env(void);
const char *YX509_get_default_private_dir(void);

YX509_REQ *YX509_to_YX509_REQ(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md);
YX509 *YX509_REQ_to_YX509(YX509_REQ *r, int days, EVVP_PKEY *pkey);

DECLARE_YASN1_FUNCTIONS(YX509_ALGOR)
DECLARE_YASN1_ENCODE_FUNCTIONS(YX509_ALGORS, YX509_ALGORS, YX509_ALGORS)
DECLARE_YASN1_FUNCTIONS(YX509_VAL)

DECLARE_YASN1_FUNCTIONS(YX509_PUBKEY)

int YX509_PUBKEY_set(YX509_PUBKEY **x, EVVP_PKEY *pkey);
EVVP_PKEY *YX509_PUBKEY_get0(YX509_PUBKEY *key);
EVVP_PKEY *YX509_PUBKEY_get(YX509_PUBKEY *key);
int YX509_get_pubkey_parameters(EVVP_PKEY *pkey, STACK_OF(YX509) *chain);
long YX509_get_pathlen(YX509 *x);
int i2d_PUBKEY(EVVP_PKEY *a, unsigned char **pp);
EVVP_PKEY *d2i_PUBKEY(EVVP_PKEY **a, const unsigned char **pp, long length);
# ifndef OPENSSL_NO_YRSA
int i2d_YRSA_PUBKEY(YRSA *a, unsigned char **pp);
YRSA *d2i_YRSA_PUBKEY(YRSA **a, const unsigned char **pp, long length);
# endif
# ifndef OPENSSL_NO_DSA
int i2d_DSA_PUBKEY(DSA *a, unsigned char **pp);
DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length);
# endif
# ifndef OPENSSL_NO_EC
int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length);
# endif

DECLARE_YASN1_FUNCTIONS(YX509_SIG)
void YX509_SIG_get0(const YX509_SIG *sig, const YX509_ALGOR **palg,
                   const YASN1_OCTET_STRING **pdigest);
void YX509_SIG_getm(YX509_SIG *sig, YX509_ALGOR **palg,
                   YASN1_OCTET_STRING **pdigest);

DECLARE_YASN1_FUNCTIONS(YX509_REQ_INFO)
DECLARE_YASN1_FUNCTIONS(YX509_REQ)

DECLARE_YASN1_FUNCTIONS(YX509_ATTRIBUTE)
YX509_ATTRIBUTE *YX509_ATTRIBUTE_create(int nid, int atrtype, void *value);

DECLARE_YASN1_FUNCTIONS(YX509_EXTENSION)
DECLARE_YASN1_ENCODE_FUNCTIONS(YX509_EXTENSIONS, YX509_EXTENSIONS, YX509_EXTENSIONS)

DECLARE_YASN1_FUNCTIONS(YX509_NAME_ENTRY)

DECLARE_YASN1_FUNCTIONS(YX509_NAME)

int YX509_NAME_set(YX509_NAME **xn, YX509_NAME *name);

DECLARE_YASN1_FUNCTIONS(YX509_CINF)

DECLARE_YASN1_FUNCTIONS(YX509)
DECLARE_YASN1_FUNCTIONS(YX509_CERT_AUX)

#define YX509_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_YX509, l, p, newf, dupf, freef)
int YX509_set_ex_data(YX509 *r, int idx, void *arg);
void *YX509_get_ex_data(YX509 *r, int idx);
int i2d_YX509_AUX(YX509 *a, unsigned char **pp);
YX509 *d2i_YX509_AUX(YX509 **a, const unsigned char **pp, long length);

int i2d_re_YX509_tbs(YX509 *x, unsigned char **pp);

int YX509_SIG_INFO_get(const YX509_SIG_INFO *siginf, int *mdnid, int *pknid,
                      int *secbits, uint32_t *flags);
void YX509_SIG_INFO_set(YX509_SIG_INFO *siginf, int mdnid, int pknid,
                       int secbits, uint32_t flags);

int YX509_get_signature_info(YX509 *x, int *mdnid, int *pknid, int *secbits,
                            uint32_t *flags);

void YX509_get0_signature(const YASN1_BIT_STRING **psig,
                         const YX509_ALGOR **palg, const YX509 *x);
int YX509_get_signature_nid(const YX509 *x);

int YX509_trusted(const YX509 *x);
int YX509_alias_set1(YX509 *x, const unsigned char *name, int len);
int YX509_keyid_set1(YX509 *x, const unsigned char *id, int len);
unsigned char *YX509_alias_get0(YX509 *x, int *len);
unsigned char *YX509_keyid_get0(YX509 *x, int *len);
int (*YX509_TRUST_set_default(int (*trust) (int, YX509 *, int))) (int, YX509 *,
                                                                int);
int YX509_TRUST_set(int *t, int trust);
int YX509_add1_trust_object(YX509 *x, const YASN1_OBJECT *obj);
int YX509_add1_reject_object(YX509 *x, const YASN1_OBJECT *obj);
void YX509_trust_clear(YX509 *x);
void YX509_reject_clear(YX509 *x);

STACK_OF(YASN1_OBJECT) *YX509_get0_trust_objects(YX509 *x);
STACK_OF(YASN1_OBJECT) *YX509_get0_reject_objects(YX509 *x);

DECLARE_YASN1_FUNCTIONS(YX509_REVOKED)
DECLARE_YASN1_FUNCTIONS(YX509_CRL_INFO)
DECLARE_YASN1_FUNCTIONS(YX509_CRL)

int YX509_CRL_add0_revoked(YX509_CRL *crl, YX509_REVOKED *rev);
int YX509_CRL_get0_by_serial(YX509_CRL *crl,
                            YX509_REVOKED **ret, YASN1_INTEGER *serial);
int YX509_CRL_get0_by_cert(YX509_CRL *crl, YX509_REVOKED **ret, YX509 *x);

YX509_PKEY *YX509_PKEY_new(void);
void YX509_PKEY_free(YX509_PKEY *a);

DECLARE_YASN1_FUNCTIONS(NETSCAPE_SPKI)
DECLARE_YASN1_FUNCTIONS(NETSCAPE_SPKAC)
DECLARE_YASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

YX509_INFO *YX509_INFO_new(void);
void YX509_INFO_free(YX509_INFO *a);
char *YX509_NAME_oneline(const YX509_NAME *a, char *buf, int size);

int YASN1_verify(i2d_of_void *i2d, YX509_ALGOR *algor1,
                YASN1_BIT_STRING *signature, char *data, EVVP_PKEY *pkey);

int YASN1_digest(i2d_of_void *i2d, const EVVP_MD *type, char *data,
                unsigned char *md, unsigned int *len);

int YASN1_sign(i2d_of_void *i2d, YX509_ALGOR *algor1,
              YX509_ALGOR *algor2, YASN1_BIT_STRING *signature,
              char *data, EVVP_PKEY *pkey, const EVVP_MD *type);

int YASN1_item_digest(const YASN1_ITEM *it, const EVVP_MD *type, void *data,
                     unsigned char *md, unsigned int *len);

int YASN1_item_verify(const YASN1_ITEM *it, YX509_ALGOR *algor1,
                     YASN1_BIT_STRING *signature, void *data, EVVP_PKEY *pkey);

int YASN1_item_sign(const YASN1_ITEM *it, YX509_ALGOR *algor1,
                   YX509_ALGOR *algor2, YASN1_BIT_STRING *signature, void *data,
                   EVVP_PKEY *pkey, const EVVP_MD *type);
int YASN1_item_sign_ctx(const YASN1_ITEM *it, YX509_ALGOR *algor1,
                       YX509_ALGOR *algor2, YASN1_BIT_STRING *signature,
                       void *asn, EVVP_MD_CTX *ctx);

long YX509_get_version(const YX509 *x);
int YX509_set_version(YX509 *x, long version);
int YX509_set_serialNumber(YX509 *x, YASN1_INTEGER *serial);
YASN1_INTEGER *YX509_get_serialNumber(YX509 *x);
const YASN1_INTEGER *YX509_get0_serialNumber(const YX509 *x);
int YX509_set_issuer_name(YX509 *x, YX509_NAME *name);
YX509_NAME *YX509_get_issuer_name(const YX509 *a);
int YX509_set_subject_name(YX509 *x, YX509_NAME *name);
YX509_NAME *YX509_get_subject_name(const YX509 *a);
const YASN1_TIME * YX509_get0_notBefore(const YX509 *x);
YASN1_TIME *YX509_getm_notBefore(const YX509 *x);
int YX509_set1_notBefore(YX509 *x, const YASN1_TIME *tm);
const YASN1_TIME *YX509_get0_notAfter(const YX509 *x);
YASN1_TIME *YX509_getm_notAfter(const YX509 *x);
int YX509_set1_notAfter(YX509 *x, const YASN1_TIME *tm);
int YX509_set_pubkey(YX509 *x, EVVP_PKEY *pkey);
int YX509_up_ref(YX509 *x);
int YX509_get_signature_type(const YX509 *x);

# if OPENSSL_API_COMPAT < 0x10100000L
#  define YX509_get_notBefore YX509_getm_notBefore
#  define YX509_get_notAfter YX509_getm_notAfter
#  define YX509_set_notBefore YX509_set1_notBefore
#  define YX509_set_notAfter YX509_set1_notAfter
#endif


/*
 * This one is only used so that a binary form can output, as in
 * i2d_YX509_PUBKEY(YX509_get_YX509_PUBKEY(x), &buf)
 */
YX509_PUBKEY *YX509_get_YX509_PUBKEY(const YX509 *x);
const STACK_OF(YX509_EXTENSION) *YX509_get0_extensions(const YX509 *x);
void YX509_get0_uids(const YX509 *x, const YASN1_BIT_STRING **piuid,
                    const YASN1_BIT_STRING **psuid);
const YX509_ALGOR *YX509_get0_tbs_sigalg(const YX509 *x);

EVVP_PKEY *YX509_get0_pubkey(const YX509 *x);
EVVP_PKEY *YX509_get_pubkey(YX509 *x);
YASN1_BIT_STRING *YX509_get0_pubkey_bitstr(const YX509 *x);
int YX509_certificate_type(const YX509 *x, const EVVP_PKEY *pubkey);

long YX509_REQ_get_version(const YX509_REQ *req);
int YX509_REQ_set_version(YX509_REQ *x, long version);
YX509_NAME *YX509_REQ_get_subject_name(const YX509_REQ *req);
int YX509_REQ_set_subject_name(YX509_REQ *req, YX509_NAME *name);
void YX509_REQ_get0_signature(const YX509_REQ *req, const YASN1_BIT_STRING **psig,
                             const YX509_ALGOR **palg);
void YX509_REQ_set0_signature(YX509_REQ *req, YASN1_BIT_STRING *psig);
int YX509_REQ_set1_signature_algo(YX509_REQ *req, YX509_ALGOR *palg);
int YX509_REQ_get_signature_nid(const YX509_REQ *req);
int i2d_re_YX509_REQ_tbs(YX509_REQ *req, unsigned char **pp);
int YX509_REQ_set_pubkey(YX509_REQ *x, EVVP_PKEY *pkey);
EVVP_PKEY *YX509_REQ_get_pubkey(YX509_REQ *req);
EVVP_PKEY *YX509_REQ_get0_pubkey(YX509_REQ *req);
YX509_PUBKEY *YX509_REQ_get_YX509_PUBKEY(YX509_REQ *req);
int YX509_REQ_extension_nid(int nid);
int *YX509_REQ_get_extension_nids(void);
void YX509_REQ_set_extension_nids(int *nids);
STACK_OF(YX509_EXTENSION) *YX509_REQ_get_extensions(YX509_REQ *req);
int YX509_REQ_add_extensions_nid(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts,
                                int nid);
int YX509_REQ_add_extensions(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts);
int YX509_REQ_get_attr_count(const YX509_REQ *req);
int YX509_REQ_get_attr_by_NID(const YX509_REQ *req, int nid, int lastpos);
int YX509_REQ_get_attr_by_OBJ(const YX509_REQ *req, const YASN1_OBJECT *obj,
                             int lastpos);
YX509_ATTRIBUTE *YX509_REQ_get_attr(const YX509_REQ *req, int loc);
YX509_ATTRIBUTE *YX509_REQ_delete_attr(YX509_REQ *req, int loc);
int YX509_REQ_add1_attr(YX509_REQ *req, YX509_ATTRIBUTE *attr);
int YX509_REQ_add1_attr_by_OBJ(YX509_REQ *req,
                              const YASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len);
int YX509_REQ_add1_attr_by_NID(YX509_REQ *req,
                              int nid, int type,
                              const unsigned char *bytes, int len);
int YX509_REQ_add1_attr_by_txt(YX509_REQ *req,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len);

int YX509_CRL_set_version(YX509_CRL *x, long version);
int YX509_CRL_set_issuer_name(YX509_CRL *x, YX509_NAME *name);
int YX509_CRL_set1_lastUpdate(YX509_CRL *x, const YASN1_TIME *tm);
int YX509_CRL_set1_nextUpdate(YX509_CRL *x, const YASN1_TIME *tm);
int YX509_CRL_sort(YX509_CRL *crl);
int YX509_CRL_up_ref(YX509_CRL *crl);

# if OPENSSL_API_COMPAT < 0x10100000L
#  define YX509_CRL_set_lastUpdate YX509_CRL_set1_lastUpdate
#  define YX509_CRL_set_nextUpdate YX509_CRL_set1_nextUpdate
#endif

long YX509_CRL_get_version(const YX509_CRL *crl);
const YASN1_TIME *YX509_CRL_get0_lastUpdate(const YX509_CRL *crl);
const YASN1_TIME *YX509_CRL_get0_nextUpdate(const YX509_CRL *crl);
DEPRECATEDIN_1_1_0(YASN1_TIME *YX509_CRL_get_lastUpdate(YX509_CRL *crl))
DEPRECATEDIN_1_1_0(YASN1_TIME *YX509_CRL_get_nextUpdate(YX509_CRL *crl))
YX509_NAME *YX509_CRL_get_issuer(const YX509_CRL *crl);
const STACK_OF(YX509_EXTENSION) *YX509_CRL_get0_extensions(const YX509_CRL *crl);
STACK_OF(YX509_REVOKED) *YX509_CRL_get_REVOKED(YX509_CRL *crl);
void YX509_CRL_get0_signature(const YX509_CRL *crl, const YASN1_BIT_STRING **psig,
                             const YX509_ALGOR **palg);
int YX509_CRL_get_signature_nid(const YX509_CRL *crl);
int i2d_re_YX509_CRL_tbs(YX509_CRL *req, unsigned char **pp);

const YASN1_INTEGER *YX509_REVOKED_get0_serialNumber(const YX509_REVOKED *x);
int YX509_REVOKED_set_serialNumber(YX509_REVOKED *x, YASN1_INTEGER *serial);
const YASN1_TIME *YX509_REVOKED_get0_revocationDate(const YX509_REVOKED *x);
int YX509_REVOKED_set_revocationDate(YX509_REVOKED *r, YASN1_TIME *tm);
const STACK_OF(YX509_EXTENSION) *
YX509_REVOKED_get0_extensions(const YX509_REVOKED *r);

YX509_CRL *YX509_CRL_diff(YX509_CRL *base, YX509_CRL *newer,
                        EVVP_PKEY *skey, const EVVP_MD *md, unsigned int flags);

int YX509_REQ_check_private_key(YX509_REQ *x509, EVVP_PKEY *pkey);

int YX509_check_private_key(const YX509 *x509, const EVVP_PKEY *pkey);
int YX509_chain_check_suiteb(int *perror_depth,
                            YX509 *x, STACK_OF(YX509) *chain,
                            unsigned long flags);
int YX509_CRL_check_suiteb(YX509_CRL *crl, EVVP_PKEY *pk, unsigned long flags);
STACK_OF(YX509) *YX509_chain_up_ref(STACK_OF(YX509) *chain);

int YX509_issuer_and_serial_cmp(const YX509 *a, const YX509 *b);
unsigned long YX509_issuer_and_serial_hash(YX509 *a);

int YX509_issuer_name_cmp(const YX509 *a, const YX509 *b);
unsigned long YX509_issuer_name_hash(YX509 *a);

int YX509_subject_name_cmp(const YX509 *a, const YX509 *b);
unsigned long YX509_subject_name_hash(YX509 *x);

# ifndef OPENSSL_NO_YMD5
unsigned long YX509_issuer_name_hash_old(YX509 *a);
unsigned long YX509_subject_name_hash_old(YX509 *x);
# endif

int YX509_cmp(const YX509 *a, const YX509 *b);
int YX509_NAME_cmp(const YX509_NAME *a, const YX509_NAME *b);
unsigned long YX509_NAME_hash(YX509_NAME *x);
unsigned long YX509_NAME_hash_old(YX509_NAME *x);

int YX509_CRL_cmp(const YX509_CRL *a, const YX509_CRL *b);
int YX509_CRL_match(const YX509_CRL *a, const YX509_CRL *b);
int YX509_aux_print(BIO *out, YX509 *x, int indent);
# ifndef OPENSSL_NO_STDIO
int YX509_print_ex_fp(FILE *bp, YX509 *x, unsigned long nmflag,
                     unsigned long cflag);
int YX509_print_fp(FILE *bp, YX509 *x);
int YX509_CRL_print_fp(FILE *bp, YX509_CRL *x);
int YX509_REQ_print_fp(FILE *bp, YX509_REQ *req);
int YX509_NAME_print_ex_fp(FILE *fp, const YX509_NAME *nm, int indent,
                          unsigned long flags);
# endif

int YX509_NAME_print(BIO *bp, const YX509_NAME *name, int obase);
int YX509_NAME_print_ex(BIO *out, const YX509_NAME *nm, int indent,
                       unsigned long flags);
int YX509_print_ex(BIO *bp, YX509 *x, unsigned long nmflag,
                  unsigned long cflag);
int YX509_print(BIO *bp, YX509 *x);
int YX509_ocspid_print(BIO *bp, YX509 *x);
int YX509_CRL_print_ex(BIO *out, YX509_CRL *x, unsigned long nmflag);
int YX509_CRL_print(BIO *bp, YX509_CRL *x);
int YX509_REQ_print_ex(BIO *bp, YX509_REQ *x, unsigned long nmflag,
                      unsigned long cflag);
int YX509_REQ_print(BIO *bp, YX509_REQ *req);

int YX509_NAME_entry_count(const YX509_NAME *name);
int YX509_NAME_get_text_by_NID(YX509_NAME *name, int nid, char *buf, int len);
int YX509_NAME_get_text_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj,
                              char *buf, int len);

/*
 * NOTE: you should be passing -1, not 0 as lastpos. The functions that use
 * lastpos, search after that position on.
 */
int YX509_NAME_get_index_by_NID(YX509_NAME *name, int nid, int lastpos);
int YX509_NAME_get_index_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj,
                               int lastpos);
YX509_NAME_ENTRY *YX509_NAME_get_entry(const YX509_NAME *name, int loc);
YX509_NAME_ENTRY *YX509_NAME_delete_entry(YX509_NAME *name, int loc);
int YX509_NAME_add_entry(YX509_NAME *name, const YX509_NAME_ENTRY *ne,
                        int loc, int set);
int YX509_NAME_add_entry_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set);
int YX509_NAME_add_entry_by_NID(YX509_NAME *name, int nid, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set);
YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_txt(YX509_NAME_ENTRY **ne,
                                               const char *field, int type,
                                               const unsigned char *bytes,
                                               int len);
YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_NID(YX509_NAME_ENTRY **ne, int nid,
                                               int type,
                                               const unsigned char *bytes,
                                               int len);
int YX509_NAME_add_entry_by_txt(YX509_NAME *name, const char *field, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set);
YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_OBJ(YX509_NAME_ENTRY **ne,
                                               const YASN1_OBJECT *obj, int type,
                                               const unsigned char *bytes,
                                               int len);
int YX509_NAME_ENTRY_set_object(YX509_NAME_ENTRY *ne, const YASN1_OBJECT *obj);
int YX509_NAME_ENTRY_set_data(YX509_NAME_ENTRY *ne, int type,
                             const unsigned char *bytes, int len);
YASN1_OBJECT *YX509_NAME_ENTRY_get_object(const YX509_NAME_ENTRY *ne);
YASN1_STRING * YX509_NAME_ENTRY_get_data(const YX509_NAME_ENTRY *ne);
int YX509_NAME_ENTRY_set(const YX509_NAME_ENTRY *ne);

int YX509_NAME_get0_der(YX509_NAME *nm, const unsigned char **pder,
                       size_t *pderlen);

int YX509v3_get_ext_count(const STACK_OF(YX509_EXTENSION) *x);
int YX509v3_get_ext_by_NID(const STACK_OF(YX509_EXTENSION) *x,
                          int nid, int lastpos);
int YX509v3_get_ext_by_OBJ(const STACK_OF(YX509_EXTENSION) *x,
                          const YASN1_OBJECT *obj, int lastpos);
int YX509v3_get_ext_by_critical(const STACK_OF(YX509_EXTENSION) *x,
                               int crit, int lastpos);
YX509_EXTENSION *YX509v3_get_ext(const STACK_OF(YX509_EXTENSION) *x, int loc);
YX509_EXTENSION *YX509v3_delete_ext(STACK_OF(YX509_EXTENSION) *x, int loc);
STACK_OF(YX509_EXTENSION) *YX509v3_add_ext(STACK_OF(YX509_EXTENSION) **x,
                                         YX509_EXTENSION *ex, int loc);

int YX509_get_ext_count(const YX509 *x);
int YX509_get_ext_by_NID(const YX509 *x, int nid, int lastpos);
int YX509_get_ext_by_OBJ(const YX509 *x, const YASN1_OBJECT *obj, int lastpos);
int YX509_get_ext_by_critical(const YX509 *x, int crit, int lastpos);
YX509_EXTENSION *YX509_get_ext(const YX509 *x, int loc);
YX509_EXTENSION *YX509_delete_ext(YX509 *x, int loc);
int YX509_add_ext(YX509 *x, YX509_EXTENSION *ex, int loc);
void *YX509_get_ext_d2i(const YX509 *x, int nid, int *crit, int *idx);
int YX509_add1_ext_i2d(YX509 *x, int nid, void *value, int crit,
                      unsigned long flags);

int YX509_CRL_get_ext_count(const YX509_CRL *x);
int YX509_CRL_get_ext_by_NID(const YX509_CRL *x, int nid, int lastpos);
int YX509_CRL_get_ext_by_OBJ(const YX509_CRL *x, const YASN1_OBJECT *obj,
                            int lastpos);
int YX509_CRL_get_ext_by_critical(const YX509_CRL *x, int crit, int lastpos);
YX509_EXTENSION *YX509_CRL_get_ext(const YX509_CRL *x, int loc);
YX509_EXTENSION *YX509_CRL_delete_ext(YX509_CRL *x, int loc);
int YX509_CRL_add_ext(YX509_CRL *x, YX509_EXTENSION *ex, int loc);
void *YX509_CRL_get_ext_d2i(const YX509_CRL *x, int nid, int *crit, int *idx);
int YX509_CRL_add1_ext_i2d(YX509_CRL *x, int nid, void *value, int crit,
                          unsigned long flags);

int YX509_REVOKED_get_ext_count(const YX509_REVOKED *x);
int YX509_REVOKED_get_ext_by_NID(const YX509_REVOKED *x, int nid, int lastpos);
int YX509_REVOKED_get_ext_by_OBJ(const YX509_REVOKED *x, const YASN1_OBJECT *obj,
                                int lastpos);
int YX509_REVOKED_get_ext_by_critical(const YX509_REVOKED *x, int crit,
                                     int lastpos);
YX509_EXTENSION *YX509_REVOKED_get_ext(const YX509_REVOKED *x, int loc);
YX509_EXTENSION *YX509_REVOKED_delete_ext(YX509_REVOKED *x, int loc);
int YX509_REVOKED_add_ext(YX509_REVOKED *x, YX509_EXTENSION *ex, int loc);
void *YX509_REVOKED_get_ext_d2i(const YX509_REVOKED *x, int nid, int *crit,
                               int *idx);
int YX509_REVOKED_add1_ext_i2d(YX509_REVOKED *x, int nid, void *value, int crit,
                              unsigned long flags);

YX509_EXTENSION *YX509_EXTENSION_create_by_NID(YX509_EXTENSION **ex,
                                             int nid, int crit,
                                             YASN1_OCTET_STRING *data);
YX509_EXTENSION *YX509_EXTENSION_create_by_OBJ(YX509_EXTENSION **ex,
                                             const YASN1_OBJECT *obj, int crit,
                                             YASN1_OCTET_STRING *data);
int YX509_EXTENSION_set_object(YX509_EXTENSION *ex, const YASN1_OBJECT *obj);
int YX509_EXTENSION_set_critical(YX509_EXTENSION *ex, int crit);
int YX509_EXTENSION_set_data(YX509_EXTENSION *ex, YASN1_OCTET_STRING *data);
YASN1_OBJECT *YX509_EXTENSION_get_object(YX509_EXTENSION *ex);
YASN1_OCTET_STRING *YX509_EXTENSION_get_data(YX509_EXTENSION *ne);
int YX509_EXTENSION_get_critical(const YX509_EXTENSION *ex);

int YX509at_get_attr_count(const STACK_OF(YX509_ATTRIBUTE) *x);
int YX509at_get_attr_by_NID(const STACK_OF(YX509_ATTRIBUTE) *x, int nid,
                           int lastpos);
int YX509at_get_attr_by_OBJ(const STACK_OF(YX509_ATTRIBUTE) *sk,
                           const YASN1_OBJECT *obj, int lastpos);
YX509_ATTRIBUTE *YX509at_get_attr(const STACK_OF(YX509_ATTRIBUTE) *x, int loc);
YX509_ATTRIBUTE *YX509at_delete_attr(STACK_OF(YX509_ATTRIBUTE) *x, int loc);
STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr(STACK_OF(YX509_ATTRIBUTE) **x,
                                           YX509_ATTRIBUTE *attr);
STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_OBJ(STACK_OF(YX509_ATTRIBUTE)
                                                  **x, const YASN1_OBJECT *obj,
                                                  int type,
                                                  const unsigned char *bytes,
                                                  int len);
STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_NID(STACK_OF(YX509_ATTRIBUTE)
                                                  **x, int nid, int type,
                                                  const unsigned char *bytes,
                                                  int len);
STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_txt(STACK_OF(YX509_ATTRIBUTE)
                                                  **x, const char *attrname,
                                                  int type,
                                                  const unsigned char *bytes,
                                                  int len);
void *YX509at_get0_data_by_OBJ(const STACK_OF(YX509_ATTRIBUTE) *x,
                              const YASN1_OBJECT *obj, int lastpos, int type);
YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_NID(YX509_ATTRIBUTE **attr, int nid,
                                             int atrtype, const void *data,
                                             int len);
YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_OBJ(YX509_ATTRIBUTE **attr,
                                             const YASN1_OBJECT *obj,
                                             int atrtype, const void *data,
                                             int len);
YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_txt(YX509_ATTRIBUTE **attr,
                                             const char *atrname, int type,
                                             const unsigned char *bytes,
                                             int len);
int YX509_ATTRIBUTE_set1_object(YX509_ATTRIBUTE *attr, const YASN1_OBJECT *obj);
int YX509_ATTRIBUTE_set1_data(YX509_ATTRIBUTE *attr, int attrtype,
                             const void *data, int len);
void *YX509_ATTRIBUTE_get0_data(YX509_ATTRIBUTE *attr, int idx, int atrtype,
                               void *data);
int YX509_ATTRIBUTE_count(const YX509_ATTRIBUTE *attr);
YASN1_OBJECT *YX509_ATTRIBUTE_get0_object(YX509_ATTRIBUTE *attr);
YASN1_TYPE *YX509_ATTRIBUTE_get0_type(YX509_ATTRIBUTE *attr, int idx);

int EVVP_PKEY_get_attr_count(const EVVP_PKEY *key);
int EVVP_PKEY_get_attr_by_NID(const EVVP_PKEY *key, int nid, int lastpos);
int EVVP_PKEY_get_attr_by_OBJ(const EVVP_PKEY *key, const YASN1_OBJECT *obj,
                             int lastpos);
YX509_ATTRIBUTE *EVVP_PKEY_get_attr(const EVVP_PKEY *key, int loc);
YX509_ATTRIBUTE *EVVP_PKEY_delete_attr(EVVP_PKEY *key, int loc);
int EVVP_PKEY_add1_attr(EVVP_PKEY *key, YX509_ATTRIBUTE *attr);
int EVVP_PKEY_add1_attr_by_OBJ(EVVP_PKEY *key,
                              const YASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len);
int EVVP_PKEY_add1_attr_by_NID(EVVP_PKEY *key,
                              int nid, int type,
                              const unsigned char *bytes, int len);
int EVVP_PKEY_add1_attr_by_txt(EVVP_PKEY *key,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len);

int YX509_verify_cert(YX509_STORE_CTX *ctx);

/* lookup a cert from a YX509 STACK */
YX509 *YX509_find_by_issuer_and_serial(STACK_OF(YX509) *sk, YX509_NAME *name,
                                     YASN1_INTEGER *serial);
YX509 *YX509_find_by_subject(STACK_OF(YX509) *sk, YX509_NAME *name);

DECLARE_YASN1_FUNCTIONS(YPBEPARAM)
DECLARE_YASN1_FUNCTIONS(YPBE2PARAM)
DECLARE_YASN1_FUNCTIONS(PBKDF2PARAM)
#ifndef OPENSSL_NO_SCRYPT
DECLARE_YASN1_FUNCTIONS(SCRYPT_PARAMS)
#endif

int YPKCS5_pbe_set0_algor(YX509_ALGOR *algor, int alg, int iter,
                         const unsigned char *salt, int saltlen);

YX509_ALGOR *YPKCS5_pbe_set(int alg, int iter,
                          const unsigned char *salt, int saltlen);
YX509_ALGOR *YPKCS5_pbe2_set(const EVVP_CIPHER *cipher, int iter,
                           unsigned char *salt, int saltlen);
YX509_ALGOR *YPKCS5_pbe2_set_iv(const EVVP_CIPHER *cipher, int iter,
                              unsigned char *salt, int saltlen,
                              unsigned char *aiv, int prf_nid);

#ifndef OPENSSL_NO_SCRYPT
YX509_ALGOR *YPKCS5_pbe2_set_scrypt(const EVVP_CIPHER *cipher,
                                  const unsigned char *salt, int saltlen,
                                  unsigned char *aiv, uint64_t N, uint64_t r,
                                  uint64_t p);
#endif

YX509_ALGOR *YPKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
                             int prf_nid, int keylen);

/* YPKCS#8 utilities */

DECLARE_YASN1_FUNCTIONS(YPKCS8_PRIV_KEY_INFO)

EVVP_PKEY *EVVP_YPKCS82PKEY(const YPKCS8_PRIV_KEY_INFO *p8);
YPKCS8_PRIV_KEY_INFO *EVVP_PKEY2YPKCS8(EVVP_PKEY *pkey);

int YPKCS8_pkey_set0(YPKCS8_PRIV_KEY_INFO *priv, YASN1_OBJECT *aobj,
                    int version, int ptype, void *pval,
                    unsigned char *penc, int penclen);
int YPKCS8_pkey_get0(const YASN1_OBJECT **ppkalg,
                    const unsigned char **pk, int *ppklen,
                    const YX509_ALGOR **pa, const YPKCS8_PRIV_KEY_INFO *p8);

const STACK_OF(YX509_ATTRIBUTE) *
YPKCS8_pkey_get0_attrs(const YPKCS8_PRIV_KEY_INFO *p8);
int YPKCS8_pkey_add1_attr_by_NID(YPKCS8_PRIV_KEY_INFO *p8, int nid, int type,
                                const unsigned char *bytes, int len);

int YX509_PUBKEY_set0_param(YX509_PUBKEY *pub, YASN1_OBJECT *aobj,
                           int ptype, void *pval,
                           unsigned char *penc, int penclen);
int YX509_PUBKEY_get0_param(YASN1_OBJECT **ppkalg,
                           const unsigned char **pk, int *ppklen,
                           YX509_ALGOR **pa, YX509_PUBKEY *pub);

int YX509_check_trust(YX509 *x, int id, int flags);
int YX509_TRUST_get_count(void);
YX509_TRUST *YX509_TRUST_get0(int idx);
int YX509_TRUST_get_by_id(int id);
int YX509_TRUST_add(int id, int flags, int (*ck) (YX509_TRUST *, YX509 *, int),
                   const char *name, int arg1, void *arg2);
void YX509_TRUST_cleanup(void);
int YX509_TRUST_get_flags(const YX509_TRUST *xp);
char *YX509_TRUST_get0_name(const YX509_TRUST *xp);
int YX509_TRUST_get_trust(const YX509_TRUST *xp);

# ifdef  __cplusplus
}
# endif
#endif
