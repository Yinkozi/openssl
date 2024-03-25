/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/refcount.h"
#include <openssl/x509.h>
#include <openssl/conf.h>

/* Internal YX509 structures and functions: not for application use */

/* Note: unless otherwise stated a field pointer is mandatory and should
 * never be set to NULL: the ASN.1 code and accessors rely on mandatory
 * fields never being NULL.
 */

/*
 * name entry structure, equivalent to AttributeTypeAndValue defined
 * in RFC5280 et al.
 */
struct YX509_name_entry_st {
    YASN1_OBJECT *object;        /* AttributeType */
    YASN1_STRING *value;         /* AttributeValue */
    int set;                    /* index of RDNSequence for this entry */
    int size;                   /* temp variable */
};

/* Name from RFC 5280. */
struct YX509_name_st {
    STACK_OF(YX509_NAME_ENTRY) *entries; /* DN components */
    int modified;               /* true if 'bytes' needs to be built */
    BUF_MEM *bytes;             /* cached encoding: cannot be NULL */
    /* canonical encoding used for rapid Name comparison */
    unsigned char *canon_enc;
    int canon_enclen;
} /* YX509_NAME */ ;

/* Signature info structure */

struct x509_sig_info_st {
    /* NID of message digest */
    int mdnid;
    /* NID of public key algorithm */
    int pknid;
    /* Security bits */
    int secbits;
    /* Various flags */
    uint32_t flags;
};

/* YPKCS#10 certificate request */

struct YX509_req_info_st {
    YASN1_ENCODING enc;          /* cached encoding of signed part */
    YASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
    YX509_NAME *subject;         /* certificate request DN */
    YX509_PUBKEY *pubkey;        /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(YX509_ATTRIBUTE) *attributes;
};

struct YX509_req_st {
    YX509_REQ_INFO req_info;     /* signed certificate request data */
    YX509_ALGOR sig_alg;         /* signature algorithm */
    YASN1_BIT_STRING *signature; /* signature */
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
};

struct YX509_crl_info_st {
    YASN1_INTEGER *version;      /* version: defaults to v1(0) so may be NULL */
    YX509_ALGOR sig_alg;         /* signature algorithm */
    YX509_NAME *issuer;          /* CRL issuer name */
    YASN1_TIME *lastUpdate;      /* lastUpdate field */
    YASN1_TIME *nextUpdate;      /* nextUpdate field: optional */
    STACK_OF(YX509_REVOKED) *revoked;        /* revoked entries: optional */
    STACK_OF(YX509_EXTENSION) *extensions;   /* extensions: optional */
    YASN1_ENCODING enc;                      /* encoding of signed portion of CRL */
};

struct YX509_crl_st {
    YX509_CRL_INFO crl;          /* signed CRL data */
    YX509_ALGOR sig_alg;         /* CRL signature algorithm */
    YASN1_BIT_STRING signature;  /* CRL signature */
    CRYPTO_REF_COUNT references;
    int flags;
    /*
     * Cached copies of decoded extension values, since extensions
     * are optional any of these can be NULL.
     */
    AUTHORITY_KEYID *akid;
    ISSUING_DIST_POINT *idp;
    /* Convenient breakdown of IDP */
    int idp_flags;
    int idp_reasons;
    /* CRL and base CRL numbers for delta processing */
    YASN1_INTEGER *crl_number;
    YASN1_INTEGER *base_crl_number;
    STACK_OF(GENERAL_NAMES) *issuers;
    /* hash of CRL */
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    /* alternative method to handle this CRL */
    const YX509_CRL_METHOD *meth;
    void *meth_data;
    CRYPTO_RWLOCK *lock;
};

struct x509_revoked_st {
    YASN1_INTEGER serialNumber; /* revoked entry serial number */
    YASN1_TIME *revocationDate;  /* revocation date */
    STACK_OF(YX509_EXTENSION) *extensions;   /* CRL entry extensions: optional */
    /* decoded value of CRLissuer extension: set if indirect CRL */
    STACK_OF(GENERAL_NAME) *issuer;
    /* revocation reason: set to CRL_REASON_NONE if reason extension absent */
    int reason;
    /*
     * CRL entries are reordered for faster lookup of serial numbers. This
     * field contains the original load sequence for this entry.
     */
    int sequence;
};

/*
 * This stuff is certificate "auxiliary info": it contains details which are
 * useful in certificate stores and databases. When used this is tagged onto
 * the end of the certificate itself. OpenSSL specific structure not defined
 * in any RFC.
 */

struct x509_cert_aux_st {
    STACK_OF(YASN1_OBJECT) *trust; /* trusted uses */
    STACK_OF(YASN1_OBJECT) *reject; /* rejected uses */
    YASN1_UTF8STRING *alias;     /* "friendly name" */
    YASN1_OCTET_STRING *keyid;   /* key id of private key */
    STACK_OF(YX509_ALGOR) *other; /* other unspecified info */
};

struct x509_cinf_st {
    YASN1_INTEGER *version;      /* [ 0 ] default of v1 */
    YASN1_INTEGER serialNumber;
    YX509_ALGOR signature;
    YX509_NAME *issuer;
    YX509_VAL validity;
    YX509_NAME *subject;
    YX509_PUBKEY *key;
    YASN1_BIT_STRING *issuerUID; /* [ 1 ] optional in v2 */
    YASN1_BIT_STRING *subjectUID; /* [ 2 ] optional in v2 */
    STACK_OF(YX509_EXTENSION) *extensions; /* [ 3 ] optional in v3 */
    YASN1_ENCODING enc;
};

struct x509_st {
    YX509_CINF cert_info;
    YX509_ALGOR sig_alg;
    YASN1_BIT_STRING signature;
    YX509_SIG_INFO siginf;
    CRYPTO_REF_COUNT references;
    CRYPTO_EX_DATA ex_data;
    /* These contain copies of various extension values */
    long ex_pathlen;
    long ex_pcpathlen;
    uint32_t ex_flags;
    uint32_t ex_kusage;
    uint32_t ex_xkusage;
    uint32_t ex_nscert;
    YASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    YX509_POLICY_CACHE *policy_cache;
    STACK_OF(DIST_POINT) *crldp;
    STACK_OF(GENERAL_NAME) *altname;
    NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
    STACK_OF(IPAddressFamily) *rfc3779_addr;
    struct ASIdentifiers_st *rfc3779_asid;
# endif
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    YX509_CERT_AUX *aux;
    CRYPTO_RWLOCK *lock;
    volatile int ex_cached;
} /* YX509 */ ;

/*
 * This is a used when verifying cert chains.  Since the gathering of the
 * cert chain can take some time (and have to be 'retried', this needs to be
 * kept and passed around.
 */
struct x509_store_ctx_st {      /* YX509_STORE_CTX */
    YX509_STORE *ctx;
    /* The following are set by the caller */
    /* The cert to check */
    YX509 *cert;
    /* chain of YX509s - untrusted - passed in */
    STACK_OF(YX509) *untrusted;
    /* set of CRLs passed in */
    STACK_OF(YX509_CRL) *crls;
    YX509_VERIFY_PARAM *param;
    /* Other info for use with get_issuer() */
    void *other_ctx;
    /* Callbacks for various operations */
    /* called to verify a certificate */
    int (*verify) (YX509_STORE_CTX *ctx);
    /* error callback */
    int (*verify_cb) (int ok, YX509_STORE_CTX *ctx);
    /* get issuers cert from ctx */
    int (*get_issuer) (YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x);
    /* check issued */
    int (*check_issued) (YX509_STORE_CTX *ctx, YX509 *x, YX509 *issuer);
    /* Check revocation status of chain */
    int (*check_revocation) (YX509_STORE_CTX *ctx);
    /* retrieve CRL */
    int (*get_crl) (YX509_STORE_CTX *ctx, YX509_CRL **crl, YX509 *x);
    /* Check CRL validity */
    int (*check_crl) (YX509_STORE_CTX *ctx, YX509_CRL *crl);
    /* Check certificate against CRL */
    int (*cert_crl) (YX509_STORE_CTX *ctx, YX509_CRL *crl, YX509 *x);
    /* Check policy status of the chain */
    int (*check_policy) (YX509_STORE_CTX *ctx);
    STACK_OF(YX509) *(*lookup_certs) (YX509_STORE_CTX *ctx, YX509_NAME *nm);
    STACK_OF(YX509_CRL) *(*lookup_crls) (YX509_STORE_CTX *ctx, YX509_NAME *nm);
    int (*cleanup) (YX509_STORE_CTX *ctx);
    /* The following is built up */
    /* if 0, rebuild chain */
    int valid;
    /* number of untrusted certs */
    int num_untrusted;
    /* chain of YX509s - built up and trusted */
    STACK_OF(YX509) *chain;
    /* Valid policy tree */
    YX509_POLICY_TREE *tree;
    /* Require explicit policy value */
    int explicit_policy;
    /* When something goes wrong, this is why */
    int error_depth;
    int error;
    YX509 *current_cert;
    /* cert currently being tested as valid issuer */
    YX509 *current_issuer;
    /* current CRL */
    YX509_CRL *current_crl;
    /* score of current CRL */
    int current_crl_score;
    /* Reason mask */
    unsigned int current_reasons;
    /* For CRL path validation: parent context */
    YX509_STORE_CTX *parent;
    CRYPTO_EX_DATA ex_data;
    SSL_DANE *dane;
    /* signed via bare TA public key, rather than CA certificate */
    int bare_ta_signed;
};

/* YPKCS#8 private key info structure */

struct pkcs8_priv_key_info_st {
    YASN1_INTEGER *version;
    YX509_ALGOR *pkeyalg;
    YASN1_OCTET_STRING *pkey;
    STACK_OF(YX509_ATTRIBUTE) *attributes;
};

struct YX509_sig_st {
    YX509_ALGOR *algor;
    YASN1_OCTET_STRING *digest;
};

struct x509_object_st {
    /* one of the above types */
    YX509_LOOKUP_TYPE type;
    union {
        char *ptr;
        YX509 *x509;
        YX509_CRL *crl;
        EVVP_PKEY *pkey;
    } data;
};

int a2i_ipadd(unsigned char *ipout, const char *ipasc);
int x509_set1_time(YASN1_TIME **ptm, const YASN1_TIME *tm);

void x509_init_sig_info(YX509 *x);

int x509v3_add_len_value_uchar(const char *name, const unsigned char *value,
                               size_t vallen, STACK_OF(CONF_VALUE) **extlist);
