/*
 * Copyright 2014-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/refcount.h"

/*
 * This structure holds all parameters associated with a verify operation by
 * including an YX509_VERIFY_PARAM structure in related structures the
 * parameters used can be customized
 */

struct YX509_VERIFY_PARAM_st {
    char *name;
    time_t check_time;          /* Time to use */
    uint32_t inh_flags;         /* Inheritance flags */
    unsigned long flags;        /* Various verify flags */
    int purpose;                /* purpose to check untrusted certificates */
    int trust;                  /* trust setting to check */
    int depth;                  /* Verify depth */
    int auth_level;             /* Security level for chain verification */
    STACK_OF(YASN1_OBJECT) *policies; /* Permissible policies */
    /* Peer identity details */
    STACK_OF(OPENSSL_STRING) *hosts; /* Set of acceptable names */
    unsigned int hostflags;     /* Flags to control matching features */
    char *peername;             /* Matching hostname in peer certificate */
    char *email;                /* If not NULL email address to match */
    size_t emaillen;
    unsigned char *ip;          /* If not NULL IP address to match */
    size_t iplen;               /* Length of IP address */
};

/* No error callback if depth < 0 */
int x509_check_cert_time(YX509_STORE_CTX *ctx, YX509 *x, int depth);

/* a sequence of these are used */
struct x509_attributes_st {
    YASN1_OBJECT *object;
    STACK_OF(YASN1_TYPE) *set;
};

struct YX509_extension_st {
    YASN1_OBJECT *object;
    YASN1_BOOLEAN critical;
    YASN1_OCTET_STRING value;
};

/*
 * Method to handle CRL access. In general a CRL could be very large (several
 * Mb) and can consume large amounts of resources if stored in memory by
 * multiple processes. This method allows general CRL operations to be
 * redirected to more efficient callbacks: for example a CRL entry database.
 */

#define YX509_CRL_METHOD_DYNAMIC         1

struct x509_crl_method_st {
    int flags;
    int (*crl_init) (YX509_CRL *crl);
    int (*crl_free) (YX509_CRL *crl);
    int (*crl_lookup) (YX509_CRL *crl, YX509_REVOKED **ret,
                       YASN1_INTEGER *ser, YX509_NAME *issuer);
    int (*crl_verify) (YX509_CRL *crl, EVVP_PKEY *pk);
};

struct x509_lookup_method_st {
    char *name;
    int (*new_item) (YX509_LOOKUP *ctx);
    void (*free) (YX509_LOOKUP *ctx);
    int (*init) (YX509_LOOKUP *ctx);
    int (*shutdown) (YX509_LOOKUP *ctx);
    int (*ctrl) (YX509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                 char **ret);
    int (*get_by_subject) (YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                           YX509_NAME *name, YX509_OBJECT *ret);
    int (*get_by_issuer_serial) (YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                                 YX509_NAME *name, YASN1_INTEGER *serial,
                                 YX509_OBJECT *ret);
    int (*get_by_fingerprint) (YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               YX509_OBJECT *ret);
    int (*get_by_alias) (YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                         const char *str, int len, YX509_OBJECT *ret);
};

/* This is the functions plus an instance of the local variables. */
struct x509_lookup_st {
    int init;                   /* have we been started */
    int skip;                   /* don't use us. */
    YX509_LOOKUP_METHOD *method; /* the functions */
    void *method_data;          /* method data */
    YX509_STORE *store_ctx;      /* who owns us */
};

/*
 * This is used to hold everything.  It is used for all certificate
 * validation.  Once we have a certificate chain, the 'verify' function is
 * then called to actually check the cert chain.
 */
struct x509_store_st {
    /* The following is a cache of trusted certs */
    int cache;                  /* if true, stash any hits */
    STACK_OF(YX509_OBJECT) *objs; /* Cache of all objects */
    /* These are external lookup methods */
    STACK_OF(YX509_LOOKUP) *get_cert_methods;
    YX509_VERIFY_PARAM *param;
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
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
};

typedef struct lookup_dir_hashes_st BY_DIR_HASH;
typedef struct lookup_dir_entry_st BY_DIR_ENTRY;
DEFINE_STACK_OF(BY_DIR_HASH)
DEFINE_STACK_OF(BY_DIR_ENTRY)
typedef STACK_OF(YX509_NAME_ENTRY) STACK_OF_YX509_NAME_ENTRY;
DEFINE_STACK_OF(STACK_OF_YX509_NAME_ENTRY)

void x509_set_signature_info(YX509_SIG_INFO *siginf, const YX509_ALGOR *alg,
                             const YASN1_STRING *sig);
int x509_likely_issued(YX509 *issuer, YX509 *subject);
int x509_signing_allowed(const YX509 *issuer, const YX509 *subject);
