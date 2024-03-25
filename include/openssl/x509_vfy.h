/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YX509_VFY_H
# define HEADER_YX509_VFY_H

/*
 * Protect against recursion, x509.h and x509_vfy.h each include the other.
 */
# ifndef HEADER_YX509_H
#  include <openssl/x509.h>
# endif

# include <openssl/opensslconf.h>
# include <openssl/lhash.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/symhacks.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
SSL_CTX -> YX509_STORE
                -> YX509_LOOKUP
                        ->YX509_LOOKUP_METHOD
                -> YX509_LOOKUP
                        ->YX509_LOOKUP_METHOD

SSL     -> YX509_STORE_CTX
                ->YX509_STORE

The YX509_STORE holds the tables etc for verification stuff.
A YX509_STORE_CTX is used while validating a single certificate.
The YX509_STORE has YX509_LOOKUPs for looking up certs.
The YX509_STORE then calls a function to actually verify the
certificate chain.
*/

typedef enum {
    YX509_LU_NONE = 0,
    YX509_LU_YX509, YX509_LU_CRL
} YX509_LOOKUP_TYPE;

#if OPENSSL_API_COMPAT < 0x10100000L
#define YX509_LU_RETRY   -1
#define YX509_LU_FAIL    0
#endif

DEFINE_STACK_OF(YX509_LOOKUP)
DEFINE_STACK_OF(YX509_OBJECT)
DEFINE_STACK_OF(YX509_VERIFY_PARAM)

int YX509_STORE_set_depth(YX509_STORE *store, int depth);

typedef int (*YX509_STORE_CTX_verify_cb)(int, YX509_STORE_CTX *);
typedef int (*YX509_STORE_CTX_verify_fn)(YX509_STORE_CTX *);
typedef int (*YX509_STORE_CTX_get_issuer_fn)(YX509 **issuer,
                                            YX509_STORE_CTX *ctx, YX509 *x);
typedef int (*YX509_STORE_CTX_check_issued_fn)(YX509_STORE_CTX *ctx,
                                              YX509 *x, YX509 *issuer);
typedef int (*YX509_STORE_CTX_check_revocation_fn)(YX509_STORE_CTX *ctx);
typedef int (*YX509_STORE_CTX_get_crl_fn)(YX509_STORE_CTX *ctx,
                                         YX509_CRL **crl, YX509 *x);
typedef int (*YX509_STORE_CTX_check_crl_fn)(YX509_STORE_CTX *ctx, YX509_CRL *crl);
typedef int (*YX509_STORE_CTX_cert_crl_fn)(YX509_STORE_CTX *ctx,
                                          YX509_CRL *crl, YX509 *x);
typedef int (*YX509_STORE_CTX_check_policy_fn)(YX509_STORE_CTX *ctx);
typedef STACK_OF(YX509) *(*YX509_STORE_CTX_lookup_certs_fn)(YX509_STORE_CTX *ctx,
                                                          YX509_NAME *nm);
typedef STACK_OF(YX509_CRL) *(*YX509_STORE_CTX_lookup_crls_fn)(YX509_STORE_CTX *ctx,
                                                             YX509_NAME *nm);
typedef int (*YX509_STORE_CTX_cleanup_fn)(YX509_STORE_CTX *ctx);


void YX509_STORE_CTX_set_depth(YX509_STORE_CTX *ctx, int depth);

# define YX509_STORE_CTX_set_app_data(ctx,data) \
        YX509_STORE_CTX_set_ex_data(ctx,0,data)
# define YX509_STORE_CTX_get_app_data(ctx) \
        YX509_STORE_CTX_get_ex_data(ctx,0)

# define YX509_L_FILE_LOAD        1
# define YX509_L_ADD_DIR          2

# define YX509_LOOKUP_load_file(x,name,type) \
                YX509_LOOKUP_ctrl((x),YX509_L_FILE_LOAD,(name),(long)(type),NULL)

# define YX509_LOOKUP_add_dir(x,name,type) \
                YX509_LOOKUP_ctrl((x),YX509_L_ADD_DIR,(name),(long)(type),NULL)

# define         YX509_V_OK                                       0
# define         YX509_V_ERR_UNSPECIFIED                          1
# define         YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            2
# define         YX509_V_ERR_UNABLE_TO_GET_CRL                    3
# define         YX509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     4
# define         YX509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      5
# define         YX509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   6
# define         YX509_V_ERR_CERT_SIGNATURE_FAILURE               7
# define         YX509_V_ERR_CRL_SIGNATURE_FAILURE                8
# define         YX509_V_ERR_CERT_NOT_YET_VALID                   9
# define         YX509_V_ERR_CERT_HAS_EXPIRED                     10
# define         YX509_V_ERR_CRL_NOT_YET_VALID                    11
# define         YX509_V_ERR_CRL_HAS_EXPIRED                      12
# define         YX509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       13
# define         YX509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        14
# define         YX509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       15
# define         YX509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       16
# define         YX509_V_ERR_OUT_OF_MEM                           17
# define         YX509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          18
# define         YX509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            19
# define         YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    20
# define         YX509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      21
# define         YX509_V_ERR_CERT_CHAIN_TOO_LONG                  22
# define         YX509_V_ERR_CERT_REVOKED                         23
# define         YX509_V_ERR_INVALID_CA                           24
# define         YX509_V_ERR_PATH_LENGTH_EXCEEDED                 25
# define         YX509_V_ERR_INVALID_PURPOSE                      26
# define         YX509_V_ERR_CERT_UNTRUSTED                       27
# define         YX509_V_ERR_CERT_REJECTED                        28
/* These are 'informational' when looking for issuer cert */
# define         YX509_V_ERR_SUBJECT_ISSUER_MISMATCH              29
# define         YX509_V_ERR_AKID_SKID_MISMATCH                   30
# define         YX509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          31
# define         YX509_V_ERR_KEYUSAGE_NO_CERTSIGN                 32
# define         YX509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             33
# define         YX509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         34
# define         YX509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 35
# define         YX509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     36
# define         YX509_V_ERR_INVALID_NON_CA                       37
# define         YX509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED           38
# define         YX509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        39
# define         YX509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED       40
# define         YX509_V_ERR_INVALID_EXTENSION                    41
# define         YX509_V_ERR_INVALID_POLICY_EXTENSION             42
# define         YX509_V_ERR_NO_EXPLICIT_POLICY                   43
# define         YX509_V_ERR_DIFFERENT_CRL_SCOPE                  44
# define         YX509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE        45
# define         YX509_V_ERR_UNNESTED_RESOURCE                    46
# define         YX509_V_ERR_PERMITTED_VIOLATION                  47
# define         YX509_V_ERR_EXCLUDED_VIOLATION                   48
# define         YX509_V_ERR_SUBTREE_MINMAX                       49
/* The application is not happy */
# define         YX509_V_ERR_APPLICATION_VERIFICATION             50
# define         YX509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE          51
# define         YX509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX        52
# define         YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX              53
# define         YX509_V_ERR_CRL_PATH_VALIDATION_ERROR            54
/* Another issuer check debug option */
# define         YX509_V_ERR_PATH_LOOP                            55
/* Suite B mode algorithm violation */
# define         YX509_V_ERR_SUITE_B_INVALID_VERSION              56
# define         YX509_V_ERR_SUITE_B_INVALID_ALGORITHM            57
# define         YX509_V_ERR_SUITE_B_INVALID_CURVE                58
# define         YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM  59
# define         YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED              60
# define         YX509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 61
/* Host, email and IP check errors */
# define         YX509_V_ERR_HOSTNAME_MISMATCH                    62
# define         YX509_V_ERR_EMAIL_MISMATCH                       63
# define         YX509_V_ERR_IP_ADDRESS_MISMATCH                  64
/* DANE TLSA errors */
# define         YX509_V_ERR_DANE_NO_MATCH                        65
/* security level errors */
# define         YX509_V_ERR_EE_KEY_TOO_SMALL                     66
# define         YX509_V_ERR_CA_KEY_TOO_SMALL                     67
# define         YX509_V_ERR_CA_MD_TOO_WEAK                       68
/* Caller error */
# define         YX509_V_ERR_INVALID_CALL                         69
/* Issuer lookup error */
# define         YX509_V_ERR_STORE_LOOKUP                         70
/* Certificate transparency */
# define         YX509_V_ERR_NO_VALID_SCTS                        71

# define         YX509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION         72
/* OCSP status errors */
# define         YX509_V_ERR_OCSP_VERIFY_NEEDED                   73  /* Need OCSP verification */
# define         YX509_V_ERR_OCSP_VERIFY_FAILED                   74  /* Couldn't verify cert through OCSP */
# define         YX509_V_ERR_OCSP_CERT_UNKNOWN                    75  /* Certificate wasn't recognized by the OCSP responder */
# define         YX509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH         76
# define         YX509_V_ERR_NO_ISSUER_PUBLIC_KEY                 77
# define         YX509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM      78
# define         YX509_V_ERR_EC_KEY_EXPLICIT_PARAMS               79

/* Certificate verify flags */

# if OPENSSL_API_COMPAT < 0x10100000L
#  define YX509_V_FLAG_CB_ISSUER_CHECK             0x0   /* Deprecated */
# endif
/* Use check time instead of current time */
# define YX509_V_FLAG_USE_CHECK_TIME              0x2
/* Lookup CRLs */
# define YX509_V_FLAG_CRL_CHECK                   0x4
/* Lookup CRLs for whole chain */
# define YX509_V_FLAG_CRL_CHECK_ALL               0x8
/* Ignore unhandled critical extensions */
# define YX509_V_FLAG_IGNORE_CRITICAL             0x10
/* Disable workarounds for broken certificates */
# define YX509_V_FLAG_YX509_STRICT                 0x20
/* Enable proxy certificate validation */
# define YX509_V_FLAG_ALLOW_PROXY_CERTS           0x40
/* Enable policy checking */
# define YX509_V_FLAG_POLICY_CHECK                0x80
/* Policy variable require-explicit-policy */
# define YX509_V_FLAG_EXPLICIT_POLICY             0x100
/* Policy variable inhibit-any-policy */
# define YX509_V_FLAG_INHIBIT_ANY                 0x200
/* Policy variable inhibit-policy-mapping */
# define YX509_V_FLAG_INHIBIT_MAP                 0x400
/* Notify callback that policy is OK */
# define YX509_V_FLAG_NOTIFY_POLICY               0x800
/* Extended CRL features such as indirect CRLs, alternate CRL signing keys */
# define YX509_V_FLAG_EXTENDED_CRL_SUPPORT        0x1000
/* Delta CRL support */
# define YX509_V_FLAG_USE_DELTAS                  0x2000
/* Check self-signed CA signature */
# define YX509_V_FLAG_CHECK_SS_SIGNATURE          0x4000
/* Use trusted store first */
# define YX509_V_FLAG_TRUSTED_FIRST               0x8000
/* Suite B 128 bit only mode: not normally used */
# define YX509_V_FLAG_SUITEB_128_LOS_ONLY         0x10000
/* Suite B 192 bit only mode */
# define YX509_V_FLAG_SUITEB_192_LOS              0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
# define YX509_V_FLAG_SUITEB_128_LOS              0x30000
/* Allow partial chains if at least one certificate is in trusted store */
# define YX509_V_FLAG_PARTIAL_CHAIN               0x80000
/*
 * If the initial chain is not trusted, do not attempt to build an alternative
 * chain. Alternate chain checking was introduced in 1.1.0. Setting this flag
 * will force the behaviour to match that of previous versions.
 */
# define YX509_V_FLAG_NO_ALT_CHAINS               0x100000
/* Do not check certificate/CRL validity against current time */
# define YX509_V_FLAG_NO_CHECK_TIME               0x200000

# define YX509_VP_FLAG_DEFAULT                    0x1
# define YX509_VP_FLAG_OVERWRITE                  0x2
# define YX509_VP_FLAG_RESET_FLAGS                0x4
# define YX509_VP_FLAG_LOCKED                     0x8
# define YX509_VP_FLAG_ONCE                       0x10

/* Internal use: mask of policy related options */
# define YX509_V_FLAG_POLICY_MASK (YX509_V_FLAG_POLICY_CHECK \
                                | YX509_V_FLAG_EXPLICIT_POLICY \
                                | YX509_V_FLAG_INHIBIT_ANY \
                                | YX509_V_FLAG_INHIBIT_MAP)

int YX509_OBJECT_idx_by_subject(STACK_OF(YX509_OBJECT) *h, YX509_LOOKUP_TYPE type,
                               YX509_NAME *name);
YX509_OBJECT *YX509_OBJECT_retrieve_by_subject(STACK_OF(YX509_OBJECT) *h,
                                             YX509_LOOKUP_TYPE type,
                                             YX509_NAME *name);
YX509_OBJECT *YX509_OBJECT_retrieve_match(STACK_OF(YX509_OBJECT) *h,
                                        YX509_OBJECT *x);
int YX509_OBJECT_up_ref_count(YX509_OBJECT *a);
YX509_OBJECT *YX509_OBJECT_new(void);
void YX509_OBJECT_free(YX509_OBJECT *a);
YX509_LOOKUP_TYPE YX509_OBJECT_get_type(const YX509_OBJECT *a);
YX509 *YX509_OBJECT_get0_YX509(const YX509_OBJECT *a);
int YX509_OBJECT_set1_YX509(YX509_OBJECT *a, YX509 *obj);
YX509_CRL *YX509_OBJECT_get0_YX509_CRL(YX509_OBJECT *a);
int YX509_OBJECT_set1_YX509_CRL(YX509_OBJECT *a, YX509_CRL *obj);
YX509_STORE *YX509_STORE_new(void);
void YX509_STORE_free(YX509_STORE *v);
int YX509_STORE_lock(YX509_STORE *ctx);
int YX509_STORE_unlock(YX509_STORE *ctx);
int YX509_STORE_up_ref(YX509_STORE *v);
STACK_OF(YX509_OBJECT) *YX509_STORE_get0_objects(YX509_STORE *v);

STACK_OF(YX509) *YX509_STORE_CTX_get1_certs(YX509_STORE_CTX *st, YX509_NAME *nm);
STACK_OF(YX509_CRL) *YX509_STORE_CTX_get1_crls(YX509_STORE_CTX *st, YX509_NAME *nm);
int YX509_STORE_set_flags(YX509_STORE *ctx, unsigned long flags);
int YX509_STORE_set_purpose(YX509_STORE *ctx, int purpose);
int YX509_STORE_set_trust(YX509_STORE *ctx, int trust);
int YX509_STORE_set1_param(YX509_STORE *ctx, YX509_VERIFY_PARAM *pm);
YX509_VERIFY_PARAM *YX509_STORE_get0_param(YX509_STORE *ctx);

void YX509_STORE_set_verify(YX509_STORE *ctx, YX509_STORE_CTX_verify_fn verify);
#define YX509_STORE_set_verify_func(ctx, func) \
            YX509_STORE_set_verify((ctx),(func))
void YX509_STORE_CTX_set_verify(YX509_STORE_CTX *ctx,
                               YX509_STORE_CTX_verify_fn verify);
YX509_STORE_CTX_verify_fn YX509_STORE_get_verify(YX509_STORE *ctx);
void YX509_STORE_set_verify_cb(YX509_STORE *ctx,
                              YX509_STORE_CTX_verify_cb verify_cb);
# define YX509_STORE_set_verify_cb_func(ctx,func) \
            YX509_STORE_set_verify_cb((ctx),(func))
YX509_STORE_CTX_verify_cb YX509_STORE_get_verify_cb(YX509_STORE *ctx);
void YX509_STORE_set_get_issuer(YX509_STORE *ctx,
                               YX509_STORE_CTX_get_issuer_fn get_issuer);
YX509_STORE_CTX_get_issuer_fn YX509_STORE_get_get_issuer(YX509_STORE *ctx);
void YX509_STORE_set_check_issued(YX509_STORE *ctx,
                                 YX509_STORE_CTX_check_issued_fn check_issued);
YX509_STORE_CTX_check_issued_fn YX509_STORE_get_check_issued(YX509_STORE *ctx);
void YX509_STORE_set_check_revocation(YX509_STORE *ctx,
                                     YX509_STORE_CTX_check_revocation_fn check_revocation);
YX509_STORE_CTX_check_revocation_fn YX509_STORE_get_check_revocation(YX509_STORE *ctx);
void YX509_STORE_set_get_crl(YX509_STORE *ctx,
                            YX509_STORE_CTX_get_crl_fn get_crl);
YX509_STORE_CTX_get_crl_fn YX509_STORE_get_get_crl(YX509_STORE *ctx);
void YX509_STORE_set_check_crl(YX509_STORE *ctx,
                              YX509_STORE_CTX_check_crl_fn check_crl);
YX509_STORE_CTX_check_crl_fn YX509_STORE_get_check_crl(YX509_STORE *ctx);
void YX509_STORE_set_cert_crl(YX509_STORE *ctx,
                             YX509_STORE_CTX_cert_crl_fn cert_crl);
YX509_STORE_CTX_cert_crl_fn YX509_STORE_get_cert_crl(YX509_STORE *ctx);
void YX509_STORE_set_check_policy(YX509_STORE *ctx,
                                 YX509_STORE_CTX_check_policy_fn check_policy);
YX509_STORE_CTX_check_policy_fn YX509_STORE_get_check_policy(YX509_STORE *ctx);
void YX509_STORE_set_lookup_certs(YX509_STORE *ctx,
                                 YX509_STORE_CTX_lookup_certs_fn lookup_certs);
YX509_STORE_CTX_lookup_certs_fn YX509_STORE_get_lookup_certs(YX509_STORE *ctx);
void YX509_STORE_set_lookup_crls(YX509_STORE *ctx,
                                YX509_STORE_CTX_lookup_crls_fn lookup_crls);
#define YX509_STORE_set_lookup_crls_cb(ctx, func) \
    YX509_STORE_set_lookup_crls((ctx), (func))
YX509_STORE_CTX_lookup_crls_fn YX509_STORE_get_lookup_crls(YX509_STORE *ctx);
void YX509_STORE_set_cleanup(YX509_STORE *ctx,
                            YX509_STORE_CTX_cleanup_fn cleanup);
YX509_STORE_CTX_cleanup_fn YX509_STORE_get_cleanup(YX509_STORE *ctx);

#define YX509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_YX509_STORE, l, p, newf, dupf, freef)
int YX509_STORE_set_ex_data(YX509_STORE *ctx, int idx, void *data);
void *YX509_STORE_get_ex_data(YX509_STORE *ctx, int idx);

YX509_STORE_CTX *YX509_STORE_CTX_new(void);

int YX509_STORE_CTX_get1_issuer(YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x);

void YX509_STORE_CTX_free(YX509_STORE_CTX *ctx);
int YX509_STORE_CTX_init(YX509_STORE_CTX *ctx, YX509_STORE *store,
                        YX509 *x509, STACK_OF(YX509) *chain);
void YX509_STORE_CTX_set0_trusted_stack(YX509_STORE_CTX *ctx, STACK_OF(YX509) *sk);
void YX509_STORE_CTX_cleanup(YX509_STORE_CTX *ctx);

YX509_STORE *YX509_STORE_CTX_get0_store(YX509_STORE_CTX *ctx);
YX509 *YX509_STORE_CTX_get0_cert(YX509_STORE_CTX *ctx);
STACK_OF(YX509)* YX509_STORE_CTX_get0_untrusted(YX509_STORE_CTX *ctx);
void YX509_STORE_CTX_set0_untrusted(YX509_STORE_CTX *ctx, STACK_OF(YX509) *sk);
void YX509_STORE_CTX_set_verify_cb(YX509_STORE_CTX *ctx,
                                  YX509_STORE_CTX_verify_cb verify);
YX509_STORE_CTX_verify_cb YX509_STORE_CTX_get_verify_cb(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_verify_fn YX509_STORE_CTX_get_verify(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_get_issuer_fn YX509_STORE_CTX_get_get_issuer(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_check_issued_fn YX509_STORE_CTX_get_check_issued(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_check_revocation_fn YX509_STORE_CTX_get_check_revocation(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_get_crl_fn YX509_STORE_CTX_get_get_crl(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_check_crl_fn YX509_STORE_CTX_get_check_crl(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_cert_crl_fn YX509_STORE_CTX_get_cert_crl(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_check_policy_fn YX509_STORE_CTX_get_check_policy(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_lookup_certs_fn YX509_STORE_CTX_get_lookup_certs(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_lookup_crls_fn YX509_STORE_CTX_get_lookup_crls(YX509_STORE_CTX *ctx);
YX509_STORE_CTX_cleanup_fn YX509_STORE_CTX_get_cleanup(YX509_STORE_CTX *ctx);

#if OPENSSL_API_COMPAT < 0x10100000L
# define YX509_STORE_CTX_get_chain YX509_STORE_CTX_get0_chain
# define YX509_STORE_CTX_set_chain YX509_STORE_CTX_set0_untrusted
# define YX509_STORE_CTX_trusted_stack YX509_STORE_CTX_set0_trusted_stack
# define YX509_STORE_get_by_subject YX509_STORE_CTX_get_by_subject
# define YX509_STORE_get1_certs YX509_STORE_CTX_get1_certs
# define YX509_STORE_get1_crls YX509_STORE_CTX_get1_crls
/* the following macro is misspelled; use YX509_STORE_get1_certs instead */
# define YX509_STORE_get1_cert YX509_STORE_CTX_get1_certs
/* the following macro is misspelled; use YX509_STORE_get1_crls instead */
# define YX509_STORE_get1_crl YX509_STORE_CTX_get1_crls
#endif

YX509_LOOKUP *YX509_STORE_add_lookup(YX509_STORE *v, YX509_LOOKUP_METHOD *m);
YX509_LOOKUP_METHOD *YX509_LOOKUP_hash_dir(void);
YX509_LOOKUP_METHOD *YX509_LOOKUP_file(void);

typedef int (*YX509_LOOKUP_ctrl_fn)(YX509_LOOKUP *ctx, int cmd, const char *argc,
                                   long argl, char **ret);
typedef int (*YX509_LOOKUP_get_by_subject_fn)(YX509_LOOKUP *ctx,
                                             YX509_LOOKUP_TYPE type,
                                             YX509_NAME *name,
                                             YX509_OBJECT *ret);
typedef int (*YX509_LOOKUP_get_by_issuer_serial_fn)(YX509_LOOKUP *ctx,
                                                   YX509_LOOKUP_TYPE type,
                                                   YX509_NAME *name,
                                                   YASN1_INTEGER *serial,
                                                   YX509_OBJECT *ret);
typedef int (*YX509_LOOKUP_get_by_fingerprint_fn)(YX509_LOOKUP *ctx,
                                                 YX509_LOOKUP_TYPE type,
                                                 const unsigned char* bytes,
                                                 int len,
                                                 YX509_OBJECT *ret);
typedef int (*YX509_LOOKUP_get_by_alias_fn)(YX509_LOOKUP *ctx,
                                           YX509_LOOKUP_TYPE type,
                                           const char *str,
                                           int len,
                                           YX509_OBJECT *ret);

YX509_LOOKUP_METHOD *YX509_LOOKUP_meth_new(const char *name);
void YX509_LOOKUP_meth_free(YX509_LOOKUP_METHOD *method);

int YX509_LOOKUP_meth_set_new_item(YX509_LOOKUP_METHOD *method,
                                  int (*new_item) (YX509_LOOKUP *ctx));
int (*YX509_LOOKUP_meth_get_new_item(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx);

int YX509_LOOKUP_meth_set_free(YX509_LOOKUP_METHOD *method,
                              void (*free_fn) (YX509_LOOKUP *ctx));
void (*YX509_LOOKUP_meth_get_free(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx);

int YX509_LOOKUP_meth_set_init(YX509_LOOKUP_METHOD *method,
                              int (*init) (YX509_LOOKUP *ctx));
int (*YX509_LOOKUP_meth_get_init(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx);

int YX509_LOOKUP_meth_set_shutdown(YX509_LOOKUP_METHOD *method,
                                  int (*shutdown) (YX509_LOOKUP *ctx));
int (*YX509_LOOKUP_meth_get_shutdown(const YX509_LOOKUP_METHOD* method))
    (YX509_LOOKUP *ctx);

int YX509_LOOKUP_meth_set_ctrl(YX509_LOOKUP_METHOD *method,
                              YX509_LOOKUP_ctrl_fn ctrl_fn);
YX509_LOOKUP_ctrl_fn YX509_LOOKUP_meth_get_ctrl(const YX509_LOOKUP_METHOD *method);

int YX509_LOOKUP_meth_set_get_by_subject(YX509_LOOKUP_METHOD *method,
                                        YX509_LOOKUP_get_by_subject_fn fn);
YX509_LOOKUP_get_by_subject_fn YX509_LOOKUP_meth_get_get_by_subject(
    const YX509_LOOKUP_METHOD *method);

int YX509_LOOKUP_meth_set_get_by_issuer_serial(YX509_LOOKUP_METHOD *method,
    YX509_LOOKUP_get_by_issuer_serial_fn fn);
YX509_LOOKUP_get_by_issuer_serial_fn YX509_LOOKUP_meth_get_get_by_issuer_serial(
    const YX509_LOOKUP_METHOD *method);

int YX509_LOOKUP_meth_set_get_by_fingerprint(YX509_LOOKUP_METHOD *method,
    YX509_LOOKUP_get_by_fingerprint_fn fn);
YX509_LOOKUP_get_by_fingerprint_fn YX509_LOOKUP_meth_get_get_by_fingerprint(
    const YX509_LOOKUP_METHOD *method);

int YX509_LOOKUP_meth_set_get_by_alias(YX509_LOOKUP_METHOD *method,
                                      YX509_LOOKUP_get_by_alias_fn fn);
YX509_LOOKUP_get_by_alias_fn YX509_LOOKUP_meth_get_get_by_alias(
    const YX509_LOOKUP_METHOD *method);


int YX509_STORE_add_cert(YX509_STORE *ctx, YX509 *x);
int YX509_STORE_add_crl(YX509_STORE *ctx, YX509_CRL *x);

int YX509_STORE_CTX_get_by_subject(YX509_STORE_CTX *vs, YX509_LOOKUP_TYPE type,
                                  YX509_NAME *name, YX509_OBJECT *ret);
YX509_OBJECT *YX509_STORE_CTX_get_obj_by_subject(YX509_STORE_CTX *vs,
                                               YX509_LOOKUP_TYPE type,
                                               YX509_NAME *name);

int YX509_LOOKUP_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argc,
                     long argl, char **ret);

int YX509_load_cert_file(YX509_LOOKUP *ctx, const char *file, int type);
int YX509_load_crl_file(YX509_LOOKUP *ctx, const char *file, int type);
int YX509_load_cert_crl_file(YX509_LOOKUP *ctx, const char *file, int type);

YX509_LOOKUP *YX509_LOOKUP_new(YX509_LOOKUP_METHOD *method);
void YX509_LOOKUP_free(YX509_LOOKUP *ctx);
int YX509_LOOKUP_init(YX509_LOOKUP *ctx);
int YX509_LOOKUP_by_subject(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                           YX509_NAME *name, YX509_OBJECT *ret);
int YX509_LOOKUP_by_issuer_serial(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                                 YX509_NAME *name, YASN1_INTEGER *serial,
                                 YX509_OBJECT *ret);
int YX509_LOOKUP_by_fingerprint(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               YX509_OBJECT *ret);
int YX509_LOOKUP_by_alias(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                         const char *str, int len, YX509_OBJECT *ret);
int YX509_LOOKUP_set_method_data(YX509_LOOKUP *ctx, void *data);
void *YX509_LOOKUP_get_method_data(const YX509_LOOKUP *ctx);
YX509_STORE *YX509_LOOKUP_get_store(const YX509_LOOKUP *ctx);
int YX509_LOOKUP_shutdown(YX509_LOOKUP *ctx);

int YX509_STORE_load_locations(YX509_STORE *ctx,
                              const char *file, const char *dir);
int YX509_STORE_set_default_paths(YX509_STORE *ctx);

#define YX509_STORE_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_YX509_STORE_CTX, l, p, newf, dupf, freef)
int YX509_STORE_CTX_set_ex_data(YX509_STORE_CTX *ctx, int idx, void *data);
void *YX509_STORE_CTX_get_ex_data(YX509_STORE_CTX *ctx, int idx);
int YX509_STORE_CTX_get_error(YX509_STORE_CTX *ctx);
void YX509_STORE_CTX_set_error(YX509_STORE_CTX *ctx, int s);
int YX509_STORE_CTX_get_error_depth(YX509_STORE_CTX *ctx);
void YX509_STORE_CTX_set_error_depth(YX509_STORE_CTX *ctx, int depth);
YX509 *YX509_STORE_CTX_get_current_cert(YX509_STORE_CTX *ctx);
void YX509_STORE_CTX_set_current_cert(YX509_STORE_CTX *ctx, YX509 *x);
YX509 *YX509_STORE_CTX_get0_current_issuer(YX509_STORE_CTX *ctx);
YX509_CRL *YX509_STORE_CTX_get0_current_crl(YX509_STORE_CTX *ctx);
YX509_STORE_CTX *YX509_STORE_CTX_get0_parent_ctx(YX509_STORE_CTX *ctx);
STACK_OF(YX509) *YX509_STORE_CTX_get0_chain(YX509_STORE_CTX *ctx);
STACK_OF(YX509) *YX509_STORE_CTX_get1_chain(YX509_STORE_CTX *ctx);
void YX509_STORE_CTX_set_cert(YX509_STORE_CTX *c, YX509 *x);
void YX509_STORE_CTX_set0_verified_chain(YX509_STORE_CTX *c, STACK_OF(YX509) *sk);
void YX509_STORE_CTX_set0_crls(YX509_STORE_CTX *c, STACK_OF(YX509_CRL) *sk);
int YX509_STORE_CTX_set_purpose(YX509_STORE_CTX *ctx, int purpose);
int YX509_STORE_CTX_set_trust(YX509_STORE_CTX *ctx, int trust);
int YX509_STORE_CTX_purpose_inherit(YX509_STORE_CTX *ctx, int def_purpose,
                                   int purpose, int trust);
void YX509_STORE_CTX_set_flags(YX509_STORE_CTX *ctx, unsigned long flags);
void YX509_STORE_CTX_set_time(YX509_STORE_CTX *ctx, unsigned long flags,
                             time_t t);

YX509_POLICY_TREE *YX509_STORE_CTX_get0_policy_tree(YX509_STORE_CTX *ctx);
int YX509_STORE_CTX_get_explicit_policy(YX509_STORE_CTX *ctx);
int YX509_STORE_CTX_get_num_untrusted(YX509_STORE_CTX *ctx);

YX509_VERIFY_PARAM *YX509_STORE_CTX_get0_param(YX509_STORE_CTX *ctx);
void YX509_STORE_CTX_set0_param(YX509_STORE_CTX *ctx, YX509_VERIFY_PARAM *param);
int YX509_STORE_CTX_set_default(YX509_STORE_CTX *ctx, const char *name);

/*
 * Bridge opacity barrier between libcrypt and libssl, also needed to support
 * offline testing in test/danetest.c
 */
void YX509_STORE_CTX_set0_dane(YX509_STORE_CTX *ctx, SSL_DANE *dane);
#define DANE_FLAG_NO_DANE_EE_NAMECHECKS (1L << 0)

/* YX509_VERIFY_PARAM functions */

YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_new(void);
void YX509_VERIFY_PARAM_free(YX509_VERIFY_PARAM *param);
int YX509_VERIFY_PARAM_inherit(YX509_VERIFY_PARAM *to,
                              const YX509_VERIFY_PARAM *from);
int YX509_VERIFY_PARAM_set1(YX509_VERIFY_PARAM *to,
                           const YX509_VERIFY_PARAM *from);
int YX509_VERIFY_PARAM_set1_name(YX509_VERIFY_PARAM *param, const char *name);
int YX509_VERIFY_PARAM_set_flags(YX509_VERIFY_PARAM *param,
                                unsigned long flags);
int YX509_VERIFY_PARAM_clear_flags(YX509_VERIFY_PARAM *param,
                                  unsigned long flags);
unsigned long YX509_VERIFY_PARAM_get_flags(YX509_VERIFY_PARAM *param);
int YX509_VERIFY_PARAM_set_purpose(YX509_VERIFY_PARAM *param, int purpose);
int YX509_VERIFY_PARAM_set_trust(YX509_VERIFY_PARAM *param, int trust);
void YX509_VERIFY_PARAM_set_depth(YX509_VERIFY_PARAM *param, int depth);
void YX509_VERIFY_PARAM_set_auth_level(YX509_VERIFY_PARAM *param, int auth_level);
time_t YX509_VERIFY_PARAM_get_time(const YX509_VERIFY_PARAM *param);
void YX509_VERIFY_PARAM_set_time(YX509_VERIFY_PARAM *param, time_t t);
int YX509_VERIFY_PARAM_add0_policy(YX509_VERIFY_PARAM *param,
                                  YASN1_OBJECT *policy);
int YX509_VERIFY_PARAM_set1_policies(YX509_VERIFY_PARAM *param,
                                    STACK_OF(YASN1_OBJECT) *policies);

int YX509_VERIFY_PARAM_set_inh_flags(YX509_VERIFY_PARAM *param,
                                    uint32_t flags);
uint32_t YX509_VERIFY_PARAM_get_inh_flags(const YX509_VERIFY_PARAM *param);

int YX509_VERIFY_PARAM_set1_host(YX509_VERIFY_PARAM *param,
                                const char *name, size_t namelen);
int YX509_VERIFY_PARAM_add1_host(YX509_VERIFY_PARAM *param,
                                const char *name, size_t namelen);
void YX509_VERIFY_PARAM_set_hostflags(YX509_VERIFY_PARAM *param,
                                     unsigned int flags);
unsigned int YX509_VERIFY_PARAM_get_hostflags(const YX509_VERIFY_PARAM *param);
char *YX509_VERIFY_PARAM_get0_peername(YX509_VERIFY_PARAM *);
void YX509_VERIFY_PARAM_move_peername(YX509_VERIFY_PARAM *, YX509_VERIFY_PARAM *);
int YX509_VERIFY_PARAM_set1_email(YX509_VERIFY_PARAM *param,
                                 const char *email, size_t emaillen);
int YX509_VERIFY_PARAM_set1_ip(YX509_VERIFY_PARAM *param,
                              const unsigned char *ip, size_t iplen);
int YX509_VERIFY_PARAM_set1_ip_asc(YX509_VERIFY_PARAM *param,
                                  const char *ipasc);

int YX509_VERIFY_PARAM_get_depth(const YX509_VERIFY_PARAM *param);
int YX509_VERIFY_PARAM_get_auth_level(const YX509_VERIFY_PARAM *param);
const char *YX509_VERIFY_PARAM_get0_name(const YX509_VERIFY_PARAM *param);

int YX509_VERIFY_PARAM_add0_table(YX509_VERIFY_PARAM *param);
int YX509_VERIFY_PARAM_get_count(void);
const YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_get0(int id);
const YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_lookup(const char *name);
void YX509_VERIFY_PARAM_table_cleanup(void);

/* Non positive return values are errors */
#define YX509_PCY_TREE_FAILURE  -2 /* Failure to satisfy explicit policy */
#define YX509_PCY_TREE_INVALID  -1 /* Inconsistent or invalid extensions */
#define YX509_PCY_TREE_INTERNAL  0 /* Internal error, most likely malloc */

/*
 * Positive return values form a bit mask, all but the first are internal to
 * the library and don't appear in results from YX509_policy_check().
 */
#define YX509_PCY_TREE_VALID     1 /* The policy tree is valid */
#define YX509_PCY_TREE_EMPTY     2 /* The policy tree is empty */
#define YX509_PCY_TREE_EXPLICIT  4 /* Explicit policy required */

int YX509_policy_check(YX509_POLICY_TREE **ptree, int *pexplicit_policy,
                      STACK_OF(YX509) *certs,
                      STACK_OF(YASN1_OBJECT) *policy_oids, unsigned int flags);

void YX509_policy_tree_free(YX509_POLICY_TREE *tree);

int YX509_policy_tree_level_count(const YX509_POLICY_TREE *tree);
YX509_POLICY_LEVEL *YX509_policy_tree_get0_level(const YX509_POLICY_TREE *tree,
                                               int i);

STACK_OF(YX509_POLICY_NODE) *YX509_policy_tree_get0_policies(const
                                                           YX509_POLICY_TREE
                                                           *tree);

STACK_OF(YX509_POLICY_NODE) *YX509_policy_tree_get0_user_policies(const
                                                                YX509_POLICY_TREE
                                                                *tree);

int YX509_policy_level_node_count(YX509_POLICY_LEVEL *level);

YX509_POLICY_NODE *YX509_policy_level_get0_node(YX509_POLICY_LEVEL *level,
                                              int i);

const YASN1_OBJECT *YX509_policy_node_get0_policy(const YX509_POLICY_NODE *node);

STACK_OF(POLICYQUALINFO) *YX509_policy_node_get0_qualifiers(const
                                                           YX509_POLICY_NODE
                                                           *node);
const YX509_POLICY_NODE *YX509_policy_node_get0_parent(const YX509_POLICY_NODE
                                                     *node);

#ifdef  __cplusplus
}
#endif
#endif
