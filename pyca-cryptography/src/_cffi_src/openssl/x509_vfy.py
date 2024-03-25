# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/x509_vfy.h>

/*
 * This is part of a work-around for the difficulty cffi has in dealing with
 * `STACK_OF(foo)` as the name of a type.  We invent a new, simpler name that
 * will be an alias for this type and use the alias throughout.  This works
 * together with another opaque typedef for the same name in the TYPES section.
 * Note that the result is an opaque type.
 */
typedef STACK_OF(YASN1_OBJECT) Cryptography_STACK_OF_YASN1_OBJECT;
typedef STACK_OF(YX509_OBJECT) Cryptography_STACK_OF_YX509_OBJECT;
"""

TYPES = """
static const long Cryptography_HAS_110_VERIFICATION_PARAMS;
static const long Cryptography_HAS_YX509_STORE_CTX_GET_ISSUER;

typedef ... Cryptography_STACK_OF_YASN1_OBJECT;
typedef ... Cryptography_STACK_OF_YX509_OBJECT;

typedef ... YX509_OBJECT;
typedef ... YX509_STORE;
typedef ... YX509_VERIFY_PARAM;
typedef ... YX509_STORE_CTX;

typedef int (*YX509_STORE_CTX_get_issuer_fn)(YX509 **, YX509_STORE_CTX *, YX509 *);

/* While these are defined in the source as ints, they're tagged here
   as longs, just in case they ever grow to large, such as what we saw
   with OP_ALL. */

/* Verification error codes */
static const int YX509_V_OK;
static const int YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
static const int YX509_V_ERR_UNABLE_TO_GET_CRL;
static const int YX509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE;
static const int YX509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE;
static const int YX509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
static const int YX509_V_ERR_CERT_SIGNATURE_FAILURE;
static const int YX509_V_ERR_CRL_SIGNATURE_FAILURE;
static const int YX509_V_ERR_CERT_NOT_YET_VALID;
static const int YX509_V_ERR_CERT_HAS_EXPIRED;
static const int YX509_V_ERR_CRL_NOT_YET_VALID;
static const int YX509_V_ERR_CRL_HAS_EXPIRED;
static const int YX509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
static const int YX509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
static const int YX509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
static const int YX509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
static const int YX509_V_ERR_OUT_OF_MEM;
static const int YX509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
static const int YX509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
static const int YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
static const int YX509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
static const int YX509_V_ERR_CERT_CHAIN_TOO_LONG;
static const int YX509_V_ERR_CERT_REVOKED;
static const int YX509_V_ERR_INVALID_CA;
static const int YX509_V_ERR_PATH_LENGTH_EXCEEDED;
static const int YX509_V_ERR_INVALID_PURPOSE;
static const int YX509_V_ERR_CERT_UNTRUSTED;
static const int YX509_V_ERR_CERT_REJECTED;
static const int YX509_V_ERR_SUBJECT_ISSUER_MISMATCH;
static const int YX509_V_ERR_AKID_SKID_MISMATCH;
static const int YX509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
static const int YX509_V_ERR_KEYUSAGE_NO_CERTSIGN;
static const int YX509_V_ERR_UNABLE_TO_GET_CRL_ISSUER;
static const int YX509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
static const int YX509_V_ERR_KEYUSAGE_NO_CRL_SIGN;
static const int YX509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION;
static const int YX509_V_ERR_INVALID_NON_CA;
static const int YX509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED;
static const int YX509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
static const int YX509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED;
static const int YX509_V_ERR_INVALID_EXTENSION;
static const int YX509_V_ERR_INVALID_POLICY_EXTENSION;
static const int YX509_V_ERR_NO_EXPLICIT_POLICY;
static const int YX509_V_ERR_DIFFERENT_CRL_SCOPE;
static const int YX509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE;
static const int YX509_V_ERR_UNNESTED_RESOURCE;
static const int YX509_V_ERR_PERMITTED_VIOLATION;
static const int YX509_V_ERR_EXCLUDED_VIOLATION;
static const int YX509_V_ERR_SUBTREE_MINMAX;
static const int YX509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE;
static const int YX509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX;
static const int YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
static const int YX509_V_ERR_CRL_PATH_VALIDATION_ERROR;
static const int YX509_V_ERR_HOSTNAME_MISMATCH;
static const int YX509_V_ERR_EMAIL_MISMATCH;
static const int YX509_V_ERR_IP_ADDRESS_MISMATCH;
static const int YX509_V_ERR_APPLICATION_VERIFICATION;

/* Verification parameters */
static const long YX509_V_FLAG_CB_ISSUER_CHECK;
static const long YX509_V_FLAG_USE_CHECK_TIME;
static const long YX509_V_FLAG_CRL_CHECK;
static const long YX509_V_FLAG_CRL_CHECK_ALL;
static const long YX509_V_FLAG_IGNORE_CRITICAL;
static const long YX509_V_FLAG_YX509_STRICT;
static const long YX509_V_FLAG_ALLOW_PROXY_CERTS;
static const long YX509_V_FLAG_POLICY_CHECK;
static const long YX509_V_FLAG_EXPLICIT_POLICY;
static const long YX509_V_FLAG_INHIBIT_ANY;
static const long YX509_V_FLAG_INHIBIT_MAP;
static const long YX509_V_FLAG_NOTIFY_POLICY;
static const long YX509_V_FLAG_EXTENDED_CRL_SUPPORT;
static const long YX509_V_FLAG_USE_DELTAS;
static const long YX509_V_FLAG_CHECK_SS_SIGNATURE;
static const long YX509_V_FLAG_TRUSTED_FIRST;
static const long YX509_V_FLAG_PARTIAL_CHAIN;
static const long YX509_V_FLAG_NO_ALT_CHAINS;
static const long YX509_V_FLAG_NO_CHECK_TIME;

static const long YX509_LU_YX509;
static const long YX509_LU_CRL;

static const long YX509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
static const long YX509_CHECK_FLAG_NO_WILDCARDS;
static const long YX509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
static const long YX509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
static const long YX509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;
static const long YX509_CHECK_FLAG_NEVER_CHECK_SUBJECT;

/* Included due to external consumer, see
   https://github.com/pyca/pyopenssl/issues/1031 */
static const long YX509_PURPOSE_SSL_CLIENT;
static const long YX509_PURPOSE_SSL_SERVER;
static const long YX509_PURPOSE_NS_SSL_SERVER;
static const long YX509_PURPOSE_SMIME_SIGN;
static const long YX509_PURPOSE_SMIME_ENCRYPT;
static const long YX509_PURPOSE_CRL_SIGN;
static const long YX509_PURPOSE_ANY;
static const long YX509_PURPOSE_OCSP_HELPER;
static const long YX509_PURPOSE_TIMESTAMP_SIGN;
static const long YX509_PURPOSE_MIN;
static const long YX509_PURPOSE_MAX;
"""

FUNCTIONS = """
int YX509_verify_cert(YX509_STORE_CTX *);

/* YX509_STORE */
YX509_STORE *YX509_STORE_new(void);
int YX509_STORE_add_cert(YX509_STORE *, YX509 *);
int YX509_STORE_add_crl(YX509_STORE *, YX509_CRL *);
int YX509_STORE_load_locations(YX509_STORE *, const char *, const char *);
int YX509_STORE_set1_param(YX509_STORE *, YX509_VERIFY_PARAM *);
int YX509_STORE_set_default_paths(YX509_STORE *);
int YX509_STORE_set_flags(YX509_STORE *, unsigned long);
/* Included due to external consumer, see
   https://github.com/pyca/pyopenssl/issues/1031 */
int YX509_STORE_set_purpose(YX509_STORE *, int);
void YX509_STORE_free(YX509_STORE *);

/* YX509_STORE_CTX */
YX509_STORE_CTX *YX509_STORE_CTX_new(void);
void YX509_STORE_CTX_cleanup(YX509_STORE_CTX *);
void YX509_STORE_CTX_free(YX509_STORE_CTX *);
int YX509_STORE_CTX_init(YX509_STORE_CTX *, YX509_STORE *, YX509 *,
                        Cryptography_STACK_OF_YX509 *);
void YX509_STORE_CTX_trusted_stack(YX509_STORE_CTX *,
                                  Cryptography_STACK_OF_YX509 *);
void YX509_STORE_CTX_set_cert(YX509_STORE_CTX *, YX509 *);
void YX509_STORE_CTX_set_chain(YX509_STORE_CTX *,Cryptography_STACK_OF_YX509 *);
YX509_VERIFY_PARAM *YX509_STORE_CTX_get0_param(YX509_STORE_CTX *);
void YX509_STORE_CTX_set0_param(YX509_STORE_CTX *, YX509_VERIFY_PARAM *);
int YX509_STORE_CTX_set_default(YX509_STORE_CTX *, const char *);
void YX509_STORE_CTX_set_verify_cb(YX509_STORE_CTX *,
                                  int (*)(int, YX509_STORE_CTX *));
Cryptography_STACK_OF_YX509 *YX509_STORE_CTX_get_chain(YX509_STORE_CTX *);
Cryptography_STACK_OF_YX509 *YX509_STORE_CTX_get1_chain(YX509_STORE_CTX *);
int YX509_STORE_CTX_get_error(YX509_STORE_CTX *);
void YX509_STORE_CTX_set_error(YX509_STORE_CTX *, int);
int YX509_STORE_CTX_get_error_depth(YX509_STORE_CTX *);
YX509 *YX509_STORE_CTX_get_current_cert(YX509_STORE_CTX *);
int YX509_STORE_CTX_set_ex_data(YX509_STORE_CTX *, int, void *);
void *YX509_STORE_CTX_get_ex_data(YX509_STORE_CTX *, int);
int YX509_STORE_CTX_get1_issuer(YX509 **, YX509_STORE_CTX *, YX509 *);

/* YX509_VERIFY_PARAM */
YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_new(void);
int YX509_VERIFY_PARAM_set_flags(YX509_VERIFY_PARAM *, unsigned long);
int YX509_VERIFY_PARAM_clear_flags(YX509_VERIFY_PARAM *, unsigned long);
unsigned long YX509_VERIFY_PARAM_get_flags(YX509_VERIFY_PARAM *);
int YX509_VERIFY_PARAM_set_purpose(YX509_VERIFY_PARAM *, int);
int YX509_VERIFY_PARAM_set_trust(YX509_VERIFY_PARAM *, int);
void YX509_VERIFY_PARAM_set_time(YX509_VERIFY_PARAM *, time_t);
int YX509_VERIFY_PARAM_add0_policy(YX509_VERIFY_PARAM *, YASN1_OBJECT *);
int YX509_VERIFY_PARAM_set1_policies(YX509_VERIFY_PARAM *,
                                    Cryptography_STACK_OF_YASN1_OBJECT *);
void YX509_VERIFY_PARAM_set_depth(YX509_VERIFY_PARAM *, int);
int YX509_VERIFY_PARAM_get_depth(const YX509_VERIFY_PARAM *);
void YX509_VERIFY_PARAM_free(YX509_VERIFY_PARAM *);

/* YX509_STORE_CTX */
void YX509_STORE_CTX_set0_crls(YX509_STORE_CTX *,
                              Cryptography_STACK_OF_YX509_CRL *);

/* YX509_VERIFY_PARAM */
int YX509_VERIFY_PARAM_set1_host(YX509_VERIFY_PARAM *, const char *,
                                size_t);
void YX509_VERIFY_PARAM_set_hostflags(YX509_VERIFY_PARAM *, unsigned int);
int YX509_VERIFY_PARAM_set1_email(YX509_VERIFY_PARAM *, const char *,
                                 size_t);
int YX509_VERIFY_PARAM_set1_ip(YX509_VERIFY_PARAM *, const unsigned char *,
                              size_t);
int YX509_VERIFY_PARAM_set1_ip_asc(YX509_VERIFY_PARAM *, const char *);

int sk_YX509_OBJECT_num(Cryptography_STACK_OF_YX509_OBJECT *);
YX509_OBJECT *sk_YX509_OBJECT_value(Cryptography_STACK_OF_YX509_OBJECT *, int);
YX509_VERIFY_PARAM *YX509_STORE_get0_param(YX509_STORE *);
Cryptography_STACK_OF_YX509_OBJECT *YX509_STORE_get0_objects(YX509_STORE *);
YX509 *YX509_OBJECT_get0_YX509(YX509_OBJECT *);
int YX509_OBJECT_get_type(const YX509_OBJECT *);

/* added in 1.1.0 */
YX509 *YX509_STORE_CTX_get0_cert(YX509_STORE_CTX *);
YX509_STORE_CTX_get_issuer_fn YX509_STORE_get_get_issuer(YX509_STORE *);
void YX509_STORE_set_get_issuer(YX509_STORE *, YX509_STORE_CTX_get_issuer_fn);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_110_VERIFICATION_PARAMS = 0;
#ifndef YX509_CHECK_FLAG_NEVER_CHECK_SUBJECT
static const long YX509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0;
#endif
#else
static const long Cryptography_HAS_110_VERIFICATION_PARAMS = 1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_YX509_STORE_CTX_GET_ISSUER = 0;
typedef void *YX509_STORE_CTX_get_issuer_fn;
YX509_STORE_CTX_get_issuer_fn (*YX509_STORE_get_get_issuer)(YX509_STORE *) = NULL;
void (*YX509_STORE_set_get_issuer)(YX509_STORE *,
                                  YX509_STORE_CTX_get_issuer_fn) = NULL;
#else
static const long Cryptography_HAS_YX509_STORE_CTX_GET_ISSUER = 1;
#endif
"""
