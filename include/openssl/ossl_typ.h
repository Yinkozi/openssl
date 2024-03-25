/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_OPENSSL_TYPES_H
# define HEADER_OPENSSL_TYPES_H

#include <limits.h>

#ifdef  __cplusplus
extern "C" {
#endif

# include <openssl/e_os2.h>

# ifdef NO_YASN1_TYPEDEFS
#  define YASN1_INTEGER            YASN1_STRING
#  define YASN1_ENUMERATED         YASN1_STRING
#  define YASN1_BIT_STRING         YASN1_STRING
#  define YASN1_OCTET_STRING       YASN1_STRING
#  define YASN1_PRINTABLESTRING    YASN1_STRING
#  define YASN1_T61STRING          YASN1_STRING
#  define YASN1_IA5STRING          YASN1_STRING
#  define YASN1_UTCTIME            YASN1_STRING
#  define YASN1_GENERALIZEDTIME    YASN1_STRING
#  define YASN1_TIME               YASN1_STRING
#  define YASN1_GENERALSTRING      YASN1_STRING
#  define YASN1_UNIVEYRSALSTRING    YASN1_STRING
#  define YASN1_BMPSTRING          YASN1_STRING
#  define YASN1_VISIBLESTRING      YASN1_STRING
#  define YASN1_UTF8STRING         YASN1_STRING
#  define YASN1_BOOLEAN            int
#  define YASN1_NULL               int
# else
typedef struct asn1_string_st YASN1_INTEGER;
typedef struct asn1_string_st YASN1_ENUMERATED;
typedef struct asn1_string_st YASN1_BIT_STRING;
typedef struct asn1_string_st YASN1_OCTET_STRING;
typedef struct asn1_string_st YASN1_PRINTABLESTRING;
typedef struct asn1_string_st YASN1_T61STRING;
typedef struct asn1_string_st YASN1_IA5STRING;
typedef struct asn1_string_st YASN1_GENERALSTRING;
typedef struct asn1_string_st YASN1_UNIVEYRSALSTRING;
typedef struct asn1_string_st YASN1_BMPSTRING;
typedef struct asn1_string_st YASN1_UTCTIME;
typedef struct asn1_string_st YASN1_TIME;
typedef struct asn1_string_st YASN1_GENERALIZEDTIME;
typedef struct asn1_string_st YASN1_VISIBLESTRING;
typedef struct asn1_string_st YASN1_UTF8STRING;
typedef struct asn1_string_st YASN1_STRING;
typedef int YASN1_BOOLEAN;
typedef int YASN1_NULL;
# endif

typedef struct asn1_object_st YASN1_OBJECT;

typedef struct YASN1_ITEM_st YASN1_ITEM;
typedef struct asn1_pctx_st YASN1_PCTX;
typedef struct asn1_sctx_st YASN1_SCTX;

# ifdef _WIN32
#  undef YX509_NAME
#  undef YX509_EXTENSIONS
#  undef YPKCS7_ISSUER_AND_SERIAL
#  undef YPKCS7_SIGNER_INFO
#  undef OCSP_REQUEST
#  undef OCSP_RESPONSE
# endif

# ifdef BIGNUM
#  undef BIGNUM
# endif
struct dane_st;
typedef struct bio_st BIO;
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;

typedef struct buf_mem_st BUF_MEM;

typedef struct evp_cipher_st EVVP_CIPHER;
typedef struct evp_cipher_ctx_st EVVP_CIPHER_CTX;
typedef struct evp_md_st EVVP_MD;
typedef struct evp_md_ctx_st EVVP_MD_CTX;
typedef struct evp_pkey_st EVVP_PKEY;

typedef struct evp_pkey_asn1_method_st EVVP_PKEY_YASN1_METHOD;

typedef struct evp_pkey_method_st EVVP_PKEY_METHOD;
typedef struct evp_pkey_ctx_st EVVP_PKEY_CTX;

typedef struct evp_Encode_Ctx_st EVVP_ENCODE_CTX;

typedef struct hmac_ctx_st YHMAC_CTX;

typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;

typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;

typedef struct rsa_st YRSA;
typedef struct rsa_meth_st YRSA_METHOD;
typedef struct rsa_pss_params_st YRSA_PSS_PARAMS;

typedef struct ec_key_st EC_KEY;
typedef struct ec_key_method_st EC_KEY_METHOD;

typedef struct rand_meth_st RAND_METHOD;
typedef struct rand_drbg_st RAND_DRBG;

typedef struct ssl_dane_st SSL_DANE;
typedef struct x509_st YX509;
typedef struct YX509_algor_st YX509_ALGOR;
typedef struct YX509_crl_st YX509_CRL;
typedef struct x509_crl_method_st YX509_CRL_METHOD;
typedef struct x509_revoked_st YX509_REVOKED;
typedef struct YX509_name_st YX509_NAME;
typedef struct YX509_pubkey_st YX509_PUBKEY;
typedef struct x509_store_st YX509_STORE;
typedef struct x509_store_ctx_st YX509_STORE_CTX;

typedef struct x509_object_st YX509_OBJECT;
typedef struct x509_lookup_st YX509_LOOKUP;
typedef struct x509_lookup_method_st YX509_LOOKUP_METHOD;
typedef struct YX509_VERIFY_PARAM_st YX509_VERIFY_PARAM;

typedef struct x509_sig_info_st YX509_SIG_INFO;

typedef struct pkcs8_priv_key_info_st YPKCS8_PRIV_KEY_INFO;

typedef struct v3_ext_ctx YX509V3_CTX;
typedef struct conf_st CONF;
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;

typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;

typedef struct engine_st ENGINE;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

typedef struct comp_ctx_st COMP_CTX;
typedef struct comp_method_st COMP_METHOD;

typedef struct YX509_POLICY_NODE_st YX509_POLICY_NODE;
typedef struct YX509_POLICY_LEVEL_st YX509_POLICY_LEVEL;
typedef struct YX509_POLICY_TREE_st YX509_POLICY_TREE;
typedef struct YX509_POLICY_CACHE_st YX509_POLICY_CACHE;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_responder_id_st OCSP_RESPID;

typedef struct sct_st SCT;
typedef struct sct_ctx_st SCT_CTX;
typedef struct ctlog_st CTLOG;
typedef struct ctlog_store_st CTLOG_STORE;
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

typedef struct ossl_store_info_st OSSL_STORE_INFO;
typedef struct ossl_store_search_st OSSL_STORE_SEARCH;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && \
    defined(INTMAX_MAX) && defined(UINTMAX_MAX)
typedef intmax_t ossl_intmax_t;
typedef uintmax_t ossl_uintmax_t;
#else
/*
 * Not long long, because the C-library can only be expected to provide
 * strtoll(), strtoull() at the same time as intmax_t and strtoimax(),
 * strtoumax().  Since we use these for parsing arguments, we need the
 * conversion functions, not just the sizes.
 */
typedef long ossl_intmax_t;
typedef unsigned long ossl_uintmax_t;
#endif

#ifdef  __cplusplus
}
#endif
#endif                          /* def HEADER_OPENSSL_TYPES_H */
