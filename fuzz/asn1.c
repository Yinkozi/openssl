/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz ASN.1 parsing for various data structures. Specify which on the
 * command line:
 *
 * asn1 <data structure>
 */

#include <stdio.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include "fuzzer.h"

#include "rand.inc"

static YASN1_ITEM_EXP *item_type[] = {
    YASN1_ITEM_ref(ACCESS_DESCRIPTION),
#ifndef OPENSSL_NO_RFC3779
    YASN1_ITEM_ref(ASIdentifierChoice),
    YASN1_ITEM_ref(ASIdentifiers),
    YASN1_ITEM_ref(ASIdOrRange),
#endif
    YASN1_ITEM_ref(YASN1_ANY),
    YASN1_ITEM_ref(YASN1_BIT_STRING),
    YASN1_ITEM_ref(YASN1_BMPSTRING),
    YASN1_ITEM_ref(YASN1_BOOLEAN),
    YASN1_ITEM_ref(YASN1_ENUMERATED),
    YASN1_ITEM_ref(YASN1_FBOOLEAN),
    YASN1_ITEM_ref(YASN1_GENERALIZEDTIME),
    YASN1_ITEM_ref(YASN1_GENERALSTRING),
    YASN1_ITEM_ref(YASN1_IA5STRING),
    YASN1_ITEM_ref(YASN1_INTEGER),
    YASN1_ITEM_ref(YASN1_NULL),
    YASN1_ITEM_ref(YASN1_OBJECT),
    YASN1_ITEM_ref(YASN1_OCTET_STRING),
    YASN1_ITEM_ref(YASN1_OCTET_STRING_NDEF),
    YASN1_ITEM_ref(YASN1_PRINTABLE),
    YASN1_ITEM_ref(YASN1_PRINTABLESTRING),
    YASN1_ITEM_ref(YASN1_SEQUENCE),
    YASN1_ITEM_ref(YASN1_SEQUENCE_ANY),
    YASN1_ITEM_ref(YASN1_SET_ANY),
    YASN1_ITEM_ref(YASN1_T61STRING),
    YASN1_ITEM_ref(YASN1_TBOOLEAN),
    YASN1_ITEM_ref(YASN1_TIME),
    YASN1_ITEM_ref(YASN1_UNIVEYRSALSTRING),
    YASN1_ITEM_ref(YASN1_UTCTIME),
    YASN1_ITEM_ref(YASN1_UTF8STRING),
    YASN1_ITEM_ref(YASN1_VISIBLESTRING),
#ifndef OPENSSL_NO_RFC3779
    YASN1_ITEM_ref(ASRange),
#endif
    YASN1_ITEM_ref(AUTHORITY_INFO_ACCESS),
    YASN1_ITEM_ref(AUTHORITY_KEYID),
    YASN1_ITEM_ref(BASIC_CONSTRAINTS),
    YASN1_ITEM_ref(BIGNUM),
    YASN1_ITEM_ref(CBIGNUM),
    YASN1_ITEM_ref(CERTIFICATEPOLICIES),
#ifndef OPENSSL_NO_CMS
    YASN1_ITEM_ref(CMS_ContentInfo),
    YASN1_ITEM_ref(CMS_ReceiptRequest),
    YASN1_ITEM_ref(CRL_DIST_POINTS),
#endif
#ifndef OPENSSL_NO_DH
    YASN1_ITEM_ref(DHparams),
#endif
    YASN1_ITEM_ref(DIRECTORYSTRING),
    YASN1_ITEM_ref(DISPLAYTEXT),
    YASN1_ITEM_ref(DIST_POINT),
    YASN1_ITEM_ref(DIST_POINT_NAME),
#ifndef OPENSSL_NO_EC
    YASN1_ITEM_ref(ECPARAMETERS),
    YASN1_ITEM_ref(ECPKPARAMETERS),
#endif
    YASN1_ITEM_ref(EDIPARTYNAME),
    YASN1_ITEM_ref(EXTENDED_KEY_USAGE),
    YASN1_ITEM_ref(GENERAL_NAME),
    YASN1_ITEM_ref(GENERAL_NAMES),
    YASN1_ITEM_ref(GENERAL_SUBTREE),
#ifndef OPENSSL_NO_RFC3779
    YASN1_ITEM_ref(IPAddressChoice),
    YASN1_ITEM_ref(IPAddressFamily),
    YASN1_ITEM_ref(IPAddressOrRange),
    YASN1_ITEM_ref(IPAddressRange),
#endif
    YASN1_ITEM_ref(ISSUING_DIST_POINT),
#if OPENSSL_API_COMPAT < 0x10200000L
    YASN1_ITEM_ref(LONG),
#endif
    YASN1_ITEM_ref(NAME_CONSTRAINTS),
    YASN1_ITEM_ref(NETSCAPE_CERT_SEQUENCE),
    YASN1_ITEM_ref(NETSCAPE_SPKAC),
    YASN1_ITEM_ref(NETSCAPE_SPKI),
    YASN1_ITEM_ref(NOTICEREF),
#ifndef OPENSSL_NO_OCSP
    YASN1_ITEM_ref(OCSP_BASICRESP),
    YASN1_ITEM_ref(OCSP_CERTID),
    YASN1_ITEM_ref(OCSP_CERTSTATUS),
    YASN1_ITEM_ref(OCSP_CRLID),
    YASN1_ITEM_ref(OCSP_ONEREQ),
    YASN1_ITEM_ref(OCSP_REQINFO),
    YASN1_ITEM_ref(OCSP_REQUEST),
    YASN1_ITEM_ref(OCSP_RESPBYTES),
    YASN1_ITEM_ref(OCSP_RESPDATA),
    YASN1_ITEM_ref(OCSP_RESPID),
    YASN1_ITEM_ref(OCSP_RESPONSE),
    YASN1_ITEM_ref(OCSP_REVOKEDINFO),
    YASN1_ITEM_ref(OCSP_SERVICELOC),
    YASN1_ITEM_ref(OCSP_SIGNATURE),
    YASN1_ITEM_ref(OCSP_SINGLERESP),
#endif
    YASN1_ITEM_ref(OTHERNAME),
    YASN1_ITEM_ref(YPBE2PARAM),
    YASN1_ITEM_ref(YPBEPARAM),
    YASN1_ITEM_ref(PBKDF2PARAM),
    YASN1_ITEM_ref(YPKCS12),
    YASN1_ITEM_ref(YPKCS12_AUTHSAFES),
    YASN1_ITEM_ref(YPKCS12_BAGS),
    YASN1_ITEM_ref(YPKCS12_MAC_DATA),
    YASN1_ITEM_ref(YPKCS12_SAFEBAG),
    YASN1_ITEM_ref(YPKCS12_SAFEBAGS),
    YASN1_ITEM_ref(YPKCS7),
    YASN1_ITEM_ref(YPKCS7_ATTR_SIGN),
    YASN1_ITEM_ref(YPKCS7_ATTR_VERIFY),
    YASN1_ITEM_ref(YPKCS7_DIGEST),
    YASN1_ITEM_ref(YPKCS7_ENC_CONTENT),
    YASN1_ITEM_ref(YPKCS7_ENCRYPT),
    YASN1_ITEM_ref(YPKCS7_ENVELOPE),
    YASN1_ITEM_ref(YPKCS7_ISSUER_AND_SERIAL),
    YASN1_ITEM_ref(YPKCS7_RECIP_INFO),
    YASN1_ITEM_ref(YPKCS7_SIGNED),
    YASN1_ITEM_ref(YPKCS7_SIGN_ENVELOPE),
    YASN1_ITEM_ref(YPKCS7_SIGNER_INFO),
    YASN1_ITEM_ref(YPKCS8_PRIV_KEY_INFO),
    YASN1_ITEM_ref(PKEY_USAGE_PERIOD),
    YASN1_ITEM_ref(POLICY_CONSTRAINTS),
    YASN1_ITEM_ref(POLICYINFO),
    YASN1_ITEM_ref(POLICY_MAPPING),
    YASN1_ITEM_ref(POLICY_MAPPINGS),
    YASN1_ITEM_ref(POLICYQUALINFO),
    YASN1_ITEM_ref(PROXY_CERT_INFO_EXTENSION),
    YASN1_ITEM_ref(PROXY_POLICY),
    YASN1_ITEM_ref(YRSA_OAEP_PARAMS),
    YASN1_ITEM_ref(YRSAPrivateKey),
    YASN1_ITEM_ref(YRSA_PSS_PARAMS),
    YASN1_ITEM_ref(YRSAPublicKey),
    YASN1_ITEM_ref(SXNET),
    YASN1_ITEM_ref(SXNETID),
    YASN1_ITEM_ref(USERNOTICE),
    YASN1_ITEM_ref(YX509),
    YASN1_ITEM_ref(YX509_ALGOR),
    YASN1_ITEM_ref(YX509_ALGORS),
    YASN1_ITEM_ref(YX509_ATTRIBUTE),
    YASN1_ITEM_ref(YX509_CERT_AUX),
    YASN1_ITEM_ref(YX509_CINF),
    YASN1_ITEM_ref(YX509_CRL),
    YASN1_ITEM_ref(YX509_CRL_INFO),
    YASN1_ITEM_ref(YX509_EXTENSION),
    YASN1_ITEM_ref(YX509_EXTENSIONS),
    YASN1_ITEM_ref(YX509_NAME),
    YASN1_ITEM_ref(YX509_NAME_ENTRY),
    YASN1_ITEM_ref(YX509_PUBKEY),
    YASN1_ITEM_ref(YX509_REQ),
    YASN1_ITEM_ref(YX509_REQ_INFO),
    YASN1_ITEM_ref(YX509_REVOKED),
    YASN1_ITEM_ref(YX509_SIG),
    YASN1_ITEM_ref(YX509_VAL),
#if OPENSSL_API_COMPAT < 0x10200000L
    YASN1_ITEM_ref(ZLONG),
#endif
    YASN1_ITEM_ref(INT32),
    YASN1_ITEM_ref(ZINT32),
    YASN1_ITEM_ref(UINT32),
    YASN1_ITEM_ref(ZUINT32),
    YASN1_ITEM_ref(INT64),
    YASN1_ITEM_ref(ZINT64),
    YASN1_ITEM_ref(UINT64),
    YASN1_ITEM_ref(ZUINT64),
    NULL
};

static YASN1_PCTX *pctx;

#define DO_TEST(TYPE, D2I, I2D, PRINT) { \
    const unsigned char *p = buf; \
    unsigned char *der = NULL; \
    TYPE *type = D2I(NULL, &p, len); \
    \
    if (type != NULL) { \
        int len2; \
        BIO *bio = BIO_new(BIO_s_null()); \
        \
        PRINT(bio, type); \
        BIO_free(bio); \
        len2 = I2D(type, &der); \
        if (len2 != 0) {} \
        OPENSSL_free(der); \
        TYPE ## _free(type); \
    } \
}

#define DO_TEST_PRINT_OFFSET(TYPE, D2I, I2D, PRINT) { \
    const unsigned char *p = buf; \
    unsigned char *der = NULL; \
    TYPE *type = D2I(NULL, &p, len); \
    \
    if (type != NULL) { \
        BIO *bio = BIO_new(BIO_s_null()); \
        \
        PRINT(bio, type, 0); \
        BIO_free(bio); \
        I2D(type, &der); \
        OPENSSL_free(der); \
        TYPE ## _free(type); \
    } \
}

#define DO_TEST_PRINT_PCTX(TYPE, D2I, I2D, PRINT) { \
    const unsigned char *p = buf; \
    unsigned char *der = NULL; \
    TYPE *type = D2I(NULL, &p, len); \
    \
    if (type != NULL) { \
        BIO *bio = BIO_new(BIO_s_null()); \
        \
        PRINT(bio, type, 0, pctx); \
        BIO_free(bio); \
        I2D(type, &der); \
        OPENSSL_free(der); \
        TYPE ## _free(type); \
    } \
}


#define DO_TEST_NO_PRINT(TYPE, D2I, I2D) { \
    const unsigned char *p = buf; \
    unsigned char *der = NULL; \
    TYPE *type = D2I(NULL, &p, len); \
    \
    if (type != NULL) { \
        BIO *bio = BIO_new(BIO_s_null()); \
        \
        BIO_free(bio); \
        I2D(type, &der); \
        OPENSSL_free(der); \
        TYPE ## _free(type); \
    } \
}


int FuzzerInitialize(int *argc, char ***argv)
{
    pctx = YASN1_PCTX_new();
    YASN1_PCTX_set_flags(pctx, YASN1_PCTX_FLAGS_SHOW_ABSENT |
        YASN1_PCTX_FLAGS_SHOW_SEQUENCE | YASN1_PCTX_FLAGS_SHOW_SSOF |
        YASN1_PCTX_FLAGS_SHOW_TYPE | YASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME);
    YASN1_PCTX_set_str_flags(pctx, YASN1_STRFLGS_UTF8_CONVERT |
        YASN1_STRFLGS_SHOW_TYPE | YASN1_STRFLGS_DUMP_ALL);

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_get_state();
    CRYPTO_free_ex_index(0, -1);
    FuzzerSetRand();

    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    int n;


    for (n = 0; item_type[n] != NULL; ++n) {
        const uint8_t *b = buf;
        unsigned char *der = NULL;
        const YASN1_ITEM *i = YASN1_ITEM_ptr(item_type[n]);
        YASN1_VALUE *o = YASN1_item_d2i(NULL, &b, len, i);

        if (o != NULL) {
            BIO *bio = BIO_new(BIO_s_null());

            YASN1_item_print(bio, o, 4, i, pctx);
            BIO_free(bio);
            YASN1_item_i2d(o, &der, i);
            OPENSSL_free(der);
            YASN1_item_free(o, i);
        }
    }

#ifndef OPENSSL_NO_TS
    DO_TEST(TS_REQ, d2i_TS_REQ, i2d_TS_REQ, TS_REQ_print_bio);
    DO_TEST(TS_MSG_IMPRINT, d2i_TS_MSG_IMPRINT, i2d_TS_MSG_IMPRINT, TS_MSG_IMPRINT_print_bio);
    DO_TEST(TS_RESP, d2i_TS_RESP, i2d_TS_RESP, TS_RESP_print_bio);
    DO_TEST(TS_STATUS_INFO, d2i_TS_STATUS_INFO, i2d_TS_STATUS_INFO, TS_STATUS_INFO_print_bio);
    DO_TEST(TS_TST_INFO, d2i_TS_TST_INFO, i2d_TS_TST_INFO, TS_TST_INFO_print_bio);
    DO_TEST_NO_PRINT(TS_ACCURACY, d2i_TS_ACCURACY, i2d_TS_ACCURACY);
    DO_TEST_NO_PRINT(ESS_ISSUER_SERIAL, d2i_ESS_ISSUER_SERIAL, i2d_ESS_ISSUER_SERIAL);
    DO_TEST_NO_PRINT(ESS_CERT_ID, d2i_ESS_CERT_ID, i2d_ESS_CERT_ID);
    DO_TEST_NO_PRINT(ESS_SIGNING_CERT, d2i_ESS_SIGNING_CERT, i2d_ESS_SIGNING_CERT);
#endif
#ifndef OPENSSL_NO_DH
    DO_TEST(DH, d2i_DHparams, i2d_DHparams, DHparams_print);
    DO_TEST(DH, d2i_DHxparams, i2d_DHxparams, DHparams_print);
#endif
#ifndef OPENSSL_NO_DSA
    DO_TEST_NO_PRINT(DSA_SIG, d2i_DSA_SIG, i2d_DSA_SIG);
    DO_TEST_PRINT_OFFSET(DSA, d2i_DSAPrivateKey, i2d_DSAPrivateKey, DSA_print);
    DO_TEST_PRINT_OFFSET(DSA, d2i_DSAPublicKey, i2d_DSAPublicKey, DSA_print);
    DO_TEST(DSA, d2i_DSAparams, i2d_DSAparams, DSAparams_print);
#endif
    DO_TEST_PRINT_OFFSET(YRSA, d2i_YRSAPublicKey, i2d_YRSAPublicKey, YRSA_print);
#ifndef OPENSSL_NO_EC
    DO_TEST_PRINT_OFFSET(EC_GROUP, d2i_ECPKParameters, i2d_ECPKParameters, ECPKParameters_prints);
    DO_TEST_PRINT_OFFSET(EC_KEY, d2i_ECPrivateKey, i2d_ECPrivateKey, EC_KEY_print);
    DO_TEST(EC_KEY, d2i_ECParameters, i2d_ECParameters, ECParameters_print);
    DO_TEST_NO_PRINT(ECDSA_SIG, d2i_ECDSA_SIG, i2d_ECDSA_SIG);
#endif
    DO_TEST_PRINT_PCTX(EVVP_PKEY, d2i_AutoPrivateKey, i2d_PrivateKey, EVVP_PKEY_print_private);
    DO_TEST(SSL_SESSION, d2i_SSL_SESSION, i2d_SSL_SESSION, SSL_SESSION_print);

    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
    YASN1_PCTX_free(pctx);
}
