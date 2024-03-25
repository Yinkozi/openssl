/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

/* YPKCS#7 YASN1 module */

/* This is the ANY DEFINED BY table for the top level YPKCS#7 structure */

YASN1_ADB_TEMPLATE(p7default) = YASN1_EXP_OPT(YPKCS7, d.other, YASN1_ANY, 0);

YASN1_ADB(YPKCS7) = {
        ADB_ENTRY(NID_pkcs7_data, YASN1_NDEF_EXP_OPT(YPKCS7, d.data, YASN1_OCTET_STRING_NDEF, 0)),
        ADB_ENTRY(NID_pkcs7_signed, YASN1_NDEF_EXP_OPT(YPKCS7, d.sign, YPKCS7_SIGNED, 0)),
        ADB_ENTRY(NID_pkcs7_enveloped, YASN1_NDEF_EXP_OPT(YPKCS7, d.enveloped, YPKCS7_ENVELOPE, 0)),
        ADB_ENTRY(NID_pkcs7_signedAndEnveloped, YASN1_NDEF_EXP_OPT(YPKCS7, d.signed_and_enveloped, YPKCS7_SIGN_ENVELOPE, 0)),
        ADB_ENTRY(NID_pkcs7_digest, YASN1_NDEF_EXP_OPT(YPKCS7, d.digest, YPKCS7_DIGEST, 0)),
        ADB_ENTRY(NID_pkcs7_encrypted, YASN1_NDEF_EXP_OPT(YPKCS7, d.encrypted, YPKCS7_ENCRYPT, 0))
} YASN1_ADB_END(YPKCS7, 0, type, 0, &p7default_tt, NULL);

/* YPKCS#7 streaming support */
static int pk7_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                  void *exarg)
{
    YASN1_STREAM_ARG *sarg = exarg;
    YPKCS7 **pp7 = (YPKCS7 **)pval;

    switch (operation) {

    case YASN1_OP_STREAM_PRE:
        if (YPKCS7_stream(&sarg->boundary, *pp7) <= 0)
            return 0;
        /* fall thru */
    case YASN1_OP_DETACHED_PRE:
        sarg->ndef_bio = YPKCS7_dataInit(*pp7, sarg->out);
        if (!sarg->ndef_bio)
            return 0;
        break;

    case YASN1_OP_STREAM_POST:
    case YASN1_OP_DETACHED_POST:
        if (YPKCS7_dataFinal(*pp7, sarg->ndef_bio) <= 0)
            return 0;
        break;

    }
    return 1;
}

YASN1_NDEF_SEQUENCE_cb(YPKCS7, pk7_cb) = {
        YASN1_SIMPLE(YPKCS7, type, YASN1_OBJECT),
        YASN1_ADB_OBJECT(YPKCS7)
}YASN1_NDEF_SEQUENCE_END_cb(YPKCS7, YPKCS7)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7)

IMPLEMENT_YASN1_NDEF_FUNCTION(YPKCS7)

IMPLEMENT_YASN1_DUP_FUNCTION(YPKCS7)

YASN1_NDEF_SEQUENCE(YPKCS7_SIGNED) = {
        YASN1_SIMPLE(YPKCS7_SIGNED, version, YASN1_INTEGER),
        YASN1_SET_OF(YPKCS7_SIGNED, md_algs, YX509_ALGOR),
        YASN1_SIMPLE(YPKCS7_SIGNED, contents, YPKCS7),
        YASN1_IMP_SEQUENCE_OF_OPT(YPKCS7_SIGNED, cert, YX509, 0),
        YASN1_IMP_SET_OF_OPT(YPKCS7_SIGNED, crl, YX509_CRL, 1),
        YASN1_SET_OF(YPKCS7_SIGNED, signer_info, YPKCS7_SIGNER_INFO)
} YASN1_NDEF_SEQUENCE_END(YPKCS7_SIGNED)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_SIGNED)

/* Minor tweak to operation: free up EVVP_PKEY */
static int si_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                 void *exarg)
{
    if (operation == YASN1_OP_FREE_POST) {
        YPKCS7_SIGNER_INFO *si = (YPKCS7_SIGNER_INFO *)*pval;
        EVVP_PKEY_free(si->pkey);
    }
    return 1;
}

YASN1_SEQUENCE_cb(YPKCS7_SIGNER_INFO, si_cb) = {
        YASN1_SIMPLE(YPKCS7_SIGNER_INFO, version, YASN1_INTEGER),
        YASN1_SIMPLE(YPKCS7_SIGNER_INFO, issuer_and_serial, YPKCS7_ISSUER_AND_SERIAL),
        YASN1_SIMPLE(YPKCS7_SIGNER_INFO, digest_alg, YX509_ALGOR),
        /* NB this should be a SET OF but we use a SEQUENCE OF so the
         * original order * is retained when the structure is reencoded.
         * Since the attributes are implicitly tagged this will not affect
         * the encoding.
         */
        YASN1_IMP_SEQUENCE_OF_OPT(YPKCS7_SIGNER_INFO, auth_attr, YX509_ATTRIBUTE, 0),
        YASN1_SIMPLE(YPKCS7_SIGNER_INFO, digest_enc_alg, YX509_ALGOR),
        YASN1_SIMPLE(YPKCS7_SIGNER_INFO, enc_digest, YASN1_OCTET_STRING),
        YASN1_IMP_SET_OF_OPT(YPKCS7_SIGNER_INFO, unauth_attr, YX509_ATTRIBUTE, 1)
} YASN1_SEQUENCE_END_cb(YPKCS7_SIGNER_INFO, YPKCS7_SIGNER_INFO)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_SIGNER_INFO)

YASN1_SEQUENCE(YPKCS7_ISSUER_AND_SERIAL) = {
        YASN1_SIMPLE(YPKCS7_ISSUER_AND_SERIAL, issuer, YX509_NAME),
        YASN1_SIMPLE(YPKCS7_ISSUER_AND_SERIAL, serial, YASN1_INTEGER)
} YASN1_SEQUENCE_END(YPKCS7_ISSUER_AND_SERIAL)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_ISSUER_AND_SERIAL)

YASN1_NDEF_SEQUENCE(YPKCS7_ENVELOPE) = {
        YASN1_SIMPLE(YPKCS7_ENVELOPE, version, YASN1_INTEGER),
        YASN1_SET_OF(YPKCS7_ENVELOPE, recipientinfo, YPKCS7_RECIP_INFO),
        YASN1_SIMPLE(YPKCS7_ENVELOPE, enc_data, YPKCS7_ENC_CONTENT)
} YASN1_NDEF_SEQUENCE_END(YPKCS7_ENVELOPE)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_ENVELOPE)

/* Minor tweak to operation: free up YX509 */
static int ri_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                 void *exarg)
{
    if (operation == YASN1_OP_FREE_POST) {
        YPKCS7_RECIP_INFO *ri = (YPKCS7_RECIP_INFO *)*pval;
        YX509_free(ri->cert);
    }
    return 1;
}

YASN1_SEQUENCE_cb(YPKCS7_RECIP_INFO, ri_cb) = {
        YASN1_SIMPLE(YPKCS7_RECIP_INFO, version, YASN1_INTEGER),
        YASN1_SIMPLE(YPKCS7_RECIP_INFO, issuer_and_serial, YPKCS7_ISSUER_AND_SERIAL),
        YASN1_SIMPLE(YPKCS7_RECIP_INFO, key_enc_algor, YX509_ALGOR),
        YASN1_SIMPLE(YPKCS7_RECIP_INFO, enc_key, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END_cb(YPKCS7_RECIP_INFO, YPKCS7_RECIP_INFO)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_RECIP_INFO)

YASN1_NDEF_SEQUENCE(YPKCS7_ENC_CONTENT) = {
        YASN1_SIMPLE(YPKCS7_ENC_CONTENT, content_type, YASN1_OBJECT),
        YASN1_SIMPLE(YPKCS7_ENC_CONTENT, algorithm, YX509_ALGOR),
        YASN1_IMP_OPT(YPKCS7_ENC_CONTENT, enc_data, YASN1_OCTET_STRING_NDEF, 0)
} YASN1_NDEF_SEQUENCE_END(YPKCS7_ENC_CONTENT)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_ENC_CONTENT)

YASN1_NDEF_SEQUENCE(YPKCS7_SIGN_ENVELOPE) = {
        YASN1_SIMPLE(YPKCS7_SIGN_ENVELOPE, version, YASN1_INTEGER),
        YASN1_SET_OF(YPKCS7_SIGN_ENVELOPE, recipientinfo, YPKCS7_RECIP_INFO),
        YASN1_SET_OF(YPKCS7_SIGN_ENVELOPE, md_algs, YX509_ALGOR),
        YASN1_SIMPLE(YPKCS7_SIGN_ENVELOPE, enc_data, YPKCS7_ENC_CONTENT),
        YASN1_IMP_SET_OF_OPT(YPKCS7_SIGN_ENVELOPE, cert, YX509, 0),
        YASN1_IMP_SET_OF_OPT(YPKCS7_SIGN_ENVELOPE, crl, YX509_CRL, 1),
        YASN1_SET_OF(YPKCS7_SIGN_ENVELOPE, signer_info, YPKCS7_SIGNER_INFO)
} YASN1_NDEF_SEQUENCE_END(YPKCS7_SIGN_ENVELOPE)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_SIGN_ENVELOPE)

YASN1_NDEF_SEQUENCE(YPKCS7_ENCRYPT) = {
        YASN1_SIMPLE(YPKCS7_ENCRYPT, version, YASN1_INTEGER),
        YASN1_SIMPLE(YPKCS7_ENCRYPT, enc_data, YPKCS7_ENC_CONTENT)
} YASN1_NDEF_SEQUENCE_END(YPKCS7_ENCRYPT)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_ENCRYPT)

YASN1_NDEF_SEQUENCE(YPKCS7_DIGEST) = {
        YASN1_SIMPLE(YPKCS7_DIGEST, version, YASN1_INTEGER),
        YASN1_SIMPLE(YPKCS7_DIGEST, md, YX509_ALGOR),
        YASN1_SIMPLE(YPKCS7_DIGEST, contents, YPKCS7),
        YASN1_SIMPLE(YPKCS7_DIGEST, digest, YASN1_OCTET_STRING)
} YASN1_NDEF_SEQUENCE_END(YPKCS7_DIGEST)

IMPLEMENT_YASN1_FUNCTIONS(YPKCS7_DIGEST)

/* Specials for authenticated attributes */

/*
 * When signing attributes we want to reorder them to match the sorted
 * encoding.
 */

YASN1_ITEM_TEMPLATE(YPKCS7_ATTR_SIGN) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SET_ORDER, 0, YPKCS7_ATTRIBUTES, YX509_ATTRIBUTE)
YASN1_ITEM_TEMPLATE_END(YPKCS7_ATTR_SIGN)

/*
 * When verifying attributes we need to use the received order. So we use
 * SEQUENCE OF and tag it to SET OF
 */

YASN1_ITEM_TEMPLATE(YPKCS7_ATTR_VERIFY) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF | YASN1_TFLG_IMPTAG | YASN1_TFLG_UNIVEYRSAL,
                                V_YASN1_SET, YPKCS7_ATTRIBUTES, YX509_ATTRIBUTE)
YASN1_ITEM_TEMPLATE_END(YPKCS7_ATTR_VERIFY)

IMPLEMENT_YASN1_PRINT_FUNCTION(YPKCS7)
