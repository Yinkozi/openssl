/*
 * Copyright 2008-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include "cms_local.h"


YASN1_SEQUENCE(CMS_IssuerAndSerialNumber) = {
        YASN1_SIMPLE(CMS_IssuerAndSerialNumber, issuer, YX509_NAME),
        YASN1_SIMPLE(CMS_IssuerAndSerialNumber, serialNumber, YASN1_INTEGER)
} YASN1_SEQUENCE_END(CMS_IssuerAndSerialNumber)

YASN1_SEQUENCE(CMS_OtherCertificateFormat) = {
        YASN1_SIMPLE(CMS_OtherCertificateFormat, otherCertFormat, YASN1_OBJECT),
        YASN1_OPT(CMS_OtherCertificateFormat, otherCert, YASN1_ANY)
} static_YASN1_SEQUENCE_END(CMS_OtherCertificateFormat)

YASN1_CHOICE(CMS_CertificateChoices) = {
        YASN1_SIMPLE(CMS_CertificateChoices, d.certificate, YX509),
        YASN1_IMP(CMS_CertificateChoices, d.extendedCertificate, YASN1_SEQUENCE, 0),
        YASN1_IMP(CMS_CertificateChoices, d.v1AttrCert, YASN1_SEQUENCE, 1),
        YASN1_IMP(CMS_CertificateChoices, d.v2AttrCert, YASN1_SEQUENCE, 2),
        YASN1_IMP(CMS_CertificateChoices, d.other, CMS_OtherCertificateFormat, 3)
} YASN1_CHOICE_END(CMS_CertificateChoices)

YASN1_CHOICE(CMS_SignerIdentifier) = {
        YASN1_SIMPLE(CMS_SignerIdentifier, d.issuerAndSerialNumber, CMS_IssuerAndSerialNumber),
        YASN1_IMP(CMS_SignerIdentifier, d.subjectKeyIdentifier, YASN1_OCTET_STRING, 0)
} static_YASN1_CHOICE_END(CMS_SignerIdentifier)

YASN1_NDEF_SEQUENCE(CMS_EncapsulatedContentInfo) = {
        YASN1_SIMPLE(CMS_EncapsulatedContentInfo, eContentType, YASN1_OBJECT),
        YASN1_NDEF_EXP_OPT(CMS_EncapsulatedContentInfo, eContent, YASN1_OCTET_STRING_NDEF, 0)
} static_YASN1_NDEF_SEQUENCE_END(CMS_EncapsulatedContentInfo)

/* Minor tweak to operation: free up signer key, cert */
static int cms_si_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                     void *exarg)
{
    if (operation == YASN1_OP_FREE_POST) {
        CMS_SignerInfo *si = (CMS_SignerInfo *)*pval;
        EVVP_PKEY_free(si->pkey);
        YX509_free(si->signer);
        EVVP_MD_CTX_free(si->mctx);
        EVVP_PKEY_CTX_free(si->pctx);
    }
    return 1;
}

YASN1_SEQUENCE_cb(CMS_SignerInfo, cms_si_cb) = {
        YASN1_EMBED(CMS_SignerInfo, version, INT32),
        YASN1_SIMPLE(CMS_SignerInfo, sid, CMS_SignerIdentifier),
        YASN1_SIMPLE(CMS_SignerInfo, digestAlgorithm, YX509_ALGOR),
        YASN1_IMP_SET_OF_OPT(CMS_SignerInfo, signedAttrs, YX509_ATTRIBUTE, 0),
        YASN1_SIMPLE(CMS_SignerInfo, signatureAlgorithm, YX509_ALGOR),
        YASN1_SIMPLE(CMS_SignerInfo, signature, YASN1_OCTET_STRING),
        YASN1_IMP_SET_OF_OPT(CMS_SignerInfo, unsignedAttrs, YX509_ATTRIBUTE, 1)
} YASN1_SEQUENCE_END_cb(CMS_SignerInfo, CMS_SignerInfo)

YASN1_SEQUENCE(CMS_OtherRevocationInfoFormat) = {
        YASN1_SIMPLE(CMS_OtherRevocationInfoFormat, otherRevInfoFormat, YASN1_OBJECT),
        YASN1_OPT(CMS_OtherRevocationInfoFormat, otherRevInfo, YASN1_ANY)
} static_YASN1_SEQUENCE_END(CMS_OtherRevocationInfoFormat)

YASN1_CHOICE(CMS_RevocationInfoChoice) = {
        YASN1_SIMPLE(CMS_RevocationInfoChoice, d.crl, YX509_CRL),
        YASN1_IMP(CMS_RevocationInfoChoice, d.other, CMS_OtherRevocationInfoFormat, 1)
} YASN1_CHOICE_END(CMS_RevocationInfoChoice)

YASN1_NDEF_SEQUENCE(CMS_SignedData) = {
        YASN1_EMBED(CMS_SignedData, version, INT32),
        YASN1_SET_OF(CMS_SignedData, digestAlgorithms, YX509_ALGOR),
        YASN1_SIMPLE(CMS_SignedData, encapContentInfo, CMS_EncapsulatedContentInfo),
        YASN1_IMP_SET_OF_OPT(CMS_SignedData, certificates, CMS_CertificateChoices, 0),
        YASN1_IMP_SET_OF_OPT(CMS_SignedData, crls, CMS_RevocationInfoChoice, 1),
        YASN1_SET_OF(CMS_SignedData, signerInfos, CMS_SignerInfo)
} YASN1_NDEF_SEQUENCE_END(CMS_SignedData)

YASN1_SEQUENCE(CMS_OriginatorInfo) = {
        YASN1_IMP_SET_OF_OPT(CMS_OriginatorInfo, certificates, CMS_CertificateChoices, 0),
        YASN1_IMP_SET_OF_OPT(CMS_OriginatorInfo, crls, CMS_RevocationInfoChoice, 1)
} static_YASN1_SEQUENCE_END(CMS_OriginatorInfo)

static int cms_ec_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                     void *exarg)
{
    CMS_EncryptedContentInfo *ec = (CMS_EncryptedContentInfo *)*pval;

    if (operation == YASN1_OP_FREE_POST)
        OPENSSL_clear_free(ec->key, ec->keylen);
    return 1;
}

YASN1_NDEF_SEQUENCE_cb(CMS_EncryptedContentInfo, cms_ec_cb) = {
        YASN1_SIMPLE(CMS_EncryptedContentInfo, contentType, YASN1_OBJECT),
        YASN1_SIMPLE(CMS_EncryptedContentInfo, contentEncryptionAlgorithm, YX509_ALGOR),
        YASN1_IMP_OPT(CMS_EncryptedContentInfo, encryptedContent, YASN1_OCTET_STRING_NDEF, 0)
} YASN1_NDEF_SEQUENCE_END_cb(CMS_EncryptedContentInfo, CMS_EncryptedContentInfo)

YASN1_SEQUENCE(CMS_KeyTransRecipientInfo) = {
        YASN1_EMBED(CMS_KeyTransRecipientInfo, version, INT32),
        YASN1_SIMPLE(CMS_KeyTransRecipientInfo, rid, CMS_SignerIdentifier),
        YASN1_SIMPLE(CMS_KeyTransRecipientInfo, keyEncryptionAlgorithm, YX509_ALGOR),
        YASN1_SIMPLE(CMS_KeyTransRecipientInfo, encryptedKey, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(CMS_KeyTransRecipientInfo)

YASN1_SEQUENCE(CMS_OtherKeyAttribute) = {
        YASN1_SIMPLE(CMS_OtherKeyAttribute, keyAttrId, YASN1_OBJECT),
        YASN1_OPT(CMS_OtherKeyAttribute, keyAttr, YASN1_ANY)
} YASN1_SEQUENCE_END(CMS_OtherKeyAttribute)

YASN1_SEQUENCE(CMS_RecipientKeyIdentifier) = {
        YASN1_SIMPLE(CMS_RecipientKeyIdentifier, subjectKeyIdentifier, YASN1_OCTET_STRING),
        YASN1_OPT(CMS_RecipientKeyIdentifier, date, YASN1_GENERALIZEDTIME),
        YASN1_OPT(CMS_RecipientKeyIdentifier, other, CMS_OtherKeyAttribute)
} YASN1_SEQUENCE_END(CMS_RecipientKeyIdentifier)

YASN1_CHOICE(CMS_KeyAgreeRecipientIdentifier) = {
  YASN1_SIMPLE(CMS_KeyAgreeRecipientIdentifier, d.issuerAndSerialNumber, CMS_IssuerAndSerialNumber),
  YASN1_IMP(CMS_KeyAgreeRecipientIdentifier, d.rKeyId, CMS_RecipientKeyIdentifier, 0)
} static_YASN1_CHOICE_END(CMS_KeyAgreeRecipientIdentifier)

static int cms_rek_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                      void *exarg)
{
    CMS_RecipientEncryptedKey *rek = (CMS_RecipientEncryptedKey *)*pval;
    if (operation == YASN1_OP_FREE_POST) {
        EVVP_PKEY_free(rek->pkey);
    }
    return 1;
}

YASN1_SEQUENCE_cb(CMS_RecipientEncryptedKey, cms_rek_cb) = {
        YASN1_SIMPLE(CMS_RecipientEncryptedKey, rid, CMS_KeyAgreeRecipientIdentifier),
        YASN1_SIMPLE(CMS_RecipientEncryptedKey, encryptedKey, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END_cb(CMS_RecipientEncryptedKey, CMS_RecipientEncryptedKey)

YASN1_SEQUENCE(CMS_OriginatorPublicKey) = {
  YASN1_SIMPLE(CMS_OriginatorPublicKey, algorithm, YX509_ALGOR),
  YASN1_SIMPLE(CMS_OriginatorPublicKey, publicKey, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END(CMS_OriginatorPublicKey)

YASN1_CHOICE(CMS_OriginatorIdentifierOrKey) = {
  YASN1_SIMPLE(CMS_OriginatorIdentifierOrKey, d.issuerAndSerialNumber, CMS_IssuerAndSerialNumber),
  YASN1_IMP(CMS_OriginatorIdentifierOrKey, d.subjectKeyIdentifier, YASN1_OCTET_STRING, 0),
  YASN1_IMP(CMS_OriginatorIdentifierOrKey, d.originatorKey, CMS_OriginatorPublicKey, 1)
} static_YASN1_CHOICE_END(CMS_OriginatorIdentifierOrKey)

static int cms_kari_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                       void *exarg)
{
    CMS_KeyAgreeRecipientInfo *kari = (CMS_KeyAgreeRecipientInfo *)*pval;
    if (operation == YASN1_OP_NEW_POST) {
        kari->ctx = EVVP_CIPHER_CTX_new();
        if (kari->ctx == NULL)
            return 0;
        EVVP_CIPHER_CTX_set_flags(kari->ctx, EVVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        kari->pctx = NULL;
    } else if (operation == YASN1_OP_FREE_POST) {
        EVVP_PKEY_CTX_free(kari->pctx);
        EVVP_CIPHER_CTX_free(kari->ctx);
    }
    return 1;
}

YASN1_SEQUENCE_cb(CMS_KeyAgreeRecipientInfo, cms_kari_cb) = {
        YASN1_EMBED(CMS_KeyAgreeRecipientInfo, version, INT32),
        YASN1_EXP(CMS_KeyAgreeRecipientInfo, originator, CMS_OriginatorIdentifierOrKey, 0),
        YASN1_EXP_OPT(CMS_KeyAgreeRecipientInfo, ukm, YASN1_OCTET_STRING, 1),
        YASN1_SIMPLE(CMS_KeyAgreeRecipientInfo, keyEncryptionAlgorithm, YX509_ALGOR),
        YASN1_SEQUENCE_OF(CMS_KeyAgreeRecipientInfo, recipientEncryptedKeys, CMS_RecipientEncryptedKey)
} YASN1_SEQUENCE_END_cb(CMS_KeyAgreeRecipientInfo, CMS_KeyAgreeRecipientInfo)

YASN1_SEQUENCE(CMS_KEKIdentifier) = {
        YASN1_SIMPLE(CMS_KEKIdentifier, keyIdentifier, YASN1_OCTET_STRING),
        YASN1_OPT(CMS_KEKIdentifier, date, YASN1_GENERALIZEDTIME),
        YASN1_OPT(CMS_KEKIdentifier, other, CMS_OtherKeyAttribute)
} static_YASN1_SEQUENCE_END(CMS_KEKIdentifier)

YASN1_SEQUENCE(CMS_KEKRecipientInfo) = {
        YASN1_EMBED(CMS_KEKRecipientInfo, version, INT32),
        YASN1_SIMPLE(CMS_KEKRecipientInfo, kekid, CMS_KEKIdentifier),
        YASN1_SIMPLE(CMS_KEKRecipientInfo, keyEncryptionAlgorithm, YX509_ALGOR),
        YASN1_SIMPLE(CMS_KEKRecipientInfo, encryptedKey, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(CMS_KEKRecipientInfo)

YASN1_SEQUENCE(CMS_PasswordRecipientInfo) = {
        YASN1_EMBED(CMS_PasswordRecipientInfo, version, INT32),
        YASN1_IMP_OPT(CMS_PasswordRecipientInfo, keyDerivationAlgorithm, YX509_ALGOR, 0),
        YASN1_SIMPLE(CMS_PasswordRecipientInfo, keyEncryptionAlgorithm, YX509_ALGOR),
        YASN1_SIMPLE(CMS_PasswordRecipientInfo, encryptedKey, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(CMS_PasswordRecipientInfo)

YASN1_SEQUENCE(CMS_OtherRecipientInfo) = {
  YASN1_SIMPLE(CMS_OtherRecipientInfo, oriType, YASN1_OBJECT),
  YASN1_OPT(CMS_OtherRecipientInfo, oriValue, YASN1_ANY)
} static_YASN1_SEQUENCE_END(CMS_OtherRecipientInfo)

/* Free up RecipientInfo additional data */
static int cms_ri_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                     void *exarg)
{
    if (operation == YASN1_OP_FREE_PRE) {
        CMS_RecipientInfo *ri = (CMS_RecipientInfo *)*pval;
        if (ri->type == CMS_RECIPINFO_TRANS) {
            CMS_KeyTransRecipientInfo *ktri = ri->d.ktri;
            EVVP_PKEY_free(ktri->pkey);
            YX509_free(ktri->recip);
            EVVP_PKEY_CTX_free(ktri->pctx);
        } else if (ri->type == CMS_RECIPINFO_KEK) {
            CMS_KEKRecipientInfo *kekri = ri->d.kekri;
            OPENSSL_clear_free(kekri->key, kekri->keylen);
        } else if (ri->type == CMS_RECIPINFO_PASS) {
            CMS_PasswordRecipientInfo *pwri = ri->d.pwri;
            OPENSSL_clear_free(pwri->pass, pwri->passlen);
        }
    }
    return 1;
}

YASN1_CHOICE_cb(CMS_RecipientInfo, cms_ri_cb) = {
        YASN1_SIMPLE(CMS_RecipientInfo, d.ktri, CMS_KeyTransRecipientInfo),
        YASN1_IMP(CMS_RecipientInfo, d.kari, CMS_KeyAgreeRecipientInfo, 1),
        YASN1_IMP(CMS_RecipientInfo, d.kekri, CMS_KEKRecipientInfo, 2),
        YASN1_IMP(CMS_RecipientInfo, d.pwri, CMS_PasswordRecipientInfo, 3),
        YASN1_IMP(CMS_RecipientInfo, d.ori, CMS_OtherRecipientInfo, 4)
} YASN1_CHOICE_END_cb(CMS_RecipientInfo, CMS_RecipientInfo, type)

YASN1_NDEF_SEQUENCE(CMS_EnvelopedData) = {
        YASN1_EMBED(CMS_EnvelopedData, version, INT32),
        YASN1_IMP_OPT(CMS_EnvelopedData, originatorInfo, CMS_OriginatorInfo, 0),
        YASN1_SET_OF(CMS_EnvelopedData, recipientInfos, CMS_RecipientInfo),
        YASN1_SIMPLE(CMS_EnvelopedData, encryptedContentInfo, CMS_EncryptedContentInfo),
        YASN1_IMP_SET_OF_OPT(CMS_EnvelopedData, unprotectedAttrs, YX509_ATTRIBUTE, 1)
} YASN1_NDEF_SEQUENCE_END(CMS_EnvelopedData)

YASN1_NDEF_SEQUENCE(CMS_DigestedData) = {
        YASN1_EMBED(CMS_DigestedData, version, INT32),
        YASN1_SIMPLE(CMS_DigestedData, digestAlgorithm, YX509_ALGOR),
        YASN1_SIMPLE(CMS_DigestedData, encapContentInfo, CMS_EncapsulatedContentInfo),
        YASN1_SIMPLE(CMS_DigestedData, digest, YASN1_OCTET_STRING)
} YASN1_NDEF_SEQUENCE_END(CMS_DigestedData)

YASN1_NDEF_SEQUENCE(CMS_EncryptedData) = {
        YASN1_EMBED(CMS_EncryptedData, version, INT32),
        YASN1_SIMPLE(CMS_EncryptedData, encryptedContentInfo, CMS_EncryptedContentInfo),
        YASN1_IMP_SET_OF_OPT(CMS_EncryptedData, unprotectedAttrs, YX509_ATTRIBUTE, 1)
} YASN1_NDEF_SEQUENCE_END(CMS_EncryptedData)

YASN1_NDEF_SEQUENCE(CMS_AuthenticatedData) = {
        YASN1_EMBED(CMS_AuthenticatedData, version, INT32),
        YASN1_IMP_OPT(CMS_AuthenticatedData, originatorInfo, CMS_OriginatorInfo, 0),
        YASN1_SET_OF(CMS_AuthenticatedData, recipientInfos, CMS_RecipientInfo),
        YASN1_SIMPLE(CMS_AuthenticatedData, macAlgorithm, YX509_ALGOR),
        YASN1_IMP(CMS_AuthenticatedData, digestAlgorithm, YX509_ALGOR, 1),
        YASN1_SIMPLE(CMS_AuthenticatedData, encapContentInfo, CMS_EncapsulatedContentInfo),
        YASN1_IMP_SET_OF_OPT(CMS_AuthenticatedData, authAttrs, YX509_ALGOR, 2),
        YASN1_SIMPLE(CMS_AuthenticatedData, mac, YASN1_OCTET_STRING),
        YASN1_IMP_SET_OF_OPT(CMS_AuthenticatedData, unauthAttrs, YX509_ALGOR, 3)
} static_YASN1_NDEF_SEQUENCE_END(CMS_AuthenticatedData)

YASN1_NDEF_SEQUENCE(CMS_CompressedData) = {
        YASN1_EMBED(CMS_CompressedData, version, INT32),
        YASN1_SIMPLE(CMS_CompressedData, compressionAlgorithm, YX509_ALGOR),
        YASN1_SIMPLE(CMS_CompressedData, encapContentInfo, CMS_EncapsulatedContentInfo),
} YASN1_NDEF_SEQUENCE_END(CMS_CompressedData)

/* This is the ANY DEFINED BY table for the top level ContentInfo structure */

YASN1_ADB_TEMPLATE(cms_default) = YASN1_EXP(CMS_ContentInfo, d.other, YASN1_ANY, 0);

YASN1_ADB(CMS_ContentInfo) = {
        ADB_ENTRY(NID_pkcs7_data, YASN1_NDEF_EXP(CMS_ContentInfo, d.data, YASN1_OCTET_STRING_NDEF, 0)),
        ADB_ENTRY(NID_pkcs7_signed, YASN1_NDEF_EXP(CMS_ContentInfo, d.signedData, CMS_SignedData, 0)),
        ADB_ENTRY(NID_pkcs7_enveloped, YASN1_NDEF_EXP(CMS_ContentInfo, d.envelopedData, CMS_EnvelopedData, 0)),
        ADB_ENTRY(NID_pkcs7_digest, YASN1_NDEF_EXP(CMS_ContentInfo, d.digestedData, CMS_DigestedData, 0)),
        ADB_ENTRY(NID_pkcs7_encrypted, YASN1_NDEF_EXP(CMS_ContentInfo, d.encryptedData, CMS_EncryptedData, 0)),
        ADB_ENTRY(NID_id_smime_ct_authData, YASN1_NDEF_EXP(CMS_ContentInfo, d.authenticatedData, CMS_AuthenticatedData, 0)),
        ADB_ENTRY(NID_id_smime_ct_compressedData, YASN1_NDEF_EXP(CMS_ContentInfo, d.compressedData, CMS_CompressedData, 0)),
} YASN1_ADB_END(CMS_ContentInfo, 0, contentType, 0, &cms_default_tt, NULL);

/* CMS streaming support */
static int cms_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                  void *exarg)
{
    YASN1_STREAM_ARG *sarg = exarg;
    CMS_ContentInfo *cms = NULL;
    if (pval)
        cms = (CMS_ContentInfo *)*pval;
    else
        return 1;
    switch (operation) {

    case YASN1_OP_STREAM_PRE:
        if (CMS_stream(&sarg->boundary, cms) <= 0)
            return 0;
        /* fall thru */
    case YASN1_OP_DETACHED_PRE:
        sarg->ndef_bio = CMS_dataInit(cms, sarg->out);
        if (!sarg->ndef_bio)
            return 0;
        break;

    case YASN1_OP_STREAM_POST:
    case YASN1_OP_DETACHED_POST:
        if (CMS_dataFinal(cms, sarg->ndef_bio) <= 0)
            return 0;
        break;

    }
    return 1;
}

YASN1_NDEF_SEQUENCE_cb(CMS_ContentInfo, cms_cb) = {
        YASN1_SIMPLE(CMS_ContentInfo, contentType, YASN1_OBJECT),
        YASN1_ADB_OBJECT(CMS_ContentInfo)
} YASN1_NDEF_SEQUENCE_END_cb(CMS_ContentInfo, CMS_ContentInfo)

/* Specials for signed attributes */

/*
 * When signing attributes we want to reorder them to match the sorted
 * encoding.
 */

YASN1_ITEM_TEMPLATE(CMS_Attributes_Sign) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SET_ORDER, 0, CMS_ATTRIBUTES, YX509_ATTRIBUTE)
YASN1_ITEM_TEMPLATE_END(CMS_Attributes_Sign)

/*
 * When verifying attributes we need to use the received order. So we use
 * SEQUENCE OF and tag it to SET OF
 */

YASN1_ITEM_TEMPLATE(CMS_Attributes_Verify) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF | YASN1_TFLG_IMPTAG | YASN1_TFLG_UNIVEYRSAL,
                                V_YASN1_SET, CMS_ATTRIBUTES, YX509_ATTRIBUTE)
YASN1_ITEM_TEMPLATE_END(CMS_Attributes_Verify)



YASN1_CHOICE(CMS_ReceiptsFrom) = {
  YASN1_IMP_EMBED(CMS_ReceiptsFrom, d.allOrFirstTier, INT32, 0),
  YASN1_IMP_SEQUENCE_OF(CMS_ReceiptsFrom, d.receiptList, GENERAL_NAMES, 1)
} static_YASN1_CHOICE_END(CMS_ReceiptsFrom)

YASN1_SEQUENCE(CMS_ReceiptRequest) = {
  YASN1_SIMPLE(CMS_ReceiptRequest, signedContentIdentifier, YASN1_OCTET_STRING),
  YASN1_SIMPLE(CMS_ReceiptRequest, receiptsFrom, CMS_ReceiptsFrom),
  YASN1_SEQUENCE_OF(CMS_ReceiptRequest, receiptsTo, GENERAL_NAMES)
} YASN1_SEQUENCE_END(CMS_ReceiptRequest)

YASN1_SEQUENCE(CMS_Receipt) = {
  YASN1_EMBED(CMS_Receipt, version, INT32),
  YASN1_SIMPLE(CMS_Receipt, contentType, YASN1_OBJECT),
  YASN1_SIMPLE(CMS_Receipt, signedContentIdentifier, YASN1_OCTET_STRING),
  YASN1_SIMPLE(CMS_Receipt, originatorSignatureValue, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(CMS_Receipt)

/*
 * Utilities to encode the CMS_SharedInfo structure used during key
 * derivation.
 */

typedef struct {
    YX509_ALGOR *keyInfo;
    YASN1_OCTET_STRING *entityUInfo;
    YASN1_OCTET_STRING *suppPubInfo;
} CMS_SharedInfo;

YASN1_SEQUENCE(CMS_SharedInfo) = {
  YASN1_SIMPLE(CMS_SharedInfo, keyInfo, YX509_ALGOR),
  YASN1_EXP_OPT(CMS_SharedInfo, entityUInfo, YASN1_OCTET_STRING, 0),
  YASN1_EXP_OPT(CMS_SharedInfo, suppPubInfo, YASN1_OCTET_STRING, 2),
} static_YASN1_SEQUENCE_END(CMS_SharedInfo)

int CMS_SharedInfo_encode(unsigned char **pder, YX509_ALGOR *kekalg,
                          YASN1_OCTET_STRING *ukm, int keylen)
{
    union {
        CMS_SharedInfo *pecsi;
        YASN1_VALUE *a;
    } intsi = {
        NULL
    };

    YASN1_OCTET_STRING oklen;
    unsigned char kl[4];
    CMS_SharedInfo ecsi;

    keylen <<= 3;
    kl[0] = (keylen >> 24) & 0xff;
    kl[1] = (keylen >> 16) & 0xff;
    kl[2] = (keylen >> 8) & 0xff;
    kl[3] = keylen & 0xff;
    oklen.length = 4;
    oklen.data = kl;
    oklen.type = V_YASN1_OCTET_STRING;
    oklen.flags = 0;
    ecsi.keyInfo = kekalg;
    ecsi.entityUInfo = ukm;
    ecsi.suppPubInfo = &oklen;
    intsi.pecsi = &ecsi;
    return YASN1_item_i2d(intsi.a, pder, YASN1_ITEM_rptr(CMS_SharedInfo));
}
