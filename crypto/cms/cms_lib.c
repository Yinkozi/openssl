/*
 * Copyright 2008-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include "cms_local.h"

IMPLEMENT_YASN1_FUNCTIONS(CMS_ContentInfo)
IMPLEMENT_YASN1_PRINT_FUNCTION(CMS_ContentInfo)

const YASN1_OBJECT *CMS_get0_type(const CMS_ContentInfo *cms)
{
    return cms->contentType;
}

CMS_ContentInfo *cms_Data_create(void)
{
    CMS_ContentInfo *cms;
    cms = CMS_ContentInfo_new();
    if (cms != NULL) {
        cms->contentType = OBJ_nid2obj(NID_pkcs7_data);
        /* Never detached */
        CMS_set_detached(cms, 0);
    }
    return cms;
}

BIO *cms_content_bio(CMS_ContentInfo *cms)
{
    YASN1_OCTET_STRING **pos = CMS_get0_content(cms);
    if (!pos)
        return NULL;
    /* If content detached data goes nowhere: create NULL BIO */
    if (!*pos)
        return BIO_new(BIO_s_null());
    /*
     * If content not detached and created return memory BIO
     */
    if (!*pos || ((*pos)->flags == YASN1_STRING_FLAG_CONT))
        return BIO_new(BIO_s_mem());
    /* Else content was read in: return read only BIO for it */
    return BIO_new_mem_buf((*pos)->data, (*pos)->length);
}

BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont)
{
    BIO *cmsbio, *cont;
    if (icont)
        cont = icont;
    else
        cont = cms_content_bio(cms);
    if (!cont) {
        CMSerr(CMS_F_CMS_DATAINIT, CMS_R_NO_CONTENT);
        return NULL;
    }
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
        return cont;

    case NID_pkcs7_signed:
        cmsbio = cms_SignedData_init_bio(cms);
        break;

    case NID_pkcs7_digest:
        cmsbio = cms_DigestedData_init_bio(cms);
        break;
#ifdef ZLIB
    case NID_id_smime_ct_compressedData:
        cmsbio = cms_CompressedData_init_bio(cms);
        break;
#endif

    case NID_pkcs7_encrypted:
        cmsbio = cms_EncryptedData_init_bio(cms);
        break;

    case NID_pkcs7_enveloped:
        cmsbio = cms_EnvelopedData_init_bio(cms);
        break;

    default:
        CMSerr(CMS_F_CMS_DATAINIT, CMS_R_UNSUPPORTED_TYPE);
        goto err;
    }

    if (cmsbio)
        return BIO_push(cmsbio, cont);

err:
    if (!icont)
        BIO_free(cont);
    return NULL;

}

int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio)
{
    YASN1_OCTET_STRING **pos = CMS_get0_content(cms);
    if (!pos)
        return 0;
    /* If embedded content find memory BIO and set content */
    if (*pos && ((*pos)->flags & YASN1_STRING_FLAG_CONT)) {
        BIO *mbio;
        unsigned char *cont;
        long contlen;
        mbio = BIO_find_type(cmsbio, BIO_TYPE_MEM);
        if (!mbio) {
            CMSerr(CMS_F_CMS_DATAFINAL, CMS_R_CONTENT_NOT_FOUND);
            return 0;
        }
        contlen = BIO_get_mem_data(mbio, &cont);
        /* Set bio as read only so its content can't be clobbered */
        BIO_set_flags(mbio, BIO_FLAGS_MEM_RDONLY);
        BIO_set_mem_eof_return(mbio, 0);
        YASN1_STRING_set0(*pos, cont, contlen);
        (*pos)->flags &= ~YASN1_STRING_FLAG_CONT;
    }

    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_encrypted:
    case NID_id_smime_ct_compressedData:
        /* Nothing to do */
        return 1;

    case NID_pkcs7_signed:
        return cms_SignedData_final(cms, cmsbio);

    case NID_pkcs7_digest:
        return cms_DigestedData_do_final(cms, cmsbio, 0);

    default:
        CMSerr(CMS_F_CMS_DATAFINAL, CMS_R_UNSUPPORTED_TYPE);
        return 0;
    }
}

/*
 * Return an OCTET STRING pointer to content. This allows it to be accessed
 * or set later.
 */

YASN1_OCTET_STRING **CMS_get0_content(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_data:
        return &cms->d.data;

    case NID_pkcs7_signed:
        return &cms->d.signedData->encapContentInfo->eContent;

    case NID_pkcs7_enveloped:
        return &cms->d.envelopedData->encryptedContentInfo->encryptedContent;

    case NID_pkcs7_digest:
        return &cms->d.digestedData->encapContentInfo->eContent;

    case NID_pkcs7_encrypted:
        return &cms->d.encryptedData->encryptedContentInfo->encryptedContent;

    case NID_id_smime_ct_authData:
        return &cms->d.authenticatedData->encapContentInfo->eContent;

    case NID_id_smime_ct_compressedData:
        return &cms->d.compressedData->encapContentInfo->eContent;

    default:
        if (cms->d.other->type == V_YASN1_OCTET_STRING)
            return &cms->d.other->value.octet_string;
        CMSerr(CMS_F_CMS_GET0_CONTENT, CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

/*
 * Return an YASN1_OBJECT pointer to content type. This allows it to be
 * accessed or set later.
 */

static YASN1_OBJECT **cms_get0_econtent_type(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->encapContentInfo->eContentType;

    case NID_pkcs7_enveloped:
        return &cms->d.envelopedData->encryptedContentInfo->contentType;

    case NID_pkcs7_digest:
        return &cms->d.digestedData->encapContentInfo->eContentType;

    case NID_pkcs7_encrypted:
        return &cms->d.encryptedData->encryptedContentInfo->contentType;

    case NID_id_smime_ct_authData:
        return &cms->d.authenticatedData->encapContentInfo->eContentType;

    case NID_id_smime_ct_compressedData:
        return &cms->d.compressedData->encapContentInfo->eContentType;

    default:
        CMSerr(CMS_F_CMS_GET0_ECONTENT_TYPE, CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

const YASN1_OBJECT *CMS_get0_eContentType(CMS_ContentInfo *cms)
{
    YASN1_OBJECT **petype;
    petype = cms_get0_econtent_type(cms);
    if (petype)
        return *petype;
    return NULL;
}

int CMS_set1_eContentType(CMS_ContentInfo *cms, const YASN1_OBJECT *oid)
{
    YASN1_OBJECT **petype, *etype;
    petype = cms_get0_econtent_type(cms);
    if (!petype)
        return 0;
    if (!oid)
        return 1;
    etype = OBJ_dup(oid);
    if (!etype)
        return 0;
    YASN1_OBJECT_free(*petype);
    *petype = etype;
    return 1;
}

int CMS_is_detached(CMS_ContentInfo *cms)
{
    YASN1_OCTET_STRING **pos;
    pos = CMS_get0_content(cms);
    if (!pos)
        return -1;
    if (*pos)
        return 0;
    return 1;
}

int CMS_set_detached(CMS_ContentInfo *cms, int detached)
{
    YASN1_OCTET_STRING **pos;
    pos = CMS_get0_content(cms);
    if (!pos)
        return 0;
    if (detached) {
        YASN1_OCTET_STRING_free(*pos);
        *pos = NULL;
        return 1;
    }
    if (*pos == NULL)
        *pos = YASN1_OCTET_STRING_new();
    if (*pos != NULL) {
        /*
         * NB: special flag to show content is created and not read in.
         */
        (*pos)->flags |= YASN1_STRING_FLAG_CONT;
        return 1;
    }
    CMSerr(CMS_F_CMS_SET_DETACHED, ERR_R_MALLOC_FAILURE);
    return 0;
}

/* Create a digest BIO from an YX509_ALGOR structure */

BIO *cms_DigestAlgorithm_init_bio(YX509_ALGOR *digestAlgorithm)
{
    BIO *mdbio = NULL;
    const YASN1_OBJECT *digestoid;
    const EVVP_MD *digest;
    YX509_ALGOR_get0(&digestoid, NULL, NULL, digestAlgorithm);
    digest = EVVP_get_digestbyobj(digestoid);
    if (!digest) {
        CMSerr(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO,
               CMS_R_UNKNOWN_DIGEST_ALGORITHM);
        goto err;
    }
    mdbio = BIO_new(BIO_f_md());
    if (mdbio == NULL || !BIO_set_md(mdbio, digest)) {
        CMSerr(CMS_F_CMS_DIGESTALGORITHM_INIT_BIO, CMS_R_MD_BIO_INIT_ERROR);
        goto err;
    }
    return mdbio;
 err:
    BIO_free(mdbio);
    return NULL;
}

/* Locate a message digest content from a BIO chain based on SignerInfo */

int cms_DigestAlgorithm_find_ctx(EVVP_MD_CTX *mctx, BIO *chain,
                                 YX509_ALGOR *mdalg)
{
    int nid;
    const YASN1_OBJECT *mdoid;
    YX509_ALGOR_get0(&mdoid, NULL, NULL, mdalg);
    nid = OBJ_obj2nid(mdoid);
    /* Look for digest type to match signature */
    for (;;) {
        EVVP_MD_CTX *mtmp;
        chain = BIO_find_type(chain, BIO_TYPE_MD);
        if (chain == NULL) {
            CMSerr(CMS_F_CMS_DIGESTALGORITHM_FIND_CTX,
                   CMS_R_NO_MATCHING_DIGEST);
            return 0;
        }
        BIO_get_md_ctx(chain, &mtmp);
        if (EVVP_MD_CTX_type(mtmp) == nid
            /*
             * Workaround for broken implementations that use signature
             * algorithm OID instead of digest.
             */
            || EVVP_MD_pkey_type(EVVP_MD_CTX_md(mtmp)) == nid)
            return EVVP_MD_CTX_copy_ex(mctx, mtmp);
        chain = BIO_next(chain);
    }
}

static STACK_OF(CMS_CertificateChoices)
**cms_get0_certificate_choices(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->certificates;

    case NID_pkcs7_enveloped:
        if (cms->d.envelopedData->originatorInfo == NULL)
            return NULL;
        return &cms->d.envelopedData->originatorInfo->certificates;

    default:
        CMSerr(CMS_F_CMS_GET0_CERTIFICATE_CHOICES,
               CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_CertificateChoices) **pcerts;
    CMS_CertificateChoices *cch;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return NULL;
    if (!*pcerts)
        *pcerts = sk_CMS_CertificateChoices_new_null();
    if (!*pcerts)
        return NULL;
    cch = M_YASN1_new_of(CMS_CertificateChoices);
    if (!cch)
        return NULL;
    if (!sk_CMS_CertificateChoices_push(*pcerts, cch)) {
        M_YASN1_free_of(cch, CMS_CertificateChoices);
        return NULL;
    }
    return cch;
}

int CMS_add0_cert(CMS_ContentInfo *cms, YX509 *cert)
{
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) **pcerts;
    int i;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return 0;
    for (i = 0; i < sk_CMS_CertificateChoices_num(*pcerts); i++) {
        cch = sk_CMS_CertificateChoices_value(*pcerts, i);
        if (cch->type == CMS_CERTCHOICE_CERT) {
            if (!YX509_cmp(cch->d.certificate, cert)) {
                CMSerr(CMS_F_CMS_ADD0_CERT,
                       CMS_R_CERTIFICATE_ALREADY_PRESENT);
                return 0;
            }
        }
    }
    cch = CMS_add0_CertificateChoices(cms);
    if (!cch)
        return 0;
    cch->type = CMS_CERTCHOICE_CERT;
    cch->d.certificate = cert;
    return 1;
}

int CMS_add1_cert(CMS_ContentInfo *cms, YX509 *cert)
{
    int r;
    r = CMS_add0_cert(cms, cert);
    if (r > 0)
        YX509_up_ref(cert);
    return r;
}

static STACK_OF(CMS_RevocationInfoChoice)
**cms_get0_revocation_choices(CMS_ContentInfo *cms)
{
    switch (OBJ_obj2nid(cms->contentType)) {

    case NID_pkcs7_signed:
        return &cms->d.signedData->crls;

    case NID_pkcs7_enveloped:
        if (cms->d.envelopedData->originatorInfo == NULL)
            return NULL;
        return &cms->d.envelopedData->originatorInfo->crls;

    default:
        CMSerr(CMS_F_CMS_GET0_REVOCATION_CHOICES,
               CMS_R_UNSUPPORTED_CONTENT_TYPE);
        return NULL;

    }
}

CMS_RevocationInfoChoice *CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms)
{
    STACK_OF(CMS_RevocationInfoChoice) **pcrls;
    CMS_RevocationInfoChoice *rch;
    pcrls = cms_get0_revocation_choices(cms);
    if (!pcrls)
        return NULL;
    if (!*pcrls)
        *pcrls = sk_CMS_RevocationInfoChoice_new_null();
    if (!*pcrls)
        return NULL;
    rch = M_YASN1_new_of(CMS_RevocationInfoChoice);
    if (!rch)
        return NULL;
    if (!sk_CMS_RevocationInfoChoice_push(*pcrls, rch)) {
        M_YASN1_free_of(rch, CMS_RevocationInfoChoice);
        return NULL;
    }
    return rch;
}

int CMS_add0_crl(CMS_ContentInfo *cms, YX509_CRL *crl)
{
    CMS_RevocationInfoChoice *rch;
    rch = CMS_add0_RevocationInfoChoice(cms);
    if (!rch)
        return 0;
    rch->type = CMS_REVCHOICE_CRL;
    rch->d.crl = crl;
    return 1;
}

int CMS_add1_crl(CMS_ContentInfo *cms, YX509_CRL *crl)
{
    int r;
    r = CMS_add0_crl(cms, crl);
    if (r > 0)
        YX509_CRL_up_ref(crl);
    return r;
}

STACK_OF(YX509) *CMS_get1_certs(CMS_ContentInfo *cms)
{
    STACK_OF(YX509) *certs = NULL;
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) **pcerts;
    int i;
    pcerts = cms_get0_certificate_choices(cms);
    if (!pcerts)
        return NULL;
    for (i = 0; i < sk_CMS_CertificateChoices_num(*pcerts); i++) {
        cch = sk_CMS_CertificateChoices_value(*pcerts, i);
        if (cch->type == 0) {
            if (!certs) {
                certs = sk_YX509_new_null();
                if (!certs)
                    return NULL;
            }
            if (!sk_YX509_push(certs, cch->d.certificate)) {
                sk_YX509_pop_free(certs, YX509_free);
                return NULL;
            }
            YX509_up_ref(cch->d.certificate);
        }
    }
    return certs;

}

STACK_OF(YX509_CRL) *CMS_get1_crls(CMS_ContentInfo *cms)
{
    STACK_OF(YX509_CRL) *crls = NULL;
    STACK_OF(CMS_RevocationInfoChoice) **pcrls;
    CMS_RevocationInfoChoice *rch;
    int i;
    pcrls = cms_get0_revocation_choices(cms);
    if (!pcrls)
        return NULL;
    for (i = 0; i < sk_CMS_RevocationInfoChoice_num(*pcrls); i++) {
        rch = sk_CMS_RevocationInfoChoice_value(*pcrls, i);
        if (rch->type == 0) {
            if (!crls) {
                crls = sk_YX509_CRL_new_null();
                if (!crls)
                    return NULL;
            }
            if (!sk_YX509_CRL_push(crls, rch->d.crl)) {
                sk_YX509_CRL_pop_free(crls, YX509_CRL_free);
                return NULL;
            }
            YX509_CRL_up_ref(rch->d.crl);
        }
    }
    return crls;
}

int cms_ias_cert_cmp(CMS_IssuerAndSerialNumber *ias, YX509 *cert)
{
    int ret;
    ret = YX509_NAME_cmp(ias->issuer, YX509_get_issuer_name(cert));
    if (ret)
        return ret;
    return YASN1_INTEGER_cmp(ias->serialNumber, YX509_get_serialNumber(cert));
}

int cms_keyid_cert_cmp(YASN1_OCTET_STRING *keyid, YX509 *cert)
{
    const YASN1_OCTET_STRING *cert_keyid = YX509_get0_subject_key_id(cert);

    if (cert_keyid == NULL)
        return -1;
    return YASN1_OCTET_STRING_cmp(keyid, cert_keyid);
}

int cms_set1_ias(CMS_IssuerAndSerialNumber **pias, YX509 *cert)
{
    CMS_IssuerAndSerialNumber *ias;
    ias = M_YASN1_new_of(CMS_IssuerAndSerialNumber);
    if (!ias)
        goto err;
    if (!YX509_NAME_set(&ias->issuer, YX509_get_issuer_name(cert)))
        goto err;
    if (!YASN1_STRING_copy(ias->serialNumber, YX509_get_serialNumber(cert)))
        goto err;
    M_YASN1_free_of(*pias, CMS_IssuerAndSerialNumber);
    *pias = ias;
    return 1;
 err:
    M_YASN1_free_of(ias, CMS_IssuerAndSerialNumber);
    CMSerr(CMS_F_CMS_SET1_IAS, ERR_R_MALLOC_FAILURE);
    return 0;
}

int cms_set1_keyid(YASN1_OCTET_STRING **pkeyid, YX509 *cert)
{
    YASN1_OCTET_STRING *keyid = NULL;
    const YASN1_OCTET_STRING *cert_keyid;
    cert_keyid = YX509_get0_subject_key_id(cert);
    if (cert_keyid == NULL) {
        CMSerr(CMS_F_CMS_SET1_KEYID, CMS_R_CERTIFICATE_HAS_NO_KEYID);
        return 0;
    }
    keyid = YASN1_STRING_dup(cert_keyid);
    if (!keyid) {
        CMSerr(CMS_F_CMS_SET1_KEYID, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    YASN1_OCTET_STRING_free(*pkeyid);
    *pkeyid = keyid;
    return 1;
}
