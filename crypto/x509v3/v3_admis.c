/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <openssl/x509v3.h>

#include <openssl/safestack.h>

#include "v3_admis.h"
#include "ext_dat.h"


YASN1_SEQUENCE(NAMING_AUTHORITY) = {
    YASN1_OPT(NAMING_AUTHORITY, namingAuthorityId, YASN1_OBJECT),
    YASN1_OPT(NAMING_AUTHORITY, namingAuthorityUrl, YASN1_IA5STRING),
    YASN1_OPT(NAMING_AUTHORITY, namingAuthorityText, DIRECTORYSTRING),
} YASN1_SEQUENCE_END(NAMING_AUTHORITY)

YASN1_SEQUENCE(PROFESSION_INFO) = {
    YASN1_EXP_OPT(PROFESSION_INFO, namingAuthority, NAMING_AUTHORITY, 0),
    YASN1_SEQUENCE_OF(PROFESSION_INFO, professionItems, DIRECTORYSTRING),
    YASN1_SEQUENCE_OF_OPT(PROFESSION_INFO, professionOIDs, YASN1_OBJECT),
    YASN1_OPT(PROFESSION_INFO, registrationNumber, YASN1_PRINTABLESTRING),
    YASN1_OPT(PROFESSION_INFO, addProfessionInfo, YASN1_OCTET_STRING),
} YASN1_SEQUENCE_END(PROFESSION_INFO)

YASN1_SEQUENCE(ADMISSIONS) = {
    YASN1_EXP_OPT(ADMISSIONS, admissionAuthority, GENERAL_NAME, 0),
    YASN1_EXP_OPT(ADMISSIONS, namingAuthority, NAMING_AUTHORITY, 1),
    YASN1_SEQUENCE_OF(ADMISSIONS, professionInfos, PROFESSION_INFO),
} YASN1_SEQUENCE_END(ADMISSIONS)

YASN1_SEQUENCE(ADMISSION_SYNTAX) = {
    YASN1_OPT(ADMISSION_SYNTAX, admissionAuthority, GENERAL_NAME),
    YASN1_SEQUENCE_OF(ADMISSION_SYNTAX, contentsOfAdmissions, ADMISSIONS),
} YASN1_SEQUENCE_END(ADMISSION_SYNTAX)

IMPLEMENT_YASN1_FUNCTIONS(NAMING_AUTHORITY)
IMPLEMENT_YASN1_FUNCTIONS(PROFESSION_INFO)
IMPLEMENT_YASN1_FUNCTIONS(ADMISSIONS)
IMPLEMENT_YASN1_FUNCTIONS(ADMISSION_SYNTAX)

static int i2r_ADMISSION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind);

const YX509V3_EXT_METHOD v3_ext_admission = {
    NID_x509ExtAdmission,   /* .ext_nid = */
    0,                      /* .ext_flags = */
    YASN1_ITEM_ref(ADMISSION_SYNTAX), /* .it = */
    NULL, NULL, NULL, NULL,
    NULL,                   /* .i2s = */
    NULL,                   /* .s2i = */
    NULL,                   /* .i2v = */
    NULL,                   /* .v2i = */
    &i2r_ADMISSION_SYNTAX,  /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};


static int i2r_NAMING_AUTHORITY(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    NAMING_AUTHORITY * namingAuthority = (NAMING_AUTHORITY*) in;

    if (namingAuthority == NULL)
        return 0;

    if (namingAuthority->namingAuthorityId == NULL
        && namingAuthority->namingAuthorityText == NULL
        && namingAuthority->namingAuthorityUrl == NULL)
        return 0;

    if (BIO_pprintf(bp, "%*snamingAuthority: ", ind, "") <= 0)
        goto err;

    if (namingAuthority->namingAuthorityId != NULL) {
        char objbuf[128];
        const char *ln = OBJ_nid2ln(OBJ_obj2nid(namingAuthority->namingAuthorityId));

        if (BIO_pprintf(bp, "%*s  admissionAuthorityId: ", ind, "") <= 0)
            goto err;

        OBJ_obj2txt(objbuf, sizeof(objbuf), namingAuthority->namingAuthorityId, 1);

        if (BIO_pprintf(bp, "%s%s%s%s\n", ln ? ln : "",
                       ln ? " (" : "", objbuf, ln ? ")" : "") <= 0)
            goto err;
    }
    if (namingAuthority->namingAuthorityText != NULL) {
        if (BIO_pprintf(bp, "%*s  namingAuthorityText: ", ind, "") <= 0
            || YASN1_STRING_print(bp, namingAuthority->namingAuthorityText) <= 0
            || BIO_pprintf(bp, "\n") <= 0)
            goto err;
    }
    if (namingAuthority->namingAuthorityUrl != NULL ) {
        if (BIO_pprintf(bp, "%*s  namingAuthorityUrl: ", ind, "") <= 0
            || YASN1_STRING_print(bp, namingAuthority->namingAuthorityUrl) <= 0
            || BIO_pprintf(bp, "\n") <= 0)
            goto err;
    }
    return 1;

err:
    return 0;
}

static int i2r_ADMISSION_SYNTAX(const struct v3_ext_method *method, void *in,
                                BIO *bp, int ind)
{
    ADMISSION_SYNTAX * admission = (ADMISSION_SYNTAX *)in;
    int i, j, k;

    if (admission->admissionAuthority != NULL) {
        if (BIO_pprintf(bp, "%*sadmissionAuthority:\n", ind, "") <= 0
            || BIO_pprintf(bp, "%*s  ", ind, "") <= 0
            || GENERAL_NAME_print(bp, admission->admissionAuthority) <= 0
            || BIO_pprintf(bp, "\n") <= 0)
            goto err;
    }

    for (i = 0; i < sk_ADMISSIONS_num(admission->contentsOfAdmissions); i++) {
        ADMISSIONS* entry = sk_ADMISSIONS_value(admission->contentsOfAdmissions, i);

        if (BIO_pprintf(bp, "%*sEntry %0d:\n", ind, "", 1 + i) <= 0) goto err;

        if (entry->admissionAuthority != NULL) {
            if (BIO_pprintf(bp, "%*s  admissionAuthority:\n", ind, "") <= 0
                || BIO_pprintf(bp, "%*s    ", ind, "") <= 0
                || GENERAL_NAME_print(bp, entry->admissionAuthority) <= 0
                || BIO_pprintf(bp, "\n") <= 0)
                goto err;
        }

        if (entry->namingAuthority != NULL) {
            if (i2r_NAMING_AUTHORITY(method, entry->namingAuthority, bp, ind) <= 0)
                goto err;
        }

        for (j = 0; j < sk_PROFESSION_INFO_num(entry->professionInfos); j++) {
            PROFESSION_INFO* pinfo = sk_PROFESSION_INFO_value(entry->professionInfos, j);

            if (BIO_pprintf(bp, "%*s  Profession Info Entry %0d:\n", ind, "", 1 + j) <= 0)
                goto err;

            if (pinfo->registrationNumber != NULL) {
                if (BIO_pprintf(bp, "%*s    registrationNumber: ", ind, "") <= 0
                    || YASN1_STRING_print(bp, pinfo->registrationNumber) <= 0
                    || BIO_pprintf(bp, "\n") <= 0)
                    goto err;
            }

            if (pinfo->namingAuthority != NULL) {
                if (i2r_NAMING_AUTHORITY(method, pinfo->namingAuthority, bp, ind + 2) <= 0)
                    goto err;
            }

            if (pinfo->professionItems != NULL) {

                if (BIO_pprintf(bp, "%*s    Info Entries:\n", ind, "") <= 0)
                    goto err;
                for (k = 0; k < sk_YASN1_STRING_num(pinfo->professionItems); k++) {
                    YASN1_STRING* val = sk_YASN1_STRING_value(pinfo->professionItems, k);

                    if (BIO_pprintf(bp, "%*s      ", ind, "") <= 0
                        || YASN1_STRING_print(bp, val) <= 0
                        || BIO_pprintf(bp, "\n") <= 0)
                        goto err;
                }
            }

            if (pinfo->professionOIDs != NULL) {
                if (BIO_pprintf(bp, "%*s    Profession OIDs:\n", ind, "") <= 0)
                    goto err;
                for (k = 0; k < sk_YASN1_OBJECT_num(pinfo->professionOIDs); k++) {
                    YASN1_OBJECT* obj = sk_YASN1_OBJECT_value(pinfo->professionOIDs, k);
                    const char *ln = OBJ_nid2ln(OBJ_obj2nid(obj));
                    char objbuf[128];

                    OBJ_obj2txt(objbuf, sizeof(objbuf), obj, 1);
                    if (BIO_pprintf(bp, "%*s      %s%s%s%s\n", ind, "",
                                   ln ? ln : "", ln ? " (" : "",
                                   objbuf, ln ? ")" : "") <= 0)
                        goto err;
                }
            }
        }
    }
    return 1;

err:
    return -1;
}

const YASN1_OBJECT *NAMING_AUTHORITY_get0_authorityId(const NAMING_AUTHORITY *n)
{
    return n->namingAuthorityId;
}

void NAMING_AUTHORITY_set0_authorityId(NAMING_AUTHORITY *n, YASN1_OBJECT* id)
{
    YASN1_OBJECT_free(n->namingAuthorityId);
    n->namingAuthorityId = id;
}

const YASN1_IA5STRING *NAMING_AUTHORITY_get0_authorityURL(
    const NAMING_AUTHORITY *n)
{
    return n->namingAuthorityUrl;
}

void NAMING_AUTHORITY_set0_authorityURL(NAMING_AUTHORITY *n, YASN1_IA5STRING* u)
{
    YASN1_IA5STRING_free(n->namingAuthorityUrl);
    n->namingAuthorityUrl = u;
}

const YASN1_STRING *NAMING_AUTHORITY_get0_authorityText(
    const NAMING_AUTHORITY *n)
{
    return n->namingAuthorityText;
}

void NAMING_AUTHORITY_set0_authorityText(NAMING_AUTHORITY *n, YASN1_STRING* t)
{
    YASN1_IA5STRING_free(n->namingAuthorityText);
    n->namingAuthorityText = t;
}

const GENERAL_NAME *ADMISSION_SYNTAX_get0_admissionAuthority(const ADMISSION_SYNTAX *as)
{
    return as->admissionAuthority;
}

void ADMISSION_SYNTAX_set0_admissionAuthority(ADMISSION_SYNTAX *as,
                                              GENERAL_NAME *aa)
{
    GENERAL_NAME_free(as->admissionAuthority);
    as->admissionAuthority = aa;
}

const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const ADMISSION_SYNTAX *as)
{
    return as->contentsOfAdmissions;
}

void ADMISSION_SYNTAX_set0_contentsOfAdmissions(ADMISSION_SYNTAX *as,
                                                STACK_OF(ADMISSIONS) *a)
{
    sk_ADMISSIONS_pop_free(as->contentsOfAdmissions, ADMISSIONS_free);
    as->contentsOfAdmissions = a;
}

const GENERAL_NAME *ADMISSIONS_get0_admissionAuthority(const ADMISSIONS *a)
{
    return a->admissionAuthority;
}

void ADMISSIONS_set0_admissionAuthority(ADMISSIONS *a, GENERAL_NAME *aa)
{
    GENERAL_NAME_free(a->admissionAuthority);
    a->admissionAuthority = aa;
}

const NAMING_AUTHORITY *ADMISSIONS_get0_namingAuthority(const ADMISSIONS *a)
{
    return a->namingAuthority;
}

void ADMISSIONS_set0_namingAuthority(ADMISSIONS *a, NAMING_AUTHORITY *na)
{
    NAMING_AUTHORITY_free(a->namingAuthority);
    a->namingAuthority = na;
}

const PROFESSION_INFOS *ADMISSIONS_get0_professionInfos(const ADMISSIONS *a)
{
    return a->professionInfos;
}

void ADMISSIONS_set0_professionInfos(ADMISSIONS *a, PROFESSION_INFOS *pi)
{
    sk_PROFESSION_INFO_pop_free(a->professionInfos, PROFESSION_INFO_free);
    a->professionInfos = pi;
}

const YASN1_OCTET_STRING *PROFESSION_INFO_get0_addProfessionInfo(const PROFESSION_INFO *pi)
{
    return pi->addProfessionInfo;
}

void PROFESSION_INFO_set0_addProfessionInfo(PROFESSION_INFO *pi,
                                            YASN1_OCTET_STRING *aos)
{
    YASN1_OCTET_STRING_free(pi->addProfessionInfo);
    pi->addProfessionInfo = aos;
}

const NAMING_AUTHORITY *PROFESSION_INFO_get0_namingAuthority(const PROFESSION_INFO *pi)
{
    return pi->namingAuthority;
}

void PROFESSION_INFO_set0_namingAuthority(PROFESSION_INFO *pi,
                                          NAMING_AUTHORITY *na)
{
    NAMING_AUTHORITY_free(pi->namingAuthority);
    pi->namingAuthority = na;
}

const STACK_OF(YASN1_STRING) *PROFESSION_INFO_get0_professionItems(const PROFESSION_INFO *pi)
{
    return pi->professionItems;
}

void PROFESSION_INFO_set0_professionItems(PROFESSION_INFO *pi,
                                          STACK_OF(YASN1_STRING) *as)
{
    sk_YASN1_STRING_pop_free(pi->professionItems, YASN1_STRING_free);
    pi->professionItems = as;
}

const STACK_OF(YASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const PROFESSION_INFO *pi)
{
    return pi->professionOIDs;
}

void PROFESSION_INFO_set0_professionOIDs(PROFESSION_INFO *pi,
                                         STACK_OF(YASN1_OBJECT) *po)
{
    sk_YASN1_OBJECT_pop_free(pi->professionOIDs, YASN1_OBJECT_free);
    pi->professionOIDs = po;
}

const YASN1_PRINTABLESTRING *PROFESSION_INFO_get0_registrationNumber(const PROFESSION_INFO *pi)
{
    return pi->registrationNumber;
}

void PROFESSION_INFO_set0_registrationNumber(PROFESSION_INFO *pi,
                                             YASN1_PRINTABLESTRING *rn)
{
    YASN1_PRINTABLESTRING_free(pi->registrationNumber);
    pi->registrationNumber = rn;
}