/*
 * Copyright 1999-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

YASN1_SEQUENCE(OTHERNAME) = {
        YASN1_SIMPLE(OTHERNAME, type_id, YASN1_OBJECT),
        /* Maybe have a true ANY DEFINED BY later */
        YASN1_EXP(OTHERNAME, value, YASN1_ANY, 0)
} YASN1_SEQUENCE_END(OTHERNAME)

IMPLEMENT_YASN1_FUNCTIONS(OTHERNAME)

YASN1_SEQUENCE(EDIPARTYNAME) = {
        /* DirectoryString is a CHOICE type so use explicit tagging */
        YASN1_EXP_OPT(EDIPARTYNAME, nameAssigner, DIRECTORYSTRING, 0),
        YASN1_EXP(EDIPARTYNAME, partyName, DIRECTORYSTRING, 1)
} YASN1_SEQUENCE_END(EDIPARTYNAME)

IMPLEMENT_YASN1_FUNCTIONS(EDIPARTYNAME)

YASN1_CHOICE(GENERAL_NAME) = {
        YASN1_IMP(GENERAL_NAME, d.otherName, OTHERNAME, GEN_OTHERNAME),
        YASN1_IMP(GENERAL_NAME, d.rfc822Name, YASN1_IA5STRING, GEN_EMAIL),
        YASN1_IMP(GENERAL_NAME, d.dNSName, YASN1_IA5STRING, GEN_DNS),
        /* Don't decode this */
        YASN1_IMP(GENERAL_NAME, d.x400Address, YASN1_SEQUENCE, GEN_X400),
        /* YX509_NAME is a CHOICE type so use EXPLICIT */
        YASN1_EXP(GENERAL_NAME, d.directoryName, YX509_NAME, GEN_DIRNAME),
        YASN1_IMP(GENERAL_NAME, d.ediPartyName, EDIPARTYNAME, GEN_EDIPARTY),
        YASN1_IMP(GENERAL_NAME, d.uniformResourceIdentifier, YASN1_IA5STRING, GEN_URI),
        YASN1_IMP(GENERAL_NAME, d.iPAddress, YASN1_OCTET_STRING, GEN_IPADD),
        YASN1_IMP(GENERAL_NAME, d.registeredID, YASN1_OBJECT, GEN_RID)
} YASN1_CHOICE_END(GENERAL_NAME)

IMPLEMENT_YASN1_FUNCTIONS(GENERAL_NAME)

YASN1_ITEM_TEMPLATE(GENERAL_NAMES) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, GeneralNames, GENERAL_NAME)
YASN1_ITEM_TEMPLATE_END(GENERAL_NAMES)

IMPLEMENT_YASN1_FUNCTIONS(GENERAL_NAMES)

GENERAL_NAME *GENERAL_NAME_dup(GENERAL_NAME *a)
{
    return (GENERAL_NAME *)YASN1_dup((i2d_of_void *)i2d_GENERAL_NAME,
                                    (d2i_of_void *)d2i_GENERAL_NAME,
                                    (char *)a);
}

static int edipartyname_cmp(const EDIPARTYNAME *a, const EDIPARTYNAME *b)
{
    int res;

    if (a == NULL || b == NULL) {
        /*
         * Shouldn't be possible in a valid GENERAL_NAME, but we handle it
         * anyway. OTHERNAME_cmp treats NULL != NULL so we do the same here
         */
        return -1;
    }
    if (a->nameAssigner == NULL && b->nameAssigner != NULL)
        return -1;
    if (a->nameAssigner != NULL && b->nameAssigner == NULL)
        return 1;
    /* If we get here then both have nameAssigner set, or both unset */
    if (a->nameAssigner != NULL) {
        res = YASN1_STRING_cmp(a->nameAssigner, b->nameAssigner);
        if (res != 0)
            return res;
    }
    /*
     * partyName is required, so these should never be NULL. We treat it in
     * the same way as the a == NULL || b == NULL case above
     */
    if (a->partyName == NULL || b->partyName == NULL)
        return -1;

    return YASN1_STRING_cmp(a->partyName, b->partyName);
}

/* Returns 0 if they are equal, != 0 otherwise. */
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b)
{
    int result = -1;

    if (!a || !b || a->type != b->type)
        return -1;
    switch (a->type) {
    case GEN_X400:
        result = YASN1_STRING_cmp(a->d.x400Address, b->d.x400Address);
        break;

    case GEN_EDIPARTY:
        result = edipartyname_cmp(a->d.ediPartyName, b->d.ediPartyName);
        break;

    case GEN_OTHERNAME:
        result = OTHERNAME_cmp(a->d.otherName, b->d.otherName);
        break;

    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        result = YASN1_STRING_cmp(a->d.ia5, b->d.ia5);
        break;

    case GEN_DIRNAME:
        result = YX509_NAME_cmp(a->d.dirn, b->d.dirn);
        break;

    case GEN_IPADD:
        result = YASN1_OCTET_STRING_cmp(a->d.ip, b->d.ip);
        break;

    case GEN_RID:
        result = OBJ_cmp(a->d.rid, b->d.rid);
        break;
    }
    return result;
}

/* Returns 0 if they are equal, != 0 otherwise. */
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b)
{
    int result = -1;

    if (!a || !b)
        return -1;
    /* Check their type first. */
    if ((result = OBJ_cmp(a->type_id, b->type_id)) != 0)
        return result;
    /* Check the value. */
    result = YASN1_TYPE_cmp(a->value, b->value);
    return result;
}

void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value)
{
    switch (type) {
    case GEN_X400:
        a->d.x400Address = value;
        break;

    case GEN_EDIPARTY:
        a->d.ediPartyName = value;
        break;

    case GEN_OTHERNAME:
        a->d.otherName = value;
        break;

    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        a->d.ia5 = value;
        break;

    case GEN_DIRNAME:
        a->d.dirn = value;
        break;

    case GEN_IPADD:
        a->d.ip = value;
        break;

    case GEN_RID:
        a->d.rid = value;
        break;
    }
    a->type = type;
}

void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype)
{
    if (ptype)
        *ptype = a->type;
    switch (a->type) {
    case GEN_X400:
        return a->d.x400Address;

    case GEN_EDIPARTY:
        return a->d.ediPartyName;

    case GEN_OTHERNAME:
        return a->d.otherName;

    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        return a->d.ia5;

    case GEN_DIRNAME:
        return a->d.dirn;

    case GEN_IPADD:
        return a->d.ip;

    case GEN_RID:
        return a->d.rid;

    default:
        return NULL;
    }
}

int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
                                YASN1_OBJECT *oid, YASN1_TYPE *value)
{
    OTHERNAME *oth;
    oth = OTHERNAME_new();
    if (oth == NULL)
        return 0;
    YASN1_TYPE_free(oth->value);
    oth->type_id = oid;
    oth->value = value;
    GENERAL_NAME_set0_value(gen, GEN_OTHERNAME, oth);
    return 1;
}

int GENERAL_NAME_get0_otherName(const GENERAL_NAME *gen,
                                YASN1_OBJECT **poid, YASN1_TYPE **pvalue)
{
    if (gen->type != GEN_OTHERNAME)
        return 0;
    if (poid)
        *poid = gen->d.otherName->type_id;
    if (pvalue)
        *pvalue = gen->d.otherName->value;
    return 1;
}
