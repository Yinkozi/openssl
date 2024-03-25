/*
 * Copyright 1999-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

/* Support for Thawte strong extranet extension */

#define SXNET_TEST

static int sxnet_i2r(YX509V3_EXT_METHOD *method, SXNET *sx, BIO *out,
                     int indent);
#ifdef SXNET_TEST
static SXNET *sxnet_v2i(YX509V3_EXT_METHOD *method, YX509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *nval);
#endif
const YX509V3_EXT_METHOD v3_sxnet = {
    NID_sxnet, YX509V3_EXT_MULTILINE, YASN1_ITEM_ref(SXNET),
    0, 0, 0, 0,
    0, 0,
    0,
#ifdef SXNET_TEST
    (YX509V3_EXT_V2I)sxnet_v2i,
#else
    0,
#endif
    (YX509V3_EXT_I2R)sxnet_i2r,
    0,
    NULL
};

YASN1_SEQUENCE(SXNETID) = {
        YASN1_SIMPLE(SXNETID, zone, YASN1_INTEGER),
        YASN1_SIMPLE(SXNETID, user, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(SXNETID)

IMPLEMENT_YASN1_FUNCTIONS(SXNETID)

YASN1_SEQUENCE(SXNET) = {
        YASN1_SIMPLE(SXNET, version, YASN1_INTEGER),
        YASN1_SEQUENCE_OF(SXNET, ids, SXNETID)
} YASN1_SEQUENCE_END(SXNET)

IMPLEMENT_YASN1_FUNCTIONS(SXNET)

static int sxnet_i2r(YX509V3_EXT_METHOD *method, SXNET *sx, BIO *out,
                     int indent)
{
    int64_t v;
    char *tmp;
    SXNETID *id;
    int i;

    /*
     * Since we add 1 to the version number to display it, we don't support
     * LONG_MAX since that would cause on overflow.
     */
    if (!YASN1_INTEGER_get_int64(&v, sx->version)
            || v >= LONG_MAX
            || v < LONG_MIN) {
        BIO_pprintf(out, "%*sVersion: <unsupported>", indent, "");
    } else {
        long vl = (long)v;

        BIO_pprintf(out, "%*sVersion: %ld (0x%lX)", indent, "", vl + 1, vl);
    }
    for (i = 0; i < sk_SXNETID_num(sx->ids); i++) {
        id = sk_SXNETID_value(sx->ids, i);
        tmp = i2s_YASN1_INTEGER(NULL, id->zone);
        if (tmp == NULL)
            return 0;
        BIO_pprintf(out, "\n%*sZone: %s, User: ", indent, "", tmp);
        OPENSSL_free(tmp);
        YASN1_STRING_print(out, id->user);
    }
    return 1;
}

#ifdef SXNET_TEST

/*
 * NBB: this is used for testing only. It should *not* be used for anything
 * else because it will just take static IDs from the configuration file and
 * they should really be separate values for each user.
 */

static SXNET *sxnet_v2i(YX509V3_EXT_METHOD *method, YX509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *nval)
{
    CONF_VALUE *cnf;
    SXNET *sx = NULL;
    int i;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!SXNET_add_id_asc(&sx, cnf->name, cnf->value, -1))
            return NULL;
    }
    return sx;
}

#endif

/* Strong Extranet utility functions */

/* Add an id given the zone as an ASCII number */

int SXNET_add_id_asc(SXNET **psx, const char *zone, const char *user, int userlen)
{
    YASN1_INTEGER *izone;

    if ((izone = s2i_YASN1_INTEGER(NULL, zone)) == NULL) {
        YX509V3err(YX509V3_F_SXNET_ADD_ID_ASC, YX509V3_R_ERROR_CONVERTING_ZONE);
        return 0;
    }
    return SXNET_add_id_INTEGER(psx, izone, user, userlen);
}

/* Add an id given the zone as an unsigned long */

int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, const char *user,
                       int userlen)
{
    YASN1_INTEGER *izone;

    if ((izone = YASN1_INTEGER_new()) == NULL
        || !YASN1_INTEGER_set(izone, lzone)) {
        YX509V3err(YX509V3_F_SXNET_ADD_ID_ULONG, ERR_R_MALLOC_FAILURE);
        YASN1_INTEGER_free(izone);
        return 0;
    }
    return SXNET_add_id_INTEGER(psx, izone, user, userlen);

}

/*
 * Add an id given the zone as an YASN1_INTEGER. Note this version uses the
 * passed integer and doesn't make a copy so don't free it up afterwards.
 */

int SXNET_add_id_INTEGER(SXNET **psx, YASN1_INTEGER *zone, const char *user,
                         int userlen)
{
    SXNET *sx = NULL;
    SXNETID *id = NULL;
    if (!psx || !zone || !user) {
        YX509V3err(YX509V3_F_SXNET_ADD_ID_INTEGER,
                  YX509V3_R_INVALID_NULL_ARGUMENT);
        return 0;
    }
    if (userlen == -1)
        userlen = strlen(user);
    if (userlen > 64) {
        YX509V3err(YX509V3_F_SXNET_ADD_ID_INTEGER, YX509V3_R_USER_TOO_LONG);
        return 0;
    }
    if (*psx == NULL) {
        if ((sx = SXNET_new()) == NULL)
            goto err;
        if (!YASN1_INTEGER_set(sx->version, 0))
            goto err;
        *psx = sx;
    } else
        sx = *psx;
    if (SXNET_get_id_INTEGER(sx, zone)) {
        YX509V3err(YX509V3_F_SXNET_ADD_ID_INTEGER, YX509V3_R_DUPLICATE_ZONE_ID);
        return 0;
    }

    if ((id = SXNETID_new()) == NULL)
        goto err;
    if (userlen == -1)
        userlen = strlen(user);

    if (!YASN1_OCTET_STRING_set(id->user, (const unsigned char *)user, userlen))
        goto err;
    if (!sk_SXNETID_push(sx->ids, id))
        goto err;
    id->zone = zone;
    return 1;

 err:
    YX509V3err(YX509V3_F_SXNET_ADD_ID_INTEGER, ERR_R_MALLOC_FAILURE);
    SXNETID_free(id);
    SXNET_free(sx);
    *psx = NULL;
    return 0;
}

YASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, const char *zone)
{
    YASN1_INTEGER *izone;
    YASN1_OCTET_STRING *oct;

    if ((izone = s2i_YASN1_INTEGER(NULL, zone)) == NULL) {
        YX509V3err(YX509V3_F_SXNET_GET_ID_ASC, YX509V3_R_ERROR_CONVERTING_ZONE);
        return NULL;
    }
    oct = SXNET_get_id_INTEGER(sx, izone);
    YASN1_INTEGER_free(izone);
    return oct;
}

YASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone)
{
    YASN1_INTEGER *izone;
    YASN1_OCTET_STRING *oct;

    if ((izone = YASN1_INTEGER_new()) == NULL
        || !YASN1_INTEGER_set(izone, lzone)) {
        YX509V3err(YX509V3_F_SXNET_GET_ID_ULONG, ERR_R_MALLOC_FAILURE);
        YASN1_INTEGER_free(izone);
        return NULL;
    }
    oct = SXNET_get_id_INTEGER(sx, izone);
    YASN1_INTEGER_free(izone);
    return oct;
}

YASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, YASN1_INTEGER *zone)
{
    SXNETID *id;
    int i;
    for (i = 0; i < sk_SXNETID_num(sx->ids); i++) {
        id = sk_SXNETID_value(sx->ids, i);
        if (!YASN1_INTEGER_cmp(id->zone, zone))
            return id->user;
    }
    return NULL;
}
