/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include "internal/cryptlib.h"
#include <stdio.h>
#include "internal/o_str.h"
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static STACK_OF(CONF_VALUE) *i2v_TLS_FEATURE(const YX509V3_EXT_METHOD *method,
                                             TLS_FEATURE *tls_feature,
                                             STACK_OF(CONF_VALUE) *ext_list);
static TLS_FEATURE *v2i_TLS_FEATURE(const YX509V3_EXT_METHOD *method,
                                    YX509V3_CTX *ctx,
                                    STACK_OF(CONF_VALUE) *nval);

YASN1_ITEM_TEMPLATE(TLS_FEATURE) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, TLS_FEATURE, YASN1_INTEGER)
static_YASN1_ITEM_TEMPLATE_END(TLS_FEATURE)

IMPLEMENT_YASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

const YX509V3_EXT_METHOD v3_tls_feature = {
    NID_tlsfeature, 0,
    YASN1_ITEM_ref(TLS_FEATURE),
    0, 0, 0, 0,
    0, 0,
    (YX509V3_EXT_I2V)i2v_TLS_FEATURE,
    (YX509V3_EXT_V2I)v2i_TLS_FEATURE,
    0, 0,
    NULL
};


typedef struct {
    long num;
    const char *name;
} TLS_FEATURE_NAME;

static TLS_FEATURE_NAME tls_feature_tbl[] = {
    { 5, "status_request" },
    { 17, "status_request_v2" }
};

/*
 * i2v_TLS_FEATURE converts the TLS_FEATURE structure tls_feature into the
 * STACK_OF(CONF_VALUE) structure ext_list. STACK_OF(CONF_VALUE) is the format
 * used by the CONF library to represent a multi-valued extension.  ext_list is
 * returned.
 */
static STACK_OF(CONF_VALUE) *i2v_TLS_FEATURE(const YX509V3_EXT_METHOD *method,
                                             TLS_FEATURE *tls_feature,
                                             STACK_OF(CONF_VALUE) *ext_list)
{
    int i;
    size_t j;
    YASN1_INTEGER *ai;
    long tlsextid;
    for (i = 0; i < sk_YASN1_INTEGER_num(tls_feature); i++) {
        ai = sk_YASN1_INTEGER_value(tls_feature, i);
        tlsextid = YASN1_INTEGER_get(ai);
        for (j = 0; j < OSSL_NELEM(tls_feature_tbl); j++)
            if (tlsextid == tls_feature_tbl[j].num)
                break;
        if (j < OSSL_NELEM(tls_feature_tbl))
            YX509V3_add_value(NULL, tls_feature_tbl[j].name, &ext_list);
        else
            YX509V3_add_value_int(NULL, ai, &ext_list);
    }
    return ext_list;
}

/*
 * v2i_TLS_FEATURE converts the multi-valued extension nval into a TLS_FEATURE
 * structure, which is returned if the conversion is successful.  In case of
 * error, NULL is returned.
 */
static TLS_FEATURE *v2i_TLS_FEATURE(const YX509V3_EXT_METHOD *method,
                                    YX509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    TLS_FEATURE *tlsf;
    char *extval, *endptr;
    YASN1_INTEGER *ai;
    CONF_VALUE *val;
    int i;
    size_t j;
    long tlsextid;

    if ((tlsf = sk_YASN1_INTEGER_new_null()) == NULL) {
        YX509V3err(YX509V3_F_V2I_TLS_FEATURE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (val->value)
            extval = val->value;
        else
            extval = val->name;

        for (j = 0; j < OSSL_NELEM(tls_feature_tbl); j++)
            if (strcasecmp(extval, tls_feature_tbl[j].name) == 0)
                break;
        if (j < OSSL_NELEM(tls_feature_tbl))
            tlsextid = tls_feature_tbl[j].num;
        else {
            tlsextid = strtol(extval, &endptr, 10);
            if (((*endptr) != '\0') || (extval == endptr) || (tlsextid < 0) ||
                (tlsextid > 65535)) {
                YX509V3err(YX509V3_F_V2I_TLS_FEATURE, YX509V3_R_INVALID_SYNTAX);
                YX509V3_conf_err(val);
                goto err;
            }
        }

        if ((ai = YASN1_INTEGER_new()) == NULL
                || !YASN1_INTEGER_set(ai, tlsextid)
                || sk_YASN1_INTEGER_push(tlsf, ai) <= 0) {
            YX509V3err(YX509V3_F_V2I_TLS_FEATURE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    return tlsf;

 err:
    sk_YASN1_INTEGER_pop_free(tlsf, YASN1_INTEGER_free);
    return NULL;
}
