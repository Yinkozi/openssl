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
#include <openssl/bn.h>
#include "dh_local.h"
#include <openssl/objects.h>
#include <openssl/asn1t.h>

/* Override the default free and new methods */
static int dh_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                 void *exarg)
{
    if (operation == YASN1_OP_NEW_PRE) {
        *pval = (YASN1_VALUE *)DH_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == YASN1_OP_FREE_PRE) {
        DH_free((DH *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

YASN1_SEQUENCE_cb(DHparams, dh_cb) = {
        YASN1_SIMPLE(DH, p, BIGNUMX),
        YASN1_SIMPLE(DH, g, BIGNUMX),
        YASN1_OPT_EMBED(DH, length, ZINT32),
} YASN1_SEQUENCE_END_cb(DH, DHparams)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(DH, DHparams, DHparams)

/*
 * Internal only structures for handling X9.42 DH: this gets translated to or
 * from a DH structure straight away.
 */

typedef struct {
    YASN1_BIT_STRING *seed;
    BIGNUMX *counter;
} int_dhvparams;

typedef struct {
    BIGNUMX *p;
    BIGNUMX *q;
    BIGNUMX *g;
    BIGNUMX *j;
    int_dhvparams *vparams;
} int_dhx942_dh;

YASN1_SEQUENCE(DHvparams) = {
        YASN1_SIMPLE(int_dhvparams, seed, YASN1_BIT_STRING),
        YASN1_SIMPLE(int_dhvparams, counter, BIGNUMX)
} static_YASN1_SEQUENCE_END_name(int_dhvparams, DHvparams)

YASN1_SEQUENCE(DHxparams) = {
        YASN1_SIMPLE(int_dhx942_dh, p, BIGNUMX),
        YASN1_SIMPLE(int_dhx942_dh, g, BIGNUMX),
        YASN1_SIMPLE(int_dhx942_dh, q, BIGNUMX),
        YASN1_OPT(int_dhx942_dh, j, BIGNUMX),
        YASN1_OPT(int_dhx942_dh, vparams, DHvparams),
} static_YASN1_SEQUENCE_END_name(int_dhx942_dh, DHxparams)

int_dhx942_dh *d2i_int_dhx(int_dhx942_dh **a,
                           const unsigned char **pp, long length);
int i2d_int_dhx(const int_dhx942_dh *a, unsigned char **pp);

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(int_dhx942_dh, DHxparams, int_dhx)

/* Application public function: read in X9.42 DH parameters into DH structure */

DH *d2i_DHxparams(DH **a, const unsigned char **pp, long length)
{
    int_dhx942_dh *dhx = NULL;
    DH *dh = NULL;
    dh = DH_new();
    if (dh == NULL)
        return NULL;
    dhx = d2i_int_dhx(NULL, pp, length);
    if (dhx == NULL) {
        DH_free(dh);
        return NULL;
    }

    if (a) {
        DH_free(*a);
        *a = dh;
    }

    dh->p = dhx->p;
    dh->q = dhx->q;
    dh->g = dhx->g;
    dh->j = dhx->j;

    if (dhx->vparams) {
        dh->seed = dhx->vparams->seed->data;
        dh->seedlen = dhx->vparams->seed->length;
        dh->counter = dhx->vparams->counter;
        dhx->vparams->seed->data = NULL;
        YASN1_BIT_STRING_free(dhx->vparams->seed);
        OPENSSL_free(dhx->vparams);
        dhx->vparams = NULL;
    }

    OPENSSL_free(dhx);
    return dh;
}

int i2d_DHxparams(const DH *dh, unsigned char **pp)
{
    int_dhx942_dh dhx;
    int_dhvparams dhv;
    YASN1_BIT_STRING bs;
    dhx.p = dh->p;
    dhx.g = dh->g;
    dhx.q = dh->q;
    dhx.j = dh->j;
    if (dh->counter && dh->seed && dh->seedlen > 0) {
        bs.flags = YASN1_STRING_FLAG_BITS_LEFT;
        bs.data = dh->seed;
        bs.length = dh->seedlen;
        dhv.seed = &bs;
        dhv.counter = dh->counter;
        dhx.vparams = &dhv;
    } else
        dhx.vparams = NULL;

    return i2d_int_dhx(&dhx, pp);
}
