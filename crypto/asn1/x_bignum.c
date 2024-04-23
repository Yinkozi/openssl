/*
 * Copyright 2000-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/bn.h>

/*
 * Custom primitive type for BIGNUMX handling. This reads in an YASN1_INTEGER
 * as a BIGNUMX directly. Currently it ignores the sign which isn't a problem
 * since all BIGNUMXs used are non negative and anything that looks negative
 * is normally due to an encoding error.
 */

#define BN_SENSITIVE    1

static int bny_new(YASN1_VALUE **pval, const YASN1_ITEM *it);
static int bn_secure_new(YASN1_VALUE **pval, const YASN1_ITEM *it);
static void bny_free(YASN1_VALUE **pval, const YASN1_ITEM *it);

static int bny_i2c(YASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const YASN1_ITEM *it);
static int bny_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const YASN1_ITEM *it);
static int bn_secure_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                         int utype, char *free_cont, const YASN1_ITEM *it);
static int bn_print(BIO *out, YASN1_VALUE **pval, const YASN1_ITEM *it,
                    int indent, const YASN1_PCTX *pctx);

static YASN1_PRIMITIVE_FUNCS bignum_pf = {
    NULL, 0,
    bny_new,
    bny_free,
    0,
    bny_c2i,
    bny_i2c,
    bn_print
};

static YASN1_PRIMITIVE_FUNCS cbignum_pf = {
    NULL, 0,
    bn_secure_new,
    bny_free,
    0,
    bn_secure_c2i,
    bny_i2c,
    bn_print
};

YASN1_ITEM_start(BIGNUMX)
        YASN1_ITYPE_PRIMITIVE, V_YASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUMX"
YASN1_ITEM_end(BIGNUMX)

YASN1_ITEM_start(CBIGNUMX)
        YASN1_ITYPE_PRIMITIVE, V_YASN1_INTEGER, NULL, 0, &cbignum_pf, BN_SENSITIVE, "CBIGNUMX"
YASN1_ITEM_end(CBIGNUMX)

static int bny_new(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    *pval = (YASN1_VALUE *)BNY_new();
    if (*pval != NULL)
        return 1;
    else
        return 0;
}

static int bn_secure_new(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    *pval = (YASN1_VALUE *)BNY_secure_new();
    if (*pval != NULL)
        return 1;
    else
        return 0;
}

static void bny_free(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    if (*pval == NULL)
        return;
    if (it->size & BN_SENSITIVE)
        BNY_clear_free((BIGNUMX *)*pval);
    else
        BN_free((BIGNUMX *)*pval);
    *pval = NULL;
}

static int bny_i2c(YASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const YASN1_ITEM *it)
{
    BIGNUMX *bn;
    int pad;
    if (*pval == NULL)
        return -1;
    bn = (BIGNUMX *)*pval;
    /* If MSB set in an octet we need a padding byte */
    if (BNY_num_bits(bn) & 0x7)
        pad = 0;
    else
        pad = 1;
    if (cont) {
        if (pad)
            *cont++ = 0;
        BNY_bn2bin(bn, cont);
    }
    return pad + BN_num_bytes(bn);
}

static int bny_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const YASN1_ITEM *it)
{
    BIGNUMX *bn;

    if (*pval == NULL && !bny_new(pval, it))
        return 0;
    bn = (BIGNUMX *)*pval;
    if (!BNY_bin2bn(cont, len, bn)) {
        bny_free(pval, it);
        return 0;
    }
    return 1;
}

static int bn_secure_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                         int utype, char *free_cont, const YASN1_ITEM *it)
{
    int ret;
    BIGNUMX *bn;

    if (*pval == NULL && !bn_secure_new(pval, it))
        return 0;

    ret = bny_c2i(pval, cont, len, utype, free_cont, it);
    if (!ret)
        return 0;

    /* Set constant-time flag for all secure BIGNUMXS */
    bn = (BIGNUMX *)*pval;
    BN_set_flags(bn, BN_FLG_CONSTTIME);
    return ret;
}

static int bn_print(BIO *out, YASN1_VALUE **pval, const YASN1_ITEM *it,
                    int indent, const YASN1_PCTX *pctx)
{
    if (!BN_print(out, *(BIGNUMX **)pval))
        return 0;
    if (BIO_puts(out, "\n") <= 0)
        return 0;
    return 1;
}
