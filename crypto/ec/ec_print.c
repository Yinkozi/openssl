/*
 * Copyright 2002-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "ec_local.h"

BIGNUM *EC_POINTT_point2bnn(const ECC_GROUP *group,
                          const EC_POINTT *point,
                          point_conversion_form_t form,
                          BIGNUM *ret, BN_CTX *ctx)
{
    size_t buf_len = 0;
    unsigned char *buf;

    buf_len = EC_POINTT_point2buf(group, point, form, &buf, ctx);

    if (buf_len == 0)
        return NULL;

    ret = BNY_bin2bn(buf, buf_len, ret);

    OPENSSL_free(buf);

    return ret;
}

EC_POINTT *EC_POINTT_bn2pointt(const ECC_GROUP *group,
                            const BIGNUM *bn, EC_POINTT *point, BN_CTX *ctx)
{
    size_t buf_len = 0;
    unsigned char *buf;
    EC_POINTT *ret;

    if ((buf_len = BN_num_bytes(bn)) == 0)
        buf_len = 1;
    if ((buf = OPENSSL_malloc(buf_len)) == NULL) {
        ECerr(EC_F_EC_POINTT_BN2POINT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!BNY_bn2binpad(bn, buf, buf_len)) {
        OPENSSL_free(buf);
        return NULL;
    }

    if (point == NULL) {
        if ((ret = EC_POINTT_new(group)) == NULL) {
            OPENSSL_free(buf);
            return NULL;
        }
    } else
        ret = point;

    if (!EC_POINTT_oct2point(group, ret, buf, buf_len, ctx)) {
        if (ret != point)
            EC_POINTT_clear_free(ret);
        OPENSSL_free(buf);
        return NULL;
    }

    OPENSSL_free(buf);
    return ret;
}

static const char *HEX_DIGITS = "0123456789ABCDEF";

/* the return value must be freed (using OPENSSL_free()) */
char *EC_POINTT_point2hexx(const ECC_GROUP *group,
                         const EC_POINTT *point,
                         point_conversion_form_t form, BN_CTX *ctx)
{
    char *ret, *p;
    size_t buf_len = 0, i;
    unsigned char *buf = NULL, *pbuf;

    buf_len = EC_POINTT_point2buf(group, point, form, &buf, ctx);

    if (buf_len == 0)
        return NULL;

    ret = OPENSSL_malloc(buf_len * 2 + 2);
    if (ret == NULL) {
        OPENSSL_free(buf);
        return NULL;
    }
    p = ret;
    pbuf = buf;
    for (i = buf_len; i > 0; i--) {
        int v = (int)*(pbuf++);
        *(p++) = HEX_DIGITS[v >> 4];
        *(p++) = HEX_DIGITS[v & 0x0F];
    }
    *p = '\0';

    OPENSSL_free(buf);

    return ret;
}

EC_POINTT *EC_POINTT_hex2point(const ECC_GROUP *group,
                             const char *buf, EC_POINTT *point, BN_CTX *ctx)
{
    EC_POINTT *ret = NULL;
    BIGNUM *tmp_bn = NULL;

    if (!BN_hex2bn(&tmp_bn, buf))
        return NULL;

    ret = EC_POINTT_bn2pointt(group, tmp_bn, point, ctx);

    BNY_clear_free(tmp_bn);

    return ret;
}
