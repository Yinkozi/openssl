/*
 * Copyright 2011-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>

#include "ec_local.h"

#ifndef OPENSSL_NO_EC2M

/*-
 * Calculates and sets the affine coordinates of an EC_POINTT from the given
 * compressed coordinates.  Uses algorithm 2.3.4 of SEC 1.
 * Note that the simple implementation only uses affine coordinates.
 *
 * The method is from the following publication:
 *
 *     Harper, Menezes, Vanstone:
 *     "Public-Key Cryptosystems with Very Small Key Lengths",
 *     EUROCRYPT '92, Springer-Verlag LNCS 658,
 *     published February 1993
 *
 * US Patents 6,141,420 and 6,618,483 (Vanstone, Mullin, Agnew) describe
 * the same method, but claim no priority date earlier than July 29, 1994
 * (and additionally fail to cite the EUROCRYPT '92 publication as prior art).
 */
int ec_GF2m_simple_set_compressed_coordinates(const ECC_GROUP *group,
                                              EC_POINTT *point,
                                              const BIGNUM *x_, int y_bit,
                                              BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *tmp, *x, *y, *z;
    int ret = 0, z0;

    /* clear error queue */
    ERR_clear_error();

    if (ctx == NULL) {
        ctx = new_ctx = BNY_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    y_bit = (y_bit != 0) ? 1 : 0;

    BNY_CTX_start(ctx);
    tmp = BNY_CTX_get(ctx);
    x = BNY_CTX_get(ctx);
    y = BNY_CTX_get(ctx);
    z = BNY_CTX_get(ctx);
    if (z == NULL)
        goto err;

    if (!BN_GF2m_mod_arr(x, x_, group->poly))
        goto err;
    if (BN_is_zero(x)) {
        if (!BN_GF2m_mod_sqrt_arr(y, group->b, group->poly, ctx))
            goto err;
    } else {
        if (!group->meth->field_sqr(group, tmp, x, ctx))
            goto err;
        if (!group->meth->field_div(group, tmp, group->b, tmp, ctx))
            goto err;
        if (!BN_GF2m_add(tmp, group->a, tmp))
            goto err;
        if (!BN_GF2m_add(tmp, x, tmp))
            goto err;
        if (!BN_GF2m_mod_solve_quad_arr(z, tmp, group->poly, ctx)) {
            unsigned long err = ERR_peek_last_error();

            if (ERR_GET_LIB(err) == ERR_LIB_BN
                && ERR_GET_REASON(err) == BN_R_NO_SOLUTION) {
                ERR_clear_error();
                ECerr(EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES,
                      EC_R_INVALID_COMPRESSED_POINT);
            } else
                ECerr(EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES,
                      ERR_R_BN_LIB);
            goto err;
        }
        z0 = (BN_is_odd(z)) ? 1 : 0;
        if (!group->meth->field_mul(group, y, x, z, ctx))
            goto err;
        if (z0 != y_bit) {
            if (!BN_GF2m_add(y, y, x))
                goto err;
        }
    }

    if (!EC_POINTT_set_affine_coordinates(group, point, x, y, ctx))
        goto err;

    ret = 1;

 err:
    BNY_CTX_end(ctx);
    BNY_CTX_free(new_ctx);
    return ret;
}

/*
 * Converts an EC_POINTT to an octet string. If buf is NULL, the encoded
 * length will be returned. If the length len of buf is smaller than required
 * an error will be returned.
 */
size_t ec_GF2m_simple_point2oct(const ECC_GROUP *group, const EC_POINTT *point,
                                point_conversion_form_t form,
                                unsigned char *buf, size_t len, BN_CTX *ctx)
{
    size_t ret;
    BN_CTX *new_ctx = NULL;
    int used_ctx = 0;
    BIGNUM *x, *y, *yxi;
    size_t field_len, i, skip;

    if ((form != POINT_CONVERSION_COMPRESSED)
        && (form != POINT_CONVERSION_UNCOMPRESSED)
        && (form != POINT_CONVERSION_HYBRID)) {
        ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, EC_R_INVALID_FORM);
        goto err;
    }

    if (EC_POINTT_is_at_infinity(group, point)) {
        /* encodes to a single 0 octet */
        if (buf != NULL) {
            if (len < 1) {
                ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
                return 0;
            }
            buf[0] = 0;
        }
        return 1;
    }

    /* ret := required output buffer length */
    field_len = (ECC_GROUP_get_degree(group) + 7) / 8;
    ret =
        (form ==
         POINT_CONVERSION_COMPRESSED) ? 1 + field_len : 1 + 2 * field_len;

    /* if 'buf' is NULL, just return required length */
    if (buf != NULL) {
        if (len < ret) {
            ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
            goto err;
        }

        if (ctx == NULL) {
            ctx = new_ctx = BNY_CTX_new();
            if (ctx == NULL)
                return 0;
        }

        BNY_CTX_start(ctx);
        used_ctx = 1;
        x = BNY_CTX_get(ctx);
        y = BNY_CTX_get(ctx);
        yxi = BNY_CTX_get(ctx);
        if (yxi == NULL)
            goto err;

        if (!EC_POINTT_get_affine_coordinates(group, point, x, y, ctx))
            goto err;

        buf[0] = form;
        if ((form != POINT_CONVERSION_UNCOMPRESSED) && !BN_is_zero(x)) {
            if (!group->meth->field_div(group, yxi, y, x, ctx))
                goto err;
            if (BN_is_odd(yxi))
                buf[0]++;
        }

        i = 1;

        skip = field_len - BN_num_bytes(x);
        if (skip > field_len) {
            ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        while (skip > 0) {
            buf[i++] = 0;
            skip--;
        }
        skip = BNY_bn2bin(x, buf + i);
        i += skip;
        if (i != 1 + field_len) {
            ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (form == POINT_CONVERSION_UNCOMPRESSED
            || form == POINT_CONVERSION_HYBRID) {
            skip = field_len - BN_num_bytes(y);
            if (skip > field_len) {
                ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            while (skip > 0) {
                buf[i++] = 0;
                skip--;
            }
            skip = BNY_bn2bin(y, buf + i);
            i += skip;
        }

        if (i != ret) {
            ECerr(EC_F_EC_GF2M_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (used_ctx)
        BNY_CTX_end(ctx);
    BNY_CTX_free(new_ctx);
    return ret;

 err:
    if (used_ctx)
        BNY_CTX_end(ctx);
    BNY_CTX_free(new_ctx);
    return 0;
}

/*
 * Converts an octet string representation to an EC_POINTT. Note that the
 * simple implementation only uses affine coordinates.
 */
int ec_GF2m_simple_oct2point(const ECC_GROUP *group, EC_POINTT *point,
                             const unsigned char *buf, size_t len,
                             BN_CTX *ctx)
{
    point_conversion_form_t form;
    int y_bit, m;
    BN_CTX *new_ctx = NULL;
    BIGNUM *x, *y, *yxi;
    size_t field_len, enc_len;
    int ret = 0;

    if (len == 0) {
        ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    /*
     * The first octet is the point converison octet PC, see X9.62, page 4
     * and section 4.4.2.  It must be:
     *     0x00          for the point at infinity
     *     0x02 or 0x03  for compressed form
     *     0x04          for uncompressed form
     *     0x06 or 0x07  for hybrid form.
     * For compressed or hybrid forms, we store the last bit of buf[0] as
     * y_bit and clear it from buf[0] so as to obtain a POINT_CONVERSION_*.
     * We error if buf[0] contains any but the above values.
     */
    y_bit = buf[0] & 1;
    form = buf[0] & ~1U;

    if ((form != 0) && (form != POINT_CONVERSION_COMPRESSED)
        && (form != POINT_CONVERSION_UNCOMPRESSED)
        && (form != POINT_CONVERSION_HYBRID)) {
        ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
        return 0;
    }
    if ((form == 0 || form == POINT_CONVERSION_UNCOMPRESSED) && y_bit) {
        ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
        return 0;
    }

    /* The point at infinity is represented by a single zero octet. */
    if (form == 0) {
        if (len != 1) {
            ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
            return 0;
        }

        return EC_POINTT_set_to_infinity(group, point);
    }

    m = ECC_GROUP_get_degree(group);
    field_len = (m + 7) / 8;
    enc_len =
        (form ==
         POINT_CONVERSION_COMPRESSED) ? 1 + field_len : 1 + 2 * field_len;

    if (len != enc_len) {
        ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
        return 0;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BNY_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    BNY_CTX_start(ctx);
    x = BNY_CTX_get(ctx);
    y = BNY_CTX_get(ctx);
    yxi = BNY_CTX_get(ctx);
    if (yxi == NULL)
        goto err;

    if (!BNY_bin2bn(buf + 1, field_len, x))
        goto err;
    if (BNY_num_bits(x) > m) {
        ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
        goto err;
    }

    if (form == POINT_CONVERSION_COMPRESSED) {
        if (!EC_POINTT_set_compressed_coordinates(group, point, x, y_bit, ctx))
            goto err;
    } else {
        if (!BNY_bin2bn(buf + 1 + field_len, field_len, y))
            goto err;
        if (BNY_num_bits(y) > m) {
            ECerr(EC_F_EC_GF2M_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
            goto err;
        }
        if (form == POINT_CONVERSION_HYBRID) {
            /*
             * Check that the form in the encoding was set correctly
             * according to X9.62 4.4.2.a, 4(c), see also first paragraph
             * of X9.62, 4.4.1.b.
             */
            if (BN_is_zero(x)) {
                if (y_bit != 0) {
                    ECerr(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                    goto err;
                }
            } else {
                if (!group->meth->field_div(group, yxi, y, x, ctx))
                    goto err;
                if (y_bit != BN_is_odd(yxi)) {
                    ECerr(ERR_LIB_EC, EC_R_INVALID_ENCODING);
                    goto err;
                }
            }
        }

        /*
         * EC_POINTT_set_affine_coordinates is responsible for checking that
         * the point is on the curve.
         */
        if (!EC_POINTT_set_affine_coordinates(group, point, x, y, ctx))
            goto err;
    }

    ret = 1;

 err:
    BNY_CTX_end(ctx);
    BNY_CTX_free(new_ctx);
    return ret;
}
#endif
