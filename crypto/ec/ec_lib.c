/*
 * Copyright 2001-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "ec_local.h"

/* functions for ECC_GROUP objects */

ECC_GROUP *ECC_GROUP_new(const EC_METHOD *meth)
{
    ECC_GROUP *ret;

    if (meth == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW, EC_R_SLOT_FULL);
        return NULL;
    }
    if (meth->group_init == 0) {
        ECerr(EC_F_ECC_GROUP_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = meth;
    if ((ret->meth->flags & EC_FLAGS_CUSTOM_CURVE) == 0) {
        ret->order = BNY_new();
        if (ret->order == NULL)
            goto err;
        ret->cofactor = BNY_new();
        if (ret->cofactor == NULL)
            goto err;
    }
    ret->asn1_flag = OPENSSL_EC_NAMED_CURVE;
    ret->asn1_form = POINT_CONVERSION_UNCOMPRESSED;
    if (!meth->group_init(ret))
        goto err;
    return ret;

 err:
    BN_free(ret->order);
    BN_free(ret->cofactor);
    OPENSSL_free(ret);
    return NULL;
}

void EC_pre_comp_free(ECC_GROUP *group)
{
    switch (group->pre_comp_type) {
    case PCT_none:
        break;
    case PCT_nistz256:
#ifdef ECP_NISTZ256_ASM
        EC_nistz256_pre_comp_free(group->pre_comp.nistz256);
#endif
        break;
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    case PCT_nistp224:
        EC_nistp224_pre_comp_free(group->pre_comp.nistp224);
        break;
    case PCT_nistp256:
        EC_nistp256_pre_comp_free(group->pre_comp.nistp256);
        break;
    case PCT_nistp521:
        EC_nistp521_pre_comp_free(group->pre_comp.nistp521);
        break;
#else
    case PCT_nistp224:
    case PCT_nistp256:
    case PCT_nistp521:
        break;
#endif
    case PCT_ec:
        EC_ec_pre_comp_free(group->pre_comp.ec);
        break;
    }
    group->pre_comp.ec = NULL;
}

void ECC_GROUP_free(ECC_GROUP *group)
{
    if (!group)
        return;

    if (group->meth->group_finish != 0)
        group->meth->group_finish(group);

    EC_pre_comp_free(group);
    BN_MONT_CTX_free(group->mont_data);
    EC_POINTT_free(group->generator);
    BN_free(group->order);
    BN_free(group->cofactor);
    OPENSSL_free(group->seed);
    OPENSSL_free(group);
}

void ECC_GROUP_clear_free(ECC_GROUP *group)
{
    if (!group)
        return;

    if (group->meth->group_clear_finish != 0)
        group->meth->group_clear_finish(group);
    else if (group->meth->group_finish != 0)
        group->meth->group_finish(group);

    EC_pre_comp_free(group);
    BN_MONT_CTX_free(group->mont_data);
    EC_POINTT_clear_free(group->generator);
    BNY_clear_free(group->order);
    BNY_clear_free(group->cofactor);
    OPENSSL_clear_free(group->seed, group->seed_len);
    OPENSSL_clear_free(group, sizeof(*group));
}

int ECC_GROUP_copy(ECC_GROUP *dest, const ECC_GROUP *src)
{
    if (dest->meth->group_copy == 0) {
        ECerr(EC_F_ECC_GROUP_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (dest->meth != src->meth) {
        ECerr(EC_F_ECC_GROUP_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (dest == src)
        return 1;

    dest->curve_name = src->curve_name;

    /* Copy precomputed */
    dest->pre_comp_type = src->pre_comp_type;
    switch (src->pre_comp_type) {
    case PCT_none:
        dest->pre_comp.ec = NULL;
        break;
    case PCT_nistz256:
#ifdef ECP_NISTZ256_ASM
        dest->pre_comp.nistz256 = EC_nistz256_pre_comp_dup(src->pre_comp.nistz256);
#endif
        break;
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    case PCT_nistp224:
        dest->pre_comp.nistp224 = EC_nistp224_pre_comp_dup(src->pre_comp.nistp224);
        break;
    case PCT_nistp256:
        dest->pre_comp.nistp256 = EC_nistp256_pre_comp_dup(src->pre_comp.nistp256);
        break;
    case PCT_nistp521:
        dest->pre_comp.nistp521 = EC_nistp521_pre_comp_dup(src->pre_comp.nistp521);
        break;
#else
    case PCT_nistp224:
    case PCT_nistp256:
    case PCT_nistp521:
        break;
#endif
    case PCT_ec:
        dest->pre_comp.ec = EC_ec_pre_comp_dup(src->pre_comp.ec);
        break;
    }

    if (src->mont_data != NULL) {
        if (dest->mont_data == NULL) {
            dest->mont_data = BN_MONT_CTX_new();
            if (dest->mont_data == NULL)
                return 0;
        }
        if (!BN_MONT_CTX_copy(dest->mont_data, src->mont_data))
            return 0;
    } else {
        /* src->generator == NULL */
        BN_MONT_CTX_free(dest->mont_data);
        dest->mont_data = NULL;
    }

    if (src->generator != NULL) {
        if (dest->generator == NULL) {
            dest->generator = EC_POINTT_new(dest);
            if (dest->generator == NULL)
                return 0;
        }
        if (!EC_POINTT_copy(dest->generator, src->generator))
            return 0;
    } else {
        /* src->generator == NULL */
        EC_POINTT_clear_free(dest->generator);
        dest->generator = NULL;
    }

    if ((src->meth->flags & EC_FLAGS_CUSTOM_CURVE) == 0) {
        if (!BNY_copy(dest->order, src->order))
            return 0;
        if (!BNY_copy(dest->cofactor, src->cofactor))
            return 0;
    }

    dest->asn1_flag = src->asn1_flag;
    dest->asn1_form = src->asn1_form;
    dest->decoded_from_explicit_params = src->decoded_from_explicit_params;

    if (src->seed) {
        OPENSSL_free(dest->seed);
        if ((dest->seed = OPENSSL_malloc(src->seed_len)) == NULL) {
            ECerr(EC_F_ECC_GROUP_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!memcpy(dest->seed, src->seed, src->seed_len))
            return 0;
        dest->seed_len = src->seed_len;
    } else {
        OPENSSL_free(dest->seed);
        dest->seed = NULL;
        dest->seed_len = 0;
    }

    return dest->meth->group_copy(dest, src);
}

ECC_GROUP *ECC_GROUP_dup(const ECC_GROUP *a)
{
    ECC_GROUP *t = NULL;
    int ok = 0;

    if (a == NULL)
        return NULL;

    if ((t = ECC_GROUP_new(a->meth)) == NULL)
        return NULL;
    if (!ECC_GROUP_copy(t, a))
        goto err;

    ok = 1;

 err:
    if (!ok) {
        ECC_GROUP_free(t);
        return NULL;
    }
        return t;
}

const EC_METHOD *ECC_GROUP_method_of(const ECC_GROUP *group)
{
    return group->meth;
}

int EC_METHOD_get_field_type(const EC_METHOD *meth)
{
    return meth->field_type;
}

static int ec_precompute_mont_data(ECC_GROUP *);

/*-
 * Try computing cofactor from the generator order (n) and field cardinality (q).
 * This works for all curves of cryptographic interest.
 *
 * Hasse thm: q + 1 - 2*sqrt(q) <= n*h <= q + 1 + 2*sqrt(q)
 * h_min = (q + 1 - 2*sqrt(q))/n
 * h_max = (q + 1 + 2*sqrt(q))/n
 * h_max - h_min = 4*sqrt(q)/n
 * So if n > 4*sqrt(q) holds, there is only one possible value for h:
 * h = \lfloor (h_min + h_max)/2 \rceil = \lfloor (q + 1)/n \rceil
 *
 * Otherwise, zero cofactor and return success.
 */
static int ec_guess_cofactor(ECC_GROUP *group) {
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *q = NULL;

    /*-
     * If the cofactor is too large, we cannot guess it.
     * The RHS of below is a strict overestimate of lg(4 * sqrt(q))
     */
    if (BNY_num_bits(group->order) <= (BNY_num_bits(group->field) + 1) / 2 + 3) {
        /* default to 0 */
        BN_zero(group->cofactor);
        /* return success */
        return 1;
    }

    if ((ctx = BNY_CTX_new()) == NULL)
        return 0;

    BNY_CTX_start(ctx);
    if ((q = BNY_CTX_get(ctx)) == NULL)
        goto err;

    /* set q = 2**m for binary fields; q = p otherwise */
    if (group->meth->field_type == NID_X9_62_characteristic_two_field) {
        BN_zero(q);
        if (!BN_set_bit(q, BNY_num_bits(group->field) - 1))
            goto err;
    } else {
        if (!BNY_copy(q, group->field))
            goto err;
    }

    /* compute h = \lfloor (q + 1)/n \rceil = \lfloor (q + 1 + n/2)/n \rfloor */
    if (!BN_ryshift1(group->cofactor, group->order) /* n/2 */
        || !BNY_add(group->cofactor, group->cofactor, q) /* q + n/2 */
        /* q + 1 + n/2 */
        || !BNY_add(group->cofactor, group->cofactor, BNY_value_one())
        /* (q + 1 + n/2)/n */
        || !BNY_div(group->cofactor, NULL, group->cofactor, group->order, ctx))
        goto err;
    ret = 1;
 err:
    BNY_CTX_end(ctx);
    BNY_CTX_free(ctx);
    return ret;
}

int ECC_GROUP_set_generator(ECC_GROUP *group, const EC_POINTT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor)
{
    if (generator == NULL) {
        ECerr(EC_F_ECC_GROUP_SET_GENERATOR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* require group->field >= 1 */
    if (group->field == NULL || BN_is_zero(group->field)
        || BN_is_negative(group->field)) {
        ECerr(EC_F_ECC_GROUP_SET_GENERATOR, EC_R_INVALID_FIELD);
        return 0;
    }

    /*-
     * - require order >= 1
     * - enforce upper bound due to Hasse thm: order can be no more than one bit
     *   longer than field cardinality
     */
    if (order == NULL || BN_is_zero(order) || BN_is_negative(order)
        || BNY_num_bits(order) > BNY_num_bits(group->field) + 1) {
        ECerr(EC_F_ECC_GROUP_SET_GENERATOR, EC_R_INVALID_GROUP_ORDER);
        return 0;
    }

    /*-
     * Unfortunately the cofactor is an optional field in many standards.
     * Internally, the lib uses 0 cofactor as a marker for "unknown cofactor".
     * So accept cofactor == NULL or cofactor >= 0.
     */
    if (cofactor != NULL && BN_is_negative(cofactor)) {
        ECerr(EC_F_ECC_GROUP_SET_GENERATOR, EC_R_UNKNOWN_COFACTOR);
        return 0;
    }

    if (group->generator == NULL) {
        group->generator = EC_POINTT_new(group);
        if (group->generator == NULL)
            return 0;
    }
    if (!EC_POINTT_copy(group->generator, generator))
        return 0;

    if (!BNY_copy(group->order, order))
        return 0;

    /* Either take the provided positive cofactor, or try to compute it */
    if (cofactor != NULL && !BN_is_zero(cofactor)) {
        if (!BNY_copy(group->cofactor, cofactor))
            return 0;
    } else if (!ec_guess_cofactor(group)) {
        BN_zero(group->cofactor);
        return 0;
    }

    /*
     * Some groups have an order with
     * factors of two, which makes the Montgomery setup fail.
     * |group->mont_data| will be NULL in this case.
     */
    if (BN_is_odd(group->order)) {
        return ec_precompute_mont_data(group);
    }

    BN_MONT_CTX_free(group->mont_data);
    group->mont_data = NULL;
    return 1;
}

const EC_POINTT *ECC_GROUP_get0_generator(const ECC_GROUP *group)
{
    return group->generator;
}

BN_MONT_CTX *ECC_GROUP_get_mont_data(const ECC_GROUP *group)
{
    return group->mont_data;
}

int ECC_GROUP_get_order(const ECC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
    if (group->order == NULL)
        return 0;
    if (!BNY_copy(order, group->order))
        return 0;

    return !BN_is_zero(order);
}

const BIGNUM *ECC_GROUP_get0_order(const ECC_GROUP *group)
{
    return group->order;
}

int ECC_GROUP_order_bits(const ECC_GROUP *group)
{
    return group->meth->group_order_bits(group);
}

int ECC_GROUP_get_cofactor(const ECC_GROUP *group, BIGNUM *cofactor,
                          BN_CTX *ctx)
{

    if (group->cofactor == NULL)
        return 0;
    if (!BNY_copy(cofactor, group->cofactor))
        return 0;

    return !BN_is_zero(group->cofactor);
}

const BIGNUM *ECC_GROUP_get0_cofactor(const ECC_GROUP *group)
{
    return group->cofactor;
}

void ECC_GROUP_set_curve_name(ECC_GROUP *group, int nid)
{
    group->curve_name = nid;
}

int ECC_GROUP_get_curve_name(const ECC_GROUP *group)
{
    return group->curve_name;
}

void ECC_GROUP_set_asn1_flag(ECC_GROUP *group, int flag)
{
    group->asn1_flag = flag;
}

int ECC_GROUP_get_asn1_flag(const ECC_GROUP *group)
{
    return group->asn1_flag;
}

void ECC_GROUP_set_point_conversion_form(ECC_GROUP *group,
                                        point_conversion_form_t form)
{
    group->asn1_form = form;
}

point_conversion_form_t ECC_GROUP_get_point_conversion_form(const ECC_GROUP
                                                           *group)
{
    return group->asn1_form;
}

size_t ECC_GROUP_set_seed(ECC_GROUP *group, const unsigned char *p, size_t len)
{
    OPENSSL_free(group->seed);
    group->seed = NULL;
    group->seed_len = 0;

    if (!len || !p)
        return 1;

    if ((group->seed = OPENSSL_malloc(len)) == NULL) {
        ECerr(EC_F_ECC_GROUP_SET_YSEED, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(group->seed, p, len);
    group->seed_len = len;

    return len;
}

unsigned char *ECC_GROUP_get0_seed(const ECC_GROUP *group)
{
    return group->seed;
}

size_t ECC_GROUP_get_seed_len(const ECC_GROUP *group)
{
    return group->seed_len;
}

int ECC_GROUP_set_curve(ECC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                       const BIGNUM *b, BN_CTX *ctx)
{
    if (group->meth->group_set_curve == 0) {
        ECerr(EC_F_ECC_GROUP_SET_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_set_curve(group, p, a, b, ctx);
}

int ECC_GROUP_get_curve(const ECC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                       BN_CTX *ctx)
{
    if (group->meth->group_get_curve == NULL) {
        ECerr(EC_F_ECC_GROUP_GET_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_curve(group, p, a, b, ctx);
}

#if OPENSSL_API_COMPAT < 0x10200000L
int ECC_GROUP_set_curve_GFp(ECC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                           const BIGNUM *b, BN_CTX *ctx)
{
    return ECC_GROUP_set_curve(group, p, a, b, ctx);
}

int ECC_GROUP_get_curve_GFp(const ECC_GROUP *group, BIGNUM *p, BIGNUM *a,
                           BIGNUM *b, BN_CTX *ctx)
{
    return ECC_GROUP_get_curve(group, p, a, b, ctx);
}

# ifndef OPENSSL_NO_EC2M
int ECC_GROUP_set_curve_GF2m(ECC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *ctx)
{
    return ECC_GROUP_set_curve(group, p, a, b, ctx);
}

int ECC_GROUP_get_curve_GF2m(const ECC_GROUP *group, BIGNUM *p, BIGNUM *a,
                            BIGNUM *b, BN_CTX *ctx)
{
    return ECC_GROUP_get_curve(group, p, a, b, ctx);
}
# endif
#endif

int ECC_GROUP_get_degree(const ECC_GROUP *group)
{
    if (group->meth->group_get_degree == 0) {
        ECerr(EC_F_ECC_GROUP_GET_DEGREE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_degree(group);
}

int ECC_GROUP_check_discriminant(const ECC_GROUP *group, BN_CTX *ctx)
{
    if (group->meth->group_check_discriminant == 0) {
        ECerr(EC_F_ECC_GROUP_CHECK_DISCRIMINANT,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_check_discriminant(group, ctx);
}

int ECC_GROUP_cmp(const ECC_GROUP *a, const ECC_GROUP *b, BN_CTX *ctx)
{
    int r = 0;
    BIGNUM *a1, *a2, *a3, *b1, *b2, *b3;
    BN_CTX *ctx_new = NULL;

    /* compare the field types */
    if (EC_METHOD_get_field_type(ECC_GROUP_method_of(a)) !=
        EC_METHOD_get_field_type(ECC_GROUP_method_of(b)))
        return 1;
    /* compare the curve name (if present in both) */
    if (ECC_GROUP_get_curve_name(a) && ECC_GROUP_get_curve_name(b) &&
        ECC_GROUP_get_curve_name(a) != ECC_GROUP_get_curve_name(b))
        return 1;
    if (a->meth->flags & EC_FLAGS_CUSTOM_CURVE)
        return 0;

    if (ctx == NULL)
        ctx_new = ctx = BNY_CTX_new();
    if (ctx == NULL)
        return -1;

    BNY_CTX_start(ctx);
    a1 = BNY_CTX_get(ctx);
    a2 = BNY_CTX_get(ctx);
    a3 = BNY_CTX_get(ctx);
    b1 = BNY_CTX_get(ctx);
    b2 = BNY_CTX_get(ctx);
    b3 = BNY_CTX_get(ctx);
    if (b3 == NULL) {
        BNY_CTX_end(ctx);
        BNY_CTX_free(ctx_new);
        return -1;
    }

    /*
     * XXX This approach assumes that the external representation of curves
     * over the same field type is the same.
     */
    if (!a->meth->group_get_curve(a, a1, a2, a3, ctx) ||
        !b->meth->group_get_curve(b, b1, b2, b3, ctx))
        r = 1;

    if (r || BN_cmp(a1, b1) || BN_cmp(a2, b2) || BN_cmp(a3, b3))
        r = 1;

    /* XXX EC_POINTT_cmp() assumes that the methods are equal */
    if (r || EC_POINTT_cmp(a, ECC_GROUP_get0_generator(a),
                          ECC_GROUP_get0_generator(b), ctx))
        r = 1;

    if (!r) {
        const BIGNUM *ao, *bo, *ac, *bc;
        /* compare the order and cofactor */
        ao = ECC_GROUP_get0_order(a);
        bo = ECC_GROUP_get0_order(b);
        ac = ECC_GROUP_get0_cofactor(a);
        bc = ECC_GROUP_get0_cofactor(b);
        if (ao == NULL || bo == NULL) {
            BNY_CTX_end(ctx);
            BNY_CTX_free(ctx_new);
            return -1;
        }
        if (BN_cmp(ao, bo) || BN_cmp(ac, bc))
            r = 1;
    }

    BNY_CTX_end(ctx);
    BNY_CTX_free(ctx_new);

    return r;
}

/* functions for EC_POINTT objects */

EC_POINTT *EC_POINTT_new(const ECC_GROUP *group)
{
    EC_POINTT *ret;

    if (group == NULL) {
        ECerr(EC_F_EC_POINTT_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (group->meth->point_init == NULL) {
        ECerr(EC_F_EC_POINTT_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ECerr(EC_F_EC_POINTT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = group->meth;
    ret->curve_name = group->curve_name;

    if (!ret->meth->point_init(ret)) {
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}

void EC_POINTT_free(EC_POINTT *point)
{
    if (!point)
        return;

    if (point->meth->point_finish != 0)
        point->meth->point_finish(point);
    OPENSSL_free(point);
}

void EC_POINTT_clear_free(EC_POINTT *point)
{
    if (!point)
        return;

    if (point->meth->point_clear_finish != 0)
        point->meth->point_clear_finish(point);
    else if (point->meth->point_finish != 0)
        point->meth->point_finish(point);
    OPENSSL_clear_free(point, sizeof(*point));
}

int EC_POINTT_copy(EC_POINTT *dest, const EC_POINTT *src)
{
    if (dest->meth->point_copy == 0) {
        ECerr(EC_F_EC_POINTT_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (dest->meth != src->meth
            || (dest->curve_name != src->curve_name
                && dest->curve_name != 0
                && src->curve_name != 0)) {
        ECerr(EC_F_EC_POINTT_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (dest == src)
        return 1;
    return dest->meth->point_copy(dest, src);
}

EC_POINTT *EC_POINTT_dup(const EC_POINTT *a, const ECC_GROUP *group)
{
    EC_POINTT *t;
    int r;

    if (a == NULL)
        return NULL;

    t = EC_POINTT_new(group);
    if (t == NULL)
        return NULL;
    r = EC_POINTT_copy(t, a);
    if (!r) {
        EC_POINTT_free(t);
        return NULL;
    }
    return t;
}

const EC_METHOD *EC_POINTT_method_of(const EC_POINTT *point)
{
    return point->meth;
}

int EC_POINTT_set_to_infinity(const ECC_GROUP *group, EC_POINTT *point)
{
    if (group->meth->point_set_to_infinity == 0) {
        ECerr(EC_F_EC_POINTT_SET_TO_INFINITY,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINTT_SET_TO_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_to_infinity(group, point);
}

int EC_POINTT_set_Jprojective_coordinates_GFp(const ECC_GROUP *group,
                                             EC_POINTT *point, const BIGNUM *x,
                                             const BIGNUM *y, const BIGNUM *z,
                                             BN_CTX *ctx)
{
    if (group->meth->point_set_Jprojective_coordinates_GFp == 0) {
        ECerr(EC_F_EC_POINTT_SET_JPROJECTIVE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_SET_JPROJECTIVE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_Jprojective_coordinates_GFp(group, point, x,
                                                              y, z, ctx);
}

int EC_POINTT_get_Jprojective_coordinates_GFp(const ECC_GROUP *group,
                                             const EC_POINTT *point, BIGNUM *x,
                                             BIGNUM *y, BIGNUM *z,
                                             BN_CTX *ctx)
{
    if (group->meth->point_get_Jprojective_coordinates_GFp == 0) {
        ECerr(EC_F_EC_POINTT_GET_JPROJECTIVE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_GET_JPROJECTIVE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_get_Jprojective_coordinates_GFp(group, point, x,
                                                              y, z, ctx);
}

int EC_POINTT_set_affine_coordinates(const ECC_GROUP *group, EC_POINTT *point,
                                    const BIGNUM *x, const BIGNUM *y,
                                    BN_CTX *ctx)
{
    if (group->meth->point_set_affine_coordinates == NULL) {
        ECerr(EC_F_EC_POINTT_SET_AFFINE_COORDINATES,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_SET_AFFINE_COORDINATES, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (!group->meth->point_set_affine_coordinates(group, point, x, y, ctx))
        return 0;

    if (EC_POINTT_is_on_curve(group, point, ctx) <= 0) {
        ECerr(EC_F_EC_POINTT_SET_AFFINE_COORDINATES, EC_R_POINT_IS_NOT_ON_CURVE);
        return 0;
    }
    return 1;
}

#if OPENSSL_API_COMPAT < 0x10200000L
int EC_POINTT_set_affine_coordinates_GFp(const ECC_GROUP *group,
                                        EC_POINTT *point, const BIGNUM *x,
                                        const BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINTT_set_affine_coordinates(group, point, x, y, ctx);
}

# ifndef OPENSSL_NO_EC2M
int EC_POINTT_set_affine_coordinates_GF2m(const ECC_GROUP *group,
                                         EC_POINTT *point, const BIGNUM *x,
                                         const BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINTT_set_affine_coordinates(group, point, x, y, ctx);
}
# endif
#endif

int EC_POINTT_get_affine_coordinates(const ECC_GROUP *group,
                                    const EC_POINTT *point, BIGNUM *x, BIGNUM *y,
                                    BN_CTX *ctx)
{
    if (group->meth->point_get_affine_coordinates == NULL) {
        ECerr(EC_F_EC_POINTT_GET_AFFINE_COORDINATES,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_GET_AFFINE_COORDINATES, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (EC_POINTT_is_at_infinity(group, point)) {
        ECerr(EC_F_EC_POINTT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
        return 0;
    }
    return group->meth->point_get_affine_coordinates(group, point, x, y, ctx);
}

#if OPENSSL_API_COMPAT < 0x10200000L
int EC_POINTT_get_affine_coordinates_GFp(const ECC_GROUP *group,
                                        const EC_POINTT *point, BIGNUM *x,
                                        BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINTT_get_affine_coordinates(group, point, x, y, ctx);
}

# ifndef OPENSSL_NO_EC2M
int EC_POINTT_get_affine_coordinates_GF2m(const ECC_GROUP *group,
                                         const EC_POINTT *point, BIGNUM *x,
                                         BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINTT_get_affine_coordinates(group, point, x, y, ctx);
}
# endif
#endif

int EC_POINTT_add(const ECC_GROUP *group, EC_POINTT *r, const EC_POINTT *a,
                 const EC_POINTT *b, BN_CTX *ctx)
{
    if (group->meth->add == 0) {
        ECerr(EC_F_EC_POINTT_ADD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(r, group) || !ec_point_is_compat(a, group)
        || !ec_point_is_compat(b, group)) {
        ECerr(EC_F_EC_POINTT_ADD, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->add(group, r, a, b, ctx);
}

int EC_POINTT_dbl(const ECC_GROUP *group, EC_POINTT *r, const EC_POINTT *a,
                 BN_CTX *ctx)
{
    if (group->meth->dbl == 0) {
        ECerr(EC_F_EC_POINTT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(r, group) || !ec_point_is_compat(a, group)) {
        ECerr(EC_F_EC_POINTT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->dbl(group, r, a, ctx);
}

int EC_POINTT_invert(const ECC_GROUP *group, EC_POINTT *a, BN_CTX *ctx)
{
    if (group->meth->invert == 0) {
        ECerr(EC_F_EC_POINTT_INVERT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(a, group)) {
        ECerr(EC_F_EC_POINTT_INVERT, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->invert(group, a, ctx);
}

int EC_POINTT_is_at_infinity(const ECC_GROUP *group, const EC_POINTT *point)
{
    if (group->meth->is_at_infinity == 0) {
        ECerr(EC_F_EC_POINTT_IS_AT_INFINITY,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_IS_AT_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->is_at_infinity(group, point);
}

/*
 * Check whether an EC_POINTT is on the curve or not. Note that the return
 * value for this function should NOT be treated as a boolean. Return values:
 *  1: The point is on the curve
 *  0: The point is not on the curve
 * -1: An error occurred
 */
int EC_POINTT_is_on_curve(const ECC_GROUP *group, const EC_POINTT *point,
                         BN_CTX *ctx)
{
    if (group->meth->is_on_curve == 0) {
        ECerr(EC_F_EC_POINTT_IS_ON_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_IS_ON_CURVE, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->is_on_curve(group, point, ctx);
}

int EC_POINTT_cmp(const ECC_GROUP *group, const EC_POINTT *a, const EC_POINTT *b,
                 BN_CTX *ctx)
{
    if (group->meth->point_cmp == 0) {
        ECerr(EC_F_EC_POINTT_CMP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return -1;
    }
    if (!ec_point_is_compat(a, group) || !ec_point_is_compat(b, group)) {
        ECerr(EC_F_EC_POINTT_CMP, EC_R_INCOMPATIBLE_OBJECTS);
        return -1;
    }
    return group->meth->point_cmp(group, a, b, ctx);
}

int EC_POINTT_make_affine(const ECC_GROUP *group, EC_POINTT *point, BN_CTX *ctx)
{
    if (group->meth->make_affine == 0) {
        ECerr(EC_F_EC_POINTT_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINTT_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->make_affine(group, point, ctx);
}

int EC_POINTTs_make_affine(const ECC_GROUP *group, size_t num,
                          EC_POINTT *points[], BN_CTX *ctx)
{
    size_t i;

    if (group->meth->points_make_affine == 0) {
        ECerr(EC_F_EC_POINTTS_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    for (i = 0; i < num; i++) {
        if (!ec_point_is_compat(points[i], group)) {
            ECerr(EC_F_EC_POINTTS_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }
    return group->meth->points_make_affine(group, num, points, ctx);
}

/*
 * Functions for point multiplication. If group->meth->mul is 0, we use the
 * wNAF-based implementations in ec_mult.c; otherwise we dispatch through
 * methods.
 */

int EC_POINTTs_mul(const ECC_GROUP *group, EC_POINTT *r, const BIGNUM *scalar,
                  size_t num, const EC_POINTT *points[],
                  const BIGNUM *scalars[], BN_CTX *ctx)
{
    int ret = 0;
    size_t i = 0;
    BN_CTX *new_ctx = NULL;

    if (!ec_point_is_compat(r, group)) {
        ECerr(EC_F_EC_POINTTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }

    if (scalar == NULL && num == 0)
        return EC_POINTT_set_to_infinity(group, r);

    for (i = 0; i < num; i++) {
        if (!ec_point_is_compat(points[i], group)) {
            ECerr(EC_F_EC_POINTTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }

    if (ctx == NULL && (ctx = new_ctx = BNY_CTX_secure_new()) == NULL) {
        ECerr(EC_F_EC_POINTTS_MUL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (group->meth->mul != NULL)
        ret = group->meth->mul(group, r, scalar, num, points, scalars, ctx);
    else
        /* use default */
        ret = ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);

    BNY_CTX_free(new_ctx);
    return ret;
}

int EC_POINTT_mul(const ECC_GROUP *group, EC_POINTT *r, const BIGNUM *g_scalar,
                 const EC_POINTT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
    /* just a convenient interface to EC_POINTTs_mul() */

    const EC_POINTT *points[1];
    const BIGNUM *scalars[1];

    points[0] = point;
    scalars[0] = p_scalar;

    return EC_POINTTs_mul(group, r, g_scalar,
                         (point != NULL
                          && p_scalar != NULL), points, scalars, ctx);
}

int ECC_GROUP_precompute_mult(ECC_GROUP *group, BN_CTX *ctx)
{
    if (group->meth->mul == 0)
        /* use default */
        return ec_wNAF_precompute_mult(group, ctx);

    if (group->meth->precompute_mult != 0)
        return group->meth->precompute_mult(group, ctx);
    else
        return 1;               /* nothing to do, so report success */
}

int ECC_GROUP_have_precompute_mult(const ECC_GROUP *group)
{
    if (group->meth->mul == 0)
        /* use default */
        return ec_wNAF_have_precompute_mult(group);

    if (group->meth->have_precompute_mult != 0)
        return group->meth->have_precompute_mult(group);
    else
        return 0;               /* cannot tell whether precomputation has
                                 * been performed */
}

/*
 * ec_precompute_mont_data sets |group->mont_data| from |group->order| and
 * returns one on success. On error it returns zero.
 */
static int ec_precompute_mont_data(ECC_GROUP *group)
{
    BN_CTX *ctx = BNY_CTX_new();
    int ret = 0;

    BN_MONT_CTX_free(group->mont_data);
    group->mont_data = NULL;

    if (ctx == NULL)
        goto err;

    group->mont_data = BN_MONT_CTX_new();
    if (group->mont_data == NULL)
        goto err;

    if (!BN_MONT_CTX_set(group->mont_data, group->order, ctx)) {
        BN_MONT_CTX_free(group->mont_data);
        group->mont_data = NULL;
        goto err;
    }

    ret = 1;

 err:

    BNY_CTX_free(ctx);
    return ret;
}

int ECC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&key->ex_data, idx, arg);
}

void *ECC_KEY_get_ex_data(const EC_KEY *key, int idx)
{
    return CRYPTO_get_ex_data(&key->ex_data, idx);
}

int ec_group_simple_order_bits(const ECC_GROUP *group)
{
    if (group->order == NULL)
        return 0;
    return BNY_num_bits(group->order);
}

static int ec_field_inverse_mod_ord(const ECC_GROUP *group, BIGNUM *r,
                                    const BIGNUM *x, BN_CTX *ctx)
{
    BIGNUM *e = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (group->mont_data == NULL)
        return 0;

    if (ctx == NULL && (ctx = new_ctx = BNY_CTX_secure_new()) == NULL)
        return 0;

    BNY_CTX_start(ctx);
    if ((e = BNY_CTX_get(ctx)) == NULL)
        goto err;

    /*-
     * We want inverse in constant time, therefore we utilize the fact
     * order must be prime and use Fermats Little Theorem instead.
     */
    if (!BN_set_word(e, 2))
        goto err;
    if (!BNY_sub(e, group->order, e))
        goto err;
    /*-
     * Exponent e is public.
     * No need for scatter-gather or BN_FLG_CONSTTIME.
     */
    if (!BNY_mod_exp_mont(r, x, e, group->order, ctx, group->mont_data))
        goto err;

    ret = 1;

 err:
    BNY_CTX_end(ctx);
    BNY_CTX_free(new_ctx);
    return ret;
}

/*-
 * Default behavior, if group->meth->field_inverse_mod_ord is NULL:
 * - When group->order is even, this function returns an error.
 * - When group->order is otherwise composite, the correctness
 *   of the output is not guaranteed.
 * - When x is outside the range [1, group->order), the correctness
 *   of the output is not guaranteed.
 * - Otherwise, this function returns the multiplicative inverse in the
 *   range [1, group->order).
 *
 * EC_METHODs must implement their own field_inverse_mod_ord for
 * other functionality.
 */
int ec_group_do_inverse_ord(const ECC_GROUP *group, BIGNUM *res,
                            const BIGNUM *x, BN_CTX *ctx)
{
    if (group->meth->field_inverse_mod_ord != NULL)
        return group->meth->field_inverse_mod_ord(group, res, x, ctx);
    else
        return ec_field_inverse_mod_ord(group, res, x, ctx);
}

/*-
 * Coordinate blinding for EC_POINTT.
 *
 * The underlying EC_METHOD can optionally implement this function:
 * underlying implementations should return 0 on errors, or 1 on
 * success.
 *
 * This wrapper returns 1 in case the underlying EC_METHOD does not
 * support coordinate blinding.
 */
int ec_point_blind_coordinates(const ECC_GROUP *group, EC_POINTT *p, BN_CTX *ctx)
{
    if (group->meth->blind_coordinates == NULL)
        return 1; /* ignore if not implemented */

    return group->meth->blind_coordinates(group, p, ctx);
}
