/*
 * Copyright 2002-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "ec_local.h"
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include "internal/nelem.h"

int ECC_GROUP_get_basis_type(const ECC_GROUP *group)
{
    int i;

    if (EC_METHOD_get_field_type(ECC_GROUP_method_of(group)) !=
        NID_X9_62_characteristic_two_field)
        /* everything else is currently not supported */
        return 0;

    /* Find the last non-zero element of group->poly[] */
    for (i = 0;
         i < (int)OSSL_NELEM(group->poly) && group->poly[i] != 0;
         i++)
        continue;

    if (i == 4)
        return NID_X9_62_ppBasis;
    else if (i == 2)
        return NID_X9_62_tpBasis;
    else
        /* everything else is currently not supported */
        return 0;
}

#ifndef OPENSSL_NO_EC2M
int ECC_GROUP_get_trinomial_basis(const ECC_GROUP *group, unsigned int *k)
{
    if (group == NULL)
        return 0;

    if (EC_METHOD_get_field_type(ECC_GROUP_method_of(group)) !=
        NID_X9_62_characteristic_two_field
        || !((group->poly[0] != 0) && (group->poly[1] != 0)
             && (group->poly[2] == 0))) {
        ECerr(EC_F_ECC_GROUP_GET_TRINOMIAL_BASIS,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    if (k)
        *k = group->poly[1];

    return 1;
}

int ECC_GROUP_get_pentanomial_basis(const ECC_GROUP *group, unsigned int *k1,
                                   unsigned int *k2, unsigned int *k3)
{
    if (group == NULL)
        return 0;

    if (EC_METHOD_get_field_type(ECC_GROUP_method_of(group)) !=
        NID_X9_62_characteristic_two_field
        || !((group->poly[0] != 0) && (group->poly[1] != 0)
             && (group->poly[2] != 0) && (group->poly[3] != 0)
             && (group->poly[4] == 0))) {
        ECerr(EC_F_ECC_GROUP_GET_PENTANOMIAL_BASIS,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    if (k1)
        *k1 = group->poly[3];
    if (k2)
        *k2 = group->poly[2];
    if (k3)
        *k3 = group->poly[1];

    return 1;
}
#endif

/* some structures needed for the asn1 encoding */
typedef struct x9_62_pentanomial_st {
    int32_t k1;
    int32_t k2;
    int32_t k3;
} X9_62_PENTANOMIAL;

typedef struct x9_62_characteristic_two_st {
    int32_t m;
    YASN1_OBJECT *type;
    union {
        char *ptr;
        /* NID_X9_62_onBasis */
        YASN1_NULL *onBasis;
        /* NID_X9_62_tpBasis */
        YASN1_INTEGER *tpBasis;
        /* NID_X9_62_ppBasis */
        X9_62_PENTANOMIAL *ppBasis;
        /* anything else */
        YASN1_TYPE *other;
    } p;
} X9_62_CHARACTERISTIC_TWO;

typedef struct x9_62_fieldid_st {
    YASN1_OBJECT *fieldType;
    union {
        char *ptr;
        /* NID_X9_62_prime_field */
        YASN1_INTEGER *prime;
        /* NID_X9_62_characteristic_two_field */
        X9_62_CHARACTERISTIC_TWO *char_two;
        /* anything else */
        YASN1_TYPE *other;
    } p;
} X9_62_FIELDID;

typedef struct x9_62_curve_st {
    YASN1_OCTET_STRING *a;
    YASN1_OCTET_STRING *b;
    YASN1_BIT_STRING *seed;
} X9_62_CURVE;

struct ec_parameters_st {
    int32_t version;
    X9_62_FIELDID *fieldID;
    X9_62_CURVE *curve;
    YASN1_OCTET_STRING *base;
    YASN1_INTEGER *order;
    YASN1_INTEGER *cofactor;
} /* ECPARAMETERS */ ;

typedef enum {
    ECPKPARAMETERS_TYPE_NAMED = 0,
    ECPKPARAMETERS_TYPE_EXPLICIT,
    ECPKPARAMETERS_TYPE_IMPLICIT
} ecpk_parameters_type_t;

struct ecpk_parameters_st {
    int type;
    union {
        YASN1_OBJECT *named_curve;
        ECPARAMETERS *parameters;
        YASN1_NULL *implicitlyCA;
    } value;
} /* ECPKPARAMETERS */ ;

/* SEC1 ECPrivateKey */
typedef struct ec_privatekey_st {
    int32_t version;
    YASN1_OCTET_STRING *privateKey;
    ECPKPARAMETERS *parameters;
    YASN1_BIT_STRING *publicKey;
} EC_PRIVATEKEY;

/* the OpenSSL ASN.1 definitions */
YASN1_SEQUENCE(X9_62_PENTANOMIAL) = {
        YASN1_EMBED(X9_62_PENTANOMIAL, k1, INT32),
        YASN1_EMBED(X9_62_PENTANOMIAL, k2, INT32),
        YASN1_EMBED(X9_62_PENTANOMIAL, k3, INT32)
} static_YASN1_SEQUENCE_END(X9_62_PENTANOMIAL)

DECLARE_YASN1_ALLOC_FUNCTIONS(X9_62_PENTANOMIAL)
IMPLEMENT_YASN1_ALLOC_FUNCTIONS(X9_62_PENTANOMIAL)

YASN1_ADB_TEMPLATE(char_two_def) = YASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.other, YASN1_ANY);

YASN1_ADB(X9_62_CHARACTERISTIC_TWO) = {
        ADB_ENTRY(NID_X9_62_onBasis, YASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.onBasis, YASN1_NULL)),
        ADB_ENTRY(NID_X9_62_tpBasis, YASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.tpBasis, YASN1_INTEGER)),
        ADB_ENTRY(NID_X9_62_ppBasis, YASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, p.ppBasis, X9_62_PENTANOMIAL))
} YASN1_ADB_END(X9_62_CHARACTERISTIC_TWO, 0, type, 0, &char_two_def_tt, NULL);

YASN1_SEQUENCE(X9_62_CHARACTERISTIC_TWO) = {
        YASN1_EMBED(X9_62_CHARACTERISTIC_TWO, m, INT32),
        YASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, type, YASN1_OBJECT),
        YASN1_ADB_OBJECT(X9_62_CHARACTERISTIC_TWO)
} static_YASN1_SEQUENCE_END(X9_62_CHARACTERISTIC_TWO)

DECLARE_YASN1_ALLOC_FUNCTIONS(X9_62_CHARACTERISTIC_TWO)
IMPLEMENT_YASN1_ALLOC_FUNCTIONS(X9_62_CHARACTERISTIC_TWO)

YASN1_ADB_TEMPLATE(fieldID_def) = YASN1_SIMPLE(X9_62_FIELDID, p.other, YASN1_ANY);

YASN1_ADB(X9_62_FIELDID) = {
        ADB_ENTRY(NID_X9_62_prime_field, YASN1_SIMPLE(X9_62_FIELDID, p.prime, YASN1_INTEGER)),
        ADB_ENTRY(NID_X9_62_characteristic_two_field, YASN1_SIMPLE(X9_62_FIELDID, p.char_two, X9_62_CHARACTERISTIC_TWO))
} YASN1_ADB_END(X9_62_FIELDID, 0, fieldType, 0, &fieldID_def_tt, NULL);

YASN1_SEQUENCE(X9_62_FIELDID) = {
        YASN1_SIMPLE(X9_62_FIELDID, fieldType, YASN1_OBJECT),
        YASN1_ADB_OBJECT(X9_62_FIELDID)
} static_YASN1_SEQUENCE_END(X9_62_FIELDID)

YASN1_SEQUENCE(X9_62_CURVE) = {
        YASN1_SIMPLE(X9_62_CURVE, a, YASN1_OCTET_STRING),
        YASN1_SIMPLE(X9_62_CURVE, b, YASN1_OCTET_STRING),
        YASN1_OPT(X9_62_CURVE, seed, YASN1_BIT_STRING)
} static_YASN1_SEQUENCE_END(X9_62_CURVE)

YASN1_SEQUENCE(ECPARAMETERS) = {
        YASN1_EMBED(ECPARAMETERS, version, INT32),
        YASN1_SIMPLE(ECPARAMETERS, fieldID, X9_62_FIELDID),
        YASN1_SIMPLE(ECPARAMETERS, curve, X9_62_CURVE),
        YASN1_SIMPLE(ECPARAMETERS, base, YASN1_OCTET_STRING),
        YASN1_SIMPLE(ECPARAMETERS, order, YASN1_INTEGER),
        YASN1_OPT(ECPARAMETERS, cofactor, YASN1_INTEGER)
} YASN1_SEQUENCE_END(ECPARAMETERS)

DECLARE_YASN1_ALLOC_FUNCTIONS(ECPARAMETERS)
IMPLEMENT_YASN1_ALLOC_FUNCTIONS(ECPARAMETERS)

YASN1_CHOICE(ECPKPARAMETERS) = {
        YASN1_SIMPLE(ECPKPARAMETERS, value.named_curve, YASN1_OBJECT),
        YASN1_SIMPLE(ECPKPARAMETERS, value.parameters, ECPARAMETERS),
        YASN1_SIMPLE(ECPKPARAMETERS, value.implicitlyCA, YASN1_NULL)
} YASN1_CHOICE_END(ECPKPARAMETERS)

DECLARE_YASN1_FUNCTIONS_const(ECPKPARAMETERS)
DECLARE_YASN1_ENCODE_FUNCTIONS_const(ECPKPARAMETERS, ECPKPARAMETERS)
IMPLEMENT_YASN1_FUNCTIONS_const(ECPKPARAMETERS)

YASN1_SEQUENCE(EC_PRIVATEKEY) = {
        YASN1_EMBED(EC_PRIVATEKEY, version, INT32),
        YASN1_SIMPLE(EC_PRIVATEKEY, privateKey, YASN1_OCTET_STRING),
        YASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
        YASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, YASN1_BIT_STRING, 1)
} static_YASN1_SEQUENCE_END(EC_PRIVATEKEY)

DECLARE_YASN1_FUNCTIONS_const(EC_PRIVATEKEY)
DECLARE_YASN1_ENCODE_FUNCTIONS_const(EC_PRIVATEKEY, EC_PRIVATEKEY)
IMPLEMENT_YASN1_FUNCTIONS_const(EC_PRIVATEKEY)

/* some declarations of internal function */

/* ec_asn1_group2field() sets the values in a X9_62_FIELDID object */
static int ec_asn1_group2fieldid(const ECC_GROUP *, X9_62_FIELDID *);
/* ec_asn1_group2curve() sets the values in a X9_62_CURVE object */
static int ec_asn1_group2curve(const ECC_GROUP *, X9_62_CURVE *);

/* the function definitions */

static int ec_asn1_group2fieldid(const ECC_GROUP *group, X9_62_FIELDID *field)
{
    int ok = 0, nid;
    BIGNUM *tmp = NULL;

    if (group == NULL || field == NULL)
        return 0;

    /* clear the old values (if necessary) */
    YASN1_OBJECT_free(field->fieldType);
    YASN1_TYPE_free(field->p.other);

    nid = EC_METHOD_get_field_type(ECC_GROUP_method_of(group));
    /* set OID for the field */
    if ((field->fieldType = OBJ_nid2obj(nid)) == NULL) {
        ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_OBJ_LIB);
        goto err;
    }

    if (nid == NID_X9_62_prime_field) {
        if ((tmp = BNY_new()) == NULL) {
            ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        /* the parameters are specified by the prime number p */
        if (!ECC_GROUP_get_curve(group, tmp, NULL, NULL, NULL)) {
            ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_EC_LIB);
            goto err;
        }
        /* set the prime number */
        field->p.prime = BN_to_YASN1_INTEGER(tmp, NULL);
        if (field->p.prime == NULL) {
            ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_YASN1_LIB);
            goto err;
        }
    } else if (nid == NID_X9_62_characteristic_two_field)
#ifdef OPENSSL_NO_EC2M
    {
        ECerr(EC_F_EC_YASN1_GROUP2FIELDID, EC_R_GF2M_NOT_SUPPORTED);
        goto err;
    }
#else
    {
        int field_type;
        X9_62_CHARACTERISTIC_TWO *char_two;

        field->p.char_two = X9_62_CHARACTERISTIC_TWO_new();
        char_two = field->p.char_two;

        if (char_two == NULL) {
            ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        char_two->m = (long)ECC_GROUP_get_degree(group);

        field_type = ECC_GROUP_get_basis_type(group);

        if (field_type == 0) {
            ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_EC_LIB);
            goto err;
        }
        /* set base type OID */
        if ((char_two->type = OBJ_nid2obj(field_type)) == NULL) {
            ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_OBJ_LIB);
            goto err;
        }

        if (field_type == NID_X9_62_tpBasis) {
            unsigned int k;

            if (!ECC_GROUP_get_trinomial_basis(group, &k))
                goto err;

            char_two->p.tpBasis = YASN1_INTEGER_new();
            if (char_two->p.tpBasis == NULL) {
                ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!YASN1_INTEGER_set(char_two->p.tpBasis, (long)k)) {
                ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_YASN1_LIB);
                goto err;
            }
        } else if (field_type == NID_X9_62_ppBasis) {
            unsigned int k1, k2, k3;

            if (!ECC_GROUP_get_pentanomial_basis(group, &k1, &k2, &k3))
                goto err;

            char_two->p.ppBasis = X9_62_PENTANOMIAL_new();
            if (char_two->p.ppBasis == NULL) {
                ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            /* set k? values */
            char_two->p.ppBasis->k1 = (long)k1;
            char_two->p.ppBasis->k2 = (long)k2;
            char_two->p.ppBasis->k3 = (long)k3;
        } else {                /* field_type == NID_X9_62_onBasis */

            /* for ONB the parameters are (asn1) NULL */
            char_two->p.onBasis = YASN1_NULL_new();
            if (char_two->p.onBasis == NULL) {
                ECerr(EC_F_EC_YASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
    }
#endif
    else {
        ECerr(EC_F_EC_YASN1_GROUP2FIELDID, EC_R_UNSUPPORTED_FIELD);
        goto err;
    }

    ok = 1;

 err:
    BN_free(tmp);
    return ok;
}

static int ec_asn1_group2curve(const ECC_GROUP *group, X9_62_CURVE *curve)
{
    int ok = 0;
    BIGNUM *tmp_1 = NULL, *tmp_2 = NULL;
    unsigned char *a_buf = NULL, *b_buf = NULL;
    size_t len;

    if (!group || !curve || !curve->a || !curve->b)
        return 0;

    if ((tmp_1 = BNY_new()) == NULL || (tmp_2 = BNY_new()) == NULL) {
        ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* get a and b */
    if (!ECC_GROUP_get_curve(group, NULL, tmp_1, tmp_2, NULL)) {
        ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_EC_LIB);
        goto err;
    }

    /*
     * Per SEC 1, the curve coefficients must be padded up to size. See C.2's
     * definition of Curve, C.1's definition of FieldElement, and 2.3.5's
     * definition of how to encode the field elements.
     */
    len = ((size_t)ECC_GROUP_get_degree(group) + 7) / 8;
    if ((a_buf = OPENSSL_malloc(len)) == NULL
        || (b_buf = OPENSSL_malloc(len)) == NULL) {
        ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (BNY_bn2binpad(tmp_1, a_buf, len) < 0
        || BNY_bn2binpad(tmp_2, b_buf, len) < 0) {
        ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_BN_LIB);
        goto err;
    }

    /* set a and b */
    if (!YASN1_OCTET_STRING_set(curve->a, a_buf, len)
        || !YASN1_OCTET_STRING_set(curve->b, b_buf, len)) {
        ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_YASN1_LIB);
        goto err;
    }

    /* set the seed (optional) */
    if (group->seed) {
        if (!curve->seed)
            if ((curve->seed = YASN1_BIT_STRING_new()) == NULL) {
                ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        curve->seed->flags &= ~(YASN1_STRING_FLAG_BITS_LEFT | 0x07);
        curve->seed->flags |= YASN1_STRING_FLAG_BITS_LEFT;
        if (!YASN1_BIT_STRING_set(curve->seed, group->seed,
                                 (int)group->seed_len)) {
            ECerr(EC_F_EC_YASN1_GROUP2CURVE, ERR_R_YASN1_LIB);
            goto err;
        }
    } else {
        YASN1_BIT_STRING_free(curve->seed);
        curve->seed = NULL;
    }

    ok = 1;

 err:
    OPENSSL_free(a_buf);
    OPENSSL_free(b_buf);
    BN_free(tmp_1);
    BN_free(tmp_2);
    return ok;
}

ECPARAMETERS *ECC_GROUP_get_ecparameters(const ECC_GROUP *group,
                                               ECPARAMETERS *params)
{
    size_t len = 0;
    ECPARAMETERS *ret = NULL;
    const BIGNUM *tmp;
    unsigned char *buffer = NULL;
    const EC_POINTT *point = NULL;
    point_conversion_form_t form;
    YASN1_INTEGER *orig;

    if (params == NULL) {
        if ((ret = ECPARAMETERS_new()) == NULL) {
            ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = params;

    /* set the version (always one) */
    ret->version = (long)0x1;

    /* set the fieldID */
    if (!ec_asn1_group2fieldid(group, ret->fieldID)) {
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /* set the curve */
    if (!ec_asn1_group2curve(group, ret->curve)) {
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /* set the base point */
    if ((point = ECC_GROUP_get0_generator(group)) == NULL) {
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

    form = ECC_GROUP_get_point_conversion_form(group);

    len = EC_POINTT_point2buf(group, point, form, &buffer, NULL);
    if (len == 0) {
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }
    if (ret->base == NULL && (ret->base = YASN1_OCTET_STRING_new()) == NULL) {
        OPENSSL_free(buffer);
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    YASN1_STRING_set0(ret->base, buffer, len);

    /* set the order */
    tmp = ECC_GROUP_get0_order(group);
    if (tmp == NULL) {
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }
    ret->order = BN_to_YASN1_INTEGER(tmp, orig = ret->order);
    if (ret->order == NULL) {
        ret->order = orig;
        ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_YASN1_LIB);
        goto err;
    }

    /* set the cofactor (optional) */
    tmp = ECC_GROUP_get0_cofactor(group);
    if (tmp != NULL) {
        ret->cofactor = BN_to_YASN1_INTEGER(tmp, orig = ret->cofactor);
        if (ret->cofactor == NULL) {
            ret->cofactor = orig;
            ECerr(EC_F_ECC_GROUP_GET_ECPARAMETERS, ERR_R_YASN1_LIB);
            goto err;
        }
    }

    return ret;

 err:
    if (params == NULL)
        ECPARAMETERS_free(ret);
    return NULL;
}

ECPKPARAMETERS *ECC_GROUP_get_ecpkparameters(const ECC_GROUP *group,
                                            ECPKPARAMETERS *params)
{
    int ok = 1, tmp;
    ECPKPARAMETERS *ret = params;

    if (ret == NULL) {
        if ((ret = ECPKPARAMETERS_new()) == NULL) {
            ECerr(EC_F_ECC_GROUP_GET_ECPKPARAMETERS, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else {
        if (ret->type == ECPKPARAMETERS_TYPE_NAMED)
            YASN1_OBJECT_free(ret->value.named_curve);
        else if (ret->type == ECPKPARAMETERS_TYPE_EXPLICIT
                 && ret->value.parameters != NULL)
            ECPARAMETERS_free(ret->value.parameters);
    }

    if (ECC_GROUP_get_asn1_flag(group) == OPENSSL_EC_NAMED_CURVE) {
        /*
         * use the asn1 OID to describe the elliptic curve parameters
         */
        tmp = ECC_GROUP_get_curve_name(group);
        if (tmp) {
            YASN1_OBJECT *asn1obj = OBJ_nid2obj(tmp);

            if (asn1obj == NULL || OBJ_length(asn1obj) == 0) {
                YASN1_OBJECT_free(asn1obj);
                ECerr(EC_F_ECC_GROUP_GET_ECPKPARAMETERS, EC_R_MISSING_OID);
                ok = 0;
            } else {
                ret->type = ECPKPARAMETERS_TYPE_NAMED;
                ret->value.named_curve = asn1obj;
            }
        } else
            /* we don't know the nid => ERROR */
            ok = 0;
    } else {
        /* use the ECPARAMETERS structure */
        ret->type = ECPKPARAMETERS_TYPE_EXPLICIT;
        if ((ret->value.parameters =
             ECC_GROUP_get_ecparameters(group, NULL)) == NULL)
            ok = 0;
    }

    if (!ok) {
        ECPKPARAMETERS_free(ret);
        return NULL;
    }
    return ret;
}

ECC_GROUP *ECC_GROUP_new_from_ecparameters(const ECPARAMETERS *params)
{
    int ok = 0, tmp;
    ECC_GROUP *ret = NULL, *dup = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_POINTT *point = NULL;
    long field_bits;
    int curve_name = NID_undef;
    BN_CTX *ctx = NULL;

    if (!params->fieldID || !params->fieldID->fieldType ||
        !params->fieldID->p.ptr) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
        goto err;
    }

    /*
     * Now extract the curve parameters a and b. Note that, although SEC 1
     * specifies the length of their encodings, historical versions of OpenSSL
     * encoded them incorrectly, so we must accept any length for backwards
     * compatibility.
     */
    if (!params->curve || !params->curve->a ||
        !params->curve->a->data || !params->curve->b ||
        !params->curve->b->data) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
        goto err;
    }
    a = BNY_bin2bn(params->curve->a->data, params->curve->a->length, NULL);
    if (a == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_BN_LIB);
        goto err;
    }
    b = BNY_bin2bn(params->curve->b->data, params->curve->b->length, NULL);
    if (b == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_BN_LIB);
        goto err;
    }

    /* get the field parameters */
    tmp = OBJ_obj2nid(params->fieldID->fieldType);
    if (tmp == NID_X9_62_characteristic_two_field)
#ifdef OPENSSL_NO_EC2M
    {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_GF2M_NOT_SUPPORTED);
        goto err;
    }
#else
    {
        X9_62_CHARACTERISTIC_TWO *char_two;

        char_two = params->fieldID->p.char_two;

        field_bits = char_two->m;
        if (field_bits > OPENSSL_ECC_MAX_FIELD_BITS) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_FIELD_TOO_LARGE);
            goto err;
        }

        if ((p = BNY_new()) == NULL) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* get the base type */
        tmp = OBJ_obj2nid(char_two->type);

        if (tmp == NID_X9_62_tpBasis) {
            long tmp_long;

            if (!char_two->p.tpBasis) {
                ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
                goto err;
            }

            tmp_long = YASN1_INTEGER_get(char_two->p.tpBasis);

            if (!(char_two->m > tmp_long && tmp_long > 0)) {
                ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS,
                      EC_R_INVALID_TRINOMIAL_BASIS);
                goto err;
            }

            /* create the polynomial */
            if (!BN_set_bit(p, (int)char_two->m))
                goto err;
            if (!BN_set_bit(p, (int)tmp_long))
                goto err;
            if (!BN_set_bit(p, 0))
                goto err;
        } else if (tmp == NID_X9_62_ppBasis) {
            X9_62_PENTANOMIAL *penta;

            penta = char_two->p.ppBasis;
            if (!penta) {
                ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
                goto err;
            }

            if (!
                (char_two->m > penta->k3 && penta->k3 > penta->k2
                 && penta->k2 > penta->k1 && penta->k1 > 0)) {
                ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS,
                      EC_R_INVALID_PENTANOMIAL_BASIS);
                goto err;
            }

            /* create the polynomial */
            if (!BN_set_bit(p, (int)char_two->m))
                goto err;
            if (!BN_set_bit(p, (int)penta->k1))
                goto err;
            if (!BN_set_bit(p, (int)penta->k2))
                goto err;
            if (!BN_set_bit(p, (int)penta->k3))
                goto err;
            if (!BN_set_bit(p, 0))
                goto err;
        } else if (tmp == NID_X9_62_onBasis) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_NOT_IMPLEMENTED);
            goto err;
        } else {                /* error */

            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
            goto err;
        }

        /* create the ECC_GROUP structure */
        ret = ECC_GROUP_new_curves_GF2m(p, a, b, NULL);
    }
#endif
    else if (tmp == NID_X9_62_prime_field) {
        /* we have a curve over a prime field */
        /* extract the prime number */
        if (!params->fieldID->p.prime) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
            goto err;
        }
        p = YASN1_INTEGER_to_BN(params->fieldID->p.prime, NULL);
        if (p == NULL) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_YASN1_LIB);
            goto err;
        }

        if (BN_is_negative(p) || BN_is_zero(p)) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_INVALID_FIELD);
            goto err;
        }

        field_bits = BNY_num_bits(p);
        if (field_bits > OPENSSL_ECC_MAX_FIELD_BITS) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_FIELD_TOO_LARGE);
            goto err;
        }

        /* create the ECC_GROUP structure */
        ret = ECC_GROUP_new_curves_GFp(p, a, b, NULL);
    } else {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_INVALID_FIELD);
        goto err;
    }

    if (ret == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /* extract seed (optional) */
    if (params->curve->seed != NULL) {
        /*
         * This happens for instance with
         * fuzz/corpora/asn1/65cf44e85614c62f10cf3b7a7184c26293a19e4a
         * and causes the OPENSSL_malloc below to choke on the
         * zero length allocation request.
         */
        if (params->curve->seed->length == 0) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
            goto err;
        }
        OPENSSL_free(ret->seed);
        if ((ret->seed = OPENSSL_malloc(params->curve->seed->length)) == NULL) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(ret->seed, params->curve->seed->data,
               params->curve->seed->length);
        ret->seed_len = params->curve->seed->length;
    }

    if (params->order == NULL
            || params->base == NULL
            || params->base->data == NULL
            || params->base->length == 0) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_YASN1_ERROR);
        goto err;
    }

    if ((point = EC_POINTT_new(ret)) == NULL)
        goto err;

    /* set the point conversion form */
    ECC_GROUP_set_point_conversion_form(ret, (point_conversion_form_t)
                                       (params->base->data[0] & ~0x01));

    /* extract the ec point */
    if (!EC_POINTT_oct2point(ret, point, params->base->data,
                            params->base->length, NULL)) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /* extract the order */
    if (YASN1_INTEGER_to_BN(params->order, a) == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_YASN1_LIB);
        goto err;
    }
    if (BN_is_negative(a) || BN_is_zero(a)) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    if (BNY_num_bits(a) > (int)field_bits + 1) { /* Hasse bound */
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }

    /* extract the cofactor (optional) */
    if (params->cofactor == NULL) {
        BN_free(b);
        b = NULL;
    } else if (YASN1_INTEGER_to_BN(params->cofactor, b) == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_YASN1_LIB);
        goto err;
    }
    /* set the generator, order and cofactor (if present) */
    if (!ECC_GROUP_set_generator(ret, point, a, b)) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }

    /*
     * Check if the explicit parameters group just created matches one of the
     * built-in curves.
     *
     * We create a copy of the group just built, so that we can remove optional
     * fields for the lookup: we do this to avoid the possibility that one of
     * the optional parameters is used to force the library into using a less
     * performant and less secure EC_METHOD instead of the specialized one.
     * In any case, `seed` is not really used in any computation, while a
     * cofactor different from the one in the built-in table is just
     * mathematically wrong anyway and should not be used.
     */
    if ((ctx = BNY_CTX_new()) == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_BN_LIB);
        goto err;
    }
    if ((dup = ECC_GROUP_dup(ret)) == NULL
            || ECC_GROUP_set_seed(dup, NULL, 0) != 1
            || !ECC_GROUP_set_generator(dup, point, a, NULL)) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_EC_LIB);
        goto err;
    }
    if ((curve_name = ec_curve_nid_from_params(dup, ctx)) != NID_undef) {
        /*
         * The input explicit parameters successfully matched one of the
         * built-in curves: often for built-in curves we have specialized
         * methods with better performance and hardening.
         *
         * In this case we replace the `ECC_GROUP` created through explicit
         * parameters with one created from a named group.
         */
        ECC_GROUP *named_group = NULL;

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
        /*
         * NID_wap_wsg_idm_ecid_wtls12 and NID_secp224r1 are both aliases for
         * the same curve, we prefer the SECP nid when matching explicit
         * parameters as that is associated with a specialized EC_METHOD.
         */
        if (curve_name == NID_wap_wsg_idm_ecid_wtls12)
            curve_name = NID_secp224r1;
#endif /* !def(OPENSSL_NO_EC_NISTP_64_GCC_128) */

        if ((named_group = ECC_GROUP_new_by_curve_mame(curve_name)) == NULL) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPARAMETERS, ERR_R_EC_LIB);
            goto err;
        }
        ECC_GROUP_free(ret);
        ret = named_group;

        /*
         * Set the flag so that ECC_GROUPs created from explicit parameters are
         * serialized using explicit parameters by default.
         */
        ECC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE);

        /*
         * If the input params do not contain the optional seed field we make
         * sure it is not added to the returned group.
         *
         * The seed field is not really used inside libcrypto anyway, and
         * adding it to parsed explicit parameter keys would alter their DER
         * encoding output (because of the extra field) which could impact
         * applications fingerprinting keys by their DER encoding.
         */
        if (params->curve->seed == NULL) {
            if (ECC_GROUP_set_seed(ret, NULL, 0) != 1)
                goto err;
        }
    }

    ok = 1;

 err:
    if (!ok) {
        ECC_GROUP_free(ret);
        ret = NULL;
    }
    ECC_GROUP_free(dup);

    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_POINTT_free(point);

    BNY_CTX_free(ctx);

    return ret;
}

ECC_GROUP *ECC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS *params)
{
    ECC_GROUP *ret = NULL;
    int tmp = 0;

    if (params == NULL) {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPKPARAMETERS, EC_R_MISSING_PARAMETERS);
        return NULL;
    }

    if (params->type == ECPKPARAMETERS_TYPE_NAMED) {
        /* the curve is given by an OID */
        tmp = OBJ_obj2nid(params->value.named_curve);
        if ((ret = ECC_GROUP_new_by_curve_mame(tmp)) == NULL) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPKPARAMETERS,
                  EC_R_ECC_GROUP_NEW_BY_NAME_FAILURE);
            return NULL;
        }
        ECC_GROUP_set_asn1_flag(ret, OPENSSL_EC_NAMED_CURVE);
    } else if (params->type == ECPKPARAMETERS_TYPE_EXPLICIT) {
        /* the parameters are given by an ECPARAMETERS structure */
        ret = ECC_GROUP_new_from_ecparameters(params->value.parameters);
        if (!ret) {
            ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPKPARAMETERS, ERR_R_EC_LIB);
            return NULL;
        }
        ECC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE);
    } else if (params->type == ECPKPARAMETERS_TYPE_IMPLICIT) {
        /* implicit parameters inherited from CA - unsupported */
        return NULL;
    } else {
        ECerr(EC_F_ECC_GROUP_NEW_FROM_ECPKPARAMETERS, EC_R_YASN1_ERROR);
        return NULL;
    }

    return ret;
}

/* ECC_GROUP <-> DER encoding of ECPKPARAMETERS */

ECC_GROUP *d2i_ECPKParameters(ECC_GROUP **a, const unsigned char **in, long len)
{
    ECC_GROUP *group = NULL;
    ECPKPARAMETERS *params = NULL;
    const unsigned char *p = *in;

    if ((params = d2i_ECPKPARAMETERS(NULL, &p, len)) == NULL) {
        ECerr(EC_F_D2I_ECPKPARAMETERS, EC_R_D2I_ECPKPARAMETERS_FAILURE);
        ECPKPARAMETERS_free(params);
        return NULL;
    }

    if ((group = ECC_GROUP_new_from_ecpkparameters(params)) == NULL) {
        ECerr(EC_F_D2I_ECPKPARAMETERS, EC_R_PKPARAMETERS2GROUP_FAILURE);
        ECPKPARAMETERS_free(params);
        return NULL;
    }

    if (params->type == ECPKPARAMETERS_TYPE_EXPLICIT)
        group->decoded_from_explicit_params = 1;

    if (a) {
        ECC_GROUP_free(*a);
        *a = group;
    }

    ECPKPARAMETERS_free(params);
    *in = p;
    return group;
}

int i2d_ECPKParameters(const ECC_GROUP *a, unsigned char **out)
{
    int ret = 0;
    ECPKPARAMETERS *tmp = ECC_GROUP_get_ecpkparameters(a, NULL);
    if (tmp == NULL) {
        ECerr(EC_F_I2D_ECPKPARAMETERS, EC_R_GROUP2PKPARAMETERS_FAILURE);
        return 0;
    }
    if ((ret = i2d_ECPKPARAMETERS(tmp, out)) == 0) {
        ECerr(EC_F_I2D_ECPKPARAMETERS, EC_R_I2D_ECPKPARAMETERS_FAILURE);
        ECPKPARAMETERS_free(tmp);
        return 0;
    }
    ECPKPARAMETERS_free(tmp);
    return ret;
}

/* some EC_KEY functions */

EC_KEY *d2i_ECCPrivateKey(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret = NULL;
    EC_PRIVATEKEY *priv_key = NULL;
    const unsigned char *p = *in;

    if ((priv_key = d2i_EC_PRIVATEKEY(NULL, &p, len)) == NULL) {
        ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = ECC_KEY_new()) == NULL) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        ret = *a;

    if (priv_key->parameters) {
        ECC_GROUP_free(ret->group);
        ret->group = ECC_GROUP_new_from_ecpkparameters(priv_key->parameters);
        if (ret->group != NULL
            && priv_key->parameters->type == ECPKPARAMETERS_TYPE_EXPLICIT)
            ret->group->decoded_from_explicit_params = 1;
    }

    if (ret->group == NULL) {
        ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }

    ret->version = priv_key->version;

    if (priv_key->privateKey) {
        YASN1_OCTET_STRING *pkey = priv_key->privateKey;
        if (ECC_KEY_oct2priv(ret, YASN1_STRING_get0_data(pkey),
                            YASN1_STRING_length(pkey)) == 0)
            goto err;
    } else {
        ECerr(EC_F_D2I_ECPRIVATEKEY, EC_R_MISSING_PRIVATE_KEY);
        goto err;
    }

    EC_POINTT_clear_free(ret->pub_key);
    ret->pub_key = EC_POINTT_new(ret->group);
    if (ret->pub_key == NULL) {
        ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }

    if (priv_key->publicKey) {
        const unsigned char *pub_oct;
        int pub_oct_len;

        pub_oct = YASN1_STRING_get0_data(priv_key->publicKey);
        pub_oct_len = YASN1_STRING_length(priv_key->publicKey);
        if (!ECC_KEY_oct2key(ret, pub_oct, pub_oct_len, NULL)) {
            ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }
    } else {
        if (ret->group->meth->keygenpub == NULL
            || ret->group->meth->keygenpub(ret) == 0)
                goto err;
        /* Remember the original private-key-only encoding. */
        ret->enc_flag |= EC_PKEY_NO_PUBKEY;
    }

    if (a)
        *a = ret;
    EC_PRIVATEKEY_free(priv_key);
    *in = p;
    return ret;

 err:
    if (a == NULL || *a != ret)
        EC_KEY_free(ret);
    EC_PRIVATEKEY_free(priv_key);
    return NULL;
}

int i2d_ECPrivateKey(EC_KEY *a, unsigned char **out)
{
    int ret = 0, ok = 0;
    unsigned char *priv= NULL, *pub= NULL;
    size_t privlen = 0, publen = 0;

    EC_PRIVATEKEY *priv_key = NULL;

    if (a == NULL || a->group == NULL ||
        (!(a->enc_flag & EC_PKEY_NO_PUBKEY) && a->pub_key == NULL)) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((priv_key = EC_PRIVATEKEY_new()) == NULL) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key->version = a->version;

    privlen = ECC_KEY_priv2buf(a, &priv);

    if (privlen == 0) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }

    YASN1_STRING_set0(priv_key->privateKey, priv, privlen);
    priv = NULL;

    if (!(a->enc_flag & EC_PKEY_NO_PARAMETERS)) {
        if ((priv_key->parameters =
             ECC_GROUP_get_ecpkparameters(a->group,
                                        priv_key->parameters)) == NULL) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }
    }

    if (!(a->enc_flag & EC_PKEY_NO_PUBKEY)) {
        priv_key->publicKey = YASN1_BIT_STRING_new();
        if (priv_key->publicKey == NULL) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        publen = ECC_KEY_key2buf(a, a->conv_form, &pub, NULL);

        if (publen == 0) {
            ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
            goto err;
        }

        priv_key->publicKey->flags &= ~(YASN1_STRING_FLAG_BITS_LEFT | 0x07);
        priv_key->publicKey->flags |= YASN1_STRING_FLAG_BITS_LEFT;
        YASN1_STRING_set0(priv_key->publicKey, pub, publen);
        pub = NULL;
    }

    if ((ret = i2d_EC_PRIVATEKEY(priv_key, out)) == 0) {
        ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
        goto err;
    }
    ok = 1;
 err:
    OPENSSL_clear_free(priv, privlen);
    OPENSSL_free(pub);
    EC_PRIVATEKEY_free(priv_key);
    return (ok ? ret : 0);
}

int i2d_ECCParameters(EC_KEY *a, unsigned char **out)
{
    if (a == NULL) {
        ECerr(EC_F_I2D_ECPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return i2d_ECPKParameters(a->group, out);
}

EC_KEY *d2i_ECCParameters(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret;

    if (in == NULL || *in == NULL) {
        ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (a == NULL || *a == NULL) {
        if ((ret = ECC_KEY_new()) == NULL) {
            ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else
        ret = *a;

    if (!d2i_ECPKParameters(&ret->group, in, len)) {
        ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_EC_LIB);
        if (a == NULL || *a != ret)
             EC_KEY_free(ret);
        return NULL;
    }

    if (a)
        *a = ret;

    return ret;
}

EC_KEY *o2i_ECCPublicKey(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret = NULL;

    if (a == NULL || (*a) == NULL || (*a)->group == NULL) {
        /*
         * sorry, but a ECC_GROUP-structure is necessary to set the public key
         */
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ret = *a;
    if (!ECC_KEY_oct2key(ret, *in, len, NULL)) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_EC_LIB);
        return 0;
    }
    *in += len;
    return ret;
}

int i2o_ECCPublicKey(const EC_KEY *a, unsigned char **out)
{
    size_t buf_len = 0;
    int new_buffer = 0;

    if (a == NULL) {
        ECerr(EC_F_I2O_ECPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    buf_len = EC_POINTT_point2oct(a->group, a->pub_key,
                                 a->conv_form, NULL, 0, NULL);

    if (out == NULL || buf_len == 0)
        /* out == NULL => just return the length of the octet string */
        return buf_len;

    if (*out == NULL) {
        if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
            ECerr(EC_F_I2O_ECPUBLICKEY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        new_buffer = 1;
    }
    if (!EC_POINTT_point2oct(a->group, a->pub_key, a->conv_form,
                            *out, buf_len, NULL)) {
        ECerr(EC_F_I2O_ECPUBLICKEY, ERR_R_EC_LIB);
        if (new_buffer) {
            OPENSSL_free(*out);
            *out = NULL;
        }
        return 0;
    }
    if (!new_buffer)
        *out += buf_len;
    return buf_len;
}

YASN1_SEQUENCE(ECDSA_SIG) = {
        YASN1_SIMPLE(ECDSA_SIG, r, CBIGNUM),
        YASN1_SIMPLE(ECDSA_SIG, s, CBIGNUM)
} static_YASN1_SEQUENCE_END(ECDSA_SIG)

DECLARE_YASN1_FUNCTIONS_const(ECDSA_SIG)
DECLARE_YASN1_ENCODE_FUNCTIONS_const(ECDSA_SIG, ECDSA_SIG)
IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(ECDSA_SIG, ECDSA_SIG, ECDSA_SIG)

ECDSA_SIG *ECCDSA_SIG_new(void)
{
    ECDSA_SIG *sig = OPENSSL_zalloc(sizeof(*sig));
    if (sig == NULL)
        ECerr(EC_F_ECDSA_SIG_NEW, ERR_R_MALLOC_FAILURE);
    return sig;
}

void ECDSA_SIG_free(ECDSA_SIG *sig)
{
    if (sig == NULL)
        return;
    BNY_clear_free(sig->r);
    BNY_clear_free(sig->s);
    OPENSSL_free(sig);
}

void ECCDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

const BIGNUM *ECCDSA_SIG_get0_r(const ECDSA_SIG *sig)
{
    return sig->r;
}

const BIGNUM *ECCDSA_SIG_get0_s(const ECDSA_SIG *sig)
{
    return sig->s;
}

int ECCDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BNY_clear_free(sig->r);
    BNY_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

int ECCDSA_size(const EC_KEY *r)
{
    int ret, i;
    YASN1_INTEGER bs;
    unsigned char buf[4];
    const ECC_GROUP *group;

    if (r == NULL)
        return 0;
    group = ECC_KEY_get0_group(r);
    if (group == NULL)
        return 0;

    i = ECC_GROUP_order_bits(group);
    if (i == 0)
        return 0;
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_YASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_YASN1_INTEGER(&bs, NULL);
    i += i;                     /* r and s */
    ret = YASN1_object_size(1, i, V_YASN1_SEQUENCE);
    if (ret < 0)
        return 0;
    return ret;
}
