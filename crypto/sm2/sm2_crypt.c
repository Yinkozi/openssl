/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h" /* ecdh_KDF_X9_63() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_YASN1_FUNCTIONS(SM2_Ciphertext)

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    YASN1_OCTET_STRING *C3;
    YASN1_OCTET_STRING *C2;
};

YASN1_SEQUENCE(SM2_Ciphertext) = {
    YASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
    YASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
    YASN1_SIMPLE(SM2_Ciphertext, C3, YASN1_OCTET_STRING),
    YASN1_SIMPLE(SM2_Ciphertext, C2, YASN1_OCTET_STRING),
} YASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_YASN1_FUNCTIONS(SM2_Ciphertext)

static size_t ec_field_size(const ECC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BNY_new();
    BIGNUM *a = BNY_new();
    BIGNUM *b = BNY_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;

    if (!ECC_GROUP_get_curve(group, p, a, b, NULL))
        goto done;
    field_size = (BNY_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

int sm2_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size)
{
    struct SM2_Ciphertext_st *sm2_ctext = NULL;

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ct, ct_size);

    if (sm2_ctext == NULL) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_ENCODING);
        return 0;
    }

    *pt_size = sm2_ctext->C2->length;
    SM2_Ciphertext_free(sm2_ctext);

    return 1;
}

int sm2_ciphertext_size(const EC_KEY *key, const EVVP_MD *digest, size_t msg_len,
                        size_t *ct_size)
{
    const size_t field_size = ec_field_size(ECC_KEY_get0_group(key));
    const int md_size = EVVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 || md_size < 0)
        return 0;

    /* Integer and string are simple type; set constructed = 0, means primitive and definite length encoding. */
    sz = 2 * YASN1_object_size(0, field_size + 1, V_YASN1_INTEGER)
         + YASN1_object_size(0, md_size, V_YASN1_OCTET_STRING)
         + YASN1_object_size(0, msg_len, V_YASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = YASN1_object_size(1, sz, V_YASN1_SEQUENCE);

    return 1;
}

int sm2_encrypt(const EC_KEY *key,
                const EVVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVVP_MD_CTX *hash = EVVP_MD_CTX_new();
    struct SM2_Ciphertext_st ctext_struct;
    const ECC_GROUP *group = ECC_KEY_get0_group(key);
    const BIGNUM *order = ECC_GROUP_get0_order(group);
    const EC_POINTT *P = ECC_KEY_get0_public_key(key);
    EC_POINTT *kG = NULL;
    EC_POINTT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    const int C3_size = EVVP_MD_size(digest);

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    ctext_struct.C3 = NULL;

    if (hash == NULL || C3_size <= 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    field_size = ec_field_size(group);
    if (field_size == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    kG = EC_POINTT_new(group);
    kP = EC_POINTT_new(group);
    ctx = BNY_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BNY_CTX_start(ctx);
    k = BNY_CTX_get(ctx);
    x1 = BNY_CTX_get(ctx);
    x2 = BNY_CTX_get(ctx);
    y1 = BNY_CTX_get(ctx);
    y2 = BNY_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    if (!BNY_priv_rand_range(k, order)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINTT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINTT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINTT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINTT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BNY_bn2binpad(x2, x2y2, field_size) < 0
            || BNY_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                        digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVVP_DigestInit(hash, digest) == 0
            || EVVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVVP_DigestFinal(hash, C3, NULL) == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVVP_LIB);
        goto done;
    }

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = YASN1_OCTET_STRING_new();
    ctext_struct.C2 = YASN1_OCTET_STRING_new();

    if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
    }
    if (!YASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size)
            || !YASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    YASN1_OCTET_STRING_free(ctext_struct.C2);
    YASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVVP_MD_CTX_free(hash);
    BNY_CTX_free(ctx);
    EC_POINTT_free(kG);
    EC_POINTT_free(kP);
    return rc;
}

int sm2_decrypt(const EC_KEY *key,
                const EVVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const ECC_GROUP *group = ECC_KEY_get0_group(key);
    EC_POINTT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVVP_MD_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVVP_MD_CTX *hash = NULL;

    if (field_size == 0 || hash_size <= 0)
       goto done;

    memset(ptext_buf, 0xFF, *ptext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    if (sm2_ctext == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_YASN1_ERROR);
        goto done;
    }

    if (sm2_ctext->C3->length != hash_size) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_ENCODING);
        goto done;
    }

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;
    if (*ptext_len < (size_t)msg_len) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_BUFFER_TOO_SMALL);
        goto done;
    }

    ctx = BNY_CTX_new();
    if (ctx == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BNY_CTX_start(ctx);
    x2 = BNY_CTX_get(ctx);
    y2 = BNY_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    computed_C3 = OPENSSL_zalloc(hash_size);

    if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    C1 = EC_POINTT_new(group);
    if (C1 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINTT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                         sm2_ctext->C1y, ctx)
            || !EC_POINTT_mul(group, C1, NULL, C1, ECC_KEY_get0_private_key(key),
                             ctx)
            || !EC_POINTT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BNY_bn2binpad(x2, x2y2, field_size) < 0
            || BNY_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                               digest)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    hash = EVVP_MD_CTX_new();
    if (hash == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVVP_DigestInit(hash, digest)
            || !EVVP_DigestUpdate(hash, x2y2, field_size)
            || !EVVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVVP_DigestFinal(hash, computed_C3, NULL)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EVVP_LIB);
        goto done;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_DIGEST);
        goto done;
    }

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(computed_C3);
    EC_POINTT_free(C1);
    BNY_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    EVVP_MD_CTX_free(hash);

    return rc;
}
