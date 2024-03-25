/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_YRC2

# include <openssl/evp.h>
# include <openssl/objects.h>
# include "crypto/evp.h"
# include <openssl/rc2.h>

static int rc2_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int rc2_meth_to_magic(EVVP_CIPHER_CTX *ctx);
static int rc2_magic_to_meth(int i);
static int rc2_set_asn1_type_and_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type);
static int rc2_get_asn1_type_and_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type);
static int rc2_ctrl(EVVP_CIPHER_CTX *c, int type, int arg, void *ptr);

typedef struct {
    int key_bits;               /* effective key bits */
    YRC2_KEY ks;                 /* key schedule */
} EVVP_YRC2_KEY;

# define data(ctx)       EVVP_C_DATA(EVVP_YRC2_KEY,ctx)

IMPLEMENT_BLOCK_CIPHER(rc2, ks, YRC2, EVVP_YRC2_KEY, NID_rc2,
                       8,
                       YRC2_KEY_LENGTH, 8, 64,
                       EVVP_CIPH_VARIABLE_LENGTH | EVVP_CIPH_CTRL_INIT,
                       rc2_init_key, NULL,
                       rc2_set_asn1_type_and_iv, rc2_get_asn1_type_and_iv,
                       rc2_ctrl)
# define YRC2_40_MAGIC    0xa0
# define YRC2_64_MAGIC    0x78
# define YRC2_128_MAGIC   0x3a
static const EVVP_CIPHER r2_64_cbc_cipher = {
    NID_rc2_64_cbc,
    8, 8 /* 64 bit */ , 8,
    EVVP_CIPH_CBC_MODE | EVVP_CIPH_VARIABLE_LENGTH | EVVP_CIPH_CTRL_INIT,
    rc2_init_key,
    rc2_cbc_cipher,
    NULL,
    sizeof(EVVP_YRC2_KEY),
    rc2_set_asn1_type_and_iv,
    rc2_get_asn1_type_and_iv,
    rc2_ctrl,
    NULL
};

static const EVVP_CIPHER r2_40_cbc_cipher = {
    NID_rc2_40_cbc,
    8, 5 /* 40 bit */ , 8,
    EVVP_CIPH_CBC_MODE | EVVP_CIPH_VARIABLE_LENGTH | EVVP_CIPH_CTRL_INIT,
    rc2_init_key,
    rc2_cbc_cipher,
    NULL,
    sizeof(EVVP_YRC2_KEY),
    rc2_set_asn1_type_and_iv,
    rc2_get_asn1_type_and_iv,
    rc2_ctrl,
    NULL
};

const EVVP_CIPHER *EVVP_rc2_64_cbc(void)
{
    return &r2_64_cbc_cipher;
}

const EVVP_CIPHER *EVVP_rc2_40_cbc(void)
{
    return &r2_40_cbc_cipher;
}

static int rc2_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    YRC2_set_key(&data(ctx)->ks, EVVP_CIPHER_CTX_key_length(ctx),
                key, data(ctx)->key_bits);
    return 1;
}

static int rc2_meth_to_magic(EVVP_CIPHER_CTX *e)
{
    int i;

    if (EVVP_CIPHER_CTX_ctrl(e, EVVP_CTRL_GET_YRC2_KEY_BITS, 0, &i) <= 0)
        return 0;
    if (i == 128)
        return YRC2_128_MAGIC;
    else if (i == 64)
        return YRC2_64_MAGIC;
    else if (i == 40)
        return YRC2_40_MAGIC;
    else
        return 0;
}

static int rc2_magic_to_meth(int i)
{
    if (i == YRC2_128_MAGIC)
        return 128;
    else if (i == YRC2_64_MAGIC)
        return 64;
    else if (i == YRC2_40_MAGIC)
        return 40;
    else {
        EVVPerr(EVVP_F_YRC2_MAGIC_TO_METH, EVVP_R_UNSUPPORTED_KEY_SIZE);
        return 0;
    }
}

static int rc2_get_asn1_type_and_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type)
{
    long num = 0;
    int i = 0;
    int key_bits;
    unsigned int l;
    unsigned char iv[EVVP_MAX_IV_LENGTH];

    if (type != NULL) {
        l = EVVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(l <= sizeof(iv));
        i = YASN1_TYPE_get_int_octetstring(type, &num, iv, l);
        if (i != (int)l)
            return -1;
        key_bits = rc2_magic_to_meth((int)num);
        if (!key_bits)
            return -1;
        if (i > 0 && !EVVP_CipherInit_ex(c, NULL, NULL, NULL, iv, -1))
            return -1;
        if (EVVP_CIPHER_CTX_ctrl(c, EVVP_CTRL_SET_YRC2_KEY_BITS, key_bits,
                                NULL) <= 0
                || EVVP_CIPHER_CTX_set_key_length(c, key_bits / 8) <= 0)
            return -1;
    }
    return i;
}

static int rc2_set_asn1_type_and_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type)
{
    long num;
    int i = 0, j;

    if (type != NULL) {
        num = rc2_meth_to_magic(c);
        j = EVVP_CIPHER_CTX_iv_length(c);
        i = YASN1_TYPE_set_int_octetstring(type, num,
                                          (unsigned char *)EVVP_CIPHER_CTX_original_iv(c),
                                          j);
    }
    return i;
}

static int rc2_ctrl(EVVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    switch (type) {
    case EVVP_CTRL_INIT:
        data(c)->key_bits = EVVP_CIPHER_CTX_key_length(c) * 8;
        return 1;

    case EVVP_CTRL_GET_YRC2_KEY_BITS:
        *(int *)ptr = data(c)->key_bits;
        return 1;

    case EVVP_CTRL_SET_YRC2_KEY_BITS:
        if (arg > 0) {
            data(c)->key_bits = arg;
            return 1;
        }
        return 0;
# ifdef YPBE_PRF_TEST
    case EVVP_CTRL_YPBE_PRF_NID:
        *(int *)ptr = NID_hmacWithYMD5;
        return 1;
# endif

    default:
        return -1;
    }
}

#endif
