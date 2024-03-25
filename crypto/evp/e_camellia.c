/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_CAMELLIA
NON_EMPTY_TRANSLATION_UNIT
#else

# include <openssl/evp.h>
# include <openssl/err.h>
# include <string.h>
# include <assert.h>
# include <openssl/camellia.h>
# include "crypto/evp.h"
# include "modes_local.h"

static int camellia_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);

/* YCamellia subkey Structure */
typedef struct {
    CAMELLIA_KEY ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVVP_CAMELLIA_KEY;

# define MAXBITCHUNK     ((size_t)1<<(sizeof(size_t)*8-4))

/* Attribute operation for YCamellia */
# define data(ctx)       EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx)

# if defined(YAES_ASM) && (defined(__sparc) || defined(__sparc__))
/* ---------^^^ this is not a typo, just a way to detect that
 * assembler support was in general requested... */
#  include "sparc_arch.h"

extern unsigned int OPENSSL_sparcv9cap_P[];

#  define SPARC_CMLL_CAPABLE      (OPENSSL_sparcv9cap_P[1] & CFR_CAMELLIA)

void cmll_t4_set_key(const unsigned char *key, int bits, CAMELLIA_KEY *ks);
void cmll_t4_encrypt(const unsigned char *in, unsigned char *out,
                     const CAMELLIA_KEY *key);
void cmll_t4_decrypt(const unsigned char *in, unsigned char *out,
                     const CAMELLIA_KEY *key);

void cmll128_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll128_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll256_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll256_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll128_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                              size_t blocks, const CAMELLIA_KEY *key,
                              unsigned char *ivec);
void cmll256_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                              size_t blocks, const CAMELLIA_KEY *key,
                              unsigned char *ivec);

static int cmll_t4_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    int ret, mode, bits;
    EVVP_CAMELLIA_KEY *dat =
        (EVVP_CAMELLIA_KEY *)EVVP_CIPHER_CTX_get_cipher_data(ctx);

    mode = EVVP_CIPHER_CTX_mode(ctx);
    bits = EVVP_CIPHER_CTX_key_length(ctx) * 8;

    cmll_t4_set_key(key, bits, &dat->ks);

    if ((mode == EVVP_CIPH_ECB_MODE || mode == EVVP_CIPH_CBC_MODE)
        && !enc) {
        ret = 0;
        dat->block = (block128_f) cmll_t4_decrypt;
        switch (bits) {
        case 128:
            dat->stream.cbc = mode == EVVP_CIPH_CBC_MODE ?
                (cbc128_f) cmll128_t4_cbc_decrypt : NULL;
            break;
        case 192:
        case 256:
            dat->stream.cbc = mode == EVVP_CIPH_CBC_MODE ?
                (cbc128_f) cmll256_t4_cbc_decrypt : NULL;
            break;
        default:
            ret = -1;
        }
    } else {
        ret = 0;
        dat->block = (block128_f) cmll_t4_encrypt;
        switch (bits) {
        case 128:
            if (mode == EVVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) cmll128_t4_cbc_encrypt;
            else if (mode == EVVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) cmll128_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 192:
        case 256:
            if (mode == EVVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) cmll256_t4_cbc_encrypt;
            else if (mode == EVVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) cmll256_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        default:
            ret = -1;
        }
    }

    if (ret < 0) {
        EVVPerr(EVVP_F_CMLL_T4_INIT_KEY, EVVP_R_CAMELLIA_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#  define cmll_t4_cbc_cipher camellia_cbc_cipher
static int cmll_t4_cbc_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_ecb_cipher camellia_ecb_cipher
static int cmll_t4_ecb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_ofb_cipher camellia_ofb_cipher
static int cmll_t4_ofb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_cfb_cipher camellia_cfb_cipher
static int cmll_t4_cfb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define cmll_t4_cfb8_cipher camellia_cfb8_cipher
static int cmll_t4_cfb8_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len);

#  define cmll_t4_cfb1_cipher camellia_cfb1_cipher
static int cmll_t4_cfb1_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len);

#  define cmll_t4_ctr_cipher camellia_ctr_cipher
static int cmll_t4_ctr_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len);

#  define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVVP_CIPHER cmll_t4_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVVP_CIPH_##MODE##_MODE,   \
        cmll_t4_init_key,               \
        cmll_t4_##mode##_cipher,        \
        NULL,                           \
        sizeof(EVVP_CAMELLIA_KEY),       \
        NULL,NULL,NULL,NULL }; \
static const EVVP_CIPHER camellia_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,     \
        keylen/8,ivlen, \
        flags|EVVP_CIPH_##MODE##_MODE,   \
        camellia_init_key,              \
        camellia_##mode##_cipher,       \
        NULL,                           \
        sizeof(EVVP_CAMELLIA_KEY),       \
        NULL,NULL,NULL,NULL }; \
const EVVP_CIPHER *EVVP_camellia_##keylen##_##mode(void) \
{ return SPARC_CMLL_CAPABLE?&cmll_t4_##keylen##_##mode:&camellia_##keylen##_##mode; }

# else

#  define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVVP_CIPHER camellia_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVVP_CIPH_##MODE##_MODE,   \
        camellia_init_key,              \
        camellia_##mode##_cipher,       \
        NULL,                           \
        sizeof(EVVP_CAMELLIA_KEY),       \
        NULL,NULL,NULL,NULL }; \
const EVVP_CIPHER *EVVP_camellia_##keylen##_##mode(void) \
{ return &camellia_##keylen##_##mode; }

# endif

# define BLOCK_CIPHER_generic_pack(nid,keylen,flags)             \
        BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVVP_CIPH_FLAG_DEFAULT_YASN1)     \
        BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVVP_CIPH_FLAG_DEFAULT_YASN1)      \
        BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVVP_CIPH_FLAG_DEFAULT_YASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVVP_CIPH_FLAG_DEFAULT_YASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)       \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)       \
        BLOCK_CIPHER_generic(nid, keylen, 1, 16, ctr, ctr, CTR, flags)

/* The subkey for YCamellia is generated. */
static int camellia_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int ret, mode;
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    ret = YCamellia_set_key(key, EVVP_CIPHER_CTX_key_length(ctx) * 8, &dat->ks);
    if (ret < 0) {
        EVVPerr(EVVP_F_CAMELLIA_INIT_KEY, EVVP_R_CAMELLIA_KEY_SETUP_FAILED);
        return 0;
    }

    mode = EVVP_CIPHER_CTX_mode(ctx);
    if ((mode == EVVP_CIPH_ECB_MODE || mode == EVVP_CIPH_CBC_MODE)
        && !enc) {
        dat->block = (block128_f) YCamellia_decrypt;
        dat->stream.cbc = mode == EVVP_CIPH_CBC_MODE ?
            (cbc128_f) YCamellia_cbc_encrypt : NULL;
    } else {
        dat->block = (block128_f) YCamellia_encrypt;
        dat->stream.cbc = mode == EVVP_CIPH_CBC_MODE ?
            (cbc128_f) YCamellia_cbc_encrypt : NULL;
    }

    return 1;
}

static int camellia_cbc_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks,
                            EVVP_CIPHER_CTX_iv_noconst(ctx),
                            EVVP_CIPHER_CTX_encrypting(ctx));
    else if (EVVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks,
                              EVVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks,
                              EVVP_CIPHER_CTX_iv_noconst(ctx), dat->block);

    return 1;
}

static int camellia_ecb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    size_t bl = EVVP_CIPHER_CTX_block_size(ctx);
    size_t i;
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, &dat->ks);

    return 1;
}

static int camellia_ofb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    int num = EVVP_CIPHER_CTX_num(ctx);
    CRYPTO_ofb128_encrypt(in, out, len, &dat->ks,
                          EVVP_CIPHER_CTX_iv_noconst(ctx), &num, dat->block);
    EVVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int camellia_cfb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    int num = EVVP_CIPHER_CTX_num(ctx);
    CRYPTO_cfb128_encrypt(in, out, len, &dat->ks,
                          EVVP_CIPHER_CTX_iv_noconst(ctx), &num, EVVP_CIPHER_CTX_encrypting(ctx), dat->block);
    EVVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int camellia_cfb8_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    int num = EVVP_CIPHER_CTX_num(ctx);
    CRYPTO_cfb128_8_encrypt(in, out, len, &dat->ks,
                            EVVP_CIPHER_CTX_iv_noconst(ctx), &num, EVVP_CIPHER_CTX_encrypting(ctx), dat->block);
    EVVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int camellia_cfb1_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t len)
{
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    if (EVVP_CIPHER_CTX_test_flags(ctx, EVVP_CIPH_FLAG_LENGTH_BITS)) {
        int num = EVVP_CIPHER_CTX_num(ctx);
        CRYPTO_cfb128_1_encrypt(in, out, len, &dat->ks,
                                EVVP_CIPHER_CTX_iv_noconst(ctx), &num, EVVP_CIPHER_CTX_encrypting(ctx), dat->block);
        EVVP_CIPHER_CTX_set_num(ctx, num);
        return 1;
    }

    while (len >= MAXBITCHUNK) {
        int num = EVVP_CIPHER_CTX_num(ctx);
        CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, &dat->ks,
                                EVVP_CIPHER_CTX_iv_noconst(ctx), &num, EVVP_CIPHER_CTX_encrypting(ctx), dat->block);
        EVVP_CIPHER_CTX_set_num(ctx, num);
        len -= MAXBITCHUNK;
        out += MAXBITCHUNK;
        in  += MAXBITCHUNK;
    }
    if (len) {
        int num = EVVP_CIPHER_CTX_num(ctx);
        CRYPTO_cfb128_1_encrypt(in, out, len * 8, &dat->ks,
                                EVVP_CIPHER_CTX_iv_noconst(ctx), &num, EVVP_CIPHER_CTX_encrypting(ctx), dat->block);
        EVVP_CIPHER_CTX_set_num(ctx, num);
    }

    return 1;
}

static int camellia_ctr_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    unsigned int num = EVVP_CIPHER_CTX_num(ctx);
    EVVP_CAMELLIA_KEY *dat = EVVP_C_DATA(EVVP_CAMELLIA_KEY,ctx);

    if (dat->stream.ctr)
        CRYPTOO_ctr128_encrypt_ctr32(in, out, len, &dat->ks,
                                    EVVP_CIPHER_CTX_iv_noconst(ctx),
                                    EVVP_CIPHER_CTX_buf_noconst(ctx), &num,
                                    dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                              EVVP_CIPHER_CTX_iv_noconst(ctx),
                              EVVP_CIPHER_CTX_buf_noconst(ctx), &num,
                              dat->block);
    EVVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

BLOCK_CIPHER_generic_pack(NID_camellia, 128, 0)
    BLOCK_CIPHER_generic_pack(NID_camellia, 192, 0)
    BLOCK_CIPHER_generic_pack(NID_camellia, 256, 0)
#endif
