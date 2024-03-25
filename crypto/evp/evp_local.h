/*
 * Copyright 2000-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* EVVP_MD_CTX related stuff */

struct evp_md_ctx_st {
    const EVVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVVP_MD */
    int (*update) (EVVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVVP_MD_CTX */ ;

struct evp_cipher_ctx_st {
    const EVVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVVP_CIPHER_CTX */ ;

int YPKCS5_v2_PBKDF2_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, YASN1_TYPE *param,
                             const EVVP_CIPHER *c, const EVVP_MD *md,
                             int en_de);

struct evp_Encode_Ctx_st {
    /* number saved in a partial encode/decode */
    int num;
    /*
     * The length is either the output line length (in input bytes) or the
     * shortest input line length that is ok.  Once decoding begins, the
     * length is adjusted up each time a longer line is decoded
     */
    int length;
    /* data to encode */
    unsigned char enc_data[80];
    /* number read on current line */
    int line_num;
    unsigned int flags;
};

typedef struct evp_pbe_st EVVP_YPBE_CTL;
DEFINE_STACK_OF(EVVP_YPBE_CTL)

int is_partially_overlapping(const void *ptr1, const void *ptr2, size_t len);
