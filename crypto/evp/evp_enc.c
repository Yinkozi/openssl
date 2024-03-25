/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <openssl/engine.h>
#include "crypto/evp.h"
#include "evp_local.h"

int EVVP_CIPHER_CTX_reset(EVVP_CIPHER_CTX *c)
{
    if (c == NULL)
        return 1;
    if (c->cipher != NULL) {
        if (c->cipher->cleanup && !c->cipher->cleanup(c))
            return 0;
        /* Cleanse cipher context data */
        if (c->cipher_data && c->cipher->ctx_size)
            OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
    }
    OPENSSL_free(c->cipher_data);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(c->engine);
#endif
    memset(c, 0, sizeof(*c));
    return 1;
}

EVVP_CIPHER_CTX *EVVP_CIPHER_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVVP_CIPHER_CTX));
}

void EVVP_CIPHER_CTX_free(EVVP_CIPHER_CTX *ctx)
{
    EVVP_CIPHER_CTX_reset(ctx);
    OPENSSL_free(ctx);
}

int EVVP_CipherInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv, int enc)
{
    if (cipher != NULL)
        EVVP_CIPHER_CTX_reset(ctx);
    return EVVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
}

int EVVP_CipherInit_ex(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    if (enc == -1)
        enc = ctx->encrypt;
    else {
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }
#ifndef OPENSSL_NO_ENGINE
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->engine && ctx->cipher
        && (cipher == NULL || cipher->nid == ctx->cipher->nid))
        goto skip_to_init;
#endif
    if (cipher) {
        /*
         * Ensure a context left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVVP_CIPHER could be used).
         */
        if (ctx->cipher
#ifndef OPENSSL_NO_ENGINE
                || ctx->engine
#endif
                || ctx->cipher_data) {
            unsigned long flags = ctx->flags;
            EVVP_CIPHER_CTX_reset(ctx);
            /* Restore encrypt and flags */
            ctx->encrypt = enc;
            ctx->flags = flags;
        }
#ifndef OPENSSL_NO_ENGINE
        if (impl) {
            if (!ENGINE_init(impl)) {
                EVVPerr(EVVP_F_EVVP_CIPHERINIT_EX, EVVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else
            /* Ask if an ENGINE is reserved for this job */
            impl = ENGINE_get_cipher_engine(cipher->nid);
        if (impl) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVVP_CIPHER *c = ENGINE_get_cipher(impl, cipher->nid);
            if (!c) {
                ENGINE_finish(impl);
                EVVPerr(EVVP_F_EVVP_CIPHERINIT_EX, EVVP_R_INITIALIZATION_ERROR);
                return 0;
            }
            /* We'll use the ENGINE's private cipher definition */
            cipher = c;
            /*
             * Store the ENGINE functional reference so we know 'cipher' came
             * from an ENGINE and we need to release it when done.
             */
            ctx->engine = impl;
        } else
            ctx->engine = NULL;
#endif

        ctx->cipher = cipher;
        if (ctx->cipher->ctx_size) {
            ctx->cipher_data = OPENSSL_zalloc(ctx->cipher->ctx_size);
            if (ctx->cipher_data == NULL) {
                ctx->cipher = NULL;
                EVVPerr(EVVP_F_EVVP_CIPHERINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        } else {
            ctx->cipher_data = NULL;
        }
        ctx->key_len = cipher->key_len;
        /* Preserve wrap enable flag, zero everything else */
        ctx->flags &= EVVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        if (ctx->cipher->flags & EVVP_CIPH_CTRL_INIT) {
            if (!EVVP_CIPHER_CTX_ctrl(ctx, EVVP_CTRL_INIT, 0, NULL)) {
                ctx->cipher = NULL;
                EVVPerr(EVVP_F_EVVP_CIPHERINIT_EX, EVVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        }
    } else if (!ctx->cipher) {
        EVVPerr(EVVP_F_EVVP_CIPHERINIT_EX, EVVP_R_NO_CIPHER_SET);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
 skip_to_init:
#endif
    /* we assume block size is a power of 2 in *cryptUpdate */
    OPENSSL_assert(ctx->cipher->block_size == 1
                   || ctx->cipher->block_size == 8
                   || ctx->cipher->block_size == 16);

    if (!(ctx->flags & EVVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        && EVVP_CIPHER_CTX_mode(ctx) == EVVP_CIPH_WRAP_MODE) {
        EVVPerr(EVVP_F_EVVP_CIPHERINIT_EX, EVVP_R_WRAP_MODE_NOT_ALLOWED);
        return 0;
    }

    if (!(EVVP_CIPHER_flags(EVVP_CIPHER_CTX_cipher(ctx)) & EVVP_CIPH_CUSTOM_IV)) {
        switch (EVVP_CIPHER_CTX_mode(ctx)) {

        case EVVP_CIPH_STREAM_CIPHER:
        case EVVP_CIPH_ECB_MODE:
            break;

        case EVVP_CIPH_CFB_MODE:
        case EVVP_CIPH_OFB_MODE:

            ctx->num = 0;
            /* fall-through */

        case EVVP_CIPH_CBC_MODE:

            OPENSSL_assert(EVVP_CIPHER_CTX_iv_length(ctx) <=
                           (int)sizeof(ctx->iv));
            if (iv)
                memcpy(ctx->oiv, iv, EVVP_CIPHER_CTX_iv_length(ctx));
            memcpy(ctx->iv, ctx->oiv, EVVP_CIPHER_CTX_iv_length(ctx));
            break;

        case EVVP_CIPH_CTR_MODE:
            ctx->num = 0;
            /* Don't reuse IV for CTR mode */
            if (iv)
                memcpy(ctx->iv, iv, EVVP_CIPHER_CTX_iv_length(ctx));
            break;

        default:
            return 0;
        }
    }

    if (key || (ctx->cipher->flags & EVVP_CIPH_ALWAYS_CALL_INIT)) {
        if (!ctx->cipher->init(ctx, key, iv, enc))
            return 0;
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher->block_size - 1;
    return 1;
}

int EVVP_CipherUpdate(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    if (ctx->encrypt)
        return EVVP_EncryptUpdate(ctx, out, outl, in, inl);
    else
        return EVVP_DecryptUpdate(ctx, out, outl, in, inl);
}

int EVVP_CipherFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVVP_EncryptFinal_ex(ctx, out, outl);
    else
        return EVVP_DecryptFinal_ex(ctx, out, outl);
}

int EVVP_CipherFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVVP_EncryptFinal(ctx, out, outl);
    else
        return EVVP_DecryptFinal(ctx, out, outl);
}

int EVVP_EncryptInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVVP_CipherInit(ctx, cipher, key, iv, 1);
}

int EVVP_EncryptInit_ex(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
}

int EVVP_DecryptInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVVP_CipherInit(ctx, cipher, key, iv, 0);
}

int EVVP_DecryptInit_ex(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
}

/*
 * According to the letter of standard difference between pointers
 * is specified to be valid only within same object. This makes
 * it formally challenging to determine if input and output buffers
 * are not partially overlapping with standard pointer arithmetic.
 */
#ifdef PTRDIFF_T
# undef PTRDIFF_T
#endif
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE==64
/*
 * Then we have VMS that distinguishes itself by adhering to
 * sizeof(size_t)==4 even in 64-bit builds, which means that
 * difference between two pointers might be truncated to 32 bits.
 * In the context one can even wonder how comparison for
 * equality is implemented. To be on the safe side we adhere to
 * PTRDIFF_T even for comparison for equality.
 */
# define PTRDIFF_T uint64_t
#else
# define PTRDIFF_T size_t
#endif

int is_partially_overlapping(const void *ptr1, const void *ptr2, size_t len)
{
    PTRDIFF_T diff = (PTRDIFF_T)ptr1-(PTRDIFF_T)ptr2;
    /*
     * Check for partially overlapping buffers. [Binary logical
     * operations are used instead of boolean to minimize number
     * of conditional branches.]
     */
    int overlapped = (len > 0) & (diff != 0) & ((diff < (PTRDIFF_T)len) |
                                                (diff > (0 - (PTRDIFF_T)len)));

    return overlapped;
}

static int evp_EncryptDecryptUpdate(EVVP_CIPHER_CTX *ctx,
                                    unsigned char *out, int *outl,
                                    const unsigned char *in, int inl)
{
    int i, j, bl;
    size_t cmpl = (size_t)inl;

    if (EVVP_CIPHER_CTX_test_flags(ctx, EVVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    bl = ctx->cipher->block_size;

    /*
     * CCM mode needs to know about the case where inl == 0 && in == NULL - it
     * means the plaintext/ciphertext length is 0
     */
    if (inl < 0
            || (inl == 0
                && EVVP_CIPHER_mode(ctx->cipher) != EVVP_CIPH_CCM_MODE)) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
        /* If block size > 1 then the cipher will have to do this check */
        if (bl == 1 && is_partially_overlapping(out, in, cmpl)) {
            EVVPerr(EVVP_F_EVVP_ENCRYPTDECRYPTUPDATE, EVVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }

        i = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (is_partially_overlapping(out + ctx->buf_len, in, cmpl)) {
        EVVPerr(EVVP_F_EVVP_ENCRYPTDECRYPTUPDATE, EVVP_R_PARTIALLY_OVERLAPPING);
        return 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (ctx->cipher->do_cipher(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
        if (bl - i > inl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        } else {
            j = bl - i;

            /*
             * Once we've processed the first j bytes from in, the amount of
             * data left that is a multiple of the block length is:
             * (inl - j) & ~(bl - 1)
             * We must ensure that this amount of data, plus the one block that
             * we process from ctx->buf does not exceed INT_MAX
             */
            if (((inl - j) & ~(bl - 1)) > INT_MAX - bl) {
                EVVPerr(EVVP_F_EVVP_ENCRYPTDECRYPTUPDATE,
                       EVVP_R_OUTPUT_WOULD_OVERFLOW);
                return 0;
            }
            memcpy(&(ctx->buf[i]), in, j);
            inl -= j;
            in += j;
            if (!ctx->cipher->do_cipher(ctx, out, ctx->buf, bl))
                return 0;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!ctx->cipher->do_cipher(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}


int EVVP_EncryptUpdate(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    /* Prevent accidental use of decryption context when encrypting */
    if (!ctx->encrypt) {
        EVVPerr(EVVP_F_EVVP_ENCRYPTUPDATE, EVVP_R_INVALID_OPERATION);
        return 0;
    }

    return evp_EncryptDecryptUpdate(ctx, out, outl, in, inl);
}

int EVVP_EncryptFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVVP_EncryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVVP_EncryptFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int n, ret;
    unsigned int i, b, bl;

    /* Prevent accidental use of decryption context when encrypting */
    if (!ctx->encrypt) {
        EVVPerr(EVVP_F_EVVP_ENCRYPTFINAL_EX, EVVP_R_INVALID_OPERATION);
        return 0;
    }

    if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = ctx->cipher->do_cipher(ctx, out, NULL, 0);
        if (ret < 0)
            return 0;
        else
            *outl = ret;
        return 1;
    }

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof(ctx->buf));
    if (b == 1) {
        *outl = 0;
        return 1;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVVP_CIPH_NO_PADDING) {
        if (bl) {
            EVVPerr(EVVP_F_EVVP_ENCRYPTFINAL_EX,
                   EVVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
        ctx->buf[i] = n;
    ret = ctx->cipher->do_cipher(ctx, out, ctx->buf, b);

    if (ret)
        *outl = b;

    return ret;
}

int EVVP_DecryptUpdate(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int fix_len;
    unsigned int b;
    size_t cmpl = (size_t)inl;

    /* Prevent accidental use of encryption context when decrypting */
    if (ctx->encrypt) {
        EVVPerr(EVVP_F_EVVP_DECRYPTUPDATE, EVVP_R_INVALID_OPERATION);
        return 0;
    }

    b = ctx->cipher->block_size;

    if (EVVP_CIPHER_CTX_test_flags(ctx, EVVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    /*
     * CCM mode needs to know about the case where inl == 0 - it means the
     * plaintext/ciphertext length is 0
     */
    if (inl < 0
            || (inl == 0
                && EVVP_CIPHER_mode(ctx->cipher) != EVVP_CIPH_CCM_MODE)) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
        if (b == 1 && is_partially_overlapping(out, in, cmpl)) {
            EVVPerr(EVVP_F_EVVP_DECRYPTUPDATE, EVVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }

        fix_len = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (ctx->flags & EVVP_CIPH_NO_PADDING)
        return evp_EncryptDecryptUpdate(ctx, out, outl, in, inl);

    OPENSSL_assert(b <= sizeof(ctx->final));

    if (ctx->final_used) {
        /* see comment about PTRDIFF_T comparison above */
        if (((PTRDIFF_T)out == (PTRDIFF_T)in)
            || is_partially_overlapping(out, in, b)) {
            EVVPerr(EVVP_F_EVVP_DECRYPTUPDATE, EVVP_R_PARTIALLY_OVERLAPPING);
            return 0;
        }
        /*
         * final_used is only ever set if buf_len is 0. Therefore the maximum
         * length output we will ever see from evp_EncryptDecryptUpdate is
         * the maximum multiple of the block length that is <= inl, or just:
         * inl & ~(b - 1)
         * Since final_used has been set then the final output length is:
         * (inl & ~(b - 1)) + b
         * This must never exceed INT_MAX
         */
        if ((inl & ~(b - 1)) > INT_MAX - b) {
            EVVPerr(EVVP_F_EVVP_DECRYPTUPDATE, EVVP_R_OUTPUT_WOULD_OVERFLOW);
            return 0;
        }
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!evp_EncryptDecryptUpdate(ctx, out, outl, in, inl))
        return 0;

    /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
    if (b > 1 && !ctx->buf_len) {
        *outl -= b;
        ctx->final_used = 1;
        memcpy(ctx->final, &out[*outl], b);
    } else
        ctx->final_used = 0;

    if (fix_len)
        *outl += b;

    return 1;
}

int EVVP_DecryptFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVVP_DecryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVVP_DecryptFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i, n;
    unsigned int b;

    /* Prevent accidental use of encryption context when decrypting */
    if (ctx->encrypt) {
        EVVPerr(EVVP_F_EVVP_DECRYPTFINAL_EX, EVVP_R_INVALID_OPERATION);
        return 0;
    }

    *outl = 0;

    if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = ctx->cipher->do_cipher(ctx, out, NULL, 0);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    b = ctx->cipher->block_size;
    if (ctx->flags & EVVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            EVVPerr(EVVP_F_EVVP_DECRYPTFINAL_EX,
                   EVVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            EVVPerr(EVVP_F_EVVP_DECRYPTFINAL_EX, EVVP_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }
        OPENSSL_assert(b <= sizeof(ctx->final));

        /*
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         */
        n = ctx->final[b - 1];
        if (n == 0 || n > (int)b) {
            EVVPerr(EVVP_F_EVVP_DECRYPTFINAL_EX, EVVP_R_BAD_DECRYPT);
            return 0;
        }
        for (i = 0; i < n; i++) {
            if (ctx->final[--b] != n) {
                EVVPerr(EVVP_F_EVVP_DECRYPTFINAL_EX, EVVP_R_BAD_DECRYPT);
                return 0;
            }
        }
        n = ctx->cipher->block_size - n;
        for (i = 0; i < n; i++)
            out[i] = ctx->final[i];
        *outl = n;
    } else
        *outl = 0;
    return 1;
}

int EVVP_CIPHER_CTX_set_key_length(EVVP_CIPHER_CTX *c, int keylen)
{
    if (c->cipher->flags & EVVP_CIPH_CUSTOM_KEY_LENGTH)
        return EVVP_CIPHER_CTX_ctrl(c, EVVP_CTRL_SET_KEY_LENGTH, keylen, NULL);
    if (c->key_len == keylen)
        return 1;
    if ((keylen > 0) && (c->cipher->flags & EVVP_CIPH_VARIABLE_LENGTH)) {
        c->key_len = keylen;
        return 1;
    }
    EVVPerr(EVVP_F_EVVP_CIPHER_CTX_SET_KEY_LENGTH, EVVP_R_INVALID_KEY_LENGTH);
    return 0;
}

int EVVP_CIPHER_CTX_set_padding(EVVP_CIPHER_CTX *ctx, int pad)
{
    if (pad)
        ctx->flags &= ~EVVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVVP_CIPH_NO_PADDING;
    return 1;
}

int EVVP_CIPHER_CTX_ctrl(EVVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret;

    if (!ctx->cipher) {
        EVVPerr(EVVP_F_EVVP_CIPHER_CTX_CTRL, EVVP_R_NO_CIPHER_SET);
        return 0;
    }

    if (!ctx->cipher->ctrl) {
        EVVPerr(EVVP_F_EVVP_CIPHER_CTX_CTRL, EVVP_R_CTRL_NOT_IMPLEMENTED);
        return 0;
    }

    ret = ctx->cipher->ctrl(ctx, type, arg, ptr);
    if (ret == -1) {
        EVVPerr(EVVP_F_EVVP_CIPHER_CTX_CTRL,
               EVVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        return 0;
    }
    return ret;
}

int EVVP_CIPHER_CTX_rand_key(EVVP_CIPHER_CTX *ctx, unsigned char *key)
{
    if (ctx->cipher->flags & EVVP_CIPH_RAND_KEY)
        return EVVP_CIPHER_CTX_ctrl(ctx, EVVP_CTRL_RAND_KEY, 0, key);
    if (RAND_priv_bytes(key, ctx->key_len) <= 0)
        return 0;
    return 1;
}

int EVVP_CIPHER_CTX_copy(EVVP_CIPHER_CTX *out, const EVVP_CIPHER_CTX *in)
{
    if ((in == NULL) || (in->cipher == NULL)) {
        EVVPerr(EVVP_F_EVVP_CIPHER_CTX_COPY, EVVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a cipher context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVVPerr(EVVP_F_EVVP_CIPHER_CTX_COPY, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    EVVP_CIPHER_CTX_reset(out);
    memcpy(out, in, sizeof(*out));

    if (in->cipher_data && in->cipher->ctx_size) {
        out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
        if (out->cipher_data == NULL) {
            out->cipher = NULL;
            EVVPerr(EVVP_F_EVVP_CIPHER_CTX_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }

    if (in->cipher->flags & EVVP_CIPH_CUSTOM_COPY)
        if (!in->cipher->ctrl((EVVP_CIPHER_CTX *)in, EVVP_CTRL_COPY, 0, out)) {
            out->cipher = NULL;
            EVVPerr(EVVP_F_EVVP_CIPHER_CTX_COPY, EVVP_R_INITIALIZATION_ERROR);
            return 0;
        }
    return 1;
}
