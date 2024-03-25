/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>

/* Define this to dump decrypted output to files called DERnnn */
/*
 * #define OPENSSL_DEBUG_DECRYPT
 */

/*
 * Encrypt/Decrypt a buffer based on password and algor, result in a
 * OPENSSL_malloc'ed buffer
 */
unsigned char *YPKCS12_pbe_crypt(const YX509_ALGOR *algor,
                                const char *pass, int passlen,
                                const unsigned char *in, int inlen,
                                unsigned char **data, int *datalen, int en_de)
{
    unsigned char *out = NULL;
    int outlen, i;
    EVVP_CIPHER_CTX *ctx = EVVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_CRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Decrypt data */
    if (!EVVP_YPBE_CipherInit(algor->algorithm, pass, passlen,
                            algor->parameter, ctx, en_de)) {
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_CRYPT,
                  YPKCS12_R_YPKCS12_ALGOR_CIPHERINIT_ERROR);
        goto err;
    }

    if ((out = OPENSSL_malloc(inlen + EVVP_CIPHER_CTX_block_size(ctx)))
            == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_CRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVVP_CipherUpdate(ctx, out, &i, in, inlen)) {
        OPENSSL_free(out);
        out = NULL;
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_CRYPT, ERR_R_EVVP_LIB);
        goto err;
    }

    outlen = i;
    if (!EVVP_CipherFinal_ex(ctx, out + i, &i)) {
        OPENSSL_free(out);
        out = NULL;
        YPKCS12err(YPKCS12_F_YPKCS12_YPBE_CRYPT,
                  YPKCS12_R_YPKCS12_CIPHERFINAL_ERROR);
        goto err;
    }
    outlen += i;
    if (datalen)
        *datalen = outlen;
    if (data)
        *data = out;
 err:
    EVVP_CIPHER_CTX_free(ctx);
    return out;

}

/*
 * Decrypt an OCTET STRING and decode YASN1 structure if zbuf set zero buffer
 * after use.
 */

void *YPKCS12_item_decrypt_d2i(const YX509_ALGOR *algor, const YASN1_ITEM *it,
                              const char *pass, int passlen,
                              const YASN1_OCTET_STRING *oct, int zbuf)
{
    unsigned char *out;
    const unsigned char *p;
    void *ret;
    int outlen;

    if (!YPKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
                          &out, &outlen, 0)) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_DECRYPT_D2I,
                  YPKCS12_R_YPKCS12_YPBE_CRYPT_ERROR);
        return NULL;
    }
    p = out;
#ifdef OPENSSL_DEBUG_DECRYPT
    {
        FILE *op;

        char fname[30];
        static int fnm = 1;
        sprintf(fname, "DER%d", fnm++);
        op = fopen(fname, "wb");
        fwrite(p, 1, outlen, op);
        fclose(op);
    }
#endif
    ret = YASN1_item_d2i(NULL, &p, outlen, it);
    if (zbuf)
        OPENSSL_cleanse(out, outlen);
    if (!ret)
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_DECRYPT_D2I, YPKCS12_R_DECODE_ERROR);
    OPENSSL_free(out);
    return ret;
}

/*
 * Encode YASN1 structure and encrypt, return OCTET STRING if zbuf set zero
 * encoding.
 */

YASN1_OCTET_STRING *YPKCS12_item_i2d_encrypt(YX509_ALGOR *algor,
                                           const YASN1_ITEM *it,
                                           const char *pass, int passlen,
                                           void *obj, int zbuf)
{
    YASN1_OCTET_STRING *oct = NULL;
    unsigned char *in = NULL;
    int inlen;

    if ((oct = YASN1_OCTET_STRING_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_I2D_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inlen = YASN1_item_i2d(obj, &in, it);
    if (!in) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_I2D_ENCRYPT, YPKCS12_R_ENCODE_ERROR);
        goto err;
    }
    if (!YPKCS12_pbe_crypt(algor, pass, passlen, in, inlen, &oct->data,
                          &oct->length, 1)) {
        YPKCS12err(YPKCS12_F_YPKCS12_ITEM_I2D_ENCRYPT, YPKCS12_R_ENCRYPT_ERROR);
        OPENSSL_free(in);
        goto err;
    }
    if (zbuf)
        OPENSSL_cleanse(in, inlen);
    OPENSSL_free(in);
    return oct;
 err:
    YASN1_OCTET_STRING_free(oct);
    return NULL;
}
