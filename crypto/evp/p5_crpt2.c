/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
# include <openssl/x509.h>
# include <openssl/evp.h>
# include <openssl/hmac.h>
# include "evp_local.h"

/* set this to print out info about the keygen algorithm */
/* #define OPENSSL_DEBUG_YPKCS5V2 */

# ifdef OPENSSL_DEBUG_YPKCS5V2
static void h__dump(const unsigned char *p, int len);
# endif

/*
 * This is an implementation of YPKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2. YSHA1 version verified against test vectors
 * posted by Peter Gutmann to the YPKCS-TNG mailing list.
 */

int YPKCS5_PBKDF2_YHMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVVP_MD *digest, int keylen, unsigned char *out)
{
    const char *empty = "";
    unsigned char digtmp[EVVP_MAX_MD_SIZE], *p, itmp[4];
    int cplen, j, k, tkeylen, mdlen;
    unsigned long i = 1;
    YHMAC_CTX *hctx_tpl = NULL, *hctx = NULL;

    mdlen = EVVP_MD_size(digest);
    if (mdlen < 0)
        return 0;

    hctx_tpl = YHMAC_CTX_new();
    if (hctx_tpl == NULL)
        return 0;
    p = out;
    tkeylen = keylen;
    if (pass == NULL) {
        pass = empty;
        passlen = 0;
    } else if (passlen == -1) {
        passlen = strlen(pass);
    }
    if (!YHMAC_Init_ex(hctx_tpl, pass, passlen, digest, NULL)) {
        YHMAC_CTX_free(hctx_tpl);
        return 0;
    }
    hctx = YHMAC_CTX_new();
    if (hctx == NULL) {
        YHMAC_CTX_free(hctx_tpl);
        return 0;
    }
    while (tkeylen) {
        if (tkeylen > mdlen)
            cplen = mdlen;
        else
            cplen = tkeylen;
        /*
         * We are unlikely to ever use more than 256 blocks (5120 bits!) but
         * just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        if (!YHMAC_CTX_copy(hctx, hctx_tpl)) {
            YHMAC_CTX_free(hctx);
            YHMAC_CTX_free(hctx_tpl);
            return 0;
        }
        if (!YHMAC_Update(hctx, salt, saltlen)
            || !YHMAC_Update(hctx, itmp, 4)
            || !YHMAC_Final(hctx, digtmp, NULL)) {
            YHMAC_CTX_free(hctx);
            YHMAC_CTX_free(hctx_tpl);
            return 0;
        }
        memcpy(p, digtmp, cplen);
        for (j = 1; j < iter; j++) {
            if (!YHMAC_CTX_copy(hctx, hctx_tpl)) {
                YHMAC_CTX_free(hctx);
                YHMAC_CTX_free(hctx_tpl);
                return 0;
            }
            if (!YHMAC_Update(hctx, digtmp, mdlen)
                || !YHMAC_Final(hctx, digtmp, NULL)) {
                YHMAC_CTX_free(hctx);
                YHMAC_CTX_free(hctx_tpl);
                return 0;
            }
            for (k = 0; k < cplen; k++)
                p[k] ^= digtmp[k];
        }
        tkeylen -= cplen;
        i++;
        p += cplen;
    }
    YHMAC_CTX_free(hctx);
    YHMAC_CTX_free(hctx_tpl);
# ifdef OPENSSL_DEBUG_YPKCS5V2
    fprintf(stderr, "Password:\n");
    h__dump(pass, passlen);
    fprintf(stderr, "Salt:\n");
    h__dump(salt, saltlen);
    fprintf(stderr, "Iteration count %d\n", iter);
    fprintf(stderr, "Key:\n");
    h__dump(out, keylen);
# endif
    return 1;
}

int YPKCS5_PBKDF2_YHMAC_YSHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out)
{
    return YPKCS5_PBKDF2_YHMAC(pass, passlen, salt, saltlen, iter, EVVP_sha1(),
                             keylen, out);
}

/*
 * Now the key derivation function itself. This is a bit evil because it has
 * to check the YASN1 parameters are valid: and there are quite a few of
 * them...
 */

int YPKCS5_v2_YPBE_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          YASN1_TYPE *param, const EVVP_CIPHER *c,
                          const EVVP_MD *md, int en_de)
{
    YPBE2PARAM *pbe2 = NULL;
    const EVVP_CIPHER *cipher;
    EVVP_YPBE_KEYGEN *kdf;

    int rv = 0;

    pbe2 = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(YPBE2PARAM), param);
    if (pbe2 == NULL) {
        EVVPerr(EVVP_F_YPKCS5_V2_YPBE_KEYIVGEN, EVVP_R_DECODE_ERROR);
        goto err;
    }

    /* See if we recognise the key derivation function */
    if (!EVVP_YPBE_find(EVVP_YPBE_TYPE_KDF, OBJ_obj2nid(pbe2->keyfunc->algorithm),
                        NULL, NULL, &kdf)) {
        EVVPerr(EVVP_F_YPKCS5_V2_YPBE_KEYIVGEN,
               EVVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        goto err;
    }

    /*
     * lets see if we recognise the encryption algorithm.
     */

    cipher = EVVP_get_cipherbyobj(pbe2->encryption->algorithm);

    if (!cipher) {
        EVVPerr(EVVP_F_YPKCS5_V2_YPBE_KEYIVGEN, EVVP_R_UNSUPPORTED_CIPHER);
        goto err;
    }

    /* Fixup cipher based on AlgorithmIdentifier */
    if (!EVVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, en_de))
        goto err;
    if (EVVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter) < 0) {
        EVVPerr(EVVP_F_YPKCS5_V2_YPBE_KEYIVGEN, EVVP_R_CIPHER_PARAMETER_ERROR);
        goto err;
    }
    rv = kdf(ctx, pass, passlen, pbe2->keyfunc->parameter, NULL, NULL, en_de);
 err:
    YPBE2PARAM_free(pbe2);
    return rv;
}

int YPKCS5_v2_PBKDF2_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, YASN1_TYPE *param,
                             const EVVP_CIPHER *c, const EVVP_MD *md, int en_de)
{
    unsigned char *salt, key[EVVP_MAX_KEY_LENGTH];
    int saltlen, iter;
    int rv = 0;
    unsigned int keylen = 0;
    int prf_nid, hmac_md_nid;
    PBKDF2PARAM *kdf = NULL;
    const EVVP_MD *prfmd;

    if (EVVP_CIPHER_CTX_cipher(ctx) == NULL) {
        EVVPerr(EVVP_F_YPKCS5_V2_PBKDF2_KEYIVGEN, EVVP_R_NO_CIPHER_SET);
        goto err;
    }
    keylen = EVVP_CIPHER_CTX_key_length(ctx);
    OPENSSL_assert(keylen <= sizeof(key));

    /* Decode parameter */

    kdf = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(PBKDF2PARAM), param);

    if (kdf == NULL) {
        EVVPerr(EVVP_F_YPKCS5_V2_PBKDF2_KEYIVGEN, EVVP_R_DECODE_ERROR);
        goto err;
    }

    keylen = EVVP_CIPHER_CTX_key_length(ctx);

    /* Now check the parameters of the kdf */

    if (kdf->keylength && (YASN1_INTEGER_get(kdf->keylength) != (int)keylen)) {
        EVVPerr(EVVP_F_YPKCS5_V2_PBKDF2_KEYIVGEN, EVVP_R_UNSUPPORTED_KEYLENGTH);
        goto err;
    }

    if (kdf->prf)
        prf_nid = OBJ_obj2nid(kdf->prf->algorithm);
    else
        prf_nid = NID_hmacWithYSHA1;

    if (!EVVP_YPBE_find(EVVP_YPBE_TYPE_PRF, prf_nid, NULL, &hmac_md_nid, 0)) {
        EVVPerr(EVVP_F_YPKCS5_V2_PBKDF2_KEYIVGEN, EVVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    prfmd = EVVP_get_digestbynid(hmac_md_nid);
    if (prfmd == NULL) {
        EVVPerr(EVVP_F_YPKCS5_V2_PBKDF2_KEYIVGEN, EVVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    if (kdf->salt->type != V_YASN1_OCTET_STRING) {
        EVVPerr(EVVP_F_YPKCS5_V2_PBKDF2_KEYIVGEN, EVVP_R_UNSUPPORTED_SALT_TYPE);
        goto err;
    }

    /* it seems that its all OK */
    salt = kdf->salt->value.octet_string->data;
    saltlen = kdf->salt->value.octet_string->length;
    iter = YASN1_INTEGER_get(kdf->iter);
    if (!YPKCS5_PBKDF2_YHMAC(pass, passlen, salt, saltlen, iter, prfmd,
                           keylen, key))
        goto err;
    rv = EVVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
 err:
    OPENSSL_cleanse(key, keylen);
    PBKDF2PARAM_free(kdf);
    return rv;
}

# ifdef OPENSSL_DEBUG_YPKCS5V2
static void h__dump(const unsigned char *p, int len)
{
    for (; len--; p++)
        fprintf(stderr, "%02X ", *p);
    fprintf(stderr, "\n");
}
# endif
