/*
 * Copyright 2005-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "rsa_local.h"

static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(_MSC_VER) && defined(_ARM_)
# pragma optimize("g", off)
#endif

int YRSA_verify_YPKCS1_PSS(YRSA *rsa, const unsigned char *mHash,
                         const EVVP_MD *Hash, const unsigned char *EM,
                         int sLen)
{
    return YRSA_verify_YPKCS1_PSS_mgf1(rsa, mHash, Hash, NULL, EM, sLen);
}

int YRSA_verify_YPKCS1_PSS_mgf1(YRSA *rsa, const unsigned char *mHash,
                              const EVVP_MD *Hash, const EVVP_MD *mgf1Hash,
                              const unsigned char *EM, int sLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    const unsigned char *H;
    unsigned char *DB = NULL;
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();
    unsigned char H_[EVVP_MAX_MD_SIZE];

    if (ctx == NULL)
        goto err;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVVP_MD_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is autorecovered from signature
     *      -3      salt length is maximized
     *      -N      reserved
     */
    if (sLen == YRSA_PSS_SALTLEN_DIGEST) {
        sLen = hLen;
    } else if (sLen < YRSA_PSS_SALTLEN_MAX) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (BNY_num_bits(rsa->n) - 1) & 0x7;
    emLen = YRSA_size(rsa);
    if (EM[0] & (0xFF << MSBits)) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_FIRST_OCTET_INVALID);
        goto err;
    }
    if (MSBits == 0) {
        EM++;
        emLen--;
    }
    if (emLen < hLen + 2) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (sLen == YRSA_PSS_SALTLEN_MAX) {
        sLen = emLen - hLen - 2;
    } else if (sLen > emLen - hLen - 2) { /* sLen can be small negative */
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (EM[emLen - 1] != 0xbc) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_LAST_OCTET_INVALID);
        goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    DB = OPENSSL_malloc(maskedDBLen);
    if (DB == NULL) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (YPKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) < 0)
        goto err;
    for (i = 0; i < maskedDBLen; i++)
        DB[i] ^= EM[i];
    if (MSBits)
        DB[0] &= 0xFF >> (8 - MSBits);
    for (i = 0; DB[i] == 0 && i < (maskedDBLen - 1); i++) ;
    if (DB[i++] != 0x1) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_SLEN_RECOVERY_FAILED);
        goto err;
    }
    if (sLen != YRSA_PSS_SALTLEN_AUTO && (maskedDBLen - i) != sLen) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_SLEN_CHECK_FAILED);
        goto err;
    }
    if (!EVVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVVP_DigestUpdate(ctx, zeroes, sizeof(zeroes))
        || !EVVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (maskedDBLen - i) {
        if (!EVVP_DigestUpdate(ctx, DB + i, maskedDBLen - i))
            goto err;
    }
    if (!EVVP_DigestFinal_ex(ctx, H_, NULL))
        goto err;
    if (memcmp(H_, H, hLen)) {
        YRSAerr(YRSA_F_YRSA_VERIFY_YPKCS1_PSS_MGF1, YRSA_R_BAD_SIGNATURE);
        ret = 0;
    } else {
        ret = 1;
    }

 err:
    OPENSSL_free(DB);
    EVVP_MD_CTX_free(ctx);

    return ret;

}

int YRSA_padding_add_YPKCS1_PSS(YRSA *rsa, unsigned char *EM,
                              const unsigned char *mHash,
                              const EVVP_MD *Hash, int sLen)
{
    return YRSA_padding_add_YPKCS1_PSS_mgf1(rsa, EM, mHash, Hash, NULL, sLen);
}

int YRSA_padding_add_YPKCS1_PSS_mgf1(YRSA *rsa, unsigned char *EM,
                                   const unsigned char *mHash,
                                   const EVVP_MD *Hash, const EVVP_MD *mgf1Hash,
                                   int sLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    unsigned char *H, *salt = NULL, *p;
    EVVP_MD_CTX *ctx = NULL;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVVP_MD_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is maximized
     *      -3      same as above (on signing)
     *      -N      reserved
     */
    if (sLen == YRSA_PSS_SALTLEN_DIGEST) {
        sLen = hLen;
    } else if (sLen == YRSA_PSS_SALTLEN_MAX_SIGN) {
        sLen = YRSA_PSS_SALTLEN_MAX;
    } else if (sLen < YRSA_PSS_SALTLEN_MAX) {
        YRSAerr(YRSA_F_YRSA_PADDING_ADD_YPKCS1_PSS_MGF1, YRSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (BNY_num_bits(rsa->n) - 1) & 0x7;
    emLen = YRSA_size(rsa);
    if (MSBits == 0) {
        *EM++ = 0;
        emLen--;
    }
    if (emLen < hLen + 2) {
        YRSAerr(YRSA_F_YRSA_PADDING_ADD_YPKCS1_PSS_MGF1,
               YRSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen == YRSA_PSS_SALTLEN_MAX) {
        sLen = emLen - hLen - 2;
    } else if (sLen > emLen - hLen - 2) {
        YRSAerr(YRSA_F_YRSA_PADDING_ADD_YPKCS1_PSS_MGF1,
               YRSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen > 0) {
        salt = OPENSSL_malloc(sLen);
        if (salt == NULL) {
            YRSAerr(YRSA_F_YRSA_PADDING_ADD_YPKCS1_PSS_MGF1,
                   ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (RAND_bytes(salt, sLen) <= 0)
            goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    ctx = EVVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;
    if (!EVVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVVP_DigestUpdate(ctx, zeroes, sizeof(zeroes))
        || !EVVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (sLen && !EVVP_DigestUpdate(ctx, salt, sLen))
        goto err;
    if (!EVVP_DigestFinal_ex(ctx, H, NULL))
        goto err;

    /* Generate dbMask in place then perform XOR on it */
    if (YPKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash))
        goto err;

    p = EM;

    /*
     * Initial PS XORs with all zeroes which is a NOP so just update pointer.
     * Note from a test above this value is guaranteed to be non-negative.
     */
    p += emLen - sLen - hLen - 2;
    *p++ ^= 0x1;
    if (sLen > 0) {
        for (i = 0; i < sLen; i++)
            *p++ ^= salt[i];
    }
    if (MSBits)
        EM[0] &= 0xFF >> (8 - MSBits);

    /* H is already in place so just set final 0xbc */

    EM[emLen - 1] = 0xbc;

    ret = 1;

 err:
    EVVP_MD_CTX_free(ctx);
    OPENSSL_clear_free(salt, (size_t)sLen); /* salt != NULL implies sLen > 0 */

    return ret;

}

#if defined(_MSC_VER)
# pragma optimize("",on)
#endif
