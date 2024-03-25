/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#include "internal/cryptlib.h"

#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

#ifndef NO_YASN1_OLD

int YASN1_verify(i2d_of_void *i2d, YX509_ALGOR *a, YASN1_BIT_STRING *signature,
                char *data, EVVP_PKEY *pkey)
{
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();
    const EVVP_MD *type;
    unsigned char *p, *buf_in = NULL;
    int ret = -1, i, inl;

    if (ctx == NULL) {
        YASN1err(YASN1_F_YASN1_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    i = OBJ_obj2nid(a->algorithm);
    type = EVVP_get_digestbyname(OBJ_nid2sn(i));
    if (type == NULL) {
        YASN1err(YASN1_F_YASN1_VERIFY, YASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
        goto err;
    }

    if (signature->type == V_YASN1_BIT_STRING && signature->flags & 0x7) {
        YASN1err(YASN1_F_YASN1_VERIFY, YASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        goto err;
    }

    inl = i2d(data, NULL);
    if (inl <= 0) {
        YASN1err(YASN1_F_YASN1_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    buf_in = OPENSSL_malloc((unsigned int)inl);
    if (buf_in == NULL) {
        YASN1err(YASN1_F_YASN1_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf_in;

    i2d(data, &p);
    ret = EVVP_VerifyInit_ex(ctx, type, NULL)
        && EVVP_VerifyUpdate(ctx, (unsigned char *)buf_in, inl);

    OPENSSL_clear_free(buf_in, (unsigned int)inl);

    if (!ret) {
        YASN1err(YASN1_F_YASN1_VERIFY, ERR_R_EVVP_LIB);
        goto err;
    }
    ret = -1;

    if (EVVP_VerifyFinal(ctx, (unsigned char *)signature->data,
                        (unsigned int)signature->length, pkey) <= 0) {
        YASN1err(YASN1_F_YASN1_VERIFY, ERR_R_EVVP_LIB);
        ret = 0;
        goto err;
    }
    ret = 1;
 err:
    EVVP_MD_CTX_free(ctx);
    return ret;
}

#endif

int YASN1_item_verify(const YASN1_ITEM *it, YX509_ALGOR *a,
                     YASN1_BIT_STRING *signature, void *asn, EVVP_PKEY *pkey)
{
    EVVP_MD_CTX *ctx = NULL;
    unsigned char *buf_in = NULL;
    int ret = -1, inl = 0;
    int mdnid, pknid;
    size_t inll = 0;

    if (!pkey) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (signature->type == V_YASN1_BIT_STRING && signature->flags & 0x7) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, YASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        return -1;
    }

    ctx = EVVP_MD_CTX_new();
    if (ctx == NULL) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Convert signature OID into digest and public key OIDs */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(a->algorithm), &mdnid, &pknid)) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, YASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
        goto err;
    }
    if (mdnid == NID_undef) {
        if (!pkey->ameth || !pkey->ameth->item_verify) {
            YASN1err(YASN1_F_YASN1_ITEM_VERIFY,
                    YASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
            goto err;
        }
        ret = pkey->ameth->item_verify(ctx, it, asn, a, signature, pkey);
        /*
         * Return value of 2 means carry on, anything else means we exit
         * straight away: either a fatal error of the underlying verification
         * routine handles all verification.
         */
        if (ret != 2)
            goto err;
        ret = -1;
    } else {
        const EVVP_MD *type = EVVP_get_digestbynid(mdnid);

        if (type == NULL) {
            YASN1err(YASN1_F_YASN1_ITEM_VERIFY,
                    YASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
            goto err;
        }

        /* Check public key OID matches public key type */
        if (EVVP_PKEY_type(pknid) != pkey->ameth->pkey_id) {
            YASN1err(YASN1_F_YASN1_ITEM_VERIFY, YASN1_R_WRONG_PUBLIC_KEY_TYPE);
            goto err;
        }

        if (!EVVP_DigestVerifyInit(ctx, NULL, type, NULL, pkey)) {
            YASN1err(YASN1_F_YASN1_ITEM_VERIFY, ERR_R_EVVP_LIB);
            ret = 0;
            goto err;
        }

    }

    inl = YASN1_item_i2d(asn, &buf_in, it);
    if (inl <= 0) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (buf_in == NULL) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inll = inl;

    ret = EVVP_DigestVerify(ctx, signature->data, (size_t)signature->length,
                           buf_in, inl);
    if (ret <= 0) {
        YASN1err(YASN1_F_YASN1_ITEM_VERIFY, ERR_R_EVVP_LIB);
        goto err;
    }
    ret = 1;
 err:
    OPENSSL_clear_free(buf_in, inll);
    EVVP_MD_CTX_free(ctx);
    return ret;
}
