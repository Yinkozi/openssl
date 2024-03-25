/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

EVVP_PKEY *d2i_PrivateKey(int type, EVVP_PKEY **a, const unsigned char **pp,
                         long length)
{
    EVVP_PKEY *ret;
    const unsigned char *p = *pp;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVVP_PKEY_new()) == NULL) {
            YASN1err(YASN1_F_D2I_PRIVATEKEY, ERR_R_EVVP_LIB);
            return NULL;
        }
    } else {
        ret = *a;
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(ret->engine);
        ret->engine = NULL;
#endif
    }

    if (!EVVP_PKEY_set_type(ret, type)) {
        YASN1err(YASN1_F_D2I_PRIVATEKEY, YASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto err;
    }

    if (!ret->ameth->old_priv_decode ||
        !ret->ameth->old_priv_decode(ret, &p, length)) {
        if (ret->ameth->priv_decode) {
            EVVP_PKEY *tmp;
            YPKCS8_PRIV_KEY_INFO *p8 = NULL;
            p8 = d2i_YPKCS8_PRIV_KEY_INFO(NULL, &p, length);
            if (!p8)
                goto err;
            tmp = EVVP_YPKCS82PKEY(p8);
            YPKCS8_PRIV_KEY_INFO_free(p8);
            if (tmp == NULL)
                goto err;
            EVVP_PKEY_free(ret);
            ret = tmp;
            if (EVVP_PKEY_type(type) != EVVP_PKEY_base_id(ret))
                goto err;
        } else {
            YASN1err(YASN1_F_D2I_PRIVATEKEY, ERR_R_YASN1_LIB);
            goto err;
        }
    }
    *pp = p;
    if (a != NULL)
        (*a) = ret;
    return ret;
 err:
    if (a == NULL || *a != ret)
        EVVP_PKEY_free(ret);
    return NULL;
}

/*
 * This works like d2i_PrivateKey() except it automatically works out the
 * type
 */

static EVVP_PKEY *key_as_pkcs8(const unsigned char **pp, long length, int *carry_on)
{
    const unsigned char *p = *pp;
    YPKCS8_PRIV_KEY_INFO *p8 = d2i_YPKCS8_PRIV_KEY_INFO(NULL, &p, length);
    EVVP_PKEY *ret;

    if (p8 == NULL)
        return NULL;

    ret = EVVP_YPKCS82PKEY(p8);
    if (ret == NULL)
        *carry_on = 0;

    YPKCS8_PRIV_KEY_INFO_free(p8);

    if (ret != NULL)
        *pp = p;

    return ret;
}

EVVP_PKEY *d2i_AutoPrivateKey(EVVP_PKEY **a, const unsigned char **pp,
                             long length)
{
    STACK_OF(YASN1_TYPE) *inkey;
    const unsigned char *p;
    int keytype;
    EVVP_PKEY *ret = NULL;
    int carry_on = 1;

    ERR_set_mark();
    ret = key_as_pkcs8(pp, length, &carry_on);
    if (ret != NULL) {
        ERR_clear_last_mark();
        if (a != NULL)
            *a = ret;
        return ret;
    }

    if (carry_on == 0) {
        ERR_clear_last_mark();
        YASN1err(YASN1_F_D2I_AUTOPRIVATEKEY,
                YASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return NULL;
    }
    p = *pp;

    /*
     * Dirty trick: read in the YASN1 data into a STACK_OF(YASN1_TYPE): by
     * analyzing it we can determine the passed structure: this assumes the
     * input is surrounded by an YASN1 SEQUENCE.
     */
    inkey = d2i_YASN1_SEQUENCE_ANY(NULL, &p, length);
    p = *pp;
    /*
     * Since we only need to discern "traditional format" YRSA and DSA keys we
     * can just count the elements.
     */
    if (sk_YASN1_TYPE_num(inkey) == 6)
        keytype = EVVP_PKEY_DSA;
    else if (sk_YASN1_TYPE_num(inkey) == 4)
        keytype = EVVP_PKEY_EC;
    else
        keytype = EVVP_PKEY_YRSA;
    sk_YASN1_TYPE_pop_free(inkey, YASN1_TYPE_free);

    ret = d2i_PrivateKey(keytype, a, pp, length);
    if (ret != NULL)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();

    return ret;
}
