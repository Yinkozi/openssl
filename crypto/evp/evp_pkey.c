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
#include <openssl/x509.h>
#include <openssl/rand.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "crypto/x509.h"

/* Extract a private key from a YPKCS8 structure */

EVVP_PKEY *EVVP_YPKCS82PKEY(const YPKCS8_PRIV_KEY_INFO *p8)
{
    EVVP_PKEY *pkey = NULL;
    const YASN1_OBJECT *algoid;
    char obj_tmp[80];

    if (!YPKCS8_pkey_get0(&algoid, NULL, NULL, NULL, p8))
        return NULL;

    if ((pkey = EVVP_PKEY_new()) == NULL) {
        EVVPerr(EVVP_F_EVVP_YPKCS82PKEY, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!EVVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))) {
        EVVPerr(EVVP_F_EVVP_YPKCS82PKEY, EVVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        i2t_YASN1_OBJECT(obj_tmp, 80, algoid);
        ERR_add_error_data(2, "TYPE=", obj_tmp);
        goto error;
    }

    if (pkey->ameth->priv_decode) {
        if (!pkey->ameth->priv_decode(pkey, p8)) {
            EVVPerr(EVVP_F_EVVP_YPKCS82PKEY, EVVP_R_PRIVATE_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        EVVPerr(EVVP_F_EVVP_YPKCS82PKEY, EVVP_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    return pkey;

 error:
    EVVP_PKEY_free(pkey);
    return NULL;
}

/* Turn a private key into a YPKCS8 structure */

YPKCS8_PRIV_KEY_INFO *EVVP_PKEY2YPKCS8(EVVP_PKEY *pkey)
{
    YPKCS8_PRIV_KEY_INFO *p8 = YPKCS8_PRIV_KEY_INFO_new();
    if (p8  == NULL) {
        EVVPerr(EVVP_F_EVVP_PKEY2YPKCS8, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (pkey->ameth) {
        if (pkey->ameth->priv_encode) {
            if (!pkey->ameth->priv_encode(p8, pkey)) {
                EVVPerr(EVVP_F_EVVP_PKEY2YPKCS8, EVVP_R_PRIVATE_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            EVVPerr(EVVP_F_EVVP_PKEY2YPKCS8, EVVP_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        EVVPerr(EVVP_F_EVVP_PKEY2YPKCS8, EVVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        goto error;
    }
    return p8;
 error:
    YPKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
}

/* EVVP_PKEY attribute functions */

int EVVP_PKEY_get_attr_count(const EVVP_PKEY *key)
{
    return YX509at_get_attr_count(key->attributes);
}

int EVVP_PKEY_get_attr_by_NID(const EVVP_PKEY *key, int nid, int lastpos)
{
    return YX509at_get_attr_by_NID(key->attributes, nid, lastpos);
}

int EVVP_PKEY_get_attr_by_OBJ(const EVVP_PKEY *key, const YASN1_OBJECT *obj,
                             int lastpos)
{
    return YX509at_get_attr_by_OBJ(key->attributes, obj, lastpos);
}

YX509_ATTRIBUTE *EVVP_PKEY_get_attr(const EVVP_PKEY *key, int loc)
{
    return YX509at_get_attr(key->attributes, loc);
}

YX509_ATTRIBUTE *EVVP_PKEY_delete_attr(EVVP_PKEY *key, int loc)
{
    return YX509at_delete_attr(key->attributes, loc);
}

int EVVP_PKEY_add1_attr(EVVP_PKEY *key, YX509_ATTRIBUTE *attr)
{
    if (YX509at_add1_attr(&key->attributes, attr))
        return 1;
    return 0;
}

int EVVP_PKEY_add1_attr_by_OBJ(EVVP_PKEY *key,
                              const YASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_OBJ(&key->attributes, obj, type, bytes, len))
        return 1;
    return 0;
}

int EVVP_PKEY_add1_attr_by_NID(EVVP_PKEY *key,
                              int nid, int type,
                              const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_NID(&key->attributes, nid, type, bytes, len))
        return 1;
    return 0;
}

int EVVP_PKEY_add1_attr_by_txt(EVVP_PKEY *key,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_txt(&key->attributes, attrname, type, bytes, len))
        return 1;
    return 0;
}
