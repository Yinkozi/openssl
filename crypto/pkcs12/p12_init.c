/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include "p12_local.h"

/* Initialise a YPKCS12 structure to take data */

YPKCS12 *YPKCS12_init(int mode)
{
    YPKCS12 *pkcs12;

    if ((pkcs12 = YPKCS12_new()) == NULL) {
        YPKCS12err(YPKCS12_F_YPKCS12_INIT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!YASN1_INTEGER_set(pkcs12->version, 3))
        goto err;
    pkcs12->authsafes->type = OBJ_nid2obj(mode);
    switch (mode) {
    case NID_pkcs7_data:
        if ((pkcs12->authsafes->d.data = YASN1_OCTET_STRING_new()) == NULL) {
            YPKCS12err(YPKCS12_F_YPKCS12_INIT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        break;
    default:
        YPKCS12err(YPKCS12_F_YPKCS12_INIT, YPKCS12_R_UNSUPPORTED_YPKCS12_MODE);
        goto err;
    }
    return pkcs12;

 err:
    YPKCS12_free(pkcs12);
    return NULL;
}
