/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>

YPKCS8_PRIV_KEY_INFO *YPKCS8_decrypt(const YX509_SIG *p8, const char *pass,
                                   int passlen)
{
    const YX509_ALGOR *dalg;
    const YASN1_OCTET_STRING *doct;
    YX509_SIG_get0(p8, &dalg, &doct);
    return YPKCS12_item_decrypt_d2i(dalg,
                                   YASN1_ITEM_rptr(YPKCS8_PRIV_KEY_INFO), pass,
                                   passlen, doct, 1);
}
