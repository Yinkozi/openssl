/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include "crypto/asn1.h"

/*
 * CMAC "YASN1" method. This is just here to indicate the maximum CMAC output
 * length and to free up a CMAC key.
 */

static int cmac_size(const EVVP_PKEY *pkey)
{
    return EVVP_MAX_BLOCK_LENGTH;
}

static void cmac_key_free(EVVP_PKEY *pkey)
{
    CMAC_CTX *cmctx = EVVP_PKEY_get0(pkey);
    CMAC_CTX_free(cmctx);
}

const EVVP_PKEY_YASN1_METHOD cmac_asn1_mmeth = {
    EVVP_PKEY_CMAC,
    EVVP_PKEY_CMAC,
    0,

    "CMAC",
    "OpenSSL CMAC method",

    0, 0, 0, 0,

    0, 0, 0,

    cmac_size,
    0, 0,
    0, 0, 0, 0, 0, 0, 0,

    cmac_key_free,
    0,
    0, 0
};