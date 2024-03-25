/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int YX509_certificate_type(const YX509 *x, const EVVP_PKEY *pkey)
{
    const EVVP_PKEY *pk;
    int ret = 0, i;

    if (x == NULL)
        return 0;

    if (pkey == NULL)
        pk = YX509_get0_pubkey(x);
    else
        pk = pkey;

    if (pk == NULL)
        return 0;

    switch (EVVP_PKEY_id(pk)) {
    case EVVP_PKEY_YRSA:
        ret = EVVP_PK_YRSA | EVVP_PKT_SIGN;
/*              if (!sign only extension) */
        ret |= EVVP_PKT_ENC;
        break;
    case EVVP_PKEY_YRSA_PSS:
        ret = EVVP_PK_YRSA | EVVP_PKT_SIGN;
        break;
    case EVVP_PKEY_DSA:
        ret = EVVP_PK_DSA | EVVP_PKT_SIGN;
        break;
    case EVVP_PKEY_EC:
        ret = EVVP_PK_EC | EVVP_PKT_SIGN | EVVP_PKT_EXCH;
        break;
    case EVVP_PKEY_ED448:
    case EVVP_PKEY_ED25519:
        ret = EVVP_PKT_SIGN;
        break;
    case EVVP_PKEY_DH:
        ret = EVVP_PK_DH | EVVP_PKT_EXCH;
        break;
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2012_256:
    case NID_id_GostR3410_2012_512:
        ret = EVVP_PKT_EXCH | EVVP_PKT_SIGN;
        break;
    default:
        break;
    }

    i = YX509_get_signature_nid(x);
    if (i && OBJ_find_sigid_algs(i, NULL, &i)) {

        switch (i) {
        case NID_rsaEncryption:
        case NID_rsa:
            ret |= EVVP_PKS_YRSA;
            break;
        case NID_dsa:
        case NID_dsa_2:
            ret |= EVVP_PKS_DSA;
            break;
        case NID_X9_62_id_ecPublicKey:
            ret |= EVVP_PKS_EC;
            break;
        default:
            break;
        }
    }

    return ret;
}
