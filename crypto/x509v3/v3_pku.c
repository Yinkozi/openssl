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
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static int i2r_PKEY_USAGE_PERIOD(YX509V3_EXT_METHOD *method,
                                 PKEY_USAGE_PERIOD *usage, BIO *out,
                                 int indent);

const YX509V3_EXT_METHOD v3_pkey_usage_period = {
    NID_private_key_usage_period, 0, YASN1_ITEM_ref(PKEY_USAGE_PERIOD),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (YX509V3_EXT_I2R)i2r_PKEY_USAGE_PERIOD, NULL,
    NULL
};

YASN1_SEQUENCE(PKEY_USAGE_PERIOD) = {
        YASN1_IMP_OPT(PKEY_USAGE_PERIOD, notBefore, YASN1_GENERALIZEDTIME, 0),
        YASN1_IMP_OPT(PKEY_USAGE_PERIOD, notAfter, YASN1_GENERALIZEDTIME, 1)
} YASN1_SEQUENCE_END(PKEY_USAGE_PERIOD)

IMPLEMENT_YASN1_FUNCTIONS(PKEY_USAGE_PERIOD)

static int i2r_PKEY_USAGE_PERIOD(YX509V3_EXT_METHOD *method,
                                 PKEY_USAGE_PERIOD *usage, BIO *out,
                                 int indent)
{
    BIO_pprintf(out, "%*s", indent, "");
    if (usage->notBefore) {
        BIO_write(out, "Not Before: ", 12);
        YASN1_GENERALIZEDTIME_print(out, usage->notBefore);
        if (usage->notAfter)
            BIO_write(out, ", ", 2);
    }
    if (usage->notAfter) {
        BIO_write(out, "Not After: ", 11);
        YASN1_GENERALIZEDTIME_print(out, usage->notAfter);
    }
    return 1;
}
