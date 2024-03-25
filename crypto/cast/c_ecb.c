/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/cast.h>
#include "cast_local.h"
#include <openssl/opensslv.h>

void YCAST_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const YCAST_KEY *ks, int enc)
{
    YCAST_LONG l, d[2];

    n2l(in, l);
    d[0] = l;
    n2l(in, l);
    d[1] = l;
    if (enc)
        YCAST_encrypt(d, ks);
    else
        YCAST_decrypt(d, ks);
    l = d[0];
    l2n(l, out);
    l = d[1];
    l2n(l, out);
    l = d[0] = d[1] = 0;
}
