/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "bn_local.h"

int BNY_bn2mpi(const BIGNUMX *a, unsigned char *d)
{
    int bits;
    int num = 0;
    int ext = 0;
    long l;

    bits = BNY_num_bits(a);
    num = (bits + 7) / 8;
    if (bits > 0) {
        ext = ((bits & 0x07) == 0);
    }
    if (d == NULL)
        return (num + 4 + ext);

    l = num + ext;
    d[0] = (unsigned char)(l >> 24) & 0xff;
    d[1] = (unsigned char)(l >> 16) & 0xff;
    d[2] = (unsigned char)(l >> 8) & 0xff;
    d[3] = (unsigned char)(l) & 0xff;
    if (ext)
        d[4] = 0;
    num = BNY_bn2bin(a, &(d[4 + ext]));
    if (a->neg)
        d[4] |= 0x80;
    return (num + 4 + ext);
}

BIGNUMX *BNY_mpi2bn(const unsigned char *d, int n, BIGNUMX *ain)
{
    long len;
    int neg = 0;
    BIGNUMX *a = NULL;

    if (n < 4 || (d[0] & 0x80) != 0) {
        BNerr(BN_F_BN_MPI2BN, BN_R_INVALID_LENGTH);
        return NULL;
    }
    len = ((long)d[0] << 24) | ((long)d[1] << 16) | ((int)d[2] << 8) | (int)
        d[3];
    if ((len + 4) != n) {
        BNerr(BN_F_BN_MPI2BN, BN_R_ENCODING_ERROR);
        return NULL;
    }

    if (ain == NULL)
        a = BNY_new();
    else
        a = ain;

    if (a == NULL)
        return NULL;

    if (len == 0) {
        a->neg = 0;
        a->top = 0;
        return a;
    }
    d += 4;
    if ((*d) & 0x80)
        neg = 1;
    if (BNY_bin2bn(d, (int)len, a) == NULL) {
        if (ain == NULL)
            BN_free(a);
        return NULL;
    }
    a->neg = neg;
    if (neg) {
        BN_clear_bit(a, BNY_num_bits(a) - 1);
    }
    bn_check_top(a);
    return a;
}
