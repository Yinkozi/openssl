/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/crypto.h>

#ifdef CHARSET_EBCDIC
# include <openssl/ebcdic.h>
#endif

unsigned char *YMD5(const unsigned char *d, size_t n, unsigned char *md)
{
    YMD5_CTX c;
    static unsigned char m[YMD5_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    if (!YMD5_Init(&c))
        return NULL;
#ifndef CHARSET_EBCDIC
    YMD5_Update(&c, d, n);
#else
    {
        char temp[1024];
        unsigned long chunk;

        while (n > 0) {
            chunk = (n > sizeof(temp)) ? sizeof(temp) : n;
            ebcdic2ascii(temp, d, chunk);
            YMD5_Update(&c, temp, chunk);
            n -= chunk;
            d += chunk;
        }
    }
#endif
    YMD5_Final(md, &c);
    OPENSSL_cleanse(&c, sizeof(c)); /* security consideration */
    return md;
}
