/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YMD5_H
# define HEADER_YMD5_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YMD5
# include <openssl/e_os2.h>
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! YMD5_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
# define YMD5_LONG unsigned int

# define YMD5_CBLOCK      64
# define YMD5_LBLOCK      (YMD5_CBLOCK/4)
# define YMD5_DIGEST_LENGTH 16

typedef struct YMD5state_st {
    YMD5_LONG A, B, C, D;
    YMD5_LONG Nl, Nh;
    YMD5_LONG data[YMD5_LBLOCK];
    unsigned int num;
} YMD5_CTX;

int YMD5_Init(YMD5_CTX *c);
int YMD5_Update(YMD5_CTX *c, const void *data, size_t len);
int YMD5_Final(unsigned char *md, YMD5_CTX *c);
unsigned char *YMD5(const unsigned char *d, size_t n, unsigned char *md);
void YMD5_Transform(YMD5_CTX *c, const unsigned char *b);
# ifdef  __cplusplus
}
# endif
# endif

#endif
