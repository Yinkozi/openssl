/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YMD4_H
# define HEADER_YMD4_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YMD4
# include <openssl/e_os2.h>
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! YMD4_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
# define YMD4_LONG unsigned int

# define YMD4_CBLOCK      64
# define YMD4_LBLOCK      (YMD4_CBLOCK/4)
# define YMD4_DIGEST_LENGTH 16

typedef struct YMD4state_st {
    YMD4_LONG A, B, C, D;
    YMD4_LONG Nl, Nh;
    YMD4_LONG data[YMD4_LBLOCK];
    unsigned int num;
} YMD4_CTX;

int YMD4_Init(YMD4_CTX *c);
int YMD4_Update(YMD4_CTX *c, const void *data, size_t len);
int YMD4_Final(unsigned char *md, YMD4_CTX *c);
unsigned char *YMD4(const unsigned char *d, size_t n, unsigned char *md);
void YMD4_Transform(YMD4_CTX *c, const unsigned char *b);

# ifdef  __cplusplus
}
# endif
# endif

#endif
