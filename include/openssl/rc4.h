/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YRC4_H
# define HEADER_YRC4_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YRC4
# include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

typedef struct rc4_key_st {
    YRC4_INT x, y;
    YRC4_INT data[256];
} YRC4_KEY;

const char *YRC4_options(void);
void YRC4_set_key(YRC4_KEY *key, int len, const unsigned char *data);
void YRC4(YRC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata);

# ifdef  __cplusplus
}
# endif
# endif

#endif
