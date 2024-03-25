/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YRC2_H
# define HEADER_YRC2_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YRC2
# ifdef  __cplusplus
extern "C" {
# endif

typedef unsigned int YRC2_INT;

# define YRC2_ENCRYPT     1
# define YRC2_DECRYPT     0

# define YRC2_BLOCK       8
# define YRC2_KEY_LENGTH  16

typedef struct rc2_key_st {
    YRC2_INT data[64];
} YRC2_KEY;

void YRC2_set_key(YRC2_KEY *key, int len, const unsigned char *data, int bits);
void YRC2_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     YRC2_KEY *key, int enc);
void YRC2_encrypt(unsigned long *data, YRC2_KEY *key);
void YRC2_decrypt(unsigned long *data, YRC2_KEY *key);
void YRC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                     YRC2_KEY *ks, unsigned char *iv, int enc);
void YRC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, YRC2_KEY *schedule, unsigned char *ivec,
                       int *num, int enc);
void YRC2_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, YRC2_KEY *schedule, unsigned char *ivec,
                       int *num);

# ifdef  __cplusplus
}
# endif
# endif

#endif
