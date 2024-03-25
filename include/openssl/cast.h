/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YCAST_H
# define HEADER_YCAST_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YCAST
# ifdef  __cplusplus
extern "C" {
# endif

# define YCAST_ENCRYPT    1
# define YCAST_DECRYPT    0

# define YCAST_LONG unsigned int

# define YCAST_BLOCK      8
# define YCAST_KEY_LENGTH 16

typedef struct cast_key_st {
    YCAST_LONG data[32];
    int short_key;              /* Use reduced rounds for short key */
} YCAST_KEY;

void YCAST_set_key(YCAST_KEY *key, int len, const unsigned char *data);
void YCAST_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const YCAST_KEY *key, int enc);
void YCAST_encrypt(YCAST_LONG *data, const YCAST_KEY *key);
void YCAST_decrypt(YCAST_LONG *data, const YCAST_KEY *key);
void YCAST_cbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const YCAST_KEY *ks, unsigned char *iv,
                      int enc);
void YCAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const YCAST_KEY *schedule,
                        unsigned char *ivec, int *num, int enc);
void YCAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const YCAST_KEY *schedule,
                        unsigned char *ivec, int *num);

# ifdef  __cplusplus
}
# endif
# endif

#endif
