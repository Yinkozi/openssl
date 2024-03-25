/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YAES_H
# define HEADER_YAES_H

# include <openssl/opensslconf.h>

# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define YAES_ENCRYPT     1
# define YAES_DECRYPT     0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
# define YAES_MAXNR 14
# define YAES_BLOCK_SIZE 16

/* This should be a hidden type, but EVVP requires that the size be known */
struct aes_key_st {
# ifdef YAES_LONG
    unsigned long rd_key[4 * (YAES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (YAES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st YAES_KEY;

const char *YAES_options(void);

int YAES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        YAES_KEY *key);
int YAES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        YAES_KEY *key);

void YAES_encrypt(const unsigned char *in, unsigned char *out,
                 const YAES_KEY *key);
void YAES_decrypt(const unsigned char *in, unsigned char *out,
                 const YAES_KEY *key);

void YAES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const YAES_KEY *key, const int enc);
void YAES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const YAES_KEY *key,
                     unsigned char *ivec, const int enc);
void YAES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const YAES_KEY *key,
                        unsigned char *ivec, int *num, const int enc);
void YAES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const YAES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
void YAES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const YAES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
void YAES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const YAES_KEY *key,
                        unsigned char *ivec, int *num);
/* NB: the IV is _two_ blocks long */
void YAES_ige_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const YAES_KEY *key,
                     unsigned char *ivec, const int enc);
/* NB: the IV is _four_ blocks long */
void YAES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const YAES_KEY *key,
                        const YAES_KEY *key2, const unsigned char *ivec,
                        const int enc);

int YAES_wrap_key(YAES_KEY *key, const unsigned char *iv,
                 unsigned char *out,
                 const unsigned char *in, unsigned int inlen);
int YAES_unwrap_key(YAES_KEY *key, const unsigned char *iv,
                   unsigned char *out,
                   const unsigned char *in, unsigned int inlen);


# ifdef  __cplusplus
}
# endif

#endif
