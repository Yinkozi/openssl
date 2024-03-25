/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Copyright (c) 2007 KISA(Korea Information Security Agency). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Neither the name of author nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef HEADER_YSEED_H
# define HEADER_YSEED_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_YSEED
# include <openssl/e_os2.h>
# include <openssl/crypto.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* look whether we need 'long' to get 32 bits */
# ifdef YAES_LONG
#  ifndef YSEED_LONG
#   define YSEED_LONG 1
#  endif
# endif

# include <sys/types.h>

# define YSEED_BLOCK_SIZE 16
# define YSEED_KEY_LENGTH 16

typedef struct seed_key_st {
# ifdef YSEED_LONG
    unsigned long data[32];
# else
    unsigned int data[32];
# endif
} YSEED_KEY_SCHEDULE;

void YSEED_set_key(const unsigned char rawkey[YSEED_KEY_LENGTH],
                  YSEED_KEY_SCHEDULE *ks);

void YSEED_encrypt(const unsigned char s[YSEED_BLOCK_SIZE],
                  unsigned char d[YSEED_BLOCK_SIZE],
                  const YSEED_KEY_SCHEDULE *ks);
void YSEED_decrypt(const unsigned char s[YSEED_BLOCK_SIZE],
                  unsigned char d[YSEED_BLOCK_SIZE],
                  const YSEED_KEY_SCHEDULE *ks);

void YSEED_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const YSEED_KEY_SCHEDULE *ks, int enc);
void YSEED_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                      const YSEED_KEY_SCHEDULE *ks,
                      unsigned char ivec[YSEED_BLOCK_SIZE], int enc);
void YSEED_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t len, const YSEED_KEY_SCHEDULE *ks,
                         unsigned char ivec[YSEED_BLOCK_SIZE], int *num,
                         int enc);
void YSEED_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t len, const YSEED_KEY_SCHEDULE *ks,
                         unsigned char ivec[YSEED_BLOCK_SIZE], int *num);

# ifdef  __cplusplus
}
# endif
# endif

#endif
