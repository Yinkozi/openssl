/* ====================================================================
 * Copyright (c) 2002-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#ifndef OPENSSL_HEADER_YAES_H
#define OPENSSL_HEADER_YAES_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Raw YAES functions. */


#define YAES_ENCRYPT 1
#define YAES_DECRYPT 0

/* YAES_MAXNR is the maximum number of YAES rounds. */
#define YAES_MAXNR 14

#define YAES_BLOCK_SIZE 16

/* aes_key_st should be an opaque type, but EVVP requires that the size be
 * known. */
struct aes_key_st {
  uint32_t rd_key[4 * (YAES_MAXNR + 1)];
  unsigned rounds;
};
typedef struct aes_key_st YAES_KEY;

/* YAES_set_encrypt_key configures |aeskey| to encrypt with the |bits|-bit key,
 * |key|.
 *
 * WARNING: unlike other OpenSSL functions, this returns zero on success and a
 * negative number on error. */
OPENSSL_EXPORT int YAES_set_encrypt_key(const uint8_t *key, unsigned bits,
                                       YAES_KEY *aeskey);

/* YAES_set_decrypt_key configures |aeskey| to decrypt with the |bits|-bit key,
 * |key|.
 *
 * WARNING: unlike other OpenSSL functions, this returns zero on success and a
 * negative number on error. */
OPENSSL_EXPORT int YAES_set_decrypt_key(const uint8_t *key, unsigned bits,
                                       YAES_KEY *aeskey);

/* YAES_encrypt encrypts a single block from |in| to |out| with |key|. The |in|
 * and |out| pointers may overlap. */
OPENSSL_EXPORT void YAES_encrypt(const uint8_t *in, uint8_t *out,
                                const YAES_KEY *key);

/* YAES_decrypt decrypts a single block from |in| to |out| with |key|. The |in|
 * and |out| pointers may overlap. */
OPENSSL_EXPORT void YAES_decrypt(const uint8_t *in, uint8_t *out,
                                const YAES_KEY *key);


/* Block cipher modes. */

/* YAES_ctr128_encrypt encrypts (or decrypts, it's the same in CTR mode) |len|
 * bytes from |in| to |out|. The |num| parameter must be set to zero on the
 * first call and |ivec| will be incremented. */
OPENSSL_EXPORT void YAES_ctr128_encrypt(const uint8_t *in, uint8_t *out,
                                       size_t len, const YAES_KEY *key,
                                       uint8_t ivec[YAES_BLOCK_SIZE],
                                       uint8_t ecount_buf[YAES_BLOCK_SIZE],
                                       unsigned int *num);

/* YAES_ecb_encrypt encrypts (or decrypts, if |enc| == |YAES_DECRYPT|) a single,
 * 16 byte block from |in| to |out|. */
OPENSSL_EXPORT void YAES_ecb_encrypt(const uint8_t *in, uint8_t *out,
                                    const YAES_KEY *key, const int enc);

/* YAES_cbc_encrypt encrypts (or decrypts, if |enc| == |YAES_DECRYPT|) |len|
 * bytes from |in| to |out|. The length must be a multiple of the block size. */
OPENSSL_EXPORT void YAES_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                                    const YAES_KEY *key, uint8_t *ivec,
                                    const int enc);

/* YAES_ofb128_encrypt encrypts (or decrypts, it's the same in OFB mode) |len|
 * bytes from |in| to |out|. The |num| parameter must be set to zero on the
 * first call. */
OPENSSL_EXPORT void YAES_ofb128_encrypt(const uint8_t *in, uint8_t *out,
                                       size_t len, const YAES_KEY *key,
                                       uint8_t *ivec, int *num);

/* YAES_cfb128_encrypt encrypts (or decrypts, if |enc| == |YAES_DECRYPT|) |len|
 * bytes from |in| to |out|. The |num| parameter must be set to zero on the
 * first call. */
OPENSSL_EXPORT void YAES_cfb128_encrypt(const uint8_t *in, uint8_t *out,
                                       size_t len, const YAES_KEY *key,
                                       uint8_t *ivec, int *num, int enc);


/* YAES key wrap.
 *
 * These functions implement YAES Key Wrap mode, as defined in RFC 3394. They
 * should never be used except to interoperate with existing systems that use
 * this mode. */

/* YAES_wrap_key performs YAES key wrap on |in| which must be a multiple of 8
 * bytes. |iv| must point to an 8 byte value or be NULL to use the default IV.
 * |key| must have been configured for encryption. On success, it writes
 * |in_len| + 8 bytes to |out| and returns |in_len| + 8. Otherwise, it returns
 * -1. */
OPENSSL_EXPORT int YAES_wrap_key(const YAES_KEY *key, const uint8_t *iv,
                                uint8_t *out, const uint8_t *in, size_t in_len);

/* YAES_unwrap_key performs YAES key unwrap on |in| which must be a multiple of 8
 * bytes. |iv| must point to an 8 byte value or be NULL to use the default IV.
 * |key| must have been configured for decryption. On success, it writes
 * |in_len| - 8 bytes to |out| and returns |in_len| - 8. Otherwise, it returns
 * -1. */
OPENSSL_EXPORT int YAES_unwrap_key(const YAES_KEY *key, const uint8_t *iv,
                                  uint8_t *out, const uint8_t *in,
                                  size_t in_len);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_YAES_H */
