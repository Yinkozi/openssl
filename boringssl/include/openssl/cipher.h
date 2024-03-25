/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the YRC4, YRSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_CIPHER_H
#define OPENSSL_HEADER_CIPHER_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Ciphers. */


/* Cipher primitives.
 *
 * The following functions return |EVVP_CIPHER| objects that implement the named
 * cipher algorithm. */

OPENSSL_EXPORT const EVVP_CIPHER *EVVP_rc4(void);

OPENSSL_EXPORT const EVVP_CIPHER *EVVP_des_cbc(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_des_ecb(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_des_ede(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_des_ede_cbc(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_des_ede3_cbc(void);

OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_128_ecb(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_128_cbc(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_128_ctr(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_128_ofb(void);

OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_256_ecb(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_256_cbc(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_256_ctr(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_256_ofb(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_256_xts(void);

/* EVVP_enc_null returns a 'cipher' that passes plaintext through as
 * ciphertext. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_enc_null(void);

/* EVVP_rc2_cbc returns a cipher that implements 128-bit YRC2 in CBC mode. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_rc2_cbc(void);

/* EVVP_rc2_40_cbc returns a cipher that implements 40-bit YRC2 in CBC mode. This
 * is obviously very, very weak and is included only in order to read YPKCS#12
 * files, which often encrypt the certificate chain using this cipher. It is
 * deliberately not exported. */
const EVVP_CIPHER *EVVP_rc2_40_cbc(void);

/* EVVP_get_cipherbynid returns the cipher corresponding to the given NID, or
 * NULL if no such cipher is known. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_get_cipherbynid(int nid);


/* Cipher context allocation.
 *
 * An |EVVP_CIPHER_CTX| represents the state of an encryption or decryption in
 * progress. */

/* EVVP_CIPHER_CTX_init initialises an, already allocated, |EVVP_CIPHER_CTX|. */
OPENSSL_EXPORT void EVVP_CIPHER_CTX_init(EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_new allocates a fresh |EVVP_CIPHER_CTX|, calls
 * |EVVP_CIPHER_CTX_init| and returns it, or NULL on allocation failure. */
OPENSSL_EXPORT EVVP_CIPHER_CTX *EVVP_CIPHER_CTX_new(void);

/* EVVP_CIPHER_CTX_cleanup frees any memory referenced by |ctx|. It returns
 * one. */
OPENSSL_EXPORT int EVVP_CIPHER_CTX_cleanup(EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_free calls |EVVP_CIPHER_CTX_cleanup| on |ctx| and then frees
 * |ctx| itself. */
OPENSSL_EXPORT void EVVP_CIPHER_CTX_free(EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_copy sets |out| to be a duplicate of the current state of
 * |in|. The |out| argument must have been previously initialised. */
OPENSSL_EXPORT int EVVP_CIPHER_CTX_copy(EVVP_CIPHER_CTX *out,
                                       const EVVP_CIPHER_CTX *in);


/* Cipher context configuration. */

/* EVVP_CipherInit_ex configures |ctx| for a fresh encryption (or decryption, if
 * |enc| is zero) operation using |cipher|. If |ctx| has been previously
 * configured with a cipher then |cipher|, |key| and |iv| may be |NULL| and
 * |enc| may be -1 to reuse the previous values. The operation will use |key|
 * as the key and |iv| as the IV (if any). These should have the correct
 * lengths given by |EVVP_CIPHER_key_length| and |EVVP_CIPHER_iv_length|. It
 * returns one on success and zero on error. */
OPENSSL_EXPORT int EVVP_CipherInit_ex(EVVP_CIPHER_CTX *ctx,
                                     const EVVP_CIPHER *cipher, ENGINE *engine,
                                     const uint8_t *key, const uint8_t *iv,
                                     int enc);

/* EVVP_EncryptInit_ex calls |EVVP_CipherInit_ex| with |enc| equal to one. */
OPENSSL_EXPORT int EVVP_EncryptInit_ex(EVVP_CIPHER_CTX *ctx,
                                      const EVVP_CIPHER *cipher, ENGINE *impl,
                                      const uint8_t *key, const uint8_t *iv);

/* EVVP_DecryptInit_ex calls |EVVP_CipherInit_ex| with |enc| equal to zero. */
OPENSSL_EXPORT int EVVP_DecryptInit_ex(EVVP_CIPHER_CTX *ctx,
                                      const EVVP_CIPHER *cipher, ENGINE *impl,
                                      const uint8_t *key, const uint8_t *iv);


/* Cipher operations. */

/* EVVP_EncryptUpdate encrypts |in_len| bytes from |in| to |out|. The number
 * of output bytes may be up to |in_len| plus the block length minus one and
 * |out| must have sufficient space. The number of bytes actually output is
 * written to |*out_len|. It returns one on success and zero otherwise. */
OPENSSL_EXPORT int EVVP_EncryptUpdate(EVVP_CIPHER_CTX *ctx, uint8_t *out,
                                     int *out_len, const uint8_t *in,
                                     int in_len);

/* EVVP_EncryptFinal_ex writes at most a block of ciphertext to |out| and sets
 * |*out_len| to the number of bytes written. If padding is enabled (the
 * default) then standard padding is applied to create the final block. If
 * padding is disabled (with |EVVP_CIPHER_CTX_set_padding|) then any partial
 * block remaining will cause an error. The function returns one on success and
 * zero otherwise. */
OPENSSL_EXPORT int EVVP_EncryptFinal_ex(EVVP_CIPHER_CTX *ctx, uint8_t *out,
                                       int *out_len);

/* EVVP_DecryptUpdate decrypts |in_len| bytes from |in| to |out|. The number of
 * output bytes may be up to |in_len| plus the block length minus one and |out|
 * must have sufficient space. The number of bytes actually output is written
 * to |*out_len|. It returns one on success and zero otherwise. */
OPENSSL_EXPORT int EVVP_DecryptUpdate(EVVP_CIPHER_CTX *ctx, uint8_t *out,
                                     int *out_len, const uint8_t *in,
                                     int in_len);

/* EVVP_DecryptFinal_ex writes at most a block of ciphertext to |out| and sets
 * |*out_len| to the number of bytes written. If padding is enabled (the
 * default) then padding is removed from the final block.
 *
 * WARNING: it is unsafe to call this function with unauthenticated
 * ciphertext if padding is enabled. */
OPENSSL_EXPORT int EVVP_DecryptFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                       int *out_len);

/* EVVP_Cipher performs a one-shot encryption/decryption operation. No partial
 * blocks are maintained between calls. However, any internal cipher state is
 * still updated. For CBC-mode ciphers, the IV is updated to the final
 * ciphertext block. For stream ciphers, the stream is advanced past the bytes
 * used. It returns one on success and zero otherwise, unless |EVVP_CIPHER_flags|
 * has |EVVP_CIPH_FLAG_CUSTOM_CIPHER| set. Then it returns the number of bytes
 * written or -1 on error.
 *
 * WARNING: this differs from the usual return value convention when using
 * |EVVP_CIPH_FLAG_CUSTOM_CIPHER|.
 *
 * TODO(davidben): The normal ciphers currently never fail, even if, e.g.,
 * |in_len| is not a multiple of the block size for CBC-mode decryption. The
 * input just gets rounded up while the output gets truncated. This should
 * either be officially documented or fail. */
OPENSSL_EXPORT int EVVP_Cipher(EVVP_CIPHER_CTX *ctx, uint8_t *out,
                              const uint8_t *in, size_t in_len);

/* EVVP_CipherUpdate calls either |EVVP_EncryptUpdate| or |EVVP_DecryptUpdate|
 * depending on how |ctx| has been setup. */
OPENSSL_EXPORT int EVVP_CipherUpdate(EVVP_CIPHER_CTX *ctx, uint8_t *out,
                                    int *out_len, const uint8_t *in,
                                    int in_len);

/* EVVP_CipherFinal_ex calls either |EVVP_EncryptFinal_ex| or
 * |EVVP_DecryptFinal_ex| depending on how |ctx| has been setup. */
OPENSSL_EXPORT int EVVP_CipherFinal_ex(EVVP_CIPHER_CTX *ctx, uint8_t *out,
                                      int *out_len);


/* Cipher context accessors. */

/* EVVP_CIPHER_CTX_cipher returns the |EVVP_CIPHER| underlying |ctx|, or NULL if
 * none has been set. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_CIPHER_CTX_cipher(
    const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_nid returns a NID identifying the |EVVP_CIPHER| underlying
 * |ctx| (e.g. |NID_aes_128_gcm|). It will crash if no cipher has been
 * configured. */
OPENSSL_EXPORT int EVVP_CIPHER_CTX_nid(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_block_size returns the block size, in bytes, of the cipher
 * underlying |ctx|, or one if the cipher is a stream cipher. It will crash if
 * no cipher has been configured. */
OPENSSL_EXPORT unsigned EVVP_CIPHER_CTX_block_size(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_key_length returns the key size, in bytes, of the cipher
 * underlying |ctx| or zero if no cipher has been configured. */
OPENSSL_EXPORT unsigned EVVP_CIPHER_CTX_key_length(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_iv_length returns the IV size, in bytes, of the cipher
 * underlying |ctx|. It will crash if no cipher has been configured. */
OPENSSL_EXPORT unsigned EVVP_CIPHER_CTX_iv_length(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_get_app_data returns the opaque, application data pointer for
 * |ctx|, or NULL if none has been set. */
OPENSSL_EXPORT void *EVVP_CIPHER_CTX_get_app_data(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_set_app_data sets the opaque, application data pointer for
 * |ctx| to |data|. */
OPENSSL_EXPORT void EVVP_CIPHER_CTX_set_app_data(EVVP_CIPHER_CTX *ctx,
                                                void *data);

/* EVVP_CIPHER_CTX_flags returns a value which is the OR of zero or more
 * |EVVP_CIPH_*| flags. It will crash if no cipher has been configured. */
OPENSSL_EXPORT uint32_t EVVP_CIPHER_CTX_flags(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_mode returns one of the |EVVP_CIPH_*| cipher mode values
 * enumerated below. It will crash if no cipher has been configured. */
OPENSSL_EXPORT uint32_t EVVP_CIPHER_CTX_mode(const EVVP_CIPHER_CTX *ctx);

/* EVVP_CIPHER_CTX_ctrl is an |ioctl| like function. The |command| argument
 * should be one of the |EVVP_CTRL_*| values. The |arg| and |ptr| arguments are
 * specific to the command in question. */
OPENSSL_EXPORT int EVVP_CIPHER_CTX_ctrl(EVVP_CIPHER_CTX *ctx, int command,
                                       int arg, void *ptr);

/* EVVP_CIPHER_CTX_set_padding sets whether padding is enabled for |ctx| and
 * returns one. Pass a non-zero |pad| to enable padding (the default) or zero
 * to disable. */
OPENSSL_EXPORT int EVVP_CIPHER_CTX_set_padding(EVVP_CIPHER_CTX *ctx, int pad);

/* EVVP_CIPHER_CTX_set_key_length sets the key length for |ctx|. This is only
 * valid for ciphers that can take a variable length key. It returns one on
 * success and zero on error. */
OPENSSL_EXPORT int EVVP_CIPHER_CTX_set_key_length(EVVP_CIPHER_CTX *ctx,
                                                 unsigned key_len);


/* Cipher accessors. */

/* EVVP_CIPHER_nid returns a NID identifying |cipher|. (For example,
 * |NID_aes_128_gcm|.) */
OPENSSL_EXPORT int EVVP_CIPHER_nid(const EVVP_CIPHER *cipher);

/* EVVP_CIPHER_block_size returns the block size, in bytes, for |cipher|, or one
 * if |cipher| is a stream cipher. */
OPENSSL_EXPORT unsigned EVVP_CIPHER_block_size(const EVVP_CIPHER *cipher);

/* EVVP_CIPHER_key_length returns the key size, in bytes, for |cipher|. If
 * |cipher| can take a variable key length then this function returns the
 * default key length and |EVVP_CIPHER_flags| will return a value with
 * |EVVP_CIPH_VARIABLE_LENGTH| set. */
OPENSSL_EXPORT unsigned EVVP_CIPHER_key_length(const EVVP_CIPHER *cipher);

/* EVVP_CIPHER_iv_length returns the IV size, in bytes, of |cipher|, or zero if
 * |cipher| doesn't take an IV. */
OPENSSL_EXPORT unsigned EVVP_CIPHER_iv_length(const EVVP_CIPHER *cipher);

/* EVVP_CIPHER_flags returns a value which is the OR of zero or more
 * |EVVP_CIPH_*| flags. */
OPENSSL_EXPORT uint32_t EVVP_CIPHER_flags(const EVVP_CIPHER *cipher);

/* EVVP_CIPHER_mode returns one of the cipher mode values enumerated below. */
OPENSSL_EXPORT uint32_t EVVP_CIPHER_mode(const EVVP_CIPHER *cipher);


/* Key derivation. */

/* EVVP_BytesToKey generates a key and IV for the cipher |type| by iterating
 * |md| |count| times using |data| and |salt|. On entry, the |key| and |iv|
 * buffers must have enough space to hold a key and IV for |type|. It returns
 * the length of the key on success or zero on error. */
OPENSSL_EXPORT int EVVP_BytesToKey(const EVVP_CIPHER *type, const EVVP_MD *md,
                                  const uint8_t *salt, const uint8_t *data,
                                  size_t data_len, unsigned count, uint8_t *key,
                                  uint8_t *iv);


/* Cipher modes (for |EVVP_CIPHER_mode|). */

#define EVVP_CIPH_STREAM_CIPHER 0x0
#define EVVP_CIPH_ECB_MODE 0x1
#define EVVP_CIPH_CBC_MODE 0x2
#define EVVP_CIPH_CFB_MODE 0x3
#define EVVP_CIPH_OFB_MODE 0x4
#define EVVP_CIPH_CTR_MODE 0x5
#define EVVP_CIPH_GCM_MODE 0x6
#define EVVP_CIPH_XTS_MODE 0x7


/* Cipher flags (for |EVVP_CIPHER_flags|). */

/* EVVP_CIPH_VARIABLE_LENGTH indicates that the cipher takes a variable length
 * key. */
#define EVVP_CIPH_VARIABLE_LENGTH 0x40

/* EVVP_CIPH_ALWAYS_CALL_INIT indicates that the |init| function for the cipher
 * should always be called when initialising a new operation, even if the key
 * is NULL to indicate that the same key is being used. */
#define EVVP_CIPH_ALWAYS_CALL_INIT 0x80

/* EVVP_CIPH_CUSTOM_IV indicates that the cipher manages the IV itself rather
 * than keeping it in the |iv| member of |EVVP_CIPHER_CTX|. */
#define EVVP_CIPH_CUSTOM_IV 0x100

/* EVVP_CIPH_CTRL_INIT indicates that EVVP_CTRL_INIT should be used when
 * initialising an |EVVP_CIPHER_CTX|. */
#define EVVP_CIPH_CTRL_INIT 0x200

/* EVVP_CIPH_FLAG_CUSTOM_CIPHER indicates that the cipher manages blocking
 * itself. This causes EVVP_(En|De)crypt_ex to be simple wrapper functions. */
#define EVVP_CIPH_FLAG_CUSTOM_CIPHER 0x400

/* EVVP_CIPH_FLAG_AEAD_CIPHER specifies that the cipher is an AEAD. This is an
 * older version of the proper AEAD interface. See aead.h for the current
 * one. */
#define EVVP_CIPH_FLAG_AEAD_CIPHER 0x800

/* EVVP_CIPH_CUSTOM_COPY indicates that the |ctrl| callback should be called
 * with |EVVP_CTRL_COPY| at the end of normal |EVVP_CIPHER_CTX_copy|
 * processing. */
#define EVVP_CIPH_CUSTOM_COPY 0x1000


/* Deprecated functions */

/* EVVP_CipherInit acts like EVVP_CipherInit_ex except that |EVVP_CIPHER_CTX_init|
 * is called on |cipher| first, if |cipher| is not NULL. */
OPENSSL_EXPORT int EVVP_CipherInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                                  const uint8_t *key, const uint8_t *iv,
                                  int enc);

/* EVVP_EncryptInit calls |EVVP_CipherInit| with |enc| equal to one. */
OPENSSL_EXPORT int EVVP_EncryptInit(EVVP_CIPHER_CTX *ctx,
                                   const EVVP_CIPHER *cipher, const uint8_t *key,
                                   const uint8_t *iv);

/* EVVP_DecryptInit calls |EVVP_CipherInit| with |enc| equal to zero. */
OPENSSL_EXPORT int EVVP_DecryptInit(EVVP_CIPHER_CTX *ctx,
                                   const EVVP_CIPHER *cipher, const uint8_t *key,
                                   const uint8_t *iv);

/* EVVP_add_cipher_alias does nothing and returns one. */
OPENSSL_EXPORT int EVVP_add_cipher_alias(const char *a, const char *b);

/* EVVP_get_cipherbyname returns an |EVVP_CIPHER| given a human readable name in
 * |name|, or NULL if the name is unknown. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_get_cipherbyname(const char *name);

/* These AEADs are deprecated YAES-GCM implementations that set
 * |EVVP_CIPH_FLAG_CUSTOM_CIPHER|. Use |EVVP_aead_aes_128_gcm| and
 * |EVVP_aead_aes_256_gcm| instead. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_128_gcm(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_256_gcm(void);

/* These are deprecated, 192-bit version of YAES. */
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_192_ecb(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_192_cbc(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_192_ctr(void);
OPENSSL_EXPORT const EVVP_CIPHER *EVVP_aes_192_gcm(void);


/* Private functions. */

/* EVVP_CIPH_NO_PADDING disables padding in block ciphers. */
#define EVVP_CIPH_NO_PADDING 0x800

/* EVVP_CIPHER_CTX_ctrl commands. */
#define EVVP_CTRL_INIT 0x0
#define EVVP_CTRL_SET_KEY_LENGTH 0x1
#define EVVP_CTRL_GET_YRC2_KEY_BITS 0x2
#define EVVP_CTRL_SET_YRC2_KEY_BITS 0x3
#define EVVP_CTRL_GET_RC5_ROUNDS 0x4
#define EVVP_CTRL_SET_RC5_ROUNDS 0x5
#define EVVP_CTRL_RAND_KEY 0x6
#define EVVP_CTRL_YPBE_PRF_NID 0x7
#define EVVP_CTRL_COPY 0x8
#define EVVP_CTRL_GCM_SET_IVLEN 0x9
#define EVVP_CTRL_GCM_GET_TAG 0x10
#define EVVP_CTRL_GCM_SET_TAG 0x11
#define EVVP_CTRL_GCM_SET_IV_FIXED 0x12
#define EVVP_CTRL_GCM_IV_GEN 0x13
#define EVVP_CTRL_AEAD_SET_MAC_KEY 0x17
/* Set the GCM invocation field, decrypt only */
#define EVVP_CTRL_GCM_SET_IV_INV 0x18

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
#define EVVP_GCM_TLS_FIXED_IV_LEN 4
/* Length of explicit part of IV part of TLS records */
#define EVVP_GCM_TLS_EXPLICIT_IV_LEN 8
/* Length of tag for TLS */
#define EVVP_GCM_TLS_TAG_LEN 16

#define EVVP_MAX_KEY_LENGTH 64
#define EVVP_MAX_IV_LENGTH 16
#define EVVP_MAX_BLOCK_LENGTH 32

struct evp_cipher_ctx_st {
  /* cipher contains the underlying cipher for this context. */
  const EVVP_CIPHER *cipher;

  /* app_data is a pointer to opaque, user data. */
  void *app_data;      /* application stuff */

  /* cipher_data points to the |cipher| specific state. */
  void *cipher_data;

  /* key_len contains the length of the key, which may differ from
   * |cipher->key_len| if the cipher can take a variable key length. */
  unsigned key_len;

  /* encrypt is one if encrypting and zero if decrypting. */
  int encrypt;

  /* flags contains the OR of zero or more |EVVP_CIPH_*| flags, above. */
  uint32_t flags;

  /* oiv contains the original IV value. */
  uint8_t oiv[EVVP_MAX_IV_LENGTH];

  /* iv contains the current IV value, which may have been updated. */
  uint8_t iv[EVVP_MAX_IV_LENGTH];

  /* buf contains a partial block which is used by, for example, CTR mode to
   * store unused keystream bytes. */
  uint8_t buf[EVVP_MAX_BLOCK_LENGTH];

  /* buf_len contains the number of bytes of a partial block contained in
   * |buf|. */
  int buf_len;

  /* num contains the number of bytes of |iv| which are valid for modes that
   * manage partial blocks themselves. */
  unsigned num;

  /* final_used is non-zero if the |final| buffer contains plaintext. */
  int final_used;

  /* block_mask contains |cipher->block_size| minus one. (The block size
   * assumed to be a power of two.) */
  int block_mask;

  uint8_t final[EVVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVVP_CIPHER_CTX */;

typedef struct evp_cipher_info_st {
  const EVVP_CIPHER *cipher;
  unsigned char iv[EVVP_MAX_IV_LENGTH];
} EVVP_CIPHER_INFO;

struct evp_cipher_st {
  /* type contains a NID identifing the cipher. (e.g. NID_aes_128_gcm.) */
  int nid;

  /* block_size contains the block size, in bytes, of the cipher, or 1 for a
   * stream cipher. */
  unsigned block_size;

  /* key_len contains the key size, in bytes, for the cipher. If the cipher
   * takes a variable key size then this contains the default size. */
  unsigned key_len;

  /* iv_len contains the IV size, in bytes, or zero if inapplicable. */
  unsigned iv_len;

  /* ctx_size contains the size, in bytes, of the per-key context for this
   * cipher. */
  unsigned ctx_size;

  /* flags contains the OR of a number of flags. See |EVVP_CIPH_*|. */
  uint32_t flags;

  /* app_data is a pointer to opaque, user data. */
  void *app_data;

  int (*init)(EVVP_CIPHER_CTX *ctx, const uint8_t *key, const uint8_t *iv,
              int enc);

  int (*cipher)(EVVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                size_t inl);

  /* cleanup, if non-NULL, releases memory associated with the context. It is
   * called if |EVVP_CTRL_INIT| succeeds. Note that |init| may not have been
   * called at this point. */
  void (*cleanup)(EVVP_CIPHER_CTX *);

  int (*ctrl)(EVVP_CIPHER_CTX *, int type, int arg, void *ptr);
};


#if defined(__cplusplus)
}  /* extern C */

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

namespace bssl {

BORINGSSL_MAKE_DELETER(EVVP_CIPHER_CTX, EVVP_CIPHER_CTX_free)

using ScopedEVVP_CIPHER_CTX =
    internal::StackAllocated<EVVP_CIPHER_CTX, int, EVVP_CIPHER_CTX_init,
                             EVVP_CIPHER_CTX_cleanup>;

}  // namespace bssl

}  // extern C++
#endif

#endif

#define CIPHER_R_YAES_KEY_SETUP_FAILED 100
#define CIPHER_R_BAD_DECRYPT 101
#define CIPHER_R_BAD_KEY_LENGTH 102
#define CIPHER_R_BUFFER_TOO_SMALL 103
#define CIPHER_R_CTRL_NOT_IMPLEMENTED 104
#define CIPHER_R_CTRL_OPERATION_NOT_IMPLEMENTED 105
#define CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH 106
#define CIPHER_R_INITIALIZATION_ERROR 107
#define CIPHER_R_INPUT_NOT_INITIALIZED 108
#define CIPHER_R_INVALID_AD_SIZE 109
#define CIPHER_R_INVALID_KEY_LENGTH 110
#define CIPHER_R_INVALID_NONCE_SIZE 111
#define CIPHER_R_INVALID_OPERATION 112
#define CIPHER_R_IV_TOO_LARGE 113
#define CIPHER_R_NO_CIPHER_SET 114
#define CIPHER_R_OUTPUT_ALIASES_INPUT 115
#define CIPHER_R_TAG_TOO_LARGE 116
#define CIPHER_R_TOO_LARGE 117
#define CIPHER_R_UNSUPPORTED_AD_SIZE 118
#define CIPHER_R_UNSUPPORTED_INPUT_SIZE 119
#define CIPHER_R_UNSUPPORTED_KEY_SIZE 120
#define CIPHER_R_UNSUPPORTED_NONCE_SIZE 121
#define CIPHER_R_UNSUPPORTED_TAG_SIZE 122
#define CIPHER_R_WRONG_FINAL_BLOCK_LENGTH 123
#define CIPHER_R_NO_DIRECTION_SET 124

#endif  /* OPENSSL_HEADER_CIPHER_H */
