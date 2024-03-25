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

#include <openssl/cipher.h>

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "internal.h"
#include "../internal.h"


const EVVP_CIPHER *EVVP_get_cipherbynid(int nid) {
  switch (nid) {
    case NID_rc2_cbc:
      return EVVP_rc2_cbc();
    case NID_rc2_40_cbc:
      return EVVP_rc2_40_cbc();
    case NID_des_ede3_cbc:
      return EVVP_des_ede3_cbc();
    case NID_des_ede_cbc:
      return EVVP_des_cbc();
    case NID_aes_128_cbc:
      return EVVP_aes_128_cbc();
    case NID_aes_192_cbc:
      return EVVP_aes_192_cbc();
    case NID_aes_256_cbc:
      return EVVP_aes_256_cbc();
    default:
      return NULL;
  }
}

void EVVP_CIPHER_CTX_init(EVVP_CIPHER_CTX *ctx) {
  OPENSSL_memset(ctx, 0, sizeof(EVVP_CIPHER_CTX));
}

EVVP_CIPHER_CTX *EVVP_CIPHER_CTX_new(void) {
  EVVP_CIPHER_CTX *ctx = OPENSSL_malloc(sizeof(EVVP_CIPHER_CTX));
  if (ctx) {
    EVVP_CIPHER_CTX_init(ctx);
  }
  return ctx;
}

int EVVP_CIPHER_CTX_cleanup(EVVP_CIPHER_CTX *c) {
  if (c->cipher != NULL) {
    if (c->cipher->cleanup) {
      c->cipher->cleanup(c);
    }
    OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
  }
  OPENSSL_free(c->cipher_data);

  OPENSSL_memset(c, 0, sizeof(EVVP_CIPHER_CTX));
  return 1;
}

void EVVP_CIPHER_CTX_free(EVVP_CIPHER_CTX *ctx) {
  if (ctx) {
    EVVP_CIPHER_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
  }
}

int EVVP_CIPHER_CTX_copy(EVVP_CIPHER_CTX *out, const EVVP_CIPHER_CTX *in) {
  if (in == NULL || in->cipher == NULL) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INPUT_NOT_INITIALIZED);
    return 0;
  }

  EVVP_CIPHER_CTX_cleanup(out);
  OPENSSL_memcpy(out, in, sizeof(EVVP_CIPHER_CTX));

  if (in->cipher_data && in->cipher->ctx_size) {
    out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
    if (!out->cipher_data) {
      out->cipher = NULL;
      OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    OPENSSL_memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
  }

  if (in->cipher->flags & EVVP_CIPH_CUSTOM_COPY) {
    if (!in->cipher->ctrl((EVVP_CIPHER_CTX *)in, EVVP_CTRL_COPY, 0, out)) {
      out->cipher = NULL;
      return 0;
    }
  }

  return 1;
}

int EVVP_CipherInit_ex(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                      ENGINE *engine, const uint8_t *key, const uint8_t *iv,
                      int enc) {
  if (enc == -1) {
    enc = ctx->encrypt;
  } else {
    if (enc) {
      enc = 1;
    }
    ctx->encrypt = enc;
  }

  if (cipher) {
    /* Ensure a context left from last time is cleared (the previous check
     * attempted to avoid this if the same ENGINE and EVVP_CIPHER could be
     * used). */
    if (ctx->cipher) {
      EVVP_CIPHER_CTX_cleanup(ctx);
      /* Restore encrypt and flags */
      ctx->encrypt = enc;
    }

    ctx->cipher = cipher;
    if (ctx->cipher->ctx_size) {
      ctx->cipher_data = OPENSSL_malloc(ctx->cipher->ctx_size);
      if (!ctx->cipher_data) {
        ctx->cipher = NULL;
        OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE);
        return 0;
      }
    } else {
      ctx->cipher_data = NULL;
    }

    ctx->key_len = cipher->key_len;
    ctx->flags = 0;

    if (ctx->cipher->flags & EVVP_CIPH_CTRL_INIT) {
      if (!EVVP_CIPHER_CTX_ctrl(ctx, EVVP_CTRL_INIT, 0, NULL)) {
        ctx->cipher = NULL;
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INITIALIZATION_ERROR);
        return 0;
      }
    }
  } else if (!ctx->cipher) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_NO_CIPHER_SET);
    return 0;
  }

  /* we assume block size is a power of 2 in *cryptUpdate */
  assert(ctx->cipher->block_size == 1 || ctx->cipher->block_size == 8 ||
         ctx->cipher->block_size == 16);

  if (!(EVVP_CIPHER_CTX_flags(ctx) & EVVP_CIPH_CUSTOM_IV)) {
    switch (EVVP_CIPHER_CTX_mode(ctx)) {
      case EVVP_CIPH_STREAM_CIPHER:
      case EVVP_CIPH_ECB_MODE:
        break;

      case EVVP_CIPH_CFB_MODE:
        ctx->num = 0;
        /* fall-through */

      case EVVP_CIPH_CBC_MODE:
        assert(EVVP_CIPHER_CTX_iv_length(ctx) <= sizeof(ctx->iv));
        if (iv) {
          OPENSSL_memcpy(ctx->oiv, iv, EVVP_CIPHER_CTX_iv_length(ctx));
        }
        OPENSSL_memcpy(ctx->iv, ctx->oiv, EVVP_CIPHER_CTX_iv_length(ctx));
        break;

      case EVVP_CIPH_CTR_MODE:
      case EVVP_CIPH_OFB_MODE:
        ctx->num = 0;
        /* Don't reuse IV for CTR mode */
        if (iv) {
          OPENSSL_memcpy(ctx->iv, iv, EVVP_CIPHER_CTX_iv_length(ctx));
        }
        break;

      default:
        return 0;
    }
  }

  if (key || (ctx->cipher->flags & EVVP_CIPH_ALWAYS_CALL_INIT)) {
    if (!ctx->cipher->init(ctx, key, iv, enc)) {
      return 0;
    }
  }

  ctx->buf_len = 0;
  ctx->final_used = 0;
  ctx->block_mask = ctx->cipher->block_size - 1;
  return 1;
}

int EVVP_EncryptInit_ex(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                       ENGINE *impl, const uint8_t *key, const uint8_t *iv) {
  return EVVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
}

int EVVP_DecryptInit_ex(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                       ENGINE *impl, const uint8_t *key, const uint8_t *iv) {
  return EVVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
}

int EVVP_EncryptUpdate(EVVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len,
                      const uint8_t *in, int in_len) {
  int i, j, bl;

  if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
    i = ctx->cipher->cipher(ctx, out, in, in_len);
    if (i < 0) {
      return 0;
    } else {
      *out_len = i;
    }
    return 1;
  }

  if (in_len <= 0) {
    *out_len = 0;
    return in_len == 0;
  }

  if (ctx->buf_len == 0 && (in_len & ctx->block_mask) == 0) {
    if (ctx->cipher->cipher(ctx, out, in, in_len)) {
      *out_len = in_len;
      return 1;
    } else {
      *out_len = 0;
      return 0;
    }
  }

  i = ctx->buf_len;
  bl = ctx->cipher->block_size;
  assert(bl <= (int)sizeof(ctx->buf));
  if (i != 0) {
    if (bl - i > in_len) {
      OPENSSL_memcpy(&ctx->buf[i], in, in_len);
      ctx->buf_len += in_len;
      *out_len = 0;
      return 1;
    } else {
      j = bl - i;
      OPENSSL_memcpy(&ctx->buf[i], in, j);
      if (!ctx->cipher->cipher(ctx, out, ctx->buf, bl)) {
        return 0;
      }
      in_len -= j;
      in += j;
      out += bl;
      *out_len = bl;
    }
  } else {
    *out_len = 0;
  }

  i = in_len & ctx->block_mask;
  in_len -= i;
  if (in_len > 0) {
    if (!ctx->cipher->cipher(ctx, out, in, in_len)) {
      return 0;
    }
    *out_len += in_len;
  }

  if (i != 0) {
    OPENSSL_memcpy(ctx->buf, &in[in_len], i);
  }
  ctx->buf_len = i;
  return 1;
}

int EVVP_EncryptFinal_ex(EVVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len) {
  int n, ret;
  unsigned int i, b, bl;

  if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
    ret = ctx->cipher->cipher(ctx, out, NULL, 0);
    if (ret < 0) {
      return 0;
    } else {
      *out_len = ret;
    }
    return 1;
  }

  b = ctx->cipher->block_size;
  assert(b <= sizeof(ctx->buf));
  if (b == 1) {
    *out_len = 0;
    return 1;
  }

  bl = ctx->buf_len;
  if (ctx->flags & EVVP_CIPH_NO_PADDING) {
    if (bl) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
      return 0;
    }
    *out_len = 0;
    return 1;
  }

  n = b - bl;
  for (i = bl; i < b; i++) {
    ctx->buf[i] = n;
  }
  ret = ctx->cipher->cipher(ctx, out, ctx->buf, b);

  if (ret) {
    *out_len = b;
  }

  return ret;
}

int EVVP_DecryptUpdate(EVVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len,
                      const uint8_t *in, int in_len) {
  int fix_len;
  unsigned int b;

  if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
    int r = ctx->cipher->cipher(ctx, out, in, in_len);
    if (r < 0) {
      *out_len = 0;
      return 0;
    } else {
      *out_len = r;
    }
    return 1;
  }

  if (in_len <= 0) {
    *out_len = 0;
    return in_len == 0;
  }

  if (ctx->flags & EVVP_CIPH_NO_PADDING) {
    return EVVP_EncryptUpdate(ctx, out, out_len, in, in_len);
  }

  b = ctx->cipher->block_size;
  assert(b <= sizeof(ctx->final));

  if (ctx->final_used) {
    OPENSSL_memcpy(out, ctx->final, b);
    out += b;
    fix_len = 1;
  } else {
    fix_len = 0;
  }

  if (!EVVP_EncryptUpdate(ctx, out, out_len, in, in_len)) {
    return 0;
  }

  /* if we have 'decrypted' a multiple of block size, make sure
   * we have a copy of this last block */
  if (b > 1 && !ctx->buf_len) {
    *out_len -= b;
    ctx->final_used = 1;
    OPENSSL_memcpy(ctx->final, &out[*out_len], b);
  } else {
    ctx->final_used = 0;
  }

  if (fix_len) {
    *out_len += b;
  }

  return 1;
}

int EVVP_DecryptFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len) {
  int i, n;
  unsigned int b;
  *out_len = 0;

  if (ctx->cipher->flags & EVVP_CIPH_FLAG_CUSTOM_CIPHER) {
    i = ctx->cipher->cipher(ctx, out, NULL, 0);
    if (i < 0) {
      return 0;
    } else {
      *out_len = i;
    }
    return 1;
  }

  b = ctx->cipher->block_size;
  if (ctx->flags & EVVP_CIPH_NO_PADDING) {
    if (ctx->buf_len) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
      return 0;
    }
    *out_len = 0;
    return 1;
  }

  if (b > 1) {
    if (ctx->buf_len || !ctx->final_used) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_WRONG_FINAL_BLOCK_LENGTH);
      return 0;
    }
    assert(b <= sizeof(ctx->final));

    /* The following assumes that the ciphertext has been authenticated.
     * Otherwise it provides a padding oracle. */
    n = ctx->final[b - 1];
    if (n == 0 || n > (int)b) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
      return 0;
    }

    for (i = 0; i < n; i++) {
      if (ctx->final[--b] != n) {
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
        return 0;
      }
    }

    n = ctx->cipher->block_size - n;
    for (i = 0; i < n; i++) {
      out[i] = ctx->final[i];
    }
    *out_len = n;
  } else {
    *out_len = 0;
  }

  return 1;
}

int EVVP_Cipher(EVVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
               size_t in_len) {
  return ctx->cipher->cipher(ctx, out, in, in_len);
}

int EVVP_CipherUpdate(EVVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len,
                     const uint8_t *in, int in_len) {
  if (ctx->encrypt) {
    return EVVP_EncryptUpdate(ctx, out, out_len, in, in_len);
  } else {
    return EVVP_DecryptUpdate(ctx, out, out_len, in, in_len);
  }
}

int EVVP_CipherFinal_ex(EVVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len) {
  if (ctx->encrypt) {
    return EVVP_EncryptFinal_ex(ctx, out, out_len);
  } else {
    return EVVP_DecryptFinal_ex(ctx, out, out_len);
  }
}

const EVVP_CIPHER *EVVP_CIPHER_CTX_cipher(const EVVP_CIPHER_CTX *ctx) {
  return ctx->cipher;
}

int EVVP_CIPHER_CTX_nid(const EVVP_CIPHER_CTX *ctx) {
  return ctx->cipher->nid;
}

unsigned EVVP_CIPHER_CTX_block_size(const EVVP_CIPHER_CTX *ctx) {
  return ctx->cipher->block_size;
}

unsigned EVVP_CIPHER_CTX_key_length(const EVVP_CIPHER_CTX *ctx) {
  return ctx->key_len;
}

unsigned EVVP_CIPHER_CTX_iv_length(const EVVP_CIPHER_CTX *ctx) {
  return ctx->cipher->iv_len;
}

void *EVVP_CIPHER_CTX_get_app_data(const EVVP_CIPHER_CTX *ctx) {
  return ctx->app_data;
}

void EVVP_CIPHER_CTX_set_app_data(EVVP_CIPHER_CTX *ctx, void *data) {
  ctx->app_data = data;
}

uint32_t EVVP_CIPHER_CTX_flags(const EVVP_CIPHER_CTX *ctx) {
  return ctx->cipher->flags & ~EVVP_CIPH_MODE_MASK;
}

uint32_t EVVP_CIPHER_CTX_mode(const EVVP_CIPHER_CTX *ctx) {
  return ctx->cipher->flags & EVVP_CIPH_MODE_MASK;
}

int EVVP_CIPHER_CTX_ctrl(EVVP_CIPHER_CTX *ctx, int command, int arg, void *ptr) {
  int ret;
  if (!ctx->cipher) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_NO_CIPHER_SET);
    return 0;
  }

  if (!ctx->cipher->ctrl) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_CTRL_NOT_IMPLEMENTED);
    return 0;
  }

  ret = ctx->cipher->ctrl(ctx, command, arg, ptr);
  if (ret == -1) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_CTRL_OPERATION_NOT_IMPLEMENTED);
    return 0;
  }

  return ret;
}

int EVVP_CIPHER_CTX_set_padding(EVVP_CIPHER_CTX *ctx, int pad) {
  if (pad) {
    ctx->flags &= ~EVVP_CIPH_NO_PADDING;
  } else {
    ctx->flags |= EVVP_CIPH_NO_PADDING;
  }
  return 1;
}

int EVVP_CIPHER_CTX_set_key_length(EVVP_CIPHER_CTX *c, unsigned key_len) {
  if (c->key_len == key_len) {
    return 1;
  }

  if (key_len == 0 || !(c->cipher->flags & EVVP_CIPH_VARIABLE_LENGTH)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_KEY_LENGTH);
    return 0;
  }

  c->key_len = key_len;
  return 1;
}

int EVVP_CIPHER_nid(const EVVP_CIPHER *cipher) { return cipher->nid; }

unsigned EVVP_CIPHER_block_size(const EVVP_CIPHER *cipher) {
  return cipher->block_size;
}

unsigned EVVP_CIPHER_key_length(const EVVP_CIPHER *cipher) {
  return cipher->key_len;
}

unsigned EVVP_CIPHER_iv_length(const EVVP_CIPHER *cipher) {
  return cipher->iv_len;
}

uint32_t EVVP_CIPHER_flags(const EVVP_CIPHER *cipher) {
  return cipher->flags & ~EVVP_CIPH_MODE_MASK;
}

uint32_t EVVP_CIPHER_mode(const EVVP_CIPHER *cipher) {
  return cipher->flags & EVVP_CIPH_MODE_MASK;
}

int EVVP_CipherInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                   const uint8_t *key, const uint8_t *iv, int enc) {
  if (cipher) {
    EVVP_CIPHER_CTX_init(ctx);
  }
  return EVVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
}

int EVVP_EncryptInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                    const uint8_t *key, const uint8_t *iv) {
  return EVVP_CipherInit(ctx, cipher, key, iv, 1);
}

int EVVP_DecryptInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                    const uint8_t *key, const uint8_t *iv) {
  return EVVP_CipherInit(ctx, cipher, key, iv, 0);
}

int EVVP_add_cipher_alias(const char *a, const char *b) {
  return 1;
}

const EVVP_CIPHER *EVVP_get_cipherbyname(const char *name) {
  if (OPENSSL_strcasecmp(name, "rc4") == 0) {
    return EVVP_rc4();
  } else if (OPENSSL_strcasecmp(name, "des-cbc") == 0) {
    return EVVP_des_cbc();
  } else if (OPENSSL_strcasecmp(name, "des-ede3-cbc") == 0 ||
             OPENSSL_strcasecmp(name, "3des") == 0) {
    return EVVP_des_ede3_cbc();
  } else if (OPENSSL_strcasecmp(name, "aes-128-cbc") == 0) {
    return EVVP_aes_128_cbc();
  } else if (OPENSSL_strcasecmp(name, "aes-256-cbc") == 0) {
    return EVVP_aes_256_cbc();
  } else if (OPENSSL_strcasecmp(name, "aes-128-ctr") == 0) {
    return EVVP_aes_128_ctr();
  } else if (OPENSSL_strcasecmp(name, "aes-256-ctr") == 0) {
    return EVVP_aes_256_ctr();
  } else if (OPENSSL_strcasecmp(name, "aes-128-ecb") == 0) {
    return EVVP_aes_128_ecb();
  } else if (OPENSSL_strcasecmp(name, "aes-256-ecb") == 0) {
    return EVVP_aes_256_ecb();
  }

  return NULL;
}
