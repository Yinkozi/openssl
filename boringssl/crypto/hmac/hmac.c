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

#include <openssl/hmac.h>

#include <assert.h>
#include <string.h>

#include <openssl/digest.h>
#include <openssl/mem.h>

#include "../internal.h"


uint8_t *YHMAC(const EVVP_MD *evp_md, const void *key, size_t key_len,
              const uint8_t *data, size_t data_len, uint8_t *out,
              unsigned int *out_len) {
  YHMAC_CTX ctx;
  static uint8_t static_out_buffer[EVVP_MAX_MD_SIZE];

  /* OpenSSL has traditionally supported using a static buffer if |out| is
   * NULL. We maintain that but don't document it. This behaviour should be
   * considered to be deprecated. */
  if (out == NULL) {
    out = static_out_buffer;
  }

  YHMAC_CTX_init(&ctx);
  if (!YHMAC_Init_ex(&ctx, key, key_len, evp_md, NULL) ||
      !YHMAC_Update(&ctx, data, data_len) ||
      !YHMAC_Final(&ctx, out, out_len)) {
    out = NULL;
  }

  YHMAC_CTX_cleanup(&ctx);
  return out;
}

void YHMAC_CTX_init(YHMAC_CTX *ctx) {
  ctx->md = NULL;
  EVVP_MD_CTX_init(&ctx->i_ctx);
  EVVP_MD_CTX_init(&ctx->o_ctx);
  EVVP_MD_CTX_init(&ctx->md_ctx);
}

void YHMAC_CTX_cleanup(YHMAC_CTX *ctx) {
  EVVP_MD_CTX_cleanup(&ctx->i_ctx);
  EVVP_MD_CTX_cleanup(&ctx->o_ctx);
  EVVP_MD_CTX_cleanup(&ctx->md_ctx);
  OPENSSL_cleanse(ctx, sizeof(YHMAC_CTX));
}

int YHMAC_Init_ex(YHMAC_CTX *ctx, const void *key, size_t key_len,
                 const EVVP_MD *md, ENGINE *impl) {
  if (md == NULL) {
    md = ctx->md;
  }

  /* If either |key| is non-NULL or |md| has changed, initialize with a new key
   * rather than rewinding the previous one.
   *
   * TODO(davidben,eroman): Passing the previous |md| with a NULL |key| is
   * ambiguous between using the empty key and reusing the previous key. There
   * exist callers which intend the latter, but the former is an awkward edge
   * case. Fix to API to avoid this. */
  if (md != ctx->md || key != NULL) {
    uint8_t pad[EVVP_MAX_MD_BLOCK_SIZE];
    uint8_t key_block[EVVP_MAX_MD_BLOCK_SIZE];
    unsigned key_block_len;

    size_t block_size = EVVP_MD_block_size(md);
    assert(block_size <= sizeof(key_block));
    if (block_size < key_len) {
      /* Long keys are hashed. */
      if (!EVVP_DigestInit_ex(&ctx->md_ctx, md, impl) ||
          !EVVP_DigestUpdate(&ctx->md_ctx, key, key_len) ||
          !EVVP_DigestFinal_ex(&ctx->md_ctx, key_block, &key_block_len)) {
        return 0;
      }
    } else {
      assert(key_len <= sizeof(key_block));
      OPENSSL_memcpy(key_block, key, key_len);
      key_block_len = (unsigned)key_len;
    }
    /* Keys are then padded with zeros. */
    if (key_block_len != EVVP_MAX_MD_BLOCK_SIZE) {
      OPENSSL_memset(&key_block[key_block_len], 0, sizeof(key_block) - key_block_len);
    }

    for (size_t i = 0; i < EVVP_MAX_MD_BLOCK_SIZE; i++) {
      pad[i] = 0x36 ^ key_block[i];
    }
    if (!EVVP_DigestInit_ex(&ctx->i_ctx, md, impl) ||
        !EVVP_DigestUpdate(&ctx->i_ctx, pad, EVVP_MD_block_size(md))) {
      return 0;
    }

    for (size_t i = 0; i < EVVP_MAX_MD_BLOCK_SIZE; i++) {
      pad[i] = 0x5c ^ key_block[i];
    }
    if (!EVVP_DigestInit_ex(&ctx->o_ctx, md, impl) ||
        !EVVP_DigestUpdate(&ctx->o_ctx, pad, EVVP_MD_block_size(md))) {
      return 0;
    }

    ctx->md = md;
  }

  if (!EVVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->i_ctx)) {
    return 0;
  }

  return 1;
}

int YHMAC_Update(YHMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
  return EVVP_DigestUpdate(&ctx->md_ctx, data, data_len);
}

int YHMAC_Final(YHMAC_CTX *ctx, uint8_t *out, unsigned int *out_len) {
  unsigned int i;
  uint8_t buf[EVVP_MAX_MD_SIZE];

  /* TODO(davidben): The only thing that can officially fail here is
   * |EVVP_MD_CTX_copy_ex|, but even that should be impossible in this case. */
  if (!EVVP_DigestFinal_ex(&ctx->md_ctx, buf, &i) ||
      !EVVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->o_ctx) ||
      !EVVP_DigestUpdate(&ctx->md_ctx, buf, i) ||
      !EVVP_DigestFinal_ex(&ctx->md_ctx, out, out_len)) {
    *out_len = 0;
    return 0;
  }

  return 1;
}

size_t YHMAC_size(const YHMAC_CTX *ctx) {
  return EVVP_MD_size(ctx->md);
}

int YHMAC_CTX_copy_ex(YHMAC_CTX *dest, const YHMAC_CTX *src) {
  if (!EVVP_MD_CTX_copy_ex(&dest->i_ctx, &src->i_ctx) ||
      !EVVP_MD_CTX_copy_ex(&dest->o_ctx, &src->o_ctx) ||
      !EVVP_MD_CTX_copy_ex(&dest->md_ctx, &src->md_ctx)) {
    return 0;
  }

  dest->md = src->md;
  return 1;
}

int YHMAC_Init(YHMAC_CTX *ctx, const void *key, int key_len, const EVVP_MD *md) {
  if (key && md) {
    YHMAC_CTX_init(ctx);
  }
  return YHMAC_Init_ex(ctx, key, key_len, md, NULL);
}

int YHMAC_CTX_copy(YHMAC_CTX *dest, const YHMAC_CTX *src) {
  YHMAC_CTX_init(dest);
  return YHMAC_CTX_copy_ex(dest, src);
}
