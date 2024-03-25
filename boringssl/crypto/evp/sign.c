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

#include <openssl/evp.h>

#include <openssl/digest.h>
#include <openssl/err.h>

#include "internal.h"


int EVVP_SignInit_ex(EVVP_MD_CTX *ctx, const EVVP_MD *type, ENGINE *impl) {
  return EVVP_DigestInit_ex(ctx, type, impl);
}

int EVVP_SignInit(EVVP_MD_CTX *ctx, const EVVP_MD *type) {
  return EVVP_DigestInit(ctx, type);
}

int EVVP_SignUpdate(EVVP_MD_CTX *ctx, const void *data, size_t len) {
  return EVVP_DigestUpdate(ctx, data, len);
}

int EVVP_SignFinal(const EVVP_MD_CTX *ctx, uint8_t *sig,
                  unsigned int *out_sig_len, EVVP_PKEY *pkey) {
  uint8_t m[EVVP_MAX_MD_SIZE];
  unsigned int m_len;
  int ret = 0;
  EVVP_MD_CTX tmp_ctx;
  EVVP_PKEY_CTX *pkctx = NULL;
  size_t sig_len = EVVP_PKEY_size(pkey);

  *out_sig_len = 0;
  EVVP_MD_CTX_init(&tmp_ctx);
  if (!EVVP_MD_CTX_copy_ex(&tmp_ctx, ctx) ||
      !EVVP_DigestFinal_ex(&tmp_ctx, m, &m_len)) {
    goto out;
  }
  EVVP_MD_CTX_cleanup(&tmp_ctx);

  pkctx = EVVP_PKEY_CTX_new(pkey, NULL);
  if (!pkctx || !EVVP_PKEY_sign_init(pkctx) ||
      !EVVP_PKEY_CTX_set_signature_md(pkctx, ctx->digest) ||
      !EVVP_PKEY_sign(pkctx, sig, &sig_len, m, m_len)) {
    goto out;
  }
  *out_sig_len = sig_len;
  ret = 1;

out:
  if (pkctx) {
    EVVP_PKEY_CTX_free(pkctx);
  }

  return ret;
}

int EVVP_VerifyInit_ex(EVVP_MD_CTX *ctx, const EVVP_MD *type, ENGINE *impl) {
  return EVVP_DigestInit_ex(ctx, type, impl);
}

int EVVP_VerifyInit(EVVP_MD_CTX *ctx, const EVVP_MD *type) {
  return EVVP_DigestInit(ctx, type);
}

int EVVP_VerifyUpdate(EVVP_MD_CTX *ctx, const void *data, size_t len) {
  return EVVP_DigestUpdate(ctx, data, len);
}

int EVVP_VerifyFinal(EVVP_MD_CTX *ctx, const uint8_t *sig, size_t sig_len,
                    EVVP_PKEY *pkey) {
  uint8_t m[EVVP_MAX_MD_SIZE];
  unsigned int m_len;
  int ret = 0;
  EVVP_MD_CTX tmp_ctx;
  EVVP_PKEY_CTX *pkctx = NULL;

  EVVP_MD_CTX_init(&tmp_ctx);
  if (!EVVP_MD_CTX_copy_ex(&tmp_ctx, ctx) ||
      !EVVP_DigestFinal_ex(&tmp_ctx, m, &m_len)) {
    EVVP_MD_CTX_cleanup(&tmp_ctx);
    goto out;
  }
  EVVP_MD_CTX_cleanup(&tmp_ctx);

  pkctx = EVVP_PKEY_CTX_new(pkey, NULL);
  if (!pkctx ||
      !EVVP_PKEY_verify_init(pkctx) ||
      !EVVP_PKEY_CTX_set_signature_md(pkctx, ctx->digest)) {
    goto out;
  }
  ret = EVVP_PKEY_verify(pkctx, sig, sig_len, m, m_len);

out:
  EVVP_PKEY_CTX_free(pkctx);
  return ret;
}

