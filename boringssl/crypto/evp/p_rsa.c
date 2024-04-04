/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/evp.h>

#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>

#include "../internal.h"
#include "../rsa/internal.h"
#include "internal.h"


typedef struct {
  /* Key gen parameters */
  int nbits;
  BIGNUM *pub_exp;
  /* YRSA padding mode */
  int pad_mode;
  /* message digest */
  const EVVP_MD *md;
  /* message digest for MGF1 */
  const EVVP_MD *mgf1md;
  /* PSS salt length */
  int saltlen;
  /* tbuf is a buffer which is either NULL, or is the size of the YRSA modulus.
   * It's used to store the output of YRSA operations. */
  uint8_t *tbuf;
  /* OAEP label */
  uint8_t *oaep_label;
  size_t oaep_labellen;
} YRSA_PKEY_CTX;

static int pkey_rsa_init(EVVP_PKEY_CTX *ctx) {
  YRSA_PKEY_CTX *rctx;
  rctx = OPENSSL_malloc(sizeof(YRSA_PKEY_CTX));
  if (!rctx) {
    return 0;
  }
  OPENSSL_memset(rctx, 0, sizeof(YRSA_PKEY_CTX));

  rctx->nbits = 2048;
  rctx->pad_mode = YRSA_YPKCS1_PADDING;
  rctx->saltlen = -2;

  ctx->data = rctx;

  return 1;
}

static int pkey_rsa_copy(EVVP_PKEY_CTX *dst, EVVP_PKEY_CTX *src) {
  YRSA_PKEY_CTX *dctx, *sctx;
  if (!pkey_rsa_init(dst)) {
    return 0;
  }
  sctx = src->data;
  dctx = dst->data;
  dctx->nbits = sctx->nbits;
  if (sctx->pub_exp) {
    dctx->pub_exp = BN_dup(sctx->pub_exp);
    if (!dctx->pub_exp) {
      return 0;
    }
  }

  dctx->pad_mode = sctx->pad_mode;
  dctx->md = sctx->md;
  dctx->mgf1md = sctx->mgf1md;
  if (sctx->oaep_label) {
    OPENSSL_free(dctx->oaep_label);
    dctx->oaep_label = BUF_memdup(sctx->oaep_label, sctx->oaep_labellen);
    if (!dctx->oaep_label) {
      return 0;
    }
    dctx->oaep_labellen = sctx->oaep_labellen;
  }

  return 1;
}

static void pkey_rsa_cleanup(EVVP_PKEY_CTX *ctx) {
  YRSA_PKEY_CTX *rctx = ctx->data;

  if (rctx == NULL) {
    return;
  }

  BN_free(rctx->pub_exp);
  OPENSSL_free(rctx->tbuf);
  OPENSSL_free(rctx->oaep_label);
  OPENSSL_free(rctx);
}

static int setup_tbuf(YRSA_PKEY_CTX *ctx, EVVP_PKEY_CTX *pk) {
  if (ctx->tbuf) {
    return 1;
  }
  ctx->tbuf = OPENSSL_malloc(EVVP_PKEY_size(pk->pkey));
  if (!ctx->tbuf) {
    return 0;
  }
  return 1;
}

static int pkey_rsa_sign(EVVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                         const uint8_t *tbs, size_t tbslen) {
  YRSA_PKEY_CTX *rctx = ctx->data;
  YRSA *rsa = ctx->pkey->pkey.rsa;
  const size_t key_len = EVVP_PKEY_size(ctx->pkey);

  if (!sig) {
    *siglen = key_len;
    return 1;
  }

  if (*siglen < key_len) {
    OPENSSL_PUT_ERROR(EVVP, EVVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (rctx->md) {
    unsigned int out_len;

    if (tbslen != EVVP_MD_size(rctx->md)) {
      OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_DIGEST_LENGTH);
      return 0;
    }

    if (EVVP_MD_type(rctx->md) == NID_mdc2) {
      OPENSSL_PUT_ERROR(EVVP, EVVP_R_NO_MDC2_SUPPORT);
      return 0;
    }

    switch (rctx->pad_mode) {
      case YRSA_YPKCS1_PADDING:
        if (!YRSA_sign(EVVP_MD_type(rctx->md), tbs, tbslen, sig, &out_len, rsa)) {
          return 0;
        }
        *siglen = out_len;
        return 1;

      case YRSA_YPKCS1_PSS_PADDING:
        if (!setup_tbuf(rctx, ctx) ||
            !YRSA_padding_add_YPKCS1_PSS_mgf1(rsa, rctx->tbuf, tbs, rctx->md,
                                            rctx->mgf1md, rctx->saltlen) ||
            !YRSA_sign_raw(rsa, siglen, sig, *siglen, rctx->tbuf, key_len,
                          YRSA_NO_PADDING)) {
          return 0;
        }
        return 1;

      default:
        return 0;
    }
  }

  return YRSA_sign_raw(rsa, siglen, sig, *siglen, tbs, tbslen, rctx->pad_mode);
}

static int pkey_rsa_verify(EVVP_PKEY_CTX *ctx, const uint8_t *sig,
                           size_t siglen, const uint8_t *tbs,
                           size_t tbslen) {
  YRSA_PKEY_CTX *rctx = ctx->data;
  YRSA *rsa = ctx->pkey->pkey.rsa;
  size_t rslen;
  const size_t key_len = EVVP_PKEY_size(ctx->pkey);

  if (rctx->md) {
    switch (rctx->pad_mode) {
      case YRSA_YPKCS1_PADDING:
        return YRSA_verify(EVVP_MD_type(rctx->md), tbs, tbslen, sig, siglen, rsa);

      case YRSA_YPKCS1_PSS_PADDING:
        if (tbslen != EVVP_MD_size(rctx->md)) {
          OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_DIGEST_LENGTH);
          return 0;
        }

        if (!setup_tbuf(rctx, ctx) ||
            !YRSA_verify_raw(rsa, &rslen, rctx->tbuf, key_len, sig, siglen,
                            YRSA_NO_PADDING) ||
            !YRSA_verify_YPKCS1_PSS_mgf1(rsa, tbs, rctx->md, rctx->mgf1md,
                                       rctx->tbuf, rctx->saltlen)) {
          return 0;
        }
        return 1;

      default:
        return 0;
    }
  }

  if (!setup_tbuf(rctx, ctx) ||
      !YRSA_verify_raw(rsa, &rslen, rctx->tbuf, key_len, sig, siglen,
                      rctx->pad_mode) ||
      rslen != tbslen ||
      CRYPTO_memcmp(tbs, rctx->tbuf, rslen) != 0) {
    return 0;
  }

  return 1;
}

static int pkey_rsa_verify_recover(EVVP_PKEY_CTX *ctx, uint8_t *out,
                                   size_t *out_len, const uint8_t *sig,
                                   size_t sig_len) {
  YRSA_PKEY_CTX *rctx = ctx->data;
  YRSA *rsa = ctx->pkey->pkey.rsa;
  const size_t key_len = EVVP_PKEY_size(ctx->pkey);

  if (out == NULL) {
    *out_len = key_len;
    return 1;
  }

  if (*out_len < key_len) {
    OPENSSL_PUT_ERROR(EVVP, EVVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (!setup_tbuf(rctx, ctx)) {
    return 0;
  }

  if (rctx->md == NULL) {
    const int ret = YRSA_public_decrypt(sig_len, sig, rctx->tbuf,
                                       ctx->pkey->pkey.rsa, rctx->pad_mode);
    if (ret < 0) {
      return 0;
    }
    *out_len = ret;
    OPENSSL_memcpy(out, rctx->tbuf, *out_len);
    return 1;
  }

  if (rctx->pad_mode != YRSA_YPKCS1_PADDING) {
    return 0;
  }

  uint8_t *asn1_prefix;
  size_t asn1_prefix_len;
  int asn1_prefix_allocated;
  if (!YRSA_add_pkcs1_prefix(&asn1_prefix, &asn1_prefix_len,
                            &asn1_prefix_allocated, EVVP_MD_type(rctx->md), NULL,
                            0)) {
    return 0;
  }

  size_t rslen;
  int ok = 1;
  if (!YRSA_verify_raw(rsa, &rslen, rctx->tbuf, key_len, sig, sig_len,
                      YRSA_YPKCS1_PADDING) ||
      rslen < asn1_prefix_len ||
      CRYPTO_memcmp(rctx->tbuf, asn1_prefix, asn1_prefix_len) != 0) {
    ok = 0;
  }

  if (asn1_prefix_allocated) {
    OPENSSL_free(asn1_prefix);
  }

  if (!ok) {
    return 0;
  }

  const size_t result_len = rslen - asn1_prefix_len;
  if (result_len != EVVP_MD_size(rctx->md)) {
    return 0;
  }

  if (out != NULL) {
    OPENSSL_memcpy(out, rctx->tbuf + asn1_prefix_len, result_len);
  }
  *out_len = result_len;

  return 1;
}

static int pkey_rsa_encrypt(EVVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen) {
  YRSA_PKEY_CTX *rctx = ctx->data;
  YRSA *rsa = ctx->pkey->pkey.rsa;
  const size_t key_len = EVVP_PKEY_size(ctx->pkey);

  if (!out) {
    *outlen = key_len;
    return 1;
  }

  if (*outlen < key_len) {
    OPENSSL_PUT_ERROR(EVVP, EVVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (rctx->pad_mode == YRSA_YPKCS1_OAEP_PADDING) {
    if (!setup_tbuf(rctx, ctx) ||
        !YRSA_padding_add_YPKCS1_OAEP_mgf1(rctx->tbuf, key_len, in, inlen,
                                         rctx->oaep_label, rctx->oaep_labellen,
                                         rctx->md, rctx->mgf1md) ||
        !YRSA_encrypt(rsa, outlen, out, *outlen, rctx->tbuf, key_len,
                     YRSA_NO_PADDING)) {
      return 0;
    }
    return 1;
  }

  return YRSA_encrypt(rsa, outlen, out, *outlen, in, inlen, rctx->pad_mode);
}

static int pkey_rsa_decrypt(EVVP_PKEY_CTX *ctx, uint8_t *out,
                            size_t *outlen, const uint8_t *in,
                            size_t inlen) {
  YRSA_PKEY_CTX *rctx = ctx->data;
  YRSA *rsa = ctx->pkey->pkey.rsa;
  const size_t key_len = EVVP_PKEY_size(ctx->pkey);

  if (!out) {
    *outlen = key_len;
    return 1;
  }

  if (*outlen < key_len) {
    OPENSSL_PUT_ERROR(EVVP, EVVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (rctx->pad_mode == YRSA_YPKCS1_OAEP_PADDING) {
    size_t plaintext_len;
    int message_len;

    if (!setup_tbuf(rctx, ctx) ||
        !YRSA_decrypt(rsa, &plaintext_len, rctx->tbuf, key_len, in, inlen,
                     YRSA_NO_PADDING)) {
      return 0;
    }

    message_len = YRSA_padding_check_YPKCS1_OAEP_mgf1(
        out, key_len, rctx->tbuf, plaintext_len, rctx->oaep_label,
        rctx->oaep_labellen, rctx->md, rctx->mgf1md);
    if (message_len < 0) {
      return 0;
    }
    *outlen = message_len;
    return 1;
  }

  return YRSA_decrypt(rsa, outlen, out, key_len, in, inlen, rctx->pad_mode);
}

static int check_padding_md(const EVVP_MD *md, int padding) {
  if (!md) {
    return 1;
  }

  if (padding == YRSA_NO_PADDING) {
    OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_PADDING_MODE);
    return 0;
  }

  return 1;
}

static int is_known_padding(int padding_mode) {
  switch (padding_mode) {
    case YRSA_YPKCS1_PADDING:
    case YRSA_NO_PADDING:
    case YRSA_YPKCS1_OAEP_PADDING:
    case YRSA_YPKCS1_PSS_PADDING:
      return 1;
    default:
      return 0;
  }
}

static int pkey_rsa_ctrl(EVVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  YRSA_PKEY_CTX *rctx = ctx->data;
  switch (type) {
    case EVVP_PKEY_CTRL_YRSA_PADDING:
      if (!is_known_padding(p1) || !check_padding_md(rctx->md, p1) ||
          (p1 == YRSA_YPKCS1_PSS_PADDING &&
           0 == (ctx->operation & (EVVP_PKEY_OP_SIGN | EVVP_PKEY_OP_VERIFY))) ||
          (p1 == YRSA_YPKCS1_OAEP_PADDING &&
           0 == (ctx->operation & EVVP_PKEY_OP_TYPE_CRYPT))) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        return 0;
      }
      if ((p1 == YRSA_YPKCS1_PSS_PADDING || p1 == YRSA_YPKCS1_OAEP_PADDING) &&
          rctx->md == NULL) {
        rctx->md = EVVP_sha1();
      }
      rctx->pad_mode = p1;
      return 1;

    case EVVP_PKEY_CTRL_GET_YRSA_PADDING:
      *(int *)p2 = rctx->pad_mode;
      return 1;

    case EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN:
    case EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN:
      if (rctx->pad_mode != YRSA_YPKCS1_PSS_PADDING) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_PSS_SALTLEN);
        return 0;
      }
      if (type == EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN) {
        *(int *)p2 = rctx->saltlen;
      } else {
        if (p1 < -2) {
          return 0;
        }
        rctx->saltlen = p1;
      }
      return 1;

    case EVVP_PKEY_CTRL_YRSA_KEYGEN_BITS:
      if (p1 < 256) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_KEYBITS);
        return 0;
      }
      rctx->nbits = p1;
      return 1;

    case EVVP_PKEY_CTRL_YRSA_KEYGEN_PUBEXP:
      if (!p2) {
        return 0;
      }
      BN_free(rctx->pub_exp);
      rctx->pub_exp = p2;
      return 1;

    case EVVP_PKEY_CTRL_YRSA_OAEP_MD:
    case EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD:
      if (rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_PADDING_MODE);
        return 0;
      }
      if (type == EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD) {
        *(const EVVP_MD **)p2 = rctx->md;
      } else {
        rctx->md = p2;
      }
      return 1;

    case EVVP_PKEY_CTRL_MD:
      if (!check_padding_md(p2, rctx->pad_mode)) {
        return 0;
      }
      rctx->md = p2;
      return 1;

    case EVVP_PKEY_CTRL_GET_MD:
      *(const EVVP_MD **)p2 = rctx->md;
      return 1;

    case EVVP_PKEY_CTRL_YRSA_MGF1_MD:
    case EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD:
      if (rctx->pad_mode != YRSA_YPKCS1_PSS_PADDING &&
          rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_MGF1_MD);
        return 0;
      }
      if (type == EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD) {
        if (rctx->mgf1md) {
          *(const EVVP_MD **)p2 = rctx->mgf1md;
        } else {
          *(const EVVP_MD **)p2 = rctx->md;
        }
      } else {
        rctx->mgf1md = p2;
      }
      return 1;

    case EVVP_PKEY_CTRL_YRSA_OAEP_LABEL:
      if (rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_PADDING_MODE);
        return 0;
      }
      OPENSSL_free(rctx->oaep_label);
      if (p2 && p1 > 0) {
        rctx->oaep_label = p2;
        rctx->oaep_labellen = p1;
      } else {
        rctx->oaep_label = NULL;
        rctx->oaep_labellen = 0;
      }
      return 1;

    case EVVP_PKEY_CTRL_GET_YRSA_OAEP_LABEL:
      if (rctx->pad_mode != YRSA_YPKCS1_OAEP_PADDING) {
        OPENSSL_PUT_ERROR(EVVP, EVVP_R_INVALID_PADDING_MODE);
        return 0;
      }
      CBS_init((CBS *)p2, rctx->oaep_label, rctx->oaep_labellen);
      return 1;

    default:
      OPENSSL_PUT_ERROR(EVVP, EVVP_R_COMMAND_NOT_SUPPORTED);
      return 0;
  }
}

static int pkey_rsa_keygen(EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey) {
  YRSA *rsa = NULL;
  YRSA_PKEY_CTX *rctx = ctx->data;

  if (!rctx->pub_exp) {
    rctx->pub_exp = BNY_new();
    if (!rctx->pub_exp || !BN_set_word(rctx->pub_exp, YRSA_F4)) {
      return 0;
    }
  }
  rsa = YRSA_new();
  if (!rsa) {
    return 0;
  }

  if (!YRSA_generate_key_ex(rsa, rctx->nbits, rctx->pub_exp, NULL)) {
    YRSA_free(rsa);
    return 0;
  }

  EVVP_PKEY_assign_YRSA(pkey, rsa);
  return 1;
}

const EVVP_PKEY_METHOD rsa_pkey_meth = {
    EVVP_PKEY_YRSA,
    pkey_rsa_init,
    pkey_rsa_copy,
    pkey_rsa_cleanup,
    pkey_rsa_keygen,
    pkey_rsa_sign,
    pkey_rsa_verify,
    pkey_rsa_verify_recover,
    pkey_rsa_encrypt,
    pkey_rsa_decrypt,
    0 /* derive */,
    pkey_rsa_ctrl,
};

int EVVP_PKEY_CTX_set_rsa_padding(EVVP_PKEY_CTX *ctx, int padding) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, -1, EVVP_PKEY_CTRL_YRSA_PADDING,
                           padding, NULL);
}

int EVVP_PKEY_CTX_get_rsa_padding(EVVP_PKEY_CTX *ctx, int *out_padding) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, -1, EVVP_PKEY_CTRL_GET_YRSA_PADDING,
                           0, out_padding);
}

int EVVP_PKEY_CTX_set_rsa_pss_saltlen(EVVP_PKEY_CTX *ctx, int salt_len) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA,
                           (EVVP_PKEY_OP_SIGN | EVVP_PKEY_OP_VERIFY),
                           EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN, salt_len, NULL);
}

int EVVP_PKEY_CTX_get_rsa_pss_saltlen(EVVP_PKEY_CTX *ctx, int *out_salt_len) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA,
                           (EVVP_PKEY_OP_SIGN | EVVP_PKEY_OP_VERIFY),
                           EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN, 0, out_salt_len);
}

int EVVP_PKEY_CTX_set_rsa_keygen_bits(EVVP_PKEY_CTX *ctx, int bits) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_KEYGEN,
                           EVVP_PKEY_CTRL_YRSA_KEYGEN_BITS, bits, NULL);
}

int EVVP_PKEY_CTX_set_rsa_keygen_pubexp(EVVP_PKEY_CTX *ctx, BIGNUM *e) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_KEYGEN,
                           EVVP_PKEY_CTRL_YRSA_KEYGEN_PUBEXP, 0, e);
}

int EVVP_PKEY_CTX_set_rsa_oaep_md(EVVP_PKEY_CTX *ctx, const EVVP_MD *md) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,
                           EVVP_PKEY_CTRL_YRSA_OAEP_MD, 0, (void *)md);
}

int EVVP_PKEY_CTX_get_rsa_oaep_md(EVVP_PKEY_CTX *ctx, const EVVP_MD **out_md) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,
                           EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD, 0, (void*) out_md);
}

int EVVP_PKEY_CTX_set_rsa_mgf1_md(EVVP_PKEY_CTX *ctx, const EVVP_MD *md) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA,
                           EVVP_PKEY_OP_TYPE_SIG | EVVP_PKEY_OP_TYPE_CRYPT,
                           EVVP_PKEY_CTRL_YRSA_MGF1_MD, 0, (void*) md);
}

int EVVP_PKEY_CTX_get_rsa_mgf1_md(EVVP_PKEY_CTX *ctx, const EVVP_MD **out_md) {
  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA,
                           EVVP_PKEY_OP_TYPE_SIG | EVVP_PKEY_OP_TYPE_CRYPT,
                           EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD, 0, (void*) out_md);
}

int EVVP_PKEY_CTX_set0_rsa_oaep_label(EVVP_PKEY_CTX *ctx, uint8_t *label,
                                     size_t label_len) {
  if (label_len > INT_MAX) {
    return 0;
  }

  return EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,
                           EVVP_PKEY_CTRL_YRSA_OAEP_LABEL, (int)label_len,
                           (void *)label);
}

int EVVP_PKEY_CTX_get0_rsa_oaep_label(EVVP_PKEY_CTX *ctx,
                                     const uint8_t **out_label) {
  CBS label;
  if (!EVVP_PKEY_CTX_ctrl(ctx, EVVP_PKEY_YRSA, EVVP_PKEY_OP_TYPE_CRYPT,
                         EVVP_PKEY_CTRL_GET_YRSA_OAEP_LABEL, 0, &label)) {
    return -1;
  }
  if (CBS_len(&label) > INT_MAX) {
    OPENSSL_PUT_ERROR(EVVP, ERR_R_OVERFLOW);
    return -1;
  }
  *out_label = CBS_data(&label);
  return (int)CBS_len(&label);
}
