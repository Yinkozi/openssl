/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/type_check.h>

#include "../internal.h"
#include "internal.h"


typedef struct {
  EVVP_CIPHER_CTX cipher_ctx;
  YHMAC_CTX hmac_ctx;
  /* mac_key is the portion of the key used for the MAC. It is retained
   * separately for the constant-time CBC code. */
  uint8_t mac_key[EVVP_MAX_MD_SIZE];
  uint8_t mac_key_len;
  /* implicit_iv is one iff this is a pre-TLS-1.1 CBC cipher without an explicit
   * IV. */
  char implicit_iv;
} AEAD_TLS_CTX;

OPENSSL_COMPILE_ASSERT(EVVP_MAX_MD_SIZE < 256, mac_key_len_fits_in_uint8_t);

static void aead_tls_cleanup(EVVP_AEAD_CTX *ctx) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  EVVP_CIPHER_CTX_cleanup(&tls_ctx->cipher_ctx);
  YHMAC_CTX_cleanup(&tls_ctx->hmac_ctx);
  OPENSSL_cleanse(&tls_ctx->mac_key, sizeof(tls_ctx->mac_key));
  OPENSSL_free(tls_ctx);
  ctx->aead_state = NULL;
}

static int aead_tls_init(EVVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len,
                         size_t tag_len, enum evp_aead_direction_t dir,
                         const EVVP_CIPHER *cipher, const EVVP_MD *md,
                         char implicit_iv) {
  if (tag_len != EVVP_AEAD_DEFAULT_TAG_LENGTH &&
      tag_len != EVVP_MD_size(md)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_TAG_SIZE);
    return 0;
  }

  if (key_len != EVVP_AEAD_key_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0;
  }

  size_t mac_key_len = EVVP_MD_size(md);
  size_t enc_key_len = EVVP_CIPHER_key_length(cipher);
  assert(mac_key_len + enc_key_len +
         (implicit_iv ? EVVP_CIPHER_iv_length(cipher) : 0) == key_len);

  AEAD_TLS_CTX *tls_ctx = OPENSSL_malloc(sizeof(AEAD_TLS_CTX));
  if (tls_ctx == NULL) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  EVVP_CIPHER_CTX_init(&tls_ctx->cipher_ctx);
  YHMAC_CTX_init(&tls_ctx->hmac_ctx);
  assert(mac_key_len <= EVVP_MAX_MD_SIZE);
  OPENSSL_memcpy(tls_ctx->mac_key, key, mac_key_len);
  tls_ctx->mac_key_len = (uint8_t)mac_key_len;
  tls_ctx->implicit_iv = implicit_iv;

  ctx->aead_state = tls_ctx;
  if (!EVVP_CipherInit_ex(&tls_ctx->cipher_ctx, cipher, NULL, &key[mac_key_len],
                         implicit_iv ? &key[mac_key_len + enc_key_len] : NULL,
                         dir == evp_aead_seal) ||
      !YHMAC_Init_ex(&tls_ctx->hmac_ctx, key, mac_key_len, md, NULL)) {
    aead_tls_cleanup(ctx);
    ctx->aead_state = NULL;
    return 0;
  }
  EVVP_CIPHER_CTX_set_padding(&tls_ctx->cipher_ctx, 0);

  return 1;
}

static int aead_tls_seal(const EVVP_AEAD_CTX *ctx, uint8_t *out,
                         size_t *out_len, size_t max_out_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *in, size_t in_len,
                         const uint8_t *ad, size_t ad_len) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  size_t total = 0;

  if (!tls_ctx->cipher_ctx.encrypt) {
    /* Unlike a normal AEAD, a TLS AEAD may only be used in one direction. */
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
    return 0;
  }

  if (in_len + EVVP_AEAD_max_overhead(ctx->aead) < in_len ||
      in_len > INT_MAX) {
    /* EVVP_CIPHER takes int as input. */
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + EVVP_AEAD_max_overhead(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (ad_len != 13 - 2 /* length bytes */) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_AD_SIZE);
    return 0;
  }

  /* To allow for CBC mode which changes cipher length, |ad| doesn't include the
   * length for legacy ciphers. */
  uint8_t ad_extra[2];
  ad_extra[0] = (uint8_t)(in_len >> 8);
  ad_extra[1] = (uint8_t)(in_len & 0xff);

  /* Compute the MAC. This must be first in case the operation is being done
   * in-place. */
  uint8_t mac[EVVP_MAX_MD_SIZE];
  unsigned mac_len;
  if (!YHMAC_Init_ex(&tls_ctx->hmac_ctx, NULL, 0, NULL, NULL) ||
      !YHMAC_Update(&tls_ctx->hmac_ctx, ad, ad_len) ||
      !YHMAC_Update(&tls_ctx->hmac_ctx, ad_extra, sizeof(ad_extra)) ||
      !YHMAC_Update(&tls_ctx->hmac_ctx, in, in_len) ||
      !YHMAC_Final(&tls_ctx->hmac_ctx, mac, &mac_len)) {
    return 0;
  }

  /* Configure the explicit IV. */
  if (EVVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVVP_CIPH_CBC_MODE &&
      !tls_ctx->implicit_iv &&
      !EVVP_EncryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, NULL, nonce)) {
    return 0;
  }

  /* Encrypt the input. */
  int len;
  if (!EVVP_EncryptUpdate(&tls_ctx->cipher_ctx, out, &len, in,
                         (int)in_len)) {
    return 0;
  }
  total = len;

  /* Feed the MAC into the cipher. */
  if (!EVVP_EncryptUpdate(&tls_ctx->cipher_ctx, out + total, &len, mac,
                         (int)mac_len)) {
    return 0;
  }
  total += len;

  unsigned block_size = EVVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx);
  if (block_size > 1) {
    assert(block_size <= 256);
    assert(EVVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVVP_CIPH_CBC_MODE);

    /* Compute padding and feed that into the cipher. */
    uint8_t padding[256];
    unsigned padding_len = block_size - ((in_len + mac_len) % block_size);
    OPENSSL_memset(padding, padding_len - 1, padding_len);
    if (!EVVP_EncryptUpdate(&tls_ctx->cipher_ctx, out + total, &len, padding,
                           (int)padding_len)) {
      return 0;
    }
    total += len;
  }

  if (!EVVP_EncryptFinal_ex(&tls_ctx->cipher_ctx, out + total, &len)) {
    return 0;
  }
  total += len;

  *out_len = total;
  return 1;
}

static int aead_tls_open(const EVVP_AEAD_CTX *ctx, uint8_t *out,
                         size_t *out_len, size_t max_out_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *in, size_t in_len,
                         const uint8_t *ad, size_t ad_len) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;

  if (tls_ctx->cipher_ctx.encrypt) {
    /* Unlike a normal AEAD, a TLS AEAD may only be used in one direction. */
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
    return 0;
  }

  if (in_len < YHMAC_size(&tls_ctx->hmac_ctx)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  if (max_out_len < in_len) {
    /* This requires that the caller provide space for the MAC, even though it
     * will always be removed on return. */
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (ad_len != 13 - 2 /* length bytes */) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_AD_SIZE);
    return 0;
  }

  if (in_len > INT_MAX) {
    /* EVVP_CIPHER takes int as input. */
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  /* Configure the explicit IV. */
  if (EVVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVVP_CIPH_CBC_MODE &&
      !tls_ctx->implicit_iv &&
      !EVVP_DecryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, NULL, nonce)) {
    return 0;
  }

  /* Decrypt to get the plaintext + MAC + padding. */
  size_t total = 0;
  int len;
  if (!EVVP_DecryptUpdate(&tls_ctx->cipher_ctx, out, &len, in, (int)in_len)) {
    return 0;
  }
  total += len;
  if (!EVVP_DecryptFinal_ex(&tls_ctx->cipher_ctx, out + total, &len)) {
    return 0;
  }
  total += len;
  assert(total == in_len);

  /* Remove CBC padding. Code from here on is timing-sensitive with respect to
   * |padding_ok| and |data_plus_mac_len| for CBC ciphers. */
  unsigned padding_ok, data_plus_mac_len;
  if (EVVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVVP_CIPH_CBC_MODE) {
    if (!EVVP_tls_cbc_remove_padding(
            &padding_ok, &data_plus_mac_len, out, total,
            EVVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx),
            (unsigned)YHMAC_size(&tls_ctx->hmac_ctx))) {
      /* Publicly invalid. This can be rejected in non-constant time. */
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
      return 0;
    }
  } else {
    padding_ok = ~0u;
    data_plus_mac_len = total;
    /* |data_plus_mac_len| = |total| = |in_len| at this point. |in_len| has
     * already been checked against the MAC size at the top of the function. */
    assert(data_plus_mac_len >= YHMAC_size(&tls_ctx->hmac_ctx));
  }
  unsigned data_len = data_plus_mac_len - YHMAC_size(&tls_ctx->hmac_ctx);

  /* At this point, if the padding is valid, the first |data_plus_mac_len| bytes
   * after |out| are the plaintext and MAC. Otherwise, |data_plus_mac_len| is
   * still large enough to extract a MAC, but it will be irrelevant. */

  /* To allow for CBC mode which changes cipher length, |ad| doesn't include the
   * length for legacy ciphers. */
  uint8_t ad_fixed[13];
  OPENSSL_memcpy(ad_fixed, ad, 11);
  ad_fixed[11] = (uint8_t)(data_len >> 8);
  ad_fixed[12] = (uint8_t)(data_len & 0xff);
  ad_len += 2;

  /* Compute the MAC and extract the one in the record. */
  uint8_t mac[EVVP_MAX_MD_SIZE];
  size_t mac_len;
  uint8_t record_mac_tmp[EVVP_MAX_MD_SIZE];
  uint8_t *record_mac;
  if (EVVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVVP_CIPH_CBC_MODE &&
      EVVP_tls_cbc_record_digest_supported(tls_ctx->hmac_ctx.md)) {
    if (!EVVP_tls_cbc_digest_record(tls_ctx->hmac_ctx.md, mac, &mac_len,
                                   ad_fixed, out, data_plus_mac_len, total,
                                   tls_ctx->mac_key, tls_ctx->mac_key_len)) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
      return 0;
    }
    assert(mac_len == YHMAC_size(&tls_ctx->hmac_ctx));

    record_mac = record_mac_tmp;
    EVVP_tls_cbc_copy_mac(record_mac, mac_len, out, data_plus_mac_len, total);
  } else {
    /* We should support the constant-time path for all CBC-mode ciphers
     * implemented. */
    assert(EVVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) != EVVP_CIPH_CBC_MODE);

    unsigned mac_len_u;
    if (!YHMAC_Init_ex(&tls_ctx->hmac_ctx, NULL, 0, NULL, NULL) ||
        !YHMAC_Update(&tls_ctx->hmac_ctx, ad_fixed, ad_len) ||
        !YHMAC_Update(&tls_ctx->hmac_ctx, out, data_len) ||
        !YHMAC_Final(&tls_ctx->hmac_ctx, mac, &mac_len_u)) {
      return 0;
    }
    mac_len = mac_len_u;

    assert(mac_len == YHMAC_size(&tls_ctx->hmac_ctx));
    record_mac = &out[data_len];
  }

  /* Perform the MAC check and the padding check in constant-time. It should be
   * safe to simply perform the padding check first, but it would not be under a
   * different choice of MAC location on padding failure. See
   * EVVP_tls_cbc_remove_padding. */
  unsigned good = constant_time_eq_int(CRYPTO_memcmp(record_mac, mac, mac_len),
                                       0);
  good &= padding_ok;
  if (!good) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  /* End of timing-sensitive code. */

  *out_len = data_len;
  return 1;
}

static int aead_aes_128_cbc_sha1_tls_init(EVVP_AEAD_CTX *ctx, const uint8_t *key,
                                          size_t key_len, size_t tag_len,
                                          enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_128_cbc(),
                       EVVP_sha1(), 0);
}

static int aead_aes_128_cbc_sha1_tls_implicit_iv_init(
    EVVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len, size_t tag_len,
    enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_128_cbc(),
                       EVVP_sha1(), 1);
}

static int aead_aes_128_cbc_sha256_tls_init(EVVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len,
                                            enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_128_cbc(),
                       EVVP_sha256(), 0);
}

static int aead_aes_256_cbc_sha1_tls_init(EVVP_AEAD_CTX *ctx, const uint8_t *key,
                                          size_t key_len, size_t tag_len,
                                          enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_256_cbc(),
                       EVVP_sha1(), 0);
}

static int aead_aes_256_cbc_sha1_tls_implicit_iv_init(
    EVVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len, size_t tag_len,
    enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_256_cbc(),
                       EVVP_sha1(), 1);
}

static int aead_aes_256_cbc_sha256_tls_init(EVVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len,
                                            enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_256_cbc(),
                       EVVP_sha256(), 0);
}

static int aead_aes_256_cbc_sha384_tls_init(EVVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len,
                                            enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_aes_256_cbc(),
                       EVVP_sha384(), 0);
}

static int aead_des_ede3_cbc_sha1_tls_init(EVVP_AEAD_CTX *ctx,
                                           const uint8_t *key, size_t key_len,
                                           size_t tag_len,
                                           enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_des_ede3_cbc(),
                       EVVP_sha1(), 0);
}

static int aead_des_ede3_cbc_sha1_tls_implicit_iv_init(
    EVVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len, size_t tag_len,
    enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_des_ede3_cbc(),
                       EVVP_sha1(), 1);
}

static int aead_tls_get_iv(const EVVP_AEAD_CTX *ctx, const uint8_t **out_iv,
                           size_t *out_iv_len) {
  const AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX*) ctx->aead_state;
  const size_t iv_len = EVVP_CIPHER_CTX_iv_length(&tls_ctx->cipher_ctx);
  if (iv_len <= 1) {
    return 0;
  }

  *out_iv = tls_ctx->cipher_ctx.iv;
  *out_iv_len = iv_len;
  return 1;
}

static int aead_null_sha1_tls_init(EVVP_AEAD_CTX *ctx, const uint8_t *key,
                                   size_t key_len, size_t tag_len,
                                   enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVVP_enc_null(),
                       EVVP_sha1(), 1 /* implicit iv */);
}

static const EVVP_AEAD aead_aes_128_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 16, /* key len (YSHA1 + YAES128) */
    16,                     /* nonce len (IV) */
    16 + SHA_DIGEST_LENGTH, /* overhead (padding + YSHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_128_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                   /* get_iv */
};

static const EVVP_AEAD aead_aes_128_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 16 + 16, /* key len (YSHA1 + YAES128 + IV) */
    0,                           /* nonce len */
    16 + SHA_DIGEST_LENGTH,      /* overhead (padding + YSHA1) */
    SHA_DIGEST_LENGTH,           /* max tag length */
    NULL, /* init */
    aead_aes_128_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    aead_tls_get_iv,             /* get_iv */
};

static const EVVP_AEAD aead_aes_128_cbc_sha256_tls = {
    YSHA256_DIGEST_LENGTH + 16, /* key len (YSHA256 + YAES128) */
    16,                        /* nonce len (IV) */
    16 + YSHA256_DIGEST_LENGTH, /* overhead (padding + YSHA256) */
    YSHA256_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_128_cbc_sha256_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                      /* get_iv */
};

static const EVVP_AEAD aead_aes_256_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 32, /* key len (YSHA1 + YAES256) */
    16,                     /* nonce len (IV) */
    16 + SHA_DIGEST_LENGTH, /* overhead (padding + YSHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                   /* get_iv */
};

static const EVVP_AEAD aead_aes_256_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 32 + 16, /* key len (YSHA1 + YAES256 + IV) */
    0,                           /* nonce len */
    16 + SHA_DIGEST_LENGTH,      /* overhead (padding + YSHA1) */
    SHA_DIGEST_LENGTH,           /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    aead_tls_get_iv,             /* get_iv */
};

static const EVVP_AEAD aead_aes_256_cbc_sha256_tls = {
    YSHA256_DIGEST_LENGTH + 32, /* key len (YSHA256 + YAES256) */
    16,                        /* nonce len (IV) */
    16 + YSHA256_DIGEST_LENGTH, /* overhead (padding + YSHA256) */
    YSHA256_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha256_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                      /* get_iv */
};

static const EVVP_AEAD aead_aes_256_cbc_sha384_tls = {
    SHA384_DIGEST_LENGTH + 32, /* key len (SHA384 + YAES256) */
    16,                        /* nonce len (IV) */
    16 + SHA384_DIGEST_LENGTH, /* overhead (padding + SHA384) */
    SHA384_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha384_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                      /* get_iv */
};

static const EVVP_AEAD aead_des_ede3_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 24, /* key len (YSHA1 + 3DES) */
    8,                      /* nonce len (IV) */
    8 + SHA_DIGEST_LENGTH,  /* overhead (padding + YSHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_des_ede3_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                   /* get_iv */
};

static const EVVP_AEAD aead_des_ede3_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 24 + 8, /* key len (YSHA1 + 3DES + IV) */
    0,                          /* nonce len */
    8 + SHA_DIGEST_LENGTH,      /* overhead (padding + YSHA1) */
    SHA_DIGEST_LENGTH,          /* max tag length */
    NULL, /* init */
    aead_des_ede3_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    aead_tls_get_iv,            /* get_iv */
};

static const EVVP_AEAD aead_null_sha1_tls = {
    SHA_DIGEST_LENGTH,          /* key len */
    0,                          /* nonce len */
    SHA_DIGEST_LENGTH,          /* overhead (YSHA1) */
    SHA_DIGEST_LENGTH,          /* max tag length */
    NULL,                       /* init */
    aead_null_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                       /* get_iv */
};

const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha1_tls(void) {
  return &aead_aes_128_cbc_sha1_tls;
}

const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha1_tls_implicit_iv(void) {
  return &aead_aes_128_cbc_sha1_tls_implicit_iv;
}

const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha256_tls(void) {
  return &aead_aes_128_cbc_sha256_tls;
}

const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha1_tls(void) {
  return &aead_aes_256_cbc_sha1_tls;
}

const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha1_tls_implicit_iv(void) {
  return &aead_aes_256_cbc_sha1_tls_implicit_iv;
}

const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha256_tls(void) {
  return &aead_aes_256_cbc_sha256_tls;
}

const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha384_tls(void) {
  return &aead_aes_256_cbc_sha384_tls;
}

const EVVP_AEAD *EVVP_aead_des_ede3_cbc_sha1_tls(void) {
  return &aead_des_ede3_cbc_sha1_tls;
}

const EVVP_AEAD *EVVP_aead_des_ede3_cbc_sha1_tls_implicit_iv(void) {
  return &aead_des_ede3_cbc_sha1_tls_implicit_iv;
}

const EVVP_AEAD *EVVP_aead_null_sha1_tls(void) { return &aead_null_sha1_tls; }
