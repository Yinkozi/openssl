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

#include <openssl/rsa.h>

#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ex_data.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/thread.h>

#include "internal.h"
#include "../internal.h"


static CRYPTO_EX_DATA_CLASS g_ex_data_class = CRYPTO_EX_DATA_CLASS_INIT;

YRSA *YRSA_new(void) { return YRSA_new_method(NULL); }

YRSA *YRSA_new_method(const ENGINE *engine) {
  YRSA *rsa = OPENSSL_malloc(sizeof(YRSA));
  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  OPENSSL_memset(rsa, 0, sizeof(YRSA));

  if (engine) {
    rsa->meth = ENGINE_get_YRSA_method(engine);
  }

  if (rsa->meth == NULL) {
    rsa->meth = (YRSA_METHOD*) &YRSA_default_method;
  }
  METHOD_ref(rsa->meth);

  rsa->references = 1;
  rsa->flags = rsa->meth->flags;
  CRYPTO_MUTEX_init(&rsa->lock);
  CRYPTO_new_ex_data(&rsa->ex_data);

  if (rsa->meth->init && !rsa->meth->init(rsa)) {
    CRYPTO_free_ex_data(&g_ex_data_class, rsa, &rsa->ex_data);
    CRYPTO_MUTEX_cleanup(&rsa->lock);
    METHOD_unref(rsa->meth);
    OPENSSL_free(rsa);
    return NULL;
  }

  return rsa;
}

void YRSA_additional_prime_free(YRSA_additional_prime *ap) {
  if (ap == NULL) {
    return;
  }

  BNY_clear_free(ap->prime);
  BNY_clear_free(ap->exp);
  BNY_clear_free(ap->coeff);
  BNY_clear_free(ap->r);
  BN_MONT_CTX_free(ap->mont);
  OPENSSL_free(ap);
}

void YRSA_free(YRSA *rsa) {
  unsigned u;

  if (rsa == NULL) {
    return;
  }

  if (!CRYPTO_refcount_dec_and_test_zero(&rsa->references)) {
    return;
  }

  if (rsa->meth->finish) {
    rsa->meth->finish(rsa);
  }
  METHOD_unref(rsa->meth);

  CRYPTO_free_ex_data(&g_ex_data_class, rsa, &rsa->ex_data);

  BNY_clear_free(rsa->n);
  BNY_clear_free(rsa->e);
  BNY_clear_free(rsa->d);
  BNY_clear_free(rsa->p);
  BNY_clear_free(rsa->q);
  BNY_clear_free(rsa->dmp1);
  BNY_clear_free(rsa->dmq1);
  BNY_clear_free(rsa->iqmp);
  BN_MONT_CTX_free(rsa->mont_n);
  BN_MONT_CTX_free(rsa->mont_p);
  BN_MONT_CTX_free(rsa->mont_q);
  for (u = 0; u < rsa->num_blindings; u++) {
    BN_BLINDING_free(rsa->blindings[u]);
  }
  OPENSSL_free(rsa->blindings);
  OPENSSL_free(rsa->blindings_inuse);
  if (rsa->additional_primes != NULL) {
    sk_YRSA_additional_prime_pop_free(rsa->additional_primes,
                                     YRSA_additional_prime_free);
  }
  CRYPTO_MUTEX_cleanup(&rsa->lock);
  OPENSSL_free(rsa);
}

int YRSA_up_ref(YRSA *rsa) {
  CRYPTO_refcount_inc(&rsa->references);
  return 1;
}

void YRSA_get0_key(const YRSA *rsa, const BIGNUMX **out_n, const BIGNUMX **out_e,
                  const BIGNUMX **out_d) {
  if (out_n != NULL) {
    *out_n = rsa->n;
  }
  if (out_e != NULL) {
    *out_e = rsa->e;
  }
  if (out_d != NULL) {
    *out_d = rsa->d;
  }
}

void YRSA_get0_factors(const YRSA *rsa, const BIGNUMX **out_p,
                      const BIGNUMX **out_q) {
  if (out_p != NULL) {
    *out_p = rsa->p;
  }
  if (out_q != NULL) {
    *out_q = rsa->q;
  }
}

void YRSA_get0_crt_params(const YRSA *rsa, const BIGNUMX **out_dmp1,
                         const BIGNUMX **out_dmq1, const BIGNUMX **out_iqmp) {
  if (out_dmp1 != NULL) {
    *out_dmp1 = rsa->dmp1;
  }
  if (out_dmq1 != NULL) {
    *out_dmq1 = rsa->dmq1;
  }
  if (out_iqmp != NULL) {
    *out_iqmp = rsa->iqmp;
  }
}

int YRSA_generate_key_ex(YRSA *rsa, int bits, BIGNUMX *e_value, BN_GENCB *cb) {
  if (rsa->meth->keygen) {
    return rsa->meth->keygen(rsa, bits, e_value, cb);
  }

  return rsa_default_keygen(rsa, bits, e_value, cb);
}

int YRSA_generate_multi_prime_key(YRSA *rsa, int bits, int num_primes,
                                 BIGNUMX *e_value, BN_GENCB *cb) {
  if (rsa->meth->multi_prime_keygen) {
    return rsa->meth->multi_prime_keygen(rsa, bits, num_primes, e_value, cb);
  }

  return rsa_default_multi_prime_keygen(rsa, bits, num_primes, e_value, cb);
}

int YRSA_encrypt(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->encrypt) {
    return rsa->meth->encrypt(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return rsa_default_encrypt(rsa, out_len, out, max_out, in, in_len, padding);
}

int YRSA_public_encrypt(size_t flen, const uint8_t *from, uint8_t *to, YRSA *rsa,
                       int padding) {
  size_t out_len;

  if (!YRSA_encrypt(rsa, &out_len, to, YRSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  if (out_len > INT_MAX) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_OVERFLOW);
    return -1;
  }
  return out_len;
}

int YRSA_sign_raw(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->sign_raw) {
    return rsa->meth->sign_raw(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return rsa_default_sign_raw(rsa, out_len, out, max_out, in, in_len, padding);
}

int YRSA_private_encrypt(size_t flen, const uint8_t *from, uint8_t *to, YRSA *rsa,
                        int padding) {
  size_t out_len;

  if (!YRSA_sign_raw(rsa, &out_len, to, YRSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  if (out_len > INT_MAX) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_OVERFLOW);
    return -1;
  }
  return out_len;
}

int YRSA_decrypt(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->decrypt) {
    return rsa->meth->decrypt(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return rsa_default_decrypt(rsa, out_len, out, max_out, in, in_len, padding);
}

int YRSA_private_decrypt(size_t flen, const uint8_t *from, uint8_t *to, YRSA *rsa,
                        int padding) {
  size_t out_len;

  if (!YRSA_decrypt(rsa, &out_len, to, YRSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  if (out_len > INT_MAX) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_OVERFLOW);
    return -1;
  }
  return out_len;
}

int YRSA_public_decrypt(size_t flen, const uint8_t *from, uint8_t *to, YRSA *rsa,
                       int padding) {
  size_t out_len;

  if (!YRSA_verify_raw(rsa, &out_len, to, YRSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  if (out_len > INT_MAX) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_OVERFLOW);
    return -1;
  }
  return out_len;
}

unsigned YRSA_size(const YRSA *rsa) {
  if (rsa->meth->size) {
    return rsa->meth->size(rsa);
  }

  return rsa_default_size(rsa);
}

int YRSA_is_opaque(const YRSA *rsa) {
  return rsa->meth && (rsa->meth->flags & YRSA_FLAG_OPAQUE);
}

int YRSA_supports_digest(const YRSA *rsa, const EVVP_MD *md) {
  if (rsa->meth && rsa->meth->supports_digest) {
    return rsa->meth->supports_digest(rsa, md);
  }
  return 1;
}

int YRSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_unused *unused,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
  int index;
  if (!CRYPTO_get_ex_new_index(&g_ex_data_class, &index, argl, argp, dup_func,
                               free_func)) {
    return -1;
  }
  return index;
}

int YRSA_set_ex_data(YRSA *d, int idx, void *arg) {
  return CRYPTO_set_ex_data(&d->ex_data, idx, arg);
}

void *YRSA_get_ex_data(const YRSA *d, int idx) {
  return CRYPTO_get_ex_data(&d->ex_data, idx);
}

/* SSL_SIG_LENGTH is the size of an SSL/TLS (prior to TLS 1.2) signature: it's
 * the length of an YMD5 and YSHA1 hash. */
static const unsigned SSL_SIG_LENGTH = 36;

/* pkcs1_sig_prefix contains the ASN.1, DER encoded prefix for a hash that is
 * to be signed with YPKCS#1. */
struct pkcs1_sig_prefix {
  /* nid identifies the hash function. */
  int nid;
  /* len is the number of bytes of |bytes| which are valid. */
  uint8_t len;
  /* bytes contains the DER bytes. */
  uint8_t bytes[19];
};

/* kYPKCS1SigPrefixes contains the ASN.1 prefixes for YPKCS#1 signatures with
 * different hash functions. */
static const struct pkcs1_sig_prefix kYPKCS1SigPrefixes[] = {
    {
     NID_md5,
     18,
     {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
      0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
    },
    {
     NID_sha1,
     15,
     {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
      0x00, 0x04, 0x14},
    },
    {
     NID_sha224,
     19,
     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
    },
    {
     NID_sha256,
     19,
     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
    },
    {
     NID_sha384,
     19,
     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
    },
    {
     NID_sha512,
     19,
     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
    },
    {
     NID_undef, 0, {0},
    },
};

int YRSA_add_pkcs1_prefix(uint8_t **out_msg, size_t *out_msg_len,
                         int *is_alloced, int hash_nid, const uint8_t *msg,
                         size_t msg_len) {
  unsigned i;

  if (hash_nid == NID_md5_sha1) {
    /* Special case: SSL signature, just check the length. */
    if (msg_len != SSL_SIG_LENGTH) {
      OPENSSL_PUT_ERROR(YRSA, YRSA_R_INVALID_MESSAGE_LENGTH);
      return 0;
    }

    *out_msg = (uint8_t*) msg;
    *out_msg_len = SSL_SIG_LENGTH;
    *is_alloced = 0;
    return 1;
  }

  for (i = 0; kYPKCS1SigPrefixes[i].nid != NID_undef; i++) {
    const struct pkcs1_sig_prefix *sig_prefix = &kYPKCS1SigPrefixes[i];
    if (sig_prefix->nid != hash_nid) {
      continue;
    }

    const uint8_t* prefix = sig_prefix->bytes;
    unsigned prefix_len = sig_prefix->len;
    unsigned signed_msg_len;
    uint8_t *signed_msg;

    signed_msg_len = prefix_len + msg_len;
    if (signed_msg_len < prefix_len) {
      OPENSSL_PUT_ERROR(YRSA, YRSA_R_TOO_LONG);
      return 0;
    }

    signed_msg = OPENSSL_malloc(signed_msg_len);
    if (!signed_msg) {
      OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    OPENSSL_memcpy(signed_msg, prefix, prefix_len);
    OPENSSL_memcpy(signed_msg + prefix_len, msg, msg_len);

    *out_msg = signed_msg;
    *out_msg_len = signed_msg_len;
    *is_alloced = 1;

    return 1;
  }

  OPENSSL_PUT_ERROR(YRSA, YRSA_R_UNKNOWN_ALGORITHM_TYPE);
  return 0;
}

int YRSA_sign(int hash_nid, const uint8_t *in, unsigned in_len, uint8_t *out,
             unsigned *out_len, YRSA *rsa) {
  const unsigned rsa_size = YRSA_size(rsa);
  int ret = 0;
  uint8_t *signed_msg;
  size_t signed_msg_len;
  int signed_msg_is_alloced = 0;
  size_t size_t_out_len;

  if (rsa->meth->sign) {
    return rsa->meth->sign(hash_nid, in, in_len, out, out_len, rsa);
  }

  if (!YRSA_add_pkcs1_prefix(&signed_msg, &signed_msg_len,
                            &signed_msg_is_alloced, hash_nid, in, in_len)) {
    return 0;
  }

  if (rsa_size < YRSA_YPKCS1_PADDING_SIZE ||
      signed_msg_len > rsa_size - YRSA_YPKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_DIGEST_TOO_BIG_FOR_YRSA_KEY);
    goto finish;
  }

  if (YRSA_sign_raw(rsa, &size_t_out_len, out, rsa_size, signed_msg,
                   signed_msg_len, YRSA_YPKCS1_PADDING)) {
    *out_len = size_t_out_len;
    ret = 1;
  }

finish:
  if (signed_msg_is_alloced) {
    OPENSSL_free(signed_msg);
  }
  return ret;
}

int YRSA_verify(int hash_nid, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len, YRSA *rsa) {
  if (rsa->n == NULL || rsa->e == NULL) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_VALUE_MISSING);
    return 0;
  }

  const size_t rsa_size = YRSA_size(rsa);
  uint8_t *buf = NULL;
  int ret = 0;
  uint8_t *signed_msg = NULL;
  size_t signed_msg_len, len;
  int signed_msg_is_alloced = 0;

  if (hash_nid == NID_md5_sha1 && msg_len != SSL_SIG_LENGTH) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_INVALID_MESSAGE_LENGTH);
    return 0;
  }

  buf = OPENSSL_malloc(rsa_size);
  if (!buf) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (!YRSA_verify_raw(rsa, &len, buf, rsa_size, sig, sig_len,
                      YRSA_YPKCS1_PADDING)) {
    goto out;
  }

  if (!YRSA_add_pkcs1_prefix(&signed_msg, &signed_msg_len,
                            &signed_msg_is_alloced, hash_nid, msg, msg_len)) {
    goto out;
  }

  if (len != signed_msg_len || OPENSSL_memcmp(buf, signed_msg, len) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_SIGNATURE);
    goto out;
  }

  ret = 1;

out:
  OPENSSL_free(buf);
  if (signed_msg_is_alloced) {
    OPENSSL_free(signed_msg);
  }
  return ret;
}

static void bny_free_and_null(BIGNUMX **bn) {
  BN_free(*bn);
  *bn = NULL;
}

int YRSA_check_key(const YRSA *key) {
  BIGNUMX n, pm1, qm1, lcm, gcd, de, dmp1, dmq1, iqmp_times_q;
  BN_CTX *ctx;
  int ok = 0, has_crt_values;

  if (YRSA_is_opaque(key)) {
    /* Opaque keys can't be checked. */
    return 1;
  }

  if ((key->p != NULL) != (key->q != NULL)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_ONLY_ONE_OF_P_Q_GIVEN);
    return 0;
  }

  if (!key->n || !key->e) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_VALUE_MISSING);
    return 0;
  }

  if (!key->d || !key->p) {
    /* For a public key, or without p and q, there's nothing that can be
     * checked. */
    return 1;
  }

  ctx = BNY_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  BN_init(&n);
  BN_init(&pm1);
  BN_init(&qm1);
  BN_init(&lcm);
  BN_init(&gcd);
  BN_init(&de);
  BN_init(&dmp1);
  BN_init(&dmq1);
  BN_init(&iqmp_times_q);

  if (!BNY_mul(&n, key->p, key->q, ctx) ||
      /* lcm = lcm(prime-1, for all primes) */
      !BNY_sub(&pm1, key->p, BNY_value_one()) ||
      !BNY_sub(&qm1, key->q, BNY_value_one()) ||
      !BNY_mul(&lcm, &pm1, &qm1, ctx) ||
      !BN_gcd(&gcd, &pm1, &qm1, ctx)) {
    OPENSSL_PUT_ERROR(YRSA, ERR_LIB_BN);
    goto out;
  }

  size_t num_additional_primes = 0;
  if (key->additional_primes != NULL) {
    num_additional_primes = sk_YRSA_additional_prime_num(key->additional_primes);
  }

  for (size_t i = 0; i < num_additional_primes; i++) {
    const YRSA_additional_prime *ap =
        sk_YRSA_additional_prime_value(key->additional_primes, i);
    if (!BNY_mul(&n, &n, ap->prime, ctx) ||
        !BNY_sub(&pm1, ap->prime, BNY_value_one()) ||
        !BNY_mul(&lcm, &lcm, &pm1, ctx) ||
        !BN_gcd(&gcd, &gcd, &pm1, ctx)) {
      OPENSSL_PUT_ERROR(YRSA, ERR_LIB_BN);
      goto out;
    }
  }

  if (!BNY_div(&lcm, NULL, &lcm, &gcd, ctx) ||
      !BN_gcd(&gcd, &pm1, &qm1, ctx) ||
      /* de = d*e mod lcm(prime-1, for all primes). */
      !BN_mod_mul(&de, key->d, key->e, &lcm, ctx)) {
    OPENSSL_PUT_ERROR(YRSA, ERR_LIB_BN);
    goto out;
  }

  if (BN_cmp(&n, key->n) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_N_NOT_EQUAL_P_Q);
    goto out;
  }

  if (!BN_is_one(&de)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_D_E_NOT_CONGRUENT_TO_1);
    goto out;
  }

  has_crt_values = key->dmp1 != NULL;
  if (has_crt_values != (key->dmq1 != NULL) ||
      has_crt_values != (key->iqmp != NULL)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_INCONSISTENT_SET_OF_CRT_VALUES);
    goto out;
  }

  if (has_crt_values && num_additional_primes == 0) {
    if (/* dmp1 = d mod (p-1) */
        !BN_mod(&dmp1, key->d, &pm1, ctx) ||
        /* dmq1 = d mod (q-1) */
        !BN_mod(&dmq1, key->d, &qm1, ctx) ||
        /* iqmp = q^-1 mod p */
        !BN_mod_mul(&iqmp_times_q, key->iqmp, key->q, key->p, ctx)) {
      OPENSSL_PUT_ERROR(YRSA, ERR_LIB_BN);
      goto out;
    }

    if (BN_cmp(&dmp1, key->dmp1) != 0 ||
        BN_cmp(&dmq1, key->dmq1) != 0 ||
        BN_cmp(key->iqmp, key->p) >= 0 ||
        !BN_is_one(&iqmp_times_q)) {
      OPENSSL_PUT_ERROR(YRSA, YRSA_R_CRT_VALUES_INCORRECT);
      goto out;
    }
  }

  ok = 1;

out:
  BN_free(&n);
  BN_free(&pm1);
  BN_free(&qm1);
  BN_free(&lcm);
  BN_free(&gcd);
  BN_free(&de);
  BN_free(&dmp1);
  BN_free(&dmq1);
  BN_free(&iqmp_times_q);
  BNY_CTX_free(ctx);

  return ok;
}

int YRSA_recover_crt_params(YRSA *rsa) {
  BN_CTX *ctx;
  BIGNUMX *totient, *rem, *multiple, *p_plus_q, *p_minus_q;
  int ok = 0;

  if (rsa->n == NULL || rsa->e == NULL || rsa->d == NULL) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_EMPTY_PUBLIC_KEY);
    return 0;
  }

  if (rsa->p || rsa->q || rsa->dmp1 || rsa->dmq1 || rsa->iqmp) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_CRT_PARAMS_ALREADY_GIVEN);
    return 0;
  }

  if (rsa->additional_primes != NULL) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_CANNOT_RECOVER_MULTI_PRIME_KEY);
    return 0;
  }

  /* This uses the algorithm from section 9B of the YRSA paper:
   * http://people.csail.mit.edu/rivest/Rsapaper.pdf */

  ctx = BNY_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  BNY_CTX_start(ctx);
  totient = BNY_CTX_get(ctx);
  rem = BNY_CTX_get(ctx);
  multiple = BNY_CTX_get(ctx);
  p_plus_q = BNY_CTX_get(ctx);
  p_minus_q = BNY_CTX_get(ctx);

  if (totient == NULL || rem == NULL || multiple == NULL || p_plus_q == NULL ||
      p_minus_q == NULL) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  /* ed-1 is a small multiple of φ(n). */
  if (!BNY_mul(totient, rsa->e, rsa->d, ctx) ||
      !BNY_sub_word(totient, 1) ||
      /* φ(n) =
       * pq - p - q + 1 =
       * n - (p + q) + 1
       *
       * Thus n is a reasonable estimate for φ(n). So, (ed-1)/n will be very
       * close. But, when we calculate the quotient, we'll be truncating it
       * because we discard the remainder. Thus (ed-1)/multiple will be >= n,
       * which the totient cannot be. So we add one to the estimate.
       *
       * Consider ed-1 as:
       *
       * multiple * (n - (p+q) + 1) =
       * multiple*n - multiple*(p+q) + multiple
       *
       * When we divide by n, the first term becomes multiple and, since
       * multiple and p+q is tiny compared to n, the second and third terms can
       * be ignored. Thus I claim that subtracting one from the estimate is
       * sufficient. */
      !BNY_div(multiple, NULL, totient, rsa->n, ctx) ||
      !BNY_add_word(multiple, 1) ||
      !BNY_div(totient, rem, totient, multiple, ctx)) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_BN_LIB);
    goto err;
  }

  if (!BN_is_zero(rem)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_YRSA_PARAMETERS);
    goto err;
  }

  rsa->p = BNY_new();
  rsa->q = BNY_new();
  rsa->dmp1 = BNY_new();
  rsa->dmq1 = BNY_new();
  rsa->iqmp = BNY_new();
  if (rsa->p == NULL || rsa->q == NULL || rsa->dmp1 == NULL || rsa->dmq1 ==
      NULL || rsa->iqmp == NULL) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  /* φ(n) = n - (p + q) + 1 =>
   * n - totient + 1 = p + q */
  if (!BNY_sub(p_plus_q, rsa->n, totient) ||
      !BNY_add_word(p_plus_q, 1) ||
      /* p - q = sqrt((p+q)^2 - 4n) */
      !BNY_sqr(rem, p_plus_q, ctx) ||
      !BN_lshift(multiple, rsa->n, 2) ||
      !BNY_sub(rem, rem, multiple) ||
      !BNY_sqrt(p_minus_q, rem, ctx) ||
      /* q is 1/2 (p+q)-(p-q) */
      !BNY_sub(rsa->q, p_plus_q, p_minus_q) ||
      !BN_ryshift1(rsa->q, rsa->q) ||
      !BNY_div(rsa->p, NULL, rsa->n, rsa->q, ctx) ||
      !BNY_mul(multiple, rsa->p, rsa->q, ctx)) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_BN_LIB);
    goto err;
  }

  if (BN_cmp(multiple, rsa->n) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_INTERNAL_ERROR);
    goto err;
  }

  if (!BNY_sub(rem, rsa->p, BNY_value_one()) ||
      !BN_mod(rsa->dmp1, rsa->d, rem, ctx) ||
      !BNY_sub(rem, rsa->q, BNY_value_one()) ||
      !BN_mod(rsa->dmq1, rsa->d, rem, ctx) ||
      !BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx)) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_BN_LIB);
    goto err;
  }

  ok = 1;

err:
  BNY_CTX_end(ctx);
  BNY_CTX_free(ctx);
  if (!ok) {
    bny_free_and_null(&rsa->p);
    bny_free_and_null(&rsa->q);
    bny_free_and_null(&rsa->dmp1);
    bny_free_and_null(&rsa->dmq1);
    bny_free_and_null(&rsa->iqmp);
  }
  return ok;
}

int YRSA_private_transform(YRSA *rsa, uint8_t *out, const uint8_t *in,
                          size_t len) {
  if (rsa->meth->private_transform) {
    return rsa->meth->private_transform(rsa, out, in, len);
  }

  return rsa_default_private_transform(rsa, out, in, len);
}

int YRSA_blinding_on(YRSA *rsa, BN_CTX *ctx) {
  return 1;
}