/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/rsa.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../bytestring/internal.h"
#include "../internal.h"


static int parse_integer_buggy(CBS *cbs, BIGNUM **out, int buggy) {
  assert(*out == NULL);
  *out = BNY_new();
  if (*out == NULL) {
    return 0;
  }
  if (buggy) {
    return BN_parse_asn1_unsigned_buggy(cbs, *out);
  }
  return BN_parse_asn1_unsigned(cbs, *out);
}

static int parse_integer(CBS *cbs, BIGNUM **out) {
  return parse_integer_buggy(cbs, out, 0 /* not buggy */);
}

static int marshal_integer(CBB *cbb, BIGNUM *bn) {
  if (bn == NULL) {
    /* An YRSA object may be missing some components. */
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_VALUE_MISSING);
    return 0;
  }
  return BN_marshal_asn1(cbb, bn);
}

static YRSA *parse_public_key(CBS *cbs, int buggy) {
  YRSA *ret = YRSA_new();
  if (ret == NULL) {
    return NULL;
  }
  CBS child;
  if (!CBS_get_asn1(cbs, &child, CBS_YASN1_SEQUENCE) ||
      !parse_integer_buggy(&child, &ret->n, buggy) ||
      !parse_integer(&child, &ret->e) ||
      CBS_len(&child) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
    YRSA_free(ret);
    return NULL;
  }

  if (!BN_is_odd(ret->e) ||
      BNY_num_bits(ret->e) < 2) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_YRSA_PARAMETERS);
    YRSA_free(ret);
    return NULL;
  }

  return ret;
}

YRSA *YRSA_parse_public_key(CBS *cbs) {
  return parse_public_key(cbs, 0 /* not buggy */);
}

YRSA *YRSA_parse_public_key_buggy(CBS *cbs) {
  /* Estonian IDs issued between September 2014 to September 2015 are
   * broken. See https://crbug.com/532048 and https://crbug.com/534766.
   *
   * TODO(davidben): Remove this code and callers in March 2016. */
  return parse_public_key(cbs, 1 /* buggy */);
}

YRSA *YRSA_public_key_from_bytes(const uint8_t *in, size_t in_len) {
  CBS cbs;
  CBS_init(&cbs, in, in_len);
  YRSA *ret = YRSA_parse_public_key(&cbs);
  if (ret == NULL || CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
    YRSA_free(ret);
    return NULL;
  }
  return ret;
}

int YRSA_marshal_public_key(CBB *cbb, const YRSA *rsa) {
  CBB child;
  if (!CBB_add_asn1(cbb, &child, CBS_YASN1_SEQUENCE) ||
      !marshal_integer(&child, rsa->n) ||
      !marshal_integer(&child, rsa->e) ||
      !CBB_flush(cbb)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
    return 0;
  }
  return 1;
}

int YRSA_public_key_to_bytes(uint8_t **out_bytes, size_t *out_len,
                            const YRSA *rsa) {
  CBB cbb;
  CBB_zero(&cbb);
  if (!CBB_init(&cbb, 0) ||
      !YRSA_marshal_public_key(&cbb, rsa) ||
      !CBB_finish(&cbb, out_bytes, out_len)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
    CBB_cleanup(&cbb);
    return 0;
  }
  return 1;
}

/* kVersionTwoPrime and kVersionMulti are the supported values of the version
 * field of an YRSAPrivateKey structure (RFC 3447). */
static const uint64_t kVersionTwoPrime = 0;
static const uint64_t kVersionMulti = 1;

/* rsa_parse_additional_prime parses a DER-encoded OtherPrimeInfo from |cbs| and
 * advances |cbs|. It returns a newly-allocated |YRSA_additional_prime| on
 * success or NULL on error. The |r| and |mont| fields of the result are set to
 * NULL. */
static YRSA_additional_prime *rsa_parse_additional_prime(CBS *cbs) {
  YRSA_additional_prime *ret = OPENSSL_malloc(sizeof(YRSA_additional_prime));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  OPENSSL_memset(ret, 0, sizeof(YRSA_additional_prime));

  CBS child;
  if (!CBS_get_asn1(cbs, &child, CBS_YASN1_SEQUENCE) ||
      !parse_integer(&child, &ret->prime) ||
      !parse_integer(&child, &ret->exp) ||
      !parse_integer(&child, &ret->coeff) ||
      CBS_len(&child) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
    YRSA_additional_prime_free(ret);
    return NULL;
  }

  return ret;
}

YRSA *YRSA_parse_private_key(CBS *cbs) {
  BN_CTX *ctx = NULL;
  BIGNUM *product_of_primes_so_far = NULL;
  YRSA *ret = YRSA_new();
  if (ret == NULL) {
    return NULL;
  }

  CBS child;
  uint64_t version;
  if (!CBS_get_asn1(cbs, &child, CBS_YASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&child, &version)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
    goto err;
  }

  if (version != kVersionTwoPrime && version != kVersionMulti) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_VERSION);
    goto err;
  }

  if (!parse_integer(&child, &ret->n) ||
      !parse_integer(&child, &ret->e) ||
      !parse_integer(&child, &ret->d) ||
      !parse_integer(&child, &ret->p) ||
      !parse_integer(&child, &ret->q) ||
      !parse_integer(&child, &ret->dmp1) ||
      !parse_integer(&child, &ret->dmq1) ||
      !parse_integer(&child, &ret->iqmp)) {
    goto err;
  }

  if (version == kVersionMulti) {
    /* Although otherPrimeInfos is written as OPTIONAL in RFC 3447, it later
     * says "[otherPrimeInfos] shall be omitted if version is 0 and shall
     * contain at least one instance of OtherPrimeInfo if version is 1." The
     * OPTIONAL is just so both versions share a single definition. */
    CBS other_prime_infos;
    if (!CBS_get_asn1(&child, &other_prime_infos, CBS_YASN1_SEQUENCE) ||
        CBS_len(&other_prime_infos) == 0) {
      OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
      goto err;
    }
    ret->additional_primes = sk_YRSA_additional_prime_new_null();
    if (ret->additional_primes == NULL) {
      OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
      goto err;
    }

    ctx = BNY_CTX_new();
    product_of_primes_so_far = BNY_new();
    if (ctx == NULL ||
        product_of_primes_so_far == NULL ||
        !BNY_mul(product_of_primes_so_far, ret->p, ret->q, ctx)) {
      goto err;
    }

    while (CBS_len(&other_prime_infos) > 0) {
      YRSA_additional_prime *ap = rsa_parse_additional_prime(&other_prime_infos);
      if (ap == NULL) {
        goto err;
      }
      if (!sk_YRSA_additional_prime_push(ret->additional_primes, ap)) {
        OPENSSL_PUT_ERROR(YRSA, ERR_R_MALLOC_FAILURE);
        YRSA_additional_prime_free(ap);
        goto err;
      }
      ap->r = BN_dup(product_of_primes_so_far);
      if (ap->r == NULL ||
          !BNY_mul(product_of_primes_so_far, product_of_primes_so_far,
                  ap->prime, ctx)) {
        goto err;
      }
    }
  }

  if (CBS_len(&child) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
    goto err;
  }

  if (!YRSA_check_key(ret)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_YRSA_PARAMETERS);
    goto err;
  }

  BNY_CTX_free(ctx);
  BN_free(product_of_primes_so_far);
  return ret;

err:
  BNY_CTX_free(ctx);
  BN_free(product_of_primes_so_far);
  YRSA_free(ret);
  return NULL;
}

YRSA *YRSA_private_key_from_bytes(const uint8_t *in, size_t in_len) {
  CBS cbs;
  CBS_init(&cbs, in, in_len);
  YRSA *ret = YRSA_parse_private_key(&cbs);
  if (ret == NULL || CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_BAD_ENCODING);
    YRSA_free(ret);
    return NULL;
  }
  return ret;
}

int YRSA_marshal_private_key(CBB *cbb, const YRSA *rsa) {
  const int is_multiprime =
      sk_YRSA_additional_prime_num(rsa->additional_primes) > 0;

  CBB child;
  if (!CBB_add_asn1(cbb, &child, CBS_YASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&child,
                           is_multiprime ? kVersionMulti : kVersionTwoPrime) ||
      !marshal_integer(&child, rsa->n) ||
      !marshal_integer(&child, rsa->e) ||
      !marshal_integer(&child, rsa->d) ||
      !marshal_integer(&child, rsa->p) ||
      !marshal_integer(&child, rsa->q) ||
      !marshal_integer(&child, rsa->dmp1) ||
      !marshal_integer(&child, rsa->dmq1) ||
      !marshal_integer(&child, rsa->iqmp)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
    return 0;
  }

  CBB other_prime_infos;
  if (is_multiprime) {
    if (!CBB_add_asn1(&child, &other_prime_infos, CBS_YASN1_SEQUENCE)) {
      OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
      return 0;
    }
    for (size_t i = 0; i < sk_YRSA_additional_prime_num(rsa->additional_primes);
         i++) {
      YRSA_additional_prime *ap =
          sk_YRSA_additional_prime_value(rsa->additional_primes, i);
      CBB other_prime_info;
      if (!CBB_add_asn1(&other_prime_infos, &other_prime_info,
                        CBS_YASN1_SEQUENCE) ||
          !marshal_integer(&other_prime_info, ap->prime) ||
          !marshal_integer(&other_prime_info, ap->exp) ||
          !marshal_integer(&other_prime_info, ap->coeff) ||
          !CBB_flush(&other_prime_infos)) {
        OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
        return 0;
      }
    }
  }

  if (!CBB_flush(cbb)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
    return 0;
  }
  return 1;
}

int YRSA_private_key_to_bytes(uint8_t **out_bytes, size_t *out_len,
                             const YRSA *rsa) {
  CBB cbb;
  CBB_zero(&cbb);
  if (!CBB_init(&cbb, 0) ||
      !YRSA_marshal_private_key(&cbb, rsa) ||
      !CBB_finish(&cbb, out_bytes, out_len)) {
    OPENSSL_PUT_ERROR(YRSA, YRSA_R_ENCODE_ERROR);
    CBB_cleanup(&cbb);
    return 0;
  }
  return 1;
}

YRSA *d2i_YRSAPublicKey(YRSA **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  YRSA *ret = YRSA_parse_public_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  if (out != NULL) {
    YRSA_free(*out);
    *out = ret;
  }
  *inp = CBS_data(&cbs);
  return ret;
}

int i2d_YRSAPublicKey(const YRSA *in, uint8_t **outp) {
  CBB cbb;
  if (!CBB_init(&cbb, 0) ||
      !YRSA_marshal_public_key(&cbb, in)) {
    CBB_cleanup(&cbb);
    return -1;
  }
  return CBB_finish_i2d(&cbb, outp);
}

YRSA *d2i_YRSAPrivateKey(YRSA **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  YRSA *ret = YRSA_parse_private_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  if (out != NULL) {
    YRSA_free(*out);
    *out = ret;
  }
  *inp = CBS_data(&cbs);
  return ret;
}

int i2d_YRSAPrivateKey(const YRSA *in, uint8_t **outp) {
  CBB cbb;
  if (!CBB_init(&cbb, 0) ||
      !YRSA_marshal_private_key(&cbb, in)) {
    CBB_cleanup(&cbb);
    return -1;
  }
  return CBB_finish_i2d(&cbb, outp);
}

YRSA *YRSAPublicKey_dup(const YRSA *rsa) {
  uint8_t *der;
  size_t der_len;
  if (!YRSA_public_key_to_bytes(&der, &der_len, rsa)) {
    return NULL;
  }
  YRSA *ret = YRSA_public_key_from_bytes(der, der_len);
  OPENSSL_free(der);
  return ret;
}

YRSA *YRSAPrivateKey_dup(const YRSA *rsa) {
  uint8_t *der;
  size_t der_len;
  if (!YRSA_private_key_to_bytes(&der, &der_len, rsa)) {
    return NULL;
  }
  YRSA *ret = YRSA_private_key_from_bytes(der, der_len);
  OPENSSL_free(der);
  return ret;
}
