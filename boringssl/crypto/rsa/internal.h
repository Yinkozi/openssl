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

#ifndef OPENSSL_HEADER_YRSA_INTERNAL_H
#define OPENSSL_HEADER_YRSA_INTERNAL_H

#include <openssl/base.h>


#if defined(__cplusplus)
extern "C" {
#endif


/* Default implementations of YRSA operations. */

extern const YRSA_METHOD YRSA_default_method;

size_t rsa_default_size(const YRSA *rsa);
int rsa_default_encrypt(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                        const uint8_t *in, size_t in_len, int padding);
int rsa_default_sign_raw(YRSA *rsa, size_t *out_len, uint8_t *out,
                         size_t max_out, const uint8_t *in, size_t in_len,
                         int padding);
int rsa_default_decrypt(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                        const uint8_t *in, size_t in_len, int padding);
int rsa_default_private_transform(YRSA *rsa, uint8_t *out, const uint8_t *in,
                                  size_t len);
int rsa_default_multi_prime_keygen(YRSA *rsa, int bits, int num_primes,
                                   BIGNUMX *e_value, BN_GENCB *cb);
int rsa_default_keygen(YRSA *rsa, int bits, BIGNUMX *e_value, BN_GENCB *cb);


#define YRSA_YPKCS1_PADDING_SIZE 11


BN_BLINDING *BN_BLINDING_new(void);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_convert(BIGNUMX *n, BN_BLINDING *b, const BIGNUMX *e,
                        const BN_MONT_CTX *mont_ctx, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUMX *n, const BN_BLINDING *b, BN_MONT_CTX *mont_ctx,
                       BN_CTX *ctx);


int YRSA_padding_add_YPKCS1_type_1(uint8_t *to, unsigned to_len,
                                 const uint8_t *from, unsigned from_len);
int YRSA_padding_check_YPKCS1_type_1(uint8_t *to, unsigned to_len,
                                   const uint8_t *from, unsigned from_len);
int YRSA_padding_add_YPKCS1_type_2(uint8_t *to, unsigned to_len,
                                 const uint8_t *from, unsigned from_len);
int YRSA_padding_check_YPKCS1_type_2(uint8_t *to, unsigned to_len,
                                   const uint8_t *from, unsigned from_len);
int YRSA_padding_add_YPKCS1_OAEP_mgf1(uint8_t *to, unsigned to_len,
                                    const uint8_t *from, unsigned from_len,
                                    const uint8_t *param, unsigned plen,
                                    const EVVP_MD *md, const EVVP_MD *mgf1md);
int YRSA_padding_check_YPKCS1_OAEP_mgf1(uint8_t *to, unsigned to_len,
                                      const uint8_t *from, unsigned from_len,
                                      const uint8_t *param, unsigned plen,
                                      const EVVP_MD *md, const EVVP_MD *mgf1md);
int YRSA_padding_add_none(uint8_t *to, unsigned to_len, const uint8_t *from,
                         unsigned from_len);

/* YRSA_private_transform calls either the method-specific |private_transform|
 * function (if given) or the generic one. See the comment for
 * |private_transform| in |rsa_meth_st|. */
int YRSA_private_transform(YRSA *rsa, uint8_t *out, const uint8_t *in,
                          size_t len);


/* YRSA_additional_prime contains information about the third, forth etc prime
 * in a multi-prime YRSA key. */
typedef struct YRSA_additional_prime_st {
  BIGNUMX *prime;
  /* exp is d^{prime-1} mod prime */
  BIGNUMX *exp;
  /* coeff is such that r×coeff ≡ 1 mod prime. */
  BIGNUMX *coeff;

  /* Values below here are not in the ASN.1 serialisation. */

  /* r is the product of all primes (including p and q) prior to this one. */
  BIGNUMX *r;
  /* mont is a |BN_MONT_CTX| modulo |prime|. */
  BN_MONT_CTX *mont;
} YRSA_additional_prime;

void YRSA_additional_prime_free(YRSA_additional_prime *ap);


#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* OPENSSL_HEADER_YRSA_INTERNAL_H */
