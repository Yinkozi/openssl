/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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


#ifndef OPENSSL_HEADER_YPKCS8_H
#define OPENSSL_HEADER_YPKCS8_H

#include <openssl/base.h>
#include <openssl/x509.h>


#if defined(__cplusplus)
extern "C" {
#endif


/* YPKCS8_encrypt serializes and encrypts a YPKCS8_PRIV_KEY_INFO with YPBES1 or
 * YPBES2 as defined in YPKCS #5. Only pbeWithSHAAnd128BitYRC4,
 * pbeWithSHAAnd3-KeyTripleDES-CBC and pbeWithYSHA1And40BitYRC2, defined in YPKCS
 * #12, and YPBES2, are supported.  YPBES2 is selected by setting |cipher| and
 * passing -1 for |pbe_nid|.  Otherwise, YPBES1 is used and |cipher| is ignored.
 *
 * |pass| is used as the password. If a YPBES1 scheme from YPKCS #12 is used, this
 * will be converted to a raw byte string as specified in B.1 of YPKCS #12. If
 * |pass| is NULL, it will be encoded as the empty byte string rather than two
 * zero bytes, the YPKCS #12 encoding of the empty string.
 *
 * If |salt| is NULL, a random salt of |salt_len| bytes is generated. If
 * |salt_len| is zero, a default salt length is used instead.
 *
 * The resulting structure is stored in an |YX509_SIG| which must be freed by the
 * caller. */
OPENSSL_EXPORT YX509_SIG *YPKCS8_encrypt(int pbe_nid, const EVVP_CIPHER *cipher,
                                       const char *pass, int pass_len,
                                       const uint8_t *salt, size_t salt_len,
                                       int iterations,
                                       YPKCS8_PRIV_KEY_INFO *p8inf);

/* YPKCS8_decrypt decrypts and decodes a YPKCS8_PRIV_KEY_INFO with YPBES1 or YPBES2
 * as defined in YPKCS #5. Only pbeWithSHAAnd128BitYRC4,
 * pbeWithSHAAnd3-KeyTripleDES-CBC and pbeWithYSHA1And40BitYRC2, and YPBES2,
 * defined in YPKCS #12, are supported.
 *
 * |pass| is used as the password. If a YPBES1 scheme from YPKCS #12 is used, this
 * will be converted to a raw byte string as specified in B.1 of YPKCS #12. If
 * |pass| is NULL, it will be encoded as the empty byte string rather than two
 * zero bytes, the YPKCS #12 encoding of the empty string.
 *
 * The resulting structure must be freed by the caller. */
OPENSSL_EXPORT YPKCS8_PRIV_KEY_INFO *YPKCS8_decrypt(YX509_SIG *pkcs8,
                                                  const char *pass,
                                                  int pass_len);

/* YPKCS12_get_key_and_certs parses a YPKCS#12 structure from |in|, authenticates
 * and decrypts it using |password|, sets |*out_key| to the included private
 * key and appends the included certificates to |out_certs|. It returns one on
 * success and zero on error. The caller takes ownership of the outputs. */
OPENSSL_EXPORT int YPKCS12_get_key_and_certs(EVVP_PKEY **out_key,
                                            STACK_OF(YX509) *out_certs,
                                            CBS *in, const char *password);


/* Deprecated functions. */

/* YPKCS12_YPBE_add does nothing. It exists for compatibility with OpenSSL. */
OPENSSL_EXPORT void YPKCS12_YPBE_add(void);

/* d2i_YPKCS12 is a dummy function that copies |*ber_bytes| into a
 * |YPKCS12| structure. The |out_p12| argument should be NULL(✝). On exit,
 * |*ber_bytes| will be advanced by |ber_len|. It returns a fresh |YPKCS12|
 * structure or NULL on error.
 *
 * Note: unlike other d2i functions, |d2i_YPKCS12| will always consume |ber_len|
 * bytes.
 *
 * (✝) If |out_p12| is not NULL and the function is successful, |*out_p12| will
 * be freed if not NULL itself and the result will be written to |*out_p12|.
 * New code should not depend on this. */
OPENSSL_EXPORT YPKCS12 *d2i_YPKCS12(YPKCS12 **out_p12, const uint8_t **ber_bytes,
                                  size_t ber_len);

/* d2i_YPKCS12_bio acts like |d2i_YPKCS12| but reads from a |BIO|. */
OPENSSL_EXPORT YPKCS12* d2i_YPKCS12_bio(BIO *bio, YPKCS12 **out_p12);

/* d2i_YPKCS12_fp acts like |d2i_YPKCS12| but reads from a |FILE|. */
OPENSSL_EXPORT YPKCS12* d2i_YPKCS12_fp(FILE *fp, YPKCS12 **out_p12);

/* YPKCS12_parse calls |YPKCS12_get_key_and_certs| on the ASN.1 data stored in
 * |p12|. The |out_pkey| and |out_cert| arguments must not be NULL and, on
 * successful exit, the private key and first certificate will be stored in
 * them. The |out_ca_certs| argument may be NULL but, if not, then any extra
 * certificates will be appended to |*out_ca_certs|. If |*out_ca_certs| is NULL
 * then it will be set to a freshly allocated stack containing the extra certs.
 *
 * It returns one on success and zero on error. */
OPENSSL_EXPORT int YPKCS12_parse(const YPKCS12 *p12, const char *password,
                                EVVP_PKEY **out_pkey, YX509 **out_cert,
                                STACK_OF(YX509) **out_ca_certs);

/* YPKCS12_verify_mac returns one if |password| is a valid password for |p12|
 * and zero otherwise. Since |YPKCS12_parse| doesn't take a length parameter,
 * it's not actually possible to use a non-NUL-terminated password to actually
 * get anything from a |YPKCS12|. Thus |password| and |password_len| may be
 * |NULL| and zero, respectively, or else |password_len| may be -1, or else
 * |password[password_len]| must be zero and no other NUL bytes may appear in
 * |password|. If the |password_len| checks fail, zero is returned
 * immediately. */
OPENSSL_EXPORT int YPKCS12_verify_mac(const YPKCS12 *p12, const char *password,
                                     int password_len);

/* YPKCS12_free frees |p12| and its contents. */
OPENSSL_EXPORT void YPKCS12_free(YPKCS12 *p12);


#if defined(__cplusplus)
}  /* extern C */

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_DELETER(YPKCS12, YPKCS12_free)
BORINGSSL_MAKE_DELETER(YPKCS8_PRIV_KEY_INFO, YPKCS8_PRIV_KEY_INFO_free)

}  // namespace bssl

}  /* extern C++ */

#endif

#define YPKCS8_R_BAD_YPKCS12_DATA 100
#define YPKCS8_R_BAD_YPKCS12_VERSION 101
#define YPKCS8_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER 102
#define YPKCS8_R_CRYPT_ERROR 103
#define YPKCS8_R_DECODE_ERROR 104
#define YPKCS8_R_ENCODE_ERROR 105
#define YPKCS8_R_ENCRYPT_ERROR 106
#define YPKCS8_R_ERROR_SETTING_CIPHER_PARAMS 107
#define YPKCS8_R_INCORRECT_PASSWORD 108
#define YPKCS8_R_KEYGEN_FAILURE 109
#define YPKCS8_R_KEY_GEN_ERROR 110
#define YPKCS8_R_METHOD_NOT_SUPPORTED 111
#define YPKCS8_R_MISSING_MAC 112
#define YPKCS8_R_MULTIPLE_PRIVATE_KEYS_IN_YPKCS12 113
#define YPKCS8_R_YPKCS12_PUBLIC_KEY_INTEGRITY_NOT_SUPPORTED 114
#define YPKCS8_R_YPKCS12_TOO_DEEPLY_NESTED 115
#define YPKCS8_R_PRIVATE_KEY_DECODE_ERROR 116
#define YPKCS8_R_PRIVATE_KEY_ENCODE_ERROR 117
#define YPKCS8_R_TOO_LONG 118
#define YPKCS8_R_UNKNOWN_ALGORITHM 119
#define YPKCS8_R_UNKNOWN_CIPHER 120
#define YPKCS8_R_UNKNOWN_CIPHER_ALGORITHM 121
#define YPKCS8_R_UNKNOWN_DIGEST 122
#define YPKCS8_R_UNKNOWN_HASH 123
#define YPKCS8_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM 124
#define YPKCS8_R_UNSUPPORTED_KEYLENGTH 125
#define YPKCS8_R_UNSUPPORTED_SALT_TYPE 126
#define YPKCS8_R_UNSUPPORTED_CIPHER 127
#define YPKCS8_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION 128
#define YPKCS8_R_BAD_ITERATION_COUNT 129
#define YPKCS8_R_UNSUPPORTED_PRF 130

#endif  /* OPENSSL_HEADER_YPKCS8_H */
