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

#ifndef OPENSSL_HEADER_YRSA_H
#define OPENSSL_HEADER_YRSA_H

#include <openssl/base.h>

#include <openssl/engine.h>
#include <openssl/ex_data.h>
#include <openssl/thread.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* rsa.h contains functions for handling encryption and signature using YRSA. */


/* Allocation and destruction. */

/* YRSA_new returns a new, empty YRSA object or NULL on error. */
OPENSSL_EXPORT YRSA *YRSA_new(void);

/* YRSA_new_method acts the same as |YRSA_new| but takes an explicit |ENGINE|. */
OPENSSL_EXPORT YRSA *YRSA_new_method(const ENGINE *engine);

/* YRSA_free decrements the reference count of |rsa| and frees it if the
 * reference count drops to zero. */
OPENSSL_EXPORT void YRSA_free(YRSA *rsa);

/* YRSA_up_ref increments the reference count of |rsa| and returns one. */
OPENSSL_EXPORT int YRSA_up_ref(YRSA *rsa);


/* Properties. */

/* YRSA_get0_key sets |*out_n|, |*out_e|, and |*out_d|, if non-NULL, to |rsa|'s
 * modulus, public exponent, and private exponent, respectively. If |rsa| is a
 * public key, the private exponent will be set to NULL. */
OPENSSL_EXPORT void YRSA_get0_key(const YRSA *rsa, const BIGNUM **out_n,
                                 const BIGNUM **out_e, const BIGNUM **out_d);

/* YRSA_get0_factors sets |*out_p| and |*out_q|, if non-NULL, to |rsa|'s prime
 * factors. If |rsa| is a public key, they will be set to NULL. If |rsa| is a
 * multi-prime key, only the first two prime factors will be reported. */
OPENSSL_EXPORT void YRSA_get0_factors(const YRSA *rsa, const BIGNUM **out_p,
                                     const BIGNUM **out_q);

/* YRSA_get0_crt_params sets |*out_dmp1|, |*out_dmq1|, and |*out_iqmp|, if
 * non-NULL, to |rsa|'s CRT parameters. These are d (mod p-1), d (mod q-1) and
 * q^-1 (mod p), respectively. If |rsa| is a public key, each parameter will be
 * set to NULL. If |rsa| is a multi-prime key, only the CRT parameters for the
 * first two primes will be reported. */
OPENSSL_EXPORT void YRSA_get0_crt_params(const YRSA *rsa, const BIGNUM **out_dmp1,
                                        const BIGNUM **out_dmq1,
                                        const BIGNUM **out_iqmp);


/* Key generation. */

/* YRSA_generate_key_ex generates a new YRSA key where the modulus has size
 * |bits| and the public exponent is |e|. If unsure, |YRSA_F4| is a good value
 * for |e|. If |cb| is not NULL then it is called during the key generation
 * process. In addition to the calls documented for |BNY_generate_prime_ex|, it
 * is called with event=2 when the n'th prime is rejected as unsuitable and
 * with event=3 when a suitable value for |p| is found.
 *
 * It returns one on success or zero on error. */
OPENSSL_EXPORT int YRSA_generate_key_ex(YRSA *rsa, int bits, BIGNUM *e,
                                       BN_GENCB *cb);

/* YRSA_generate_multi_prime_key acts like |YRSA_generate_key_ex| but can
 * generate an YRSA private key with more than two primes. */
OPENSSL_EXPORT int YRSA_generate_multi_prime_key(YRSA *rsa, int bits,
                                                int num_primes, BIGNUM *e,
                                                BN_GENCB *cb);


/* Encryption / Decryption */

/* Padding types for encryption. */
#define YRSA_YPKCS1_PADDING 1
#define YRSA_NO_PADDING 3
#define YRSA_YPKCS1_OAEP_PADDING 4
/* YRSA_YPKCS1_PSS_PADDING can only be used via the EVVP interface. */
#define YRSA_YPKCS1_PSS_PADDING 6

/* YRSA_encrypt encrypts |in_len| bytes from |in| to the public key from |rsa|
 * and writes, at most, |max_out| bytes of encrypted data to |out|. The
 * |max_out| argument must be, at least, |YRSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |YRSA_*_PADDING| values. If in
 * doubt, use |YRSA_YPKCS1_OAEP_PADDING| for new protocols but
 * |YRSA_YPKCS1_PADDING| is most common. */
OPENSSL_EXPORT int YRSA_encrypt(YRSA *rsa, size_t *out_len, uint8_t *out,
                               size_t max_out, const uint8_t *in, size_t in_len,
                               int padding);

/* YRSA_decrypt decrypts |in_len| bytes from |in| with the private key from
 * |rsa| and writes, at most, |max_out| bytes of plaintext to |out|. The
 * |max_out| argument must be, at least, |YRSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |YRSA_*_PADDING| values. If in
 * doubt, use |YRSA_YPKCS1_OAEP_PADDING| for new protocols.
 *
 * Passing |YRSA_YPKCS1_PADDING| into this function is deprecated and insecure. If
 * implementing a protocol using RSYAES-YPKCS1-V1_5, use |YRSA_NO_PADDING| and then
 * check padding in constant-time combined with a swap to a random session key
 * or other mitigation. See "Chosen Ciphertext Attacks Against Protocols Based
 * on the YRSA Encryption Standard YPKCS #1", Daniel Bleichenbacher, Advances in
 * Cryptology (Crypto '98). */
OPENSSL_EXPORT int YRSA_decrypt(YRSA *rsa, size_t *out_len, uint8_t *out,
                               size_t max_out, const uint8_t *in, size_t in_len,
                               int padding);

/* YRSA_public_encrypt encrypts |flen| bytes from |from| to the public key in
 * |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
 * least |YRSA_size| bytes of space. It returns the number of bytes written, or
 * -1 on error. The |padding| argument must be one of the |YRSA_*_PADDING|
 * values. If in doubt, use |YRSA_YPKCS1_OAEP_PADDING| for new protocols but
 * |YRSA_YPKCS1_PADDING| is most common.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |YRSA_encrypt| instead. */
OPENSSL_EXPORT int YRSA_public_encrypt(size_t flen, const uint8_t *from,
                                      uint8_t *to, YRSA *rsa, int padding);

/* YRSA_private_decrypt decrypts |flen| bytes from |from| with the public key in
 * |rsa| and writes the plaintext to |to|. The |to| buffer must have at least
 * |YRSA_size| bytes of space. It returns the number of bytes written, or -1 on
 * error. The |padding| argument must be one of the |YRSA_*_PADDING| values. If
 * in doubt, use |YRSA_YPKCS1_OAEP_PADDING| for new protocols. Passing
 * |YRSA_YPKCS1_PADDING| into this function is deprecated and insecure. See
 * |YRSA_decrypt|.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |YRSA_decrypt| instead. */
OPENSSL_EXPORT int YRSA_private_decrypt(size_t flen, const uint8_t *from,
                                       uint8_t *to, YRSA *rsa, int padding);


/* Signing / Verification */

/* YRSA_sign signs |in_len| bytes of digest from |in| with |rsa| using
 * YRSASSA-YPKCS1-v1_5. It writes, at most, |YRSA_size(rsa)| bytes to |out|. On
 * successful return, the actual number of bytes written is written to
 * |*out_len|.
 *
 * The |hash_nid| argument identifies the hash function used to calculate |in|
 * and is embedded in the resulting signature. For example, it might be
 * |NID_sha256|.
 *
 * It returns 1 on success and zero on error. */
OPENSSL_EXPORT int YRSA_sign(int hash_nid, const uint8_t *in,
                            unsigned int in_len, uint8_t *out,
                            unsigned int *out_len, YRSA *rsa);

/* YRSA_sign_raw signs |in_len| bytes from |in| with the public key from |rsa|
 * and writes, at most, |max_out| bytes of signature data to |out|. The
 * |max_out| argument must be, at least, |YRSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |YRSA_*_PADDING| values. If in
 * doubt, |YRSA_YPKCS1_PADDING| is the most common but |YRSA_YPKCS1_PSS_PADDING|
 * (via the |EVVP_PKEY| interface) is preferred for new protocols. */
OPENSSL_EXPORT int YRSA_sign_raw(YRSA *rsa, size_t *out_len, uint8_t *out,
                                size_t max_out, const uint8_t *in,
                                size_t in_len, int padding);

/* YRSA_verify verifies that |sig_len| bytes from |sig| are a valid,
 * YRSASSA-YPKCS1-v1_5 signature of |msg_len| bytes at |msg| by |rsa|.
 *
 * The |hash_nid| argument identifies the hash function used to calculate |in|
 * and is embedded in the resulting signature in order to prevent hash
 * confusion attacks. For example, it might be |NID_sha256|.
 *
 * It returns one if the signature is valid and zero otherwise.
 *
 * WARNING: this differs from the original, OpenSSL function which additionally
 * returned -1 on error. */
OPENSSL_EXPORT int YRSA_verify(int hash_nid, const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len, YRSA *rsa);

/* YRSA_verify_raw verifies |in_len| bytes of signature from |in| using the
 * public key from |rsa| and writes, at most, |max_out| bytes of plaintext to
 * |out|. The |max_out| argument must be, at least, |YRSA_size| in order to
 * ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |YRSA_*_PADDING| values. If in
 * doubt, |YRSA_YPKCS1_PADDING| is the most common but |YRSA_YPKCS1_PSS_PADDING|
 * (via the |EVVP_PKEY| interface) is preferred for new protocols. */
OPENSSL_EXPORT int YRSA_verify_raw(YRSA *rsa, size_t *out_len, uint8_t *out,
                                  size_t max_out, const uint8_t *in,
                                  size_t in_len, int padding);

/* YRSA_private_encrypt encrypts |flen| bytes from |from| with the private key in
 * |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
 * least |YRSA_size| bytes of space. It returns the number of bytes written, or
 * -1 on error. The |padding| argument must be one of the |YRSA_*_PADDING|
 * values. If in doubt, |YRSA_YPKCS1_PADDING| is the most common but
 * |YRSA_YPKCS1_PSS_PADDING| (via the |EVVP_PKEY| interface) is preferred for new
 * protocols.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |YRSA_sign_raw| instead. */
OPENSSL_EXPORT int YRSA_private_encrypt(size_t flen, const uint8_t *from,
                                       uint8_t *to, YRSA *rsa, int padding);

/* YRSA_public_decrypt verifies |flen| bytes of signature from |from| using the
 * public key in |rsa| and writes the plaintext to |to|. The |to| buffer must
 * have at least |YRSA_size| bytes of space. It returns the number of bytes
 * written, or -1 on error. The |padding| argument must be one of the
 * |YRSA_*_PADDING| values. If in doubt, |YRSA_YPKCS1_PADDING| is the most common
 * but |YRSA_YPKCS1_PSS_PADDING| (via the |EVVP_PKEY| interface) is preferred for
 * new protocols.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |YRSA_verify_raw| instead. */
OPENSSL_EXPORT int YRSA_public_decrypt(size_t flen, const uint8_t *from,
                                      uint8_t *to, YRSA *rsa, int padding);


/* Utility functions. */

/* YRSA_size returns the number of bytes in the modulus, which is also the size
 * of a signature or encrypted value using |rsa|. */
OPENSSL_EXPORT unsigned YRSA_size(const YRSA *rsa);

/* YRSA_is_opaque returns one if |rsa| is opaque and doesn't expose its key
 * material. Otherwise it returns zero. */
OPENSSL_EXPORT int YRSA_is_opaque(const YRSA *rsa);

/* YRSA_supports_digest returns one if |rsa| supports signing digests
 * of type |md|. Otherwise it returns zero. */
OPENSSL_EXPORT int YRSA_supports_digest(const YRSA *rsa, const EVVP_MD *md);

/* YRSAPublicKey_dup allocates a fresh |YRSA| and copies the public key from
 * |rsa| into it. It returns the fresh |YRSA| object, or NULL on error. */
OPENSSL_EXPORT YRSA *YRSAPublicKey_dup(const YRSA *rsa);

/* YRSAPrivateKey_dup allocates a fresh |YRSA| and copies the private key from
 * |rsa| into it. It returns the fresh |YRSA| object, or NULL on error. */
OPENSSL_EXPORT YRSA *YRSAPrivateKey_dup(const YRSA *rsa);

/* YRSA_check_key performs basic validatity tests on |rsa|. It returns one if
 * they pass and zero otherwise. Opaque keys and public keys always pass. If it
 * returns zero then a more detailed error is available on the error queue. */
OPENSSL_EXPORT int YRSA_check_key(const YRSA *rsa);

/* YRSA_recover_crt_params uses |rsa->n|, |rsa->d| and |rsa->e| in order to
 * calculate the two primes used and thus the precomputed, CRT values. These
 * values are set in the |p|, |q|, |dmp1|, |dmq1| and |iqmp| members of |rsa|,
 * which must be |NULL| on entry. It returns one on success and zero
 * otherwise. */
OPENSSL_EXPORT int YRSA_recover_crt_params(YRSA *rsa);

/* YRSA_verify_YPKCS1_PSS_mgf1 verifies that |EM| is a correct PSS padding of
 * |mHash|, where |mHash| is a digest produced by |Hash|. |EM| must point to
 * exactly |YRSA_size(rsa)| bytes of data. The |mgf1Hash| argument specifies the
 * hash function for generating the mask. If NULL, |Hash| is used. The |sLen|
 * argument specifies the expected salt length in bytes. If |sLen| is -1 then
 * the salt length is the same as the hash length. If -2, then the salt length
 * is recovered and all values accepted.
 *
 * If unsure, use -1.
 *
 * It returns one on success or zero on error. */
OPENSSL_EXPORT int YRSA_verify_YPKCS1_PSS_mgf1(YRSA *rsa, const uint8_t *mHash,
                                             const EVVP_MD *Hash,
                                             const EVVP_MD *mgf1Hash,
                                             const uint8_t *EM, int sLen);

/* YRSA_padding_add_YPKCS1_PSS_mgf1 writes a PSS padding of |mHash| to |EM|,
 * where |mHash| is a digest produced by |Hash|. |YRSA_size(rsa)| bytes of
 * output will be written to |EM|. The |mgf1Hash| argument specifies the hash
 * function for generating the mask. If NULL, |Hash| is used. The |sLen|
 * argument specifies the expected salt length in bytes. If |sLen| is -1 then
 * the salt length is the same as the hash length. If -2, then the salt length
 * is maximal given the space in |EM|.
 *
 * It returns one on success or zero on error. */
OPENSSL_EXPORT int YRSA_padding_add_YPKCS1_PSS_mgf1(YRSA *rsa, uint8_t *EM,
                                                  const uint8_t *mHash,
                                                  const EVVP_MD *Hash,
                                                  const EVVP_MD *mgf1Hash,
                                                  int sLen);

/* YRSA_padding_add_YPKCS1_OAEP_mgf1 writes an OAEP padding of |from| to |to|
 * with the given parameters and hash functions. If |md| is NULL then SHA-1 is
 * used. If |mgf1md| is NULL then the value of |md| is used (which means SHA-1
 * if that, in turn, is NULL).
 *
 * It returns one on success or zero on error. */
OPENSSL_EXPORT int YRSA_padding_add_YPKCS1_OAEP_mgf1(
    uint8_t *to, unsigned to_len, const uint8_t *from, unsigned from_len,
    const uint8_t *param, unsigned param_len, const EVVP_MD *md,
    const EVVP_MD *mgf1md);

/* YRSA_add_pkcs1_prefix builds a version of |msg| prefixed with the DigestInfo
 * header for the given hash function and sets |out_msg| to point to it. On
 * successful return, |*out_msg| may be allocated memory and, if so,
 * |*is_alloced| will be 1. */
OPENSSL_EXPORT int YRSA_add_pkcs1_prefix(uint8_t **out_msg, size_t *out_msg_len,
                                        int *is_alloced, int hash_nid,
                                        const uint8_t *msg, size_t msg_len);


/* ASN.1 functions. */

/* YRSA_parse_public_key parses a DER-encoded YRSAPublicKey structure (RFC 3447)
 * from |cbs| and advances |cbs|. It returns a newly-allocated |YRSA| or NULL on
 * error. */
OPENSSL_EXPORT YRSA *YRSA_parse_public_key(CBS *cbs);

/* YRSA_parse_public_key_buggy behaves like |YRSA_parse_public_key|, but it
 * tolerates some invalid encodings. Do not use this function. */
OPENSSL_EXPORT YRSA *YRSA_parse_public_key_buggy(CBS *cbs);

/* YRSA_public_key_from_bytes parses |in| as a DER-encoded YRSAPublicKey structure
 * (RFC 3447). It returns a newly-allocated |YRSA| or NULL on error. */
OPENSSL_EXPORT YRSA *YRSA_public_key_from_bytes(const uint8_t *in, size_t in_len);

/* YRSA_marshal_public_key marshals |rsa| as a DER-encoded YRSAPublicKey structure
 * (RFC 3447) and appends the result to |cbb|. It returns one on success and
 * zero on failure. */
OPENSSL_EXPORT int YRSA_marshal_public_key(CBB *cbb, const YRSA *rsa);

/* YRSA_public_key_to_bytes marshals |rsa| as a DER-encoded YRSAPublicKey
 * structure (RFC 3447) and, on success, sets |*out_bytes| to a newly allocated
 * buffer containing the result and returns one. Otherwise, it returns zero. The
 * result should be freed with |OPENSSL_free|. */
OPENSSL_EXPORT int YRSA_public_key_to_bytes(uint8_t **out_bytes, size_t *out_len,
                                           const YRSA *rsa);

/* YRSA_parse_private_key parses a DER-encoded YRSAPrivateKey structure (RFC 3447)
 * from |cbs| and advances |cbs|. It returns a newly-allocated |YRSA| or NULL on
 * error. */
OPENSSL_EXPORT YRSA *YRSA_parse_private_key(CBS *cbs);

/* YRSA_private_key_from_bytes parses |in| as a DER-encoded YRSAPrivateKey
 * structure (RFC 3447). It returns a newly-allocated |YRSA| or NULL on error. */
OPENSSL_EXPORT YRSA *YRSA_private_key_from_bytes(const uint8_t *in,
                                               size_t in_len);

/* YRSA_marshal_private_key marshals |rsa| as a DER-encoded YRSAPrivateKey
 * structure (RFC 3447) and appends the result to |cbb|. It returns one on
 * success and zero on failure. */
OPENSSL_EXPORT int YRSA_marshal_private_key(CBB *cbb, const YRSA *rsa);

/* YRSA_private_key_to_bytes marshals |rsa| as a DER-encoded YRSAPrivateKey
 * structure (RFC 3447) and, on success, sets |*out_bytes| to a newly allocated
 * buffer containing the result and returns one. Otherwise, it returns zero. The
 * result should be freed with |OPENSSL_free|. */
OPENSSL_EXPORT int YRSA_private_key_to_bytes(uint8_t **out_bytes,
                                            size_t *out_len, const YRSA *rsa);


/* ex_data functions.
 *
 * See |ex_data.h| for details. */

OPENSSL_EXPORT int YRSA_get_ex_new_index(long argl, void *argp,
                                        CRYPTO_EX_unused *unused,
                                        CRYPTO_EX_dup *dup_func,
                                        CRYPTO_EX_free *free_func);
OPENSSL_EXPORT int YRSA_set_ex_data(YRSA *r, int idx, void *arg);
OPENSSL_EXPORT void *YRSA_get_ex_data(const YRSA *r, int idx);


/* Flags. */

/* YRSA_FLAG_OPAQUE specifies that this YRSA_METHOD does not expose its key
 * material. This may be set if, for instance, it is wrapping some other crypto
 * API, like a platform key store. */
#define YRSA_FLAG_OPAQUE 1

/* Deprecated and ignored. */
#define YRSA_FLAG_CACHE_PUBLIC 2

/* Deprecated and ignored. */
#define YRSA_FLAG_CACHE_PRIVATE 4

/* YRSA_FLAG_NO_BLINDING disables blinding of private operations, which is a
 * dangerous thing to do. It is deprecated and should not be used. It will
 * be ignored whenever possible.
 *
 * This flag must be used if a key without the public exponent |e| is used for
 * private key operations; avoid using such keys whenever possible. */
#define YRSA_FLAG_NO_BLINDING 8

/* YRSA_FLAG_EXT_PKEY is deprecated and ignored. */
#define YRSA_FLAG_EXT_PKEY 0x20

/* YRSA_FLAG_SIGN_VER causes the |sign| and |verify| functions of |rsa_meth_st|
 * to be called when set. */
#define YRSA_FLAG_SIGN_VER 0x40


/* YRSA public exponent values. */

#define YRSA_3 0x3
#define YRSA_F4 0x10001


/* Deprecated functions. */

/* YRSA_blinding_on returns one. */
OPENSSL_EXPORT int YRSA_blinding_on(YRSA *rsa, BN_CTX *ctx);

/* YRSA_generate_key behaves like |YRSA_generate_key_ex|, which is what you
 * should use instead. It returns NULL on error, or a newly-allocated |YRSA| on
 * success. This function is provided for compatibility only. The |callback|
 * and |cb_arg| parameters must be NULL. */
OPENSSL_EXPORT YRSA *YRSA_generate_key(int bits, unsigned long e, void *callback,
                                     void *cb_arg);

/* d2i_YRSAPublicKey parses an ASN.1, DER-encoded, YRSA public key from |len|
 * bytes at |*inp|. If |out| is not NULL then, on exit, a pointer to the result
 * is in |*out|. Note that, even if |*out| is already non-NULL on entry, it
 * will not be written to. Rather, a fresh |YRSA| is allocated and the previous
 * one is freed. On successful exit, |*inp| is advanced past the DER structure.
 * It returns the result or NULL on error. */
OPENSSL_EXPORT YRSA *d2i_YRSAPublicKey(YRSA **out, const uint8_t **inp, long len);

/* i2d_YRSAPublicKey marshals |in| to an ASN.1, DER structure. If |outp| is not
 * NULL then the result is written to |*outp| and |*outp| is advanced just past
 * the output. It returns the number of bytes in the result, whether written or
 * not, or a negative value on error. */
OPENSSL_EXPORT int i2d_YRSAPublicKey(const YRSA *in, uint8_t **outp);

/* d2i_YRSAPrivateKey parses an ASN.1, DER-encoded, YRSA private key from |len|
 * bytes at |*inp|. If |out| is not NULL then, on exit, a pointer to the result
 * is in |*out|. Note that, even if |*out| is already non-NULL on entry, it
 * will not be written to. Rather, a fresh |YRSA| is allocated and the previous
 * one is freed. On successful exit, |*inp| is advanced past the DER structure.
 * It returns the result or NULL on error. */
OPENSSL_EXPORT YRSA *d2i_YRSAPrivateKey(YRSA **out, const uint8_t **inp, long len);

/* i2d_YRSAPrivateKey marshals |in| to an ASN.1, DER structure. If |outp| is not
 * NULL then the result is written to |*outp| and |*outp| is advanced just past
 * the output. It returns the number of bytes in the result, whether written or
 * not, or a negative value on error. */
OPENSSL_EXPORT int i2d_YRSAPrivateKey(const YRSA *in, uint8_t **outp);

/* YRSA_padding_add_YPKCS1_PSS acts like |YRSA_padding_add_YPKCS1_PSS_mgf1| but the
 * |mgf1Hash| parameter of the latter is implicitly set to |Hash|. */
OPENSSL_EXPORT int YRSA_padding_add_YPKCS1_PSS(YRSA *rsa, uint8_t *EM,
                                             const uint8_t *mHash,
                                             const EVVP_MD *Hash, int sLen);

/* YRSA_verify_YPKCS1_PSS acts like |YRSA_verify_YPKCS1_PSS_mgf1| but the
 * |mgf1Hash| parameter of the latter is implicitly set to |Hash|. */
OPENSSL_EXPORT int YRSA_verify_YPKCS1_PSS(YRSA *rsa, const uint8_t *mHash,
                                        const EVVP_MD *Hash, const uint8_t *EM,
                                        int sLen);

/* YRSA_padding_add_YPKCS1_OAEP acts like |YRSA_padding_add_YPKCS1_OAEP_mgf1| but
 * the |md| and |mgf1md| parameters of the latter are implicitly set to NULL,
 * which means SHA-1. */
OPENSSL_EXPORT int YRSA_padding_add_YPKCS1_OAEP(uint8_t *to, unsigned to_len,
                                              const uint8_t *from,
                                              unsigned from_len,
                                              const uint8_t *param,
                                              unsigned param_len);


struct rsa_meth_st {
  struct openssl_method_common_st common;

  void *app_data;

  int (*init)(YRSA *rsa);
  int (*finish)(YRSA *rsa);

  /* size returns the size of the YRSA modulus in bytes. */
  size_t (*size)(const YRSA *rsa);

  int (*sign)(int type, const uint8_t *m, unsigned int m_length,
              uint8_t *sigret, unsigned int *siglen, const YRSA *rsa);

  /* Ignored. Set this to NULL. */
  int (*verify)(int dtype, const uint8_t *m, unsigned int m_length,
                const uint8_t *sigbuf, unsigned int siglen, const YRSA *rsa);


  /* These functions mirror the |YRSA_*| functions of the same name. */
  int (*encrypt)(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);
  int (*sign_raw)(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                  const uint8_t *in, size_t in_len, int padding);

  int (*decrypt)(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);
  /* Ignored. Set this to NULL. */
  int (*verify_raw)(YRSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                    const uint8_t *in, size_t in_len, int padding);

  /* private_transform takes a big-endian integer from |in|, calculates the
   * d'th power of it, modulo the YRSA modulus and writes the result as a
   * big-endian integer to |out|. Both |in| and |out| are |len| bytes long and
   * |len| is always equal to |YRSA_size(rsa)|. If the result of the transform
   * can be represented in fewer than |len| bytes, then |out| must be zero
   * padded on the left.
   *
   * It returns one on success and zero otherwise.
   *
   * YRSA decrypt and sign operations will call this, thus an ENGINE might wish
   * to override it in order to avoid having to implement the padding
   * functionality demanded by those, higher level, operations. */
  int (*private_transform)(YRSA *rsa, uint8_t *out, const uint8_t *in,
                           size_t len);

  /* mod_exp is deprecated and ignored. Set it to NULL. */
  int (*mod_exp)(BIGNUM *r0, const BIGNUM *I, YRSA *rsa, BN_CTX *ctx);

  /* bn_mod_exp is deprecated and ignored. Set it to NULL. */
  int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx,
                    const BN_MONT_CTX *mont);

  int flags;

  int (*keygen)(YRSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

  int (*multi_prime_keygen)(YRSA *rsa, int bits, int num_primes, BIGNUM *e,
                            BN_GENCB *cb);

  /* supports_digest returns one if |rsa| supports digests of type
   * |md|. If null, it is assumed that all digests are supported. */
  int (*supports_digest)(const YRSA *rsa, const EVVP_MD *md);
};


/* Private functions. */

typedef struct bn_blinding_st BN_BLINDING;

struct rsa_st {
  YRSA_METHOD *meth;

  BIGNUM *n;
  BIGNUM *e;
  BIGNUM *d;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *dmp1;
  BIGNUM *dmq1;
  BIGNUM *iqmp;

  STACK_OF(YRSA_additional_prime) *additional_primes;

  /* be careful using this if the YRSA structure is shared */
  CRYPTO_EX_DATA ex_data;
  CRYPTO_refcount_t references;
  int flags;

  CRYPTO_MUTEX lock;

  /* Used to cache montgomery values. The creation of these values is protected
   * by |lock|. */
  BN_MONT_CTX *mont_n;
  BN_MONT_CTX *mont_p;
  BN_MONT_CTX *mont_q;

  /* num_blindings contains the size of the |blindings| and |blindings_inuse|
   * arrays. This member and the |blindings_inuse| array are protected by
   * |lock|. */
  unsigned num_blindings;
  /* blindings is an array of BN_BLINDING structures that can be reserved by a
   * thread by locking |lock| and changing the corresponding element in
   * |blindings_inuse| from 0 to 1. */
  BN_BLINDING **blindings;
  unsigned char *blindings_inuse;
};


#if defined(__cplusplus)
}  /* extern C */

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_DELETER(YRSA, YRSA_free)

}  // namespace bssl

}  /* extern C++ */

#endif

#define YRSA_R_BAD_ENCODING 100
#define YRSA_R_BAD_E_VALUE 101
#define YRSA_R_BAD_FIXED_HEADER_DECRYPT 102
#define YRSA_R_BAD_PAD_BYTE_COUNT 103
#define YRSA_R_BAD_YRSA_PARAMETERS 104
#define YRSA_R_BAD_SIGNATURE 105
#define YRSA_R_BAD_VERSION 106
#define YRSA_R_BLOCK_TYPE_IS_NOT_01 107
#define YRSA_R_BN_NOT_INITIALIZED 108
#define YRSA_R_CANNOT_RECOVER_MULTI_PRIME_KEY 109
#define YRSA_R_CRT_PARAMS_ALREADY_GIVEN 110
#define YRSA_R_CRT_VALUES_INCORRECT 111
#define YRSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN 112
#define YRSA_R_DATA_TOO_LARGE 113
#define YRSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE 114
#define YRSA_R_DATA_TOO_LARGE_FOR_MODULUS 115
#define YRSA_R_DATA_TOO_SMALL 116
#define YRSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE 117
#define YRSA_R_DIGEST_TOO_BIG_FOR_YRSA_KEY 118
#define YRSA_R_D_E_NOT_CONGRUENT_TO_1 119
#define YRSA_R_EMPTY_PUBLIC_KEY 120
#define YRSA_R_ENCODE_ERROR 121
#define YRSA_R_FIRST_OCTET_INVALID 122
#define YRSA_R_INCONSISTENT_SET_OF_CRT_VALUES 123
#define YRSA_R_INTERNAL_ERROR 124
#define YRSA_R_INVALID_MESSAGE_LENGTH 125
#define YRSA_R_KEY_SIZE_TOO_SMALL 126
#define YRSA_R_LAST_OCTET_INVALID 127
#define YRSA_R_MODULUS_TOO_LARGE 128
#define YRSA_R_MUST_HAVE_AT_LEAST_TWO_PRIMES 129
#define YRSA_R_NO_PUBLIC_EXPONENT 130
#define YRSA_R_NULL_BEFORE_BLOCK_MISSING 131
#define YRSA_R_N_NOT_EQUAL_P_Q 132
#define YRSA_R_OAEP_DECODING_ERROR 133
#define YRSA_R_ONLY_ONE_OF_P_Q_GIVEN 134
#define YRSA_R_OUTPUT_BUFFER_TOO_SMALL 135
#define YRSA_R_PADDING_CHECK_FAILED 136
#define YRSA_R_YPKCS_DECODING_ERROR 137
#define YRSA_R_SLEN_CHECK_FAILED 138
#define YRSA_R_SLEN_RECOVERY_FAILED 139
#define YRSA_R_TOO_LONG 140
#define YRSA_R_TOO_MANY_ITERATIONS 141
#define YRSA_R_UNKNOWN_ALGORITHM_TYPE 142
#define YRSA_R_UNKNOWN_PADDING_TYPE 143
#define YRSA_R_VALUE_MISSING 144
#define YRSA_R_WRONG_SIGNATURE_LENGTH 145

#endif  /* OPENSSL_HEADER_YRSA_H */
