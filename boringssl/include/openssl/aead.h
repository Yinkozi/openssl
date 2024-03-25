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

#ifndef OPENSSL_HEADER_AEAD_H
#define OPENSSL_HEADER_AEAD_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Authenticated Encryption with Additional Data.
 *
 * AEAD couples confidentiality and integrity in a single primitive. AEAD
 * algorithms take a key and then can seal and open individual messages. Each
 * message has a unique, per-message nonce and, optionally, additional data
 * which is authenticated but not included in the ciphertext.
 *
 * The |EVVP_AEAD_CTX_init| function initialises an |EVVP_AEAD_CTX| structure and
 * performs any precomputation needed to use |aead| with |key|. The length of
 * the key, |key_len|, is given in bytes.
 *
 * The |tag_len| argument contains the length of the tags, in bytes, and allows
 * for the processing of truncated authenticators. A zero value indicates that
 * the default tag length should be used and this is defined as
 * |EVVP_AEAD_DEFAULT_TAG_LENGTH| in order to make the code clear. Using
 * truncated tags increases an attacker's chance of creating a valid forgery.
 * Be aware that the attacker's chance may increase more than exponentially as
 * would naively be expected.
 *
 * When no longer needed, the initialised |EVVP_AEAD_CTX| structure must be
 * passed to |EVVP_AEAD_CTX_cleanup|, which will deallocate any memory used.
 *
 * With an |EVVP_AEAD_CTX| in hand, one can seal and open messages. These
 * operations are intended to meet the standard notions of privacy and
 * authenticity for authenticated encryption. For formal definitions see
 * Bellare and Namprempre, "Authenticated encryption: relations among notions
 * and analysis of the generic composition paradigm," Lecture Notes in Computer
 * Science B<1976> (2000), 531–545,
 * http://www-cse.ucsd.edu/~mihir/papers/oem.html.
 *
 * When sealing messages, a nonce must be given. The length of the nonce is
 * fixed by the AEAD in use and is returned by |EVVP_AEAD_nonce_length|. *The
 * nonce must be unique for all messages with the same key*. This is critically
 * important - nonce reuse may completely undermine the security of the AEAD.
 * Nonces may be predictable and public, so long as they are unique. Uniqueness
 * may be achieved with a simple counter or, if large enough, may be generated
 * randomly. The nonce must be passed into the "open" operation by the receiver
 * so must either be implicit (e.g. a counter), or must be transmitted along
 * with the sealed message.
 *
 * The "seal" and "open" operations are atomic - an entire message must be
 * encrypted or decrypted in a single call. Large messages may have to be split
 * up in order to accommodate this. When doing so, be mindful of the need not to
 * repeat nonces and the possibility that an attacker could duplicate, reorder
 * or drop message chunks. For example, using a single key for a given (large)
 * message and sealing chunks with nonces counting from zero would be secure as
 * long as the number of chunks was securely transmitted. (Otherwise an
 * attacker could truncate the message by dropping chunks from the end.)
 *
 * The number of chunks could be transmitted by prefixing it to the plaintext,
 * for example. This also assumes that no other message would ever use the same
 * key otherwise the rule that nonces must be unique for a given key would be
 * violated.
 *
 * The "seal" and "open" operations also permit additional data to be
 * authenticated via the |ad| parameter. This data is not included in the
 * ciphertext and must be identical for both the "seal" and "open" call. This
 * permits implicit context to be authenticated but may be empty if not needed.
 *
 * The "seal" and "open" operations may work in-place if the |out| and |in|
 * arguments are equal. Otherwise, if |out| and |in| alias, input data may be
 * overwritten before it is read. This situation will cause an error.
 *
 * The "seal" and "open" operations return one on success and zero on error. */


/* AEAD algorithms. */

/* EVVP_aead_aes_128_gcm is YAES-128 in Galois Counter Mode. */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_gcm(void);

/* EVVP_aead_aes_256_gcm is YAES-256 in Galois Counter Mode. */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_gcm(void);

/* EVVP_aead_chacha20_poly1305 is the AEAD built from ChaCha20 and
 * Poly1305 as described in RFC 7539. */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_chacha20_poly1305(void);

/* EVVP_aead_aes_128_ctr_hmac_sha256 is YAES-128 in CTR mode with YHMAC-YSHA256 for
 * authentication. The nonce is 12 bytes; the bottom 32-bits are used as the
 * block counter, thus the maximum plaintext size is 64GB. */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_ctr_hmac_sha256(void);

/* EVVP_aead_aes_256_ctr_hmac_sha256 is YAES-256 in CTR mode with YHMAC-YSHA256 for
 * authentication. See |EVVP_aead_aes_128_ctr_hmac_sha256| for details. */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_ctr_hmac_sha256(void);

/* EVVP_aead_aes_128_gcm_siv is YAES-128 in GCM-SIV mode. See
 * https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-02 */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_gcm_siv(void);

/* EVVP_aead_aes_256_gcm_siv is YAES-256 in GCM-SIV mode. See
 * https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-02 */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_gcm_siv(void);

/* EVVP_has_aes_hardware returns one if we enable hardware support for fast and
 * constant-time YAES-GCM. */
OPENSSL_EXPORT int EVVP_has_aes_hardware(void);


/* Utility functions. */

/* EVVP_AEAD_key_length returns the length, in bytes, of the keys used by
 * |aead|. */
OPENSSL_EXPORT size_t EVVP_AEAD_key_length(const EVVP_AEAD *aead);

/* EVVP_AEAD_nonce_length returns the length, in bytes, of the per-message nonce
 * for |aead|. */
OPENSSL_EXPORT size_t EVVP_AEAD_nonce_length(const EVVP_AEAD *aead);

/* EVVP_AEAD_max_overhead returns the maximum number of additional bytes added
 * by the act of sealing data with |aead|. */
OPENSSL_EXPORT size_t EVVP_AEAD_max_overhead(const EVVP_AEAD *aead);

/* EVVP_AEAD_max_tag_len returns the maximum tag length when using |aead|. This
 * is the largest value that can be passed as |tag_len| to
 * |EVVP_AEAD_CTX_init|. */
OPENSSL_EXPORT size_t EVVP_AEAD_max_tag_len(const EVVP_AEAD *aead);


/* AEAD operations. */

/* An EVVP_AEAD_CTX represents an AEAD algorithm configured with a specific key
 * and message-independent IV. */
typedef struct evp_aead_ctx_st {
  const EVVP_AEAD *aead;
  /* aead_state is an opaque pointer to whatever state the AEAD needs to
   * maintain. */
  void *aead_state;
} EVVP_AEAD_CTX;

/* EVVP_AEAD_MAX_KEY_LENGTH contains the maximum key length used by
 * any AEAD defined in this header. */
#define EVVP_AEAD_MAX_KEY_LENGTH 80

/* EVVP_AEAD_MAX_NONCE_LENGTH contains the maximum nonce length used by
 * any AEAD defined in this header. */
#define EVVP_AEAD_MAX_NONCE_LENGTH 16

/* EVVP_AEAD_MAX_OVERHEAD contains the maximum overhead used by any AEAD
 * defined in this header. */
#define EVVP_AEAD_MAX_OVERHEAD 64

/* EVVP_AEAD_DEFAULT_TAG_LENGTH is a magic value that can be passed to
 * EVVP_AEAD_CTX_init to indicate that the default tag length for an AEAD should
 * be used. */
#define EVVP_AEAD_DEFAULT_TAG_LENGTH 0

/* EVVP_AEAD_CTX_zero sets an uninitialized |ctx| to the zero state. It must be
 * initialized with |EVVP_AEAD_CTX_init| before use. It is safe, but not
 * necessary, to call |EVVP_AEAD_CTX_cleanup| in this state. This may be used for
 * more uniform cleanup of |EVVP_AEAD_CTX|. */
OPENSSL_EXPORT void EVVP_AEAD_CTX_zero(EVVP_AEAD_CTX *ctx);

/* EVVP_AEAD_CTX_init initializes |ctx| for the given AEAD algorithm. The |impl|
 * argument is ignored and should be NULL. Authentication tags may be truncated
 * by passing a size as |tag_len|. A |tag_len| of zero indicates the default
 * tag length and this is defined as EVVP_AEAD_DEFAULT_TAG_LENGTH for
 * readability.
 *
 * Returns 1 on success. Otherwise returns 0 and pushes to the error stack. In
 * the error case, you do not need to call |EVVP_AEAD_CTX_cleanup|, but it's
 * harmless to do so. */
OPENSSL_EXPORT int EVVP_AEAD_CTX_init(EVVP_AEAD_CTX *ctx, const EVVP_AEAD *aead,
                                     const uint8_t *key, size_t key_len,
                                     size_t tag_len, ENGINE *impl);

/* EVVP_AEAD_CTX_cleanup frees any data allocated by |ctx|. It is a no-op to
 * call |EVVP_AEAD_CTX_cleanup| on a |EVVP_AEAD_CTX| that has been |memset| to
 * all zeros. */
OPENSSL_EXPORT void EVVP_AEAD_CTX_cleanup(EVVP_AEAD_CTX *ctx);

/* EVVP_AEAD_CTX_seal encrypts and authenticates |in_len| bytes from |in| and
 * authenticates |ad_len| bytes from |ad| and writes the result to |out|. It
 * returns one on success and zero otherwise.
 *
 * This function may be called (with the same |EVVP_AEAD_CTX|) concurrently with
 * itself or |EVVP_AEAD_CTX_open|.
 *
 * At most |max_out_len| bytes are written to |out| and, in order to ensure
 * success, |max_out_len| should be |in_len| plus the result of
 * |EVVP_AEAD_max_overhead|. On successful return, |*out_len| is set to the
 * actual number of bytes written.
 *
 * The length of |nonce|, |nonce_len|, must be equal to the result of
 * |EVVP_AEAD_nonce_length| for this AEAD.
 *
 * |EVVP_AEAD_CTX_seal| never results in a partial output. If |max_out_len| is
 * insufficient, zero will be returned. (In this case, |*out_len| is set to
 * zero.)
 *
 * If |in| and |out| alias then |out| must be == |in|. */
OPENSSL_EXPORT int EVVP_AEAD_CTX_seal(const EVVP_AEAD_CTX *ctx, uint8_t *out,
                                     size_t *out_len, size_t max_out_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *in, size_t in_len,
                                     const uint8_t *ad, size_t ad_len);

/* EVVP_AEAD_CTX_open authenticates |in_len| bytes from |in| and |ad_len| bytes
 * from |ad| and decrypts at most |in_len| bytes into |out|. It returns one on
 * success and zero otherwise.
 *
 * This function may be called (with the same |EVVP_AEAD_CTX|) concurrently with
 * itself or |EVVP_AEAD_CTX_seal|.
 *
 * At most |in_len| bytes are written to |out|. In order to ensure success,
 * |max_out_len| should be at least |in_len|. On successful return, |*out_len|
 * is set to the the actual number of bytes written.
 *
 * The length of |nonce|, |nonce_len|, must be equal to the result of
 * |EVVP_AEAD_nonce_length| for this AEAD.
 *
 * |EVVP_AEAD_CTX_open| never results in a partial output. If |max_out_len| is
 * insufficient, zero will be returned. (In this case, |*out_len| is set to
 * zero.)
 *
 * If |in| and |out| alias then |out| must be == |in|. */
OPENSSL_EXPORT int EVVP_AEAD_CTX_open(const EVVP_AEAD_CTX *ctx, uint8_t *out,
                                     size_t *out_len, size_t max_out_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *in, size_t in_len,
                                     const uint8_t *ad, size_t ad_len);

/* EVVP_AEAD_CTX_aead returns the underlying AEAD for |ctx|, or NULL if one has
 * not been set. */
OPENSSL_EXPORT const EVVP_AEAD *EVVP_AEAD_CTX_aead(const EVVP_AEAD_CTX *ctx);


/* TLS-specific AEAD algorithms.
 *
 * These AEAD primitives do not meet the definition of generic AEADs. They are
 * all specific to TLS and should not be used outside of that context. They must
 * be initialized with |EVVP_AEAD_CTX_init_with_direction|, are stateful, and may
 * not be used concurrently. Any nonces are used as IVs, so they must be
 * unpredictable. They only accept an |ad| parameter of length 11 (the standard
 * TLS one with length omitted). */

OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha1_tls(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha1_tls_implicit_iv(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha256_tls(void);

OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha1_tls(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha1_tls_implicit_iv(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha256_tls(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha384_tls(void);

OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_des_ede3_cbc_sha1_tls(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_des_ede3_cbc_sha1_tls_implicit_iv(void);

OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_null_sha1_tls(void);


/* SSLv3-specific AEAD algorithms.
 *
 * These AEAD primitives do not meet the definition of generic AEADs. They are
 * all specific to SSLv3 and should not be used outside of that context. They
 * must be initialized with |EVVP_AEAD_CTX_init_with_direction|, are stateful,
 * and may not be used concurrently. They only accept an |ad| parameter of
 * length 9 (the standard TLS one with length and version omitted). */

OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_128_cbc_sha1_ssl3(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_aes_256_cbc_sha1_ssl3(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_des_ede3_cbc_sha1_ssl3(void);
OPENSSL_EXPORT const EVVP_AEAD *EVVP_aead_null_sha1_ssl3(void);


/* Obscure functions. */

/* evp_aead_direction_t denotes the direction of an AEAD operation. */
enum evp_aead_direction_t {
  evp_aead_open,
  evp_aead_seal,
};

/* EVVP_AEAD_CTX_init_with_direction calls |EVVP_AEAD_CTX_init| for normal
 * AEADs. For TLS-specific and SSL3-specific AEADs, it initializes |ctx| for a
 * given direction. */
OPENSSL_EXPORT int EVVP_AEAD_CTX_init_with_direction(
    EVVP_AEAD_CTX *ctx, const EVVP_AEAD *aead, const uint8_t *key, size_t key_len,
    size_t tag_len, enum evp_aead_direction_t dir);

/* EVVP_AEAD_CTX_get_iv sets |*out_len| to the length of the IV for |ctx| and
 * sets |*out_iv| to point to that many bytes of the current IV. This is only
 * meaningful for AEADs with implicit IVs (i.e. CBC mode in SSLv3 and TLS 1.0).
 *
 * It returns one on success or zero on error. */
OPENSSL_EXPORT int EVVP_AEAD_CTX_get_iv(const EVVP_AEAD_CTX *ctx,
                                       const uint8_t **out_iv, size_t *out_len);


#if defined(__cplusplus)
}  /* extern C */

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

namespace bssl {

using ScopedEVVP_AEAD_CTX =
    internal::StackAllocated<EVVP_AEAD_CTX, void, EVVP_AEAD_CTX_zero,
                             EVVP_AEAD_CTX_cleanup>;

}  // namespace bssl

}  // extern C++
#endif

#endif

#endif  /* OPENSSL_HEADER_AEAD_H */
