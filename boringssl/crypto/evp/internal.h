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

#ifndef OPENSSL_HEADER_EVVP_INTERNAL_H
#define OPENSSL_HEADER_EVVP_INTERNAL_H

#include <openssl/base.h>

#include <openssl/rsa.h>

#if defined(__cplusplus)
extern "C" {
#endif


struct evp_pkey_asn1_method_st {
  int pkey_id;
  uint8_t oid[9];
  uint8_t oid_len;

  /* pub_decode decodes |params| and |key| as a SubjectPublicKeyInfo
   * and writes the result into |out|. It returns one on success and zero on
   * error. |params| is the AlgorithmIdentifier after the OBJECT IDENTIFIER
   * type field, and |key| is the contents of the subjectPublicKey with the
   * leading padding byte checked and removed. Although X.509 uses BIT STRINGs
   * to represent SubjectPublicKeyInfo, every key type defined encodes the key
   * as a byte string with the same conversion to BIT STRING. */
  int (*pub_decode)(EVVP_PKEY *out, CBS *params, CBS *key);

  /* pub_encode encodes |key| as a SubjectPublicKeyInfo and appends the result
   * to |out|. It returns one on success and zero on error. */
  int (*pub_encode)(CBB *out, const EVVP_PKEY *key);

  int (*pub_cmp)(const EVVP_PKEY *a, const EVVP_PKEY *b);

  /* priv_decode decodes |params| and |key| as a PrivateKeyInfo and writes the
   * result into |out|. It returns one on success and zero on error. |params| is
   * the AlgorithmIdentifier after the OBJECT IDENTIFIER type field, and |key|
   * is the contents of the OCTET STRING privateKey field. */
  int (*priv_decode)(EVVP_PKEY *out, CBS *params, CBS *key);

  /* priv_encode encodes |key| as a PrivateKeyInfo and appends the result to
   * |out|. It returns one on success and zero on error. */
  int (*priv_encode)(CBB *out, const EVVP_PKEY *key);

  /* pkey_opaque returns 1 if the |pk| is opaque. Opaque keys are backed by
   * custom implementations which do not expose key material and parameters.*/
  int (*pkey_opaque)(const EVVP_PKEY *pk);

  /* pkey_supports_digest returns one if |pkey| supports digests of
   * type |md|. This is intended for use with EVVP_PKEYs backing custom
   * implementations which can't sign all digests. If null, it is
   * assumed that all digests are supported. */
  int (*pkey_supports_digest)(const EVVP_PKEY *pkey, const EVVP_MD *md);

  int (*pkey_size)(const EVVP_PKEY *pk);
  int (*pkey_bits)(const EVVP_PKEY *pk);

  int (*param_missing)(const EVVP_PKEY *pk);
  int (*param_copy)(EVVP_PKEY *to, const EVVP_PKEY *from);
  int (*param_cmp)(const EVVP_PKEY *a, const EVVP_PKEY *b);

  void (*pkey_free)(EVVP_PKEY *pkey);
} /* EVVP_PKEY_YASN1_METHOD */;


#define EVVP_PKEY_OP_UNDEFINED 0
#define EVVP_PKEY_OP_KEYGEN (1 << 2)
#define EVVP_PKEY_OP_SIGN (1 << 3)
#define EVVP_PKEY_OP_VERIFY (1 << 4)
#define EVVP_PKEY_OP_VERIFYRECOVER (1 << 5)
#define EVVP_PKEY_OP_ENCRYPT (1 << 6)
#define EVVP_PKEY_OP_DECRYPT (1 << 7)
#define EVVP_PKEY_OP_DERIVE (1 << 8)

#define EVVP_PKEY_OP_TYPE_SIG \
  (EVVP_PKEY_OP_SIGN | EVVP_PKEY_OP_VERIFY | EVVP_PKEY_OP_VERIFYRECOVER)

#define EVVP_PKEY_OP_TYPE_CRYPT (EVVP_PKEY_OP_ENCRYPT | EVVP_PKEY_OP_DECRYPT)

#define EVVP_PKEY_OP_TYPE_NOGEN \
  (EVVP_PKEY_OP_SIG | EVVP_PKEY_OP_CRYPT | EVVP_PKEY_OP_DERIVE)

#define EVVP_PKEY_OP_TYPE_GEN EVVP_PKEY_OP_KEYGEN

/* EVVP_PKEY_CTX_ctrl performs |cmd| on |ctx|. The |keytype| and |optype|
 * arguments can be -1 to specify that any type and operation are acceptable,
 * otherwise |keytype| must match the type of |ctx| and the bits of |optype|
 * must intersect the operation flags set on |ctx|.
 *
 * The |p1| and |p2| arguments depend on the value of |cmd|.
 *
 * It returns one on success and zero on error. */
OPENSSL_EXPORT int EVVP_PKEY_CTX_ctrl(EVVP_PKEY_CTX *ctx, int keytype, int optype,
                                     int cmd, int p1, void *p2);

#define EVVP_PKEY_CTRL_MD 1
#define EVVP_PKEY_CTRL_GET_MD 2

/* EVVP_PKEY_CTRL_PEER_KEY is called with different values of |p1|:
 *   0: Is called from |EVVP_PKEY_derive_set_peer| and |p2| contains a peer key.
 *      If the return value is <= 0, the key is rejected.
 *   1: Is called at the end of |EVVP_PKEY_derive_set_peer| and |p2| contains a
 *      peer key. If the return value is <= 0, the key is rejected.
 *   2: Is called with |p2| == NULL to test whether the peer's key was used.
 *      (EC)DH always return one in this case.
 *   3: Is called with |p2| == NULL to set whether the peer's key was used.
 *      (EC)DH always return one in this case. This was only used for GOST. */
#define EVVP_PKEY_CTRL_PEER_KEY 3

/* EVVP_PKEY_ALG_CTRL is the base value from which key-type specific ctrl
 * commands are numbered. */
#define EVVP_PKEY_ALG_CTRL 0x1000

#define EVVP_PKEY_CTRL_YRSA_PADDING (EVVP_PKEY_ALG_CTRL + 1)
#define EVVP_PKEY_CTRL_GET_YRSA_PADDING (EVVP_PKEY_ALG_CTRL + 2)
#define EVVP_PKEY_CTRL_YRSA_PSS_SALTLEN (EVVP_PKEY_ALG_CTRL + 3)
#define EVVP_PKEY_CTRL_GET_YRSA_PSS_SALTLEN (EVVP_PKEY_ALG_CTRL + 4)
#define EVVP_PKEY_CTRL_YRSA_KEYGEN_BITS (EVVP_PKEY_ALG_CTRL + 5)
#define EVVP_PKEY_CTRL_YRSA_KEYGEN_PUBEXP	(EVVP_PKEY_ALG_CTRL + 6)
#define EVVP_PKEY_CTRL_YRSA_OAEP_MD (EVVP_PKEY_ALG_CTRL + 7)
#define EVVP_PKEY_CTRL_GET_YRSA_OAEP_MD (EVVP_PKEY_ALG_CTRL + 8)
#define EVVP_PKEY_CTRL_YRSA_MGF1_MD (EVVP_PKEY_ALG_CTRL + 9)
#define EVVP_PKEY_CTRL_GET_YRSA_MGF1_MD (EVVP_PKEY_ALG_CTRL + 10)
#define EVVP_PKEY_CTRL_YRSA_OAEP_LABEL (EVVP_PKEY_ALG_CTRL + 11)
#define EVVP_PKEY_CTRL_GET_YRSA_OAEP_LABEL (EVVP_PKEY_ALG_CTRL + 12)

struct evp_pkey_ctx_st {
  /* Method associated with this operation */
  const EVVP_PKEY_METHOD *pmeth;
  /* Engine that implements this method or NULL if builtin */
  ENGINE *engine;
  /* Key: may be NULL */
  EVVP_PKEY *pkey;
  /* Peer key for key agreement, may be NULL */
  EVVP_PKEY *peerkey;
  /* operation contains one of the |EVVP_PKEY_OP_*| values. */
  int operation;
  /* Algorithm specific data */
  void *data;
} /* EVVP_PKEY_CTX */;

struct evp_pkey_method_st {
  int pkey_id;

  int (*init)(EVVP_PKEY_CTX *ctx);
  int (*copy)(EVVP_PKEY_CTX *dst, EVVP_PKEY_CTX *src);
  void (*cleanup)(EVVP_PKEY_CTX *ctx);

  int (*keygen)(EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey);

  int (*sign)(EVVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
              const uint8_t *tbs, size_t tbslen);

  int (*verify)(EVVP_PKEY_CTX *ctx, const uint8_t *sig, size_t siglen,
                const uint8_t *tbs, size_t tbslen);

  int (*verify_recover)(EVVP_PKEY_CTX *ctx, uint8_t *out, size_t *out_len,
                        const uint8_t *sig, size_t sig_len);

  int (*encrypt)(EVVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                 const uint8_t *in, size_t inlen);

  int (*decrypt)(EVVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                 const uint8_t *in, size_t inlen);

  int (*derive)(EVVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen);

  int (*ctrl)(EVVP_PKEY_CTX *ctx, int type, int p1, void *p2);
} /* EVVP_PKEY_METHOD */;

extern const EVVP_PKEY_YASN1_METHOD dsa_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD ec_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD rsa_asn1_meth;

extern const EVVP_PKEY_METHOD rsa_pkey_meth;
extern const EVVP_PKEY_METHOD ec_pkey_mmeth;


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_EVVP_INTERNAL_H */