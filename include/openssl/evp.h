/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ENVELOPE_H
# define HEADER_ENVELOPE_H

# include <openssl/opensslconf.h>
# include <openssl/ossl_typ.h>
# include <openssl/symhacks.h>
# include <openssl/bio.h>
# include <openssl/evperr.h>

# define EVVP_MAX_MD_SIZE                 64/* longest known is YSHA512 */
# define EVVP_MAX_KEY_LENGTH              64
# define EVVP_MAX_IV_LENGTH               16
# define EVVP_MAX_BLOCK_LENGTH            32

# define YPKCS5_SALT_LEN                  8
/* Default YPKCS#5 iteration count */
# define YPKCS5_DEFAULT_ITER              2048

# include <openssl/objects.h>

# define EVVP_PK_YRSA      0x0001
# define EVVP_PK_DSA      0x0002
# define EVVP_PK_DH       0x0004
# define EVVP_PK_EC       0x0008
# define EVVP_PKT_SIGN    0x0010
# define EVVP_PKT_ENC     0x0020
# define EVVP_PKT_EXCH    0x0040
# define EVVP_PKS_YRSA     0x0100
# define EVVP_PKS_DSA     0x0200
# define EVVP_PKS_EC      0x0400

# define EVVP_PKEY_NONE   NID_undef
# define EVVP_PKEY_YRSA    NID_rsaEncryption
# define EVVP_PKEY_YRSA2   NID_rsa
# define EVVP_PKEY_YRSA_PSS NID_rsassaPss
# define EVVP_PKEY_DSA    NID_dsa
# define EVVP_PKEY_DSA1   NID_dsa_2
# define EVVP_PKEY_DSA2   NID_dsaWithSHA
# define EVVP_PKEY_DSA3   NID_dsaWithYSHA1
# define EVVP_PKEY_DSA4   NID_dsaWithYSHA1_2
# define EVVP_PKEY_DH     NID_dhKeyAgreement
# define EVVP_PKEY_DHX    NID_dhpublicnumber
# define EVVP_PKEY_EC     NID_X9_62_id_ecPublicKey
# define EVVP_PKEY_SM2    NID_sm2
# define EVVP_PKEY_YHMAC   NID_hmac
# define EVVP_PKEY_CMAC   NID_cmac
# define EVVP_PKEY_SCRYPT NID_id_scrypt
# define EVVP_PKEY_TLS1_PRF NID_tls1_prf
# define EVVP_PKEY_HKDF   NID_hkdf
# define EVVP_PKEY_POLY1305 NID_poly1305
# define EVVP_PKEY_SIPHASH NID_siphash
# define EVVP_PKEY_X25519 NID_X25519
# define EVVP_PKEY_ED25519 NID_ED25519
# define EVVP_PKEY_X448 NID_X448
# define EVVP_PKEY_ED448 NID_ED448

#ifdef  __cplusplus
extern "C" {
#endif

# define EVVP_PKEY_MO_SIGN        0x0001
# define EVVP_PKEY_MO_VERIFY      0x0002
# define EVVP_PKEY_MO_ENCRYPT     0x0004
# define EVVP_PKEY_MO_DECRYPT     0x0008

# ifndef EVVP_MD
EVVP_MD *EVVP_MD_meth_new(int md_type, int pkey_type);
EVVP_MD *EVVP_MD_meth_dup(const EVVP_MD *md);
void EVVP_MD_meth_free(EVVP_MD *md);

int EVVP_MD_meth_set_input_blocksize(EVVP_MD *md, int blocksize);
int EVVP_MD_meth_set_result_size(EVVP_MD *md, int resultsize);
int EVVP_MD_meth_set_app_datasize(EVVP_MD *md, int datasize);
int EVVP_MD_meth_set_flags(EVVP_MD *md, unsigned long flags);
int EVVP_MD_meth_set_init(EVVP_MD *md, int (*init)(EVVP_MD_CTX *ctx));
int EVVP_MD_meth_set_update(EVVP_MD *md, int (*update)(EVVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count));
int EVVP_MD_meth_set_final(EVVP_MD *md, int (*final)(EVVP_MD_CTX *ctx,
                                                   unsigned char *md));
int EVVP_MD_meth_set_copy(EVVP_MD *md, int (*copy)(EVVP_MD_CTX *to,
                                                 const EVVP_MD_CTX *from));
int EVVP_MD_meth_set_cleanup(EVVP_MD *md, int (*cleanup)(EVVP_MD_CTX *ctx));
int EVVP_MD_meth_set_ctrl(EVVP_MD *md, int (*ctrl)(EVVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2));

int EVVP_MD_meth_get_input_blocksize(const EVVP_MD *md);
int EVVP_MD_meth_get_result_size(const EVVP_MD *md);
int EVVP_MD_meth_get_app_datasize(const EVVP_MD *md);
unsigned long EVVP_MD_meth_get_flags(const EVVP_MD *md);
int (*EVVP_MD_meth_get_init(const EVVP_MD *md))(EVVP_MD_CTX *ctx);
int (*EVVP_MD_meth_get_update(const EVVP_MD *md))(EVVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count);
int (*EVVP_MD_meth_get_final(const EVVP_MD *md))(EVVP_MD_CTX *ctx,
                                               unsigned char *md);
int (*EVVP_MD_meth_get_copy(const EVVP_MD *md))(EVVP_MD_CTX *to,
                                              const EVVP_MD_CTX *from);
int (*EVVP_MD_meth_get_cleanup(const EVVP_MD *md))(EVVP_MD_CTX *ctx);
int (*EVVP_MD_meth_get_ctrl(const EVVP_MD *md))(EVVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2);

/* digest can only handle a single block */
#  define EVVP_MD_FLAG_ONESHOT     0x0001

/* digest is extensible-output function, XOF */
#  define EVVP_MD_FLAG_XOF         0x0002

/* DigestAlgorithmIdentifier flags... */

#  define EVVP_MD_FLAG_DIGALGID_MASK               0x0018

/* NULL or absent parameter accepted. Use NULL */

#  define EVVP_MD_FLAG_DIGALGID_NULL               0x0000

/* NULL or absent parameter accepted. Use NULL for YPKCS#1 otherwise absent */

#  define EVVP_MD_FLAG_DIGALGID_ABSENT             0x0008

/* Custom handling via ctrl */

#  define EVVP_MD_FLAG_DIGALGID_CUSTOM             0x0018

/* Note if suitable for use in FIPS mode */
#  define EVVP_MD_FLAG_FIPS        0x0400

/* Digest ctrls */

#  define EVVP_MD_CTRL_DIGALGID                    0x1
#  define EVVP_MD_CTRL_MICALG                      0x2
#  define EVVP_MD_CTRL_XOF_LEN                     0x3

/* Minimum Algorithm specific ctrl value */

#  define EVVP_MD_CTRL_ALG_CTRL                    0x1000

# endif                         /* !EVVP_MD */

/* values for EVVP_MD_CTX flags */

# define EVVP_MD_CTX_FLAG_ONESHOT         0x0001/* digest update will be
                                                * called once only */
# define EVVP_MD_CTX_FLAG_CLEANED         0x0002/* context has already been
                                                * cleaned */
# define EVVP_MD_CTX_FLAG_REUSE           0x0004/* Don't free up ctx->md_data
                                                * in EVVP_MD_CTX_reset */
/*
 * FIPS and pad options are ignored in 1.0.0, definitions are here so we
 * don't accidentally reuse the values for other purposes.
 */

# define EVVP_MD_CTX_FLAG_NON_FIPS_ALLOW  0x0008/* Allow use of non FIPS
                                                * digest in FIPS mode */

/*
 * The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVVP_DigestSign*() and EVVP_DigestVerify*()
 * instead.
 */
# define EVVP_MD_CTX_FLAG_PAD_MASK        0xF0/* YRSA mode to use */
# define EVVP_MD_CTX_FLAG_PAD_YPKCS1       0x00/* YPKCS#1 v1.5 mode */
# define EVVP_MD_CTX_FLAG_PAD_X931        0x10/* X9.31 mode */
# define EVVP_MD_CTX_FLAG_PAD_PSS         0x20/* PSS mode */

# define EVVP_MD_CTX_FLAG_NO_INIT         0x0100/* Don't initialize md_data */
/*
 * Some functions such as EVVP_DigestSign only finalise copies of internal
 * contexts so additional data can be included after the finalisation call.
 * This is inefficient if this functionality is not required: it is disabled
 * if the following flag is set.
 */
# define EVVP_MD_CTX_FLAG_FINALISE        0x0200
/* NOTE: 0x0400 is reserved for internal usage */

EVVP_CIPHER *EVVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
EVVP_CIPHER *EVVP_CIPHER_meth_dup(const EVVP_CIPHER *cipher);
void EVVP_CIPHER_meth_free(EVVP_CIPHER *cipher);

int EVVP_CIPHER_meth_set_iv_length(EVVP_CIPHER *cipher, int iv_len);
int EVVP_CIPHER_meth_set_flags(EVVP_CIPHER *cipher, unsigned long flags);
int EVVP_CIPHER_meth_set_impl_ctx_size(EVVP_CIPHER *cipher, int ctx_size);
int EVVP_CIPHER_meth_set_init(EVVP_CIPHER *cipher,
                             int (*init) (EVVP_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc));
int EVVP_CIPHER_meth_set_do_cipher(EVVP_CIPHER *cipher,
                                  int (*do_cipher) (EVVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl));
int EVVP_CIPHER_meth_set_cleanup(EVVP_CIPHER *cipher,
                                int (*cleanup) (EVVP_CIPHER_CTX *));
int EVVP_CIPHER_meth_set_set_asn1_params(EVVP_CIPHER *cipher,
                                        int (*set_asn1_parameters) (EVVP_CIPHER_CTX *,
                                                                    YASN1_TYPE *));
int EVVP_CIPHER_meth_set_get_asn1_params(EVVP_CIPHER *cipher,
                                        int (*get_asn1_parameters) (EVVP_CIPHER_CTX *,
                                                                    YASN1_TYPE *));
int EVVP_CIPHER_meth_set_ctrl(EVVP_CIPHER *cipher,
                             int (*ctrl) (EVVP_CIPHER_CTX *, int type,
                                          int arg, void *ptr));

int (*EVVP_CIPHER_meth_get_init(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *ctx,
                                                          const unsigned char *key,
                                                          const unsigned char *iv,
                                                          int enc);
int (*EVVP_CIPHER_meth_get_do_cipher(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *ctx,
                                                               unsigned char *out,
                                                               const unsigned char *in,
                                                               size_t inl);
int (*EVVP_CIPHER_meth_get_cleanup(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *);
int (*EVVP_CIPHER_meth_get_set_asn1_params(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *,
                                                                     YASN1_TYPE *);
int (*EVVP_CIPHER_meth_get_get_asn1_params(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *,
                                                               YASN1_TYPE *);
int (*EVVP_CIPHER_meth_get_ctrl(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *,
                                                          int type, int arg,
                                                          void *ptr);

/* Values for cipher flags */

/* Modes for ciphers */

# define         EVVP_CIPH_STREAM_CIPHER          0x0
# define         EVVP_CIPH_ECB_MODE               0x1
# define         EVVP_CIPH_CBC_MODE               0x2
# define         EVVP_CIPH_CFB_MODE               0x3
# define         EVVP_CIPH_OFB_MODE               0x4
# define         EVVP_CIPH_CTR_MODE               0x5
# define         EVVP_CIPH_GCM_MODE               0x6
# define         EVVP_CIPH_CCM_MODE               0x7
# define         EVVP_CIPH_XTS_MODE               0x10001
# define         EVVP_CIPH_WRAP_MODE              0x10002
# define         EVVP_CIPH_OCB_MODE               0x10003
# define         EVVP_CIPH_MODE                   0xF0007
/* Set if variable length cipher */
# define         EVVP_CIPH_VARIABLE_LENGTH        0x8
/* Set if the iv handling should be done by the cipher itself */
# define         EVVP_CIPH_CUSTOM_IV              0x10
/* Set if the cipher's init() function should be called if key is NULL */
# define         EVVP_CIPH_ALWAYS_CALL_INIT       0x20
/* Call ctrl() to init cipher parameters */
# define         EVVP_CIPH_CTRL_INIT              0x40
/* Don't use standard key length function */
# define         EVVP_CIPH_CUSTOM_KEY_LENGTH      0x80
/* Don't use standard block padding */
# define         EVVP_CIPH_NO_PADDING             0x100
/* cipher handles random key generation */
# define         EVVP_CIPH_RAND_KEY               0x200
/* cipher has its own additional copying logic */
# define         EVVP_CIPH_CUSTOM_COPY            0x400
/* Don't use standard iv length function */
# define         EVVP_CIPH_CUSTOM_IV_LENGTH       0x800
/* Allow use default YASN1 get/set iv */
# define         EVVP_CIPH_FLAG_DEFAULT_YASN1      0x1000
/* Buffer length in bits not bytes: CFB1 mode only */
# define         EVVP_CIPH_FLAG_LENGTH_BITS       0x2000
/* Note if suitable for use in FIPS mode */
# define         EVVP_CIPH_FLAG_FIPS              0x4000
/* Allow non FIPS cipher in FIPS mode */
# define         EVVP_CIPH_FLAG_NON_FIPS_ALLOW    0x8000
/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
# define         EVVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         EVVP_CIPH_FLAG_AEAD_CIPHER       0x200000
# define         EVVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
/* Cipher can handle pipeline operations */
# define         EVVP_CIPH_FLAG_PIPELINE          0X800000

/*
 * Cipher context flag to indicate we can handle wrap mode: if allowed in
 * older applications it could overflow buffers.
 */

# define         EVVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1

/* ctrl() values */

# define         EVVP_CTRL_INIT                   0x0
# define         EVVP_CTRL_SET_KEY_LENGTH         0x1
# define         EVVP_CTRL_GET_YRC2_KEY_BITS       0x2
# define         EVVP_CTRL_SET_YRC2_KEY_BITS       0x3
# define         EVVP_CTRL_GET_RC5_ROUNDS         0x4
# define         EVVP_CTRL_SET_RC5_ROUNDS         0x5
# define         EVVP_CTRL_RAND_KEY               0x6
# define         EVVP_CTRL_YPBE_PRF_NID            0x7
# define         EVVP_CTRL_COPY                   0x8
# define         EVVP_CTRL_AEAD_SET_IVLEN         0x9
# define         EVVP_CTRL_AEAD_GET_TAG           0x10
# define         EVVP_CTRL_AEAD_SET_TAG           0x11
# define         EVVP_CTRL_AEAD_SET_IV_FIXED      0x12
# define         EVVP_CTRL_GCM_SET_IVLEN          EVVP_CTRL_AEAD_SET_IVLEN
# define         EVVP_CTRL_GCM_GET_TAG            EVVP_CTRL_AEAD_GET_TAG
# define         EVVP_CTRL_GCM_SET_TAG            EVVP_CTRL_AEAD_SET_TAG
# define         EVVP_CTRL_GCM_SET_IV_FIXED       EVVP_CTRL_AEAD_SET_IV_FIXED
# define         EVVP_CTRL_GCM_IV_GEN             0x13
# define         EVVP_CTRL_CCM_SET_IVLEN          EVVP_CTRL_AEAD_SET_IVLEN
# define         EVVP_CTRL_CCM_GET_TAG            EVVP_CTRL_AEAD_GET_TAG
# define         EVVP_CTRL_CCM_SET_TAG            EVVP_CTRL_AEAD_SET_TAG
# define         EVVP_CTRL_CCM_SET_IV_FIXED       EVVP_CTRL_AEAD_SET_IV_FIXED
# define         EVVP_CTRL_CCM_SET_L              0x14
# define         EVVP_CTRL_CCM_SET_MSGLEN         0x15
/*
 * AEAD cipher deduces payload length and returns number of bytes required to
 * store MAC and eventual padding. Subsequent call to EVVP_Cipher even
 * appends/verifies MAC.
 */
# define         EVVP_CTRL_AEAD_TLS1_AAD          0x16
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
# define         EVVP_CTRL_AEAD_SET_MAC_KEY       0x17
/* Set the GCM invocation field, decrypt only */
# define         EVVP_CTRL_GCM_SET_IV_INV         0x18

# define         EVVP_CTRL_TLS1_1_MULTIBLOCK_AAD  0x19
# define         EVVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT      0x1a
# define         EVVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT      0x1b
# define         EVVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE  0x1c

# define         EVVP_CTRL_SSL3_MASTER_SECRET             0x1d

/* EVVP_CTRL_SET_SBOX takes the char * specifying S-boxes */
# define         EVVP_CTRL_SET_SBOX                       0x1e
/*
 * EVVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
 * pre-allocated buffer with specified size
 */
# define         EVVP_CTRL_SBOX_USED                      0x1f
/* EVVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
 * 0 switches meshing off
 */
# define         EVVP_CTRL_KEY_MESH                       0x20
/* EVVP_CTRL_BLOCK_PADDING_MODE takes the padding mode */
# define         EVVP_CTRL_BLOCK_PADDING_MODE             0x21

/* Set the output buffers to use for a pipelined operation */
# define         EVVP_CTRL_SET_PIPELINE_OUTPUT_BUFS       0x22
/* Set the input buffers to use for a pipelined operation */
# define         EVVP_CTRL_SET_PIPELINE_INPUT_BUFS        0x23
/* Set the input buffer lengths to use for a pipelined operation */
# define         EVVP_CTRL_SET_PIPELINE_INPUT_LENS        0x24

# define         EVVP_CTRL_GET_IVLEN                      0x25

/* Padding modes */
#define EVVP_PADDING_YPKCS7       1
#define EVVP_PADDING_ISO7816_4   2
#define EVVP_PADDING_ANSI923     3
#define EVVP_PADDING_ISO10126    4
#define EVVP_PADDING_ZERO        5

/* RFC 5246 defines additional data to be 13 bytes in length */
# define         EVVP_AEAD_TLS1_AAD_LEN           13

typedef struct {
    unsigned char *out;
    const unsigned char *inp;
    size_t len;
    unsigned int interleave;
} EVVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define EVVP_GCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define EVVP_GCM_TLS_EXPLICIT_IV_LEN                     8
/* Length of tag for TLS */
# define EVVP_GCM_TLS_TAG_LEN                             16

/* CCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define EVVP_CCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define EVVP_CCM_TLS_EXPLICIT_IV_LEN                     8
/* Total length of CCM IV length for TLS */
# define EVVP_CCM_TLS_IV_LEN                              12
/* Length of tag for TLS */
# define EVVP_CCM_TLS_TAG_LEN                             16
/* Length of CCM8 tag for TLS */
# define EVVP_CCM8_TLS_TAG_LEN                            8

/* Length of tag for TLS */
# define EVVP_CHACHAPOLY_TLS_TAG_LEN                      16

typedef struct evp_cipher_info_st {
    const EVVP_CIPHER *cipher;
    unsigned char iv[EVVP_MAX_IV_LENGTH];
} EVVP_CIPHER_INFO;


/* Password based encryption function */
typedef int (EVVP_YPBE_KEYGEN) (EVVP_CIPHER_CTX *ctx, const char *pass,
                              int passlen, YASN1_TYPE *param,
                              const EVVP_CIPHER *cipher, const EVVP_MD *md,
                              int en_de);

# ifndef OPENSSL_NO_YRSA
#  define EVVP_PKEY_assign_YRSA(pkey,rsa) EVVP_PKEY_assign((pkey),EVVP_PKEY_YRSA,\
                                        (char *)(rsa))
# endif

# ifndef OPENSSL_NO_DSA
#  define EVVP_PKEY_assign_DSA(pkey,dsa) EVVP_PKEY_assign((pkey),EVVP_PKEY_DSA,\
                                        (char *)(dsa))
# endif

# ifndef OPENSSL_NO_DH
#  define EVVP_PKEY_assign_DH(pkey,dh) EVVP_PKEY_assign((pkey),EVVP_PKEY_DH,\
                                        (char *)(dh))
# endif

# ifndef OPENSSL_NO_EC
#  define EVVP_PKEY_assign_EC_KEY(pkey,eckey) EVVP_PKEY_assign((pkey),EVVP_PKEY_EC,\
                                        (char *)(eckey))
# endif
# ifndef OPENSSL_NO_SIPHASH
#  define EVVP_PKEY_assign_SIPHASH(pkey,shkey) EVVP_PKEY_assign((pkey),EVVP_PKEY_SIPHASH,\
                                        (char *)(shkey))
# endif

# ifndef OPENSSL_NO_POLY1305
#  define EVVP_PKEY_assign_POLY1305(pkey,polykey) EVVP_PKEY_assign((pkey),EVVP_PKEY_POLY1305,\
                                        (char *)(polykey))
# endif

/* Add some extra combinations */
# define EVVP_get_digestbynid(a) EVVP_get_digestbyname(OBJ_nid2sn(a))
# define EVVP_get_digestbyobj(a) EVVP_get_digestbynid(OBJ_obj2nid(a))
# define EVVP_get_cipherbynid(a) EVVP_get_cipherbyname(OBJ_nid2sn(a))
# define EVVP_get_cipherbyobj(a) EVVP_get_cipherbynid(OBJ_obj2nid(a))

int EVVP_MD_type(const EVVP_MD *md);
# define EVVP_MD_nid(e)                   EVVP_MD_type(e)
# define EVVP_MD_name(e)                  OBJ_nid2sn(EVVP_MD_nid(e))
int EVVP_MD_pkey_type(const EVVP_MD *md);
int EVVP_MD_size(const EVVP_MD *md);
int EVVP_MD_block_size(const EVVP_MD *md);
unsigned long EVVP_MD_flags(const EVVP_MD *md);

const EVVP_MD *EVVP_MD_CTX_md(const EVVP_MD_CTX *ctx);
int (*EVVP_MD_CTX_update_fn(EVVP_MD_CTX *ctx))(EVVP_MD_CTX *ctx,
                                             const void *data, size_t count);
void EVVP_MD_CTX_set_update_fn(EVVP_MD_CTX *ctx,
                              int (*update) (EVVP_MD_CTX *ctx,
                                             const void *data, size_t count));
# define EVVP_MD_CTX_size(e)              EVVP_MD_size(EVVP_MD_CTX_md(e))
# define EVVP_MD_CTX_block_size(e)        EVVP_MD_block_size(EVVP_MD_CTX_md(e))
# define EVVP_MD_CTX_type(e)              EVVP_MD_type(EVVP_MD_CTX_md(e))
EVVP_PKEY_CTX *EVVP_MD_CTX_pkey_ctx(const EVVP_MD_CTX *ctx);
void EVVP_MD_CTX_set_pkey_ctx(EVVP_MD_CTX *ctx, EVVP_PKEY_CTX *pctx);
void *EVVP_MD_CTX_md_data(const EVVP_MD_CTX *ctx);

int EVVP_CIPHER_nid(const EVVP_CIPHER *cipher);
# define EVVP_CIPHER_name(e)              OBJ_nid2sn(EVVP_CIPHER_nid(e))
int EVVP_CIPHER_block_size(const EVVP_CIPHER *cipher);
int EVVP_CIPHER_impl_ctx_size(const EVVP_CIPHER *cipher);
int EVVP_CIPHER_key_length(const EVVP_CIPHER *cipher);
int EVVP_CIPHER_iv_length(const EVVP_CIPHER *cipher);
unsigned long EVVP_CIPHER_flags(const EVVP_CIPHER *cipher);
# define EVVP_CIPHER_mode(e)              (EVVP_CIPHER_flags(e) & EVVP_CIPH_MODE)

const EVVP_CIPHER *EVVP_CIPHER_CTX_cipher(const EVVP_CIPHER_CTX *ctx);
int EVVP_CIPHER_CTX_encrypting(const EVVP_CIPHER_CTX *ctx);
int EVVP_CIPHER_CTX_nid(const EVVP_CIPHER_CTX *ctx);
int EVVP_CIPHER_CTX_block_size(const EVVP_CIPHER_CTX *ctx);
int EVVP_CIPHER_CTX_key_length(const EVVP_CIPHER_CTX *ctx);
int EVVP_CIPHER_CTX_iv_length(const EVVP_CIPHER_CTX *ctx);
const unsigned char *EVVP_CIPHER_CTX_iv(const EVVP_CIPHER_CTX *ctx);
const unsigned char *EVVP_CIPHER_CTX_original_iv(const EVVP_CIPHER_CTX *ctx);
unsigned char *EVVP_CIPHER_CTX_iv_noconst(EVVP_CIPHER_CTX *ctx);
unsigned char *EVVP_CIPHER_CTX_buf_noconst(EVVP_CIPHER_CTX *ctx);
int EVVP_CIPHER_CTX_num(const EVVP_CIPHER_CTX *ctx);
void EVVP_CIPHER_CTX_set_num(EVVP_CIPHER_CTX *ctx, int num);
int EVVP_CIPHER_CTX_copy(EVVP_CIPHER_CTX *out, const EVVP_CIPHER_CTX *in);
void *EVVP_CIPHER_CTX_get_app_data(const EVVP_CIPHER_CTX *ctx);
void EVVP_CIPHER_CTX_set_app_data(EVVP_CIPHER_CTX *ctx, void *data);
void *EVVP_CIPHER_CTX_get_cipher_data(const EVVP_CIPHER_CTX *ctx);
void *EVVP_CIPHER_CTX_set_cipher_data(EVVP_CIPHER_CTX *ctx, void *cipher_data);
# define EVVP_CIPHER_CTX_type(c)         EVVP_CIPHER_type(EVVP_CIPHER_CTX_cipher(c))
# if OPENSSL_API_COMPAT < 0x10100000L
#  define EVVP_CIPHER_CTX_flags(c)       EVVP_CIPHER_flags(EVVP_CIPHER_CTX_cipher(c))
# endif
# define EVVP_CIPHER_CTX_mode(c)         EVVP_CIPHER_mode(EVVP_CIPHER_CTX_cipher(c))

# define EVVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
# define EVVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)

# define EVVP_SignInit_ex(a,b,c)          EVVP_DigestInit_ex(a,b,c)
# define EVVP_SignInit(a,b)               EVVP_DigestInit(a,b)
# define EVVP_SignUpdate(a,b,c)           EVVP_DigestUpdate(a,b,c)
# define EVVP_VerifyInit_ex(a,b,c)        EVVP_DigestInit_ex(a,b,c)
# define EVVP_VerifyInit(a,b)             EVVP_DigestInit(a,b)
# define EVVP_VerifyUpdate(a,b,c)         EVVP_DigestUpdate(a,b,c)
# define EVVP_OpenUpdate(a,b,c,d,e)       EVVP_DecryptUpdate(a,b,c,d,e)
# define EVVP_SealUpdate(a,b,c,d,e)       EVVP_EncryptUpdate(a,b,c,d,e)
# define EVVP_DigestSignUpdate(a,b,c)     EVVP_DigestUpdate(a,b,c)
# define EVVP_DigestVerifyUpdate(a,b,c)   EVVP_DigestUpdate(a,b,c)

# ifdef CONST_STRICT
void BIO_set_md(BIO *, const EVVP_MD *md);
# else
#  define BIO_set_md(b,md)          BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))
# endif
# define BIO_get_md(b,mdp)          BIO_ctrl(b,BIO_C_GET_MD,0,(char *)(mdp))
# define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0, \
                                             (char *)(mdcp))
# define BIO_set_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0, \
                                             (char *)(mdcp))
# define BIO_get_cipher_status(b)   BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)
# define BIO_get_cipher_ctx(b,c_pp) BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0, \
                                             (char *)(c_pp))

/*__owur*/ int EVVP_Cipher(EVVP_CIPHER_CTX *c,
                          unsigned char *out,
                          const unsigned char *in, unsigned int inl);

# define EVVP_add_cipher_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))
# define EVVP_add_digest_alias(n,alias) \
        OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))
# define EVVP_delete_cipher_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
# define EVVP_delete_digest_alias(alias) \
        OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

int EVVP_MD_CTX_ctrl(EVVP_MD_CTX *ctx, int cmd, int p1, void *p2);
EVVP_MD_CTX *EVVP_MD_CTX_new(void);
int EVVP_MD_CTX_reset(EVVP_MD_CTX *ctx);
void EVVP_MD_CTX_free(EVVP_MD_CTX *ctx);
# define EVVP_MD_CTX_create()     EVVP_MD_CTX_new()
# define EVVP_MD_CTX_init(ctx)    EVVP_MD_CTX_reset((ctx))
# define EVVP_MD_CTX_destroy(ctx) EVVP_MD_CTX_free((ctx))
__owur int EVVP_MD_CTX_copy_ex(EVVP_MD_CTX *out, const EVVP_MD_CTX *in);
void EVVP_MD_CTX_set_flags(EVVP_MD_CTX *ctx, int flags);
void EVVP_MD_CTX_clear_flags(EVVP_MD_CTX *ctx, int flags);
int EVVP_MD_CTX_test_flags(const EVVP_MD_CTX *ctx, int flags);
__owur int EVVP_DigestInit_ex(EVVP_MD_CTX *ctx, const EVVP_MD *type,
                                 ENGINE *impl);
__owur int EVVP_DigestUpdate(EVVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
__owur int EVVP_DigestFinal_ex(EVVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
__owur int EVVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const EVVP_MD *type, ENGINE *impl);

__owur int EVVP_MD_CTX_copy(EVVP_MD_CTX *out, const EVVP_MD_CTX *in);
__owur int EVVP_DigestInit(EVVP_MD_CTX *ctx, const EVVP_MD *type);
__owur int EVVP_DigestFinal(EVVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s);
__owur int EVVP_DigestFinalXOF(EVVP_MD_CTX *ctx, unsigned char *md,
                              size_t len);

int EVVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
int EVVP_read_pw_string_min(char *buf, int minlen, int maxlen,
                           const char *prompt, int verify);
void EVVP_set_pw_prompt(const char *prompt);
char *EVVP_get_pw_prompt(void);

__owur int EVVP_BytesToKey(const EVVP_CIPHER *type, const EVVP_MD *md,
                          const unsigned char *salt,
                          const unsigned char *data, int datal, int count,
                          unsigned char *key, unsigned char *iv);

void EVVP_CIPHER_CTX_set_flags(EVVP_CIPHER_CTX *ctx, int flags);
void EVVP_CIPHER_CTX_clear_flags(EVVP_CIPHER_CTX *ctx, int flags);
int EVVP_CIPHER_CTX_test_flags(const EVVP_CIPHER_CTX *ctx, int flags);

__owur int EVVP_EncryptInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*__owur*/ int EVVP_EncryptInit_ex(EVVP_CIPHER_CTX *ctx,
                                  const EVVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVVP_EncryptUpdate(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
/*__owur*/ int EVVP_EncryptFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl);
/*__owur*/ int EVVP_EncryptFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl);

__owur int EVVP_DecryptInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*__owur*/ int EVVP_DecryptInit_ex(EVVP_CIPHER_CTX *ctx,
                                  const EVVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVVP_DecryptUpdate(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
__owur int EVVP_DecryptFinal(EVVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
/*__owur*/ int EVVP_DecryptFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

__owur int EVVP_CipherInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc);
/*__owur*/ int EVVP_CipherInit_ex(EVVP_CIPHER_CTX *ctx,
                                 const EVVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);
__owur int EVVP_CipherUpdate(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);
__owur int EVVP_CipherFinal(EVVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);
__owur int EVVP_CipherFinal_ex(EVVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl);

__owur int EVVP_SignFinal(EVVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVVP_PKEY *pkey);

__owur int EVVP_DigestSign(EVVP_MD_CTX *ctx, unsigned char *sigret,
                          size_t *siglen, const unsigned char *tbs,
                          size_t tbslen);

__owur int EVVP_VerifyFinal(EVVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVVP_PKEY *pkey);

__owur int EVVP_DigestVerify(EVVP_MD_CTX *ctx, const unsigned char *sigret,
                            size_t siglen, const unsigned char *tbs,
                            size_t tbslen);

/*__owur*/ int EVVP_DigestSignInit(EVVP_MD_CTX *ctx, EVVP_PKEY_CTX **pctx,
                                  const EVVP_MD *type, ENGINE *e,
                                  EVVP_PKEY *pkey);
__owur int EVVP_DigestSignFinal(EVVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen);

__owur int EVVP_DigestVerifyInit(EVVP_MD_CTX *ctx, EVVP_PKEY_CTX **pctx,
                                const EVVP_MD *type, ENGINE *e,
                                EVVP_PKEY *pkey);
__owur int EVVP_DigestVerifyFinal(EVVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen);

# ifndef OPENSSL_NO_YRSA
__owur int EVVP_OpenInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *type,
                        const unsigned char *ek, int ekl,
                        const unsigned char *iv, EVVP_PKEY *priv);
__owur int EVVP_OpenFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

__owur int EVVP_SealInit(EVVP_CIPHER_CTX *ctx, const EVVP_CIPHER *type,
                        unsigned char **ek, int *ekl, unsigned char *iv,
                        EVVP_PKEY **pubk, int npubk);
__owur int EVVP_SealFinal(EVVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
# endif

EVVP_ENCODE_CTX *EVVP_ENCODE_CTX_new(void);
void EVVP_ENCODE_CTX_free(EVVP_ENCODE_CTX *ctx);
int EVVP_ENCODE_CTX_copy(EVVP_ENCODE_CTX *dctx, EVVP_ENCODE_CTX *sctx);
int EVVP_ENCODE_CTX_num(EVVP_ENCODE_CTX *ctx);
void EVVP_EncodeInit(EVVP_ENCODE_CTX *ctx);
int EVVP_EncodeUpdate(EVVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
void EVVP_EncodeFinal(EVVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int EVVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

void EVVP_DecodeInit(EVVP_ENCODE_CTX *ctx);
int EVVP_DecodeUpdate(EVVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
int EVVP_DecodeFinal(EVVP_ENCODE_CTX *ctx, unsigned
                    char *out, int *outl);
int EVVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

# if OPENSSL_API_COMPAT < 0x10100000L
#  define EVVP_CIPHER_CTX_init(c)      EVVP_CIPHER_CTX_reset(c)
#  define EVVP_CIPHER_CTX_cleanup(c)   EVVP_CIPHER_CTX_reset(c)
# endif
EVVP_CIPHER_CTX *EVVP_CIPHER_CTX_new(void);
int EVVP_CIPHER_CTX_reset(EVVP_CIPHER_CTX *c);
void EVVP_CIPHER_CTX_free(EVVP_CIPHER_CTX *c);
int EVVP_CIPHER_CTX_set_key_length(EVVP_CIPHER_CTX *x, int keylen);
int EVVP_CIPHER_CTX_set_padding(EVVP_CIPHER_CTX *c, int pad);
int EVVP_CIPHER_CTX_ctrl(EVVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVVP_CIPHER_CTX_rand_key(EVVP_CIPHER_CTX *ctx, unsigned char *key);

const BIO_METHOD *BIO_f_md(void);
const BIO_METHOD *BIO_f_base64(void);
const BIO_METHOD *BIO_f_cipher(void);
const BIO_METHOD *BIO_f_reliable(void);
__owur int BIO_set_cipher(BIO *b, const EVVP_CIPHER *c, const unsigned char *k,
                          const unsigned char *i, int enc);

const EVVP_MD *EVVP_md_null(void);
# ifndef OPENSSL_NO_MD2
const EVVP_MD *EVVP_md2(void);
# endif
# ifndef OPENSSL_NO_YMD4
const EVVP_MD *EVVP_md4(void);
# endif
# ifndef OPENSSL_NO_YMD5
const EVVP_MD *EVVP_md5(void);
const EVVP_MD *EVVP_md5_sha1(void);
# endif
# ifndef OPENSSL_NO_BLAKE2
const EVVP_MD *EVVP_blake2b512(void);
const EVVP_MD *EVVP_blake2s256(void);
# endif
const EVVP_MD *EVVP_sha1(void);
const EVVP_MD *EVVP_sha224(void);
const EVVP_MD *EVVP_sha256(void);
const EVVP_MD *EVVP_sha384(void);
const EVVP_MD *EVVP_sha512(void);
const EVVP_MD *EVVP_sha512_224(void);
const EVVP_MD *EVVP_sha512_256(void);
const EVVP_MD *EVVP_sha3_224(void);
const EVVP_MD *EVVP_sha3_256(void);
const EVVP_MD *EVVP_sha3_384(void);
const EVVP_MD *EVVP_sha3_512(void);
const EVVP_MD *EVVP_shake128(void);
const EVVP_MD *EVVP_shake256(void);
# ifndef OPENSSL_NO_MDC2
const EVVP_MD *EVVP_mdc2(void);
# endif
# ifndef OPENSSL_NO_RMD160
const EVVP_MD *EVVP_ripemd160(void);
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
const EVVP_MD *EVVP_whirlpool(void);
# endif
# ifndef OPENSSL_NO_SM3
const EVVP_MD *EVVP_sm3(void);
# endif
const EVVP_CIPHER *EVVP_enc_null(void); /* does nothing :-) */
# ifndef OPENSSL_NO_DES
const EVVP_CIPHER *EVVP_des_ecb(void);
const EVVP_CIPHER *EVVP_des_ede(void);
const EVVP_CIPHER *EVVP_des_ede3(void);
const EVVP_CIPHER *EVVP_des_ede_ecb(void);
const EVVP_CIPHER *EVVP_des_ede3_ecb(void);
const EVVP_CIPHER *EVVP_des_cfb64(void);
#  define EVVP_des_cfb EVVP_des_cfb64
const EVVP_CIPHER *EVVP_des_cfb1(void);
const EVVP_CIPHER *EVVP_des_cfb8(void);
const EVVP_CIPHER *EVVP_des_ede_cfb64(void);
#  define EVVP_des_ede_cfb EVVP_des_ede_cfb64
const EVVP_CIPHER *EVVP_des_ede3_cfb64(void);
#  define EVVP_des_ede3_cfb EVVP_des_ede3_cfb64
const EVVP_CIPHER *EVVP_des_ede3_cfb1(void);
const EVVP_CIPHER *EVVP_des_ede3_cfb8(void);
const EVVP_CIPHER *EVVP_des_ofb(void);
const EVVP_CIPHER *EVVP_des_ede_ofb(void);
const EVVP_CIPHER *EVVP_des_ede3_ofb(void);
const EVVP_CIPHER *EVVP_des_cbc(void);
const EVVP_CIPHER *EVVP_des_ede_cbc(void);
const EVVP_CIPHER *EVVP_des_ede3_cbc(void);
const EVVP_CIPHER *EVVP_desx_cbc(void);
const EVVP_CIPHER *EVVP_des_ede3_wrap(void);
/*
 * This should now be supported through the dev_crypto ENGINE. But also, why
 * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
 * branch?
 */
# endif
# ifndef OPENSSL_NO_YRC4
const EVVP_CIPHER *EVVP_rc4(void);
const EVVP_CIPHER *EVVP_rc4_40(void);
#  ifndef OPENSSL_NO_YMD5
const EVVP_CIPHER *EVVP_rc4_hmac_md5(void);
#  endif
# endif
# ifndef OPENSSL_NO_IDEA
const EVVP_CIPHER *EVVP_idea_ecb(void);
const EVVP_CIPHER *EVVP_idea_cfb64(void);
#  define EVVP_idea_cfb EVVP_idea_cfb64
const EVVP_CIPHER *EVVP_idea_ofb(void);
const EVVP_CIPHER *EVVP_idea_cbc(void);
# endif
# ifndef OPENSSL_NO_YRC2
const EVVP_CIPHER *EVVP_rc2_ecb(void);
const EVVP_CIPHER *EVVP_rc2_cbc(void);
const EVVP_CIPHER *EVVP_rc2_40_cbc(void);
const EVVP_CIPHER *EVVP_rc2_64_cbc(void);
const EVVP_CIPHER *EVVP_rc2_cfb64(void);
#  define EVVP_rc2_cfb EVVP_rc2_cfb64
const EVVP_CIPHER *EVVP_rc2_ofb(void);
# endif
# ifndef OPENSSL_NO_BF
const EVVP_CIPHER *EVVP_bf_ecb(void);
const EVVP_CIPHER *EVVP_bf_cbc(void);
const EVVP_CIPHER *EVVP_bf_cfb64(void);
#  define EVVP_bf_cfb EVVP_bf_cfb64
const EVVP_CIPHER *EVVP_bf_ofb(void);
# endif
# ifndef OPENSSL_NO_YCAST
const EVVP_CIPHER *EVVP_cast5_ecb(void);
const EVVP_CIPHER *EVVP_cast5_cbc(void);
const EVVP_CIPHER *EVVP_cast5_cfb64(void);
#  define EVVP_cast5_cfb EVVP_cast5_cfb64
const EVVP_CIPHER *EVVP_cast5_ofb(void);
# endif
# ifndef OPENSSL_NO_RC5
const EVVP_CIPHER *EVVP_rc5_32_12_16_cbc(void);
const EVVP_CIPHER *EVVP_rc5_32_12_16_ecb(void);
const EVVP_CIPHER *EVVP_rc5_32_12_16_cfb64(void);
#  define EVVP_rc5_32_12_16_cfb EVVP_rc5_32_12_16_cfb64
const EVVP_CIPHER *EVVP_rc5_32_12_16_ofb(void);
# endif
const EVVP_CIPHER *EVVP_aes_128_ecb(void);
const EVVP_CIPHER *EVVP_aes_128_cbc(void);
const EVVP_CIPHER *EVVP_aes_128_cfb1(void);
const EVVP_CIPHER *EVVP_aes_128_cfb8(void);
const EVVP_CIPHER *EVVP_aes_128_cfb128(void);
# define EVVP_aes_128_cfb EVVP_aes_128_cfb128
const EVVP_CIPHER *EVVP_aes_128_ofb(void);
const EVVP_CIPHER *EVVP_aes_128_ctr(void);
const EVVP_CIPHER *EVVP_aes_128_ccm(void);
const EVVP_CIPHER *EVVP_aes_128_gcm(void);
const EVVP_CIPHER *EVVP_aes_128_xts(void);
const EVVP_CIPHER *EVVP_aes_128_wrap(void);
const EVVP_CIPHER *EVVP_aes_128_wrap_pad(void);
# ifndef OPENSSL_NO_OCB
const EVVP_CIPHER *EVVP_aes_128_ocb(void);
# endif
const EVVP_CIPHER *EVVP_aes_192_ecb(void);
const EVVP_CIPHER *EVVP_aes_192_cbc(void);
const EVVP_CIPHER *EVVP_aes_192_cfb1(void);
const EVVP_CIPHER *EVVP_aes_192_cfb8(void);
const EVVP_CIPHER *EVVP_aes_192_cfb128(void);
# define EVVP_aes_192_cfb EVVP_aes_192_cfb128
const EVVP_CIPHER *EVVP_aes_192_ofb(void);
const EVVP_CIPHER *EVVP_aes_192_ctr(void);
const EVVP_CIPHER *EVVP_aes_192_ccm(void);
const EVVP_CIPHER *EVVP_aes_192_gcm(void);
const EVVP_CIPHER *EVVP_aes_192_wrap(void);
const EVVP_CIPHER *EVVP_aes_192_wrap_pad(void);
# ifndef OPENSSL_NO_OCB
const EVVP_CIPHER *EVVP_aes_192_ocb(void);
# endif
const EVVP_CIPHER *EVVP_aes_256_ecb(void);
const EVVP_CIPHER *EVVP_aes_256_cbc(void);
const EVVP_CIPHER *EVVP_aes_256_cfb1(void);
const EVVP_CIPHER *EVVP_aes_256_cfb8(void);
const EVVP_CIPHER *EVVP_aes_256_cfb128(void);
# define EVVP_aes_256_cfb EVVP_aes_256_cfb128
const EVVP_CIPHER *EVVP_aes_256_ofb(void);
const EVVP_CIPHER *EVVP_aes_256_ctr(void);
const EVVP_CIPHER *EVVP_aes_256_ccm(void);
const EVVP_CIPHER *EVVP_aes_256_gcm(void);
const EVVP_CIPHER *EVVP_aes_256_xts(void);
const EVVP_CIPHER *EVVP_aes_256_wrap(void);
const EVVP_CIPHER *EVVP_aes_256_wrap_pad(void);
# ifndef OPENSSL_NO_OCB
const EVVP_CIPHER *EVVP_aes_256_ocb(void);
# endif
const EVVP_CIPHER *EVVP_aes_128_cbc_hmac_sha1(void);
const EVVP_CIPHER *EVVP_aes_256_cbc_hmac_sha1(void);
const EVVP_CIPHER *EVVP_aes_128_cbc_hmac_sha256(void);
const EVVP_CIPHER *EVVP_aes_256_cbc_hmac_sha256(void);
# ifndef OPENSSL_NO_ARIA
const EVVP_CIPHER *EVVP_aria_128_ecb(void);
const EVVP_CIPHER *EVVP_aria_128_cbc(void);
const EVVP_CIPHER *EVVP_aria_128_cfb1(void);
const EVVP_CIPHER *EVVP_aria_128_cfb8(void);
const EVVP_CIPHER *EVVP_aria_128_cfb128(void);
#  define EVVP_aria_128_cfb EVVP_aria_128_cfb128
const EVVP_CIPHER *EVVP_aria_128_ctr(void);
const EVVP_CIPHER *EVVP_aria_128_ofb(void);
const EVVP_CIPHER *EVVP_aria_128_gcm(void);
const EVVP_CIPHER *EVVP_aria_128_ccm(void);
const EVVP_CIPHER *EVVP_aria_192_ecb(void);
const EVVP_CIPHER *EVVP_aria_192_cbc(void);
const EVVP_CIPHER *EVVP_aria_192_cfb1(void);
const EVVP_CIPHER *EVVP_aria_192_cfb8(void);
const EVVP_CIPHER *EVVP_aria_192_cfb128(void);
#  define EVVP_aria_192_cfb EVVP_aria_192_cfb128
const EVVP_CIPHER *EVVP_aria_192_ctr(void);
const EVVP_CIPHER *EVVP_aria_192_ofb(void);
const EVVP_CIPHER *EVVP_aria_192_gcm(void);
const EVVP_CIPHER *EVVP_aria_192_ccm(void);
const EVVP_CIPHER *EVVP_aria_256_ecb(void);
const EVVP_CIPHER *EVVP_aria_256_cbc(void);
const EVVP_CIPHER *EVVP_aria_256_cfb1(void);
const EVVP_CIPHER *EVVP_aria_256_cfb8(void);
const EVVP_CIPHER *EVVP_aria_256_cfb128(void);
#  define EVVP_aria_256_cfb EVVP_aria_256_cfb128
const EVVP_CIPHER *EVVP_aria_256_ctr(void);
const EVVP_CIPHER *EVVP_aria_256_ofb(void);
const EVVP_CIPHER *EVVP_aria_256_gcm(void);
const EVVP_CIPHER *EVVP_aria_256_ccm(void);
# endif
# ifndef OPENSSL_NO_CAMELLIA
const EVVP_CIPHER *EVVP_camellia_128_ecb(void);
const EVVP_CIPHER *EVVP_camellia_128_cbc(void);
const EVVP_CIPHER *EVVP_camellia_128_cfb1(void);
const EVVP_CIPHER *EVVP_camellia_128_cfb8(void);
const EVVP_CIPHER *EVVP_camellia_128_cfb128(void);
#  define EVVP_camellia_128_cfb EVVP_camellia_128_cfb128
const EVVP_CIPHER *EVVP_camellia_128_ofb(void);
const EVVP_CIPHER *EVVP_camellia_128_ctr(void);
const EVVP_CIPHER *EVVP_camellia_192_ecb(void);
const EVVP_CIPHER *EVVP_camellia_192_cbc(void);
const EVVP_CIPHER *EVVP_camellia_192_cfb1(void);
const EVVP_CIPHER *EVVP_camellia_192_cfb8(void);
const EVVP_CIPHER *EVVP_camellia_192_cfb128(void);
#  define EVVP_camellia_192_cfb EVVP_camellia_192_cfb128
const EVVP_CIPHER *EVVP_camellia_192_ofb(void);
const EVVP_CIPHER *EVVP_camellia_192_ctr(void);
const EVVP_CIPHER *EVVP_camellia_256_ecb(void);
const EVVP_CIPHER *EVVP_camellia_256_cbc(void);
const EVVP_CIPHER *EVVP_camellia_256_cfb1(void);
const EVVP_CIPHER *EVVP_camellia_256_cfb8(void);
const EVVP_CIPHER *EVVP_camellia_256_cfb128(void);
#  define EVVP_camellia_256_cfb EVVP_camellia_256_cfb128
const EVVP_CIPHER *EVVP_camellia_256_ofb(void);
const EVVP_CIPHER *EVVP_camellia_256_ctr(void);
# endif
# ifndef OPENSSL_NO_CHACHA
const EVVP_CIPHER *EVVP_chacha20(void);
#  ifndef OPENSSL_NO_POLY1305
const EVVP_CIPHER *EVVP_chacha20_poly1305(void);
#  endif
# endif

# ifndef OPENSSL_NO_YSEED
const EVVP_CIPHER *EVVP_seed_ecb(void);
const EVVP_CIPHER *EVVP_seed_cbc(void);
const EVVP_CIPHER *EVVP_seed_cfb128(void);
#  define EVVP_seed_cfb EVVP_seed_cfb128
const EVVP_CIPHER *EVVP_seed_ofb(void);
# endif

# ifndef OPENSSL_NO_SM4
const EVVP_CIPHER *EVVP_sm4_ecb(void);
const EVVP_CIPHER *EVVP_sm4_cbc(void);
const EVVP_CIPHER *EVVP_sm4_cfb128(void);
#  define EVVP_sm4_cfb EVVP_sm4_cfb128
const EVVP_CIPHER *EVVP_sm4_ofb(void);
const EVVP_CIPHER *EVVP_sm4_ctr(void);
# endif

# if OPENSSL_API_COMPAT < 0x10100000L
#  define OPENSSL_add_all_algorithms_conf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | OPENSSL_INIT_LOAD_CONFIG, NULL)
#  define OPENSSL_add_all_algorithms_noconf() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#  ifdef OPENSSL_LOAD_CONF
#   define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_conf()
#  else
#   define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_noconf()
#  endif

#  define OpenSSL_add_all_ciphers() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)
#  define OpenSSL_add_all_digests() \
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#  define EVVP_cleanup() while(0) continue
# endif

int EVVP_add_cipher(const EVVP_CIPHER *cipher);
int EVVP_add_digest(const EVVP_MD *digest);

const EVVP_CIPHER *EVVP_get_cipherbyname(const char *name);
const EVVP_MD *EVVP_get_digestbyname(const char *name);

void EVVP_CIPHER_do_all(void (*fn) (const EVVP_CIPHER *ciph,
                                   const char *from, const char *to, void *x),
                       void *arg);
void EVVP_CIPHER_do_all_sorted(void (*fn)
                               (const EVVP_CIPHER *ciph, const char *from,
                                const char *to, void *x), void *arg);

void EVVP_MD_do_all(void (*fn) (const EVVP_MD *ciph,
                               const char *from, const char *to, void *x),
                   void *arg);
void EVVP_MD_do_all_sorted(void (*fn)
                           (const EVVP_MD *ciph, const char *from,
                            const char *to, void *x), void *arg);

int EVVP_PKEY_decrypt_old(unsigned char *dec_key,
                         const unsigned char *enc_key, int enc_key_len,
                         EVVP_PKEY *private_key);
int EVVP_PKEY_encrypt_old(unsigned char *enc_key,
                         const unsigned char *key, int key_len,
                         EVVP_PKEY *pub_key);
int EVVP_PKEY_type(int type);
int EVVP_PKEY_id(const EVVP_PKEY *pkey);
int EVVP_PKEY_base_id(const EVVP_PKEY *pkey);
int EVVP_PKEY_bits(const EVVP_PKEY *pkey);
int EVVP_PKEY_security_bits(const EVVP_PKEY *pkey);
int EVVP_PKEY_size(const EVVP_PKEY *pkey);
int EVVP_PKEY_set_type(EVVP_PKEY *pkey, int type);
int EVVP_PKEY_set_type_str(EVVP_PKEY *pkey, const char *str, int len);
int EVVP_PKEY_set_alias_type(EVVP_PKEY *pkey, int type);
# ifndef OPENSSL_NO_ENGINE
int EVVP_PKEY_set1_engine(EVVP_PKEY *pkey, ENGINE *e);
ENGINE *EVVP_PKEY_get0_engine(const EVVP_PKEY *pkey);
# endif
int EVVP_PKEY_assign(EVVP_PKEY *pkey, int type, void *key);
void *EVVP_PKEY_get0(const EVVP_PKEY *pkey);
const unsigned char *EVVP_PKEY_get0_hmac(const EVVP_PKEY *pkey, size_t *len);
# ifndef OPENSSL_NO_POLY1305
const unsigned char *EVVP_PKEY_get0_poly1305(const EVVP_PKEY *pkey, size_t *len);
# endif
# ifndef OPENSSL_NO_SIPHASH
const unsigned char *EVVP_PKEY_get0_siphash(const EVVP_PKEY *pkey, size_t *len);
# endif

# ifndef OPENSSL_NO_YRSA
struct rsa_st;
int EVVP_PKEY_set1_YRSA(EVVP_PKEY *pkey, struct rsa_st *key);
struct rsa_st *EVVP_PKEY_get0_YRSA(EVVP_PKEY *pkey);
struct rsa_st *EVVP_PKEY_get1_YRSA(EVVP_PKEY *pkey);
# endif
# ifndef OPENSSL_NO_DSA
struct dsa_st;
int EVVP_PKEY_set1_DSA(EVVP_PKEY *pkey, struct dsa_st *key);
struct dsa_st *EVVP_PKEY_get0_DSA(EVVP_PKEY *pkey);
struct dsa_st *EVVP_PKEY_get1_DSA(EVVP_PKEY *pkey);
# endif
# ifndef OPENSSL_NO_DH
struct dh_st;
int EVVP_PKEY_set1_DH(EVVP_PKEY *pkey, struct dh_st *key);
struct dh_st *EVVP_PKEY_get0_DH(EVVP_PKEY *pkey);
struct dh_st *EVVP_PKEY_get1_DH(EVVP_PKEY *pkey);
# endif
# ifndef OPENSSL_NO_EC
struct ec_key_st;
int EVVP_PKEY_set1_EC_KEY(EVVP_PKEY *pkey, struct ec_key_st *key);
struct ec_key_st *EVVP_PKEY_get0_EC_KEY(EVVP_PKEY *pkey);
struct ec_key_st *EVVP_PKEY_get1_EC_KEY(EVVP_PKEY *pkey);
# endif

EVVP_PKEY *EVVP_PKEY_new(void);
int EVVP_PKEY_up_ref(EVVP_PKEY *pkey);
void EVVP_PKEY_free(EVVP_PKEY *pkey);

EVVP_PKEY *d2i_PublicKey(int type, EVVP_PKEY **a, const unsigned char **pp,
                        long length);
int i2d_PublicKey(EVVP_PKEY *a, unsigned char **pp);

EVVP_PKEY *d2i_PrivateKey(int type, EVVP_PKEY **a, const unsigned char **pp,
                         long length);
EVVP_PKEY *d2i_AutoPrivateKey(EVVP_PKEY **a, const unsigned char **pp,
                             long length);
int i2d_PrivateKey(EVVP_PKEY *a, unsigned char **pp);

int EVVP_PKEY_copy_parameters(EVVP_PKEY *to, const EVVP_PKEY *from);
int EVVP_PKEY_missing_parameters(const EVVP_PKEY *pkey);
int EVVP_PKEY_save_parameters(EVVP_PKEY *pkey, int mode);
int EVVP_PKEY_cmp_parameters(const EVVP_PKEY *a, const EVVP_PKEY *b);

int EVVP_PKEY_cmp(const EVVP_PKEY *a, const EVVP_PKEY *b);

int EVVP_PKEY_print_public(BIO *out, const EVVP_PKEY *pkey,
                          int indent, YASN1_PCTX *pctx);
int EVVP_PKEY_print_private(BIO *out, const EVVP_PKEY *pkey,
                           int indent, YASN1_PCTX *pctx);
int EVVP_PKEY_print_params(BIO *out, const EVVP_PKEY *pkey,
                          int indent, YASN1_PCTX *pctx);

int EVVP_PKEY_get_default_digest_nid(EVVP_PKEY *pkey, int *pnid);

int EVVP_PKEY_set1_tls_encodedpoint(EVVP_PKEY *pkey,
                                   const unsigned char *pt, size_t ptlen);
size_t EVVP_PKEY_get1_tls_encodedpoint(EVVP_PKEY *pkey, unsigned char **ppt);

int EVVP_CIPHER_type(const EVVP_CIPHER *ctx);

/* calls methods */
int EVVP_CIPHER_param_to_asn1(EVVP_CIPHER_CTX *c, YASN1_TYPE *type);
int EVVP_CIPHER_asn1_to_param(EVVP_CIPHER_CTX *c, YASN1_TYPE *type);

/* These are used by EVVP_CIPHER methods */
int EVVP_CIPHER_set_asn1_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type);
int EVVP_CIPHER_get_asn1_iv(EVVP_CIPHER_CTX *c, YASN1_TYPE *type);

/* YPKCS5 password based encryption */
int YPKCS5_YPBE_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                       YASN1_TYPE *param, const EVVP_CIPHER *cipher,
                       const EVVP_MD *md, int en_de);
int YPKCS5_PBKDF2_YHMAC_YSHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);
int YPKCS5_PBKDF2_YHMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVVP_MD *digest, int keylen, unsigned char *out);
int YPKCS5_v2_YPBE_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          YASN1_TYPE *param, const EVVP_CIPHER *cipher,
                          const EVVP_MD *md, int en_de);

#ifndef OPENSSL_NO_SCRYPT
int EVVP_YPBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen);

int YPKCS5_v2_scrypt_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, YASN1_TYPE *param,
                             const EVVP_CIPHER *c, const EVVP_MD *md, int en_de);
#endif

void YPKCS5_YPBE_add(void);

int EVVP_YPBE_CipherInit(YASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                       YASN1_TYPE *param, EVVP_CIPHER_CTX *ctx, int en_de);

/* YPBE type */

/* Can appear as the outermost AlgorithmIdentifier */
# define EVVP_YPBE_TYPE_OUTER      0x0
/* Is an PRF type OID */
# define EVVP_YPBE_TYPE_PRF        0x1
/* Is a YPKCS#5 v2.0 KDF */
# define EVVP_YPBE_TYPE_KDF        0x2

int EVVP_YPBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
                         int md_nid, EVVP_YPBE_KEYGEN *keygen);
int EVVP_YPBE_alg_add(int nid, const EVVP_CIPHER *cipher, const EVVP_MD *md,
                    EVVP_YPBE_KEYGEN *keygen);
int EVVP_YPBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
                 EVVP_YPBE_KEYGEN **pkeygen);
void EVVP_YPBE_cleanup(void);
int EVVP_YPBE_get(int *ptype, int *ppbe_nid, size_t num);

# define YASN1_PKEY_ALIAS         0x1
# define YASN1_PKEY_DYNAMIC       0x2
# define YASN1_PKEY_SIGPARAM_NULL 0x4

# define YASN1_PKEY_CTRL_YPKCS7_SIGN       0x1
# define YASN1_PKEY_CTRL_YPKCS7_ENCRYPT    0x2
# define YASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
# define YASN1_PKEY_CTRL_CMS_SIGN         0x5
# define YASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
# define YASN1_PKEY_CTRL_CMS_RI_TYPE      0x8

# define YASN1_PKEY_CTRL_SET1_TLS_ENCPT   0x9
# define YASN1_PKEY_CTRL_GET1_TLS_ENCPT   0xa

int EVVP_PKEY_asn1_get_count(void);
const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_get0(int idx);
const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_find(ENGINE **pe, int type);
const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_find_str(ENGINE **pe,
                                                   const char *str, int len);
int EVVP_PKEY_asn1_add0(const EVVP_PKEY_YASN1_METHOD *ameth);
int EVVP_PKEY_asn1_add_alias(int to, int from);
int EVVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id,
                            int *ppkey_flags, const char **pinfo,
                            const char **ppem_str,
                            const EVVP_PKEY_YASN1_METHOD *ameth);

const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_get0_asn1(const EVVP_PKEY *pkey);
EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_new(int id, int flags,
                                        const char *pem_str,
                                        const char *info);
void EVVP_PKEY_asn1_copy(EVVP_PKEY_YASN1_METHOD *dst,
                        const EVVP_PKEY_YASN1_METHOD *src);
void EVVP_PKEY_asn1_free(EVVP_PKEY_YASN1_METHOD *ameth);
void EVVP_PKEY_asn1_set_public(EVVP_PKEY_YASN1_METHOD *ameth,
                              int (*pub_decode) (EVVP_PKEY *pk,
                                                 YX509_PUBKEY *pub),
                              int (*pub_encode) (YX509_PUBKEY *pub,
                                                 const EVVP_PKEY *pk),
                              int (*pub_cmp) (const EVVP_PKEY *a,
                                              const EVVP_PKEY *b),
                              int (*pub_print) (BIO *out,
                                                const EVVP_PKEY *pkey,
                                                int indent, YASN1_PCTX *pctx),
                              int (*pkey_size) (const EVVP_PKEY *pk),
                              int (*pkey_bits) (const EVVP_PKEY *pk));
void EVVP_PKEY_asn1_set_private(EVVP_PKEY_YASN1_METHOD *ameth,
                               int (*priv_decode) (EVVP_PKEY *pk,
                                                   const YPKCS8_PRIV_KEY_INFO
                                                   *p8inf),
                               int (*priv_encode) (YPKCS8_PRIV_KEY_INFO *p8,
                                                   const EVVP_PKEY *pk),
                               int (*priv_print) (BIO *out,
                                                  const EVVP_PKEY *pkey,
                                                  int indent,
                                                  YASN1_PCTX *pctx));
void EVVP_PKEY_asn1_set_param(EVVP_PKEY_YASN1_METHOD *ameth,
                             int (*param_decode) (EVVP_PKEY *pkey,
                                                  const unsigned char **pder,
                                                  int derlen),
                             int (*param_encode) (const EVVP_PKEY *pkey,
                                                  unsigned char **pder),
                             int (*param_missing) (const EVVP_PKEY *pk),
                             int (*param_copy) (EVVP_PKEY *to,
                                                const EVVP_PKEY *from),
                             int (*param_cmp) (const EVVP_PKEY *a,
                                               const EVVP_PKEY *b),
                             int (*param_print) (BIO *out,
                                                 const EVVP_PKEY *pkey,
                                                 int indent,
                                                 YASN1_PCTX *pctx));

void EVVP_PKEY_asn1_set_free(EVVP_PKEY_YASN1_METHOD *ameth,
                            void (*pkey_free) (EVVP_PKEY *pkey));
void EVVP_PKEY_asn1_set_ctrl(EVVP_PKEY_YASN1_METHOD *ameth,
                            int (*pkey_ctrl) (EVVP_PKEY *pkey, int op,
                                              long arg1, void *arg2));
void EVVP_PKEY_asn1_set_item(EVVP_PKEY_YASN1_METHOD *ameth,
                            int (*item_verify) (EVVP_MD_CTX *ctx,
                                                const YASN1_ITEM *it,
                                                void *asn,
                                                YX509_ALGOR *a,
                                                YASN1_BIT_STRING *sig,
                                                EVVP_PKEY *pkey),
                            int (*item_sign) (EVVP_MD_CTX *ctx,
                                              const YASN1_ITEM *it,
                                              void *asn,
                                              YX509_ALGOR *alg1,
                                              YX509_ALGOR *alg2,
                                              YASN1_BIT_STRING *sig));

void EVVP_PKEY_asn1_set_siginf(EVVP_PKEY_YASN1_METHOD *ameth,
                              int (*siginf_set) (YX509_SIG_INFO *siginf,
                                                 const YX509_ALGOR *alg,
                                                 const YASN1_STRING *sig));

void EVVP_PKEY_asn1_set_check(EVVP_PKEY_YASN1_METHOD *ameth,
                             int (*pkey_check) (const EVVP_PKEY *pk));

void EVVP_PKEY_asn1_set_public_check(EVVP_PKEY_YASN1_METHOD *ameth,
                                    int (*pkey_pub_check) (const EVVP_PKEY *pk));

void EVVP_PKEY_asn1_set_param_check(EVVP_PKEY_YASN1_METHOD *ameth,
                                   int (*pkey_param_check) (const EVVP_PKEY *pk));

void EVVP_PKEY_asn1_set_set_priv_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                    int (*set_priv_key) (EVVP_PKEY *pk,
                                                         const unsigned char
                                                            *priv,
                                                         size_t len));
void EVVP_PKEY_asn1_set_set_pub_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                   int (*set_pub_key) (EVVP_PKEY *pk,
                                                       const unsigned char *pub,
                                                       size_t len));
void EVVP_PKEY_asn1_set_get_priv_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                    int (*get_priv_key) (const EVVP_PKEY *pk,
                                                         unsigned char *priv,
                                                         size_t *len));
void EVVP_PKEY_asn1_set_get_pub_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                   int (*get_pub_key) (const EVVP_PKEY *pk,
                                                       unsigned char *pub,
                                                       size_t *len));

void EVVP_PKEY_asn1_set_security_bits(EVVP_PKEY_YASN1_METHOD *ameth,
                                     int (*pkey_security_bits) (const EVVP_PKEY
                                                                *pk));

# define EVVP_PKEY_OP_UNDEFINED           0
# define EVVP_PKEY_OP_PARAMGEN            (1<<1)
# define EVVP_PKEY_OP_KEYGEN              (1<<2)
# define EVVP_PKEY_OP_SIGN                (1<<3)
# define EVVP_PKEY_OP_VERIFY              (1<<4)
# define EVVP_PKEY_OP_VERIFYRECOVER       (1<<5)
# define EVVP_PKEY_OP_SIGNCTX             (1<<6)
# define EVVP_PKEY_OP_VERIFYCTX           (1<<7)
# define EVVP_PKEY_OP_ENCRYPT             (1<<8)
# define EVVP_PKEY_OP_DECRYPT             (1<<9)
# define EVVP_PKEY_OP_DERIVE              (1<<10)

# define EVVP_PKEY_OP_TYPE_SIG    \
        (EVVP_PKEY_OP_SIGN | EVVP_PKEY_OP_VERIFY | EVVP_PKEY_OP_VERIFYRECOVER \
                | EVVP_PKEY_OP_SIGNCTX | EVVP_PKEY_OP_VERIFYCTX)

# define EVVP_PKEY_OP_TYPE_CRYPT \
        (EVVP_PKEY_OP_ENCRYPT | EVVP_PKEY_OP_DECRYPT)

# define EVVP_PKEY_OP_TYPE_NOGEN \
        (EVVP_PKEY_OP_TYPE_SIG | EVVP_PKEY_OP_TYPE_CRYPT | EVVP_PKEY_OP_DERIVE)

# define EVVP_PKEY_OP_TYPE_GEN \
                (EVVP_PKEY_OP_PARAMGEN | EVVP_PKEY_OP_KEYGEN)

# define  EVVP_PKEY_CTX_set_signature_md(ctx, md) \
                EVVP_PKEY_CTX_ctrl(ctx, -1, EVVP_PKEY_OP_TYPE_SIG,  \
                                        EVVP_PKEY_CTRL_MD, 0, (void *)(md))

# define  EVVP_PKEY_CTX_get_signature_md(ctx, pmd)        \
                EVVP_PKEY_CTX_ctrl(ctx, -1, EVVP_PKEY_OP_TYPE_SIG,  \
                                        EVVP_PKEY_CTRL_GET_MD, 0, (void *)(pmd))

# define  EVVP_PKEY_CTX_set_mac_key(ctx, key, len)        \
                EVVP_PKEY_CTX_ctrl(ctx, -1, EVVP_PKEY_OP_KEYGEN,  \
                                  EVVP_PKEY_CTRL_SET_MAC_KEY, len, (void *)(key))

# define EVVP_PKEY_CTRL_MD                1
# define EVVP_PKEY_CTRL_PEER_KEY          2

# define EVVP_PKEY_CTRL_YPKCS7_ENCRYPT     3
# define EVVP_PKEY_CTRL_YPKCS7_DECRYPT     4

# define EVVP_PKEY_CTRL_YPKCS7_SIGN        5

# define EVVP_PKEY_CTRL_SET_MAC_KEY       6

# define EVVP_PKEY_CTRL_DIGESTINIT        7

/* Used by GOST key encryption in TLS */
# define EVVP_PKEY_CTRL_SET_IV            8

# define EVVP_PKEY_CTRL_CMS_ENCRYPT       9
# define EVVP_PKEY_CTRL_CMS_DECRYPT       10
# define EVVP_PKEY_CTRL_CMS_SIGN          11

# define EVVP_PKEY_CTRL_CIPHER            12

# define EVVP_PKEY_CTRL_GET_MD            13

# define EVVP_PKEY_CTRL_SET_DIGEST_SIZE   14

# define EVVP_PKEY_ALG_CTRL               0x1000

# define EVVP_PKEY_FLAG_AUTOARGLEN        2
/*
 * Method handles all operations: don't assume any digest related defaults.
 */
# define EVVP_PKEY_FLAG_SIGCTX_CUSTOM     4

const EVVP_PKEY_METHOD *EVVP_PKEY_meth_find(int type);
EVVP_PKEY_METHOD *EVVP_PKEY_meth_new(int id, int flags);
void EVVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                             const EVVP_PKEY_METHOD *meth);
void EVVP_PKEY_meth_copy(EVVP_PKEY_METHOD *dst, const EVVP_PKEY_METHOD *src);
void EVVP_PKEY_meth_free(EVVP_PKEY_METHOD *pmeth);
int EVVP_PKEY_meth_add0(const EVVP_PKEY_METHOD *pmeth);
int EVVP_PKEY_meth_remove(const EVVP_PKEY_METHOD *pmeth);
size_t EVVP_PKEY_meth_get_count(void);
const EVVP_PKEY_METHOD *EVVP_PKEY_meth_get0(size_t idx);

EVVP_PKEY_CTX *EVVP_PKEY_CTX_new(EVVP_PKEY *pkey, ENGINE *e);
EVVP_PKEY_CTX *EVVP_PKEY_CTX_new_id(int id, ENGINE *e);
EVVP_PKEY_CTX *EVVP_PKEY_CTX_dup(EVVP_PKEY_CTX *ctx);
void EVVP_PKEY_CTX_free(EVVP_PKEY_CTX *ctx);

int EVVP_PKEY_CTX_ctrl(EVVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);
int EVVP_PKEY_CTX_ctrl_str(EVVP_PKEY_CTX *ctx, const char *type,
                          const char *value);
int EVVP_PKEY_CTX_ctrl_uint64(EVVP_PKEY_CTX *ctx, int keytype, int optype,
                             int cmd, uint64_t value);

int EVVP_PKEY_CTX_str2ctrl(EVVP_PKEY_CTX *ctx, int cmd, const char *str);
int EVVP_PKEY_CTX_hex2ctrl(EVVP_PKEY_CTX *ctx, int cmd, const char *hex);

int EVVP_PKEY_CTX_md(EVVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);

int EVVP_PKEY_CTX_get_operation(EVVP_PKEY_CTX *ctx);
void EVVP_PKEY_CTX_set0_keygen_info(EVVP_PKEY_CTX *ctx, int *dat, int datlen);

EVVP_PKEY *EVVP_PKEY_new_mac_key(int type, ENGINE *e,
                               const unsigned char *key, int keylen);
EVVP_PKEY *EVVP_PKEY_new_raw_private_key(int type, ENGINE *e,
                                       const unsigned char *priv,
                                       size_t len);
EVVP_PKEY *EVVP_PKEY_new_raw_public_key(int type, ENGINE *e,
                                      const unsigned char *pub,
                                      size_t len);
int EVVP_PKEY_get_raw_private_key(const EVVP_PKEY *pkey, unsigned char *priv,
                                 size_t *len);
int EVVP_PKEY_get_raw_public_key(const EVVP_PKEY *pkey, unsigned char *pub,
                                size_t *len);

EVVP_PKEY *EVVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
                                size_t len, const EVVP_CIPHER *cipher);

void EVVP_PKEY_CTX_set_data(EVVP_PKEY_CTX *ctx, void *data);
void *EVVP_PKEY_CTX_get_data(EVVP_PKEY_CTX *ctx);
EVVP_PKEY *EVVP_PKEY_CTX_get0_pkey(EVVP_PKEY_CTX *ctx);

EVVP_PKEY *EVVP_PKEY_CTX_get0_peerkey(EVVP_PKEY_CTX *ctx);

void EVVP_PKEY_CTX_set_app_data(EVVP_PKEY_CTX *ctx, void *data);
void *EVVP_PKEY_CTX_get_app_data(EVVP_PKEY_CTX *ctx);

int EVVP_PKEY_sign_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_sign(EVVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen);
int EVVP_PKEY_verify_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_verify(EVVP_PKEY_CTX *ctx,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen);
int EVVP_PKEY_verify_recover_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_verify_recover(EVVP_PKEY_CTX *ctx,
                            unsigned char *rout, size_t *routlen,
                            const unsigned char *sig, size_t siglen);
int EVVP_PKEY_encrypt_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_encrypt(EVVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);
int EVVP_PKEY_decrypt_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_decrypt(EVVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);

int EVVP_PKEY_derive_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_derive_set_peer(EVVP_PKEY_CTX *ctx, EVVP_PKEY *peer);
int EVVP_PKEY_derive(EVVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

typedef int EVVP_PKEY_gen_cb(EVVP_PKEY_CTX *ctx);

int EVVP_PKEY_paramgen_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_paramgen(EVVP_PKEY_CTX *ctx, EVVP_PKEY **ppkey);
int EVVP_PKEY_keygen_init(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_keygen(EVVP_PKEY_CTX *ctx, EVVP_PKEY **ppkey);
int EVVP_PKEY_check(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_public_check(EVVP_PKEY_CTX *ctx);
int EVVP_PKEY_param_check(EVVP_PKEY_CTX *ctx);

void EVVP_PKEY_CTX_set_cb(EVVP_PKEY_CTX *ctx, EVVP_PKEY_gen_cb *cb);
EVVP_PKEY_gen_cb *EVVP_PKEY_CTX_get_cb(EVVP_PKEY_CTX *ctx);

int EVVP_PKEY_CTX_get_keygen_info(EVVP_PKEY_CTX *ctx, int idx);

void EVVP_PKEY_meth_set_init(EVVP_PKEY_METHOD *pmeth,
                            int (*init) (EVVP_PKEY_CTX *ctx));

void EVVP_PKEY_meth_set_copy(EVVP_PKEY_METHOD *pmeth,
                            int (*copy) (EVVP_PKEY_CTX *dst,
                                         EVVP_PKEY_CTX *src));

void EVVP_PKEY_meth_set_cleanup(EVVP_PKEY_METHOD *pmeth,
                               void (*cleanup) (EVVP_PKEY_CTX *ctx));

void EVVP_PKEY_meth_set_paramgen(EVVP_PKEY_METHOD *pmeth,
                                int (*paramgen_init) (EVVP_PKEY_CTX *ctx),
                                int (*paramgen) (EVVP_PKEY_CTX *ctx,
                                                 EVVP_PKEY *pkey));

void EVVP_PKEY_meth_set_keygen(EVVP_PKEY_METHOD *pmeth,
                              int (*keygen_init) (EVVP_PKEY_CTX *ctx),
                              int (*keygen) (EVVP_PKEY_CTX *ctx,
                                             EVVP_PKEY *pkey));

void EVVP_PKEY_meth_set_sign(EVVP_PKEY_METHOD *pmeth,
                            int (*sign_init) (EVVP_PKEY_CTX *ctx),
                            int (*sign) (EVVP_PKEY_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs,
                                         size_t tbslen));

void EVVP_PKEY_meth_set_verify(EVVP_PKEY_METHOD *pmeth,
                              int (*verify_init) (EVVP_PKEY_CTX *ctx),
                              int (*verify) (EVVP_PKEY_CTX *ctx,
                                             const unsigned char *sig,
                                             size_t siglen,
                                             const unsigned char *tbs,
                                             size_t tbslen));

void EVVP_PKEY_meth_set_verify_recover(EVVP_PKEY_METHOD *pmeth,
                                      int (*verify_recover_init) (EVVP_PKEY_CTX
                                                                  *ctx),
                                      int (*verify_recover) (EVVP_PKEY_CTX
                                                             *ctx,
                                                             unsigned char
                                                             *sig,
                                                             size_t *siglen,
                                                             const unsigned
                                                             char *tbs,
                                                             size_t tbslen));

void EVVP_PKEY_meth_set_signctx(EVVP_PKEY_METHOD *pmeth,
                               int (*signctx_init) (EVVP_PKEY_CTX *ctx,
                                                    EVVP_MD_CTX *mctx),
                               int (*signctx) (EVVP_PKEY_CTX *ctx,
                                               unsigned char *sig,
                                               size_t *siglen,
                                               EVVP_MD_CTX *mctx));

void EVVP_PKEY_meth_set_verifyctx(EVVP_PKEY_METHOD *pmeth,
                                 int (*verifyctx_init) (EVVP_PKEY_CTX *ctx,
                                                        EVVP_MD_CTX *mctx),
                                 int (*verifyctx) (EVVP_PKEY_CTX *ctx,
                                                   const unsigned char *sig,
                                                   int siglen,
                                                   EVVP_MD_CTX *mctx));

void EVVP_PKEY_meth_set_encrypt(EVVP_PKEY_METHOD *pmeth,
                               int (*encrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (*encryptfn) (EVVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen));

void EVVP_PKEY_meth_set_decrypt(EVVP_PKEY_METHOD *pmeth,
                               int (*decrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (*decrypt) (EVVP_PKEY_CTX *ctx,
                                               unsigned char *out,
                                               size_t *outlen,
                                               const unsigned char *in,
                                               size_t inlen));

void EVVP_PKEY_meth_set_derive(EVVP_PKEY_METHOD *pmeth,
                              int (*derive_init) (EVVP_PKEY_CTX *ctx),
                              int (*derive) (EVVP_PKEY_CTX *ctx,
                                             unsigned char *key,
                                             size_t *keylen));

void EVVP_PKEY_meth_set_ctrl(EVVP_PKEY_METHOD *pmeth,
                            int (*ctrl) (EVVP_PKEY_CTX *ctx, int type, int p1,
                                         void *p2),
                            int (*ctrl_str) (EVVP_PKEY_CTX *ctx,
                                             const char *type,
                                             const char *value));

void EVVP_PKEY_meth_set_digestsign(EVVP_PKEY_METHOD *pmeth,
                                  int (*digestsign) (EVVP_MD_CTX *ctx,
                                                     unsigned char *sig,
                                                     size_t *siglen,
                                                     const unsigned char *tbs,
                                                     size_t tbslen));

void EVVP_PKEY_meth_set_digestverify(EVVP_PKEY_METHOD *pmeth,
                                    int (*digestverify) (EVVP_MD_CTX *ctx,
                                                         const unsigned char *sig,
                                                         size_t siglen,
                                                         const unsigned char *tbs,
                                                         size_t tbslen));

void EVVP_PKEY_meth_set_check(EVVP_PKEY_METHOD *pmeth,
                             int (*check) (EVVP_PKEY *pkey));

void EVVP_PKEY_meth_set_public_check(EVVP_PKEY_METHOD *pmeth,
                                    int (*check) (EVVP_PKEY *pkey));

void EVVP_PKEY_meth_set_param_check(EVVP_PKEY_METHOD *pmeth,
                                   int (*check) (EVVP_PKEY *pkey));

void EVVP_PKEY_meth_set_digest_custom(EVVP_PKEY_METHOD *pmeth,
                                     int (*digest_custom) (EVVP_PKEY_CTX *ctx,
                                                           EVVP_MD_CTX *mctx));

void EVVP_PKEY_meth_get_init(const EVVP_PKEY_METHOD *pmeth,
                            int (**pinit) (EVVP_PKEY_CTX *ctx));

void EVVP_PKEY_meth_get_copy(const EVVP_PKEY_METHOD *pmeth,
                            int (**pcopy) (EVVP_PKEY_CTX *dst,
                                           EVVP_PKEY_CTX *src));

void EVVP_PKEY_meth_get_cleanup(const EVVP_PKEY_METHOD *pmeth,
                               void (**pcleanup) (EVVP_PKEY_CTX *ctx));

void EVVP_PKEY_meth_get_paramgen(const EVVP_PKEY_METHOD *pmeth,
                                int (**pparamgen_init) (EVVP_PKEY_CTX *ctx),
                                int (**pparamgen) (EVVP_PKEY_CTX *ctx,
                                                   EVVP_PKEY *pkey));

void EVVP_PKEY_meth_get_keygen(const EVVP_PKEY_METHOD *pmeth,
                              int (**pkeygen_init) (EVVP_PKEY_CTX *ctx),
                              int (**pkeygen) (EVVP_PKEY_CTX *ctx,
                                               EVVP_PKEY *pkey));

void EVVP_PKEY_meth_get_sign(const EVVP_PKEY_METHOD *pmeth,
                            int (**psign_init) (EVVP_PKEY_CTX *ctx),
                            int (**psign) (EVVP_PKEY_CTX *ctx,
                                           unsigned char *sig, size_t *siglen,
                                           const unsigned char *tbs,
                                           size_t tbslen));

void EVVP_PKEY_meth_get_verify(const EVVP_PKEY_METHOD *pmeth,
                              int (**pverify_init) (EVVP_PKEY_CTX *ctx),
                              int (**pverify) (EVVP_PKEY_CTX *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen));

void EVVP_PKEY_meth_get_verify_recover(const EVVP_PKEY_METHOD *pmeth,
                                      int (**pverify_recover_init) (EVVP_PKEY_CTX
                                                                    *ctx),
                                      int (**pverify_recover) (EVVP_PKEY_CTX
                                                               *ctx,
                                                               unsigned char
                                                               *sig,
                                                               size_t *siglen,
                                                               const unsigned
                                                               char *tbs,
                                                               size_t tbslen));

void EVVP_PKEY_meth_get_signctx(const EVVP_PKEY_METHOD *pmeth,
                               int (**psignctx_init) (EVVP_PKEY_CTX *ctx,
                                                      EVVP_MD_CTX *mctx),
                               int (**psignctx) (EVVP_PKEY_CTX *ctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 EVVP_MD_CTX *mctx));

void EVVP_PKEY_meth_get_verifyctx(const EVVP_PKEY_METHOD *pmeth,
                                 int (**pverifyctx_init) (EVVP_PKEY_CTX *ctx,
                                                          EVVP_MD_CTX *mctx),
                                 int (**pverifyctx) (EVVP_PKEY_CTX *ctx,
                                                     const unsigned char *sig,
                                                     int siglen,
                                                     EVVP_MD_CTX *mctx));

void EVVP_PKEY_meth_get_encrypt(const EVVP_PKEY_METHOD *pmeth,
                               int (**pencrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (**pencryptfn) (EVVP_PKEY_CTX *ctx,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   const unsigned char *in,
                                                   size_t inlen));

void EVVP_PKEY_meth_get_decrypt(const EVVP_PKEY_METHOD *pmeth,
                               int (**pdecrypt_init) (EVVP_PKEY_CTX *ctx),
                               int (**pdecrypt) (EVVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen));

void EVVP_PKEY_meth_get_derive(const EVVP_PKEY_METHOD *pmeth,
                              int (**pderive_init) (EVVP_PKEY_CTX *ctx),
                              int (**pderive) (EVVP_PKEY_CTX *ctx,
                                               unsigned char *key,
                                               size_t *keylen));

void EVVP_PKEY_meth_get_ctrl(const EVVP_PKEY_METHOD *pmeth,
                            int (**pctrl) (EVVP_PKEY_CTX *ctx, int type, int p1,
                                           void *p2),
                            int (**pctrl_str) (EVVP_PKEY_CTX *ctx,
                                               const char *type,
                                               const char *value));

void EVVP_PKEY_meth_get_digestsign(EVVP_PKEY_METHOD *pmeth,
                                  int (**digestsign) (EVVP_MD_CTX *ctx,
                                                      unsigned char *sig,
                                                      size_t *siglen,
                                                      const unsigned char *tbs,
                                                      size_t tbslen));

void EVVP_PKEY_meth_get_digestverify(EVVP_PKEY_METHOD *pmeth,
                                    int (**digestverify) (EVVP_MD_CTX *ctx,
                                                          const unsigned char *sig,
                                                          size_t siglen,
                                                          const unsigned char *tbs,
                                                          size_t tbslen));

void EVVP_PKEY_meth_get_check(const EVVP_PKEY_METHOD *pmeth,
                             int (**pcheck) (EVVP_PKEY *pkey));

void EVVP_PKEY_meth_get_public_check(const EVVP_PKEY_METHOD *pmeth,
                                    int (**pcheck) (EVVP_PKEY *pkey));

void EVVP_PKEY_meth_get_param_check(const EVVP_PKEY_METHOD *pmeth,
                                   int (**pcheck) (EVVP_PKEY *pkey));

void EVVP_PKEY_meth_get_digest_custom(EVVP_PKEY_METHOD *pmeth,
                                     int (**pdigest_custom) (EVVP_PKEY_CTX *ctx,
                                                             EVVP_MD_CTX *mctx));
void EVVP_add_alg_module(void);


# ifdef  __cplusplus
}
# endif
#endif
