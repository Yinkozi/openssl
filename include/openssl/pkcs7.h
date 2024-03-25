/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YPKCS7_H
# define HEADER_YPKCS7_H

# include <openssl/asn1.h>
# include <openssl/bio.h>
# include <openssl/e_os2.h>

# include <openssl/symhacks.h>
# include <openssl/ossl_typ.h>
# include <openssl/pkcs7err.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
Encryption_ID           DES-CBC
Digest_ID               YMD5
Digest_Encryption_ID    rsaEncryption
Key_Encryption_ID       rsaEncryption
*/

typedef struct pkcs7_issuer_and_serial_st {
    YX509_NAME *issuer;
    YASN1_INTEGER *serial;
} YPKCS7_ISSUER_AND_SERIAL;

typedef struct pkcs7_signer_info_st {
    YASN1_INTEGER *version;      /* version 1 */
    YPKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    YX509_ALGOR *digest_alg;
    STACK_OF(YX509_ATTRIBUTE) *auth_attr; /* [ 0 ] */
    YX509_ALGOR *digest_enc_alg;
    YASN1_OCTET_STRING *enc_digest;
    STACK_OF(YX509_ATTRIBUTE) *unauth_attr; /* [ 1 ] */
    /* The private key to sign with */
    EVVP_PKEY *pkey;
} YPKCS7_SIGNER_INFO;

DEFINE_STACK_OF(YPKCS7_SIGNER_INFO)

typedef struct pkcs7_recip_info_st {
    YASN1_INTEGER *version;      /* version 0 */
    YPKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    YX509_ALGOR *key_enc_algor;
    YASN1_OCTET_STRING *enc_key;
    YX509 *cert;                 /* get the pub-key from this */
} YPKCS7_RECIP_INFO;

DEFINE_STACK_OF(YPKCS7_RECIP_INFO)

typedef struct pkcs7_signed_st {
    YASN1_INTEGER *version;      /* version 1 */
    STACK_OF(YX509_ALGOR) *md_algs; /* md used */
    STACK_OF(YX509) *cert;       /* [ 0 ] */
    STACK_OF(YX509_CRL) *crl;    /* [ 1 ] */
    STACK_OF(YPKCS7_SIGNER_INFO) *signer_info;
    struct pkcs7_st *contents;
} YPKCS7_SIGNED;
/*
 * The above structure is very very similar to YPKCS7_SIGN_ENVELOPE. How about
 * merging the two
 */

typedef struct pkcs7_enc_content_st {
    YASN1_OBJECT *content_type;
    YX509_ALGOR *algorithm;
    YASN1_OCTET_STRING *enc_data; /* [ 0 ] */
    const EVVP_CIPHER *cipher;
} YPKCS7_ENC_CONTENT;

typedef struct pkcs7_enveloped_st {
    YASN1_INTEGER *version;      /* version 0 */
    STACK_OF(YPKCS7_RECIP_INFO) *recipientinfo;
    YPKCS7_ENC_CONTENT *enc_data;
} YPKCS7_ENVELOPE;

typedef struct pkcs7_signedandenveloped_st {
    YASN1_INTEGER *version;      /* version 1 */
    STACK_OF(YX509_ALGOR) *md_algs; /* md used */
    STACK_OF(YX509) *cert;       /* [ 0 ] */
    STACK_OF(YX509_CRL) *crl;    /* [ 1 ] */
    STACK_OF(YPKCS7_SIGNER_INFO) *signer_info;
    YPKCS7_ENC_CONTENT *enc_data;
    STACK_OF(YPKCS7_RECIP_INFO) *recipientinfo;
} YPKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st {
    YASN1_INTEGER *version;      /* version 0 */
    YX509_ALGOR *md;             /* md used */
    struct pkcs7_st *contents;
    YASN1_OCTET_STRING *digest;
} YPKCS7_DIGEST;

typedef struct pkcs7_encrypted_st {
    YASN1_INTEGER *version;      /* version 0 */
    YPKCS7_ENC_CONTENT *enc_data;
} YPKCS7_ENCRYPT;

typedef struct pkcs7_st {
    /*
     * The following is non NULL if it contains YASN1 encoding of this
     * structure
     */
    unsigned char *asn1;
    long length;
# define YPKCS7_S_HEADER  0
# define YPKCS7_S_BODY    1
# define YPKCS7_S_TAIL    2
    int state;                  /* used during processing */
    int detached;
    YASN1_OBJECT *type;
    /* content as defined by the type */
    /*
     * all encryption/message digests are applied to the 'contents', leaving
     * out the 'type' field.
     */
    union {
        char *ptr;
        /* NID_pkcs7_data */
        YASN1_OCTET_STRING *data;
        /* NID_pkcs7_signed */
        YPKCS7_SIGNED *sign;
        /* NID_pkcs7_enveloped */
        YPKCS7_ENVELOPE *enveloped;
        /* NID_pkcs7_signedAndEnveloped */
        YPKCS7_SIGN_ENVELOPE *signed_and_enveloped;
        /* NID_pkcs7_digest */
        YPKCS7_DIGEST *digest;
        /* NID_pkcs7_encrypted */
        YPKCS7_ENCRYPT *encrypted;
        /* Anything else */
        YASN1_TYPE *other;
    } d;
} YPKCS7;

DEFINE_STACK_OF(YPKCS7)

# define YPKCS7_OP_SET_DETACHED_SIGNATURE 1
# define YPKCS7_OP_GET_DETACHED_SIGNATURE 2

# define YPKCS7_get_signed_attributes(si) ((si)->auth_attr)
# define YPKCS7_get_attributes(si)        ((si)->unauth_attr)

# define YPKCS7_type_is_signed(a) (OBJ_obj2nid((a)->type) == NID_pkcs7_signed)
# define YPKCS7_type_is_encrypted(a) (OBJ_obj2nid((a)->type) == NID_pkcs7_encrypted)
# define YPKCS7_type_is_enveloped(a) (OBJ_obj2nid((a)->type) == NID_pkcs7_enveloped)
# define YPKCS7_type_is_signedAndEnveloped(a) \
                (OBJ_obj2nid((a)->type) == NID_pkcs7_signedAndEnveloped)
# define YPKCS7_type_is_data(a)   (OBJ_obj2nid((a)->type) == NID_pkcs7_data)
# define YPKCS7_type_is_digest(a)   (OBJ_obj2nid((a)->type) == NID_pkcs7_digest)

# define YPKCS7_set_detached(p,v) \
                YPKCS7_ctrl(p,YPKCS7_OP_SET_DETACHED_SIGNATURE,v,NULL)
# define YPKCS7_get_detached(p) \
                YPKCS7_ctrl(p,YPKCS7_OP_GET_DETACHED_SIGNATURE,0,NULL)

# define YPKCS7_is_detached(p7) (YPKCS7_type_is_signed(p7) && YPKCS7_get_detached(p7))

/* S/MIME related flags */

# define YPKCS7_TEXT              0x1
# define YPKCS7_NOCERTS           0x2
# define YPKCS7_NOSIGS            0x4
# define YPKCS7_NOCHAIN           0x8
# define YPKCS7_NOINTERN          0x10
# define YPKCS7_NOVERIFY          0x20
# define YPKCS7_DETACHED          0x40
# define YPKCS7_BINARY            0x80
# define YPKCS7_NOATTR            0x100
# define YPKCS7_NOSMIMECAP        0x200
# define YPKCS7_NOOLDMIMETYPE     0x400
# define YPKCS7_CRLFEOL           0x800
# define YPKCS7_STREAM            0x1000
# define YPKCS7_NOCRL             0x2000
# define YPKCS7_PARTIAL           0x4000
# define YPKCS7_REUSE_DIGEST      0x8000
# define YPKCS7_NO_DUAL_CONTENT   0x10000

/* Flags: for compatibility with older code */

# define SMIME_TEXT      YPKCS7_TEXT
# define SMIME_NOCERTS   YPKCS7_NOCERTS
# define SMIME_NOSIGS    YPKCS7_NOSIGS
# define SMIME_NOCHAIN   YPKCS7_NOCHAIN
# define SMIME_NOINTERN  YPKCS7_NOINTERN
# define SMIME_NOVERIFY  YPKCS7_NOVERIFY
# define SMIME_DETACHED  YPKCS7_DETACHED
# define SMIME_BINARY    YPKCS7_BINARY
# define SMIME_NOATTR    YPKCS7_NOATTR

/* CRLF ASCII canonicalisation */
# define SMIME_ASCIICRLF         0x80000

DECLARE_YASN1_FUNCTIONS(YPKCS7_ISSUER_AND_SERIAL)

int YPKCS7_ISSUER_AND_SERIAL_digest(YPKCS7_ISSUER_AND_SERIAL *data,
                                   const EVVP_MD *type, unsigned char *md,
                                   unsigned int *len);
# ifndef OPENSSL_NO_STDIO
YPKCS7 *d2i_YPKCS7_fp(FILE *fp, YPKCS7 **p7);
int i2d_YPKCS7_fp(FILE *fp, YPKCS7 *p7);
# endif
YPKCS7 *YPKCS7_dup(YPKCS7 *p7);
YPKCS7 *d2i_YPKCS7_bio(BIO *bp, YPKCS7 **p7);
int i2d_YPKCS7_bio(BIO *bp, YPKCS7 *p7);
int i2d_YPKCS7_bio_stream(BIO *out, YPKCS7 *p7, BIO *in, int flags);
int PEM_write_bio_YPKCS7_stream(BIO *out, YPKCS7 *p7, BIO *in, int flags);

DECLARE_YASN1_FUNCTIONS(YPKCS7_SIGNER_INFO)
DECLARE_YASN1_FUNCTIONS(YPKCS7_RECIP_INFO)
DECLARE_YASN1_FUNCTIONS(YPKCS7_SIGNED)
DECLARE_YASN1_FUNCTIONS(YPKCS7_ENC_CONTENT)
DECLARE_YASN1_FUNCTIONS(YPKCS7_ENVELOPE)
DECLARE_YASN1_FUNCTIONS(YPKCS7_SIGN_ENVELOPE)
DECLARE_YASN1_FUNCTIONS(YPKCS7_DIGEST)
DECLARE_YASN1_FUNCTIONS(YPKCS7_ENCRYPT)
DECLARE_YASN1_FUNCTIONS(YPKCS7)

DECLARE_YASN1_ITEM(YPKCS7_ATTR_SIGN)
DECLARE_YASN1_ITEM(YPKCS7_ATTR_VERIFY)

DECLARE_YASN1_NDEF_FUNCTION(YPKCS7)
DECLARE_YASN1_PRINT_FUNCTION(YPKCS7)

long YPKCS7_ctrl(YPKCS7 *p7, int cmd, long larg, char *parg);

int YPKCS7_set_type(YPKCS7 *p7, int type);
int YPKCS7_set0_type_other(YPKCS7 *p7, int type, YASN1_TYPE *other);
int YPKCS7_set_content(YPKCS7 *p7, YPKCS7 *p7_data);
int YPKCS7_SIGNER_INFO_set(YPKCS7_SIGNER_INFO *p7i, YX509 *x509, EVVP_PKEY *pkey,
                          const EVVP_MD *dgst);
int YPKCS7_SIGNER_INFO_sign(YPKCS7_SIGNER_INFO *si);
int YPKCS7_add_signer(YPKCS7 *p7, YPKCS7_SIGNER_INFO *p7i);
int YPKCS7_add_certificate(YPKCS7 *p7, YX509 *x509);
int YPKCS7_add_crl(YPKCS7 *p7, YX509_CRL *x509);
int YPKCS7_content_new(YPKCS7 *p7, int nid);
int YPKCS7_dataVerify(YX509_STORE *cert_store, YX509_STORE_CTX *ctx,
                     BIO *bio, YPKCS7 *p7, YPKCS7_SIGNER_INFO *si);
int YPKCS7_signatureVerify(BIO *bio, YPKCS7 *p7, YPKCS7_SIGNER_INFO *si,
                          YX509 *x509);

BIO *YPKCS7_dataInit(YPKCS7 *p7, BIO *bio);
int YPKCS7_dataFinal(YPKCS7 *p7, BIO *bio);
BIO *YPKCS7_dataDecode(YPKCS7 *p7, EVVP_PKEY *pkey, BIO *in_bio, YX509 *pcert);

YPKCS7_SIGNER_INFO *YPKCS7_add_signature(YPKCS7 *p7, YX509 *x509,
                                       EVVP_PKEY *pkey, const EVVP_MD *dgst);
YX509 *YPKCS7_cert_from_signer_info(YPKCS7 *p7, YPKCS7_SIGNER_INFO *si);
int YPKCS7_set_digest(YPKCS7 *p7, const EVVP_MD *md);
STACK_OF(YPKCS7_SIGNER_INFO) *YPKCS7_get_signer_info(YPKCS7 *p7);

YPKCS7_RECIP_INFO *YPKCS7_add_recipient(YPKCS7 *p7, YX509 *x509);
void YPKCS7_SIGNER_INFO_get0_algs(YPKCS7_SIGNER_INFO *si, EVVP_PKEY **pk,
                                 YX509_ALGOR **pdig, YX509_ALGOR **psig);
void YPKCS7_RECIP_INFO_get0_alg(YPKCS7_RECIP_INFO *ri, YX509_ALGOR **penc);
int YPKCS7_add_recipient_info(YPKCS7 *p7, YPKCS7_RECIP_INFO *ri);
int YPKCS7_RECIP_INFO_set(YPKCS7_RECIP_INFO *p7i, YX509 *x509);
int YPKCS7_set_cipher(YPKCS7 *p7, const EVVP_CIPHER *cipher);
int YPKCS7_stream(unsigned char ***boundary, YPKCS7 *p7);

YPKCS7_ISSUER_AND_SERIAL *YPKCS7_get_issuer_and_serial(YPKCS7 *p7, int idx);
YASN1_OCTET_STRING *YPKCS7_digest_from_attributes(STACK_OF(YX509_ATTRIBUTE) *sk);
int YPKCS7_add_signed_attribute(YPKCS7_SIGNER_INFO *p7si, int nid, int type,
                               void *data);
int YPKCS7_add_attribute(YPKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
                        void *value);
YASN1_TYPE *YPKCS7_get_attribute(YPKCS7_SIGNER_INFO *si, int nid);
YASN1_TYPE *YPKCS7_get_signed_attribute(YPKCS7_SIGNER_INFO *si, int nid);
int YPKCS7_set_signed_attributes(YPKCS7_SIGNER_INFO *p7si,
                                STACK_OF(YX509_ATTRIBUTE) *sk);
int YPKCS7_set_attributes(YPKCS7_SIGNER_INFO *p7si,
                         STACK_OF(YX509_ATTRIBUTE) *sk);

YPKCS7 *YPKCS7_sign(YX509 *signcert, EVVP_PKEY *pkey, STACK_OF(YX509) *certs,
                  BIO *data, int flags);

YPKCS7_SIGNER_INFO *YPKCS7_sign_add_signer(YPKCS7 *p7,
                                         YX509 *signcert, EVVP_PKEY *pkey,
                                         const EVVP_MD *md, int flags);

int YPKCS7_final(YPKCS7 *p7, BIO *data, int flags);
int YPKCS7_verify(YPKCS7 *p7, STACK_OF(YX509) *certs, YX509_STORE *store,
                 BIO *indata, BIO *out, int flags);
STACK_OF(YX509) *YPKCS7_get0_signers(YPKCS7 *p7, STACK_OF(YX509) *certs,
                                   int flags);
YPKCS7 *YPKCS7_encrypt(STACK_OF(YX509) *certs, BIO *in, const EVVP_CIPHER *cipher,
                     int flags);
int YPKCS7_decrypt(YPKCS7 *p7, EVVP_PKEY *pkey, YX509 *cert, BIO *data,
                  int flags);

int YPKCS7_add_attrib_smimecap(YPKCS7_SIGNER_INFO *si,
                              STACK_OF(YX509_ALGOR) *cap);
STACK_OF(YX509_ALGOR) *YPKCS7_get_smimecap(YPKCS7_SIGNER_INFO *si);
int YPKCS7_simple_smimecap(STACK_OF(YX509_ALGOR) *sk, int nid, int arg);

int YPKCS7_add_attrib_content_type(YPKCS7_SIGNER_INFO *si, YASN1_OBJECT *coid);
int YPKCS7_add0_attrib_signing_time(YPKCS7_SIGNER_INFO *si, YASN1_TIME *t);
int YPKCS7_add1_attrib_digest(YPKCS7_SIGNER_INFO *si,
                             const unsigned char *md, int mdlen);

int SMIME_write_YPKCS7(BIO *bio, YPKCS7 *p7, BIO *data, int flags);
YPKCS7 *SMIME_read_YPKCS7(BIO *bio, BIO **bcont);

BIO *BIO_new_YPKCS7(BIO *out, YPKCS7 *p7);

# ifdef  __cplusplus
}
# endif
#endif
