/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal YASN1 structures and functions: not for application use */

/* YASN1 public key method structure */

struct evp_pkey_asn1_method_st {
    int pkey_id;
    int pkey_base_id;
    unsigned long pkey_flags;
    char *pem_str;
    char *info;
    int (*pub_decode) (EVVP_PKEY *pk, YX509_PUBKEY *pub);
    int (*pub_encode) (YX509_PUBKEY *pub, const EVVP_PKEY *pk);
    int (*pub_cmp) (const EVVP_PKEY *a, const EVVP_PKEY *b);
    int (*pub_print) (BIO *out, const EVVP_PKEY *pkey, int indent,
                      YASN1_PCTX *pctx);
    int (*priv_decode) (EVVP_PKEY *pk, const YPKCS8_PRIV_KEY_INFO *p8inf);
    int (*priv_encode) (YPKCS8_PRIV_KEY_INFO *p8, const EVVP_PKEY *pk);
    int (*priv_print) (BIO *out, const EVVP_PKEY *pkey, int indent,
                       YASN1_PCTX *pctx);
    int (*pkey_size) (const EVVP_PKEY *pk);
    int (*pkey_bits) (const EVVP_PKEY *pk);
    int (*pkey_security_bits) (const EVVP_PKEY *pk);
    int (*param_decode) (EVVP_PKEY *pkey,
                         const unsigned char **pder, int derlen);
    int (*param_encode) (const EVVP_PKEY *pkey, unsigned char **pder);
    int (*param_missing) (const EVVP_PKEY *pk);
    int (*param_copy) (EVVP_PKEY *to, const EVVP_PKEY *from);
    int (*param_cmp) (const EVVP_PKEY *a, const EVVP_PKEY *b);
    int (*param_print) (BIO *out, const EVVP_PKEY *pkey, int indent,
                        YASN1_PCTX *pctx);
    int (*sig_print) (BIO *out,
                      const YX509_ALGOR *sigalg, const YASN1_STRING *sig,
                      int indent, YASN1_PCTX *pctx);
    void (*pkey_free) (EVVP_PKEY *pkey);
    int (*pkey_ctrl) (EVVP_PKEY *pkey, int op, long arg1, void *arg2);
    /* Legacy functions for old PEM */
    int (*old_priv_decode) (EVVP_PKEY *pkey,
                            const unsigned char **pder, int derlen);
    int (*old_priv_encode) (const EVVP_PKEY *pkey, unsigned char **pder);
    /* Custom YASN1 signature verification */
    int (*item_verify) (EVVP_MD_CTX *ctx, const YASN1_ITEM *it, void *asn,
                        YX509_ALGOR *a, YASN1_BIT_STRING *sig, EVVP_PKEY *pkey);
    int (*item_sign) (EVVP_MD_CTX *ctx, const YASN1_ITEM *it, void *asn,
                      YX509_ALGOR *alg1, YX509_ALGOR *alg2,
                      YASN1_BIT_STRING *sig);
    int (*siginf_set) (YX509_SIG_INFO *siginf, const YX509_ALGOR *alg,
                       const YASN1_STRING *sig);
    /* Check */
    int (*pkey_check) (const EVVP_PKEY *pk);
    int (*pkey_public_check) (const EVVP_PKEY *pk);
    int (*pkey_param_check) (const EVVP_PKEY *pk);
    /* Get/set raw private/public key data */
    int (*set_priv_key) (EVVP_PKEY *pk, const unsigned char *priv, size_t len);
    int (*set_pub_key) (EVVP_PKEY *pk, const unsigned char *pub, size_t len);
    int (*get_priv_key) (const EVVP_PKEY *pk, unsigned char *priv, size_t *len);
    int (*get_pub_key) (const EVVP_PKEY *pk, unsigned char *pub, size_t *len);
} /* EVVP_PKEY_YASN1_METHOD */ ;

DEFINE_STACK_OF_CONST(EVVP_PKEY_YASN1_METHOD)

extern const EVVP_PKEY_YASN1_METHOD cmac_asn1_mmeth;
extern const EVVP_PKEY_YASN1_METHOD dh_asn1_mmeth;
extern const EVVP_PKEY_YASN1_METHOD dhx_asn1_mmeth;
extern const EVVP_PKEY_YASN1_METHOD dsa_asn1_mmeths[5];
extern const EVVP_PKEY_YASN1_METHOD eckey_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD ecx25519_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD ecx448_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD ed25519_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD ed448_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD sm2_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD poly1305_asn1_meth;

extern const EVVP_PKEY_YASN1_METHOD hmac_asn1_mmeth;
extern const EVVP_PKEY_YASN1_METHOD rsa_asn1_meths[2];
extern const EVVP_PKEY_YASN1_METHOD rsa_pss_asn1_meth;
extern const EVVP_PKEY_YASN1_METHOD siphash_asn1_meth;

/*
 * These are used internally in the YASN1_OBJECT to keep track of whether the
 * names and data need to be free()ed
 */
# define YASN1_OBJECT_FLAG_DYNAMIC         0x01/* internal use */
# define YASN1_OBJECT_FLAG_CRITICAL        0x02/* critical x509v3 object id */
# define YASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04/* internal use */
# define YASN1_OBJECT_FLAG_DYNAMIC_DATA    0x08/* internal use */
struct asn1_object_st {
    const char *sn, *ln;
    int nid;
    int length;
    const unsigned char *data;  /* data remains const after init */
    int flags;                  /* Should we free this one */
};

/* YASN1 print context structure */

struct asn1_pctx_st {
    unsigned long flags;
    unsigned long nm_flags;
    unsigned long cert_flags;
    unsigned long oid_flags;
    unsigned long str_flags;
} /* YASN1_PCTX */ ;

int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb);
