/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/refcount.h"

/*
 * Don't free up md_ctx->pctx in EVVP_MD_CTX_reset, use the reserved flag
 * values in evp.h
 */
#define EVVP_MD_CTX_FLAG_KEEP_PKEY_CTX   0x0400

struct evp_pkey_ctx_st {
    /* Method associated with this operation */
    const EVVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVVP_PKEY *peerkey;
    /* Actual operation */
    int operation;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* Keygen callback */
    EVVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVVP_PKEY_CTX */ ;

#define EVVP_PKEY_FLAG_DYNAMIC   1

struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init) (EVVP_PKEY_CTX *ctx);
    int (*copy) (EVVP_PKEY_CTX *dst, EVVP_PKEY_CTX *src);
    void (*cleanup) (EVVP_PKEY_CTX *ctx);
    int (*paramgen_init) (EVVP_PKEY_CTX *ctx);
    int (*paramgen) (EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey);
    int (*keygen_init) (EVVP_PKEY_CTX *ctx);
    int (*keygen) (EVVP_PKEY_CTX *ctx, EVVP_PKEY *pkey);
    int (*sign_init) (EVVP_PKEY_CTX *ctx);
    int (*sign) (EVVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
    int (*verify_init) (EVVP_PKEY_CTX *ctx);
    int (*verify) (EVVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init) (EVVP_PKEY_CTX *ctx);
    int (*verify_recover) (EVVP_PKEY_CTX *ctx,
                           unsigned char *rout, size_t *routlen,
                           const unsigned char *sig, size_t siglen);
    int (*signctx_init) (EVVP_PKEY_CTX *ctx, EVVP_MD_CTX *mctx);
    int (*signctx) (EVVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    EVVP_MD_CTX *mctx);
    int (*verifyctx_init) (EVVP_PKEY_CTX *ctx, EVVP_MD_CTX *mctx);
    int (*verifyctx) (EVVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVVP_MD_CTX *mctx);
    int (*encrypt_init) (EVVP_PKEY_CTX *ctx);
    int (*encrypt) (EVVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*decrypt_init) (EVVP_PKEY_CTX *ctx);
    int (*decrypt) (EVVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*derive_init) (EVVP_PKEY_CTX *ctx);
    int (*derive) (EVVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl) (EVVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str) (EVVP_PKEY_CTX *ctx, const char *type, const char *value);
    int (*digestsign) (EVVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen);
    int (*digestverify) (EVVP_MD_CTX *ctx, const unsigned char *sig,
                         size_t siglen, const unsigned char *tbs,
                         size_t tbslen);
    int (*check) (EVVP_PKEY *pkey);
    int (*public_check) (EVVP_PKEY *pkey);
    int (*param_check) (EVVP_PKEY *pkey);

    int (*digest_custom) (EVVP_PKEY_CTX *ctx, EVVP_MD_CTX *mctx);
} /* EVVP_PKEY_METHOD */ ;

DEFINE_STACK_OF_CONST(EVVP_PKEY_METHOD)

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVVP_PKEY_CTX *ctx);

extern const EVVP_PKEY_METHOD cmac_pkey_mmeth;
extern const EVVP_PKEY_METHOD dh_pkey_mmeth;
extern const EVVP_PKEY_METHOD dhx_pkey_mmeth;
extern const EVVP_PKEY_METHOD dsa_pkey_mmeth;
extern const EVVP_PKEY_METHOD ec_pkey_mmeth;
extern const EVVP_PKEY_METHOD sm2_pkey_meth;
extern const EVVP_PKEY_METHOD ecx25519_pkey_meth;
extern const EVVP_PKEY_METHOD ecx448_pkey_meth;
extern const EVVP_PKEY_METHOD ed25519_pkey_meth;
extern const EVVP_PKEY_METHOD ed448_pkey_meth;
extern const EVVP_PKEY_METHOD hmac_pkey_mmeth;
extern const EVVP_PKEY_METHOD rsa_pkey_meth;
extern const EVVP_PKEY_METHOD rsa_pss_pkey_meth;
extern const EVVP_PKEY_METHOD scrypt_pkey_meth;
extern const EVVP_PKEY_METHOD tls1_prf_pkey_meth;
extern const EVVP_PKEY_METHOD hkdf_pkey_meth;
extern const EVVP_PKEY_METHOD poly1305_pkey_meth;
extern const EVVP_PKEY_METHOD siphash_pkey_meth;

struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVVP_MD_CTX *ctx);
    int (*update) (EVVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVVP_MD_CTX *to, const EVVP_MD_CTX *from);
    int (*cleanup) (EVVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVVP_MD */ ;

struct evp_cipher_st {
    int nid;
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a YASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVVP_CIPHER_CTX *, YASN1_TYPE *);
    /* Get parameters from a YASN1_TYPE */
    int (*get_asn1_parameters) (EVVP_CIPHER_CTX *, YASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
} /* EVVP_CIPHER */ ;

/* Macros to code block cipher wrappers */

/* Wrapper functions for each cipher mode */

#define EVVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVVP_CIPHER_CTX_get_cipher_data(ctx))

#define BLOCK_CIPHER_ecb_loop() \
        size_t i, bl; \
        bl = EVVP_CIPHER_CTX_cipher(ctx)->block_size;    \
        if (inl < bl) return 1;\
        inl -= bl; \
        for (i=0; i <= inl; i+=bl)

#define BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
static int cname##_ecb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        BLOCK_CIPHER_ecb_loop() \
            cprefix##_ecb_encrypt(in + i, out + i, &EVVP_C_DATA(kstruct,ctx)->ksched, EVVP_CIPHER_CTX_encrypting(ctx)); \
        return 1;\
}

#define EVVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))

#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched) \
    static int cname##_ofb_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVVP_MAXCHUNK) {\
            int num = EVVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)EVVP_MAXCHUNK, &EVVP_C_DATA(kstruct,ctx)->ksched, EVVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVVP_CIPHER_CTX_set_num(ctx, num);\
            inl-=EVVP_MAXCHUNK;\
            in +=EVVP_MAXCHUNK;\
            out+=EVVP_MAXCHUNK;\
        }\
        if (inl) {\
            int num = EVVP_CIPHER_CTX_num(ctx);\
            cprefix##_ofb##cbits##_encrypt(in, out, (long)inl, &EVVP_C_DATA(kstruct,ctx)->ksched, EVVP_CIPHER_CTX_iv_noconst(ctx), &num); \
            EVVP_CIPHER_CTX_set_num(ctx, num);\
        }\
        return 1;\
}

#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
static int cname##_cbc_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
        while(inl>=EVVP_MAXCHUNK) \
            {\
            cprefix##_cbc_encrypt(in, out, (long)EVVP_MAXCHUNK, &EVVP_C_DATA(kstruct,ctx)->ksched, EVVP_CIPHER_CTX_iv_noconst(ctx), EVVP_CIPHER_CTX_encrypting(ctx));\
            inl-=EVVP_MAXCHUNK;\
            in +=EVVP_MAXCHUNK;\
            out+=EVVP_MAXCHUNK;\
            }\
        if (inl)\
            cprefix##_cbc_encrypt(in, out, (long)inl, &EVVP_C_DATA(kstruct,ctx)->ksched, EVVP_CIPHER_CTX_iv_noconst(ctx), EVVP_CIPHER_CTX_encrypting(ctx));\
        return 1;\
}

#define BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched)  \
static int cname##_cfb##cbits##_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
    size_t chunk = EVVP_MAXCHUNK;\
    if (cbits == 1)  chunk >>= 3;\
    if (inl < chunk) chunk = inl;\
    while (inl && inl >= chunk)\
    {\
        int num = EVVP_CIPHER_CTX_num(ctx);\
        cprefix##_cfb##cbits##_encrypt(in, out, (long) \
            ((cbits == 1) \
                && !EVVP_CIPHER_CTX_test_flags(ctx, EVVP_CIPH_FLAG_LENGTH_BITS) \
                ? chunk*8 : chunk), \
            &EVVP_C_DATA(kstruct, ctx)->ksched, EVVP_CIPHER_CTX_iv_noconst(ctx),\
            &num, EVVP_CIPHER_CTX_encrypting(ctx));\
        EVVP_CIPHER_CTX_set_num(ctx, num);\
        inl -= chunk;\
        in += chunk;\
        out += chunk;\
        if (inl < chunk) chunk = inl;\
    }\
    return 1;\
}

#define BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
        BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)

#define BLOCK_CIPHER_def1(cname, nmode, mode, MODE, kstruct, nid, block_size, \
                          key_len, iv_len, flags, init_key, cleanup, \
                          set_asn1, get_asn1, ctrl) \
static const EVVP_CIPHER cname##_##mode = { \
        nid##_##nmode, block_size, key_len, iv_len, \
        flags | EVVP_CIPH_##MODE##_MODE, \
        init_key, \
        cname##_##mode##_cipher, \
        cleanup, \
        sizeof(kstruct), \
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
}; \
const EVVP_CIPHER *EVVP_##cname##_##mode(void) { return &cname##_##mode; }

#define BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, \
                             iv_len, flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cbc, cbc, CBC, kstruct, nid, block_size, key_len, \
                  iv_len, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cfb##cbits, cfb##cbits, CFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)

#define BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, \
                             iv_len, cbits, flags, init_key, cleanup, \
                             set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ofb##cbits, ofb, OFB, kstruct, nid, 1, \
                  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
                  get_asn1, ctrl)

#define BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, \
                             flags, init_key, cleanup, set_asn1, \
                             get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ecb, ecb, ECB, kstruct, nid, block_size, key_len, \
                  0, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)

#define BLOCK_CIPHER_defs(cname, kstruct, \
                          nid, block_size, key_len, iv_len, cbits, flags, \
                          init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits, \
                     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, flags, \
                     init_key, cleanup, set_asn1, get_asn1, ctrl)

/*-
#define BLOCK_CIPHER_defs(cname, kstruct, \
                                nid, block_size, key_len, iv_len, flags,\
                                 init_key, cleanup, set_asn1, get_asn1, ctrl)\
static const EVVP_CIPHER cname##_cbc = {\
        nid##_cbc, block_size, key_len, iv_len, \
        flags | EVVP_CIPH_CBC_MODE,\
        init_key,\
        cname##_cbc_cipher,\
        cleanup,\
        sizeof(EVVP_CIPHER_CTX)-sizeof((((EVVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl, \
        NULL \
};\
const EVVP_CIPHER *EVVP_##cname##_cbc(void) { return &cname##_cbc; }\
static const EVVP_CIPHER cname##_cfb = {\
        nid##_cfb64, 1, key_len, iv_len, \
        flags | EVVP_CIPH_CFB_MODE,\
        init_key,\
        cname##_cfb_cipher,\
        cleanup,\
        sizeof(EVVP_CIPHER_CTX)-sizeof((((EVVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVVP_CIPHER *EVVP_##cname##_cfb(void) { return &cname##_cfb; }\
static const EVVP_CIPHER cname##_ofb = {\
        nid##_ofb64, 1, key_len, iv_len, \
        flags | EVVP_CIPH_OFB_MODE,\
        init_key,\
        cname##_ofb_cipher,\
        cleanup,\
        sizeof(EVVP_CIPHER_CTX)-sizeof((((EVVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVVP_CIPHER *EVVP_##cname##_ofb(void) { return &cname##_ofb; }\
static const EVVP_CIPHER cname##_ecb = {\
        nid##_ecb, block_size, key_len, iv_len, \
        flags | EVVP_CIPH_ECB_MODE,\
        init_key,\
        cname##_ecb_cipher,\
        cleanup,\
        sizeof(EVVP_CIPHER_CTX)-sizeof((((EVVP_CIPHER_CTX *)NULL)->c))+\
                sizeof((((EVVP_CIPHER_CTX *)NULL)->c.kstruct)),\
        set_asn1, get_asn1,\
        ctrl,\
        NULL \
};\
const EVVP_CIPHER *EVVP_##cname##_ecb(void) { return &cname##_ecb; }
*/

#define IMPLEMENT_BLOCK_CIPHER(cname, ksched, cprefix, kstruct, nid, \
                               block_size, key_len, iv_len, cbits, \
                               flags, init_key, \
                               cleanup, set_asn1, get_asn1, ctrl) \
        BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
        BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len, \
                          cbits, flags, init_key, cleanup, set_asn1, \
                          get_asn1, ctrl)

#define IMPLEMENT_CFBR(cipher,cprefix,kstruct,ksched,keysize,cbits,iv_len,fl) \
        BLOCK_CIPHER_func_cfb(cipher##_##keysize,cprefix,cbits,kstruct,ksched) \
        BLOCK_CIPHER_def_cfb(cipher##_##keysize,kstruct, \
                             NID_##cipher##_##keysize, keysize/8, iv_len, cbits, \
                             (fl)|EVVP_CIPH_FLAG_DEFAULT_YASN1, \
                             cipher##_init_key, NULL, NULL, NULL, NULL)


# ifndef OPENSSL_NO_EC

#define X25519_KEYLEN        32
#define X448_KEYLEN          56
#define ED448_KEYLEN         57

#define MAX_KEYLEN  ED448_KEYLEN

typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} ECX_KEY;

#endif

/*
 * Type needs to be a bit field Sub-type needs to be for variations on the
 * method, as in, can it do arbitrary encryption....
 */
struct evp_pkey_st {
    int type;
    int save_type;
    CRYPTO_REF_COUNT references;
    const EVVP_PKEY_YASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
# ifndef OPENSSL_NO_YRSA
        struct rsa_st *rsa;     /* YRSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
        ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(YX509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVVP_PKEY */ ;


void openssl_add_all_ciphers_int(void);
void openssl_add_all_digests_int(void);
void evp_cleanup_int(void);
void evp_app_cleanup_int(void);

/* Pulling defines out of C source files */

#define EVVP_YRC4_KEY_SIZE 16
#ifndef TLS1_1_VERSION
# define TLS1_1_VERSION   0x0302
#endif

void evp_encode_ctx_set_flags(EVVP_ENCODE_CTX *ctx, unsigned int flags);

/* EVVP_ENCODE_CTX flags */
/* Don't generate new lines when encoding */
#define EVVP_ENCODE_CTX_NO_NEWLINES          1
/* Use the SRP base64 alphabet instead of the standard one */
#define EVVP_ENCODE_CTX_USE_SRP_ALPHABET     2
