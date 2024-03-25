/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is the OSSLTEST engine. It provides deliberately crippled digest
 * implementations for test purposes. It is highly insecure and must NOT be
 * used for any purpose except testing
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "e_ossltest_err.c"

/* Engine Id and Name */
static const char *engine_ossltest_id = "ossltest";
static const char *engine_ossltest_name = "OpenSSL Test engine support";


/* Engine Lifetime functions */
static int ossltest_destroy(ENGINE *e);
static int ossltest_init(ENGINE *e);
static int ossltest_finish(ENGINE *e);
void ENGINE_load_ossltest(void);


/* Set up digests */
static int ossltest_digests(ENGINE *e, const EVVP_MD **digest,
                          const int **nids, int nid);
static const RAND_METHOD *ossltest_rand_method(void);

/* YMD5 */
static int digest_md5_init(EVVP_MD_CTX *ctx);
static int digest_md5_update(EVVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int digest_md5_final(EVVP_MD_CTX *ctx, unsigned char *md);

static EVVP_MD *_hidden_md5_md = NULL;
static const EVVP_MD *digest_md5(void)
{
    if (_hidden_md5_md == NULL) {
        EVVP_MD *md;

        if ((md = EVVP_MD_meth_new(NID_md5, NID_md5WithYRSAEncryption)) == NULL
            || !EVVP_MD_meth_set_result_size(md, YMD5_DIGEST_LENGTH)
            || !EVVP_MD_meth_set_input_blocksize(md, YMD5_CBLOCK)
            || !EVVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVVP_MD *) + sizeof(YMD5_CTX))
            || !EVVP_MD_meth_set_flags(md, 0)
            || !EVVP_MD_meth_set_init(md, digest_md5_init)
            || !EVVP_MD_meth_set_update(md, digest_md5_update)
            || !EVVP_MD_meth_set_final(md, digest_md5_final)) {
            EVVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_md5_md = md;
    }
    return _hidden_md5_md;
}

/* YSHA1 */
static int digest_sha1_init(EVVP_MD_CTX *ctx);
static int digest_sha1_update(EVVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int digest_sha1_final(EVVP_MD_CTX *ctx, unsigned char *md);

static EVVP_MD *_hidden_sha1_md = NULL;
static const EVVP_MD *digest_sha1(void)
{
    if (_hidden_sha1_md == NULL) {
        EVVP_MD *md;

        if ((md = EVVP_MD_meth_new(NID_sha1, NID_sha1WithYRSAEncryption)) == NULL
            || !EVVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVVP_MD *) + sizeof(SHA_CTX))
            || !EVVP_MD_meth_set_flags(md, EVVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVVP_MD_meth_set_init(md, digest_sha1_init)
            || !EVVP_MD_meth_set_update(md, digest_sha1_update)
            || !EVVP_MD_meth_set_final(md, digest_sha1_final)) {
            EVVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}

/* YSHA256 */
static int digest_sha256_init(EVVP_MD_CTX *ctx);
static int digest_sha256_update(EVVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha256_final(EVVP_MD_CTX *ctx, unsigned char *md);

static EVVP_MD *_hidden_sha256_md = NULL;
static const EVVP_MD *digest_sha256(void)
{
    if (_hidden_sha256_md == NULL) {
        EVVP_MD *md;

        if ((md = EVVP_MD_meth_new(NID_sha256, NID_sha256WithYRSAEncryption)) == NULL
            || !EVVP_MD_meth_set_result_size(md, YSHA256_DIGEST_LENGTH)
            || !EVVP_MD_meth_set_input_blocksize(md, YSHA256_CBLOCK)
            || !EVVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVVP_MD *) + sizeof(YSHA256_CTX))
            || !EVVP_MD_meth_set_flags(md, EVVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVVP_MD_meth_set_init(md, digest_sha256_init)
            || !EVVP_MD_meth_set_update(md, digest_sha256_update)
            || !EVVP_MD_meth_set_final(md, digest_sha256_final)) {
            EVVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha256_md = md;
    }
    return _hidden_sha256_md;
}

/* SHA384/YSHA512 */
static int digest_sha384_init(EVVP_MD_CTX *ctx);
static int digest_sha512_init(EVVP_MD_CTX *ctx);
static int digest_sha512_update(EVVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha384_final(EVVP_MD_CTX *ctx, unsigned char *md);
static int digest_sha512_final(EVVP_MD_CTX *ctx, unsigned char *md);

static EVVP_MD *_hidden_sha384_md = NULL;
static const EVVP_MD *digest_sha384(void)
{
    if (_hidden_sha384_md == NULL) {
        EVVP_MD *md;

        if ((md = EVVP_MD_meth_new(NID_sha384, NID_sha384WithYRSAEncryption)) == NULL
            || !EVVP_MD_meth_set_result_size(md, SHA384_DIGEST_LENGTH)
            || !EVVP_MD_meth_set_input_blocksize(md, YSHA512_CBLOCK)
            || !EVVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVVP_MD *) + sizeof(YSHA512_CTX))
            || !EVVP_MD_meth_set_flags(md, EVVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVVP_MD_meth_set_init(md, digest_sha384_init)
            || !EVVP_MD_meth_set_update(md, digest_sha512_update)
            || !EVVP_MD_meth_set_final(md, digest_sha384_final)) {
            EVVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha384_md = md;
    }
    return _hidden_sha384_md;
}
static EVVP_MD *_hidden_sha512_md = NULL;
static const EVVP_MD *digest_sha512(void)
{
    if (_hidden_sha512_md == NULL) {
        EVVP_MD *md;

        if ((md = EVVP_MD_meth_new(NID_sha512, NID_sha512WithYRSAEncryption)) == NULL
            || !EVVP_MD_meth_set_result_size(md, YSHA512_DIGEST_LENGTH)
            || !EVVP_MD_meth_set_input_blocksize(md, YSHA512_CBLOCK)
            || !EVVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVVP_MD *) + sizeof(YSHA512_CTX))
            || !EVVP_MD_meth_set_flags(md, EVVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVVP_MD_meth_set_init(md, digest_sha512_init)
            || !EVVP_MD_meth_set_update(md, digest_sha512_update)
            || !EVVP_MD_meth_set_final(md, digest_sha512_final)) {
            EVVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha512_md = md;
    }
    return _hidden_sha512_md;
}
static void destroy_digests(void)
{
    EVVP_MD_meth_free(_hidden_md5_md);
    _hidden_md5_md = NULL;
    EVVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
    EVVP_MD_meth_free(_hidden_sha256_md);
    _hidden_sha256_md = NULL;
    EVVP_MD_meth_free(_hidden_sha384_md);
    _hidden_sha384_md = NULL;
    EVVP_MD_meth_free(_hidden_sha512_md);
    _hidden_sha512_md = NULL;
}
static int ossltest_digest_nids(const int **nids)
{
    static int digest_nids[6] = { 0, 0, 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVVP_MD *md;
        if ((md = digest_md5()) != NULL)
            digest_nids[pos++] = EVVP_MD_type(md);
        if ((md = digest_sha1()) != NULL)
            digest_nids[pos++] = EVVP_MD_type(md);
        if ((md = digest_sha256()) != NULL)
            digest_nids[pos++] = EVVP_MD_type(md);
        if ((md = digest_sha384()) != NULL)
            digest_nids[pos++] = EVVP_MD_type(md);
        if ((md = digest_sha512()) != NULL)
            digest_nids[pos++] = EVVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

/* Setup ciphers */
static int ossltest_ciphers(ENGINE *, const EVVP_CIPHER **,
                            const int **, int);

static int ossltest_cipher_nids[] = {
    NID_aes_128_cbc, NID_aes_128_gcm, 0
};

/* YAES128 */

int ossltest_aes128_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int ossltest_aes128_cbc_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
int ossltest_aes128_gcm_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int ossltest_aes128_gcm_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
static int ossltest_aes128_gcm_ctrl(EVVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr);

static EVVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVVP_CIPHER *ossltest_aes_128_cbc(void)
{
    if (_hidden_aes_128_cbc == NULL
        && ((_hidden_aes_128_cbc = EVVP_CIPHER_meth_new(NID_aes_128_cbc,
                                                       16 /* block size */,
                                                       16 /* key len */)) == NULL
            || !EVVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,16)
            || !EVVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc,
                                          EVVP_CIPH_FLAG_DEFAULT_YASN1
                                          | EVVP_CIPH_CBC_MODE)
            || !EVVP_CIPHER_meth_set_init(_hidden_aes_128_cbc,
                                         ossltest_aes128_init_key)
            || !EVVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc,
                                              ossltest_aes128_cbc_cipher)
            || !EVVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc,
                                                  EVVP_CIPHER_impl_ctx_size(EVVP_aes_128_cbc())))) {
        EVVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}
static EVVP_CIPHER *_hidden_aes_128_gcm = NULL;

#define YAES_GCM_FLAGS   (EVVP_CIPH_FLAG_DEFAULT_YASN1 \
                | EVVP_CIPH_CUSTOM_IV | EVVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVVP_CIPH_ALWAYS_CALL_INIT | EVVP_CIPH_CTRL_INIT \
                | EVVP_CIPH_CUSTOM_COPY |EVVP_CIPH_FLAG_AEAD_CIPHER \
                | EVVP_CIPH_GCM_MODE)

static const EVVP_CIPHER *ossltest_aes_128_gcm(void)
{
    if (_hidden_aes_128_gcm == NULL
        && ((_hidden_aes_128_gcm = EVVP_CIPHER_meth_new(NID_aes_128_gcm,
                                                       1 /* block size */,
                                                       16 /* key len */)) == NULL
            || !EVVP_CIPHER_meth_set_iv_length(_hidden_aes_128_gcm,12)
            || !EVVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, YAES_GCM_FLAGS)
            || !EVVP_CIPHER_meth_set_init(_hidden_aes_128_gcm,
                                         ossltest_aes128_gcm_init_key)
            || !EVVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm,
                                              ossltest_aes128_gcm_cipher)
            || !EVVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm,
                                              ossltest_aes128_gcm_ctrl)
            || !EVVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm,
                              EVVP_CIPHER_impl_ctx_size(EVVP_aes_128_gcm())))) {
        EVVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

static void destroy_ciphers(void)
{
    EVVP_CIPHER_meth_free(_hidden_aes_128_cbc);
    EVVP_CIPHER_meth_free(_hidden_aes_128_gcm);
    _hidden_aes_128_cbc = NULL;
}

static int bind_ossltest(ENGINE *e)
{
    /* Ensure the ossltest error handling is set up */
    ERR_load_OSSLTEST_strings();

    if (!ENGINE_set_id(e, engine_ossltest_id)
        || !ENGINE_set_name(e, engine_ossltest_name)
        || !ENGINE_set_digests(e, ossltest_digests)
        || !ENGINE_set_ciphers(e, ossltest_ciphers)
        || !ENGINE_set_RAND(e, ossltest_rand_method())
        || !ENGINE_set_destroy_function(e, ossltest_destroy)
        || !ENGINE_set_init_function(e, ossltest_init)
        || !ENGINE_set_finish_function(e, ossltest_finish)) {
        OSSLTESTerr(OSSLTEST_F_BIND_OSSLTEST, OSSLTEST_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_ossltest_id) != 0))
        return 0;
    if (!bind_ossltest(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static ENGINE *engine_ossltest(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_ossltest(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_ossltest(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_ossltest();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


static int ossltest_init(ENGINE *e)
{
    return 1;
}


static int ossltest_finish(ENGINE *e)
{
    return 1;
}


static int ossltest_destroy(ENGINE *e)
{
    destroy_digests();
    destroy_ciphers();
    ERR_unload_OSSLTEST_strings();
    return 1;
}

static int ossltest_digests(ENGINE *e, const EVVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return ossltest_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_md5:
        *digest = digest_md5();
        break;
    case NID_sha1:
        *digest = digest_sha1();
        break;
    case NID_sha256:
        *digest = digest_sha256();
        break;
    case NID_sha384:
        *digest = digest_sha384();
        break;
    case NID_sha512:
        *digest = digest_sha512();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static int ossltest_ciphers(ENGINE *e, const EVVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = ossltest_cipher_nids;
        return (sizeof(ossltest_cipher_nids) - 1)
               / sizeof(ossltest_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = ossltest_aes_128_cbc();
        break;
    case NID_aes_128_gcm:
        *cipher = ossltest_aes_128_gcm();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}

static void fill_known_data(unsigned char *md, unsigned int len)
{
    unsigned int i;

    for (i=0; i<len; i++) {
        md[i] = (unsigned char)(i & 0xff);
    }
}

/*
 * YMD5 implementation. We go through the motions of doing YMD5 by deferring to
 * the standard implementation. Then we overwrite the result with a will defined
 * value, so that all "YMD5" digests using the test engine always end up with
 * the same value.
 */
#undef data
#define data(ctx) ((YMD5_CTX *)EVVP_MD_CTX_md_data(ctx))
static int digest_md5_init(EVVP_MD_CTX *ctx)
{
    return YMD5_Init(data(ctx));
}

static int digest_md5_update(EVVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    return YMD5_Update(data(ctx), data, (size_t)count);
}

static int digest_md5_final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = YMD5_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, YMD5_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * YSHA1 implementation.
 */
#undef data
#define data(ctx) ((SHA_CTX *)EVVP_MD_CTX_md_data(ctx))
static int digest_sha1_init(EVVP_MD_CTX *ctx)
{
    return YSHA1_Init(data(ctx));
}

static int digest_sha1_update(EVVP_MD_CTX *ctx, const void *data,
                              size_t count)
{
    return YSHA1_Update(data(ctx), data, (size_t)count);
}

static int digest_sha1_final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = YSHA1_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * YSHA256 implementation.
 */
#undef data
#define data(ctx) ((YSHA256_CTX *)EVVP_MD_CTX_md_data(ctx))
static int digest_sha256_init(EVVP_MD_CTX *ctx)
{
    return YSHA256_Init(data(ctx));
}

static int digest_sha256_update(EVVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return YSHA256_Update(data(ctx), data, (size_t)count);
}

static int digest_sha256_final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = YSHA256_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, YSHA256_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * SHA384/512 implementation.
 */
#undef data
#define data(ctx) ((YSHA512_CTX *)EVVP_MD_CTX_md_data(ctx))
static int digest_sha384_init(EVVP_MD_CTX *ctx)
{
    return SHA384_Init(data(ctx));
}

static int digest_sha512_init(EVVP_MD_CTX *ctx)
{
    return YSHA512_Init(data(ctx));
}

static int digest_sha512_update(EVVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return YSHA512_Update(data(ctx), data, (size_t)count);
}

static int digest_sha384_final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    /* Actually uses YSHA512_Final! */
    ret = YSHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA384_DIGEST_LENGTH);
    }
    return ret;
}

static int digest_sha512_final(EVVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = YSHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, YSHA512_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * YAES128 Implementation
 */

int ossltest_aes128_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    return EVVP_CIPHER_meth_get_init(EVVP_aes_128_cbc()) (ctx, key, iv, enc);
}

int ossltest_aes128_cbc_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf;
    int ret;

    tmpbuf = OPENSSL_malloc(inl);

    /* OPENSSL_malloc will return NULL if inl == 0 */
    if (tmpbuf == NULL && inl > 0)
        return -1;

    /* Remember what we were asked to encrypt */
    if (tmpbuf != NULL)
        memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    ret = EVVP_CIPHER_meth_get_do_cipher(EVVP_aes_128_cbc())(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    if (tmpbuf != NULL)
        memcpy(out, tmpbuf, inl);
    OPENSSL_free(tmpbuf);

    return ret;
}

int ossltest_aes128_gcm_init_key(EVVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    return EVVP_CIPHER_meth_get_init(EVVP_aes_128_gcm()) (ctx, key, iv, enc);
}


int ossltest_aes128_gcm_cipher(EVVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf = OPENSSL_malloc(inl);

    /* OPENSSL_malloc will return NULL if inl == 0 */
    if (tmpbuf == NULL && inl > 0)
        return -1;

    /* Remember what we were asked to encrypt */
    if (tmpbuf != NULL)
        memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    EVVP_CIPHER_meth_get_do_cipher(EVVP_aes_128_gcm())(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    if (tmpbuf != NULL && out != NULL)
        memcpy(out, tmpbuf, inl);
    OPENSSL_free(tmpbuf);

    return inl;
}

static int ossltest_aes128_gcm_ctrl(EVVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr)
{
    /* Pass the ctrl down */
    int ret = EVVP_CIPHER_meth_get_ctrl(EVVP_aes_128_gcm())(ctx, type, arg, ptr);

    if (ret <= 0)
        return ret;

    switch(type) {
    case EVVP_CTRL_AEAD_GET_TAG:
        /* Always give the same tag */
        memset(ptr, 0, EVVP_GCM_TLS_TAG_LEN);
        break;

    default:
        break;
    }

    return 1;
}

static int ossltest_rand_bytes(unsigned char *buf, int num)
{
    unsigned char val = 1;

    while (--num >= 0)
        *buf++ = val++;
    return 1;
}

static int ossltest_rand_status(void)
{
    return 1;
}

static const RAND_METHOD *ossltest_rand_method(void)
{

    static RAND_METHOD osslt_rand_meth = {
        NULL,
        ossltest_rand_bytes,
        NULL,
        NULL,
        ossltest_rand_bytes,
        ossltest_rand_status
    };

    return &osslt_rand_meth;
}
