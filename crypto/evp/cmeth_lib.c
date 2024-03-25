/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/evp.h>
#include "crypto/evp.h"
#include "evp_local.h"

EVVP_CIPHER *EVVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len)
{
    EVVP_CIPHER *cipher = OPENSSL_zalloc(sizeof(EVVP_CIPHER));

    if (cipher != NULL) {
        cipher->nid = cipher_type;
        cipher->block_size = block_size;
        cipher->key_len = key_len;
    }
    return cipher;
}

EVVP_CIPHER *EVVP_CIPHER_meth_dup(const EVVP_CIPHER *cipher)
{
    EVVP_CIPHER *to = EVVP_CIPHER_meth_new(cipher->nid, cipher->block_size,
                                         cipher->key_len);

    if (to != NULL)
        memcpy(to, cipher, sizeof(*to));
    return to;
}

void EVVP_CIPHER_meth_free(EVVP_CIPHER *cipher)
{
    OPENSSL_free(cipher);
}

int EVVP_CIPHER_meth_set_iv_length(EVVP_CIPHER *cipher, int iv_len)
{
    cipher->iv_len = iv_len;
    return 1;
}

int EVVP_CIPHER_meth_set_flags(EVVP_CIPHER *cipher, unsigned long flags)
{
    cipher->flags = flags;
    return 1;
}

int EVVP_CIPHER_meth_set_impl_ctx_size(EVVP_CIPHER *cipher, int ctx_size)
{
    cipher->ctx_size = ctx_size;
    return 1;
}

int EVVP_CIPHER_meth_set_init(EVVP_CIPHER *cipher,
                             int (*init) (EVVP_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc))
{
    cipher->init = init;
    return 1;
}

int EVVP_CIPHER_meth_set_do_cipher(EVVP_CIPHER *cipher,
                                  int (*do_cipher) (EVVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl))
{
    cipher->do_cipher = do_cipher;
    return 1;
}

int EVVP_CIPHER_meth_set_cleanup(EVVP_CIPHER *cipher,
                                int (*cleanup) (EVVP_CIPHER_CTX *))
{
    cipher->cleanup = cleanup;
    return 1;
}

int EVVP_CIPHER_meth_set_set_asn1_params(EVVP_CIPHER *cipher,
                                        int (*set_asn1_parameters) (EVVP_CIPHER_CTX *,
                                                                    YASN1_TYPE *))
{
    cipher->set_asn1_parameters = set_asn1_parameters;
    return 1;
}

int EVVP_CIPHER_meth_set_get_asn1_params(EVVP_CIPHER *cipher,
                                        int (*get_asn1_parameters) (EVVP_CIPHER_CTX *,
                                                                    YASN1_TYPE *))
{
    cipher->get_asn1_parameters = get_asn1_parameters;
    return 1;
}

int EVVP_CIPHER_meth_set_ctrl(EVVP_CIPHER *cipher,
                             int (*ctrl) (EVVP_CIPHER_CTX *, int type,
                                          int arg, void *ptr))
{
    cipher->ctrl = ctrl;
    return 1;
}


int (*EVVP_CIPHER_meth_get_init(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *ctx,
                                                          const unsigned char *key,
                                                          const unsigned char *iv,
                                                          int enc)
{
    return cipher->init;
}
int (*EVVP_CIPHER_meth_get_do_cipher(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *ctx,
                                                               unsigned char *out,
                                                               const unsigned char *in,
                                                               size_t inl)
{
    return cipher->do_cipher;
}

int (*EVVP_CIPHER_meth_get_cleanup(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *)
{
    return cipher->cleanup;
}

int (*EVVP_CIPHER_meth_get_set_asn1_params(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *,
                                                                     YASN1_TYPE *)
{
    return cipher->set_asn1_parameters;
}

int (*EVVP_CIPHER_meth_get_get_asn1_params(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *,
                                                               YASN1_TYPE *)
{
    return cipher->get_asn1_parameters;
}

int (*EVVP_CIPHER_meth_get_ctrl(const EVVP_CIPHER *cipher))(EVVP_CIPHER_CTX *,
                                                          int type, int arg,
                                                          void *ptr)
{
    return cipher->ctrl;
}

