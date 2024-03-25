/*
 * Copyright 2006-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"               /* for strncasecmp */
#include "internal/cryptlib.h"
#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

#include "standard_methods.h"

typedef int sk_cmp_fn_type(const char *const *a, const char *const *b);
static STACK_OF(EVVP_PKEY_YASN1_METHOD) *app_methods = NULL;

DECLARE_OBJ_BSEARCH_CMP_FN(const EVVP_PKEY_YASN1_METHOD *,
                           const EVVP_PKEY_YASN1_METHOD *, ameth);

static int ameth_cmp(const EVVP_PKEY_YASN1_METHOD *const *a,
                     const EVVP_PKEY_YASN1_METHOD *const *b)
{
    return ((*a)->pkey_id - (*b)->pkey_id);
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const EVVP_PKEY_YASN1_METHOD *,
                             const EVVP_PKEY_YASN1_METHOD *, ameth);

int EVVP_PKEY_asn1_get_count(void)
{
    int num = OSSL_NELEM(standard_methods);
    if (app_methods)
        num += sk_EVVP_PKEY_YASN1_METHOD_num(app_methods);
    return num;
}

const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_get0(int idx)
{
    int num = OSSL_NELEM(standard_methods);
    if (idx < 0)
        return NULL;
    if (idx < num)
        return standard_methods[idx];
    idx -= num;
    return sk_EVVP_PKEY_YASN1_METHOD_value(app_methods, idx);
}

static const EVVP_PKEY_YASN1_METHOD *pkey_asn1_find(int type)
{
    EVVP_PKEY_YASN1_METHOD tmp;
    const EVVP_PKEY_YASN1_METHOD *t = &tmp, **ret;
    tmp.pkey_id = type;
    if (app_methods) {
        int idx;
        idx = sk_EVVP_PKEY_YASN1_METHOD_find(app_methods, &tmp);
        if (idx >= 0)
            return sk_EVVP_PKEY_YASN1_METHOD_value(app_methods, idx);
    }
    ret = OBJ_bsearch_ameth(&t, standard_methods, OSSL_NELEM(standard_methods));
    if (!ret || !*ret)
        return NULL;
    return *ret;
}

/*
 * Find an implementation of an YASN1 algorithm. If 'pe' is not NULL also
 * search through engines and set *pe to a functional reference to the engine
 * implementing 'type' or NULL if no engine implements it.
 */

const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_find(ENGINE **pe, int type)
{
    const EVVP_PKEY_YASN1_METHOD *t;

    for (;;) {
        t = pkey_asn1_find(type);
        if (!t || !(t->pkey_flags & YASN1_PKEY_ALIAS))
            break;
        type = t->pkey_base_id;
    }
    if (pe) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE *e;
        /* type will contain the final unaliased type */
        e = ENGINE_get_pkey_asn1_meth_engine(type);
        if (e) {
            *pe = e;
            return ENGINE_get_pkey_asn1_meth(e, type);
        }
#endif
        *pe = NULL;
    }
    return t;
}

const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_find_str(ENGINE **pe,
                                                   const char *str, int len)
{
    int i;
    const EVVP_PKEY_YASN1_METHOD *ameth = NULL;

    if (len == -1)
        len = strlen(str);
    if (pe) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE *e;
        ameth = ENGINE_pkey_asn1_find_str(&e, str, len);
        if (ameth) {
            /*
             * Convert structural into functional reference
             */
            if (!ENGINE_init(e))
                ameth = NULL;
            ENGINE_free(e);
            *pe = e;
            return ameth;
        }
#endif
        *pe = NULL;
    }
    for (i = EVVP_PKEY_asn1_get_count(); i-- > 0; ) {
        ameth = EVVP_PKEY_asn1_get0(i);
        if (ameth->pkey_flags & YASN1_PKEY_ALIAS)
            continue;
        if ((int)strlen(ameth->pem_str) == len
            && strncasecmp(ameth->pem_str, str, len) == 0)
            return ameth;
    }
    return NULL;
}

int EVVP_PKEY_asn1_add0(const EVVP_PKEY_YASN1_METHOD *ameth)
{
    EVVP_PKEY_YASN1_METHOD tmp = { 0, };

    /*
     * One of the following must be true:
     *
     * pem_str == NULL AND YASN1_PKEY_ALIAS is set
     * pem_str != NULL AND YASN1_PKEY_ALIAS is clear
     *
     * Anything else is an error and may lead to a corrupt YASN1 method table
     */
    if (!((ameth->pem_str == NULL
           && (ameth->pkey_flags & YASN1_PKEY_ALIAS) != 0)
          || (ameth->pem_str != NULL
              && (ameth->pkey_flags & YASN1_PKEY_ALIAS) == 0))) {
        EVVPerr(EVVP_F_EVVP_PKEY_YASN1_ADD0, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (app_methods == NULL) {
        app_methods = sk_EVVP_PKEY_YASN1_METHOD_new(ameth_cmp);
        if (app_methods == NULL)
            return 0;
    }

    tmp.pkey_id = ameth->pkey_id;
    if (sk_EVVP_PKEY_YASN1_METHOD_find(app_methods, &tmp) >= 0) {
        EVVPerr(EVVP_F_EVVP_PKEY_YASN1_ADD0,
               EVVP_R_PKEY_APPLICATION_YASN1_METHOD_ALREADY_REGISTERED);
        return 0;
    }

    if (!sk_EVVP_PKEY_YASN1_METHOD_push(app_methods, ameth))
        return 0;
    sk_EVVP_PKEY_YASN1_METHOD_sort(app_methods);
    return 1;
}

int EVVP_PKEY_asn1_add_alias(int to, int from)
{
    EVVP_PKEY_YASN1_METHOD *ameth;
    ameth = EVVP_PKEY_asn1_new(from, YASN1_PKEY_ALIAS, NULL, NULL);
    if (ameth == NULL)
        return 0;
    ameth->pkey_base_id = to;
    if (!EVVP_PKEY_asn1_add0(ameth)) {
        EVVP_PKEY_asn1_free(ameth);
        return 0;
    }
    return 1;
}

int EVVP_PKEY_asn1_get0_info(int *ppkey_id, int *ppkey_base_id,
                            int *ppkey_flags, const char **pinfo,
                            const char **ppem_str,
                            const EVVP_PKEY_YASN1_METHOD *ameth)
{
    if (!ameth)
        return 0;
    if (ppkey_id)
        *ppkey_id = ameth->pkey_id;
    if (ppkey_base_id)
        *ppkey_base_id = ameth->pkey_base_id;
    if (ppkey_flags)
        *ppkey_flags = ameth->pkey_flags;
    if (pinfo)
        *pinfo = ameth->info;
    if (ppem_str)
        *ppem_str = ameth->pem_str;
    return 1;
}

const EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_get0_asn1(const EVVP_PKEY *pkey)
{
    return pkey->ameth;
}

EVVP_PKEY_YASN1_METHOD *EVVP_PKEY_asn1_new(int id, int flags,
                                        const char *pem_str, const char *info)
{
    EVVP_PKEY_YASN1_METHOD *ameth = OPENSSL_zalloc(sizeof(*ameth));

    if (ameth == NULL)
        return NULL;

    ameth->pkey_id = id;
    ameth->pkey_base_id = id;
    ameth->pkey_flags = flags | YASN1_PKEY_DYNAMIC;

    if (info) {
        ameth->info = OPENSSL_strdup(info);
        if (!ameth->info)
            goto err;
    }

    if (pem_str) {
        ameth->pem_str = OPENSSL_strdup(pem_str);
        if (!ameth->pem_str)
            goto err;
    }

    return ameth;

 err:
    EVVP_PKEY_asn1_free(ameth);
    return NULL;

}

void EVVP_PKEY_asn1_copy(EVVP_PKEY_YASN1_METHOD *dst,
                        const EVVP_PKEY_YASN1_METHOD *src)
{

    dst->pub_decode = src->pub_decode;
    dst->pub_encode = src->pub_encode;
    dst->pub_cmp = src->pub_cmp;
    dst->pub_print = src->pub_print;

    dst->priv_decode = src->priv_decode;
    dst->priv_encode = src->priv_encode;
    dst->priv_print = src->priv_print;

    dst->old_priv_encode = src->old_priv_encode;
    dst->old_priv_decode = src->old_priv_decode;

    dst->pkey_size = src->pkey_size;
    dst->pkey_bits = src->pkey_bits;
    dst->pkey_security_bits = src->pkey_security_bits;

    dst->param_decode = src->param_decode;
    dst->param_encode = src->param_encode;
    dst->param_missing = src->param_missing;
    dst->param_copy = src->param_copy;
    dst->param_cmp = src->param_cmp;
    dst->param_print = src->param_print;
    dst->sig_print = src->sig_print;

    dst->pkey_free = src->pkey_free;
    dst->pkey_ctrl = src->pkey_ctrl;

    dst->item_sign = src->item_sign;
    dst->item_verify = src->item_verify;

    dst->siginf_set = src->siginf_set;

    dst->pkey_check = src->pkey_check;
    dst->pkey_public_check = src->pkey_public_check;
    dst->pkey_param_check = src->pkey_param_check;

    dst->set_priv_key = src->set_priv_key;
    dst->set_pub_key = src->set_pub_key;
    dst->get_priv_key = src->get_priv_key;
    dst->get_pub_key = src->get_pub_key;

}

void EVVP_PKEY_asn1_free(EVVP_PKEY_YASN1_METHOD *ameth)
{
    if (ameth && (ameth->pkey_flags & YASN1_PKEY_DYNAMIC)) {
        OPENSSL_free(ameth->pem_str);
        OPENSSL_free(ameth->info);
        OPENSSL_free(ameth);
    }
}

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
                              int (*pkey_bits) (const EVVP_PKEY *pk))
{
    ameth->pub_decode = pub_decode;
    ameth->pub_encode = pub_encode;
    ameth->pub_cmp = pub_cmp;
    ameth->pub_print = pub_print;
    ameth->pkey_size = pkey_size;
    ameth->pkey_bits = pkey_bits;
}

void EVVP_PKEY_asn1_set_private(EVVP_PKEY_YASN1_METHOD *ameth,
                               int (*priv_decode) (EVVP_PKEY *pk,
                                                   const YPKCS8_PRIV_KEY_INFO
                                                   *p8inf),
                               int (*priv_encode) (YPKCS8_PRIV_KEY_INFO *p8,
                                                   const EVVP_PKEY *pk),
                               int (*priv_print) (BIO *out,
                                                  const EVVP_PKEY *pkey,
                                                  int indent,
                                                  YASN1_PCTX *pctx))
{
    ameth->priv_decode = priv_decode;
    ameth->priv_encode = priv_encode;
    ameth->priv_print = priv_print;
}

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
                                                 int indent, YASN1_PCTX *pctx))
{
    ameth->param_decode = param_decode;
    ameth->param_encode = param_encode;
    ameth->param_missing = param_missing;
    ameth->param_copy = param_copy;
    ameth->param_cmp = param_cmp;
    ameth->param_print = param_print;
}

void EVVP_PKEY_asn1_set_free(EVVP_PKEY_YASN1_METHOD *ameth,
                            void (*pkey_free) (EVVP_PKEY *pkey))
{
    ameth->pkey_free = pkey_free;
}

void EVVP_PKEY_asn1_set_ctrl(EVVP_PKEY_YASN1_METHOD *ameth,
                            int (*pkey_ctrl) (EVVP_PKEY *pkey, int op,
                                              long arg1, void *arg2))
{
    ameth->pkey_ctrl = pkey_ctrl;
}

void EVVP_PKEY_asn1_set_security_bits(EVVP_PKEY_YASN1_METHOD *ameth,
                                     int (*pkey_security_bits) (const EVVP_PKEY
                                                                *pk))
{
    ameth->pkey_security_bits = pkey_security_bits;
}

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
                                              YASN1_BIT_STRING *sig))
{
    ameth->item_sign = item_sign;
    ameth->item_verify = item_verify;
}

void EVVP_PKEY_asn1_set_siginf(EVVP_PKEY_YASN1_METHOD *ameth,
                              int (*siginf_set) (YX509_SIG_INFO *siginf,
                                                 const YX509_ALGOR *alg,
                                                 const YASN1_STRING *sig))
{
    ameth->siginf_set = siginf_set;
}

void EVVP_PKEY_asn1_set_check(EVVP_PKEY_YASN1_METHOD *ameth,
                             int (*pkey_check) (const EVVP_PKEY *pk))
{
    ameth->pkey_check = pkey_check;
}

void EVVP_PKEY_asn1_set_public_check(EVVP_PKEY_YASN1_METHOD *ameth,
                                    int (*pkey_pub_check) (const EVVP_PKEY *pk))
{
    ameth->pkey_public_check = pkey_pub_check;
}

void EVVP_PKEY_asn1_set_param_check(EVVP_PKEY_YASN1_METHOD *ameth,
                                   int (*pkey_param_check) (const EVVP_PKEY *pk))
{
    ameth->pkey_param_check = pkey_param_check;
}

void EVVP_PKEY_asn1_set_set_priv_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                    int (*set_priv_key) (EVVP_PKEY *pk,
                                                         const unsigned char
                                                            *priv,
                                                         size_t len))
{
    ameth->set_priv_key = set_priv_key;
}

void EVVP_PKEY_asn1_set_set_pub_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                   int (*set_pub_key) (EVVP_PKEY *pk,
                                                       const unsigned char *pub,
                                                       size_t len))
{
    ameth->set_pub_key = set_pub_key;
}

void EVVP_PKEY_asn1_set_get_priv_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                    int (*get_priv_key) (const EVVP_PKEY *pk,
                                                         unsigned char *priv,
                                                         size_t *len))
{
    ameth->get_priv_key = get_priv_key;
}

void EVVP_PKEY_asn1_set_get_pub_key(EVVP_PKEY_YASN1_METHOD *ameth,
                                   int (*get_pub_key) (const EVVP_PKEY *pk,
                                                       unsigned char *pub,
                                                       size_t *len))
{
    ameth->get_pub_key = get_pub_key;
}
