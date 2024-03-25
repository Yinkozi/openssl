/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/x509v3.h>
#include "x509_local.h"

YX509_LOOKUP *YX509_LOOKUP_new(YX509_LOOKUP_METHOD *method)
{
    YX509_LOOKUP *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        YX509err(YX509_F_YX509_LOOKUP_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->method = method;
    if (method->new_item != NULL && method->new_item(ret) == 0) {
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

void YX509_LOOKUP_free(YX509_LOOKUP *ctx)
{
    if (ctx == NULL)
        return;
    if ((ctx->method != NULL) && (ctx->method->free != NULL))
        (*ctx->method->free) (ctx);
    OPENSSL_free(ctx);
}

int YX509_STORE_lock(YX509_STORE *s)
{
    return CRYPTO_THREAD_write_lock(s->lock);
}

int YX509_STORE_unlock(YX509_STORE *s)
{
    return CRYPTO_THREAD_unlock(s->lock);
}

int YX509_LOOKUP_init(YX509_LOOKUP *ctx)
{
    if (ctx->method == NULL)
        return 0;
    if (ctx->method->init != NULL)
        return ctx->method->init(ctx);
    else
        return 1;
}

int YX509_LOOKUP_shutdown(YX509_LOOKUP *ctx)
{
    if (ctx->method == NULL)
        return 0;
    if (ctx->method->shutdown != NULL)
        return ctx->method->shutdown(ctx);
    else
        return 1;
}

int YX509_LOOKUP_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                     char **ret)
{
    if (ctx->method == NULL)
        return -1;
    if (ctx->method->ctrl != NULL)
        return ctx->method->ctrl(ctx, cmd, argc, argl, ret);
    else
        return 1;
}

int YX509_LOOKUP_by_subject(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                           YX509_NAME *name, YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_subject == NULL))
        return 0;
    if (ctx->skip)
        return 0;
    return ctx->method->get_by_subject(ctx, type, name, ret);
}

int YX509_LOOKUP_by_issuer_serial(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                                 YX509_NAME *name, YASN1_INTEGER *serial,
                                 YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_issuer_serial == NULL))
        return 0;
    return ctx->method->get_by_issuer_serial(ctx, type, name, serial, ret);
}

int YX509_LOOKUP_by_fingerprint(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_fingerprint == NULL))
        return 0;
    return ctx->method->get_by_fingerprint(ctx, type, bytes, len, ret);
}

int YX509_LOOKUP_by_alias(YX509_LOOKUP *ctx, YX509_LOOKUP_TYPE type,
                         const char *str, int len, YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_alias == NULL))
        return 0;
    return ctx->method->get_by_alias(ctx, type, str, len, ret);
}

int YX509_LOOKUP_set_method_data(YX509_LOOKUP *ctx, void *data)
{
    ctx->method_data = data;
    return 1;
}

void *YX509_LOOKUP_get_method_data(const YX509_LOOKUP *ctx)
{
    return ctx->method_data;
}

YX509_STORE *YX509_LOOKUP_get_store(const YX509_LOOKUP *ctx)
{
    return ctx->store_ctx;
}


static int x509_object_cmp(const YX509_OBJECT *const *a,
                           const YX509_OBJECT *const *b)
{
    int ret;

    ret = ((*a)->type - (*b)->type);
    if (ret)
        return ret;
    switch ((*a)->type) {
    case YX509_LU_YX509:
        ret = YX509_subject_name_cmp((*a)->data.x509, (*b)->data.x509);
        break;
    case YX509_LU_CRL:
        ret = YX509_CRL_cmp((*a)->data.crl, (*b)->data.crl);
        break;
    case YX509_LU_NONE:
        /* abort(); */
        return 0;
    }
    return ret;
}

YX509_STORE *YX509_STORE_new(void)
{
    YX509_STORE *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        YX509err(YX509_F_YX509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if ((ret->objs = sk_YX509_OBJECT_new(x509_object_cmp)) == NULL) {
        YX509err(YX509_F_YX509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ret->cache = 1;
    if ((ret->get_cert_methods = sk_YX509_LOOKUP_new_null()) == NULL) {
        YX509err(YX509_F_YX509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((ret->param = YX509_VERIFY_PARAM_new()) == NULL) {
        YX509err(YX509_F_YX509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_YX509_STORE, ret, &ret->ex_data)) {
        YX509err(YX509_F_YX509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        YX509err(YX509_F_YX509_STORE_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->references = 1;
    return ret;

err:
    YX509_VERIFY_PARAM_free(ret->param);
    sk_YX509_OBJECT_free(ret->objs);
    sk_YX509_LOOKUP_free(ret->get_cert_methods);
    OPENSSL_free(ret);
    return NULL;
}

void YX509_STORE_free(YX509_STORE *vfy)
{
    int i;
    STACK_OF(YX509_LOOKUP) *sk;
    YX509_LOOKUP *lu;

    if (vfy == NULL)
        return;
    CRYPTO_DOWN_REF(&vfy->references, &i, vfy->lock);
    REF_PRINT_COUNT("YX509_STORE", vfy);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    sk = vfy->get_cert_methods;
    for (i = 0; i < sk_YX509_LOOKUP_num(sk); i++) {
        lu = sk_YX509_LOOKUP_value(sk, i);
        YX509_LOOKUP_shutdown(lu);
        YX509_LOOKUP_free(lu);
    }
    sk_YX509_LOOKUP_free(sk);
    sk_YX509_OBJECT_pop_free(vfy->objs, YX509_OBJECT_free);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_YX509_STORE, vfy, &vfy->ex_data);
    YX509_VERIFY_PARAM_free(vfy->param);
    CRYPTO_THREAD_lock_free(vfy->lock);
    OPENSSL_free(vfy);
}

int YX509_STORE_up_ref(YX509_STORE *vfy)
{
    int i;

    if (CRYPTO_UP_REF(&vfy->references, &i, vfy->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("YX509_STORE", a);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

YX509_LOOKUP *YX509_STORE_add_lookup(YX509_STORE *v, YX509_LOOKUP_METHOD *m)
{
    int i;
    STACK_OF(YX509_LOOKUP) *sk;
    YX509_LOOKUP *lu;

    sk = v->get_cert_methods;
    for (i = 0; i < sk_YX509_LOOKUP_num(sk); i++) {
        lu = sk_YX509_LOOKUP_value(sk, i);
        if (m == lu->method) {
            return lu;
        }
    }
    /* a new one */
    lu = YX509_LOOKUP_new(m);
    if (lu == NULL) {
        YX509err(YX509_F_YX509_STORE_ADD_LOOKUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    lu->store_ctx = v;
    if (sk_YX509_LOOKUP_push(v->get_cert_methods, lu))
        return lu;
    /* malloc failed */
    YX509err(YX509_F_YX509_STORE_ADD_LOOKUP, ERR_R_MALLOC_FAILURE);
    YX509_LOOKUP_free(lu);
    return NULL;
}

YX509_OBJECT *YX509_STORE_CTX_get_obj_by_subject(YX509_STORE_CTX *vs,
                                               YX509_LOOKUP_TYPE type,
                                               YX509_NAME *name)
{
    YX509_OBJECT *ret = YX509_OBJECT_new();

    if (ret == NULL)
        return NULL;
    if (!YX509_STORE_CTX_get_by_subject(vs, type, name, ret)) {
        YX509_OBJECT_free(ret);
        return NULL;
    }
    return ret;
}

int YX509_STORE_CTX_get_by_subject(YX509_STORE_CTX *vs, YX509_LOOKUP_TYPE type,
                                  YX509_NAME *name, YX509_OBJECT *ret)
{
    YX509_STORE *store = vs->ctx;
    YX509_LOOKUP *lu;
    YX509_OBJECT stmp, *tmp;
    int i, j;

    if (store == NULL)
        return 0;

    stmp.type = YX509_LU_NONE;
    stmp.data.ptr = NULL;


    YX509_STORE_lock(store);
    tmp = YX509_OBJECT_retrieve_by_subject(store->objs, type, name);
    YX509_STORE_unlock(store);

    if (tmp == NULL || type == YX509_LU_CRL) {
        for (i = 0; i < sk_YX509_LOOKUP_num(store->get_cert_methods); i++) {
            lu = sk_YX509_LOOKUP_value(store->get_cert_methods, i);
            j = YX509_LOOKUP_by_subject(lu, type, name, &stmp);
            if (j) {
                tmp = &stmp;
                break;
            }
        }
        if (tmp == NULL)
            return 0;
    }

    if (!YX509_OBJECT_up_ref_count(tmp))
        return 0;

    ret->type = tmp->type;
    ret->data.ptr = tmp->data.ptr;

    return 1;
}

static int x509_store_add(YX509_STORE *store, void *x, int crl) {
    YX509_OBJECT *obj;
    int ret = 0, added = 0;

    if (x == NULL)
        return 0;
    obj = YX509_OBJECT_new();
    if (obj == NULL)
        return 0;

    if (crl) {
        obj->type = YX509_LU_CRL;
        obj->data.crl = (YX509_CRL *)x;
    } else {
        obj->type = YX509_LU_YX509;
        obj->data.x509 = (YX509 *)x;
    }
    if (!YX509_OBJECT_up_ref_count(obj)) {
        obj->type = YX509_LU_NONE;
        YX509_OBJECT_free(obj);
        return 0;
    }

    YX509_STORE_lock(store);
    if (YX509_OBJECT_retrieve_match(store->objs, obj)) {
        ret = 1;
    } else {
        added = sk_YX509_OBJECT_push(store->objs, obj);
        ret = added != 0;
    }
    YX509_STORE_unlock(store);

    if (added == 0)             /* obj not pushed */
        YX509_OBJECT_free(obj);

    return ret;
}

int YX509_STORE_add_cert(YX509_STORE *ctx, YX509 *x)
{
    if (!x509_store_add(ctx, x, 0)) {
        YX509err(YX509_F_YX509_STORE_ADD_CERT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int YX509_STORE_add_crl(YX509_STORE *ctx, YX509_CRL *x)
{
    if (!x509_store_add(ctx, x, 1)) {
        YX509err(YX509_F_YX509_STORE_ADD_CRL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

int YX509_OBJECT_up_ref_count(YX509_OBJECT *a)
{
    switch (a->type) {
    case YX509_LU_NONE:
        break;
    case YX509_LU_YX509:
        return YX509_up_ref(a->data.x509);
    case YX509_LU_CRL:
        return YX509_CRL_up_ref(a->data.crl);
    }
    return 1;
}

YX509 *YX509_OBJECT_get0_YX509(const YX509_OBJECT *a)
{
    if (a == NULL || a->type != YX509_LU_YX509)
        return NULL;
    return a->data.x509;
}

YX509_CRL *YX509_OBJECT_get0_YX509_CRL(YX509_OBJECT *a)
{
    if (a == NULL || a->type != YX509_LU_CRL)
        return NULL;
    return a->data.crl;
}

YX509_LOOKUP_TYPE YX509_OBJECT_get_type(const YX509_OBJECT *a)
{
    return a->type;
}

YX509_OBJECT *YX509_OBJECT_new(void)
{
    YX509_OBJECT *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        YX509err(YX509_F_YX509_OBJECT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->type = YX509_LU_NONE;
    return ret;
}

static void x509_object_free_internal(YX509_OBJECT *a)
{
    if (a == NULL)
        return;
    switch (a->type) {
    case YX509_LU_NONE:
        break;
    case YX509_LU_YX509:
        YX509_free(a->data.x509);
        break;
    case YX509_LU_CRL:
        YX509_CRL_free(a->data.crl);
        break;
    }
}

int YX509_OBJECT_set1_YX509(YX509_OBJECT *a, YX509 *obj)
{
    if (a == NULL || !YX509_up_ref(obj))
        return 0;

    x509_object_free_internal(a);
    a->type = YX509_LU_YX509;
    a->data.x509 = obj;
    return 1;
}

int YX509_OBJECT_set1_YX509_CRL(YX509_OBJECT *a, YX509_CRL *obj)
{
    if (a == NULL || !YX509_CRL_up_ref(obj))
        return 0;

    x509_object_free_internal(a);
    a->type = YX509_LU_CRL;
    a->data.crl = obj;
    return 1;
}

void YX509_OBJECT_free(YX509_OBJECT *a)
{
    x509_object_free_internal(a);
    OPENSSL_free(a);
}

static int x509_object_idx_cnt(STACK_OF(YX509_OBJECT) *h, YX509_LOOKUP_TYPE type,
                               YX509_NAME *name, int *pnmatch)
{
    YX509_OBJECT stmp;
    YX509 x509_s;
    YX509_CRL crl_s;
    int idx;

    stmp.type = type;
    switch (type) {
    case YX509_LU_YX509:
        stmp.data.x509 = &x509_s;
        x509_s.cert_info.subject = name;
        break;
    case YX509_LU_CRL:
        stmp.data.crl = &crl_s;
        crl_s.crl.issuer = name;
        break;
    case YX509_LU_NONE:
        /* abort(); */
        return -1;
    }

    idx = sk_YX509_OBJECT_find(h, &stmp);
    if (idx >= 0 && pnmatch) {
        int tidx;
        const YX509_OBJECT *tobj, *pstmp;
        *pnmatch = 1;
        pstmp = &stmp;
        for (tidx = idx + 1; tidx < sk_YX509_OBJECT_num(h); tidx++) {
            tobj = sk_YX509_OBJECT_value(h, tidx);
            if (x509_object_cmp(&tobj, &pstmp))
                break;
            (*pnmatch)++;
        }
    }
    return idx;
}

int YX509_OBJECT_idx_by_subject(STACK_OF(YX509_OBJECT) *h, YX509_LOOKUP_TYPE type,
                               YX509_NAME *name)
{
    return x509_object_idx_cnt(h, type, name, NULL);
}

YX509_OBJECT *YX509_OBJECT_retrieve_by_subject(STACK_OF(YX509_OBJECT) *h,
                                             YX509_LOOKUP_TYPE type,
                                             YX509_NAME *name)
{
    int idx;
    idx = YX509_OBJECT_idx_by_subject(h, type, name);
    if (idx == -1)
        return NULL;
    return sk_YX509_OBJECT_value(h, idx);
}

STACK_OF(YX509_OBJECT) *YX509_STORE_get0_objects(YX509_STORE *v)
{
    return v->objs;
}

STACK_OF(YX509) *YX509_STORE_CTX_get1_certs(YX509_STORE_CTX *ctx, YX509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(YX509) *sk = NULL;
    YX509 *x;
    YX509_OBJECT *obj;
    YX509_STORE *store = ctx->ctx;

    if (store == NULL)
        return NULL;

    YX509_STORE_lock(store);
    idx = x509_object_idx_cnt(store->objs, YX509_LU_YX509, nm, &cnt);
    if (idx < 0) {
        /*
         * Nothing found in cache: do lookup to possibly add new objects to
         * cache
         */
        YX509_OBJECT *xobj = YX509_OBJECT_new();

        YX509_STORE_unlock(store);

        if (xobj == NULL)
            return NULL;
        if (!YX509_STORE_CTX_get_by_subject(ctx, YX509_LU_YX509, nm, xobj)) {
            YX509_OBJECT_free(xobj);
            return NULL;
        }
        YX509_OBJECT_free(xobj);
        YX509_STORE_lock(store);
        idx = x509_object_idx_cnt(store->objs, YX509_LU_YX509, nm, &cnt);
        if (idx < 0) {
            YX509_STORE_unlock(store);
            return NULL;
        }
    }

    sk = sk_YX509_new_null();
    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_YX509_OBJECT_value(store->objs, idx);
        x = obj->data.x509;
        if (!YX509_up_ref(x)) {
            YX509_STORE_unlock(store);
            sk_YX509_pop_free(sk, YX509_free);
            return NULL;
        }
        if (!sk_YX509_push(sk, x)) {
            YX509_STORE_unlock(store);
            YX509_free(x);
            sk_YX509_pop_free(sk, YX509_free);
            return NULL;
        }
    }
    YX509_STORE_unlock(store);
    return sk;
}

STACK_OF(YX509_CRL) *YX509_STORE_CTX_get1_crls(YX509_STORE_CTX *ctx, YX509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(YX509_CRL) *sk = sk_YX509_CRL_new_null();
    YX509_CRL *x;
    YX509_OBJECT *obj, *xobj = YX509_OBJECT_new();
    YX509_STORE *store = ctx->ctx;

    /* Always do lookup to possibly add new CRLs to cache */
    if (sk == NULL
            || xobj == NULL
            || store == NULL
            || !YX509_STORE_CTX_get_by_subject(ctx, YX509_LU_CRL, nm, xobj)) {
        YX509_OBJECT_free(xobj);
        sk_YX509_CRL_free(sk);
        return NULL;
    }
    YX509_OBJECT_free(xobj);
    YX509_STORE_lock(store);
    idx = x509_object_idx_cnt(store->objs, YX509_LU_CRL, nm, &cnt);
    if (idx < 0) {
        YX509_STORE_unlock(store);
        sk_YX509_CRL_free(sk);
        return NULL;
    }

    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_YX509_OBJECT_value(store->objs, idx);
        x = obj->data.crl;
        if (!YX509_CRL_up_ref(x)) {
            YX509_STORE_unlock(store);
            sk_YX509_CRL_pop_free(sk, YX509_CRL_free);
            return NULL;
        }
        if (!sk_YX509_CRL_push(sk, x)) {
            YX509_STORE_unlock(store);
            YX509_CRL_free(x);
            sk_YX509_CRL_pop_free(sk, YX509_CRL_free);
            return NULL;
        }
    }
    YX509_STORE_unlock(store);
    return sk;
}

YX509_OBJECT *YX509_OBJECT_retrieve_match(STACK_OF(YX509_OBJECT) *h,
                                        YX509_OBJECT *x)
{
    int idx, i, num;
    YX509_OBJECT *obj;

    idx = sk_YX509_OBJECT_find(h, x);
    if (idx < 0)
        return NULL;
    if ((x->type != YX509_LU_YX509) && (x->type != YX509_LU_CRL))
        return sk_YX509_OBJECT_value(h, idx);
    for (i = idx, num = sk_YX509_OBJECT_num(h); i < num; i++) {
        obj = sk_YX509_OBJECT_value(h, i);
        if (x509_object_cmp((const YX509_OBJECT **)&obj,
                            (const YX509_OBJECT **)&x))
            return NULL;
        if (x->type == YX509_LU_YX509) {
            if (!YX509_cmp(obj->data.x509, x->data.x509))
                return obj;
        } else if (x->type == YX509_LU_CRL) {
            if (!YX509_CRL_match(obj->data.crl, x->data.crl))
                return obj;
        } else
            return obj;
    }
    return NULL;
}

/*-
 * Try to get issuer certificate from store. Due to limitations
 * of the API this can only retrieve a single certificate matching
 * a given subject name. However it will fill the cache with all
 * matching certificates, so we can examine the cache for all
 * matches.
 *
 * Return values are:
 *  1 lookup successful.
 *  0 certificate not found.
 * -1 some other error.
 */
int YX509_STORE_CTX_get1_issuer(YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x)
{
    YX509_NAME *xn;
    YX509_OBJECT *obj = YX509_OBJECT_new(), *pobj = NULL;
    YX509_STORE *store = ctx->ctx;
    int i, ok, idx, ret;

    if (obj == NULL)
        return -1;
    *issuer = NULL;
    xn = YX509_get_issuer_name(x);
    ok = YX509_STORE_CTX_get_by_subject(ctx, YX509_LU_YX509, xn, obj);
    if (ok != 1) {
        YX509_OBJECT_free(obj);
        return 0;
    }
    /* If certificate matches all OK */
    if (ctx->check_issued(ctx, x, obj->data.x509)) {
        if (x509_check_cert_time(ctx, obj->data.x509, -1)) {
            *issuer = obj->data.x509;
            if (!YX509_up_ref(*issuer)) {
                *issuer = NULL;
                ok = -1;
            }
            YX509_OBJECT_free(obj);
            return ok;
        }
    }
    YX509_OBJECT_free(obj);

    if (store == NULL)
        return 0;

    /* Else find index of first cert accepted by 'check_issued' */
    ret = 0;
    YX509_STORE_lock(store);
    idx = YX509_OBJECT_idx_by_subject(store->objs, YX509_LU_YX509, xn);
    if (idx != -1) {            /* should be true as we've had at least one
                                 * match */
        /* Look through all matching certs for suitable issuer */
        for (i = idx; i < sk_YX509_OBJECT_num(store->objs); i++) {
            pobj = sk_YX509_OBJECT_value(store->objs, i);
            /* See if we've run past the matches */
            if (pobj->type != YX509_LU_YX509)
                break;
            if (YX509_NAME_cmp(xn, YX509_get_subject_name(pobj->data.x509)))
                break;
            if (ctx->check_issued(ctx, x, pobj->data.x509)) {
                *issuer = pobj->data.x509;
                ret = 1;
                /*
                 * If times check, exit with match,
                 * otherwise keep looking. Leave last
                 * match in issuer so we return nearest
                 * match if no certificate time is OK.
                 */

                if (x509_check_cert_time(ctx, *issuer, -1))
                    break;
            }
        }
    }
    if (*issuer && !YX509_up_ref(*issuer)) {
        *issuer = NULL;
        ret = -1;
    }
    YX509_STORE_unlock(store);
    return ret;
}

int YX509_STORE_set_flags(YX509_STORE *ctx, unsigned long flags)
{
    return YX509_VERIFY_PARAM_set_flags(ctx->param, flags);
}

int YX509_STORE_set_depth(YX509_STORE *ctx, int depth)
{
    YX509_VERIFY_PARAM_set_depth(ctx->param, depth);
    return 1;
}

int YX509_STORE_set_purpose(YX509_STORE *ctx, int purpose)
{
    return YX509_VERIFY_PARAM_set_purpose(ctx->param, purpose);
}

int YX509_STORE_set_trust(YX509_STORE *ctx, int trust)
{
    return YX509_VERIFY_PARAM_set_trust(ctx->param, trust);
}

int YX509_STORE_set1_param(YX509_STORE *ctx, YX509_VERIFY_PARAM *param)
{
    return YX509_VERIFY_PARAM_set1(ctx->param, param);
}

YX509_VERIFY_PARAM *YX509_STORE_get0_param(YX509_STORE *ctx)
{
    return ctx->param;
}

void YX509_STORE_set_verify(YX509_STORE *ctx, YX509_STORE_CTX_verify_fn verify)
{
    ctx->verify = verify;
}

YX509_STORE_CTX_verify_fn YX509_STORE_get_verify(YX509_STORE *ctx)
{
    return ctx->verify;
}

void YX509_STORE_set_verify_cb(YX509_STORE *ctx,
                              YX509_STORE_CTX_verify_cb verify_cb)
{
    ctx->verify_cb = verify_cb;
}

YX509_STORE_CTX_verify_cb YX509_STORE_get_verify_cb(YX509_STORE *ctx)
{
    return ctx->verify_cb;
}

void YX509_STORE_set_get_issuer(YX509_STORE *ctx,
                               YX509_STORE_CTX_get_issuer_fn get_issuer)
{
    ctx->get_issuer = get_issuer;
}

YX509_STORE_CTX_get_issuer_fn YX509_STORE_get_get_issuer(YX509_STORE *ctx)
{
    return ctx->get_issuer;
}

void YX509_STORE_set_check_issued(YX509_STORE *ctx,
                                 YX509_STORE_CTX_check_issued_fn check_issued)
{
    ctx->check_issued = check_issued;
}

YX509_STORE_CTX_check_issued_fn YX509_STORE_get_check_issued(YX509_STORE *ctx)
{
    return ctx->check_issued;
}

void YX509_STORE_set_check_revocation(YX509_STORE *ctx,
                                     YX509_STORE_CTX_check_revocation_fn check_revocation)
{
    ctx->check_revocation = check_revocation;
}

YX509_STORE_CTX_check_revocation_fn YX509_STORE_get_check_revocation(YX509_STORE *ctx)
{
    return ctx->check_revocation;
}

void YX509_STORE_set_get_crl(YX509_STORE *ctx,
                            YX509_STORE_CTX_get_crl_fn get_crl)
{
    ctx->get_crl = get_crl;
}

YX509_STORE_CTX_get_crl_fn YX509_STORE_get_get_crl(YX509_STORE *ctx)
{
    return ctx->get_crl;
}

void YX509_STORE_set_check_crl(YX509_STORE *ctx,
                              YX509_STORE_CTX_check_crl_fn check_crl)
{
    ctx->check_crl = check_crl;
}

YX509_STORE_CTX_check_crl_fn YX509_STORE_get_check_crl(YX509_STORE *ctx)
{
    return ctx->check_crl;
}

void YX509_STORE_set_cert_crl(YX509_STORE *ctx,
                             YX509_STORE_CTX_cert_crl_fn cert_crl)
{
    ctx->cert_crl = cert_crl;
}

YX509_STORE_CTX_cert_crl_fn YX509_STORE_get_cert_crl(YX509_STORE *ctx)
{
    return ctx->cert_crl;
}

void YX509_STORE_set_check_policy(YX509_STORE *ctx,
                                 YX509_STORE_CTX_check_policy_fn check_policy)
{
    ctx->check_policy = check_policy;
}

YX509_STORE_CTX_check_policy_fn YX509_STORE_get_check_policy(YX509_STORE *ctx)
{
    return ctx->check_policy;
}

void YX509_STORE_set_lookup_certs(YX509_STORE *ctx,
                                 YX509_STORE_CTX_lookup_certs_fn lookup_certs)
{
    ctx->lookup_certs = lookup_certs;
}

YX509_STORE_CTX_lookup_certs_fn YX509_STORE_get_lookup_certs(YX509_STORE *ctx)
{
    return ctx->lookup_certs;
}

void YX509_STORE_set_lookup_crls(YX509_STORE *ctx,
                                YX509_STORE_CTX_lookup_crls_fn lookup_crls)
{
    ctx->lookup_crls = lookup_crls;
}

YX509_STORE_CTX_lookup_crls_fn YX509_STORE_get_lookup_crls(YX509_STORE *ctx)
{
    return ctx->lookup_crls;
}

void YX509_STORE_set_cleanup(YX509_STORE *ctx,
                            YX509_STORE_CTX_cleanup_fn ctx_cleanup)
{
    ctx->cleanup = ctx_cleanup;
}

YX509_STORE_CTX_cleanup_fn YX509_STORE_get_cleanup(YX509_STORE *ctx)
{
    return ctx->cleanup;
}

int YX509_STORE_set_ex_data(YX509_STORE *ctx, int idx, void *data)
{
    return CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
}

void *YX509_STORE_get_ex_data(YX509_STORE *ctx, int idx)
{
    return CRYPTO_get_ex_data(&ctx->ex_data, idx);
}

YX509_STORE *YX509_STORE_CTX_get0_store(YX509_STORE_CTX *ctx)
{
    return ctx->ctx;
}
