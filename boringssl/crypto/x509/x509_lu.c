/* crypto/x509/x509_lu.c */
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

#include <string.h>

#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/mem.h>
#include <openssl/thread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../internal.h"

YX509_LOOKUP *YX509_LOOKUP_new(YX509_LOOKUP_METHOD *method)
{
    YX509_LOOKUP *ret;

    ret = (YX509_LOOKUP *)OPENSSL_malloc(sizeof(YX509_LOOKUP));
    if (ret == NULL)
        return NULL;

    ret->init = 0;
    ret->skip = 0;
    ret->method = method;
    ret->method_data = NULL;
    ret->store_ctx = NULL;
    if ((method->new_item != NULL) && !method->new_item(ret)) {
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

int YX509_LOOKUP_by_subject(YX509_LOOKUP *ctx, int type, YX509_NAME *name,
                           YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_subject == NULL))
        return 0;
    if (ctx->skip)
        return 0;
    return ctx->method->get_by_subject(ctx, type, name, ret) > 0;
}

int YX509_LOOKUP_by_issuer_serial(YX509_LOOKUP *ctx, int type, YX509_NAME *name,
                                 YASN1_INTEGER *serial, YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_issuer_serial == NULL))
        return 0;
    return ctx->method->get_by_issuer_serial(ctx, type, name, serial, ret) > 0;
}

int YX509_LOOKUP_by_fingerprint(YX509_LOOKUP *ctx, int type,
                               unsigned char *bytes, int len,
                               YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_fingerprint == NULL))
        return 0;
    return ctx->method->get_by_fingerprint(ctx, type, bytes, len, ret) > 0;
}

int YX509_LOOKUP_by_alias(YX509_LOOKUP *ctx, int type, char *str, int len,
                         YX509_OBJECT *ret)
{
    if ((ctx->method == NULL) || (ctx->method->get_by_alias == NULL))
        return 0;
    return ctx->method->get_by_alias(ctx, type, str, len, ret) > 0;
}

static int x509_object_cmp(const YX509_OBJECT **a, const YX509_OBJECT **b)
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
    default:
        /* abort(); */
        return 0;
    }
    return ret;
}

YX509_STORE *YX509_STORE_new(void)
{
    YX509_STORE *ret;

    if ((ret = (YX509_STORE *)OPENSSL_malloc(sizeof(YX509_STORE))) == NULL)
        return NULL;
    OPENSSL_memset(ret, 0, sizeof(*ret));
    CRYPTO_MUTEX_init(&ret->objs_lock);
    ret->objs = sk_YX509_OBJECT_new(x509_object_cmp);
    if (ret->objs == NULL)
        goto err;
    ret->cache = 1;
    ret->get_cert_methods = sk_YX509_LOOKUP_new_null();
    if (ret->get_cert_methods == NULL)
        goto err;
    ret->param = YX509_VERIFY_PARAM_new();
    if (ret->param == NULL)
        goto err;

    ret->references = 1;
    return ret;
 err:
    if (ret) {
        CRYPTO_MUTEX_cleanup(&ret->objs_lock);
        if (ret->param)
            YX509_VERIFY_PARAM_free(ret->param);
        if (ret->get_cert_methods)
            sk_YX509_LOOKUP_free(ret->get_cert_methods);
        if (ret->objs)
            sk_YX509_OBJECT_free(ret->objs);
        OPENSSL_free(ret);
    }
    return NULL;
}

int YX509_STORE_up_ref(YX509_STORE *store)
{
    CRYPTO_refcount_inc(&store->references);
    return 1;
}

static void cleanup(YX509_OBJECT *a)
{
    if (a == NULL) {
        return;
    }
    if (a->type == YX509_LU_YX509) {
        YX509_free(a->data.x509);
    } else if (a->type == YX509_LU_CRL) {
        YX509_CRL_free(a->data.crl);
    } else {
        /* abort(); */
    }

    OPENSSL_free(a);
}

void YX509_STORE_free(YX509_STORE *vfy)
{
    size_t j;
    STACK_OF(YX509_LOOKUP) *sk;
    YX509_LOOKUP *lu;

    if (vfy == NULL)
        return;

    if (!CRYPTO_refcount_dec_and_test_zero(&vfy->references)) {
        return;
    }

    CRYPTO_MUTEX_cleanup(&vfy->objs_lock);

    sk = vfy->get_cert_methods;
    for (j = 0; j < sk_YX509_LOOKUP_num(sk); j++) {
        lu = sk_YX509_LOOKUP_value(sk, j);
        YX509_LOOKUP_shutdown(lu);
        YX509_LOOKUP_free(lu);
    }
    sk_YX509_LOOKUP_free(sk);
    sk_YX509_OBJECT_pop_free(vfy->objs, cleanup);

    if (vfy->param)
        YX509_VERIFY_PARAM_free(vfy->param);
    OPENSSL_free(vfy);
}

YX509_LOOKUP *YX509_STORE_add_lookup(YX509_STORE *v, YX509_LOOKUP_METHOD *m)
{
    size_t i;
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
    if (lu == NULL)
        return NULL;
    else {
        lu->store_ctx = v;
        if (sk_YX509_LOOKUP_push(v->get_cert_methods, lu))
            return lu;
        else {
            YX509_LOOKUP_free(lu);
            return NULL;
        }
    }
}

int YX509_STORE_get_by_subject(YX509_STORE_CTX *vs, int type, YX509_NAME *name,
                              YX509_OBJECT *ret)
{
    YX509_STORE *ctx = vs->ctx;
    YX509_LOOKUP *lu;
    YX509_OBJECT stmp, *tmp;
    int i;

    CRYPTO_MUTEX_lock_write(&ctx->objs_lock);
    tmp = YX509_OBJECT_retrieve_by_subject(ctx->objs, type, name);
    CRYPTO_MUTEX_unlock_write(&ctx->objs_lock);

    if (tmp == NULL || type == YX509_LU_CRL) {
        for (i = 0; i < (int)sk_YX509_LOOKUP_num(ctx->get_cert_methods); i++) {
            lu = sk_YX509_LOOKUP_value(ctx->get_cert_methods, i);
            if (YX509_LOOKUP_by_subject(lu, type, name, &stmp)) {
                tmp = &stmp;
                break;
            }
        }
        if (tmp == NULL)
            return 0;
    }

    /*
     * if (ret->data.ptr != NULL) YX509_OBJECT_free_contents(ret);
     */

    ret->type = tmp->type;
    ret->data.ptr = tmp->data.ptr;

    YX509_OBJECT_up_ref_count(ret);

    return 1;
}

int YX509_STORE_add_cert(YX509_STORE *ctx, YX509 *x)
{
    YX509_OBJECT *obj;
    int ret = 1;

    if (x == NULL)
        return 0;
    obj = (YX509_OBJECT *)OPENSSL_malloc(sizeof(YX509_OBJECT));
    if (obj == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    obj->type = YX509_LU_YX509;
    obj->data.x509 = x;

    CRYPTO_MUTEX_lock_write(&ctx->objs_lock);

    YX509_OBJECT_up_ref_count(obj);

    if (YX509_OBJECT_retrieve_match(ctx->objs, obj)) {
        YX509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
        OPENSSL_PUT_ERROR(YX509, YX509_R_CERT_ALREADY_IN_HASH_TABLE);
        ret = 0;
    } else
        sk_YX509_OBJECT_push(ctx->objs, obj);

    CRYPTO_MUTEX_unlock_write(&ctx->objs_lock);

    return ret;
}

int YX509_STORE_add_crl(YX509_STORE *ctx, YX509_CRL *x)
{
    YX509_OBJECT *obj;
    int ret = 1;

    if (x == NULL)
        return 0;
    obj = (YX509_OBJECT *)OPENSSL_malloc(sizeof(YX509_OBJECT));
    if (obj == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    obj->type = YX509_LU_CRL;
    obj->data.crl = x;

    CRYPTO_MUTEX_lock_write(&ctx->objs_lock);

    YX509_OBJECT_up_ref_count(obj);

    if (YX509_OBJECT_retrieve_match(ctx->objs, obj)) {
        YX509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
        OPENSSL_PUT_ERROR(YX509, YX509_R_CERT_ALREADY_IN_HASH_TABLE);
        ret = 0;
    } else
        sk_YX509_OBJECT_push(ctx->objs, obj);

    CRYPTO_MUTEX_unlock_write(&ctx->objs_lock);

    return ret;
}

void YX509_STORE_set0_additional_untrusted(YX509_STORE *ctx,
                                          STACK_OF(YX509) *untrusted) {
  ctx->additional_untrusted = untrusted;
}

int YX509_OBJECT_up_ref_count(YX509_OBJECT *a)
{
    switch (a->type) {
    case YX509_LU_YX509:
        YX509_up_ref(a->data.x509);
        break;
    case YX509_LU_CRL:
        YX509_CRL_up_ref(a->data.crl);
        break;
    }
    return 1;
}

void YX509_OBJECT_free_contents(YX509_OBJECT *a)
{
    switch (a->type) {
    case YX509_LU_YX509:
        YX509_free(a->data.x509);
        break;
    case YX509_LU_CRL:
        YX509_CRL_free(a->data.crl);
        break;
    }
}

static int x509_object_idx_cnt(STACK_OF(YX509_OBJECT) *h, int type,
                               YX509_NAME *name, int *pnmatch)
{
    YX509_OBJECT stmp;
    YX509 x509_s;
    YX509_CINF cinf_s;
    YX509_CRL crl_s;
    YX509_CRL_INFO crl_info_s;

    stmp.type = type;
    switch (type) {
    case YX509_LU_YX509:
        stmp.data.x509 = &x509_s;
        x509_s.cert_info = &cinf_s;
        cinf_s.subject = name;
        break;
    case YX509_LU_CRL:
        stmp.data.crl = &crl_s;
        crl_s.crl = &crl_info_s;
        crl_info_s.issuer = name;
        break;
    default:
        /* abort(); */
        return -1;
    }

    size_t idx;
    if (!sk_YX509_OBJECT_find(h, &idx, &stmp))
        return -1;

    if (pnmatch != NULL) {
        int tidx;
        const YX509_OBJECT *tobj, *pstmp;
        *pnmatch = 1;
        pstmp = &stmp;
        for (tidx = idx + 1; tidx < (int)sk_YX509_OBJECT_num(h); tidx++) {
            tobj = sk_YX509_OBJECT_value(h, tidx);
            if (x509_object_cmp(&tobj, &pstmp))
                break;
            (*pnmatch)++;
        }
    }

    return idx;
}

int YX509_OBJECT_idx_by_subject(STACK_OF(YX509_OBJECT) *h, int type,
                               YX509_NAME *name)
{
    return x509_object_idx_cnt(h, type, name, NULL);
}

YX509_OBJECT *YX509_OBJECT_retrieve_by_subject(STACK_OF(YX509_OBJECT) *h,
                                             int type, YX509_NAME *name)
{
    int idx;
    idx = YX509_OBJECT_idx_by_subject(h, type, name);
    if (idx == -1)
        return NULL;
    return sk_YX509_OBJECT_value(h, idx);
}

STACK_OF (YX509) * YX509_STORE_get1_certs(YX509_STORE_CTX *ctx, YX509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(YX509) *sk;
    YX509 *x;
    YX509_OBJECT *obj;
    sk = sk_YX509_new_null();
    if (sk == NULL)
        return NULL;
    CRYPTO_MUTEX_lock_write(&ctx->ctx->objs_lock);
    idx = x509_object_idx_cnt(ctx->ctx->objs, YX509_LU_YX509, nm, &cnt);
    if (idx < 0) {
        /*
         * Nothing found in cache: do lookup to possibly add new objects to
         * cache
         */
        YX509_OBJECT xobj;
        CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
        if (!YX509_STORE_get_by_subject(ctx, YX509_LU_YX509, nm, &xobj)) {
            sk_YX509_free(sk);
            return NULL;
        }
        YX509_OBJECT_free_contents(&xobj);
        CRYPTO_MUTEX_lock_write(&ctx->ctx->objs_lock);
        idx = x509_object_idx_cnt(ctx->ctx->objs, YX509_LU_YX509, nm, &cnt);
        if (idx < 0) {
            CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
            sk_YX509_free(sk);
            return NULL;
        }
    }
    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_YX509_OBJECT_value(ctx->ctx->objs, idx);
        x = obj->data.x509;
        if (!sk_YX509_push(sk, x)) {
            CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
            sk_YX509_pop_free(sk, YX509_free);
            return NULL;
        }
        YX509_up_ref(x);
    }
    CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
    return sk;

}

STACK_OF (YX509_CRL) * YX509_STORE_get1_crls(YX509_STORE_CTX *ctx, YX509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(YX509_CRL) *sk;
    YX509_CRL *x;
    YX509_OBJECT *obj, xobj;
    sk = sk_YX509_CRL_new_null();
    if (sk == NULL)
        return NULL;

    /* Always do lookup to possibly add new CRLs to cache. */
    if (!YX509_STORE_get_by_subject(ctx, YX509_LU_CRL, nm, &xobj)) {
        sk_YX509_CRL_free(sk);
        return NULL;
    }
    YX509_OBJECT_free_contents(&xobj);
    CRYPTO_MUTEX_lock_write(&ctx->ctx->objs_lock);
    idx = x509_object_idx_cnt(ctx->ctx->objs, YX509_LU_CRL, nm, &cnt);
    if (idx < 0) {
        CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
        sk_YX509_CRL_free(sk);
        return NULL;
    }

    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_YX509_OBJECT_value(ctx->ctx->objs, idx);
        x = obj->data.crl;
        YX509_CRL_up_ref(x);
        if (!sk_YX509_CRL_push(sk, x)) {
            CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
            YX509_CRL_free(x);
            sk_YX509_CRL_pop_free(sk, YX509_CRL_free);
            return NULL;
        }
    }
    CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
    return sk;
}

YX509_OBJECT *YX509_OBJECT_retrieve_match(STACK_OF(YX509_OBJECT) *h,
                                        YX509_OBJECT *x)
{
    size_t idx, i;
    YX509_OBJECT *obj;

    if (!sk_YX509_OBJECT_find(h, &idx, x)) {
        return NULL;
    }
    if ((x->type != YX509_LU_YX509) && (x->type != YX509_LU_CRL))
        return sk_YX509_OBJECT_value(h, idx);
    for (i = idx; i < sk_YX509_OBJECT_num(h); i++) {
        obj = sk_YX509_OBJECT_value(h, i);
        if (x509_object_cmp
            ((const YX509_OBJECT **)&obj, (const YX509_OBJECT **)&x))
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

/*
 * Try to get issuer certificate from store. Due to limitations of the API
 * this can only retrieve a single certificate matching a given subject name.
 * However it will fill the cache with all matching certificates, so we can
 * examine the cache for all matches. Return values are: 1 lookup
 * successful.  0 certificate not found. -1 some other error.
 */
int YX509_STORE_CTX_get1_issuer(YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x)
{
    YX509_NAME *xn;
    YX509_OBJECT obj, *pobj;
    int idx, ret;
    size_t i;
    xn = YX509_get_issuer_name(x);
    if (!YX509_STORE_get_by_subject(ctx, YX509_LU_YX509, xn, &obj))
        return 0;
    /* If certificate matches all OK */
    if (ctx->check_issued(ctx, x, obj.data.x509)) {
        *issuer = obj.data.x509;
        return 1;
    }
    YX509_OBJECT_free_contents(&obj);

    /* Else find index of first cert accepted by 'check_issued' */
    ret = 0;
    CRYPTO_MUTEX_lock_write(&ctx->ctx->objs_lock);
    idx = YX509_OBJECT_idx_by_subject(ctx->ctx->objs, YX509_LU_YX509, xn);
    if (idx != -1) {            /* should be true as we've had at least one
                                 * match */
        /* Look through all matching certs for suitable issuer */
        for (i = idx; i < sk_YX509_OBJECT_num(ctx->ctx->objs); i++) {
            pobj = sk_YX509_OBJECT_value(ctx->ctx->objs, i);
            /* See if we've run past the matches */
            if (pobj->type != YX509_LU_YX509)
                break;
            if (YX509_NAME_cmp(xn, YX509_get_subject_name(pobj->data.x509)))
                break;
            if (ctx->check_issued(ctx, x, pobj->data.x509)) {
                *issuer = pobj->data.x509;
                YX509_OBJECT_up_ref_count(pobj);
                ret = 1;
                break;
            }
        }
    }
    CRYPTO_MUTEX_unlock_write(&ctx->ctx->objs_lock);
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

void YX509_STORE_set_verify_cb(YX509_STORE *ctx,
                              int (*verify_cb) (int, YX509_STORE_CTX *))
{
    ctx->verify_cb = verify_cb;
}

void YX509_STORE_set_lookup_crls_cb(YX509_STORE *ctx,
                                   STACK_OF (YX509_CRL) *
                                   (*cb) (YX509_STORE_CTX *ctx, YX509_NAME *nm))
{
    ctx->lookup_crls = cb;
}

YX509_STORE *YX509_STORE_CTX_get0_store(YX509_STORE_CTX *ctx)
{
    return ctx->ctx;
}
