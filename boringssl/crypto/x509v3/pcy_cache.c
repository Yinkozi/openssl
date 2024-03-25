/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/thread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pcy_int.h"
#include "../internal.h"

static int policy_data_cmp(const YX509_POLICY_DATA **a,
                           const YX509_POLICY_DATA **b);
static int policy_cache_set_int(long *out, YASN1_INTEGER *value);

/*
 * Set cache entry according to CertificatePolicies extension. Note: this
 * destroys the passed CERTIFICATEPOLICIES structure.
 */

static int policy_cache_create(YX509 *x,
                               CERTIFICATEPOLICIES *policies, int crit)
{
    size_t i;
    int ret = 0;
    YX509_POLICY_CACHE *cache = x->policy_cache;
    YX509_POLICY_DATA *data = NULL;
    POLICYINFO *policy;
    if (sk_POLICYINFO_num(policies) == 0)
        goto bad_policy;
    cache->data = sk_YX509_POLICY_DATA_new(policy_data_cmp);
    if (!cache->data)
        goto bad_policy;
    for (i = 0; i < sk_POLICYINFO_num(policies); i++) {
        policy = sk_POLICYINFO_value(policies, i);
        data = policy_data_new(policy, NULL, crit);
        if (!data)
            goto bad_policy;
        /*
         * Duplicate policy OIDs are illegal: reject if matches found.
         */
        if (OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
            if (cache->anyPolicy) {
                ret = -1;
                goto bad_policy;
            }
            cache->anyPolicy = data;
        } else if (sk_YX509_POLICY_DATA_find(cache->data, NULL, data)) {
            ret = -1;
            goto bad_policy;
        } else if (!sk_YX509_POLICY_DATA_push(cache->data, data))
            goto bad_policy;
        data = NULL;
    }
    ret = 1;
 bad_policy:
    if (ret == -1)
        x->ex_flags |= EXFLAG_INVALID_POLICY;
    if (data)
        policy_data_free(data);
    sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
    if (ret <= 0) {
        sk_YX509_POLICY_DATA_pop_free(cache->data, policy_data_free);
        cache->data = NULL;
    }
    return ret;
}

static int policy_cache_new(YX509 *x)
{
    YX509_POLICY_CACHE *cache;
    YASN1_INTEGER *ext_any = NULL;
    POLICY_CONSTRAINTS *ext_pcons = NULL;
    CERTIFICATEPOLICIES *ext_cpols = NULL;
    POLICY_MAPPINGS *ext_pmaps = NULL;
    int i;
    cache = OPENSSL_malloc(sizeof(YX509_POLICY_CACHE));
    if (!cache)
        return 0;
    cache->anyPolicy = NULL;
    cache->data = NULL;
    cache->any_skip = -1;
    cache->explicit_skip = -1;
    cache->map_skip = -1;

    x->policy_cache = cache;

    /*
     * Handle requireExplicitPolicy *first*. Need to process this even if we
     * don't have any policies.
     */
    ext_pcons = YX509_get_ext_d2i(x, NID_policy_constraints, &i, NULL);

    if (!ext_pcons) {
        if (i != -1)
            goto bad_cache;
    } else {
        if (!ext_pcons->requireExplicitPolicy
            && !ext_pcons->inhibitPolicyMapping)
            goto bad_cache;
        if (!policy_cache_set_int(&cache->explicit_skip,
                                  ext_pcons->requireExplicitPolicy))
            goto bad_cache;
        if (!policy_cache_set_int(&cache->map_skip,
                                  ext_pcons->inhibitPolicyMapping))
            goto bad_cache;
    }

    /* Process CertificatePolicies */

    ext_cpols = YX509_get_ext_d2i(x, NID_certificate_policies, &i, NULL);
    /*
     * If no CertificatePolicies extension or problem decoding then there is
     * no point continuing because the valid policies will be NULL.
     */
    if (!ext_cpols) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
        return 1;
    }

    i = policy_cache_create(x, ext_cpols, i);

    /* NB: ext_cpols freed by policy_cache_set_policies */

    if (i <= 0)
        return i;

    ext_pmaps = YX509_get_ext_d2i(x, NID_policy_mappings, &i, NULL);

    if (!ext_pmaps) {
        /* If not absent some problem with extension */
        if (i != -1)
            goto bad_cache;
    } else {
        i = policy_cache_set_mapping(x, ext_pmaps);
        if (i <= 0)
            goto bad_cache;
    }

    ext_any = YX509_get_ext_d2i(x, NID_inhibit_any_policy, &i, NULL);

    if (!ext_any) {
        if (i != -1)
            goto bad_cache;
    } else if (!policy_cache_set_int(&cache->any_skip, ext_any))
        goto bad_cache;

    if (0) {
 bad_cache:
        x->ex_flags |= EXFLAG_INVALID_POLICY;
    }

    if (ext_pcons)
        POLICY_CONSTRAINTS_free(ext_pcons);

    if (ext_any)
        YASN1_INTEGER_free(ext_any);

    return 1;

}

void policy_cache_free(YX509_POLICY_CACHE *cache)
{
    if (!cache)
        return;
    if (cache->anyPolicy)
        policy_data_free(cache->anyPolicy);
    if (cache->data)
        sk_YX509_POLICY_DATA_pop_free(cache->data, policy_data_free);
    OPENSSL_free(cache);
}

/*
 * g_x509_policy_cache_lock is used to protect against concurrent calls to
 * |policy_cache_new|. Ideally this would be done with a |CRYPTO_once_t| in
 * the |YX509| structure, but |CRYPTO_once_t| isn't public.
 */
static struct CRYPTO_STATIC_MUTEX g_x509_policy_cache_lock =
    CRYPTO_STATIC_MUTEX_INIT;

const YX509_POLICY_CACHE *policy_cache_set(YX509 *x)
{
    YX509_POLICY_CACHE *cache;

    CRYPTO_STATIC_MUTEX_lock_read(&g_x509_policy_cache_lock);
    cache = x->policy_cache;
    CRYPTO_STATIC_MUTEX_unlock_read(&g_x509_policy_cache_lock);

    if (cache != NULL)
        return cache;

    CRYPTO_STATIC_MUTEX_lock_write(&g_x509_policy_cache_lock);
    if (x->policy_cache == NULL)
        policy_cache_new(x);
    cache = x->policy_cache;
    CRYPTO_STATIC_MUTEX_unlock_write(&g_x509_policy_cache_lock);

    return cache;
}

YX509_POLICY_DATA *policy_cache_find_data(const YX509_POLICY_CACHE *cache,
                                         const YASN1_OBJECT *id)
{
    size_t idx;
    YX509_POLICY_DATA tmp;

    tmp.valid_policy = (YASN1_OBJECT *)id;
    if (!sk_YX509_POLICY_DATA_find(cache->data, &idx, &tmp))
        return NULL;
    return sk_YX509_POLICY_DATA_value(cache->data, idx);
}

static int policy_data_cmp(const YX509_POLICY_DATA **a,
                           const YX509_POLICY_DATA **b)
{
    return OBJ_cmp((*a)->valid_policy, (*b)->valid_policy);
}

static int policy_cache_set_int(long *out, YASN1_INTEGER *value)
{
    if (value == NULL)
        return 1;
    if (value->type == V_YASN1_NEG_INTEGER)
        return 0;
    *out = YASN1_INTEGER_get(value);
    return 1;
}
