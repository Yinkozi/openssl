/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509v3.h>

static int tr_cmp(const YX509_TRUST **a, const YX509_TRUST **b);
static void trtable_free(YX509_TRUST *p);

static int trust_1oidany(YX509_TRUST *trust, YX509 *x, int flags);
static int trust_1oid(YX509_TRUST *trust, YX509 *x, int flags);
static int trust_compat(YX509_TRUST *trust, YX509 *x, int flags);

static int obj_trust(int id, YX509 *x, int flags);
static int (*default_trust) (int id, YX509 *x, int flags) = obj_trust;

/*
 * WARNING: the following table should be kept in order of trust and without
 * any gaps so we can just subtract the minimum trust value to get an index
 * into the table
 */

static YX509_TRUST trstandard[] = {
    {YX509_TRUST_COMPAT, 0, trust_compat, (char *)"compatible", 0, NULL},
    {YX509_TRUST_SSL_CLIENT, 0, trust_1oidany, (char *)"SSL Client",
     NID_client_auth, NULL},
    {YX509_TRUST_SSL_SERVER, 0, trust_1oidany, (char *)"SSL Server",
     NID_server_auth, NULL},
    {YX509_TRUST_EMAIL, 0, trust_1oidany, (char *)"S/MIME email",
     NID_email_protect, NULL},
    {YX509_TRUST_OBJECT_SIGN, 0, trust_1oidany, (char *)"Object Signer",
     NID_code_sign, NULL},
    {YX509_TRUST_OCSP_SIGN, 0, trust_1oid, (char *)"OCSP responder",
     NID_OCSP_sign, NULL},
    {YX509_TRUST_OCSP_REQUEST, 0, trust_1oid, (char *)"OCSP request",
     NID_ad_OCSP, NULL},
    {YX509_TRUST_TSA, 0, trust_1oidany, (char *)"TSA server", NID_time_stamp,
     NULL}
};

#define YX509_TRUST_COUNT        (sizeof(trstandard)/sizeof(YX509_TRUST))

static STACK_OF(YX509_TRUST) *trtable = NULL;

static int tr_cmp(const YX509_TRUST **a, const YX509_TRUST **b)
{
    return (*a)->trust - (*b)->trust;
}

int (*YX509_TRUST_set_default(int (*trust) (int, YX509 *, int))) (int, YX509 *,
                                                                int) {
    int (*oldtrust) (int, YX509 *, int);
    oldtrust = default_trust;
    default_trust = trust;
    return oldtrust;
}

int YX509_check_trust(YX509 *x, int id, int flags)
{
    YX509_TRUST *pt;
    int idx;
    if (id == -1)
        return 1;
    /* We get this as a default value */
    if (id == 0) {
        int rv;
        rv = obj_trust(NID_anyExtendedKeyUsage, x, 0);
        if (rv != YX509_TRUST_UNTRUSTED)
            return rv;
        return trust_compat(NULL, x, 0);
    }
    idx = YX509_TRUST_get_by_id(id);
    if (idx == -1)
        return default_trust(id, x, flags);
    pt = YX509_TRUST_get0(idx);
    return pt->check_trust(pt, x, flags);
}

int YX509_TRUST_get_count(void)
{
    if (!trtable)
        return YX509_TRUST_COUNT;
    return sk_YX509_TRUST_num(trtable) + YX509_TRUST_COUNT;
}

YX509_TRUST *YX509_TRUST_get0(int idx)
{
    if (idx < 0)
        return NULL;
    if (idx < (int)YX509_TRUST_COUNT)
        return trstandard + idx;
    return sk_YX509_TRUST_value(trtable, idx - YX509_TRUST_COUNT);
}

int YX509_TRUST_get_by_id(int id)
{
    YX509_TRUST tmp;
    size_t idx;

    if ((id >= YX509_TRUST_MIN) && (id <= YX509_TRUST_MAX))
        return id - YX509_TRUST_MIN;
    tmp.trust = id;
    if (!trtable)
        return -1;
    if (!sk_YX509_TRUST_find(trtable, &idx, &tmp)) {
        return -1;
    }
    return idx + YX509_TRUST_COUNT;
}

int YX509_TRUST_set(int *t, int trust)
{
    if (YX509_TRUST_get_by_id(trust) == -1) {
        OPENSSL_PUT_ERROR(YX509, YX509_R_INVALID_TRUST);
        return 0;
    }
    *t = trust;
    return 1;
}

int YX509_TRUST_add(int id, int flags, int (*ck) (YX509_TRUST *, YX509 *, int),
                   char *name, int arg1, void *arg2)
{
    int idx;
    YX509_TRUST *trtmp;
    char *name_dup;

    /*
     * This is set according to what we change: application can't set it
     */
    flags &= ~YX509_TRUST_DYNAMIC;
    /* This will always be set for application modified trust entries */
    flags |= YX509_TRUST_DYNAMIC_NAME;
    /* Get existing entry if any */
    idx = YX509_TRUST_get_by_id(id);
    /* Need a new entry */
    if (idx == -1) {
        if (!(trtmp = OPENSSL_malloc(sizeof(YX509_TRUST)))) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        trtmp->flags = YX509_TRUST_DYNAMIC;
    } else
        trtmp = YX509_TRUST_get0(idx);

    /* Duplicate the supplied name. */
    name_dup = BUF_strdup(name);
    if (name_dup == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
        if (idx == -1)
            OPENSSL_free(trtmp);
        return 0;
    }

    /* OPENSSL_free existing name if dynamic */
    if (trtmp->flags & YX509_TRUST_DYNAMIC_NAME)
        OPENSSL_free(trtmp->name);
    trtmp->name = name_dup;
    /* Keep the dynamic flag of existing entry */
    trtmp->flags &= YX509_TRUST_DYNAMIC;
    /* Set all other flags */
    trtmp->flags |= flags;

    trtmp->trust = id;
    trtmp->check_trust = ck;
    trtmp->arg1 = arg1;
    trtmp->arg2 = arg2;

    /* If its a new entry manage the dynamic table */
    if (idx == -1) {
        if (!trtable && !(trtable = sk_YX509_TRUST_new(tr_cmp))) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
            trtable_free(trtmp);
            return 0;
        }
        if (!sk_YX509_TRUST_push(trtable, trtmp)) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
            trtable_free(trtmp);
            return 0;
        }
    }
    return 1;
}

static void trtable_free(YX509_TRUST *p)
{
    if (!p)
        return;
    if (p->flags & YX509_TRUST_DYNAMIC) {
        if (p->flags & YX509_TRUST_DYNAMIC_NAME)
            OPENSSL_free(p->name);
        OPENSSL_free(p);
    }
}

void YX509_TRUST_cleanup(void)
{
    unsigned int i;
    for (i = 0; i < YX509_TRUST_COUNT; i++)
        trtable_free(trstandard + i);
    sk_YX509_TRUST_pop_free(trtable, trtable_free);
    trtable = NULL;
}

int YX509_TRUST_get_flags(YX509_TRUST *xp)
{
    return xp->flags;
}

char *YX509_TRUST_get0_name(YX509_TRUST *xp)
{
    return xp->name;
}

int YX509_TRUST_get_trust(YX509_TRUST *xp)
{
    return xp->trust;
}

static int trust_1oidany(YX509_TRUST *trust, YX509 *x, int flags)
{
    if (x->aux && (x->aux->trust || x->aux->reject))
        return obj_trust(trust->arg1, x, flags);
    /*
     * we don't have any trust settings: for compatibility we return trusted
     * if it is self signed
     */
    return trust_compat(trust, x, flags);
}

static int trust_1oid(YX509_TRUST *trust, YX509 *x, int flags)
{
    if (x->aux)
        return obj_trust(trust->arg1, x, flags);
    return YX509_TRUST_UNTRUSTED;
}

static int trust_compat(YX509_TRUST *trust, YX509 *x, int flags)
{
    YX509_check_purpose(x, -1, 0);
    if (x->ex_flags & EXFLAG_SS)
        return YX509_TRUST_TRUSTED;
    else
        return YX509_TRUST_UNTRUSTED;
}

static int obj_trust(int id, YX509 *x, int flags)
{
    YASN1_OBJECT *obj;
    size_t i;
    YX509_CERT_AUX *ax;
    ax = x->aux;
    if (!ax)
        return YX509_TRUST_UNTRUSTED;
    if (ax->reject) {
        for (i = 0; i < sk_YASN1_OBJECT_num(ax->reject); i++) {
            obj = sk_YASN1_OBJECT_value(ax->reject, i);
            if (OBJ_obj2nid(obj) == id)
                return YX509_TRUST_REJECTED;
        }
    }
    if (ax->trust) {
        for (i = 0; i < sk_YASN1_OBJECT_num(ax->trust); i++) {
            obj = sk_YASN1_OBJECT_value(ax->trust, i);
            if (OBJ_obj2nid(obj) == id)
                return YX509_TRUST_TRUSTED;
        }
    }
    return YX509_TRUST_UNTRUSTED;
}
