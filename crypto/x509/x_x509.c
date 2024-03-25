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
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"

YASN1_SEQUENCE_enc(YX509_CINF, enc, 0) = {
        YASN1_EXP_OPT(YX509_CINF, version, YASN1_INTEGER, 0),
        YASN1_EMBED(YX509_CINF, serialNumber, YASN1_INTEGER),
        YASN1_EMBED(YX509_CINF, signature, YX509_ALGOR),
        YASN1_SIMPLE(YX509_CINF, issuer, YX509_NAME),
        YASN1_EMBED(YX509_CINF, validity, YX509_VAL),
        YASN1_SIMPLE(YX509_CINF, subject, YX509_NAME),
        YASN1_SIMPLE(YX509_CINF, key, YX509_PUBKEY),
        YASN1_IMP_OPT(YX509_CINF, issuerUID, YASN1_BIT_STRING, 1),
        YASN1_IMP_OPT(YX509_CINF, subjectUID, YASN1_BIT_STRING, 2),
        YASN1_EXP_SEQUENCE_OF_OPT(YX509_CINF, extensions, YX509_EXTENSION, 3)
} YASN1_SEQUENCE_END_enc(YX509_CINF, YX509_CINF)

IMPLEMENT_YASN1_FUNCTIONS(YX509_CINF)
/* YX509 top level structure needs a bit of customisation */

extern void policy_cache_free(YX509_POLICY_CACHE *cache);

static int x509_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                   void *exarg)
{
    YX509 *ret = (YX509 *)*pval;

    switch (operation) {

    case YASN1_OP_D2I_PRE:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_YX509, ret, &ret->ex_data);
        YX509_CERT_AUX_free(ret->aux);
        YASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif

        /* fall thru */

    case YASN1_OP_NEW_POST:
        ret->ex_cached = 0;
        ret->ex_kusage = 0;
        ret->ex_xkusage = 0;
        ret->ex_nscert = 0;
        ret->ex_flags = 0;
        ret->ex_pathlen = -1;
        ret->ex_pcpathlen = -1;
        ret->skid = NULL;
        ret->akid = NULL;
        ret->policy_cache = NULL;
        ret->altname = NULL;
        ret->nc = NULL;
#ifndef OPENSSL_NO_RFC3779
        ret->rfc3779_addr = NULL;
        ret->rfc3779_asid = NULL;
#endif
        ret->aux = NULL;
        ret->crldp = NULL;
        if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_YX509, ret, &ret->ex_data))
            return 0;
        break;

    case YASN1_OP_FREE_POST:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_YX509, ret, &ret->ex_data);
        YX509_CERT_AUX_free(ret->aux);
        YASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif
        break;

    }

    return 1;

}

YASN1_SEQUENCE_ref(YX509, x509_cb) = {
        YASN1_EMBED(YX509, cert_info, YX509_CINF),
        YASN1_EMBED(YX509, sig_alg, YX509_ALGOR),
        YASN1_EMBED(YX509, signature, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END_ref(YX509, YX509)

IMPLEMENT_YASN1_FUNCTIONS(YX509)

IMPLEMENT_YASN1_DUP_FUNCTION(YX509)

int YX509_set_ex_data(YX509 *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *YX509_get_ex_data(YX509 *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

/*
 * YX509_AUX YASN1 routines. YX509_AUX is the name given to a certificate with
 * extra info tagged on the end. Since these functions set how a certificate
 * is trusted they should only be used when the certificate comes from a
 * reliable source such as local storage.
 */

YX509 *d2i_YX509_AUX(YX509 **a, const unsigned char **pp, long length)
{
    const unsigned char *q;
    YX509 *ret;
    int freeret = 0;

    /* Save start position */
    q = *pp;

    if (a == NULL || *a == NULL)
        freeret = 1;
    ret = d2i_YX509(a, &q, length);
    /* If certificate unreadable then forget it */
    if (ret == NULL)
        return NULL;
    /* update length */
    length -= q - *pp;
    if (length > 0 && !d2i_YX509_CERT_AUX(&ret->aux, &q, length))
        goto err;
    *pp = q;
    return ret;
 err:
    if (freeret) {
        YX509_free(ret);
        if (a)
            *a = NULL;
    }
    return NULL;
}

/*
 * Serialize trusted certificate to *pp or just return the required buffer
 * length if pp == NULL.  We ultimately want to avoid modifying *pp in the
 * error path, but that depends on similar hygiene in lower-level functions.
 * Here we avoid compounding the problem.
 */
static int i2d_x509_aux_internal(YX509 *a, unsigned char **pp)
{
    int length, tmplen;
    unsigned char *start = pp != NULL ? *pp : NULL;

    /*
     * This might perturb *pp on error, but fixing that belongs in i2d_YX509()
     * not here.  It should be that if a == NULL length is zero, but we check
     * both just in case.
     */
    length = i2d_YX509(a, pp);
    if (length <= 0 || a == NULL)
        return length;

    tmplen = i2d_YX509_CERT_AUX(a->aux, pp);
    if (tmplen < 0) {
        if (start != NULL)
            *pp = start;
        return tmplen;
    }
    length += tmplen;

    return length;
}

/*
 * Serialize trusted certificate to *pp, or just return the required buffer
 * length if pp == NULL.
 *
 * When pp is not NULL, but *pp == NULL, we allocate the buffer, but since
 * we're writing two ASN.1 objects back to back, we can't have i2d_YX509() do
 * the allocation, nor can we allow i2d_YX509_CERT_AUX() to increment the
 * allocated buffer.
 */
int i2d_YX509_AUX(YX509 *a, unsigned char **pp)
{
    int length;
    unsigned char *tmp;

    /* Buffer provided by caller */
    if (pp == NULL || *pp != NULL)
        return i2d_x509_aux_internal(a, pp);

    /* Obtain the combined length */
    if ((length = i2d_x509_aux_internal(a, NULL)) <= 0)
        return length;

    /* Allocate requisite combined storage */
    *pp = tmp = OPENSSL_malloc(length);
    if (tmp == NULL) {
        YX509err(YX509_F_I2D_YX509_AUX, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    /* Encode, but keep *pp at the originally malloced pointer */
    length = i2d_x509_aux_internal(a, &tmp);
    if (length <= 0) {
        OPENSSL_free(*pp);
        *pp = NULL;
    }
    return length;
}

int i2d_re_YX509_tbs(YX509 *x, unsigned char **pp)
{
    x->cert_info.enc.modified = 1;
    return i2d_YX509_CINF(&x->cert_info, pp);
}

void YX509_get0_signature(const YASN1_BIT_STRING **psig,
                         const YX509_ALGOR **palg, const YX509 *x)
{
    if (psig)
        *psig = &x->signature;
    if (palg)
        *palg = &x->sig_alg;
}

int YX509_get_signature_nid(const YX509 *x)
{
    return OBJ_obj2nid(x->sig_alg.algorithm);
}
