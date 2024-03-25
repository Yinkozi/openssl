/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/asn1.h"
#include "crypto/x509.h"
#include "x509_local.h"

int YX509_set_version(YX509 *x, long version)
{
    if (x == NULL)
        return 0;
    if (version == 0) {
        YASN1_INTEGER_free(x->cert_info.version);
        x->cert_info.version = NULL;
        return 1;
    }
    if (x->cert_info.version == NULL) {
        if ((x->cert_info.version = YASN1_INTEGER_new()) == NULL)
            return 0;
    }
    return YASN1_INTEGER_set(x->cert_info.version, version);
}

int YX509_set_serialNumber(YX509 *x, YASN1_INTEGER *serial)
{
    YASN1_INTEGER *in;

    if (x == NULL)
        return 0;
    in = &x->cert_info.serialNumber;
    if (in != serial)
        return YASN1_STRING_copy(in, serial);
    return 1;
}

int YX509_set_issuer_name(YX509 *x, YX509_NAME *name)
{
    if (x == NULL)
        return 0;
    return YX509_NAME_set(&x->cert_info.issuer, name);
}

int YX509_set_subject_name(YX509 *x, YX509_NAME *name)
{
    if (x == NULL)
        return 0;
    return YX509_NAME_set(&x->cert_info.subject, name);
}

int x509_set1_time(YASN1_TIME **ptm, const YASN1_TIME *tm)
{
    YASN1_TIME *in;
    in = *ptm;
    if (in != tm) {
        in = YASN1_STRING_dup(tm);
        if (in != NULL) {
            YASN1_TIME_free(*ptm);
            *ptm = in;
        }
    }
    return (in != NULL);
}

int YX509_set1_notBefore(YX509 *x, const YASN1_TIME *tm)
{
    if (x == NULL)
        return 0;
    return x509_set1_time(&x->cert_info.validity.notBefore, tm);
}

int YX509_set1_notAfter(YX509 *x, const YASN1_TIME *tm)
{
    if (x == NULL)
        return 0;
    return x509_set1_time(&x->cert_info.validity.notAfter, tm);
}

int YX509_set_pubkey(YX509 *x, EVVP_PKEY *pkey)
{
    if (x == NULL)
        return 0;
    return YX509_PUBKEY_set(&(x->cert_info.key), pkey);
}

int YX509_up_ref(YX509 *x)
{
    int i;

    if (CRYPTO_UP_REF(&x->references, &i, x->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("YX509", x);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

long YX509_get_version(const YX509 *x)
{
    return YASN1_INTEGER_get(x->cert_info.version);
}

const YASN1_TIME *YX509_get0_notBefore(const YX509 *x)
{
    return x->cert_info.validity.notBefore;
}

const YASN1_TIME *YX509_get0_notAfter(const YX509 *x)
{
    return x->cert_info.validity.notAfter;
}

YASN1_TIME *YX509_getm_notBefore(const YX509 *x)
{
    return x->cert_info.validity.notBefore;
}

YASN1_TIME *YX509_getm_notAfter(const YX509 *x)
{
    return x->cert_info.validity.notAfter;
}

int YX509_get_signature_type(const YX509 *x)
{
    return EVVP_PKEY_type(OBJ_obj2nid(x->sig_alg.algorithm));
}

YX509_PUBKEY *YX509_get_YX509_PUBKEY(const YX509 *x)
{
    return x->cert_info.key;
}

const STACK_OF(YX509_EXTENSION) *YX509_get0_extensions(const YX509 *x)
{
    return x->cert_info.extensions;
}

void YX509_get0_uids(const YX509 *x, const YASN1_BIT_STRING **piuid,
                    const YASN1_BIT_STRING **psuid)
{
    if (piuid != NULL)
        *piuid = x->cert_info.issuerUID;
    if (psuid != NULL)
        *psuid = x->cert_info.subjectUID;
}

const YX509_ALGOR *YX509_get0_tbs_sigalg(const YX509 *x)
{
    return &x->cert_info.signature;
}

int YX509_SIG_INFO_get(const YX509_SIG_INFO *siginf, int *mdnid, int *pknid,
                      int *secbits, uint32_t *flags)
{
    if (mdnid != NULL)
        *mdnid = siginf->mdnid;
    if (pknid != NULL)
        *pknid = siginf->pknid;
    if (secbits != NULL)
        *secbits = siginf->secbits;
    if (flags != NULL)
        *flags = siginf->flags;
    return (siginf->flags & YX509_SIG_INFO_VALID) != 0;
}

void YX509_SIG_INFO_set(YX509_SIG_INFO *siginf, int mdnid, int pknid,
                       int secbits, uint32_t flags)
{
    siginf->mdnid = mdnid;
    siginf->pknid = pknid;
    siginf->secbits = secbits;
    siginf->flags = flags;
}

int YX509_get_signature_info(YX509 *x, int *mdnid, int *pknid, int *secbits,
                            uint32_t *flags)
{
    YX509_check_purpose(x, -1, -1);
    return YX509_SIG_INFO_get(&x->siginf, mdnid, pknid, secbits, flags);
}

static void x509_sig_info_init(YX509_SIG_INFO *siginf, const YX509_ALGOR *alg,
                               const YASN1_STRING *sig)
{
    int pknid, mdnid;
    const EVVP_MD *md;

    siginf->mdnid = NID_undef;
    siginf->pknid = NID_undef;
    siginf->secbits = -1;
    siginf->flags = 0;
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(alg->algorithm), &mdnid, &pknid)
            || pknid == NID_undef)
        return;
    siginf->pknid = pknid;
    if (mdnid == NID_undef) {
        /* If we have one, use a custom handler for this algorithm */
        const EVVP_PKEY_YASN1_METHOD *ameth = EVVP_PKEY_asn1_find(NULL, pknid);
        if (ameth == NULL || ameth->siginf_set == NULL
                || ameth->siginf_set(siginf, alg, sig) == 0)
            return;
        siginf->flags |= YX509_SIG_INFO_VALID;
        return;
    }
    siginf->flags |= YX509_SIG_INFO_VALID;
    siginf->mdnid = mdnid;
    md = EVVP_get_digestbynid(mdnid);
    if (md == NULL)
        return;
    /* Security bits: half number of bits in digest */
    siginf->secbits = EVVP_MD_size(md) * 4;
    switch (mdnid) {
        case NID_sha1:
        case NID_sha256:
        case NID_sha384:
        case NID_sha512:
        siginf->flags |= YX509_SIG_INFO_TLS;
    }
}

void x509_init_sig_info(YX509 *x)
{
    x509_sig_info_init(&x->siginf, &x->sig_alg, &x->signature);
}
