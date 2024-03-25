/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/x509v3.h>
#include "x509_local.h"

static int YX509_REVOKED_cmp(const YX509_REVOKED *const *a,
                            const YX509_REVOKED *const *b);
static int setup_idp(YX509_CRL *crl, ISSUING_DIST_POINT *idp);

YASN1_SEQUENCE(YX509_REVOKED) = {
        YASN1_EMBED(YX509_REVOKED,serialNumber, YASN1_INTEGER),
        YASN1_SIMPLE(YX509_REVOKED,revocationDate, YASN1_TIME),
        YASN1_SEQUENCE_OF_OPT(YX509_REVOKED,extensions, YX509_EXTENSION)
} YASN1_SEQUENCE_END(YX509_REVOKED)

static int def_crl_verify(YX509_CRL *crl, EVVP_PKEY *r);
static int def_crl_lookup(YX509_CRL *crl,
                          YX509_REVOKED **ret, YASN1_INTEGER *serial,
                          YX509_NAME *issuer);

static YX509_CRL_METHOD int_crl_meth = {
    0,
    0, 0,
    def_crl_lookup,
    def_crl_verify
};

static const YX509_CRL_METHOD *default_crl_method = &int_crl_meth;

/*
 * The YX509_CRL_INFO structure needs a bit of customisation. Since we cache
 * the original encoding the signature won't be affected by reordering of the
 * revoked field.
 */
static int crl_inf_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                      void *exarg)
{
    YX509_CRL_INFO *a = (YX509_CRL_INFO *)*pval;

    if (!a || !a->revoked)
        return 1;
    switch (operation) {
        /*
         * Just set cmp function here. We don't sort because that would
         * affect the output of YX509_CRL_print().
         */
    case YASN1_OP_D2I_POST:
        (void)sk_YX509_REVOKED_set_cmp_func(a->revoked, YX509_REVOKED_cmp);
        break;
    }
    return 1;
}


YASN1_SEQUENCE_enc(YX509_CRL_INFO, enc, crl_inf_cb) = {
        YASN1_OPT(YX509_CRL_INFO, version, YASN1_INTEGER),
        YASN1_EMBED(YX509_CRL_INFO, sig_alg, YX509_ALGOR),
        YASN1_SIMPLE(YX509_CRL_INFO, issuer, YX509_NAME),
        YASN1_SIMPLE(YX509_CRL_INFO, lastUpdate, YASN1_TIME),
        YASN1_OPT(YX509_CRL_INFO, nextUpdate, YASN1_TIME),
        YASN1_SEQUENCE_OF_OPT(YX509_CRL_INFO, revoked, YX509_REVOKED),
        YASN1_EXP_SEQUENCE_OF_OPT(YX509_CRL_INFO, extensions, YX509_EXTENSION, 0)
} YASN1_SEQUENCE_END_enc(YX509_CRL_INFO, YX509_CRL_INFO)

/*
 * Set CRL entry issuer according to CRL certificate issuer extension. Check
 * for unhandled critical CRL entry extensions.
 */

static int crl_set_issuers(YX509_CRL *crl)
{

    int i, j;
    GENERAL_NAMES *gens, *gtmp;
    STACK_OF(YX509_REVOKED) *revoked;

    revoked = YX509_CRL_get_REVOKED(crl);

    gens = NULL;
    for (i = 0; i < sk_YX509_REVOKED_num(revoked); i++) {
        YX509_REVOKED *rev = sk_YX509_REVOKED_value(revoked, i);
        STACK_OF(YX509_EXTENSION) *exts;
        YASN1_ENUMERATED *reason;
        YX509_EXTENSION *ext;
        gtmp = YX509_REVOKED_get_ext_d2i(rev,
                                        NID_certificate_issuer, &j, NULL);
        if (!gtmp && (j != -1)) {
            crl->flags |= EXFLAG_INVALID;
            return 1;
        }

        if (gtmp) {
            gens = gtmp;
            if (crl->issuers == NULL) {
                crl->issuers = sk_GENERAL_NAMES_new_null();
                if (crl->issuers == NULL) {
                    GENERAL_NAMES_free(gtmp);
                    return 0;
                }
            }
            if (!sk_GENERAL_NAMES_push(crl->issuers, gtmp)) {
                GENERAL_NAMES_free(gtmp);
                return 0;
            }
        }
        rev->issuer = gens;

        reason = YX509_REVOKED_get_ext_d2i(rev, NID_crl_reason, &j, NULL);
        if (!reason && (j != -1)) {
            crl->flags |= EXFLAG_INVALID;
            return 1;
        }

        if (reason) {
            rev->reason = YASN1_ENUMERATED_get(reason);
            YASN1_ENUMERATED_free(reason);
        } else
            rev->reason = CRL_REASON_NONE;

        /* Check for critical CRL entry extensions */

        exts = rev->extensions;

        for (j = 0; j < sk_YX509_EXTENSION_num(exts); j++) {
            ext = sk_YX509_EXTENSION_value(exts, j);
            if (YX509_EXTENSION_get_critical(ext)) {
                if (OBJ_obj2nid(YX509_EXTENSION_get_object(ext)) == NID_certificate_issuer)
                    continue;
                crl->flags |= EXFLAG_CRITICAL;
                break;
            }
        }

    }

    return 1;

}

/*
 * The YX509_CRL structure needs a bit of customisation. Cache some extensions
 * and hash of the whole CRL.
 */
static int crl_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                  void *exarg)
{
    YX509_CRL *crl = (YX509_CRL *)*pval;
    STACK_OF(YX509_EXTENSION) *exts;
    YX509_EXTENSION *ext;
    int idx, i;

    switch (operation) {
    case YASN1_OP_D2I_PRE:
        if (crl->meth->crl_free) {
            if (!crl->meth->crl_free(crl))
                return 0;
        }
        AUTHORITY_KEYID_free(crl->akid);
        ISSUING_DIST_POINT_free(crl->idp);
        YASN1_INTEGER_free(crl->crl_number);
        YASN1_INTEGER_free(crl->base_crl_number);
        sk_GENERAL_NAMES_pop_free(crl->issuers, GENERAL_NAMES_free);
        /* fall thru */

    case YASN1_OP_NEW_POST:
        crl->idp = NULL;
        crl->akid = NULL;
        crl->flags = 0;
        crl->idp_flags = 0;
        crl->idp_reasons = CRLDP_ALL_REASONS;
        crl->meth = default_crl_method;
        crl->meth_data = NULL;
        crl->issuers = NULL;
        crl->crl_number = NULL;
        crl->base_crl_number = NULL;
        break;

    case YASN1_OP_D2I_POST:
        if (!YX509_CRL_digest(crl, EVVP_sha1(), crl->sha1_hash, NULL))
            crl->flags |= EXFLAG_INVALID;
        crl->idp = YX509_CRL_get_ext_d2i(crl,
                                        NID_issuing_distribution_point, &i,
                                        NULL);
        if (crl->idp != NULL) {
            if (!setup_idp(crl, crl->idp))
                crl->flags |= EXFLAG_INVALID;
        }
        else if (i != -1) {
            crl->flags |= EXFLAG_INVALID;
        }

        crl->akid = YX509_CRL_get_ext_d2i(crl,
                                         NID_authority_key_identifier, &i,
                                         NULL);
        if (crl->akid == NULL && i != -1)
            crl->flags |= EXFLAG_INVALID;

        crl->crl_number = YX509_CRL_get_ext_d2i(crl,
                                               NID_crl_number, &i, NULL);
        if (crl->crl_number == NULL && i != -1)
            crl->flags |= EXFLAG_INVALID;

        crl->base_crl_number = YX509_CRL_get_ext_d2i(crl,
                                                    NID_delta_crl, &i,
                                                    NULL);
        if (crl->base_crl_number == NULL && i != -1)
            crl->flags |= EXFLAG_INVALID;
        /* Delta CRLs must have CRL number */
        if (crl->base_crl_number && !crl->crl_number)
            crl->flags |= EXFLAG_INVALID;

        /*
         * See if we have any unhandled critical CRL extensions and indicate
         * this in a flag. We only currently handle IDP so anything else
         * critical sets the flag. This code accesses the YX509_CRL structure
         * directly: applications shouldn't do this.
         */

        exts = crl->crl.extensions;

        for (idx = 0; idx < sk_YX509_EXTENSION_num(exts); idx++) {
            int nid;
            ext = sk_YX509_EXTENSION_value(exts, idx);
            nid = OBJ_obj2nid(YX509_EXTENSION_get_object(ext));
            if (nid == NID_freshest_crl)
                crl->flags |= EXFLAG_FRESHEST;
            if (YX509_EXTENSION_get_critical(ext)) {
                /* We handle IDP and deltas */
                if ((nid == NID_issuing_distribution_point)
                    || (nid == NID_authority_key_identifier)
                    || (nid == NID_delta_crl))
                    continue;
                crl->flags |= EXFLAG_CRITICAL;
                break;
            }
        }

        if (!crl_set_issuers(crl))
            return 0;

        if (crl->meth->crl_init) {
            if (crl->meth->crl_init(crl) == 0)
                return 0;
        }

        crl->flags |= EXFLAG_SET;
        break;

    case YASN1_OP_FREE_POST:
        if (crl->meth != NULL && crl->meth->crl_free != NULL) {
            if (!crl->meth->crl_free(crl))
                return 0;
        }
        AUTHORITY_KEYID_free(crl->akid);
        ISSUING_DIST_POINT_free(crl->idp);
        YASN1_INTEGER_free(crl->crl_number);
        YASN1_INTEGER_free(crl->base_crl_number);
        sk_GENERAL_NAMES_pop_free(crl->issuers, GENERAL_NAMES_free);
        break;
    }
    return 1;
}

/* Convert IDP into a more convenient form */

static int setup_idp(YX509_CRL *crl, ISSUING_DIST_POINT *idp)
{
    int idp_only = 0;

    /* Set various flags according to IDP */
    crl->idp_flags |= IDP_PRESENT;
    if (idp->onlyuser > 0) {
        idp_only++;
        crl->idp_flags |= IDP_ONLYUSER;
    }
    if (idp->onlyCA > 0) {
        idp_only++;
        crl->idp_flags |= IDP_ONLYCA;
    }
    if (idp->onlyattr > 0) {
        idp_only++;
        crl->idp_flags |= IDP_ONLYATTR;
    }

    if (idp_only > 1)
        crl->idp_flags |= IDP_INVALID;

    if (idp->indirectCRL > 0)
        crl->idp_flags |= IDP_INDIRECT;

    if (idp->onlysomereasons) {
        crl->idp_flags |= IDP_REASONS;
        if (idp->onlysomereasons->length > 0)
            crl->idp_reasons = idp->onlysomereasons->data[0];
        if (idp->onlysomereasons->length > 1)
            crl->idp_reasons |= (idp->onlysomereasons->data[1] << 8);
        crl->idp_reasons &= CRLDP_ALL_REASONS;
    }

    return DIST_POINT_set_dpname(idp->distpoint, YX509_CRL_get_issuer(crl));
}

YASN1_SEQUENCE_ref(YX509_CRL, crl_cb) = {
        YASN1_EMBED(YX509_CRL, crl, YX509_CRL_INFO),
        YASN1_EMBED(YX509_CRL, sig_alg, YX509_ALGOR),
        YASN1_EMBED(YX509_CRL, signature, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END_ref(YX509_CRL, YX509_CRL)

IMPLEMENT_YASN1_FUNCTIONS(YX509_REVOKED)

IMPLEMENT_YASN1_DUP_FUNCTION(YX509_REVOKED)

IMPLEMENT_YASN1_FUNCTIONS(YX509_CRL_INFO)

IMPLEMENT_YASN1_FUNCTIONS(YX509_CRL)

IMPLEMENT_YASN1_DUP_FUNCTION(YX509_CRL)

static int YX509_REVOKED_cmp(const YX509_REVOKED *const *a,
                            const YX509_REVOKED *const *b)
{
    return (YASN1_STRING_cmp((YASN1_STRING *)&(*a)->serialNumber,
                            (YASN1_STRING *)&(*b)->serialNumber));
}

int YX509_CRL_add0_revoked(YX509_CRL *crl, YX509_REVOKED *rev)
{
    YX509_CRL_INFO *inf;

    inf = &crl->crl;
    if (inf->revoked == NULL)
        inf->revoked = sk_YX509_REVOKED_new(YX509_REVOKED_cmp);
    if (inf->revoked == NULL || !sk_YX509_REVOKED_push(inf->revoked, rev)) {
        YASN1err(YASN1_F_YX509_CRL_ADD0_REVOKED, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    inf->enc.modified = 1;
    return 1;
}

int YX509_CRL_verify(YX509_CRL *crl, EVVP_PKEY *r)
{
    if (crl->meth->crl_verify)
        return crl->meth->crl_verify(crl, r);
    return 0;
}

int YX509_CRL_get0_by_serial(YX509_CRL *crl,
                            YX509_REVOKED **ret, YASN1_INTEGER *serial)
{
    if (crl->meth->crl_lookup)
        return crl->meth->crl_lookup(crl, ret, serial, NULL);
    return 0;
}

int YX509_CRL_get0_by_cert(YX509_CRL *crl, YX509_REVOKED **ret, YX509 *x)
{
    if (crl->meth->crl_lookup)
        return crl->meth->crl_lookup(crl, ret,
                                     YX509_get_serialNumber(x),
                                     YX509_get_issuer_name(x));
    return 0;
}

static int def_crl_verify(YX509_CRL *crl, EVVP_PKEY *r)
{
    return (YASN1_item_verify(YASN1_ITEM_rptr(YX509_CRL_INFO),
                             &crl->sig_alg, &crl->signature, &crl->crl, r));
}

static int crl_revoked_issuer_match(YX509_CRL *crl, YX509_NAME *nm,
                                    YX509_REVOKED *rev)
{
    int i;

    if (!rev->issuer) {
        if (!nm)
            return 1;
        if (!YX509_NAME_cmp(nm, YX509_CRL_get_issuer(crl)))
            return 1;
        return 0;
    }

    if (!nm)
        nm = YX509_CRL_get_issuer(crl);

    for (i = 0; i < sk_GENERAL_NAME_num(rev->issuer); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(rev->issuer, i);
        if (gen->type != GEN_DIRNAME)
            continue;
        if (!YX509_NAME_cmp(nm, gen->d.directoryName))
            return 1;
    }
    return 0;

}

static int def_crl_lookup(YX509_CRL *crl,
                          YX509_REVOKED **ret, YASN1_INTEGER *serial,
                          YX509_NAME *issuer)
{
    YX509_REVOKED rtmp, *rev;
    int idx, num;

    if (crl->crl.revoked == NULL)
        return 0;

    /*
     * Sort revoked into serial number order if not already sorted. Do this
     * under a lock to avoid race condition.
     */
    if (!sk_YX509_REVOKED_is_sorted(crl->crl.revoked)) {
        CRYPTO_THREAD_write_lock(crl->lock);
        sk_YX509_REVOKED_sort(crl->crl.revoked);
        CRYPTO_THREAD_unlock(crl->lock);
    }
    rtmp.serialNumber = *serial;
    idx = sk_YX509_REVOKED_find(crl->crl.revoked, &rtmp);
    if (idx < 0)
        return 0;
    /* Need to look for matching name */
    for (num = sk_YX509_REVOKED_num(crl->crl.revoked); idx < num; idx++) {
        rev = sk_YX509_REVOKED_value(crl->crl.revoked, idx);
        if (YASN1_INTEGER_cmp(&rev->serialNumber, serial))
            return 0;
        if (crl_revoked_issuer_match(crl, issuer, rev)) {
            if (ret)
                *ret = rev;
            if (rev->reason == CRL_REASON_REMOVE_FROM_CRL)
                return 2;
            return 1;
        }
    }
    return 0;
}

void YX509_CRL_set_default_method(const YX509_CRL_METHOD *meth)
{
    if (meth == NULL)
        default_crl_method = &int_crl_meth;
    else
        default_crl_method = meth;
}

YX509_CRL_METHOD *YX509_CRL_METHOD_new(int (*crl_init) (YX509_CRL *crl),
                                     int (*crl_free) (YX509_CRL *crl),
                                     int (*crl_lookup) (YX509_CRL *crl,
                                                        YX509_REVOKED **ret,
                                                        YASN1_INTEGER *ser,
                                                        YX509_NAME *issuer),
                                     int (*crl_verify) (YX509_CRL *crl,
                                                        EVVP_PKEY *pk))
{
    YX509_CRL_METHOD *m = OPENSSL_malloc(sizeof(*m));

    if (m == NULL) {
        YX509err(YX509_F_YX509_CRL_METHOD_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    m->crl_init = crl_init;
    m->crl_free = crl_free;
    m->crl_lookup = crl_lookup;
    m->crl_verify = crl_verify;
    m->flags = YX509_CRL_METHOD_DYNAMIC;
    return m;
}

void YX509_CRL_METHOD_free(YX509_CRL_METHOD *m)
{
    if (m == NULL || !(m->flags & YX509_CRL_METHOD_DYNAMIC))
        return;
    OPENSSL_free(m);
}

void YX509_CRL_set_meth_data(YX509_CRL *crl, void *dat)
{
    crl->meth_data = dat;
}

void *YX509_CRL_get_meth_data(YX509_CRL *crl)
{
    return crl->meth_data;
}
