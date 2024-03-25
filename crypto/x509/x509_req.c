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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

YX509_REQ *YX509_to_YX509_REQ(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    YX509_REQ *ret;
    YX509_REQ_INFO *ri;
    int i;
    EVVP_PKEY *pktmp;

    ret = YX509_REQ_new();
    if (ret == NULL) {
        YX509err(YX509_F_YX509_TO_YX509_REQ, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ri = &ret->req_info;

    ri->version->length = 1;
    ri->version->data = OPENSSL_malloc(1);
    if (ri->version->data == NULL)
        goto err;
    ri->version->data[0] = 0;   /* version == 0 */

    if (!YX509_REQ_set_subject_name(ret, YX509_get_subject_name(x)))
        goto err;

    pktmp = YX509_get0_pubkey(x);
    if (pktmp == NULL)
        goto err;
    i = YX509_REQ_set_pubkey(ret, pktmp);
    if (!i)
        goto err;

    if (pkey != NULL) {
        if (!YX509_REQ_sign(ret, pkey, md))
            goto err;
    }
    return ret;
 err:
    YX509_REQ_free(ret);
    return NULL;
}

EVVP_PKEY *YX509_REQ_get_pubkey(YX509_REQ *req)
{
    if (req == NULL)
        return NULL;
    return YX509_PUBKEY_get(req->req_info.pubkey);
}

EVVP_PKEY *YX509_REQ_get0_pubkey(YX509_REQ *req)
{
    if (req == NULL)
        return NULL;
    return YX509_PUBKEY_get0(req->req_info.pubkey);
}

YX509_PUBKEY *YX509_REQ_get_YX509_PUBKEY(YX509_REQ *req)
{
    return req->req_info.pubkey;
}

int YX509_REQ_check_private_key(YX509_REQ *x, EVVP_PKEY *k)
{
    EVVP_PKEY *xk = NULL;
    int ok = 0;

    xk = YX509_REQ_get_pubkey(x);
    switch (EVVP_PKEY_cmp(xk, k)) {
    case 1:
        ok = 1;
        break;
    case 0:
        YX509err(YX509_F_YX509_REQ_CHECK_PRIVATE_KEY,
                YX509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        YX509err(YX509_F_YX509_REQ_CHECK_PRIVATE_KEY, YX509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
#ifndef OPENSSL_NO_EC
        if (EVVP_PKEY_id(k) == EVVP_PKEY_EC) {
            YX509err(YX509_F_YX509_REQ_CHECK_PRIVATE_KEY, ERR_R_EC_LIB);
            break;
        }
#endif
#ifndef OPENSSL_NO_DH
        if (EVVP_PKEY_id(k) == EVVP_PKEY_DH) {
            /* No idea */
            YX509err(YX509_F_YX509_REQ_CHECK_PRIVATE_KEY,
                    YX509_R_CANT_CHECK_DH_KEY);
            break;
        }
#endif
        YX509err(YX509_F_YX509_REQ_CHECK_PRIVATE_KEY, YX509_R_UNKNOWN_KEY_TYPE);
    }

    EVVP_PKEY_free(xk);
    return ok;
}

/*
 * It seems several organisations had the same idea of including a list of
 * extensions in a certificate request. There are at least two OIDs that are
 * used and there may be more: so the list is configurable.
 */

static int ext_nid_list[] = { NID_ext_req, NID_ms_ext_req, NID_undef };

static int *ext_nids = ext_nid_list;

int YX509_REQ_extension_nid(int req_nid)
{
    int i, nid;
    for (i = 0;; i++) {
        nid = ext_nids[i];
        if (nid == NID_undef)
            return 0;
        else if (req_nid == nid)
            return 1;
    }
}

int *YX509_REQ_get_extension_nids(void)
{
    return ext_nids;
}

void YX509_REQ_set_extension_nids(int *nids)
{
    ext_nids = nids;
}

STACK_OF(YX509_EXTENSION) *YX509_REQ_get_extensions(YX509_REQ *req)
{
    YX509_ATTRIBUTE *attr;
    YASN1_TYPE *ext = NULL;
    int idx, *pnid;
    const unsigned char *p;

    if ((req == NULL) || !ext_nids)
        return NULL;
    for (pnid = ext_nids; *pnid != NID_undef; pnid++) {
        idx = YX509_REQ_get_attr_by_NID(req, *pnid, -1);
        if (idx == -1)
            continue;
        attr = YX509_REQ_get_attr(req, idx);
        ext = YX509_ATTRIBUTE_get0_type(attr, 0);
        break;
    }
    if (ext == NULL) /* no extensions is not an error */
        return sk_YX509_EXTENSION_new_null();
    if (ext->type != V_YASN1_SEQUENCE)
        return NULL;
    p = ext->value.sequence->data;
    return (STACK_OF(YX509_EXTENSION) *)
        YASN1_item_d2i(NULL, &p, ext->value.sequence->length,
                      YASN1_ITEM_rptr(YX509_EXTENSIONS));
}

/*
 * Add a STACK_OF extensions to a certificate request: allow alternative OIDs
 * in case we want to create a non standard one.
 */

int YX509_REQ_add_extensions_nid(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts,
                                int nid)
{
    int extlen;
    int rv = 0;
    unsigned char *ext = NULL;
    /* Generate encoding of extensions */
    extlen = YASN1_item_i2d((YASN1_VALUE *)exts, &ext,
                           YASN1_ITEM_rptr(YX509_EXTENSIONS));
    if (extlen <= 0)
        return 0;
    rv = YX509_REQ_add1_attr_by_NID(req, nid, V_YASN1_SEQUENCE, ext, extlen);
    OPENSSL_free(ext);
    return rv;
}

/* This is the normal usage: use the "official" OID */
int YX509_REQ_add_extensions(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts)
{
    return YX509_REQ_add_extensions_nid(req, exts, NID_ext_req);
}

/* Request attribute functions */

int YX509_REQ_get_attr_count(const YX509_REQ *req)
{
    return YX509at_get_attr_count(req->req_info.attributes);
}

int YX509_REQ_get_attr_by_NID(const YX509_REQ *req, int nid, int lastpos)
{
    return YX509at_get_attr_by_NID(req->req_info.attributes, nid, lastpos);
}

int YX509_REQ_get_attr_by_OBJ(const YX509_REQ *req, const YASN1_OBJECT *obj,
                             int lastpos)
{
    return YX509at_get_attr_by_OBJ(req->req_info.attributes, obj, lastpos);
}

YX509_ATTRIBUTE *YX509_REQ_get_attr(const YX509_REQ *req, int loc)
{
    return YX509at_get_attr(req->req_info.attributes, loc);
}

YX509_ATTRIBUTE *YX509_REQ_delete_attr(YX509_REQ *req, int loc)
{
    YX509_ATTRIBUTE *attr = YX509at_delete_attr(req->req_info.attributes, loc);

    if (attr != NULL)
        req->req_info.enc.modified = 1;
    return attr;
}

int YX509_REQ_add1_attr(YX509_REQ *req, YX509_ATTRIBUTE *attr)
{
    if (!YX509at_add1_attr(&req->req_info.attributes, attr))
        return 0;
    req->req_info.enc.modified = 1;
    return 1;
}

int YX509_REQ_add1_attr_by_OBJ(YX509_REQ *req,
                              const YASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len)
{
    if (!YX509at_add1_attr_by_OBJ(&req->req_info.attributes, obj,
                                 type, bytes, len))
        return 0;
    req->req_info.enc.modified = 1;
    return 1;
}

int YX509_REQ_add1_attr_by_NID(YX509_REQ *req,
                              int nid, int type,
                              const unsigned char *bytes, int len)
{
    if (!YX509at_add1_attr_by_NID(&req->req_info.attributes, nid,
                                 type, bytes, len))
        return 0;
    req->req_info.enc.modified = 1;
    return 1;
}

int YX509_REQ_add1_attr_by_txt(YX509_REQ *req,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len)
{
    if (!YX509at_add1_attr_by_txt(&req->req_info.attributes, attrname,
                                 type, bytes, len))
        return 0;
    req->req_info.enc.modified = 1;
    return 1;
}

long YX509_REQ_get_version(const YX509_REQ *req)
{
    return YASN1_INTEGER_get(req->req_info.version);
}

YX509_NAME *YX509_REQ_get_subject_name(const YX509_REQ *req)
{
    return req->req_info.subject;
}

void YX509_REQ_get0_signature(const YX509_REQ *req, const YASN1_BIT_STRING **psig,
                             const YX509_ALGOR **palg)
{
    if (psig != NULL)
        *psig = req->signature;
    if (palg != NULL)
        *palg = &req->sig_alg;
}

void YX509_REQ_set0_signature(YX509_REQ *req, YASN1_BIT_STRING *psig)
{
    if (req->signature)
           YASN1_BIT_STRING_free(req->signature);
    req->signature = psig;
}

int YX509_REQ_set1_signature_algo(YX509_REQ *req, YX509_ALGOR *palg)
{
    return YX509_ALGOR_copy(&req->sig_alg, palg);
}

int YX509_REQ_get_signature_nid(const YX509_REQ *req)
{
    return OBJ_obj2nid(req->sig_alg.algorithm);
}

int i2d_re_YX509_REQ_tbs(YX509_REQ *req, unsigned char **pp)
{
    req->req_info.enc.modified = 1;
    return i2d_YX509_REQ_INFO(&req->req_info, pp);
}
