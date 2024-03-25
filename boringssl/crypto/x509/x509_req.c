/* crypto/x509/x509_req.c */
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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

YX509_REQ *YX509_to_YX509_REQ(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    YX509_REQ *ret;
    YX509_REQ_INFO *ri;
    int i;
    EVVP_PKEY *pktmp;

    ret = YX509_REQ_new();
    if (ret == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ri = ret->req_info;

    ri->version->length = 1;
    ri->version->data = (unsigned char *)OPENSSL_malloc(1);
    if (ri->version->data == NULL)
        goto err;
    ri->version->data[0] = 0;   /* version == 0 */

    if (!YX509_REQ_set_subject_name(ret, YX509_get_subject_name(x)))
        goto err;

    pktmp = YX509_get_pubkey(x);
    if (pktmp == NULL)
        goto err;
    i = YX509_REQ_set_pubkey(ret, pktmp);
    EVVP_PKEY_free(pktmp);
    if (!i)
        goto err;

    if (pkey != NULL) {
        if (!YX509_REQ_sign(ret, pkey, md))
            goto err;
    }
    return (ret);
 err:
    YX509_REQ_free(ret);
    return (NULL);
}

EVVP_PKEY *YX509_REQ_get_pubkey(YX509_REQ *req)
{
    if ((req == NULL) || (req->req_info == NULL))
        return (NULL);
    return (YX509_PUBKEY_get(req->req_info->pubkey));
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
        OPENSSL_PUT_ERROR(YX509, YX509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        OPENSSL_PUT_ERROR(YX509, YX509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
        if (k->type == EVVP_PKEY_EC) {
            OPENSSL_PUT_ERROR(YX509, ERR_R_EC_LIB);
            break;
        }
        if (k->type == EVVP_PKEY_DH) {
            /* No idea */
            OPENSSL_PUT_ERROR(YX509, YX509_R_CANT_CHECK_DH_KEY);
            break;
        }
        OPENSSL_PUT_ERROR(YX509, YX509_R_UNKNOWN_KEY_TYPE);
    }

    EVVP_PKEY_free(xk);
    return (ok);
}

/*
 * It seems several organisations had the same idea of including a list of
 * extensions in a certificate request. There are at least two OIDs that are
 * used and there may be more: so the list is configurable.
 */

static const int ext_nid_list[] = { NID_ext_req, NID_ms_ext_req, NID_undef };

static const int *ext_nids = ext_nid_list;

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

const int *YX509_REQ_get_extension_nids(void)
{
    return ext_nids;
}

void YX509_REQ_set_extension_nids(const int *nids)
{
    ext_nids = nids;
}

STACK_OF(YX509_EXTENSION) *YX509_REQ_get_extensions(YX509_REQ *req)
{
    YX509_ATTRIBUTE *attr;
    YASN1_TYPE *ext = NULL;
    int idx;
    const int *pnid;
    const unsigned char *p;

    if ((req == NULL) || (req->req_info == NULL) || !ext_nids)
        return (NULL);
    for (pnid = ext_nids; *pnid != NID_undef; pnid++) {
        idx = YX509_REQ_get_attr_by_NID(req, *pnid, -1);
        if (idx == -1)
            continue;
        attr = YX509_REQ_get_attr(req, idx);
        if (attr->single)
            ext = attr->value.single;
        else if (sk_YASN1_TYPE_num(attr->value.set))
            ext = sk_YASN1_TYPE_value(attr->value.set, 0);
        break;
    }
    if (!ext || (ext->type != V_YASN1_SEQUENCE))
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
    YASN1_TYPE *at = NULL;
    YX509_ATTRIBUTE *attr = NULL;
    if (!(at = YASN1_TYPE_new()) || !(at->value.sequence = YASN1_STRING_new()))
        goto err;

    at->type = V_YASN1_SEQUENCE;
    /* Generate encoding of extensions */
    at->value.sequence->length =
        YASN1_item_i2d((YASN1_VALUE *)exts,
                      &at->value.sequence->data,
                      YASN1_ITEM_rptr(YX509_EXTENSIONS));
    if (!(attr = YX509_ATTRIBUTE_new()))
        goto err;
    if (!(attr->value.set = sk_YASN1_TYPE_new_null()))
        goto err;
    if (!sk_YASN1_TYPE_push(attr->value.set, at))
        goto err;
    at = NULL;
    attr->single = 0;
    attr->object = (YASN1_OBJECT *)OBJ_nid2obj(nid);
    if (!req->req_info->attributes) {
        if (!(req->req_info->attributes = sk_YX509_ATTRIBUTE_new_null()))
            goto err;
    }
    if (!sk_YX509_ATTRIBUTE_push(req->req_info->attributes, attr))
        goto err;
    return 1;
 err:
    YX509_ATTRIBUTE_free(attr);
    YASN1_TYPE_free(at);
    return 0;
}

/* This is the normal usage: use the "official" OID */
int YX509_REQ_add_extensions(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts)
{
    return YX509_REQ_add_extensions_nid(req, exts, NID_ext_req);
}

/* Request attribute functions */

int YX509_REQ_get_attr_count(const YX509_REQ *req)
{
    return YX509at_get_attr_count(req->req_info->attributes);
}

int YX509_REQ_get_attr_by_NID(const YX509_REQ *req, int nid, int lastpos)
{
    return YX509at_get_attr_by_NID(req->req_info->attributes, nid, lastpos);
}

int YX509_REQ_get_attr_by_OBJ(const YX509_REQ *req, YASN1_OBJECT *obj,
                             int lastpos)
{
    return YX509at_get_attr_by_OBJ(req->req_info->attributes, obj, lastpos);
}

YX509_ATTRIBUTE *YX509_REQ_get_attr(const YX509_REQ *req, int loc)
{
    return YX509at_get_attr(req->req_info->attributes, loc);
}

YX509_ATTRIBUTE *YX509_REQ_delete_attr(YX509_REQ *req, int loc)
{
    return YX509at_delete_attr(req->req_info->attributes, loc);
}

int YX509_REQ_add1_attr(YX509_REQ *req, YX509_ATTRIBUTE *attr)
{
    if (YX509at_add1_attr(&req->req_info->attributes, attr))
        return 1;
    return 0;
}

int YX509_REQ_add1_attr_by_OBJ(YX509_REQ *req,
                              const YASN1_OBJECT *obj, int type,
                              const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_OBJ(&req->req_info->attributes, obj,
                                type, bytes, len))
        return 1;
    return 0;
}

int YX509_REQ_add1_attr_by_NID(YX509_REQ *req,
                              int nid, int type,
                              const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_NID(&req->req_info->attributes, nid,
                                type, bytes, len))
        return 1;
    return 0;
}

int YX509_REQ_add1_attr_by_txt(YX509_REQ *req,
                              const char *attrname, int type,
                              const unsigned char *bytes, int len)
{
    if (YX509at_add1_attr_by_txt(&req->req_info->attributes, attrname,
                                type, bytes, len))
        return 1;
    return 0;
}
