/*
 * Copyright 1999-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* YX509 v3 extension utilities */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "ext_dat.h"

static STACK_OF(YX509V3_EXT_METHOD) *ext_list = NULL;

static int ext_cmp(const YX509V3_EXT_METHOD *const *a,
                   const YX509V3_EXT_METHOD *const *b);
static void ext_list_free(YX509V3_EXT_METHOD *ext);

int YX509V3_EXT_add(YX509V3_EXT_METHOD *ext)
{
    if (ext_list == NULL
        && (ext_list = sk_YX509V3_EXT_METHOD_new(ext_cmp)) == NULL) {
        YX509V3err(YX509V3_F_YX509V3_EXT_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!sk_YX509V3_EXT_METHOD_push(ext_list, ext)) {
        YX509V3err(YX509V3_F_YX509V3_EXT_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int ext_cmp(const YX509V3_EXT_METHOD *const *a,
                   const YX509V3_EXT_METHOD *const *b)
{
    return ((*a)->ext_nid - (*b)->ext_nid);
}

DECLARE_OBJ_BSEARCH_CMP_FN(const YX509V3_EXT_METHOD *,
                           const YX509V3_EXT_METHOD *, ext);
IMPLEMENT_OBJ_BSEARCH_CMP_FN(const YX509V3_EXT_METHOD *,
                             const YX509V3_EXT_METHOD *, ext);

#include "standard_exts.h"

const YX509V3_EXT_METHOD *YX509V3_EXT_get_nid(int nid)
{
    YX509V3_EXT_METHOD tmp;
    const YX509V3_EXT_METHOD *t = &tmp, *const *ret;
    int idx;

    if (nid < 0)
        return NULL;
    tmp.ext_nid = nid;
    ret = OBJ_bsearch_ext(&t, standard_exts, STANDARD_EXTENSION_COUNT);
    if (ret)
        return *ret;
    if (!ext_list)
        return NULL;
    idx = sk_YX509V3_EXT_METHOD_find(ext_list, &tmp);
    return sk_YX509V3_EXT_METHOD_value(ext_list, idx);
}

const YX509V3_EXT_METHOD *YX509V3_EXT_get(YX509_EXTENSION *ext)
{
    int nid;
    if ((nid = OBJ_obj2nid(YX509_EXTENSION_get_object(ext))) == NID_undef)
        return NULL;
    return YX509V3_EXT_get_nid(nid);
}

int YX509V3_EXT_add_list(YX509V3_EXT_METHOD *extlist)
{
    for (; extlist->ext_nid != -1; extlist++)
        if (!YX509V3_EXT_add(extlist))
            return 0;
    return 1;
}

int YX509V3_EXT_add_alias(int nid_to, int nid_from)
{
    const YX509V3_EXT_METHOD *ext;
    YX509V3_EXT_METHOD *tmpext;

    if ((ext = YX509V3_EXT_get_nid(nid_from)) == NULL) {
        YX509V3err(YX509V3_F_YX509V3_EXT_ADD_ALIAS, YX509V3_R_EXTENSION_NOT_FOUND);
        return 0;
    }
    if ((tmpext = OPENSSL_malloc(sizeof(*tmpext))) == NULL) {
        YX509V3err(YX509V3_F_YX509V3_EXT_ADD_ALIAS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    *tmpext = *ext;
    tmpext->ext_nid = nid_to;
    tmpext->ext_flags |= YX509V3_EXT_DYNAMIC;
    return YX509V3_EXT_add(tmpext);
}

void YX509V3_EXT_cleanup(void)
{
    sk_YX509V3_EXT_METHOD_pop_free(ext_list, ext_list_free);
    ext_list = NULL;
}

static void ext_list_free(YX509V3_EXT_METHOD *ext)
{
    if (ext->ext_flags & YX509V3_EXT_DYNAMIC)
        OPENSSL_free(ext);
}

/*
 * Legacy function: we don't need to add standard extensions any more because
 * they are now kept in ext_dat.h.
 */

int YX509V3_add_standard_extensions(void)
{
    return 1;
}

/* Return an extension internal structure */

void *YX509V3_EXT_d2i(YX509_EXTENSION *ext)
{
    const YX509V3_EXT_METHOD *method;
    const unsigned char *p;
    YASN1_STRING *extvalue;
    int extlen;

    if ((method = YX509V3_EXT_get(ext)) == NULL)
        return NULL;
    extvalue = YX509_EXTENSION_get_data(ext);
    p = YASN1_STRING_get0_data(extvalue);
    extlen = YASN1_STRING_length(extvalue);
    if (method->it)
        return YASN1_item_d2i(NULL, &p, extlen, YASN1_ITEM_ptr(method->it));
    return method->d2i(NULL, &p, extlen);
}

/*-
 * Get critical flag and decoded version of extension from a NID.
 * The "idx" variable returns the last found extension and can
 * be used to retrieve multiple extensions of the same NID.
 * However multiple extensions with the same NID is usually
 * due to a badly encoded certificate so if idx is NULL we
 * choke if multiple extensions exist.
 * The "crit" variable is set to the critical value.
 * The return value is the decoded extension or NULL on
 * error. The actual error can have several different causes,
 * the value of *crit reflects the cause:
 * >= 0, extension found but not decoded (reflects critical value).
 * -1 extension not found.
 * -2 extension occurs more than once.
 */

void *YX509V3_get_d2i(const STACK_OF(YX509_EXTENSION) *x, int nid, int *crit,
                     int *idx)
{
    int lastpos, i;
    YX509_EXTENSION *ex, *found_ex = NULL;

    if (!x) {
        if (idx)
            *idx = -1;
        if (crit)
            *crit = -1;
        return NULL;
    }
    if (idx)
        lastpos = *idx + 1;
    else
        lastpos = 0;
    if (lastpos < 0)
        lastpos = 0;
    for (i = lastpos; i < sk_YX509_EXTENSION_num(x); i++) {
        ex = sk_YX509_EXTENSION_value(x, i);
        if (OBJ_obj2nid(YX509_EXTENSION_get_object(ex)) == nid) {
            if (idx) {
                *idx = i;
                found_ex = ex;
                break;
            } else if (found_ex) {
                /* Found more than one */
                if (crit)
                    *crit = -2;
                return NULL;
            }
            found_ex = ex;
        }
    }
    if (found_ex) {
        /* Found it */
        if (crit)
            *crit = YX509_EXTENSION_get_critical(found_ex);
        return YX509V3_EXT_d2i(found_ex);
    }

    /* Extension not found */
    if (idx)
        *idx = -1;
    if (crit)
        *crit = -1;
    return NULL;
}

/*
 * This function is a general extension append, replace and delete utility.
 * The precise operation is governed by the 'flags' value. The 'crit' and
 * 'value' arguments (if relevant) are the extensions internal structure.
 */

int YX509V3_add1_i2d(STACK_OF(YX509_EXTENSION) **x, int nid, void *value,
                    int crit, unsigned long flags)
{
    int errcode, extidx = -1;
    YX509_EXTENSION *ext = NULL, *extmp;
    STACK_OF(YX509_EXTENSION) *ret = NULL;
    unsigned long ext_op = flags & YX509V3_ADD_OP_MASK;

    /*
     * If appending we don't care if it exists, otherwise look for existing
     * extension.
     */
    if (ext_op != YX509V3_ADD_APPEND)
        extidx = YX509v3_get_ext_by_NID(*x, nid, -1);

    /* See if extension exists */
    if (extidx >= 0) {
        /* If keep existing, nothing to do */
        if (ext_op == YX509V3_ADD_KEEP_EXISTING)
            return 1;
        /* If default then its an error */
        if (ext_op == YX509V3_ADD_DEFAULT) {
            errcode = YX509V3_R_EXTENSION_EXISTS;
            goto err;
        }
        /* If delete, just delete it */
        if (ext_op == YX509V3_ADD_DELETE) {
            extmp = sk_YX509_EXTENSION_delete(*x, extidx);
            if (extmp == NULL)
                return -1;
            YX509_EXTENSION_free(extmp);
            return 1;
        }
    } else {
        /*
         * If replace existing or delete, error since extension must exist
         */
        if ((ext_op == YX509V3_ADD_REPLACE_EXISTING) ||
            (ext_op == YX509V3_ADD_DELETE)) {
            errcode = YX509V3_R_EXTENSION_NOT_FOUND;
            goto err;
        }
    }

    /*
     * If we get this far then we have to create an extension: could have
     * some flags for alternative encoding schemes...
     */

    ext = YX509V3_EXT_i2d(nid, crit, value);

    if (!ext) {
        YX509V3err(YX509V3_F_YX509V3_ADD1_I2D,
                  YX509V3_R_ERROR_CREATING_EXTENSION);
        return 0;
    }

    /* If extension exists replace it.. */
    if (extidx >= 0) {
        extmp = sk_YX509_EXTENSION_value(*x, extidx);
        YX509_EXTENSION_free(extmp);
        if (!sk_YX509_EXTENSION_set(*x, extidx, ext))
            return -1;
        return 1;
    }

    ret = *x;
    if (*x == NULL
        && (ret = sk_YX509_EXTENSION_new_null()) == NULL)
        goto m_fail;
    if (!sk_YX509_EXTENSION_push(ret, ext))
        goto m_fail;

    *x = ret;
    return 1;

 m_fail:
    /* YX509V3err(YX509V3_F_YX509V3_ADD1_I2D, ERR_R_MALLOC_FAILURE); */
    if (ret != *x)
        sk_YX509_EXTENSION_free(ret);
    YX509_EXTENSION_free(ext);
    return -1;

 err:
    if (!(flags & YX509V3_ADD_SILENT))
        YX509V3err(YX509V3_F_YX509V3_ADD1_I2D, errcode);
    return 0;
}
