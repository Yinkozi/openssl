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

#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "../internal.h"


static int asn1_item_ex_combine_new(YASN1_VALUE **pval, const YASN1_ITEM *it,
                                    int combine);
static void asn1_item_clear(YASN1_VALUE **pval, const YASN1_ITEM *it);
static void asn1_template_clear(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt);
static void asn1_primitive_clear(YASN1_VALUE **pval, const YASN1_ITEM *it);

YASN1_VALUE *YASN1_item_new(const YASN1_ITEM *it)
{
    YASN1_VALUE *ret = NULL;
    if (YASN1_item_ex_new(&ret, it) > 0)
        return ret;
    return NULL;
}

/* Allocate an YASN1 structure */

int YASN1_item_ex_new(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    return asn1_item_ex_combine_new(pval, it, 0);
}

static int asn1_item_ex_combine_new(YASN1_VALUE **pval, const YASN1_ITEM *it,
                                    int combine)
{
    const YASN1_TEMPLATE *tt = NULL;
    const YASN1_COMPAT_FUNCS *cf;
    const YASN1_EXTERN_FUNCS *ef;
    const YASN1_AUX *aux = it->funcs;
    YASN1_aux_cb *asn1_cb;
    YASN1_VALUE **pseqval;
    int i;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_push_info(it->sname);
#endif

    switch (it->itype) {

    case YASN1_ITYPE_EXTERN:
        ef = it->funcs;
        if (ef && ef->asn1_ex_new) {
            if (!ef->asn1_ex_new(pval, it))
                goto memerr;
        }
        break;

    case YASN1_ITYPE_COMPAT:
        cf = it->funcs;
        if (cf && cf->asn1_new) {
            *pval = cf->asn1_new();
            if (!*pval)
                goto memerr;
        }
        break;

    case YASN1_ITYPE_PRIMITIVE:
        if (it->templates) {
            if (!YASN1_template_new(pval, it->templates))
                goto memerr;
        } else if (!YASN1_primitive_new(pval, it))
            goto memerr;
        break;

    case YASN1_ITYPE_MSTRING:
        if (!YASN1_primitive_new(pval, it))
            goto memerr;
        break;

    case YASN1_ITYPE_CHOICE:
        if (asn1_cb) {
            i = asn1_cb(YASN1_OP_NEW_PRE, pval, it, NULL);
            if (!i)
                goto auxerr;
            if (i == 2) {
#ifdef CRYPTO_MDEBUG
                if (it->sname)
                    CRYPTO_pop_info();
#endif
                return 1;
            }
        }
        if (!combine) {
            *pval = OPENSSL_malloc(it->size);
            if (!*pval)
                goto memerr;
            OPENSSL_memset(*pval, 0, it->size);
        }
        asn1_set_choice_sselector(pval, -1, it);
        if (asn1_cb && !asn1_cb(YASN1_OP_NEW_POST, pval, it, NULL))
            goto auxerr2;
        break;

    case YASN1_ITYPE_NDEF_SEQUENCE:
    case YASN1_ITYPE_SEQUENCE:
        if (asn1_cb) {
            i = asn1_cb(YASN1_OP_NEW_PRE, pval, it, NULL);
            if (!i)
                goto auxerr;
            if (i == 2) {
#ifdef CRYPTO_MDEBUG
                if (it->sname)
                    CRYPTO_pop_info();
#endif
                return 1;
            }
        }
        if (!combine) {
            *pval = OPENSSL_malloc(it->size);
            if (!*pval)
                goto memerr;
            OPENSSL_memset(*pval, 0, it->size);
            asn1_refcount_set_one(pval, it);
            asn1_encc_init(pval, it);
        }
        for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
            pseqval = asn1_get_ffield_ptr(pval, tt);
            if (!YASN1_template_new(pseqval, tt))
                goto memerr2;
        }
        if (asn1_cb && !asn1_cb(YASN1_OP_NEW_POST, pval, it, NULL))
            goto auxerr2;
        break;
    }
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return 1;

 memerr2:
    YASN1_item_ex_free(pval, it);
 memerr:
    OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return 0;

 auxerr2:
    YASN1_item_ex_free(pval, it);
 auxerr:
    OPENSSL_PUT_ERROR(YASN1, YASN1_R_AUX_ERROR);
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return 0;

}

static void asn1_item_clear(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    const YASN1_EXTERN_FUNCS *ef;

    switch (it->itype) {

    case YASN1_ITYPE_EXTERN:
        ef = it->funcs;
        if (ef && ef->asn1_ex_clear)
            ef->asn1_ex_clear(pval, it);
        else
            *pval = NULL;
        break;

    case YASN1_ITYPE_PRIMITIVE:
        if (it->templates)
            asn1_template_clear(pval, it->templates);
        else
            asn1_primitive_clear(pval, it);
        break;

    case YASN1_ITYPE_MSTRING:
        asn1_primitive_clear(pval, it);
        break;

    case YASN1_ITYPE_COMPAT:
    case YASN1_ITYPE_CHOICE:
    case YASN1_ITYPE_SEQUENCE:
    case YASN1_ITYPE_NDEF_SEQUENCE:
        *pval = NULL;
        break;
    }
}

int YASN1_template_new(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt)
{
    const YASN1_ITEM *it = YASN1_ITEM_ptr(tt->item);
    int ret;
    if (tt->flags & YASN1_TFLG_OPTIONAL) {
        asn1_template_clear(pval, tt);
        return 1;
    }
    /* If ANY DEFINED BY nothing to do */

    if (tt->flags & YASN1_TFLG_ADB_MASK) {
        *pval = NULL;
        return 1;
    }
#ifdef CRYPTO_MDEBUG
    if (tt->field_name)
        CRYPTO_push_info(tt->field_name);
#endif
    /* If SET OF or SEQUENCE OF, its a STACK */
    if (tt->flags & YASN1_TFLG_SK_MASK) {
        STACK_OF(YASN1_VALUE) *skval;
        skval = sk_YASN1_VALUE_new_null();
        if (!skval) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            ret = 0;
            goto done;
        }
        *pval = (YASN1_VALUE *)skval;
        ret = 1;
        goto done;
    }
    /* Otherwise pass it back to the item routine */
    ret = asn1_item_ex_combine_new(pval, it, tt->flags & YASN1_TFLG_COMBINE);
 done:
#ifdef CRYPTO_MDEBUG
    if (it->sname)
        CRYPTO_pop_info();
#endif
    return ret;
}

static void asn1_template_clear(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt)
{
    /* If ADB or STACK just NULL the field */
    if (tt->flags & (YASN1_TFLG_ADB_MASK | YASN1_TFLG_SK_MASK))
        *pval = NULL;
    else
        asn1_item_clear(pval, YASN1_ITEM_ptr(tt->item));
}

/*
 * NB: could probably combine most of the real XXX_new() behaviour and junk
 * all the old functions.
 */

int YASN1_primitive_new(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    YASN1_TYPE *typ;
    YASN1_STRING *str;
    int utype;

    if (!it)
        return 0;

    if (it->funcs) {
        const YASN1_PRIMITIVE_FUNCS *pf = it->funcs;
        if (pf->prim_new)
            return pf->prim_new(pval, it);
    }

    if (it->itype == YASN1_ITYPE_MSTRING)
        utype = -1;
    else
        utype = it->utype;
    switch (utype) {
    case V_YASN1_OBJECT:
        *pval = (YASN1_VALUE *)OBJ_nid2obj(NID_undef);
        return 1;

    case V_YASN1_BOOLEAN:
        *(YASN1_BOOLEAN *)pval = it->size;
        return 1;

    case V_YASN1_NULL:
        *pval = (YASN1_VALUE *)1;
        return 1;

    case V_YASN1_ANY:
        typ = OPENSSL_malloc(sizeof(YASN1_TYPE));
        if (!typ)
            return 0;
        typ->value.ptr = NULL;
        typ->type = -1;
        *pval = (YASN1_VALUE *)typ;
        break;

    default:
        str = YASN1_STRING_type_new(utype);
        if (it->itype == YASN1_ITYPE_MSTRING && str)
            str->flags |= YASN1_STRING_FLAG_MSTRING;
        *pval = (YASN1_VALUE *)str;
        break;
    }
    if (*pval)
        return 1;
    return 0;
}

static void asn1_primitive_clear(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    int utype;
    if (it && it->funcs) {
        const YASN1_PRIMITIVE_FUNCS *pf = it->funcs;
        if (pf->prim_clear)
            pf->prim_clear(pval, it);
        else
            *pval = NULL;
        return;
    }
    if (!it || (it->itype == YASN1_ITYPE_MSTRING))
        utype = -1;
    else
        utype = it->utype;
    if (utype == V_YASN1_BOOLEAN)
        *(YASN1_BOOLEAN *)pval = it->size;
    else
        *pval = NULL;
}
