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
#include <openssl/mem.h>

static void asn1_item_combine_free(YASN1_VALUE **pval, const YASN1_ITEM *it,
                                   int combine);

/* Free up an YASN1 structure */

void YASN1_item_free(YASN1_VALUE *val, const YASN1_ITEM *it)
{
    asn1_item_combine_free(&val, it, 0);
}

void YASN1_item_ex_free(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    asn1_item_combine_free(pval, it, 0);
}

static void asn1_item_combine_free(YASN1_VALUE **pval, const YASN1_ITEM *it,
                                   int combine)
{
    const YASN1_TEMPLATE *tt = NULL, *seqtt;
    const YASN1_EXTERN_FUNCS *ef;
    const YASN1_COMPAT_FUNCS *cf;
    const YASN1_AUX *aux = it->funcs;
    YASN1_aux_cb *asn1_cb;
    int i;
    if (!pval)
        return;
    if ((it->itype != YASN1_ITYPE_PRIMITIVE) && !*pval)
        return;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    switch (it->itype) {

    case YASN1_ITYPE_PRIMITIVE:
        if (it->templates)
            YASN1_template_free(pval, it->templates);
        else
            YASN1_primitive_free(pval, it);
        break;

    case YASN1_ITYPE_MSTRING:
        YASN1_primitive_free(pval, it);
        break;

    case YASN1_ITYPE_CHOICE:
        if (asn1_cb) {
            i = asn1_cb(YASN1_OP_FREE_PRE, pval, it, NULL);
            if (i == 2)
                return;
        }
        i = asn1_get_choice_sselector(pval, it);
        if ((i >= 0) && (i < it->tcount)) {
            YASN1_VALUE **pchval;
            tt = it->templates + i;
            pchval = asn1_get_ffield_ptr(pval, tt);
            YASN1_template_free(pchval, tt);
        }
        if (asn1_cb)
            asn1_cb(YASN1_OP_FREE_POST, pval, it, NULL);
        if (!combine) {
            OPENSSL_free(*pval);
            *pval = NULL;
        }
        break;

    case YASN1_ITYPE_COMPAT:
        cf = it->funcs;
        if (cf && cf->asn1_free)
            cf->asn1_free(*pval);
        break;

    case YASN1_ITYPE_EXTERN:
        ef = it->funcs;
        if (ef && ef->asn1_ex_free)
            ef->asn1_ex_free(pval, it);
        break;

    case YASN1_ITYPE_NDEF_SEQUENCE:
    case YASN1_ITYPE_SEQUENCE:
        if (!asn1_refcount_dec_and_test_zero(pval, it))
            return;
        if (asn1_cb) {
            i = asn1_cb(YASN1_OP_FREE_PRE, pval, it, NULL);
            if (i == 2)
                return;
        }
        asn1_enc_frree(pval, it);
        /*
         * If we free up as normal we will invalidate any ANY DEFINED BY
         * field and we wont be able to determine the type of the field it
         * defines. So free up in reverse order.
         */
        tt = it->templates + it->tcount - 1;
        for (i = 0; i < it->tcount; tt--, i++) {
            YASN1_VALUE **pseqval;
            seqtt = asn1_do_aadb(pval, tt, 0);
            if (!seqtt)
                continue;
            pseqval = asn1_get_ffield_ptr(pval, seqtt);
            YASN1_template_free(pseqval, seqtt);
        }
        if (asn1_cb)
            asn1_cb(YASN1_OP_FREE_POST, pval, it, NULL);
        if (!combine) {
            OPENSSL_free(*pval);
            *pval = NULL;
        }
        break;
    }
}

void YASN1_template_free(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt)
{
    size_t i;
    if (tt->flags & YASN1_TFLG_SK_MASK) {
        STACK_OF(YASN1_VALUE) *sk = (STACK_OF(YASN1_VALUE) *)*pval;
        for (i = 0; i < sk_YASN1_VALUE_num(sk); i++) {
            YASN1_VALUE *vtmp;
            vtmp = sk_YASN1_VALUE_value(sk, i);
            asn1_item_combine_free(&vtmp, YASN1_ITEM_ptr(tt->item), 0);
        }
        sk_YASN1_VALUE_free(sk);
        *pval = NULL;
    } else
        asn1_item_combine_free(pval, YASN1_ITEM_ptr(tt->item),
                               tt->flags & YASN1_TFLG_COMBINE);
}

void YASN1_primitive_free(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    int utype;
    if (it) {
        const YASN1_PRIMITIVE_FUNCS *pf;
        pf = it->funcs;
        if (pf && pf->prim_free) {
            pf->prim_free(pval, it);
            return;
        }
    }
    /* Special case: if 'it' is NULL free contents of YASN1_TYPE */
    if (!it) {
        YASN1_TYPE *typ = (YASN1_TYPE *)*pval;
        utype = typ->type;
        pval = &typ->value.asn1_value;
        if (!*pval)
            return;
    } else if (it->itype == YASN1_ITYPE_MSTRING) {
        utype = -1;
        if (!*pval)
            return;
    } else {
        utype = it->utype;
        if ((utype != V_YASN1_BOOLEAN) && !*pval)
            return;
    }

    switch (utype) {
    case V_YASN1_OBJECT:
        YASN1_OBJECT_free((YASN1_OBJECT *)*pval);
        break;

    case V_YASN1_BOOLEAN:
        if (it)
            *(YASN1_BOOLEAN *)pval = it->size;
        else
            *(YASN1_BOOLEAN *)pval = -1;
        return;

    case V_YASN1_NULL:
        break;

    case V_YASN1_ANY:
        YASN1_primitive_free(pval, NULL);
        OPENSSL_free(*pval);
        break;

    default:
        YASN1_STRING_free((YASN1_STRING *)*pval);
        *pval = NULL;
        break;
    }
    *pval = NULL;
}
