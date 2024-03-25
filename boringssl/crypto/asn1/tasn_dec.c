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
#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../internal.h"

static int asn1_check_eoc(const unsigned char **in, long len);
static int asn1_find_end(const unsigned char **in, long len, char inf);

static int asn1_collect(BUF_MEM *buf, const unsigned char **in, long len,
                        char inf, int tag, int aclass, int depth);

static int collect_data(BUF_MEM *buf, const unsigned char **p, long plen);

static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
                           char *inf, char *cst,
                           const unsigned char **in, long len,
                           int exptag, int expclass, char opt, YASN1_TLC *ctx);

static int asn1_template_ex_d2i(YASN1_VALUE **pval,
                                const unsigned char **in, long len,
                                const YASN1_TEMPLATE *tt, char opt,
                                YASN1_TLC *ctx);
static int asn1_template_noexp_d2i(YASN1_VALUE **val,
                                   const unsigned char **in, long len,
                                   const YASN1_TEMPLATE *tt, char opt,
                                   YASN1_TLC *ctx);
static int asn1_d2i_ex_primitive(YASN1_VALUE **pval,
                                 const unsigned char **in, long len,
                                 const YASN1_ITEM *it,
                                 int tag, int aclass, char opt,
                                 YASN1_TLC *ctx);

/* Table to convert tags to bit values, used for MSTRING type */
static const unsigned long tag2bit[32] = {
    0, 0, 0, B_YASN1_BIT_STRING, /* tags 0 - 3 */
    B_YASN1_OCTET_STRING, 0, 0, B_YASN1_UNKNOWN, /* tags 4- 7 */
    B_YASN1_UNKNOWN, B_YASN1_UNKNOWN, B_YASN1_UNKNOWN, B_YASN1_UNKNOWN, /* tags
                                                                     * 8-11 */
    B_YASN1_UTF8STRING, B_YASN1_UNKNOWN, B_YASN1_UNKNOWN, B_YASN1_UNKNOWN, /* tags
                                                                        * 12-15
                                                                        */
    B_YASN1_SEQUENCE, 0, B_YASN1_NUMERICSTRING, B_YASN1_PRINTABLESTRING, /* tags
                                                                       * 16-19
                                                                       */
    B_YASN1_T61STRING, B_YASN1_VIDEOTEXSTRING, B_YASN1_IA5STRING, /* tags 20-22 */
    B_YASN1_UTCTIME, B_YASN1_GENERALIZEDTIME, /* tags 23-24 */
    B_YASN1_GRAPHICSTRING, B_YASN1_ISO64STRING, B_YASN1_GENERALSTRING, /* tags
                                                                     * 25-27 */
    B_YASN1_UNIVEYRSALSTRING, B_YASN1_UNKNOWN, B_YASN1_BMPSTRING, B_YASN1_UNKNOWN, /* tags
                                                                               * 28-31
                                                                               */
};

unsigned long YASN1_tag2bit(int tag)
{
    if ((tag < 0) || (tag > 30))
        return 0;
    return tag2bit[tag];
}

/* Macro to initialize and invalidate the cache */

#define asn1_tlc_clear(c)       if (c) (c)->valid = 0
/* Version to avoid compiler warning about 'c' always non-NULL */
#define asn1_tlc_clear_nc(c)    (c)->valid = 0

/*
 * Decode an YASN1 item, this currently behaves just like a standard 'd2i'
 * function. 'in' points to a buffer to read the data from, in future we
 * will have more advanced versions that can input data a piece at a time and
 * this will simply be a special case.
 */

YASN1_VALUE *YASN1_item_d2i(YASN1_VALUE **pval,
                          const unsigned char **in, long len,
                          const YASN1_ITEM *it)
{
    YASN1_TLC c;
    YASN1_VALUE *ptmpval = NULL;
    if (!pval)
        pval = &ptmpval;
    asn1_tlc_clear_nc(&c);
    if (YASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0)
        return *pval;
    return NULL;
}

int YASN1_template_d2i(YASN1_VALUE **pval,
                      const unsigned char **in, long len,
                      const YASN1_TEMPLATE *tt)
{
    YASN1_TLC c;
    asn1_tlc_clear_nc(&c);
    return asn1_template_ex_d2i(pval, in, len, tt, 0, &c);
}

/*
 * Decode an item, taking care of IMPLICIT tagging, if any. If 'opt' set and
 * tag mismatch return -1 to handle OPTIONAL
 */

int YASN1_item_ex_d2i(YASN1_VALUE **pval, const unsigned char **in, long len,
                     const YASN1_ITEM *it,
                     int tag, int aclass, char opt, YASN1_TLC *ctx)
{
    const YASN1_TEMPLATE *tt, *errtt = NULL;
    const YASN1_COMPAT_FUNCS *cf;
    const YASN1_EXTERN_FUNCS *ef;
    const YASN1_AUX *aux = it->funcs;
    YASN1_aux_cb *asn1_cb;
    const unsigned char *p = NULL, *q;
    unsigned char *wp = NULL;   /* BIG FAT WARNING! BREAKS CONST WHERE USED */
    unsigned char imphack = 0, oclass;
    char seq_eoc, seq_nolen, cst, isopt;
    long tmplen;
    int i;
    int otag;
    int ret = 0;
    YASN1_VALUE **pchptr, *ptmpval;
    int combine = aclass & YASN1_TFLG_COMBINE;
    aclass &= ~YASN1_TFLG_COMBINE;
    if (!pval)
        return 0;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    switch (it->itype) {
    case YASN1_ITYPE_PRIMITIVE:
        if (it->templates) {
            /*
             * tagging or OPTIONAL is currently illegal on an item template
             * because the flags can't get passed down. In practice this
             * isn't a problem: we include the relevant flags from the item
             * template in the template itself.
             */
            if ((tag != -1) || opt) {
                OPENSSL_PUT_ERROR(YASN1,
                                  YASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE);
                goto err;
            }
            return asn1_template_ex_d2i(pval, in, len,
                                        it->templates, opt, ctx);
        }
        return asn1_d2i_ex_primitive(pval, in, len, it,
                                     tag, aclass, opt, ctx);
        break;

    case YASN1_ITYPE_MSTRING:
        p = *in;
        /* Just read in tag and class */
        ret = asn1_check_tlen(NULL, &otag, &oclass, NULL, NULL,
                              &p, len, -1, 0, 1, ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        }

        /* Must be UNIVEYRSAL class */
        if (oclass != V_YASN1_UNIVEYRSAL) {
            /* If OPTIONAL, assume this is OK */
            if (opt)
                return -1;
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_MSTRING_NOT_UNIVEYRSAL);
            goto err;
        }
        /* Check tag matches bit map */
        if (!(YASN1_tag2bit(otag) & it->utype)) {
            /* If OPTIONAL, assume this is OK */
            if (opt)
                return -1;
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_MSTRING_WRONG_TAG);
            goto err;
        }
        return asn1_d2i_ex_primitive(pval, in, len, it, otag, 0, 0, ctx);

    case YASN1_ITYPE_EXTERN:
        /* Use new style d2i */
        ef = it->funcs;
        return ef->asn1_ex_d2i(pval, in, len, it, tag, aclass, opt, ctx);

    case YASN1_ITYPE_COMPAT:
        /* we must resort to old style evil hackery */
        cf = it->funcs;

        /* If OPTIONAL see if it is there */
        if (opt) {
            int exptag;
            p = *in;
            if (tag == -1)
                exptag = it->utype;
            else
                exptag = tag;
            /*
             * Don't care about anything other than presence of expected tag
             */

            ret = asn1_check_tlen(NULL, NULL, NULL, NULL, NULL,
                                  &p, len, exptag, aclass, 1, ctx);
            if (!ret) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
                goto err;
            }
            if (ret == -1)
                return -1;
        }

        /*
         * This is the old style evil hack IMPLICIT handling: since the
         * underlying code is expecting a tag and class other than the one
         * present we change the buffer temporarily then change it back
         * afterwards. This doesn't and never did work for tags > 30. Yes
         * this is *horrible* but it is only needed for old style d2i which
         * will hopefully not be around for much longer. FIXME: should copy
         * the buffer then modify it so the input buffer can be const: we
         * should *always* copy because the old style d2i might modify the
         * buffer.
         */

        if (tag != -1) {
            wp = *(unsigned char **)in;
            imphack = *wp;
            if (p == NULL) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
                goto err;
            }
            *wp = (unsigned char)((*p & V_YASN1_CONSTRUCTED)
                                  | it->utype);
        }

        ptmpval = cf->asn1_d2i(pval, in, len);

        if (tag != -1)
            *wp = imphack;

        if (ptmpval)
            return 1;

        OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
        goto err;

    case YASN1_ITYPE_CHOICE:
        if (asn1_cb && !asn1_cb(YASN1_OP_D2I_PRE, pval, it, NULL))
            goto auxerr;

        if (*pval) {
            /* Free up and zero CHOICE value if initialised */
            i = asn1_get_choice_sselector(pval, it);
            if ((i >= 0) && (i < it->tcount)) {
                tt = it->templates + i;
                pchptr = asn1_get_ffield_ptr(pval, tt);
                YASN1_template_free(pchptr, tt);
                asn1_set_choice_sselector(pval, -1, it);
            }
        } else if (!YASN1_item_ex_new(pval, it)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        }
        /* CHOICE type, try each possibility in turn */
        p = *in;
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            pchptr = asn1_get_ffield_ptr(pval, tt);
            /*
             * We mark field as OPTIONAL so its absence can be recognised.
             */
            ret = asn1_template_ex_d2i(pchptr, &p, len, tt, 1, ctx);
            /* If field not present, try the next one */
            if (ret == -1)
                continue;
            /* If positive return, read OK, break loop */
            if (ret > 0)
                break;
            /* Otherwise must be an YASN1 parsing error */
            errtt = tt;
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        }

        /* Did we fall off the end without reading anything? */
        if (i == it->tcount) {
            /* If OPTIONAL, this is OK */
            if (opt) {
                /* Free and zero it */
                YASN1_item_ex_free(pval, it);
                return -1;
            }
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NO_MATCHING_CHOICE_TYPE);
            goto err;
        }

        asn1_set_choice_sselector(pval, i, it);
        if (asn1_cb && !asn1_cb(YASN1_OP_D2I_POST, pval, it, NULL))
            goto auxerr;
        *in = p;
        return 1;

    case YASN1_ITYPE_NDEF_SEQUENCE:
    case YASN1_ITYPE_SEQUENCE:
        p = *in;
        tmplen = len;

        /* If no IMPLICIT tagging set to SEQUENCE, UNIVEYRSAL */
        if (tag == -1) {
            tag = V_YASN1_SEQUENCE;
            aclass = V_YASN1_UNIVEYRSAL;
        }
        /* Get SEQUENCE length and update len, p */
        ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
                              &p, len, tag, aclass, opt, ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
        if (aux && (aux->flags & YASN1_AFLG_BROKEN)) {
            len = tmplen - (p - *in);
            seq_nolen = 1;
        }
        /* If indefinite we don't do a length check */
        else
            seq_nolen = seq_eoc;
        if (!cst) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_SEQUENCE_NOT_CONSTRUCTED);
            goto err;
        }

        if (!*pval && !YASN1_item_ex_new(pval, it)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        }

        if (asn1_cb && !asn1_cb(YASN1_OP_D2I_PRE, pval, it, NULL))
            goto auxerr;

        /* Free up and zero any ADB found */
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            if (tt->flags & YASN1_TFLG_ADB_MASK) {
                const YASN1_TEMPLATE *seqtt;
                YASN1_VALUE **pseqval;
                seqtt = asn1_do_aadb(pval, tt, 0);
                if (seqtt == NULL)
                    continue;
                pseqval = asn1_get_ffield_ptr(pval, seqtt);
                YASN1_template_free(pseqval, seqtt);
            }
        }

        /* Get each field entry */
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            const YASN1_TEMPLATE *seqtt;
            YASN1_VALUE **pseqval;
            seqtt = asn1_do_aadb(pval, tt, 1);
            if (seqtt == NULL)
                goto err;
            pseqval = asn1_get_ffield_ptr(pval, seqtt);
            /* Have we ran out of data? */
            if (!len)
                break;
            q = p;
            if (asn1_check_eoc(&p, len)) {
                if (!seq_eoc) {
                    OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNEXPECTED_EOC);
                    goto err;
                }
                len -= p - q;
                seq_eoc = 0;
                q = p;
                break;
            }
            /*
             * This determines the OPTIONAL flag value. The field cannot be
             * omitted if it is the last of a SEQUENCE and there is still
             * data to be read. This isn't strictly necessary but it
             * increases efficiency in some cases.
             */
            if (i == (it->tcount - 1))
                isopt = 0;
            else
                isopt = (char)(seqtt->flags & YASN1_TFLG_OPTIONAL);
            /*
             * attempt to read in field, allowing each to be OPTIONAL
             */

            ret = asn1_template_ex_d2i(pseqval, &p, len, seqtt, isopt, ctx);
            if (!ret) {
                errtt = seqtt;
                goto err;
            } else if (ret == -1) {
                /*
                 * OPTIONAL component absent. Free and zero the field.
                 */
                YASN1_template_free(pseqval, seqtt);
                continue;
            }
            /* Update length */
            len -= p - q;
        }

        /* Check for EOC if expecting one */
        if (seq_eoc && !asn1_check_eoc(&p, len)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_EOC);
            goto err;
        }
        /* Check all data read */
        if (!seq_nolen && len) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_SEQUENCE_LENGTH_MISMATCH);
            goto err;
        }

        /*
         * If we get here we've got no more data in the SEQUENCE, however we
         * may not have read all fields so check all remaining are OPTIONAL
         * and clear any that are.
         */
        for (; i < it->tcount; tt++, i++) {
            const YASN1_TEMPLATE *seqtt;
            seqtt = asn1_do_aadb(pval, tt, 1);
            if (seqtt == NULL)
                goto err;
            if (seqtt->flags & YASN1_TFLG_OPTIONAL) {
                YASN1_VALUE **pseqval;
                pseqval = asn1_get_ffield_ptr(pval, seqtt);
                YASN1_template_free(pseqval, seqtt);
            } else {
                errtt = seqtt;
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_FIELD_MISSING);
                goto err;
            }
        }
        /* Save encoding */
        if (!asn1_enc_ssave(pval, *in, p - *in, it))
            goto auxerr;
        if (asn1_cb && !asn1_cb(YASN1_OP_D2I_POST, pval, it, NULL))
            goto auxerr;
        *in = p;
        return 1;

    default:
        return 0;
    }
 auxerr:
    OPENSSL_PUT_ERROR(YASN1, YASN1_R_AUX_ERROR);
 err:
    if (combine == 0)
        YASN1_item_ex_free(pval, it);
    if (errtt)
        ERR_add_error_data(4, "Field=", errtt->field_name,
                           ", Type=", it->sname);
    else
        ERR_add_error_data(2, "Type=", it->sname);
    return 0;
}

/*
 * Templates are handled with two separate functions. One handles any
 * EXPLICIT tag and the other handles the rest.
 */

static int asn1_template_ex_d2i(YASN1_VALUE **val,
                                const unsigned char **in, long inlen,
                                const YASN1_TEMPLATE *tt, char opt,
                                YASN1_TLC *ctx)
{
    int flags, aclass;
    int ret;
    long len;
    const unsigned char *p, *q;
    char exp_eoc;
    if (!val)
        return 0;
    flags = tt->flags;
    aclass = flags & YASN1_TFLG_TAG_CLASS;

    p = *in;

    /* Check if EXPLICIT tag expected */
    if (flags & YASN1_TFLG_EXPTAG) {
        char cst;
        /*
         * Need to work out amount of data available to the inner content and
         * where it starts: so read in EXPLICIT header to get the info.
         */
        ret = asn1_check_tlen(&len, NULL, NULL, &exp_eoc, &cst,
                              &p, inlen, tt->tag, aclass, opt, ctx);
        q = p;
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            return 0;
        } else if (ret == -1)
            return -1;
        if (!cst) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED);
            return 0;
        }
        /* We've found the field so it can't be OPTIONAL now */
        ret = asn1_template_noexp_d2i(val, &p, len, tt, 0, ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            return 0;
        }
        /* We read the field in OK so update length */
        len -= p - q;
        if (exp_eoc) {
            /* If NDEF we must have an EOC here */
            if (!asn1_check_eoc(&p, len)) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_EOC);
                goto err;
            }
        } else {
            /*
             * Otherwise we must hit the EXPLICIT tag end or its an error
             */
            if (len) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_EXPLICIT_LENGTH_MISMATCH);
                goto err;
            }
        }
    } else
        return asn1_template_noexp_d2i(val, in, inlen, tt, opt, ctx);

    *in = p;
    return 1;

 err:
    YASN1_template_free(val, tt);
    return 0;
}

static int asn1_template_noexp_d2i(YASN1_VALUE **val,
                                   const unsigned char **in, long len,
                                   const YASN1_TEMPLATE *tt, char opt,
                                   YASN1_TLC *ctx)
{
    int flags, aclass;
    int ret;
    const unsigned char *p;
    if (!val)
        return 0;
    flags = tt->flags;
    aclass = flags & YASN1_TFLG_TAG_CLASS;

    p = *in;

    if (flags & YASN1_TFLG_SK_MASK) {
        /* SET OF, SEQUENCE OF */
        int sktag, skaclass;
        char sk_eoc;
        /* First work out expected inner tag value */
        if (flags & YASN1_TFLG_IMPTAG) {
            sktag = tt->tag;
            skaclass = aclass;
        } else {
            skaclass = V_YASN1_UNIVEYRSAL;
            if (flags & YASN1_TFLG_SET_OF)
                sktag = V_YASN1_SET;
            else
                sktag = V_YASN1_SEQUENCE;
        }
        /* Get the tag */
        ret = asn1_check_tlen(&len, NULL, NULL, &sk_eoc, NULL,
                              &p, len, sktag, skaclass, opt, ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            return 0;
        } else if (ret == -1)
            return -1;
        if (!*val)
            *val = (YASN1_VALUE *)sk_new_null();
        else {
            /*
             * We've got a valid STACK: free up any items present
             */
            STACK_OF(YASN1_VALUE) *sktmp = (STACK_OF(YASN1_VALUE) *)*val;
            YASN1_VALUE *vtmp;
            while (sk_YASN1_VALUE_num(sktmp) > 0) {
                vtmp = sk_YASN1_VALUE_pop(sktmp);
                YASN1_item_ex_free(&vtmp, YASN1_ITEM_ptr(tt->item));
            }
        }

        if (!*val) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Read as many items as we can */
        while (len > 0) {
            YASN1_VALUE *skfield;
            const unsigned char *q = p;
            /* See if EOC found */
            if (asn1_check_eoc(&p, len)) {
                if (!sk_eoc) {
                    OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNEXPECTED_EOC);
                    goto err;
                }
                len -= p - q;
                sk_eoc = 0;
                break;
            }
            skfield = NULL;
            if (!YASN1_item_ex_d2i(&skfield, &p, len,
                                  YASN1_ITEM_ptr(tt->item), -1, 0, 0, ctx)) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
                goto err;
            }
            len -= p - q;
            if (!sk_YASN1_VALUE_push((STACK_OF(YASN1_VALUE) *)*val, skfield)) {
                YASN1_item_ex_free(&skfield, YASN1_ITEM_ptr(tt->item));
                OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if (sk_eoc) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_EOC);
            goto err;
        }
    } else if (flags & YASN1_TFLG_IMPTAG) {
        /* IMPLICIT tagging */
        ret = YASN1_item_ex_d2i(val, &p, len,
                               YASN1_ITEM_ptr(tt->item), tt->tag, aclass, opt,
                               ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
    } else {
        /* Nothing special */
        ret = YASN1_item_ex_d2i(val, &p, len, YASN1_ITEM_ptr(tt->item),
                               -1, tt->flags & YASN1_TFLG_COMBINE, opt, ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
    }

    *in = p;
    return 1;

 err:
    YASN1_template_free(val, tt);
    return 0;
}

static int asn1_d2i_ex_primitive(YASN1_VALUE **pval,
                                 const unsigned char **in, long inlen,
                                 const YASN1_ITEM *it,
                                 int tag, int aclass, char opt, YASN1_TLC *ctx)
{
    int ret = 0, utype;
    long plen;
    char cst, inf, free_cont = 0;
    const unsigned char *p;
    BUF_MEM buf = {0, NULL, 0 };
    const unsigned char *cont = NULL;
    long len;
    if (!pval) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_NULL);
        return 0;               /* Should never happen */
    }

    if (it->itype == YASN1_ITYPE_MSTRING) {
        utype = tag;
        tag = -1;
    } else
        utype = it->utype;

    if (utype == V_YASN1_ANY) {
        /* If type is ANY need to figure out type from tag */
        unsigned char oclass;
        if (tag >= 0) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_TAGGED_ANY);
            return 0;
        }
        if (opt) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_OPTIONAL_ANY);
            return 0;
        }
        p = *in;
        ret = asn1_check_tlen(NULL, &utype, &oclass, NULL, NULL,
                              &p, inlen, -1, 0, 0, ctx);
        if (!ret) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            return 0;
        }
        if (oclass != V_YASN1_UNIVEYRSAL)
            utype = V_YASN1_OTHER;
    }
    if (tag == -1) {
        tag = utype;
        aclass = V_YASN1_UNIVEYRSAL;
    }
    p = *in;
    /* Check header */
    ret = asn1_check_tlen(&plen, NULL, NULL, &inf, &cst,
                          &p, inlen, tag, aclass, opt, ctx);
    if (!ret) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
        return 0;
    } else if (ret == -1)
        return -1;
    ret = 0;
    /* SEQUENCE, SET and "OTHER" are left in encoded form */
    if ((utype == V_YASN1_SEQUENCE)
        || (utype == V_YASN1_SET) || (utype == V_YASN1_OTHER)) {
        /*
         * Clear context cache for type OTHER because the auto clear when we
         * have a exact match wont work
         */
        if (utype == V_YASN1_OTHER) {
            asn1_tlc_clear(ctx);
        }
        /* SEQUENCE and SET must be constructed */
        else if (!cst) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_TYPE_NOT_CONSTRUCTED);
            return 0;
        }

        cont = *in;
        /* If indefinite length constructed find the real end */
        if (inf) {
            if (!asn1_find_end(&p, plen, inf))
                goto err;
            len = p - cont;
        } else {
            len = p - cont + plen;
            p += plen;
        }
    } else if (cst) {
        if (utype == V_YASN1_NULL || utype == V_YASN1_BOOLEAN
            || utype == V_YASN1_OBJECT || utype == V_YASN1_INTEGER
            || utype == V_YASN1_ENUMERATED) {
            /* These types only have primitive encodings. */
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_TYPE_NOT_PRIMITIVE);
            return 0;
        }

        /* Free any returned 'buf' content */
        free_cont = 1;
        /*
         * Should really check the internal tags are correct but some things
         * may get this wrong. The relevant specs say that constructed string
         * types should be OCTET STRINGs internally irrespective of the type.
         * So instead just check for UNIVEYRSAL class and ignore the tag.
         */
        if (!asn1_collect(&buf, &p, plen, inf, -1, V_YASN1_UNIVEYRSAL, 0)) {
            goto err;
        }
        len = buf.length;
        /* Append a final null to string */
        if (!BUF_MEM_grow_clean(&buf, len + 1)) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        buf.data[len] = 0;
        cont = (const unsigned char *)buf.data;
    } else {
        cont = p;
        len = plen;
        p += plen;
    }

    /* We now have content length and type: translate into a structure */
    /* asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 */
    if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))
        goto err;

    *in = p;
    ret = 1;
 err:
    if (free_cont && buf.data)
        OPENSSL_free(buf.data);
    return ret;
}

/* Translate YASN1 content octets into a structure */

int asn1_ex_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                int utype, char *free_cont, const YASN1_ITEM *it)
{
    YASN1_VALUE **opval = NULL;
    YASN1_STRING *stmp;
    YASN1_TYPE *typ = NULL;
    int ret = 0;
    const YASN1_PRIMITIVE_FUNCS *pf;
    YASN1_INTEGER **tint;
    pf = it->funcs;

    if (pf && pf->prim_c2i)
        return pf->prim_c2i(pval, cont, len, utype, free_cont, it);
    /* If ANY type clear type and set pointer to internal value */
    if (it->utype == V_YASN1_ANY) {
        if (!*pval) {
            typ = YASN1_TYPE_new();
            if (typ == NULL)
                goto err;
            *pval = (YASN1_VALUE *)typ;
        } else
            typ = (YASN1_TYPE *)*pval;

        if (utype != typ->type)
            YASN1_TYPE_set(typ, utype, NULL);
        opval = pval;
        pval = &typ->value.asn1_value;
    }
    switch (utype) {
    case V_YASN1_OBJECT:
        if (!c2i_YASN1_OBJECT((YASN1_OBJECT **)pval, &cont, len))
            goto err;
        break;

    case V_YASN1_NULL:
        if (len) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NULL_IS_WRONG_LENGTH);
            goto err;
        }
        *pval = (YASN1_VALUE *)1;
        break;

    case V_YASN1_BOOLEAN:
        if (len != 1) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_BOOLEAN_IS_WRONG_LENGTH);
            goto err;
        } else {
            YASN1_BOOLEAN *tbool;
            tbool = (YASN1_BOOLEAN *)pval;
            *tbool = *cont;
        }
        break;

    case V_YASN1_BIT_STRING:
        if (!c2i_YASN1_BIT_STRING((YASN1_BIT_STRING **)pval, &cont, len))
            goto err;
        break;

    case V_YASN1_INTEGER:
    case V_YASN1_ENUMERATED:
        tint = (YASN1_INTEGER **)pval;
        if (!c2i_YASN1_INTEGER(tint, &cont, len))
            goto err;
        /* Fixup type to match the expected form */
        (*tint)->type = utype | ((*tint)->type & V_YASN1_NEG);
        break;

    case V_YASN1_OCTET_STRING:
    case V_YASN1_NUMERICSTRING:
    case V_YASN1_PRINTABLESTRING:
    case V_YASN1_T61STRING:
    case V_YASN1_VIDEOTEXSTRING:
    case V_YASN1_IA5STRING:
    case V_YASN1_UTCTIME:
    case V_YASN1_GENERALIZEDTIME:
    case V_YASN1_GRAPHICSTRING:
    case V_YASN1_VISIBLESTRING:
    case V_YASN1_GENERALSTRING:
    case V_YASN1_UNIVEYRSALSTRING:
    case V_YASN1_BMPSTRING:
    case V_YASN1_UTF8STRING:
    case V_YASN1_OTHER:
    case V_YASN1_SET:
    case V_YASN1_SEQUENCE:
    default:
        if (utype == V_YASN1_BMPSTRING && (len & 1)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_BMPSTRING_IS_WRONG_LENGTH);
            goto err;
        }
        if (utype == V_YASN1_UNIVEYRSALSTRING && (len & 3)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNIVEYRSALSTRING_IS_WRONG_LENGTH);
            goto err;
        }
        /* All based on YASN1_STRING and handled the same */
        if (!*pval) {
            stmp = YASN1_STRING_type_new(utype);
            if (!stmp) {
                OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            *pval = (YASN1_VALUE *)stmp;
        } else {
            stmp = (YASN1_STRING *)*pval;
            stmp->type = utype;
        }
        /* If we've already allocated a buffer use it */
        if (*free_cont) {
            if (stmp->data)
                OPENSSL_free(stmp->data);
            stmp->data = (unsigned char *)cont; /* UGLY YCAST! RL */
            stmp->length = len;
            *free_cont = 0;
        } else {
            if (!YASN1_STRING_set(stmp, cont, len)) {
                OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
                YASN1_STRING_free(stmp);
                *pval = NULL;
                goto err;
            }
        }
        break;
    }
    /* If YASN1_ANY and NULL type fix up value */
    if (typ && (utype == V_YASN1_NULL))
        typ->value.ptr = NULL;

    ret = 1;
 err:
    if (!ret) {
        YASN1_TYPE_free(typ);
        if (opval)
            *opval = NULL;
    }
    return ret;
}

/*
 * This function finds the end of an YASN1 structure when passed its maximum
 * length, whether it is indefinite length and a pointer to the content. This
 * is more efficient than calling asn1_collect because it does not recurse on
 * each indefinite length header.
 */

static int asn1_find_end(const unsigned char **in, long len, char inf)
{
    int expected_eoc;
    long plen;
    const unsigned char *p = *in, *q;
    /* If not indefinite length constructed just add length */
    if (inf == 0) {
        *in += len;
        return 1;
    }
    expected_eoc = 1;
    /*
     * Indefinite length constructed form. Find the end when enough EOCs are
     * found. If more indefinite length constructed headers are encountered
     * increment the expected eoc count otherwise just skip to the end of the
     * data.
     */
    while (len > 0) {
        if (asn1_check_eoc(&p, len)) {
            expected_eoc--;
            if (expected_eoc == 0)
                break;
            len -= 2;
            continue;
        }
        q = p;
        /* Just read in a header: only care about the length */
        if (!asn1_check_tlen(&plen, NULL, NULL, &inf, NULL, &p, len,
                             -1, 0, 0, NULL)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            return 0;
        }
        if (inf)
            expected_eoc++;
        else
            p += plen;
        len -= p - q;
    }
    if (expected_eoc) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_EOC);
        return 0;
    }
    *in = p;
    return 1;
}

/*
 * This function collects the asn1 data from a constructred string type into
 * a buffer. The values of 'in' and 'len' should refer to the contents of the
 * constructed type and 'inf' should be set if it is indefinite length.
 */

#ifndef YASN1_MAX_STRING_NEST
/*
 * This determines how many levels of recursion are permitted in YASN1 string
 * types. If it is not limited stack overflows can occur. If set to zero no
 * recursion is allowed at all. Although zero should be adequate examples
 * exist that require a value of 1. So 5 should be more than enough.
 */
# define YASN1_MAX_STRING_NEST 5
#endif

static int asn1_collect(BUF_MEM *buf, const unsigned char **in, long len,
                        char inf, int tag, int aclass, int depth)
{
    const unsigned char *p, *q;
    long plen;
    char cst, ininf;
    p = *in;
    inf &= 1;
    /*
     * If no buffer and not indefinite length constructed just pass over the
     * encoded data
     */
    if (!buf && !inf) {
        *in += len;
        return 1;
    }
    while (len > 0) {
        q = p;
        /* Check for EOC */
        if (asn1_check_eoc(&p, len)) {
            /*
             * EOC is illegal outside indefinite length constructed form
             */
            if (!inf) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNEXPECTED_EOC);
                return 0;
            }
            inf = 0;
            break;
        }

        if (!asn1_check_tlen(&plen, NULL, NULL, &ininf, &cst, &p,
                             len, tag, aclass, 0, NULL)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_ERROR);
            return 0;
        }

        /* If indefinite length constructed update max length */
        if (cst) {
            if (depth >= YASN1_MAX_STRING_NEST) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_NESTED_YASN1_STRING);
                return 0;
            }
            if (!asn1_collect(buf, &p, plen, ininf, tag, aclass, depth + 1))
                return 0;
        } else if (plen && !collect_data(buf, &p, plen))
            return 0;
        len -= p - q;
    }
    if (inf) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_EOC);
        return 0;
    }
    *in = p;
    return 1;
}

static int collect_data(BUF_MEM *buf, const unsigned char **p, long plen)
{
    int len;
    if (buf) {
        len = buf->length;
        if (!BUF_MEM_grow_clean(buf, len + plen)) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        OPENSSL_memcpy(buf->data + len, *p, plen);
    }
    *p += plen;
    return 1;
}

/* Check for YASN1 EOC and swallow it if found */

static int asn1_check_eoc(const unsigned char **in, long len)
{
    const unsigned char *p;
    if (len < 2)
        return 0;
    p = *in;
    if (!p[0] && !p[1]) {
        *in += 2;
        return 1;
    }
    return 0;
}

/*
 * Check an YASN1 tag and length: a bit like YASN1_get_object but it sets the
 * length for indefinite length constructed form, we don't know the exact
 * length but we can set an upper bound to the amount of data available minus
 * the header length just read.
 */

static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
                           char *inf, char *cst,
                           const unsigned char **in, long len,
                           int exptag, int expclass, char opt, YASN1_TLC *ctx)
{
    int i;
    int ptag, pclass;
    long plen;
    const unsigned char *p, *q;
    p = *in;
    q = p;

    if (ctx && ctx->valid) {
        i = ctx->ret;
        plen = ctx->plen;
        pclass = ctx->pclass;
        ptag = ctx->ptag;
        p += ctx->hdrlen;
    } else {
        i = YASN1_get_object(&p, &plen, &ptag, &pclass, len);
        if (ctx) {
            ctx->ret = i;
            ctx->plen = plen;
            ctx->pclass = pclass;
            ctx->ptag = ptag;
            ctx->hdrlen = p - q;
            ctx->valid = 1;
            /*
             * If definite length, and no error, length + header can't exceed
             * total amount of data available.
             */
            if (!(i & 0x81) && ((plen + ctx->hdrlen) > len)) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_TOO_LONG);
                asn1_tlc_clear(ctx);
                return 0;
            }
        }
    }

    if (i & 0x80) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_BAD_OBJECT_HEADER);
        asn1_tlc_clear(ctx);
        return 0;
    }
    if (exptag >= 0) {
        if ((exptag != ptag) || (expclass != pclass)) {
            /*
             * If type is OPTIONAL, not an error: indicate missing type.
             */
            if (opt)
                return -1;
            asn1_tlc_clear(ctx);
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_WRONG_TAG);
            return 0;
        }
        /*
         * We have a tag and class match: assume we are going to do something
         * with it
         */
        asn1_tlc_clear(ctx);
    }

    if (i & 1)
        plen = len - (p - q);

    if (inf)
        *inf = i & 1;

    if (cst)
        *cst = i & V_YASN1_CONSTRUCTED;

    if (olen)
        *olen = plen;

    if (oclass)
        *oclass = pclass;

    if (otag)
        *otag = ptag;

    *in = p;
    return 1;
}
