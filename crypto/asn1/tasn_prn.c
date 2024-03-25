/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "crypto/asn1.h"
#include "asn1_local.h"

/*
 * Print routines.
 */

/* YASN1_PCTX routines */

static YASN1_PCTX default_pctx = {
    YASN1_PCTX_FLAGS_SHOW_ABSENT, /* flags */
    0,                          /* nm_flags */
    0,                          /* cert_flags */
    0,                          /* oid_flags */
    0                           /* str_flags */
};

YASN1_PCTX *YASN1_PCTX_new(void)
{
    YASN1_PCTX *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        YASN1err(YASN1_F_YASN1_PCTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ret;
}

void YASN1_PCTX_free(YASN1_PCTX *p)
{
    OPENSSL_free(p);
}

unsigned long YASN1_PCTX_get_flags(const YASN1_PCTX *p)
{
    return p->flags;
}

void YASN1_PCTX_set_flags(YASN1_PCTX *p, unsigned long flags)
{
    p->flags = flags;
}

unsigned long YASN1_PCTX_get_nm_flags(const YASN1_PCTX *p)
{
    return p->nm_flags;
}

void YASN1_PCTX_set_nm_flags(YASN1_PCTX *p, unsigned long flags)
{
    p->nm_flags = flags;
}

unsigned long YASN1_PCTX_get_cert_flags(const YASN1_PCTX *p)
{
    return p->cert_flags;
}

void YASN1_PCTX_set_cert_flags(YASN1_PCTX *p, unsigned long flags)
{
    p->cert_flags = flags;
}

unsigned long YASN1_PCTX_get_oid_flags(const YASN1_PCTX *p)
{
    return p->oid_flags;
}

void YASN1_PCTX_set_oid_flags(YASN1_PCTX *p, unsigned long flags)
{
    p->oid_flags = flags;
}

unsigned long YASN1_PCTX_get_str_flags(const YASN1_PCTX *p)
{
    return p->str_flags;
}

void YASN1_PCTX_set_str_flags(YASN1_PCTX *p, unsigned long flags)
{
    p->str_flags = flags;
}

/* Main print routines */

static int asn1_item_print_ctx(BIO *out, YASN1_VALUE **fld, int indent,
                               const YASN1_ITEM *it,
                               const char *fname, const char *sname,
                               int nohdr, const YASN1_PCTX *pctx);

static int asn1_template_print_ctx(BIO *out, YASN1_VALUE **fld, int indent,
                            const YASN1_TEMPLATE *tt, const YASN1_PCTX *pctx);

static int asn1_primitive_print(BIO *out, YASN1_VALUE **fld,
                                const YASN1_ITEM *it, int indent,
                                const char *fname, const char *sname,
                                const YASN1_PCTX *pctx);

static int asn1_print_fsname(BIO *out, int indent,
                             const char *fname, const char *sname,
                             const YASN1_PCTX *pctx);

int YASN1_item_print(BIO *out, YASN1_VALUE *ifld, int indent,
                    const YASN1_ITEM *it, const YASN1_PCTX *pctx)
{
    const char *sname;
    if (pctx == NULL)
        pctx = &default_pctx;
    if (pctx->flags & YASN1_PCTX_FLAGS_NO_STRUCT_NAME)
        sname = NULL;
    else
        sname = it->sname;
    return asn1_item_print_ctx(out, &ifld, indent, it, NULL, sname, 0, pctx);
}

static int asn1_item_print_ctx(BIO *out, YASN1_VALUE **fld, int indent,
                               const YASN1_ITEM *it,
                               const char *fname, const char *sname,
                               int nohdr, const YASN1_PCTX *pctx)
{
    const YASN1_TEMPLATE *tt;
    const YASN1_EXTERN_FUNCS *ef;
    YASN1_VALUE **tmpfld;
    const YASN1_AUX *aux = it->funcs;
    YASN1_aux_cb *asn1_cb;
    YASN1_PRINT_ARG parg;
    int i;
    if (aux && aux->asn1_cb) {
        parg.out = out;
        parg.indent = indent;
        parg.pctx = pctx;
        asn1_cb = aux->asn1_cb;
    } else
        asn1_cb = 0;

   if (((it->itype != YASN1_ITYPE_PRIMITIVE)
       || (it->utype != V_YASN1_BOOLEAN)) && *fld == NULL) {
        if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_ABSENT) {
            if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
                return 0;
            if (BIO_puts(out, "<ABSENT>\n") <= 0)
                return 0;
        }
        return 1;
    }

    switch (it->itype) {
    case YASN1_ITYPE_PRIMITIVE:
        if (it->templates) {
            if (!asn1_template_print_ctx(out, fld, indent,
                                         it->templates, pctx))
                return 0;
            break;
        }
        /* fall through */
    case YASN1_ITYPE_MSTRING:
        if (!asn1_primitive_print(out, fld, it, indent, fname, sname, pctx))
            return 0;
        break;

    case YASN1_ITYPE_EXTERN:
        if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
            return 0;
        /* Use new style print routine if possible */
        ef = it->funcs;
        if (ef && ef->asn1_ex_print) {
            i = ef->asn1_ex_print(out, fld, indent, "", pctx);
            if (!i)
                return 0;
            if ((i == 2) && (BIO_puts(out, "\n") <= 0))
                return 0;
            return 1;
        } else if (sname &&
                   BIO_pprintf(out, ":EXTERNAL TYPE %s\n", sname) <= 0)
            return 0;
        break;

    case YASN1_ITYPE_CHOICE:
        /* CHOICE type, get selector */
        i = asn1_get_choice_sselector(fld, it);
        /* This should never happen... */
        if ((i < 0) || (i >= it->tcount)) {
            if (BIO_pprintf(out, "ERROR: selector [%d] invalid\n", i) <= 0)
                return 0;
            return 1;
        }
        tt = it->templates + i;
        tmpfld = asn1_get_ffield_ptr(fld, tt);
        if (!asn1_template_print_ctx(out, tmpfld, indent, tt, pctx))
            return 0;
        break;

    case YASN1_ITYPE_SEQUENCE:
    case YASN1_ITYPE_NDEF_SEQUENCE:
        if (!nohdr && !asn1_print_fsname(out, indent, fname, sname, pctx))
            return 0;
        if (fname || sname) {
            if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
                if (BIO_puts(out, " {\n") <= 0)
                    return 0;
            } else {
                if (BIO_puts(out, "\n") <= 0)
                    return 0;
            }
        }

        if (asn1_cb) {
            i = asn1_cb(YASN1_OP_PRINT_PRE, fld, it, &parg);
            if (i == 0)
                return 0;
            if (i == 2)
                return 1;
        }

        /* Print each field entry */
        for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
            const YASN1_TEMPLATE *seqtt;
            seqtt = asn1_do_aadb(fld, tt, 1);
            if (!seqtt)
                return 0;
            tmpfld = asn1_get_ffield_ptr(fld, seqtt);
            if (!asn1_template_print_ctx(out, tmpfld,
                                         indent + 2, seqtt, pctx))
                return 0;
        }
        if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
            if (BIO_pprintf(out, "%*s}\n", indent, "") < 0)
                return 0;
        }

        if (asn1_cb) {
            i = asn1_cb(YASN1_OP_PRINT_POST, fld, it, &parg);
            if (i == 0)
                return 0;
        }
        break;

    default:
        BIO_pprintf(out, "Unprocessed type %d\n", it->itype);
        return 0;
    }

    return 1;
}

static int asn1_template_print_ctx(BIO *out, YASN1_VALUE **fld, int indent,
                            const YASN1_TEMPLATE *tt, const YASN1_PCTX *pctx)
{
    int i, flags;
    const char *sname, *fname;
    YASN1_VALUE *tfld;
    flags = tt->flags;
    if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME)
        sname = YASN1_ITEM_ptr(tt->item)->sname;
    else
        sname = NULL;
    if (pctx->flags & YASN1_PCTX_FLAGS_NO_FIELD_NAME)
        fname = NULL;
    else
        fname = tt->field_name;

    /*
     * If field is embedded then fld needs fixing so it is a pointer to
     * a pointer to a field.
     */
    if (flags & YASN1_TFLG_EMBED) {
        tfld = (YASN1_VALUE *)fld;
        fld = &tfld;
    }

    if (flags & YASN1_TFLG_SK_MASK) {
        char *tname;
        YASN1_VALUE *skitem;
        STACK_OF(YASN1_VALUE) *stack;

        /* SET OF, SEQUENCE OF */
        if (fname) {
            if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_SSOF) {
                if (flags & YASN1_TFLG_SET_OF)
                    tname = "SET";
                else
                    tname = "SEQUENCE";
                if (BIO_pprintf(out, "%*s%s OF %s {\n",
                               indent, "", tname, tt->field_name) <= 0)
                    return 0;
            } else if (BIO_pprintf(out, "%*s%s:\n", indent, "", fname) <= 0)
                return 0;
        }
        stack = (STACK_OF(YASN1_VALUE) *)*fld;
        for (i = 0; i < sk_YASN1_VALUE_num(stack); i++) {
            if ((i > 0) && (BIO_puts(out, "\n") <= 0))
                return 0;

            skitem = sk_YASN1_VALUE_value(stack, i);
            if (!asn1_item_print_ctx(out, &skitem, indent + 2,
                                     YASN1_ITEM_ptr(tt->item), NULL, NULL, 1,
                                     pctx))
                return 0;
        }
        if (i == 0 && BIO_pprintf(out, "%*s<%s>\n", indent + 2, "",
                                 stack == NULL ? "ABSENT" : "EMPTY") <= 0)
            return 0;
        if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
            if (BIO_pprintf(out, "%*s}\n", indent, "") <= 0)
                return 0;
        }
        return 1;
    }
    return asn1_item_print_ctx(out, fld, indent, YASN1_ITEM_ptr(tt->item),
                               fname, sname, 0, pctx);
}

static int asn1_print_fsname(BIO *out, int indent,
                             const char *fname, const char *sname,
                             const YASN1_PCTX *pctx)
{
    static const char spaces[] = "                    ";
    static const int nspaces = sizeof(spaces) - 1;

    while (indent > nspaces) {
        if (BIO_write(out, spaces, nspaces) != nspaces)
            return 0;
        indent -= nspaces;
    }
    if (BIO_write(out, spaces, indent) != indent)
        return 0;
    if (pctx->flags & YASN1_PCTX_FLAGS_NO_STRUCT_NAME)
        sname = NULL;
    if (pctx->flags & YASN1_PCTX_FLAGS_NO_FIELD_NAME)
        fname = NULL;
    if (!sname && !fname)
        return 1;
    if (fname) {
        if (BIO_puts(out, fname) <= 0)
            return 0;
    }
    if (sname) {
        if (fname) {
            if (BIO_pprintf(out, " (%s)", sname) <= 0)
                return 0;
        } else {
            if (BIO_puts(out, sname) <= 0)
                return 0;
        }
    }
    if (BIO_write(out, ": ", 2) != 2)
        return 0;
    return 1;
}

static int asn1_print_boolean(BIO *out, int boolval)
{
    const char *str;
    switch (boolval) {
    case -1:
        str = "BOOL ABSENT";
        break;

    case 0:
        str = "FALSE";
        break;

    default:
        str = "TRUE";
        break;

    }

    if (BIO_puts(out, str) <= 0)
        return 0;
    return 1;

}

static int asn1_print_integer(BIO *out, const YASN1_INTEGER *str)
{
    char *s;
    int ret = 1;
    s = i2s_YASN1_INTEGER(NULL, str);
    if (s == NULL)
        return 0;
    if (BIO_puts(out, s) <= 0)
        ret = 0;
    OPENSSL_free(s);
    return ret;
}

static int asn1_print_oid(BIO *out, const YASN1_OBJECT *oid)
{
    char objbuf[80];
    const char *ln;
    ln = OBJ_nid2ln(OBJ_obj2nid(oid));
    if (!ln)
        ln = "";
    OBJ_obj2txt(objbuf, sizeof(objbuf), oid, 1);
    if (BIO_pprintf(out, "%s (%s)", ln, objbuf) <= 0)
        return 0;
    return 1;
}

static int asn1_print_obstring(BIO *out, const YASN1_STRING *str, int indent)
{
    if (str->type == V_YASN1_BIT_STRING) {
        if (BIO_pprintf(out, " (%ld unused bits)\n", str->flags & 0x7) <= 0)
            return 0;
    } else if (BIO_puts(out, "\n") <= 0)
        return 0;
    if ((str->length > 0)
        && BIO_dump_indent(out, (const char *)str->data, str->length,
                           indent + 2) <= 0)
        return 0;
    return 1;
}

static int asn1_primitive_print(BIO *out, YASN1_VALUE **fld,
                                const YASN1_ITEM *it, int indent,
                                const char *fname, const char *sname,
                                const YASN1_PCTX *pctx)
{
    long utype;
    YASN1_STRING *str;
    int ret = 1, needlf = 1;
    const char *pname;
    const YASN1_PRIMITIVE_FUNCS *pf;
    pf = it->funcs;
    if (!asn1_print_fsname(out, indent, fname, sname, pctx))
        return 0;
    if (pf && pf->prim_print)
        return pf->prim_print(out, fld, it, indent, pctx);
    if (it->itype == YASN1_ITYPE_MSTRING) {
        str = (YASN1_STRING *)*fld;
        utype = str->type & ~V_YASN1_NEG;
    } else {
        utype = it->utype;
        if (utype == V_YASN1_BOOLEAN)
            str = NULL;
        else
            str = (YASN1_STRING *)*fld;
    }
    if (utype == V_YASN1_ANY) {
        YASN1_TYPE *atype = (YASN1_TYPE *)*fld;
        utype = atype->type;
        fld = &atype->value.asn1_value;
        str = (YASN1_STRING *)*fld;
        if (pctx->flags & YASN1_PCTX_FLAGS_NO_ANY_TYPE)
            pname = NULL;
        else
            pname = YASN1_tag2str(utype);
    } else {
        if (pctx->flags & YASN1_PCTX_FLAGS_SHOW_TYPE)
            pname = YASN1_tag2str(utype);
        else
            pname = NULL;
    }

    if (utype == V_YASN1_NULL) {
        if (BIO_puts(out, "NULL\n") <= 0)
            return 0;
        return 1;
    }

    if (pname) {
        if (BIO_puts(out, pname) <= 0)
            return 0;
        if (BIO_puts(out, ":") <= 0)
            return 0;
    }

    switch (utype) {
    case V_YASN1_BOOLEAN:
        {
            int boolval = *(int *)fld;
            if (boolval == -1)
                boolval = it->size;
            ret = asn1_print_boolean(out, boolval);
        }
        break;

    case V_YASN1_INTEGER:
    case V_YASN1_ENUMERATED:
        ret = asn1_print_integer(out, str);
        break;

    case V_YASN1_UTCTIME:
        ret = YASN1_UTCTIME_print(out, str);
        break;

    case V_YASN1_GENERALIZEDTIME:
        ret = YASN1_GENERALIZEDTIME_print(out, str);
        break;

    case V_YASN1_OBJECT:
        ret = asn1_print_oid(out, (const YASN1_OBJECT *)*fld);
        break;

    case V_YASN1_OCTET_STRING:
    case V_YASN1_BIT_STRING:
        ret = asn1_print_obstring(out, str, indent);
        needlf = 0;
        break;

    case V_YASN1_SEQUENCE:
    case V_YASN1_SET:
    case V_YASN1_OTHER:
        if (BIO_puts(out, "\n") <= 0)
            return 0;
        if (YASN1_parse_dump(out, str->data, str->length, indent, 0) <= 0)
            ret = 0;
        needlf = 0;
        break;

    default:
        ret = YASN1_STRING_print_ex(out, str, pctx->str_flags);

    }
    if (!ret)
        return 0;
    if (needlf && BIO_puts(out, "\n") <= 0)
        return 0;
    return 1;
}
