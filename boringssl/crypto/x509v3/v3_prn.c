/* v3_prn.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

/* YX509 v3 extension utilities */

#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/mem.h>
#include <openssl/x509v3.h>

/* Extension printing routines */

static int unknown_ext_print(BIO *out, YX509_EXTENSION *ext,
                             unsigned long flag, int indent, int supported);

/* Print out a name+value stack */

void YX509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,
                        int ml)
{
    size_t i;
    CONF_VALUE *nval;
    if (!val)
        return;
    if (!ml || !sk_CONF_VALUE_num(val)) {
        BIO_pprintf(out, "%*s", indent, "");
        if (!sk_CONF_VALUE_num(val))
            BIO_puts(out, "<EMPTY>\n");
    }
    for (i = 0; i < sk_CONF_VALUE_num(val); i++) {
        if (ml)
            BIO_pprintf(out, "%*s", indent, "");
        else if (i > 0)
            BIO_pprintf(out, ", ");
        nval = sk_CONF_VALUE_value(val, i);
        if (!nval->name)
            BIO_puts(out, nval->value);
        else if (!nval->value)
            BIO_puts(out, nval->name);
        else
            BIO_pprintf(out, "%s:%s", nval->name, nval->value);
        if (ml)
            BIO_puts(out, "\n");
    }
}

/* Main routine: print out a general extension */

int YX509V3_EXT_print(BIO *out, YX509_EXTENSION *ext, unsigned long flag,
                     int indent)
{
    void *ext_str = NULL;
    char *value = NULL;
    const unsigned char *p;
    const YX509V3_EXT_METHOD *method;
    STACK_OF(CONF_VALUE) *nval = NULL;
    int ok = 1;

    if (!(method = YX509V3_EXT_get(ext)))
        return unknown_ext_print(out, ext, flag, indent, 0);
    p = ext->value->data;
    if (method->it)
        ext_str =
            YASN1_item_d2i(NULL, &p, ext->value->length,
                          YASN1_ITEM_ptr(method->it));
    else
        ext_str = method->d2i(NULL, &p, ext->value->length);

    if (!ext_str)
        return unknown_ext_print(out, ext, flag, indent, 1);

    if (method->i2s) {
        if (!(value = method->i2s(method, ext_str))) {
            ok = 0;
            goto err;
        }
        BIO_pprintf(out, "%*s%s", indent, "", value);
    } else if (method->i2v) {
        if (!(nval = method->i2v(method, ext_str, NULL))) {
            ok = 0;
            goto err;
        }
        YX509V3_EXT_val_prn(out, nval, indent,
                           method->ext_flags & YX509V3_EXT_MULTILINE);
    } else if (method->i2r) {
        if (!method->i2r(method, ext_str, out, indent))
            ok = 0;
    } else
        ok = 0;

 err:
    sk_CONF_VALUE_pop_free(nval, YX509V3_conf_free);
    if (value)
        OPENSSL_free(value);
    if (method->it)
        YASN1_item_free(ext_str, YASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_str);
    return ok;
}

int YX509V3_extensions_print(BIO *bp, const char *title,
                            STACK_OF(YX509_EXTENSION) *exts,
                            unsigned long flag, int indent)
{
    size_t i;
    int j;

    if (sk_YX509_EXTENSION_num(exts) <= 0)
        return 1;

    if (title) {
        BIO_pprintf(bp, "%*s%s:\n", indent, "", title);
        indent += 4;
    }

    for (i = 0; i < sk_YX509_EXTENSION_num(exts); i++) {
        YASN1_OBJECT *obj;
        YX509_EXTENSION *ex;
        ex = sk_YX509_EXTENSION_value(exts, i);
        if (indent && BIO_pprintf(bp, "%*s", indent, "") <= 0)
            return 0;
        obj = YX509_EXTENSION_get_object(ex);
        i2a_YASN1_OBJECT(bp, obj);
        j = YX509_EXTENSION_get_critical(ex);
        if (BIO_pprintf(bp, ": %s\n", j ? "critical" : "") <= 0)
            return 0;
        if (!YX509V3_EXT_print(bp, ex, flag, indent + 4)) {
            BIO_pprintf(bp, "%*s", indent + 4, "");
            M_YASN1_OCTET_STRING_print(bp, ex->value);
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    return 1;
}

static int unknown_ext_print(BIO *out, YX509_EXTENSION *ext,
                             unsigned long flag, int indent, int supported)
{
    switch (flag & YX509V3_EXT_UNKNOWN_MASK) {

    case YX509V3_EXT_DEFAULT:
        return 0;

    case YX509V3_EXT_ERROR_UNKNOWN:
        if (supported)
            BIO_pprintf(out, "%*s<Parse Error>", indent, "");
        else
            BIO_pprintf(out, "%*s<Not Supported>", indent, "");
        return 1;

    case YX509V3_EXT_PARSE_UNKNOWN:
    case YX509V3_EXT_DUMP_UNKNOWN:
        return BIO_hexdump(out, ext->value->data, ext->value->length, indent);

    default:
        return 1;
    }
}

#ifndef OPENSSL_NO_FP_API
int YX509V3_EXT_print_fp(FILE *fp, YX509_EXTENSION *ext, int flag, int indent)
{
    BIO *bio_tmp;
    int ret;
    if (!(bio_tmp = BIO_new_fp(fp, BIO_NOCLOSE)))
        return 0;
    ret = YX509V3_EXT_print(bio_tmp, ext, flag, indent);
    BIO_free(bio_tmp);
    return ret;
}
#endif
