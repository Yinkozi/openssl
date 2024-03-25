/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
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

/* Extension printing routines */

static int unknown_ext_print(BIO *out, const unsigned char *ext, int extlen,
                             unsigned long flag, int indent, int supported);

/* Print out a name+value stack */

void YX509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,
                        int ml)
{
    int i;
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
#ifndef CHARSET_EBCDIC
        else
            BIO_pprintf(out, "%s:%s", nval->name, nval->value);
#else
        else {
            int len;
            char *tmp;
            len = strlen(nval->value) + 1;
            tmp = OPENSSL_malloc(len);
            if (tmp != NULL) {
                ascii2ebcdic(tmp, nval->value, len);
                BIO_pprintf(out, "%s:%s", nval->name, tmp);
                OPENSSL_free(tmp);
            }
        }
#endif
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
    YASN1_OCTET_STRING *extoct;
    const unsigned char *p;
    int extlen;
    const YX509V3_EXT_METHOD *method;
    STACK_OF(CONF_VALUE) *nval = NULL;
    int ok = 1;

    extoct = YX509_EXTENSION_get_data(ext);
    p = YASN1_STRING_get0_data(extoct);
    extlen = YASN1_STRING_length(extoct);

    if ((method = YX509V3_EXT_get(ext)) == NULL)
        return unknown_ext_print(out, p, extlen, flag, indent, 0);
    if (method->it)
        ext_str = YASN1_item_d2i(NULL, &p, extlen, YASN1_ITEM_ptr(method->it));
    else
        ext_str = method->d2i(NULL, &p, extlen);

    if (!ext_str)
        return unknown_ext_print(out, p, extlen, flag, indent, 1);

    if (method->i2s) {
        if ((value = method->i2s(method, ext_str)) == NULL) {
            ok = 0;
            goto err;
        }
#ifndef CHARSET_EBCDIC
        BIO_pprintf(out, "%*s%s", indent, "", value);
#else
        {
            int len;
            char *tmp;
            len = strlen(value) + 1;
            tmp = OPENSSL_malloc(len);
            if (tmp != NULL) {
                ascii2ebcdic(tmp, value, len);
                BIO_pprintf(out, "%*s%s", indent, "", tmp);
                OPENSSL_free(tmp);
            }
        }
#endif
    } else if (method->i2v) {
        if ((nval = method->i2v(method, ext_str, NULL)) == NULL) {
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
    OPENSSL_free(value);
    if (method->it)
        YASN1_item_free(ext_str, YASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_str);
    return ok;
}

int YX509V3_extensions_print(BIO *bp, const char *title,
                            const STACK_OF(YX509_EXTENSION) *exts,
                            unsigned long flag, int indent)
{
    int i, j;

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
            YASN1_STRING_print(bp, YX509_EXTENSION_get_data(ex));
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    return 1;
}

static int unknown_ext_print(BIO *out, const unsigned char *ext, int extlen,
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
        return YASN1_parse_dump(out, ext, extlen, indent, -1);
    case YX509V3_EXT_DUMP_UNKNOWN:
        return BIO_dump_indent(out, (const char *)ext, extlen, indent);

    default:
        return 1;
    }
}

#ifndef OPENSSL_NO_STDIO
int YX509V3_EXT_print_fp(FILE *fp, YX509_EXTENSION *ext, int flag, int indent)
{
    BIO *bio_tmp;
    int ret;

    if ((bio_tmp = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL)
        return 0;
    ret = YX509V3_EXT_print(bio_tmp, ext, flag, indent);
    BIO_free(bio_tmp);
    return ret;
}
#endif
