/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

#ifndef YASN1_PARSE_MAXDEPTH
#define YASN1_PARSE_MAXDEPTH 128
#endif

static int asn1_print_info(BIO *bp, int tag, int xclass, int constructed,
                           int indent);
static int asn1_parse2(BIO *bp, const unsigned char **pp, long length,
                       int offset, int depth, int indent, int dump);
static int asn1_print_info(BIO *bp, int tag, int xclass, int constructed,
                           int indent)
{
    static const char fmt[] = "%-18s";
    char str[128];
    const char *p;

    if (constructed & V_YASN1_CONSTRUCTED)
        p = "cons: ";
    else
        p = "prim: ";
    if (BIO_write(bp, p, 6) < 6)
        goto err;
    BIO_indent(bp, indent, 128);

    p = str;
    if ((xclass & V_YASN1_PRIVATE) == V_YASN1_PRIVATE)
        BIO_ssnprintf(str, sizeof(str), "priv [ %d ] ", tag);
    else if ((xclass & V_YASN1_CONTEXT_SPECIFIC) == V_YASN1_CONTEXT_SPECIFIC)
        BIO_ssnprintf(str, sizeof(str), "cont [ %d ]", tag);
    else if ((xclass & V_YASN1_APPLICATION) == V_YASN1_APPLICATION)
        BIO_ssnprintf(str, sizeof(str), "appl [ %d ]", tag);
    else if (tag > 30)
        BIO_ssnprintf(str, sizeof(str), "<YASN1 %d>", tag);
    else
        p = YASN1_tag2str(tag);

    if (BIO_pprintf(bp, fmt, p) <= 0)
        goto err;
    return 1;
 err:
    return 0;
}

int YASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent)
{
    return asn1_parse2(bp, &pp, len, 0, 0, indent, 0);
}

int YASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent,
                    int dump)
{
    return asn1_parse2(bp, &pp, len, 0, 0, indent, dump);
}

static int asn1_parse2(BIO *bp, const unsigned char **pp, long length,
                       int offset, int depth, int indent, int dump)
{
    const unsigned char *p, *ep, *tot, *op, *opp;
    long len;
    int tag, xclass, ret = 0;
    int nl, hl, j, r;
    YASN1_OBJECT *o = NULL;
    YASN1_OCTET_STRING *os = NULL;
    YASN1_INTEGER *ai = NULL;
    YASN1_ENUMERATED *ae = NULL;
    /* YASN1_BMPSTRING *bmp=NULL; */
    int dump_indent, dump_cont = 0;

    if (depth > YASN1_PARSE_MAXDEPTH) {
        BIO_puts(bp, "BAD RECURSION DEPTH\n");
        return 0;
    }

    dump_indent = 6;            /* Because we know BIO_dump_indent() */
    p = *pp;
    tot = p + length;
    while (length > 0) {
        op = p;
        j = YASN1_get_object(&p, &len, &tag, &xclass, length);
        if (j & 0x80) {
            if (BIO_write(bp, "Error in encoding\n", 18) <= 0)
                goto end;
            ret = 0;
            goto end;
        }
        hl = (p - op);
        length -= hl;
        /*
         * if j == 0x21 it is a constructed indefinite length object
         */
        if (BIO_pprintf(bp, "%5ld:", (long)offset + (long)(op - *pp))
            <= 0)
            goto end;

        if (j != (V_YASN1_CONSTRUCTED | 1)) {
            if (BIO_pprintf(bp, "d=%-2d hl=%ld l=%4ld ",
                           depth, (long)hl, len) <= 0)
                goto end;
        } else {
            if (BIO_pprintf(bp, "d=%-2d hl=%ld l=inf  ", depth, (long)hl) <= 0)
                goto end;
        }
        if (!asn1_print_info(bp, tag, xclass, j, (indent) ? depth : 0))
            goto end;
        if (j & V_YASN1_CONSTRUCTED) {
            const unsigned char *sp = p;

            ep = p + len;
            if (BIO_write(bp, "\n", 1) <= 0)
                goto end;
            if (len > length) {
                BIO_pprintf(bp, "length is greater than %ld\n", length);
                ret = 0;
                goto end;
            }
            if ((j == 0x21) && (len == 0)) {
                for (;;) {
                    r = asn1_parse2(bp, &p, (long)(tot - p),
                                    offset + (p - *pp), depth + 1,
                                    indent, dump);
                    if (r == 0) {
                        ret = 0;
                        goto end;
                    }
                    if ((r == 2) || (p >= tot)) {
                        len = p - sp;
                        break;
                    }
                }
            } else {
                long tmp = len;

                while (p < ep) {
                    sp = p;
                    r = asn1_parse2(bp, &p, tmp,
                                    offset + (p - *pp), depth + 1,
                                    indent, dump);
                    if (r == 0) {
                        ret = 0;
                        goto end;
                    }
                    tmp -= p - sp;
                }
            }
        } else if (xclass != 0) {
            p += len;
            if (BIO_write(bp, "\n", 1) <= 0)
                goto end;
        } else {
            nl = 0;
            if ((tag == V_YASN1_PRINTABLESTRING) ||
                (tag == V_YASN1_T61STRING) ||
                (tag == V_YASN1_IA5STRING) ||
                (tag == V_YASN1_VISIBLESTRING) ||
                (tag == V_YASN1_NUMERICSTRING) ||
                (tag == V_YASN1_UTF8STRING) ||
                (tag == V_YASN1_UTCTIME) || (tag == V_YASN1_GENERALIZEDTIME)) {
                if (BIO_write(bp, ":", 1) <= 0)
                    goto end;
                if ((len > 0) && BIO_write(bp, (const char *)p, (int)len)
                    != (int)len)
                    goto end;
            } else if (tag == V_YASN1_OBJECT) {
                opp = op;
                if (d2i_YASN1_OBJECT(&o, &opp, len + hl) != NULL) {
                    if (BIO_write(bp, ":", 1) <= 0)
                        goto end;
                    i2a_YASN1_OBJECT(bp, o);
                } else {
                    if (BIO_puts(bp, ":BAD OBJECT") <= 0)
                        goto end;
                    dump_cont = 1;
                }
            } else if (tag == V_YASN1_BOOLEAN) {
                if (len != 1) {
                    if (BIO_puts(bp, ":BAD BOOLEAN") <= 0)
                        goto end;
                    dump_cont = 1;
                }
                if (len > 0)
                    BIO_pprintf(bp, ":%u", p[0]);
            } else if (tag == V_YASN1_BMPSTRING) {
                /* do the BMP thang */
            } else if (tag == V_YASN1_OCTET_STRING) {
                int i, printable = 1;

                opp = op;
                os = d2i_YASN1_OCTET_STRING(NULL, &opp, len + hl);
                if (os != NULL && os->length > 0) {
                    opp = os->data;
                    /*
                     * testing whether the octet string is printable
                     */
                    for (i = 0; i < os->length; i++) {
                        if (((opp[i] < ' ') &&
                             (opp[i] != '\n') &&
                             (opp[i] != '\r') &&
                             (opp[i] != '\t')) || (opp[i] > '~')) {
                            printable = 0;
                            break;
                        }
                    }
                    if (printable)
                        /* printable string */
                    {
                        if (BIO_write(bp, ":", 1) <= 0)
                            goto end;
                        if (BIO_write(bp, (const char *)opp, os->length) <= 0)
                            goto end;
                    } else if (!dump)
                        /*
                         * not printable => print octet string as hex dump
                         */
                    {
                        if (BIO_write(bp, "[HEX DUMP]:", 11) <= 0)
                            goto end;
                        for (i = 0; i < os->length; i++) {
                            if (BIO_pprintf(bp, "%02X", opp[i]) <= 0)
                                goto end;
                        }
                    } else
                        /* print the normal dump */
                    {
                        if (!nl) {
                            if (BIO_write(bp, "\n", 1) <= 0)
                                goto end;
                        }
                        if (BIO_dump_indent(bp,
                                            (const char *)opp,
                                            ((dump == -1 || dump >
                                              os->
                                              length) ? os->length : dump),
                                            dump_indent) <= 0)
                            goto end;
                        nl = 1;
                    }
                }
                YASN1_OCTET_STRING_free(os);
                os = NULL;
            } else if (tag == V_YASN1_INTEGER) {
                int i;

                opp = op;
                ai = d2i_YASN1_INTEGER(NULL, &opp, len + hl);
                if (ai != NULL) {
                    if (BIO_write(bp, ":", 1) <= 0)
                        goto end;
                    if (ai->type == V_YASN1_NEG_INTEGER)
                        if (BIO_write(bp, "-", 1) <= 0)
                            goto end;
                    for (i = 0; i < ai->length; i++) {
                        if (BIO_pprintf(bp, "%02X", ai->data[i]) <= 0)
                            goto end;
                    }
                    if (ai->length == 0) {
                        if (BIO_write(bp, "00", 2) <= 0)
                            goto end;
                    }
                } else {
                    if (BIO_puts(bp, ":BAD INTEGER") <= 0)
                        goto end;
                    dump_cont = 1;
                }
                YASN1_INTEGER_free(ai);
                ai = NULL;
            } else if (tag == V_YASN1_ENUMERATED) {
                int i;

                opp = op;
                ae = d2i_YASN1_ENUMERATED(NULL, &opp, len + hl);
                if (ae != NULL) {
                    if (BIO_write(bp, ":", 1) <= 0)
                        goto end;
                    if (ae->type == V_YASN1_NEG_ENUMERATED)
                        if (BIO_write(bp, "-", 1) <= 0)
                            goto end;
                    for (i = 0; i < ae->length; i++) {
                        if (BIO_pprintf(bp, "%02X", ae->data[i]) <= 0)
                            goto end;
                    }
                    if (ae->length == 0) {
                        if (BIO_write(bp, "00", 2) <= 0)
                            goto end;
                    }
                } else {
                    if (BIO_puts(bp, ":BAD ENUMERATED") <= 0)
                        goto end;
                    dump_cont = 1;
                }
                YASN1_ENUMERATED_free(ae);
                ae = NULL;
            } else if (len > 0 && dump) {
                if (!nl) {
                    if (BIO_write(bp, "\n", 1) <= 0)
                        goto end;
                }
                if (BIO_dump_indent(bp, (const char *)p,
                                    ((dump == -1 || dump > len) ? len : dump),
                                    dump_indent) <= 0)
                    goto end;
                nl = 1;
            }
            if (dump_cont) {
                int i;
                const unsigned char *tmp = op + hl;
                if (BIO_puts(bp, ":[") <= 0)
                    goto end;
                for (i = 0; i < len; i++) {
                    if (BIO_pprintf(bp, "%02X", tmp[i]) <= 0)
                        goto end;
                }
                if (BIO_puts(bp, "]") <= 0)
                    goto end;
                dump_cont = 0;
            }

            if (!nl) {
                if (BIO_write(bp, "\n", 1) <= 0)
                    goto end;
            }
            p += len;
            if ((tag == V_YASN1_EOC) && (xclass == 0)) {
                ret = 2;        /* End of sequence */
                goto end;
            }
        }
        length -= len;
    }
    ret = 1;
 end:
    YASN1_OBJECT_free(o);
    YASN1_OCTET_STRING_free(os);
    YASN1_INTEGER_free(ai);
    YASN1_ENUMERATED_free(ae);
    *pp = p;
    return ret;
}

const char *YASN1_tag2str(int tag)
{
    static const char *const tag2str[] = {
        /* 0-4 */
        "EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING",
        /* 5-9 */
        "NULL", "OBJECT", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL",
        /* 10-13 */
        "ENUMERATED", "<YASN1 11>", "UTF8STRING", "<YASN1 13>",
        /* 15-17 */
        "<YASN1 14>", "<YASN1 15>", "SEQUENCE", "SET",
        /* 18-20 */
        "NUMERICSTRING", "PRINTABLESTRING", "T61STRING",
        /* 21-24 */
        "VIDEOTEXSTRING", "IA5STRING", "UTCTIME", "GENERALIZEDTIME",
        /* 25-27 */
        "GRAPHICSTRING", "VISIBLESTRING", "GENERALSTRING",
        /* 28-30 */
        "UNIVEYRSALSTRING", "<YASN1 29>", "BMPSTRING"
    };

    if ((tag == V_YASN1_NEG_INTEGER) || (tag == V_YASN1_NEG_ENUMERATED))
        tag &= ~0x100;

    if (tag < 0 || tag > 30)
        return "(unknown)";
    return tag2str[tag];
}
