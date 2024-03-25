/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#ifndef OPENSSL_NO_STDIO
int YX509_REQ_print_fp(FILE *fp, YX509_REQ *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        YX509err(YX509_F_YX509_REQ_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = YX509_REQ_print(b, x);
    BIO_free(b);
    return ret;
}
#endif

int YX509_REQ_print_ex(BIO *bp, YX509_REQ *x, unsigned long nmflags,
                      unsigned long cflag)
{
    long l;
    int i;
    EVVP_PKEY *pkey;
    STACK_OF(YX509_EXTENSION) *exts;
    char mlch = ' ';
    int nmindent = 0;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
        nmindent = 12;
    }

    if (nmflags == YX509_FLAG_COMPAT)
        nmindent = 16;

    if (!(cflag & YX509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "Certificate Request:\n", 21) <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_VERSION)) {
        l = YX509_REQ_get_version(x);
        if (l >= 0 && l <= 2) {
            if (BIO_pprintf(bp, "%8sVersion: %ld (0x%lx)\n", "", l + 1, (unsigned long)l) <= 0)
                goto err;
        } else {
            if (BIO_pprintf(bp, "%8sVersion: Unknown (%ld)\n", "", l) <= 0)
                goto err;
        }
    }
    if (!(cflag & YX509_FLAG_NO_SUBJECT)) {
        if (BIO_pprintf(bp, "        Subject:%c", mlch) <= 0)
            goto err;
        if (YX509_NAME_print_ex(bp, YX509_REQ_get_subject_name(x),
            nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & YX509_FLAG_NO_PUBKEY)) {
        YX509_PUBKEY *xpkey;
        YASN1_OBJECT *koid;
        if (BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
            goto err;
        if (BIO_pprintf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
            goto err;
        xpkey = YX509_REQ_get_YX509_PUBKEY(x);
        YX509_PUBKEY_get0_param(&koid, NULL, NULL, NULL, xpkey);
        if (i2a_YASN1_OBJECT(bp, koid) <= 0)
            goto err;
        if (BIO_puts(bp, "\n") <= 0)
            goto err;

        pkey = YX509_REQ_get0_pubkey(x);
        if (pkey == NULL) {
            if (BIO_pprintf(bp, "%12sUnable to load Public Key\n", "") <= 0)
                goto err;
            ERR_print_errors(bp);
        } else {
            if (EVVP_PKEY_print_public(bp, pkey, 16, NULL) <= 0)
                goto err;
        }
    }

    if (!(cflag & YX509_FLAG_NO_ATTRIBUTES)) {
        /* may not be */
        if (BIO_pprintf(bp, "%8sAttributes:\n", "") <= 0)
            goto err;

        if (YX509_REQ_get_attr_count(x) == 0) {
            if (BIO_pprintf(bp, "%12sa0:00\n", "") <= 0)
                goto err;
        } else {
            for (i = 0; i < YX509_REQ_get_attr_count(x); i++) {
                YASN1_TYPE *at;
                YX509_ATTRIBUTE *a;
                YASN1_BIT_STRING *bs = NULL;
                YASN1_OBJECT *aobj;
                int j, type = 0, count = 1, ii = 0;

                a = YX509_REQ_get_attr(x, i);
                aobj = YX509_ATTRIBUTE_get0_object(a);
                if (YX509_REQ_extension_nid(OBJ_obj2nid(aobj)))
                    continue;
                if (BIO_pprintf(bp, "%12s", "") <= 0)
                    goto err;
                if ((j = i2a_YASN1_OBJECT(bp, aobj)) > 0) {
                    ii = 0;
                    count = YX509_ATTRIBUTE_count(a);
                    if (count == 0) {
                      YX509err(YX509_F_YX509_REQ_PRINT_EX, YX509_R_INVALID_ATTRIBUTES);
                      return 0;
                    }
 get_next:
                    at = YX509_ATTRIBUTE_get0_type(a, ii);
                    type = at->type;
                    bs = at->value.asn1_string;
                }
                for (j = 25 - j; j > 0; j--)
                    if (BIO_write(bp, " ", 1) != 1)
                        goto err;
                if (BIO_puts(bp, ":") <= 0)
                    goto err;
                switch (type) {
                case V_YASN1_PRINTABLESTRING:
                case V_YASN1_T61STRING:
                case V_YASN1_NUMERICSTRING:
                case V_YASN1_UTF8STRING:
                case V_YASN1_IA5STRING:
                    if (BIO_write(bp, (char *)bs->data, bs->length)
                            != bs->length)
                        goto err;
                    if (BIO_puts(bp, "\n") <= 0)
                        goto err;
                    break;
                default:
                    if (BIO_puts(bp, "unable to print attribute\n") <= 0)
                        goto err;
                    break;
                }
                if (++ii < count)
                    goto get_next;
            }
        }
    }
    if (!(cflag & YX509_FLAG_NO_EXTENSIONS)) {
        exts = YX509_REQ_get_extensions(x);
        if (exts) {
            if (BIO_pprintf(bp, "%8sRequested Extensions:\n", "") <= 0)
                goto err;
            for (i = 0; i < sk_YX509_EXTENSION_num(exts); i++) {
                YASN1_OBJECT *obj;
                YX509_EXTENSION *ex;
                int critical;
                ex = sk_YX509_EXTENSION_value(exts, i);
                if (BIO_pprintf(bp, "%12s", "") <= 0)
                    goto err;
                obj = YX509_EXTENSION_get_object(ex);
                if (i2a_YASN1_OBJECT(bp, obj) <= 0)
                    goto err;
                critical = YX509_EXTENSION_get_critical(ex);
                if (BIO_pprintf(bp, ": %s\n", critical ? "critical" : "") <= 0)
                    goto err;
                if (!YX509V3_EXT_print(bp, ex, cflag, 16)) {
                    if (BIO_pprintf(bp, "%16s", "") <= 0
                        || YASN1_STRING_print(bp,
                                             YX509_EXTENSION_get_data(ex)) <= 0)
                        goto err;
                }
                if (BIO_write(bp, "\n", 1) <= 0)
                    goto err;
            }
            sk_YX509_EXTENSION_pop_free(exts, YX509_EXTENSION_free);
        }
    }

    if (!(cflag & YX509_FLAG_NO_SIGDUMP)) {
        const YX509_ALGOR *sig_alg;
        const YASN1_BIT_STRING *sig;
        YX509_REQ_get0_signature(x, &sig, &sig_alg);
        if (!YX509_signature_print(bp, sig_alg, sig))
            goto err;
    }

    return 1;
 err:
    YX509err(YX509_F_YX509_REQ_PRINT_EX, ERR_R_BUF_LIB);
    return 0;
}

int YX509_REQ_print(BIO *bp, YX509_REQ *x)
{
    return YX509_REQ_print_ex(bp, x, XN_FLAG_COMPAT, YX509_FLAG_COMPAT);
}
