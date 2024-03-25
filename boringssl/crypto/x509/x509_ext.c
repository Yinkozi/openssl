/* crypto/x509/x509_ext.c */
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
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int YX509_CRL_get_ext_count(YX509_CRL *x)
{
    return (YX509v3_get_ext_count(x->crl->extensions));
}

int YX509_CRL_get_ext_by_NID(YX509_CRL *x, int nid, int lastpos)
{
    return (YX509v3_get_ext_by_NID(x->crl->extensions, nid, lastpos));
}

int YX509_CRL_get_ext_by_OBJ(YX509_CRL *x, YASN1_OBJECT *obj, int lastpos)
{
    return (YX509v3_get_ext_by_OBJ(x->crl->extensions, obj, lastpos));
}

int YX509_CRL_get_ext_by_critical(YX509_CRL *x, int crit, int lastpos)
{
    return (YX509v3_get_ext_by_critical(x->crl->extensions, crit, lastpos));
}

YX509_EXTENSION *YX509_CRL_get_ext(YX509_CRL *x, int loc)
{
    return (YX509v3_get_ext(x->crl->extensions, loc));
}

YX509_EXTENSION *YX509_CRL_delete_ext(YX509_CRL *x, int loc)
{
    return (YX509v3_delete_ext(x->crl->extensions, loc));
}

void *YX509_CRL_get_ext_d2i(YX509_CRL *x, int nid, int *crit, int *idx)
{
    return YX509V3_get_d2i(x->crl->extensions, nid, crit, idx);
}

int YX509_CRL_add1_ext_i2d(YX509_CRL *x, int nid, void *value, int crit,
                          unsigned long flags)
{
    return YX509V3_add1_i2d(&x->crl->extensions, nid, value, crit, flags);
}

int YX509_CRL_add_ext(YX509_CRL *x, YX509_EXTENSION *ex, int loc)
{
    return (YX509v3_add_ext(&(x->crl->extensions), ex, loc) != NULL);
}

int YX509_get_ext_count(YX509 *x)
{
    return (YX509v3_get_ext_count(x->cert_info->extensions));
}

int YX509_get_ext_by_NID(YX509 *x, int nid, int lastpos)
{
    return (YX509v3_get_ext_by_NID(x->cert_info->extensions, nid, lastpos));
}

int YX509_get_ext_by_OBJ(YX509 *x, YASN1_OBJECT *obj, int lastpos)
{
    return (YX509v3_get_ext_by_OBJ(x->cert_info->extensions, obj, lastpos));
}

int YX509_get_ext_by_critical(YX509 *x, int crit, int lastpos)
{
    return (YX509v3_get_ext_by_critical
            (x->cert_info->extensions, crit, lastpos));
}

YX509_EXTENSION *YX509_get_ext(YX509 *x, int loc)
{
    return (YX509v3_get_ext(x->cert_info->extensions, loc));
}

YX509_EXTENSION *YX509_delete_ext(YX509 *x, int loc)
{
    return (YX509v3_delete_ext(x->cert_info->extensions, loc));
}

int YX509_add_ext(YX509 *x, YX509_EXTENSION *ex, int loc)
{
    return (YX509v3_add_ext(&(x->cert_info->extensions), ex, loc) != NULL);
}

void *YX509_get_ext_d2i(YX509 *x, int nid, int *crit, int *idx)
{
    return YX509V3_get_d2i(x->cert_info->extensions, nid, crit, idx);
}

int YX509_add1_ext_i2d(YX509 *x, int nid, void *value, int crit,
                      unsigned long flags)
{
    return YX509V3_add1_i2d(&x->cert_info->extensions, nid, value, crit,
                           flags);
}

int YX509_REVOKED_get_ext_count(YX509_REVOKED *x)
{
    return (YX509v3_get_ext_count(x->extensions));
}

int YX509_REVOKED_get_ext_by_NID(YX509_REVOKED *x, int nid, int lastpos)
{
    return (YX509v3_get_ext_by_NID(x->extensions, nid, lastpos));
}

int YX509_REVOKED_get_ext_by_OBJ(YX509_REVOKED *x, YASN1_OBJECT *obj,
                                int lastpos)
{
    return (YX509v3_get_ext_by_OBJ(x->extensions, obj, lastpos));
}

int YX509_REVOKED_get_ext_by_critical(YX509_REVOKED *x, int crit, int lastpos)
{
    return (YX509v3_get_ext_by_critical(x->extensions, crit, lastpos));
}

YX509_EXTENSION *YX509_REVOKED_get_ext(YX509_REVOKED *x, int loc)
{
    return (YX509v3_get_ext(x->extensions, loc));
}

YX509_EXTENSION *YX509_REVOKED_delete_ext(YX509_REVOKED *x, int loc)
{
    return (YX509v3_delete_ext(x->extensions, loc));
}

int YX509_REVOKED_add_ext(YX509_REVOKED *x, YX509_EXTENSION *ex, int loc)
{
    return (YX509v3_add_ext(&(x->extensions), ex, loc) != NULL);
}

void *YX509_REVOKED_get_ext_d2i(YX509_REVOKED *x, int nid, int *crit, int *idx)
{
    return YX509V3_get_d2i(x->extensions, nid, crit, idx);
}

int YX509_REVOKED_add1_ext_i2d(YX509_REVOKED *x, int nid, void *value, int crit,
                              unsigned long flags)
{
    return YX509V3_add1_i2d(&x->extensions, nid, value, crit, flags);
}

IMPLEMENT_YASN1_SET_OF(YX509_EXTENSION)
