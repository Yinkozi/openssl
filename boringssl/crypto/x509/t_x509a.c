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
#include <openssl/bio.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509.h>

/* YX509_CERT_AUX and string set routines */

int YX509_CERT_AUX_print(BIO *out, YX509_CERT_AUX *aux, int indent)
{
    char oidstr[80], first;
    size_t i;
    int j;
    if (!aux)
        return 1;
    if (aux->trust) {
        first = 1;
        BIO_pprintf(out, "%*sTrusted Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_YASN1_OBJECT_num(aux->trust); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof oidstr,
                        sk_YASN1_OBJECT_value(aux->trust, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_pprintf(out, "%*sNo Trusted Uses.\n", indent, "");
    if (aux->reject) {
        first = 1;
        BIO_pprintf(out, "%*sRejected Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_YASN1_OBJECT_num(aux->reject); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof oidstr,
                        sk_YASN1_OBJECT_value(aux->reject, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_pprintf(out, "%*sNo Rejected Uses.\n", indent, "");
    if (aux->alias)
        BIO_pprintf(out, "%*sAlias: %s\n", indent, "", aux->alias->data);
    if (aux->keyid) {
        BIO_pprintf(out, "%*sKey Id: ", indent, "");
        for (j = 0; j < aux->keyid->length; j++)
            BIO_pprintf(out, "%s%02X", j ? ":" : "", aux->keyid->data[j]);
        BIO_write(out, "\n", 1);
    }
    return 1;
}