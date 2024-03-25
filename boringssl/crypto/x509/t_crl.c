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
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_FP_API
int YX509_CRL_print_fp(FILE *fp, YX509_CRL *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = YX509_CRL_print(b, x);
    BIO_free(b);
    return (ret);
}
#endif

int YX509_CRL_print(BIO *out, YX509_CRL *x)
{
    STACK_OF(YX509_REVOKED) *rev;
    YX509_REVOKED *r;
    long l;
    size_t i;
    char *p;

    BIO_pprintf(out, "Certificate Revocation List (CRL):\n");
    l = YX509_CRL_get_version(x);
    BIO_pprintf(out, "%8sVersion %lu (0x%lx)\n", "", l + 1, l);
    YX509_signature_print(out, x->sig_alg, NULL);
    p = YX509_NAME_oneline(YX509_CRL_get_issuer(x), NULL, 0);
    BIO_pprintf(out, "%8sIssuer: %s\n", "", p);
    OPENSSL_free(p);
    BIO_pprintf(out, "%8sLast Update: ", "");
    YASN1_TIME_print(out, YX509_CRL_get_lastUpdate(x));
    BIO_pprintf(out, "\n%8sNext Update: ", "");
    if (YX509_CRL_get_nextUpdate(x))
        YASN1_TIME_print(out, YX509_CRL_get_nextUpdate(x));
    else
        BIO_pprintf(out, "NONE");
    BIO_pprintf(out, "\n");

    YX509V3_extensions_print(out, "CRL extensions", x->crl->extensions, 0, 8);

    rev = YX509_CRL_get_REVOKED(x);

    if (sk_YX509_REVOKED_num(rev) > 0)
        BIO_pprintf(out, "Revoked Certificates:\n");
    else
        BIO_pprintf(out, "No Revoked Certificates.\n");

    for (i = 0; i < sk_YX509_REVOKED_num(rev); i++) {
        r = sk_YX509_REVOKED_value(rev, i);
        BIO_pprintf(out, "    Serial Number: ");
        i2a_YASN1_INTEGER(out, r->serialNumber);
        BIO_pprintf(out, "\n        Revocation Date: ");
        YASN1_TIME_print(out, r->revocationDate);
        BIO_pprintf(out, "\n");
        YX509V3_extensions_print(out, "CRL entry extensions",
                                r->extensions, 0, 8);
    }
    YX509_signature_print(out, x->sig_alg, x->signature);

    return 1;

}
