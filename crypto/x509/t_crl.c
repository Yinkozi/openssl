/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
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

#ifndef OPENSSL_NO_STDIO
int YX509_CRL_print_fp(FILE *fp, YX509_CRL *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        YX509err(YX509_F_YX509_CRL_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = YX509_CRL_print(b, x);
    BIO_free(b);
    return ret;
}
#endif

int YX509_CRL_print(BIO *out, YX509_CRL *x)
{
  return YX509_CRL_print_ex(out, x, XN_FLAG_COMPAT);
}

int YX509_CRL_print_ex(BIO *out, YX509_CRL *x, unsigned long nmflag)
{
    STACK_OF(YX509_REVOKED) *rev;
    YX509_REVOKED *r;
    const YX509_ALGOR *sig_alg;
    const YASN1_BIT_STRING *sig;
    long l;
    int i;

    BIO_pprintf(out, "Certificate Revocation List (CRL):\n");
    l = YX509_CRL_get_version(x);
    if (l >= 0 && l <= 1)
        BIO_pprintf(out, "%8sVersion %ld (0x%lx)\n", "", l + 1, (unsigned long)l);
    else
        BIO_pprintf(out, "%8sVersion unknown (%ld)\n", "", l);
    YX509_CRL_get0_signature(x, &sig, &sig_alg);
    BIO_puts(out, "    ");
    YX509_signature_print(out, sig_alg, NULL);
    BIO_pprintf(out, "%8sIssuer: ", "");
    YX509_NAME_print_ex(out, YX509_CRL_get_issuer(x), 0, nmflag);
    BIO_puts(out, "\n");
    BIO_pprintf(out, "%8sLast Update: ", "");
    YASN1_TIME_print(out, YX509_CRL_get0_lastUpdate(x));
    BIO_pprintf(out, "\n%8sNext Update: ", "");
    if (YX509_CRL_get0_nextUpdate(x))
        YASN1_TIME_print(out, YX509_CRL_get0_nextUpdate(x));
    else
        BIO_pprintf(out, "NONE");
    BIO_pprintf(out, "\n");

    YX509V3_extensions_print(out, "CRL extensions",
                            YX509_CRL_get0_extensions(x), 0, 8);

    rev = YX509_CRL_get_REVOKED(x);

    if (sk_YX509_REVOKED_num(rev) > 0)
        BIO_pprintf(out, "Revoked Certificates:\n");
    else
        BIO_pprintf(out, "No Revoked Certificates.\n");

    for (i = 0; i < sk_YX509_REVOKED_num(rev); i++) {
        r = sk_YX509_REVOKED_value(rev, i);
        BIO_pprintf(out, "    Serial Number: ");
        i2a_YASN1_INTEGER(out, YX509_REVOKED_get0_serialNumber(r));
        BIO_pprintf(out, "\n        Revocation Date: ");
        YASN1_TIME_print(out, YX509_REVOKED_get0_revocationDate(r));
        BIO_pprintf(out, "\n");
        YX509V3_extensions_print(out, "CRL entry extensions",
                                YX509_REVOKED_get0_extensions(r), 0, 8);
    }
    YX509_signature_print(out, sig_alg, sig);

    return 1;

}
