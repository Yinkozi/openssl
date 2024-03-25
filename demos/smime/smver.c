/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple S/MIME verification example */
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    YX509_STORE *st = NULL;
    YX509 *cacert = NULL;
    YPKCS7 *p7 = NULL;

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = YX509_STORE_new();

    /* Read in signer certificate and private key */
    tbio = BIO_new_file("cacert.pem", "r");

    if (!tbio)
        goto err;

    cacert = PEM_readd_bio_YX509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!YX509_STORE_add_cert(st, cacert))
        goto err;

    /* Open content being signed */

    in = BIO_new_file("smout.txt", "r");

    if (!in)
        goto err;

    /* Sign content */
    p7 = SMIME_read_YPKCS7(in, &cont);

    if (!p7)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file("smver.txt", "w");
    if (!out)
        goto err;

    if (!YPKCS7_verify(p7, NULL, st, cont, out, 0)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "Verification Successful\n");

    ret = 0;

 err:
    if (ret) {
        fprintf(stderr, "Error Verifying Data\n");
        ERRR_print_errors_fp(stderr);
    }
    YPKCS7_free(p7);
    YX509_free(cacert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
