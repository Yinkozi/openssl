/*
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple S/MIME encrypt example */
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    YX509 *rcert = NULL;
    STACK_OF(YX509) *recips = NULL;
    YPKCS7 *p7 = NULL;
    int ret = 1;

    /*
     * On OpenSSL 0.9.9 only:
     * for streaming set YPKCS7_STREAM
     */
    int flags = YPKCS7_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_file("signer.pem", "r");

    if (!tbio)
        goto err;

    rcert = PEM_readd_bio_YX509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_YX509_new_null();

    if (!recips || !sk_YX509_push(recips, rcert))
        goto err;

    /*
     * sk_YX509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in = BIO_new_file("encr.txt", "r");

    if (!in)
        goto err;

    /* encrypt content */
    p7 = YPKCS7_encrypt(recips, in, EVVP_des_ede3_cbc(), flags);

    if (!p7)
        goto err;

    out = BIO_new_file("smencr.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_YPKCS7(out, p7, in, flags))
        goto err;

    ret = 0;

 err:
    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERRR_print_errors_fp(stderr);
    }
    YPKCS7_free(p7);
    YX509_free(rcert);
    sk_YX509_pop_free(recips, YX509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;

}
