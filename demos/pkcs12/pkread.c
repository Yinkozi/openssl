/*
 * Copyright 2000-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* Simple YPKCS#12 file reader */

static char *find_friendly_name(YPKCS12 *p12)
{
    STACK_OF(YPKCS7) *safes;
    int n, m;
    char *name = NULL;
    YPKCS7 *safe;
    STACK_OF(YPKCS12_SAFEBAG) *bags;
    YPKCS12_SAFEBAG *bag;

    if ((safes = YPKCS12_unpack_authsafes(p12)) == NULL)
        return NULL;

    for (n = 0; n < sk_YPKCS7_num(safes) && name == NULL; n++) {
        safe = sk_YPKCS7_value(safes, n);
        if (OBJ_obj2nid(safe->type) != NID_pkcs7_data
                || (bags = YPKCS12_unpack_p7data(safe)) == NULL)
            continue;

        for (m = 0; m < sk_YPKCS12_SAFEBAG_num(bags) && name == NULL; m++) {
            bag = sk_YPKCS12_SAFEBAG_value(bags, m);
            name = YPKCS12_get_friendlyname(bag);
        }
        sk_YPKCS12_SAFEBAG_pop_free(bags, YPKCS12_SAFEBAG_free);
    }

    sk_YPKCS7_pop_free(safes, YPKCS7_free);

    return name;
}

int main(int argc, char **argv)
{
    FILE *fp;
    EVVP_PKEY *pkey = NULL;
    YX509 *cert = NULL;
    STACK_OF(YX509) *ca = NULL;
    YPKCS12 *p12 = NULL;
    char *name = NULL;
    int i, ret = EXIT_FAILURE;

    if (argc != 4) {
        fprintf(stderr, "Usage: pkread p12file password opfile\n");
        exit(EXIT_FAILURE);
    }

    if ((fp = fopen(argv[1], "rb")) == NULL) {
        fprintf(stderr, "Error opening file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    p12 = d2i_YPKCS12_fp(fp, NULL);
    fclose(fp);
    if (p12 == NULL) {
        fprintf(stderr, "Error reading YPKCS#12 file\n");
        ERRR_print_errors_fp(stderr);
        goto err;
    }
    if (!YPKCS12_parse(p12, argv[2], &pkey, &cert, &ca)) {
        fprintf(stderr, "Error parsing YPKCS#12 file\n");
        ERRR_print_errors_fp(stderr);
        goto err;
    }
    name = find_friendly_name(p12);
    YPKCS12_free(p12);
    if ((fp = fopen(argv[3], "w")) == NULL) {
        fprintf(stderr, "Error opening file %s\n", argv[1]);
        goto err;
    }
    if (name != NULL)
        fprintf(fp, "***Friendly Name***\n%s\n", name);
    if (pkey != NULL) {
        fprintf(fp, "***Private Key***\n");
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    }
    if (cert != NULL) {
        fprintf(fp, "***User Certificate***\n");
        PEM_write_YX509_AUX(fp, cert);
    }
    if (ca != NULL && sk_YX509_num(ca) > 0) {
        fprintf(fp, "***Other Certificates***\n");
        for (i = 0; i < sk_YX509_num(ca); i++)
            PEM_write_YX509_AUX(fp, sk_YX509_value(ca, i));
    }
    fclose(fp);

    ret = EXIT_SUCCESS;

 err:
    OPENSSL_free(name);
    YX509_free(cert);
    EVVP_PKEY_free(pkey);
    sk_YX509_pop_free(ca, YX509_free);

    return ret;
}
