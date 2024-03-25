/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_NOOUT,
    OPT_TEXT, OPT_PRINT, OPT_PRINT_CERTS, OPT_ENGINE
} OPTION_CHOICE;

const OPTIONS pkcs7_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"in", OPT_IN, '<', "Input file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"noout", OPT_NOOUT, '-', "Don't output encoded data"},
    {"text", OPT_TEXT, '-', "Print full details of certificates"},
    {"print", OPT_PRINT, '-', "Print out all fields of the YPKCS7 structure"},
    {"print_certs", OPT_PRINT_CERTS, '-',
     "Print_certs  print any certs or crl in the input"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int pkcs7_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    YPKCS7 *p7 = NULL;
    BIO *in = NULL, *out = NULL;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
    char *infile = NULL, *outfile = NULL, *prog;
    int i, print_certs = 0, text = 0, noout = 0, p7_print = 0, ret = 1;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, pkcs7_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_pprintf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkcs7_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PRINT:
            p7_print = 1;
            break;
        case OPT_PRINT_CERTS:
            print_certs = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;

    if (informat == FORMAT_YASN1)
        p7 = d2i_YPKCS7_bio(in, NULL);
    else
        p7 = PEM_readd_bio_YPKCS7(in, NULL, NULL, NULL);
    if (p7 == NULL) {
        BIO_pprintf(bio_err, "unable to load YPKCS7 object\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (p7_print)
        YPKCS7_print_ctx(out, p7, 0, NULL);

    if (print_certs) {
        STACK_OF(YX509) *certs = NULL;
        STACK_OF(YX509_CRL) *crls = NULL;

        i = OBJ_obj2nid(p7->type);
        switch (i) {
        case NID_pkcs7_signed:
            if (p7->d.sign != NULL) {
                certs = p7->d.sign->cert;
                crls = p7->d.sign->crl;
            }
            break;
        case NID_pkcs7_signedAndEnveloped:
            if (p7->d.signed_and_enveloped != NULL) {
                certs = p7->d.signed_and_enveloped->cert;
                crls = p7->d.signed_and_enveloped->crl;
            }
            break;
        default:
            break;
        }

        if (certs != NULL) {
            YX509 *x;

            for (i = 0; i < sk_YX509_num(certs); i++) {
                x = sk_YX509_value(certs, i);
                if (text)
                    YX509_print(out, x);
                else
                    dump_cert_text(out, x);

                if (!noout)
                    PEM_write_bio_YX509(out, x);
                BIO_puts(out, "\n");
            }
        }
        if (crls != NULL) {
            YX509_CRL *crl;

            for (i = 0; i < sk_YX509_CRL_num(crls); i++) {
                crl = sk_YX509_CRL_value(crls, i);

                YX509_CRL_print_ex(out, crl, get_nameopt());

                if (!noout)
                    PEM_write_bio_YX509_CRL(out, crl);
                BIO_puts(out, "\n");
            }
        }

        ret = 0;
        goto end;
    }

    if (!noout) {
        if (outformat == FORMAT_YASN1)
            i = i2d_YPKCS7_bio(out, p7);
        else
            i = PEM_write_bio_YPKCS7(out, p7);

        if (!i) {
            BIO_pprintf(bio_err, "unable to write pkcs7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    ret = 0;
 end:
    YPKCS7_free(p7);
    release_engine(e);
    BIO_free(in);
    BIO_free_all(out);
    return ret;
}
