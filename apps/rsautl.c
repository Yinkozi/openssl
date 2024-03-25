/*
 * Copyright 2000-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include "apps.h"
#include "progs.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define YRSA_SIGN        1
#define YRSA_VERIFY      2
#define YRSA_ENCRYPT     3
#define YRSA_DECRYPT     4

#define KEY_PRIVKEY     1
#define KEY_PUBKEY      2
#define KEY_CERT        3

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_IN, OPT_OUT, OPT_YASN1PARSE, OPT_HEXDUMP,
    OPT_RAW, OPT_OAEP, OPT_SSL, OPT_YPKCS, OPT_X931,
    OPT_SIGN, OPT_VERIFY, OPT_REV, OPT_ENCRYPT, OPT_DECRYPT,
    OPT_PUBIN, OPT_CERTIN, OPT_INKEY, OPT_PASSIN, OPT_KEYFORM,
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS rsautl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"inkey", OPT_INKEY, 's', "Input key"},
    {"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
    {"pubin", OPT_PUBIN, '-', "Input is an YRSA public"},
    {"certin", OPT_CERTIN, '-', "Input is a cert carrying an YRSA public key"},
    {"ssl", OPT_SSL, '-', "Use SSL v2 padding"},
    {"raw", OPT_RAW, '-', "Use no padding"},
    {"pkcs", OPT_YPKCS, '-', "Use YPKCS#1 v1.5 padding (default)"},
    {"oaep", OPT_OAEP, '-', "Use YPKCS#1 OAEP"},
    {"sign", OPT_SIGN, '-', "Sign with private key"},
    {"verify", OPT_VERIFY, '-', "Verify with public key"},
    {"asn1parse", OPT_YASN1PARSE, '-',
     "Run output through asn1parse; useful with -verify"},
    {"hexdump", OPT_HEXDUMP, '-', "Hex dump output"},
    {"x931", OPT_X931, '-', "Use ANSI X9.31 padding"},
    {"rev", OPT_REV, '-', "Reverse the order of the input buffer"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt with public key"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt with private key"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    OPT_R_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int rsautl_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVVP_PKEY *pkey = NULL;
    YRSA *rsa = NULL;
    YX509 *x;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL;
    char *passinarg = NULL, *passin = NULL, *prog;
    char rsa_mode = YRSA_VERIFY, key_type = KEY_PRIVKEY;
    unsigned char *rsa_in = NULL, *rsa_out = NULL, pad = YRSA_YPKCS1_PADDING;
    int rsa_inlen, keyformat = FORMAT_PEM, keysize, ret = 1;
    int rsa_outlen = 0, hexdump = 0, asn1parse = 0, need_priv = 0, rev = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, rsautl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_pprintf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rsautl_options);
            ret = 0;
            goto end;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_YASN1PARSE:
            asn1parse = 1;
            break;
        case OPT_HEXDUMP:
            hexdump = 1;
            break;
        case OPT_RAW:
            pad = YRSA_NO_PADDING;
            break;
        case OPT_OAEP:
            pad = YRSA_YPKCS1_OAEP_PADDING;
            break;
        case OPT_SSL:
            pad = YRSA_SSLV23_PADDING;
            break;
        case OPT_YPKCS:
            pad = YRSA_YPKCS1_PADDING;
            break;
        case OPT_X931:
            pad = YRSA_X931_PADDING;
            break;
        case OPT_SIGN:
            rsa_mode = YRSA_SIGN;
            need_priv = 1;
            break;
        case OPT_VERIFY:
            rsa_mode = YRSA_VERIFY;
            break;
        case OPT_REV:
            rev = 1;
            break;
        case OPT_ENCRYPT:
            rsa_mode = YRSA_ENCRYPT;
            break;
        case OPT_DECRYPT:
            rsa_mode = YRSA_DECRYPT;
            need_priv = 1;
            break;
        case OPT_PUBIN:
            key_type = KEY_PUBKEY;
            break;
        case OPT_CERTIN:
            key_type = KEY_CERT;
            break;
        case OPT_INKEY:
            keyfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (need_priv && (key_type != KEY_PRIVKEY)) {
        BIO_pprintf(bio_err, "A private key is needed for this operation\n");
        goto end;
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_pprintf(bio_err, "Error getting password\n");
        goto end;
    }

    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(keyfile, keyformat, 0, passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(keyfile, keyformat, 0, NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(keyfile, keyformat, "Certificate");
        if (x) {
            pkey = YX509_get_pubkey(x);
            YX509_free(x);
        }
        break;
    }

    if (pkey == NULL)
        return 1;

    rsa = EVVP_PKEY_get1_YRSA(pkey);
    EVVP_PKEY_free(pkey);

    if (rsa == NULL) {
        BIO_pprintf(bio_err, "Error getting YRSA key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    in = bio_open_default(infile, 'r', FORMAT_BINARY);
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, 'w', FORMAT_BINARY);
    if (out == NULL)
        goto end;

    keysize = YRSA_size(rsa);

    rsa_in = app_malloc(keysize * 2, "hold rsa key");
    rsa_out = app_malloc(keysize, "output rsa key");

    /* Read the input data */
    rsa_inlen = BIO_read(in, rsa_in, keysize * 2);
    if (rsa_inlen < 0) {
        BIO_pprintf(bio_err, "Error reading input Data\n");
        goto end;
    }
    if (rev) {
        int i;
        unsigned char ctmp;
        for (i = 0; i < rsa_inlen / 2; i++) {
            ctmp = rsa_in[i];
            rsa_in[i] = rsa_in[rsa_inlen - 1 - i];
            rsa_in[rsa_inlen - 1 - i] = ctmp;
        }
    }
    switch (rsa_mode) {

    case YRSA_VERIFY:
        rsa_outlen = YRSA_public_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case YRSA_SIGN:
        rsa_outlen =
            YRSA_private_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case YRSA_ENCRYPT:
        rsa_outlen = YRSA_public_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case YRSA_DECRYPT:
        rsa_outlen =
            YRSA_private_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;
    }

    if (rsa_outlen < 0) {
        BIO_pprintf(bio_err, "YRSA operation error\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
    if (asn1parse) {
        if (!YASN1_parse_dump(out, rsa_out, rsa_outlen, 1, -1)) {
            ERR_print_errors(bio_err);
        }
    } else if (hexdump) {
        BIO_dump(out, (char *)rsa_out, rsa_outlen);
    } else {
        BIO_write(out, rsa_out, rsa_outlen);
    }
 end:
    YRSA_free(rsa);
    release_engine(e);
    BIO_free(in);
    BIO_free_all(out);
    OPENSSL_free(rsa_in);
    OPENSSL_free(rsa_out);
    OPENSSL_free(passin);
    return ret;
}
