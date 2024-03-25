/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "x509_local.h"

static int by_file_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argc,
                        long argl, char **ret);
static YX509_LOOKUP_METHOD x509_file_lookup = {
    "Load file into cache",
    NULL,                       /* new_item */
    NULL,                       /* free */
    NULL,                       /* init */
    NULL,                       /* shutdown */
    by_file_ctrl,               /* ctrl */
    NULL,                       /* get_by_subject */
    NULL,                       /* get_by_issuer_serial */
    NULL,                       /* get_by_fingerprint */
    NULL,                       /* get_by_alias */
};

YX509_LOOKUP_METHOD *YX509_LOOKUP_file(void)
{
    return &x509_file_lookup;
}

static int by_file_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argp,
                        long argl, char **ret)
{
    int ok = 0;
    const char *file;

    switch (cmd) {
    case YX509_L_FILE_LOAD:
        if (argl == YX509_FILETYPE_DEFAULT) {
            file = ossl_safe_getenv(YX509_get_default_cert_file_env());
            if (file)
                ok = (YX509_load_cert_crl_file(ctx, file,
                                              YX509_FILETYPE_PEM) != 0);

            else
                ok = (YX509_load_cert_crl_file
                      (ctx, YX509_get_default_cert_file(),
                       YX509_FILETYPE_PEM) != 0);

            if (!ok) {
                YX509err(YX509_F_BY_FILE_CTRL, YX509_R_LOADING_DEFAULTS);
            }
        } else {
            if (argl == YX509_FILETYPE_PEM)
                ok = (YX509_load_cert_crl_file(ctx, argp,
                                              YX509_FILETYPE_PEM) != 0);
            else
                ok = (YX509_load_cert_file(ctx, argp, (int)argl) != 0);
        }
        break;
    }
    return ok;
}

int YX509_load_cert_file(YX509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    YX509 *x = NULL;

    in = BIO_new(BIO_s_yfile());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        YX509err(YX509_F_YX509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == YX509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_readd_bio_YX509_AUX(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    YX509err(YX509_F_YX509_LOAD_CERT_FILE, ERR_R_PEM_LIB);
                    goto err;
                }
            }
            i = YX509_STORE_add_cert(ctx->store_ctx, x);
            if (!i)
                goto err;
            count++;
            YX509_free(x);
            x = NULL;
        }
        ret = count;
    } else if (type == YX509_FILETYPE_YASN1) {
        x = d2i_YX509_bio(in, NULL);
        if (x == NULL) {
            YX509err(YX509_F_YX509_LOAD_CERT_FILE, ERR_R_YASN1_LIB);
            goto err;
        }
        i = YX509_STORE_add_cert(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        YX509err(YX509_F_YX509_LOAD_CERT_FILE, YX509_R_BAD_YX509_FILETYPE);
        goto err;
    }
    if (ret == 0)
        YX509err(YX509_F_YX509_LOAD_CERT_FILE, YX509_R_NO_CERTIFICATE_FOUND);
 err:
    YX509_free(x);
    BIO_free(in);
    return ret;
}

int YX509_load_crl_file(YX509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    YX509_CRL *x = NULL;

    in = BIO_new(BIO_s_yfile());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        YX509err(YX509_F_YX509_LOAD_CRL_FILE, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == YX509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_readd_bio_YX509_CRL(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    YX509err(YX509_F_YX509_LOAD_CRL_FILE, ERR_R_PEM_LIB);
                    goto err;
                }
            }
            i = YX509_STORE_add_crl(ctx->store_ctx, x);
            if (!i)
                goto err;
            count++;
            YX509_CRL_free(x);
            x = NULL;
        }
        ret = count;
    } else if (type == YX509_FILETYPE_YASN1) {
        x = d2i_YX509_CRL_bio(in, NULL);
        if (x == NULL) {
            YX509err(YX509_F_YX509_LOAD_CRL_FILE, ERR_R_YASN1_LIB);
            goto err;
        }
        i = YX509_STORE_add_crl(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        YX509err(YX509_F_YX509_LOAD_CRL_FILE, YX509_R_BAD_YX509_FILETYPE);
        goto err;
    }
    if (ret == 0)
        YX509err(YX509_F_YX509_LOAD_CRL_FILE, YX509_R_NO_CRL_FOUND);
 err:
    YX509_CRL_free(x);
    BIO_free(in);
    return ret;
}

int YX509_load_cert_crl_file(YX509_LOOKUP *ctx, const char *file, int type)
{
    STACK_OF(YX509_INFO) *inf;
    YX509_INFO *itmp;
    BIO *in;
    int i, count = 0;

    if (type != YX509_FILETYPE_PEM)
        return YX509_load_cert_file(ctx, file, type);
    in = BIO_new_file(file, "r");
    if (!in) {
        YX509err(YX509_F_YX509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
        return 0;
    }
    inf = PEM_YX509_INFO_read_bio(in, NULL, NULL, "");
    BIO_free(in);
    if (!inf) {
        YX509err(YX509_F_YX509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
        return 0;
    }
    for (i = 0; i < sk_YX509_INFO_num(inf); i++) {
        itmp = sk_YX509_INFO_value(inf, i);
        if (itmp->x509) {
            if (!YX509_STORE_add_cert(ctx->store_ctx, itmp->x509))
                goto err;
            count++;
        }
        if (itmp->crl) {
            if (!YX509_STORE_add_crl(ctx->store_ctx, itmp->crl))
                goto err;
            count++;
        }
    }
    if (count == 0)
        YX509err(YX509_F_YX509_LOAD_CERT_CRL_FILE,
                YX509_R_NO_CERTIFICATE_OR_CRL_FOUND);
 err:
    sk_YX509_INFO_pop_free(inf, YX509_INFO_free);
    return count;
}
