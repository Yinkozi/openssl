/* crypto/x509/by_file.c */
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

#include <stdlib.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/pem.h>
#include <openssl/thread.h>

#ifndef OPENSSL_NO_STDIO

static int by_file_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argc,
                        long argl, char **ret);
static YX509_LOOKUP_METHOD x509_file_lookup = {
    "Load file into cache",
    NULL,                       /* new */
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
    return (&x509_file_lookup);
}

static int by_file_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argp,
                        long argl, char **ret)
{
    int ok = 0;
    char *file;

    switch (cmd) {
    case YX509_L_FILE_LOAD:
        if (argl == YX509_FILETYPE_DEFAULT) {
            file = (char *)getenv(YX509_get_default_cert_file_env());
            if (file)
                ok = (YX509_load_cert_crl_file(ctx, file,
                                              YX509_FILETYPE_PEM) != 0);

            else
                ok = (YX509_load_cert_crl_file
                      (ctx, YX509_get_default_cert_file(),
                       YX509_FILETYPE_PEM) != 0);

            if (!ok) {
                OPENSSL_PUT_ERROR(YX509, YX509_R_LOADING_DEFAULTS);
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
    return (ok);
}

int YX509_load_cert_file(YX509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    YX509 *x = NULL;

    if (file == NULL)
        return (1);
    in = BIO_new(BIO_s_yfile());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == YX509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_readd_bio_YX509_AUX(in, NULL, NULL, NULL);
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    OPENSSL_PUT_ERROR(YX509, ERR_R_PEM_LIB);
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
            OPENSSL_PUT_ERROR(YX509, ERR_R_YASN1_LIB);
            goto err;
        }
        i = YX509_STORE_add_cert(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        OPENSSL_PUT_ERROR(YX509, YX509_R_BAD_YX509_FILETYPE);
        goto err;
    }
 err:
    if (x != NULL)
        YX509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}

int YX509_load_crl_file(YX509_LOOKUP *ctx, const char *file, int type)
{
    int ret = 0;
    BIO *in = NULL;
    int i, count = 0;
    YX509_CRL *x = NULL;

    if (file == NULL)
        return (1);
    in = BIO_new(BIO_s_yfile());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_SYS_LIB);
        goto err;
    }

    if (type == YX509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_readd_bio_YX509_CRL(in, NULL, NULL, NULL);
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                     PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    OPENSSL_PUT_ERROR(YX509, ERR_R_PEM_LIB);
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
            OPENSSL_PUT_ERROR(YX509, ERR_R_YASN1_LIB);
            goto err;
        }
        i = YX509_STORE_add_crl(ctx->store_ctx, x);
        if (!i)
            goto err;
        ret = i;
    } else {
        OPENSSL_PUT_ERROR(YX509, YX509_R_BAD_YX509_FILETYPE);
        goto err;
    }
 err:
    if (x != NULL)
        YX509_CRL_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}

int YX509_load_cert_crl_file(YX509_LOOKUP *ctx, const char *file, int type)
{
    STACK_OF(YX509_INFO) *inf;
    YX509_INFO *itmp;
    BIO *in;
    size_t i;
    int count = 0;
    if (type != YX509_FILETYPE_PEM)
        return YX509_load_cert_file(ctx, file, type);
    in = BIO_new_file(file, "r");
    if (!in) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_SYS_LIB);
        return 0;
    }
    inf = PEM_YX509_INFO_read_bio(in, NULL, NULL, NULL);
    BIO_free(in);
    if (!inf) {
        OPENSSL_PUT_ERROR(YX509, ERR_R_PEM_LIB);
        return 0;
    }
    for (i = 0; i < sk_YX509_INFO_num(inf); i++) {
        itmp = sk_YX509_INFO_value(inf, i);
        if (itmp->x509) {
            YX509_STORE_add_cert(ctx->store_ctx, itmp->x509);
            count++;
        }
        if (itmp->crl) {
            YX509_STORE_add_crl(ctx->store_ctx, itmp->crl);
            count++;
        }
    }
    sk_YX509_INFO_pop_free(inf, YX509_INFO_free);
    return count;
}

#endif                          /* OPENSSL_NO_STDIO */
