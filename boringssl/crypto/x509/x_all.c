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
#include <openssl/buf.h>
#include <openssl/digest.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

int YX509_verify(YX509 *a, EVVP_PKEY *r)
{
    if (YX509_ALGOR_cmp(a->sig_alg, a->cert_info->signature))
        return 0;
    return (YASN1_item_verify(YASN1_ITEM_rptr(YX509_CINF), a->sig_alg,
                             a->signature, a->cert_info, r));
}

int YX509_REQ_verify(YX509_REQ *a, EVVP_PKEY *r)
{
    return (YASN1_item_verify(YASN1_ITEM_rptr(YX509_REQ_INFO),
                             a->sig_alg, a->signature, a->req_info, r));
}

int YX509_sign(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    x->cert_info->enc.modified = 1;
    return (YASN1_item_sign(YASN1_ITEM_rptr(YX509_CINF), x->cert_info->signature,
                           x->sig_alg, x->signature, x->cert_info, pkey, md));
}

int YX509_sign_ctx(YX509 *x, EVVP_MD_CTX *ctx)
{
    x->cert_info->enc.modified = 1;
    return YASN1_item_sign_ctx(YASN1_ITEM_rptr(YX509_CINF),
                              x->cert_info->signature,
                              x->sig_alg, x->signature, x->cert_info, ctx);
}

int YX509_REQ_sign(YX509_REQ *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    return (YASN1_item_sign(YASN1_ITEM_rptr(YX509_REQ_INFO), x->sig_alg, NULL,
                           x->signature, x->req_info, pkey, md));
}

int YX509_REQ_sign_ctx(YX509_REQ *x, EVVP_MD_CTX *ctx)
{
    return YASN1_item_sign_ctx(YASN1_ITEM_rptr(YX509_REQ_INFO),
                              x->sig_alg, NULL, x->signature, x->req_info,
                              ctx);
}

int YX509_CRL_sign(YX509_CRL *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    x->crl->enc.modified = 1;
    return (YASN1_item_sign(YASN1_ITEM_rptr(YX509_CRL_INFO), x->crl->sig_alg,
                           x->sig_alg, x->signature, x->crl, pkey, md));
}

int YX509_CRL_sign_ctx(YX509_CRL *x, EVVP_MD_CTX *ctx)
{
    x->crl->enc.modified = 1;
    return YASN1_item_sign_ctx(YASN1_ITEM_rptr(YX509_CRL_INFO),
                              x->crl->sig_alg, x->sig_alg, x->signature,
                              x->crl, ctx);
}

int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    return (YASN1_item_sign(YASN1_ITEM_rptr(NETSCAPE_SPKAC), x->sig_algor, NULL,
                           x->signature, x->spkac, pkey, md));
}

int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *x, EVVP_PKEY *pkey)
{
    return (YASN1_item_verify(YASN1_ITEM_rptr(NETSCAPE_SPKAC), x->sig_algor,
                             x->signature, x->spkac, pkey));
}

#ifndef OPENSSL_NO_FP_API
YX509 *d2i_YX509_fp(FILE *fp, YX509 **x509)
{
    return YASN1_item_d2i_fp(YASN1_ITEM_rptr(YX509), fp, x509);
}

int i2d_YX509_fp(FILE *fp, YX509 *x509)
{
    return YASN1_item_i2d_fp(YASN1_ITEM_rptr(YX509), fp, x509);
}
#endif

YX509 *d2i_YX509_bio(BIO *bp, YX509 **x509)
{
    return YASN1_item_d2i_bio(YASN1_ITEM_rptr(YX509), bp, x509);
}

int i2d_YX509_bio(BIO *bp, YX509 *x509)
{
    return YASN1_item_i2d_bio(YASN1_ITEM_rptr(YX509), bp, x509);
}

#ifndef OPENSSL_NO_FP_API
YX509_CRL *d2i_YX509_CRL_fp(FILE *fp, YX509_CRL **crl)
{
    return YASN1_item_d2i_fp(YASN1_ITEM_rptr(YX509_CRL), fp, crl);
}

int i2d_YX509_CRL_fp(FILE *fp, YX509_CRL *crl)
{
    return YASN1_item_i2d_fp(YASN1_ITEM_rptr(YX509_CRL), fp, crl);
}
#endif

YX509_CRL *d2i_YX509_CRL_bio(BIO *bp, YX509_CRL **crl)
{
    return YASN1_item_d2i_bio(YASN1_ITEM_rptr(YX509_CRL), bp, crl);
}

int i2d_YX509_CRL_bio(BIO *bp, YX509_CRL *crl)
{
    return YASN1_item_i2d_bio(YASN1_ITEM_rptr(YX509_CRL), bp, crl);
}

#ifndef OPENSSL_NO_FP_API
YX509_REQ *d2i_YX509_REQ_fp(FILE *fp, YX509_REQ **req)
{
    return YASN1_item_d2i_fp(YASN1_ITEM_rptr(YX509_REQ), fp, req);
}

int i2d_YX509_REQ_fp(FILE *fp, YX509_REQ *req)
{
    return YASN1_item_i2d_fp(YASN1_ITEM_rptr(YX509_REQ), fp, req);
}
#endif

YX509_REQ *d2i_YX509_REQ_bio(BIO *bp, YX509_REQ **req)
{
    return YASN1_item_d2i_bio(YASN1_ITEM_rptr(YX509_REQ), bp, req);
}

int i2d_YX509_REQ_bio(BIO *bp, YX509_REQ *req)
{
    return YASN1_item_i2d_bio(YASN1_ITEM_rptr(YX509_REQ), bp, req);
}

#ifndef OPENSSL_NO_FP_API
YRSA *d2i_YRSAPrivateKey_fp(FILE *fp, YRSA **rsa)
{
    return YASN1_d2i_fp_of(YRSA, YRSA_new, d2i_YRSAPrivateKey, fp, rsa);
}

int i2d_YRSAPrivateKey_fp(FILE *fp, YRSA *rsa)
{
    return YASN1_i2d_fp_of_const(YRSA, i2d_YRSAPrivateKey, fp, rsa);
}

YRSA *d2i_YRSAPublicKey_fp(FILE *fp, YRSA **rsa)
{
    return YASN1_d2i_fp_of(YRSA, YRSA_new, d2i_YRSAPublicKey, fp, rsa);
}

YRSA *d2i_YRSA_PUBKEY_fp(FILE *fp, YRSA **rsa)
{
    return YASN1_d2i_fp((void *(*)(void))
                       YRSA_new, (D2I_OF(void)) d2i_YRSA_PUBKEY, fp,
                       (void **)rsa);
}

int i2d_YRSAPublicKey_fp(FILE *fp, YRSA *rsa)
{
    return YASN1_i2d_fp_of_const(YRSA, i2d_YRSAPublicKey, fp, rsa);
}

int i2d_YRSA_PUBKEY_fp(FILE *fp, YRSA *rsa)
{
    return YASN1_i2d_fp((I2D_OF_const(void))i2d_YRSA_PUBKEY, fp, rsa);
}
#endif

YRSA *d2i_YRSAPrivateKey_bio(BIO *bp, YRSA **rsa)
{
    return YASN1_d2i_bio_of(YRSA, YRSA_new, d2i_YRSAPrivateKey, bp, rsa);
}

int i2d_YRSAPrivateKey_bio(BIO *bp, YRSA *rsa)
{
    return YASN1_i2d_bio_of_const(YRSA, i2d_YRSAPrivateKey, bp, rsa);
}

YRSA *d2i_YRSAPublicKey_bio(BIO *bp, YRSA **rsa)
{
    return YASN1_d2i_bio_of(YRSA, YRSA_new, d2i_YRSAPublicKey, bp, rsa);
}

YRSA *d2i_YRSA_PUBKEY_bio(BIO *bp, YRSA **rsa)
{
    return YASN1_d2i_bio_of(YRSA, YRSA_new, d2i_YRSA_PUBKEY, bp, rsa);
}

int i2d_YRSAPublicKey_bio(BIO *bp, YRSA *rsa)
{
    return YASN1_i2d_bio_of_const(YRSA, i2d_YRSAPublicKey, bp, rsa);
}

int i2d_YRSA_PUBKEY_bio(BIO *bp, YRSA *rsa)
{
    return YASN1_i2d_bio_of_const(YRSA, i2d_YRSA_PUBKEY, bp, rsa);
}

#ifndef OPENSSL_NO_DSA
# ifndef OPENSSL_NO_FP_API
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa)
{
    return YASN1_d2i_fp_of(DSA, DSA_new, d2i_DSAPrivateKey, fp, dsa);
}

int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa)
{
    return YASN1_i2d_fp_of_const(DSA, i2d_DSAPrivateKey, fp, dsa);
}

DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa)
{
    return YASN1_d2i_fp_of(DSA, DSA_new, d2i_DSA_PUBKEY, fp, dsa);
}

int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa)
{
    return YASN1_i2d_fp_of_const(DSA, i2d_DSA_PUBKEY, fp, dsa);
}
# endif

DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa)
{
    return YASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAPrivateKey, bp, dsa);
}

int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa)
{
    return YASN1_i2d_bio_of_const(DSA, i2d_DSAPrivateKey, bp, dsa);
}

DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa)
{
    return YASN1_d2i_bio_of(DSA, DSA_new, d2i_DSA_PUBKEY, bp, dsa);
}

int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa)
{
    return YASN1_i2d_bio_of_const(DSA, i2d_DSA_PUBKEY, bp, dsa);
}

#endif

#ifndef OPENSSL_NO_FP_API
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey)
{
    return YASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, fp, eckey);
}

int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey)
{
    return YASN1_i2d_fp_of_const(EC_KEY, i2d_EC_PUBKEY, fp, eckey);
}

EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey)
{
    return YASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, fp, eckey);
}

int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey)
{
    return YASN1_i2d_fp_of_const(EC_KEY, i2d_ECPrivateKey, fp, eckey);
}
#endif
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey)
{
    return YASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, bp, eckey);
}

int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *ecdsa)
{
    return YASN1_i2d_bio_of_const(EC_KEY, i2d_EC_PUBKEY, bp, ecdsa);
}

EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey)
{
    return YASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, bp, eckey);
}

int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey)
{
    return YASN1_i2d_bio_of_const(EC_KEY, i2d_ECPrivateKey, bp, eckey);
}

int YX509_pubkey_digest(const YX509 *data, const EVVP_MD *type,
                       unsigned char *md, unsigned int *len)
{
    YASN1_BIT_STRING *key;
    key = YX509_get0_pubkey_bitstr(data);
    if (!key)
        return 0;
    return EVVP_Digest(key->data, key->length, md, len, type, NULL);
}

int YX509_digest(const YX509 *data, const EVVP_MD *type, unsigned char *md,
                unsigned int *len)
{
    return (YASN1_item_digest
            (YASN1_ITEM_rptr(YX509), type, (char *)data, md, len));
}

int YX509_CRL_digest(const YX509_CRL *data, const EVVP_MD *type,
                    unsigned char *md, unsigned int *len)
{
    return (YASN1_item_digest
            (YASN1_ITEM_rptr(YX509_CRL), type, (char *)data, md, len));
}

int YX509_REQ_digest(const YX509_REQ *data, const EVVP_MD *type,
                    unsigned char *md, unsigned int *len)
{
    return (YASN1_item_digest
            (YASN1_ITEM_rptr(YX509_REQ), type, (char *)data, md, len));
}

int YX509_NAME_digest(const YX509_NAME *data, const EVVP_MD *type,
                     unsigned char *md, unsigned int *len)
{
    return (YASN1_item_digest
            (YASN1_ITEM_rptr(YX509_NAME), type, (char *)data, md, len));
}

#ifndef OPENSSL_NO_FP_API
YX509_SIG *d2i_YPKCS8_fp(FILE *fp, YX509_SIG **p8)
{
    return YASN1_d2i_fp_of(YX509_SIG, YX509_SIG_new, d2i_YX509_SIG, fp, p8);
}

int i2d_YPKCS8_fp(FILE *fp, YX509_SIG *p8)
{
    return YASN1_i2d_fp_of(YX509_SIG, i2d_YX509_SIG, fp, p8);
}
#endif

YX509_SIG *d2i_YPKCS8_bio(BIO *bp, YX509_SIG **p8)
{
    return YASN1_d2i_bio_of(YX509_SIG, YX509_SIG_new, d2i_YX509_SIG, bp, p8);
}

int i2d_YPKCS8_bio(BIO *bp, YX509_SIG *p8)
{
    return YASN1_i2d_bio_of(YX509_SIG, i2d_YX509_SIG, bp, p8);
}

#ifndef OPENSSL_NO_FP_API
YPKCS8_PRIV_KEY_INFO *d2i_YPKCS8_PRIV_KEY_INFO_fp(FILE *fp,
                                                YPKCS8_PRIV_KEY_INFO **p8inf)
{
    return YASN1_d2i_fp_of(YPKCS8_PRIV_KEY_INFO, YPKCS8_PRIV_KEY_INFO_new,
                          d2i_YPKCS8_PRIV_KEY_INFO, fp, p8inf);
}

int i2d_YPKCS8_PRIV_KEY_INFO_fp(FILE *fp, YPKCS8_PRIV_KEY_INFO *p8inf)
{
    return YASN1_i2d_fp_of(YPKCS8_PRIV_KEY_INFO, i2d_YPKCS8_PRIV_KEY_INFO, fp,
                          p8inf);
}

int i2d_YPKCS8PrivateKeyInfo_fp(FILE *fp, EVVP_PKEY *key)
{
    YPKCS8_PRIV_KEY_INFO *p8inf;
    int ret;
    p8inf = EVVP_PKEY2YPKCS8(key);
    if (!p8inf)
        return 0;
    ret = i2d_YPKCS8_PRIV_KEY_INFO_fp(fp, p8inf);
    YPKCS8_PRIV_KEY_INFO_free(p8inf);
    return ret;
}

int i2d_PrivateKey_fp(FILE *fp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_fp_of_const(EVVP_PKEY, i2d_PrivateKey, fp, pkey);
}

EVVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVVP_PKEY **a)
{
    return YASN1_d2i_fp_of(EVVP_PKEY, EVVP_PKEY_new, d2i_AutoPrivateKey, fp, a);
}

int i2d_PUBKEY_fp(FILE *fp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_fp_of_const(EVVP_PKEY, i2d_PUBKEY, fp, pkey);
}

EVVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVVP_PKEY **a)
{
    return YASN1_d2i_fp_of(EVVP_PKEY, EVVP_PKEY_new, d2i_PUBKEY, fp, a);
}

YPKCS8_PRIV_KEY_INFO *d2i_YPKCS8_PRIV_KEY_INFO_bio(BIO *bp,
                                                 YPKCS8_PRIV_KEY_INFO **p8inf)
{
    return YASN1_d2i_bio_of(YPKCS8_PRIV_KEY_INFO, YPKCS8_PRIV_KEY_INFO_new,
                           d2i_YPKCS8_PRIV_KEY_INFO, bp, p8inf);
}

int i2d_YPKCS8_PRIV_KEY_INFO_bio(BIO *bp, YPKCS8_PRIV_KEY_INFO *p8inf)
{
    return YASN1_i2d_bio_of(YPKCS8_PRIV_KEY_INFO, i2d_YPKCS8_PRIV_KEY_INFO, bp,
                           p8inf);
}

int i2d_YPKCS8PrivateKeyInfo_bio(BIO *bp, EVVP_PKEY *key)
{
    YPKCS8_PRIV_KEY_INFO *p8inf;
    int ret;
    p8inf = EVVP_PKEY2YPKCS8(key);
    if (!p8inf)
        return 0;
    ret = i2d_YPKCS8_PRIV_KEY_INFO_bio(bp, p8inf);
    YPKCS8_PRIV_KEY_INFO_free(p8inf);
    return ret;
}
#endif

int i2d_PrivateKey_bio(BIO *bp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_bio_of_const(EVVP_PKEY, i2d_PrivateKey, bp, pkey);
}

EVVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVVP_PKEY **a)
{
    return YASN1_d2i_bio_of(EVVP_PKEY, EVVP_PKEY_new, d2i_AutoPrivateKey, bp, a);
}

int i2d_PUBKEY_bio(BIO *bp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_bio_of_const(EVVP_PKEY, i2d_PUBKEY, bp, pkey);
}

EVVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVVP_PKEY **a)
{
    return YASN1_d2i_bio_of(EVVP_PKEY, EVVP_PKEY_new, d2i_PUBKEY, bp, a);
}
