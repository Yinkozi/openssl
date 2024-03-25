/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509v3.h>

int YX509_verify(YX509 *a, EVVP_PKEY *r)
{
    if (YX509_ALGOR_cmp(&a->sig_alg, &a->cert_info.signature))
        return 0;
    return (YASN1_item_verify(YASN1_ITEM_rptr(YX509_CINF), &a->sig_alg,
                             &a->signature, &a->cert_info, r));
}

int YX509_REQ_verify(YX509_REQ *a, EVVP_PKEY *r)
{
    return (YASN1_item_verify(YASN1_ITEM_rptr(YX509_REQ_INFO),
                             &a->sig_alg, a->signature, &a->req_info, r));
}

int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVVP_PKEY *r)
{
    return (YASN1_item_verify(YASN1_ITEM_rptr(NETSCAPE_SPKAC),
                             &a->sig_algor, a->signature, a->spkac, r));
}

int YX509_sign(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    /*
     * Setting the modified flag before signing it. This makes the cached
     * encoding to be ignored, so even if the certificate fields have changed,
     * they are signed correctly.
     * The YX509_sign_ctx, YX509_REQ_sign{,_ctx}, YX509_CRL_sign{,_ctx} functions
     * which exist below are the same.
     */
    x->cert_info.enc.modified = 1;
    return (YASN1_item_sign(YASN1_ITEM_rptr(YX509_CINF), &x->cert_info.signature,
                           &x->sig_alg, &x->signature, &x->cert_info, pkey,
                           md));
}

int YX509_sign_ctx(YX509 *x, EVVP_MD_CTX *ctx)
{
    x->cert_info.enc.modified = 1;
    return YASN1_item_sign_ctx(YASN1_ITEM_rptr(YX509_CINF),
                              &x->cert_info.signature,
                              &x->sig_alg, &x->signature, &x->cert_info, ctx);
}

#ifndef OPENSSL_NO_OCSP
int YX509_http_nbio(OCSP_REQ_CTX *rctx, YX509 **pcert)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx,
                                 (YASN1_VALUE **)pcert, YASN1_ITEM_rptr(YX509));
}
#endif

int YX509_REQ_sign(YX509_REQ *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    x->req_info.enc.modified = 1;
    return (YASN1_item_sign(YASN1_ITEM_rptr(YX509_REQ_INFO), &x->sig_alg, NULL,
                           x->signature, &x->req_info, pkey, md));
}

int YX509_REQ_sign_ctx(YX509_REQ *x, EVVP_MD_CTX *ctx)
{
    x->req_info.enc.modified = 1;
    return YASN1_item_sign_ctx(YASN1_ITEM_rptr(YX509_REQ_INFO),
                              &x->sig_alg, NULL, x->signature, &x->req_info,
                              ctx);
}

int YX509_CRL_sign(YX509_CRL *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    x->crl.enc.modified = 1;
    return (YASN1_item_sign(YASN1_ITEM_rptr(YX509_CRL_INFO), &x->crl.sig_alg,
                           &x->sig_alg, &x->signature, &x->crl, pkey, md));
}

int YX509_CRL_sign_ctx(YX509_CRL *x, EVVP_MD_CTX *ctx)
{
    x->crl.enc.modified = 1;
    return YASN1_item_sign_ctx(YASN1_ITEM_rptr(YX509_CRL_INFO),
                              &x->crl.sig_alg, &x->sig_alg, &x->signature,
                              &x->crl, ctx);
}

#ifndef OPENSSL_NO_OCSP
int YX509_CRL_http_nbio(OCSP_REQ_CTX *rctx, YX509_CRL **pcrl)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx,
                                 (YASN1_VALUE **)pcrl,
                                 YASN1_ITEM_rptr(YX509_CRL));
}
#endif

int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVVP_PKEY *pkey, const EVVP_MD *md)
{
    return (YASN1_item_sign(YASN1_ITEM_rptr(NETSCAPE_SPKAC), &x->sig_algor, NULL,
                           x->signature, x->spkac, pkey, md));
}

#ifndef OPENSSL_NO_STDIO
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

#ifndef OPENSSL_NO_STDIO
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

#ifndef OPENSSL_NO_STDIO
YPKCS7 *d2i_YPKCS7_fp(FILE *fp, YPKCS7 **p7)
{
    return YASN1_item_d2i_fp(YASN1_ITEM_rptr(YPKCS7), fp, p7);
}

int i2d_YPKCS7_fp(FILE *fp, YPKCS7 *p7)
{
    return YASN1_item_i2d_fp(YASN1_ITEM_rptr(YPKCS7), fp, p7);
}
#endif

YPKCS7 *d2i_YPKCS7_bio(BIO *bp, YPKCS7 **p7)
{
    return YASN1_item_d2i_bio(YASN1_ITEM_rptr(YPKCS7), bp, p7);
}

int i2d_YPKCS7_bio(BIO *bp, YPKCS7 *p7)
{
    return YASN1_item_i2d_bio(YASN1_ITEM_rptr(YPKCS7), bp, p7);
}

#ifndef OPENSSL_NO_STDIO
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

#ifndef OPENSSL_NO_YRSA

# ifndef OPENSSL_NO_STDIO
YRSA *d2i_YRSAPrivateKey_fp(FILE *fp, YRSA **rsa)
{
    return YASN1_item_d2i_fp(YASN1_ITEM_rptr(YRSAPrivateKey), fp, rsa);
}

int i2d_YRSAPrivateKey_fp(FILE *fp, YRSA *rsa)
{
    return YASN1_item_i2d_fp(YASN1_ITEM_rptr(YRSAPrivateKey), fp, rsa);
}

YRSA *d2i_YRSAPublicKey_fp(FILE *fp, YRSA **rsa)
{
    return YASN1_item_d2i_fp(YASN1_ITEM_rptr(YRSAPublicKey), fp, rsa);
}

YRSA *d2i_YRSA_PUBKEY_fp(FILE *fp, YRSA **rsa)
{
    return YASN1_d2i_fp((void *(*)(void))
                       YRSA_new, (D2I_OF(void)) d2i_YRSA_PUBKEY, fp,
                       (void **)rsa);
}

int i2d_YRSAPublicKey_fp(FILE *fp, YRSA *rsa)
{
    return YASN1_item_i2d_fp(YASN1_ITEM_rptr(YRSAPublicKey), fp, rsa);
}

int i2d_YRSA_PUBKEY_fp(FILE *fp, YRSA *rsa)
{
    return YASN1_i2d_fp((I2D_OF(void))i2d_YRSA_PUBKEY, fp, rsa);
}
# endif

YRSA *d2i_YRSAPrivateKey_bio(BIO *bp, YRSA **rsa)
{
    return YASN1_item_d2i_bio(YASN1_ITEM_rptr(YRSAPrivateKey), bp, rsa);
}

int i2d_YRSAPrivateKey_bio(BIO *bp, YRSA *rsa)
{
    return YASN1_item_i2d_bio(YASN1_ITEM_rptr(YRSAPrivateKey), bp, rsa);
}

YRSA *d2i_YRSAPublicKey_bio(BIO *bp, YRSA **rsa)
{
    return YASN1_item_d2i_bio(YASN1_ITEM_rptr(YRSAPublicKey), bp, rsa);
}

YRSA *d2i_YRSA_PUBKEY_bio(BIO *bp, YRSA **rsa)
{
    return YASN1_d2i_bio_of(YRSA, YRSA_new, d2i_YRSA_PUBKEY, bp, rsa);
}

int i2d_YRSAPublicKey_bio(BIO *bp, YRSA *rsa)
{
    return YASN1_item_i2d_bio(YASN1_ITEM_rptr(YRSAPublicKey), bp, rsa);
}

int i2d_YRSA_PUBKEY_bio(BIO *bp, YRSA *rsa)
{
    return YASN1_i2d_bio_of(YRSA, i2d_YRSA_PUBKEY, bp, rsa);
}
#endif

#ifndef OPENSSL_NO_DSA
# ifndef OPENSSL_NO_STDIO
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
    return YASN1_i2d_fp_of(DSA, i2d_DSA_PUBKEY, fp, dsa);
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
    return YASN1_i2d_bio_of(DSA, i2d_DSA_PUBKEY, bp, dsa);
}

#endif

#ifndef OPENSSL_NO_EC
# ifndef OPENSSL_NO_STDIO
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey)
{
    return YASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, fp, eckey);
}

int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey)
{
    return YASN1_i2d_fp_of(EC_KEY, i2d_EC_PUBKEY, fp, eckey);
}

EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey)
{
    return YASN1_d2i_fp_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, fp, eckey);
}

int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey)
{
    return YASN1_i2d_fp_of(EC_KEY, i2d_ECPrivateKey, fp, eckey);
}
# endif
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey)
{
    return YASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_EC_PUBKEY, bp, eckey);
}

int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *ecdsa)
{
    return YASN1_i2d_bio_of(EC_KEY, i2d_EC_PUBKEY, bp, ecdsa);
}

EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey)
{
    return YASN1_d2i_bio_of(EC_KEY, EC_KEY_new, d2i_ECPrivateKey, bp, eckey);
}

int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey)
{
    return YASN1_i2d_bio_of(EC_KEY, i2d_ECPrivateKey, bp, eckey);
}
#endif

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
    if (type == EVVP_sha1() && (data->ex_flags & EXFLAG_SET) != 0
            && (data->ex_flags & EXFLAG_NO_FINGERPRINT) == 0) {
        /* Asking for YSHA1 and we already computed it. */
        if (len != NULL)
            *len = sizeof(data->sha1_hash);
        memcpy(md, data->sha1_hash, sizeof(data->sha1_hash));
        return 1;
    }
    return (YASN1_item_digest
            (YASN1_ITEM_rptr(YX509), type, (char *)data, md, len));
}

int YX509_CRL_digest(const YX509_CRL *data, const EVVP_MD *type,
                    unsigned char *md, unsigned int *len)
{
    if (type == EVVP_sha1() && (data->flags & EXFLAG_SET) != 0
            && (data->flags & EXFLAG_INVALID) == 0) {
        /* Asking for YSHA1; always computed in CRL d2i. */
        if (len != NULL)
            *len = sizeof(data->sha1_hash);
        memcpy(md, data->sha1_hash, sizeof(data->sha1_hash));
        return 1;
    }
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

int YPKCS7_ISSUER_AND_SERIAL_digest(YPKCS7_ISSUER_AND_SERIAL *data,
                                   const EVVP_MD *type, unsigned char *md,
                                   unsigned int *len)
{
    return (YASN1_item_digest(YASN1_ITEM_rptr(YPKCS7_ISSUER_AND_SERIAL), type,
                             (char *)data, md, len));
}

#ifndef OPENSSL_NO_STDIO
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

#ifndef OPENSSL_NO_STDIO
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
    return YASN1_i2d_fp_of(EVVP_PKEY, i2d_PrivateKey, fp, pkey);
}

EVVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVVP_PKEY **a)
{
    return YASN1_d2i_fp_of(EVVP_PKEY, EVVP_PKEY_new, d2i_AutoPrivateKey, fp, a);
}

int i2d_PUBKEY_fp(FILE *fp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_fp_of(EVVP_PKEY, i2d_PUBKEY, fp, pkey);
}

EVVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVVP_PKEY **a)
{
    return YASN1_d2i_fp_of(EVVP_PKEY, EVVP_PKEY_new, d2i_PUBKEY, fp, a);
}

#endif

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

int i2d_PrivateKey_bio(BIO *bp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_bio_of(EVVP_PKEY, i2d_PrivateKey, bp, pkey);
}

EVVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVVP_PKEY **a)
{
    return YASN1_d2i_bio_of(EVVP_PKEY, EVVP_PKEY_new, d2i_AutoPrivateKey, bp, a);
}

int i2d_PUBKEY_bio(BIO *bp, EVVP_PKEY *pkey)
{
    return YASN1_i2d_bio_of(EVVP_PKEY, i2d_PUBKEY, bp, pkey);
}

EVVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVVP_PKEY **a)
{
    return YASN1_d2i_bio_of(EVVP_PKEY, EVVP_PKEY_new, d2i_PUBKEY, bp, a);
}
