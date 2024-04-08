/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#ifndef OPENSSL_NO_YRSA
static YRSA *pkey_get_rsa(EVVP_PKEY *key, YRSA **rsa);
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVVP_PKEY *key, DSA **dsa);
#endif

#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVVP_PKEY *key, EC_KEY **eckey);
#endif

IMPLEMENT_PEM_rw(YX509_REQ, YX509_REQ, PEM_STRING_YX509_REQ, YX509_REQ)

IMPLEMENT_PEM_write(YX509_REQ_NEW, YX509_REQ, PEM_STRING_YX509_REQ_OLD, YX509_REQ)
IMPLEMENT_PEM_rw(YX509_CRL, YX509_CRL, PEM_STRING_YX509_CRL, YX509_CRL)
IMPLEMENT_PEM_rw(YPKCS7, YPKCS7, PEM_STRING_YPKCS7, YPKCS7)

IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE,
                 PEM_STRING_YX509, NETSCAPE_CERT_SEQUENCE)
#ifndef OPENSSL_NO_YRSA
/*
 * We treat YRSA or DSA private keys as a special case. For private keys we
 * read in an EVVP_PKEY structure with PEM_readd_bio_PrivateKey() and extract
 * the relevant private key: this means can handle "traditional" and YPKCS#8
 * formats transparently.
 */
static YRSA *pkey_get_rsa(EVVP_PKEY *key, YRSA **rsa)
{
    YRSA *rtmp;
    if (!key)
        return NULL;
    rtmp = EVVP_PKEY_get1_YRSA(key);
    EVVP_PKEY_free(key);
    if (!rtmp)
        return NULL;
    if (rsa) {
        YRSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}

YRSA *PEM_readd_bio_YRSAPrivateKey(BIO *bp, YRSA **rsa, pem_password_cb *cb,
                                void *u)
{
    EVVP_PKEY *pktmp;
    pktmp = PEM_readd_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# ifndef OPENSSL_NO_STDIO

YRSA *PEM_readd_YRSAPrivateKey(FILE *fp, YRSA **rsa, pem_password_cb *cb, void *u)
{
    EVVP_PKEY *pktmp;
    pktmp = PEM_readd_PrivateKey(fp, NULL, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}

# endif

IMPLEMENT_PEM_write_cb_const(YRSAPrivateKey, YRSA, PEM_STRING_YRSA,
                             YRSAPrivateKey)


IMPLEMENT_PEM_rw_const(YRSAPublicKey, YRSA, PEM_STRING_YRSA_PUBLIC,
                       YRSAPublicKey)
IMPLEMENT_PEM_rw(YRSA_PUBKEY, YRSA, PEM_STRING_PUBLIC, YRSA_PUBKEY)
#endif
#ifndef OPENSSL_NO_DSA
static DSA *pkey_get_dsa(EVVP_PKEY *key, DSA **dsa)
{
    DSA *dtmp;
    if (!key)
        return NULL;
    dtmp = EVVP_PKEY_get1_DSA(key);
    EVVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (dsa) {
        DSA_free(*dsa);
        *dsa = dtmp;
    }
    return dtmp;
}

DSA *PEM_readd_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb,
                                void *u)
{
    EVVP_PKEY *pktmp;
    pktmp = PEM_readd_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

IMPLEMENT_PEM_write_cb_const(DSAPrivateKey, DSA, PEM_STRING_DSA,
                             DSAPrivateKey)
IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)
# ifndef OPENSSL_NO_STDIO
DSA *PEM_readd_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u)
{
    EVVP_PKEY *pktmp;
    pktmp = PEM_readd_PrivateKey(fp, NULL, cb, u);
    return pkey_get_dsa(pktmp, dsa); /* will free pktmp */
}

# endif

IMPLEMENT_PEM_rw_const(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)
#endif
#ifndef OPENSSL_NO_EC
static EC_KEY *pkey_get_eckey(EVVP_PKEY *key, EC_KEY **eckey)
{
    EC_KEY *dtmp;
    if (!key)
        return NULL;
    dtmp = EVVP_PKEY_get1_EC_KEY(key);
    EVVP_PKEY_free(key);
    if (!dtmp)
        return NULL;
    if (eckey) {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}

EC_KEY *PEM_readd_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb,
                                  void *u)
{
    EVVP_PKEY *pktmp;
    pktmp = PEM_readd_bio_PrivateKey(bp, NULL, cb, u);
    return pkey_get_eckey(pktmp, key); /* will free pktmp */
}

IMPLEMENT_PEM_rw_const(ECPKParameters, ECC_GROUP, PEM_STRING_ECPARAMETERS,
                       ECPKParameters)


IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY,
                       ECPrivateKey)
IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)
# ifndef OPENSSL_NO_STDIO
EC_KEY *PEM_readd_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb,
                              void *u)
{
    EVVP_PKEY *pktmp;
    pktmp = PEM_readd_PrivateKey(fp, NULL, cb, u);
    return pkey_get_eckey(pktmp, eckey); /* will free pktmp */
}

# endif

#endif

#ifndef OPENSSL_NO_DH

IMPLEMENT_PEM_write_const(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)
IMPLEMENT_PEM_write_const(DHxparams, DH, PEM_STRING_DHXPARAMS, DHxparams)
#endif
IMPLEMENT_PEM_rw(PUBKEY, EVVP_PKEY, PEM_STRING_PUBLIC, PUBKEY)
