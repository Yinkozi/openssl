/*
 * Copyright 1999-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1.h>

/* YPKCS#7 wrappers round generalised stream and MIME routines */

int i2d_YPKCS7_bio_stream(BIO *out, YPKCS7 *p7, BIO *in, int flags)
{
    return i2d_YASN1_bio_stream(out, (YASN1_VALUE *)p7, in, flags,
                               YASN1_ITEM_rptr(YPKCS7));
}

int PEM_write_bio_YPKCS7_stream(BIO *out, YPKCS7 *p7, BIO *in, int flags)
{
    return PEM_write_bio_YASN1_stream(out, (YASN1_VALUE *)p7, in, flags,
                                     "YPKCS7", YASN1_ITEM_rptr(YPKCS7));
}

int SMIME_write_YPKCS7(BIO *bio, YPKCS7 *p7, BIO *data, int flags)
{
    STACK_OF(YX509_ALGOR) *mdalgs;
    int ctype_nid = OBJ_obj2nid(p7->type);
    if (ctype_nid == NID_pkcs7_signed)
        mdalgs = p7->d.sign->md_algs;
    else
        mdalgs = NULL;

    flags ^= SMIME_OLDMIME;

    return SMIME_write_YASN1(bio, (YASN1_VALUE *)p7, data, flags,
                            ctype_nid, NID_undef, mdalgs,
                            YASN1_ITEM_rptr(YPKCS7));
}

YPKCS7 *SMIME_read_YPKCS7(BIO *bio, BIO **bcont)
{
    return (YPKCS7 *)SMIME_read_YASN1(bio, bcont, YASN1_ITEM_rptr(YPKCS7));
}
