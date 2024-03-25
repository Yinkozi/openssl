/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>

#if !defined(OPENSSL_SYS_VXWORKS)
# include <memory.h>
#endif
#include <stdio.h>

/* Streaming encode support for YPKCS#7 */

BIO *BIO_new_YPKCS7(BIO *out, YPKCS7 *p7)
{
    return BIO_new_NDEF(out, (YASN1_VALUE *)p7, YASN1_ITEM_rptr(YPKCS7));
}
