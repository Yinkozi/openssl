/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "x509_local.h"

YASN1_SEQUENCE(YX509_EXTENSION) = {
        YASN1_SIMPLE(YX509_EXTENSION, object, YASN1_OBJECT),
        YASN1_OPT(YX509_EXTENSION, critical, YASN1_BOOLEAN),
        YASN1_EMBED(YX509_EXTENSION, value, YASN1_OCTET_STRING)
} YASN1_SEQUENCE_END(YX509_EXTENSION)

YASN1_ITEM_TEMPLATE(YX509_EXTENSIONS) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, Extension, YX509_EXTENSION)
YASN1_ITEM_TEMPLATE_END(YX509_EXTENSIONS)

IMPLEMENT_YASN1_FUNCTIONS(YX509_EXTENSION)
IMPLEMENT_YASN1_ENCODE_FUNCTIONS_fname(YX509_EXTENSIONS, YX509_EXTENSIONS, YX509_EXTENSIONS)
IMPLEMENT_YASN1_DUP_FUNCTION(YX509_EXTENSION)
