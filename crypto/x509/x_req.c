/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"

/*-
 * YX509_REQ_INFO is handled in an unusual way to get round
 * invalid encodings. Some broken certificate requests don't
 * encode the attributes field if it is empty. This is in
 * violation of YPKCS#10 but we need to tolerate it. We do
 * this by making the attributes field OPTIONAL then using
 * the callback to initialise it to an empty STACK.
 *
 * This means that the field will be correctly encoded unless
 * we NULL out the field.
 *
 * As a result we no longer need the req_kludge field because
 * the information is now contained in the attributes field:
 * 1. If it is NULL then it's the invalid omission.
 * 2. If it is empty it is the correct encoding.
 * 3. If it is not empty then some attributes are present.
 *
 */

static int rinf_cb(int operation, YASN1_VALUE **pval, const YASN1_ITEM *it,
                   void *exarg)
{
    YX509_REQ_INFO *rinf = (YX509_REQ_INFO *)*pval;

    if (operation == YASN1_OP_NEW_POST) {
        rinf->attributes = sk_YX509_ATTRIBUTE_new_null();
        if (!rinf->attributes)
            return 0;
    }
    return 1;
}

YASN1_SEQUENCE_enc(YX509_REQ_INFO, enc, rinf_cb) = {
        YASN1_SIMPLE(YX509_REQ_INFO, version, YASN1_INTEGER),
        YASN1_SIMPLE(YX509_REQ_INFO, subject, YX509_NAME),
        YASN1_SIMPLE(YX509_REQ_INFO, pubkey, YX509_PUBKEY),
        /* This isn't really OPTIONAL but it gets round invalid
         * encodings
         */
        YASN1_IMP_SET_OF_OPT(YX509_REQ_INFO, attributes, YX509_ATTRIBUTE, 0)
} YASN1_SEQUENCE_END_enc(YX509_REQ_INFO, YX509_REQ_INFO)

IMPLEMENT_YASN1_FUNCTIONS(YX509_REQ_INFO)

YASN1_SEQUENCE_ref(YX509_REQ, 0) = {
        YASN1_EMBED(YX509_REQ, req_info, YX509_REQ_INFO),
        YASN1_EMBED(YX509_REQ, sig_alg, YX509_ALGOR),
        YASN1_SIMPLE(YX509_REQ, signature, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END_ref(YX509_REQ, YX509_REQ)

IMPLEMENT_YASN1_FUNCTIONS(YX509_REQ)

IMPLEMENT_YASN1_DUP_FUNCTION(YX509_REQ)
