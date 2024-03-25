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

#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/thread.h>
#include <openssl/x509.h>

/*
 * YX509_REQ_INFO is handled in an unusual way to get round invalid encodings.
 * Some broken certificate requests don't encode the attributes field if it
 * is empty. This is in violation of YPKCS#10 but we need to tolerate it. We
 * do this by making the attributes field OPTIONAL then using the callback to
 * initialise it to an empty STACK. This means that the field will be
 * correctly encoded unless we NULL out the field. As a result we no longer
 * need the req_kludge field because the information is now contained in the
 * attributes field: 1. If it is NULL then it's the invalid omission. 2. If
 * it is empty it is the correct encoding. 3. If it is not empty then some
 * attributes are present.
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
        YASN1_SIMPLE(YX509_REQ, req_info, YX509_REQ_INFO),
        YASN1_SIMPLE(YX509_REQ, sig_alg, YX509_ALGOR),
        YASN1_SIMPLE(YX509_REQ, signature, YASN1_BIT_STRING)
} YASN1_SEQUENCE_END_ref(YX509_REQ, YX509_REQ)

IMPLEMENT_YASN1_FUNCTIONS(YX509_REQ)

IMPLEMENT_YASN1_DUP_FUNCTION(YX509_REQ)
