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

#include <openssl/asn1t.h>

/* Declarations for string types */

#define IMPLEMENT_YASN1_STRING_FUNCTIONS(sname) \
        IMPLEMENT_YASN1_TYPE(sname) \
        IMPLEMENT_YASN1_ENCODE_FUNCTIONS_fname(sname, sname, sname) \
        sname *sname##_new(void) \
        { \
                return YASN1_STRING_type_new(V_##sname); \
        } \
        void sname##_free(sname *x) \
        { \
                YASN1_STRING_free(x); \
        }

IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_OCTET_STRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_INTEGER)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_ENUMERATED)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_BIT_STRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_UTF8STRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_PRINTABLESTRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_T61STRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_IA5STRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_GENERALSTRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_UTCTIME)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_GENERALIZEDTIME)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_VISIBLESTRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_UNIVEYRSALSTRING)
IMPLEMENT_YASN1_STRING_FUNCTIONS(YASN1_BMPSTRING)

IMPLEMENT_YASN1_TYPE(YASN1_NULL)
IMPLEMENT_YASN1_FUNCTIONS(YASN1_NULL)

IMPLEMENT_YASN1_TYPE(YASN1_OBJECT)

IMPLEMENT_YASN1_TYPE(YASN1_ANY)

/* Just swallow an YASN1_SEQUENCE in an YASN1_STRING */
IMPLEMENT_YASN1_TYPE(YASN1_SEQUENCE)

IMPLEMENT_YASN1_FUNCTIONS_fname(YASN1_TYPE, YASN1_ANY, YASN1_TYPE)

/* Multistring types */

IMPLEMENT_YASN1_MSTRING(YASN1_PRINTABLE, B_YASN1_PRINTABLE)
IMPLEMENT_YASN1_FUNCTIONS_name(YASN1_STRING, YASN1_PRINTABLE)

IMPLEMENT_YASN1_MSTRING(DISPLAYTEXT, B_YASN1_DISPLAYTEXT)
IMPLEMENT_YASN1_FUNCTIONS_name(YASN1_STRING, DISPLAYTEXT)

IMPLEMENT_YASN1_MSTRING(DIRECTORYSTRING, B_YASN1_DIRECTORYSTRING)
IMPLEMENT_YASN1_FUNCTIONS_name(YASN1_STRING, DIRECTORYSTRING)

/* Three separate BOOLEAN type: normal, DEFAULT TRUE and DEFAULT FALSE */
IMPLEMENT_YASN1_TYPE_ex(YASN1_BOOLEAN, YASN1_BOOLEAN, -1)
IMPLEMENT_YASN1_TYPE_ex(YASN1_TBOOLEAN, YASN1_BOOLEAN, 1)
IMPLEMENT_YASN1_TYPE_ex(YASN1_FBOOLEAN, YASN1_BOOLEAN, 0)

/* Special, OCTET STRING with indefinite length constructed support */

IMPLEMENT_YASN1_TYPE_ex(YASN1_OCTET_STRING_NDEF, YASN1_OCTET_STRING, YASN1_TFLG_NDEF)

YASN1_ITEM_TEMPLATE(YASN1_SEQUENCE_ANY) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, YASN1_SEQUENCE_ANY, YASN1_ANY)
YASN1_ITEM_TEMPLATE_END(YASN1_SEQUENCE_ANY)

YASN1_ITEM_TEMPLATE(YASN1_SET_ANY) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SET_OF, 0, YASN1_SET_ANY, YASN1_ANY)
YASN1_ITEM_TEMPLATE_END(YASN1_SET_ANY)

IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(YASN1_SEQUENCE_ANY, YASN1_SEQUENCE_ANY, YASN1_SEQUENCE_ANY)
IMPLEMENT_YASN1_ENCODE_FUNCTIONS_const_fname(YASN1_SEQUENCE_ANY, YASN1_SET_ANY, YASN1_SET_ANY)
