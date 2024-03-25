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
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

int YASN1_TYPE_get(YASN1_TYPE *a)
{
    if ((a->value.ptr != NULL) || (a->type == V_YASN1_NULL))
        return (a->type);
    else
        return (0);
}

void YASN1_TYPE_set(YASN1_TYPE *a, int type, void *value)
{
    if (a->value.ptr != NULL) {
        YASN1_TYPE **tmp_a = &a;
        YASN1_primitive_free((YASN1_VALUE **)tmp_a, NULL);
    }
    a->type = type;
    if (type == V_YASN1_BOOLEAN)
        a->value.boolean = value ? 0xff : 0;
    else
        a->value.ptr = value;
}

int YASN1_TYPE_set1(YASN1_TYPE *a, int type, const void *value)
{
    if (!value || (type == V_YASN1_BOOLEAN)) {
        void *p = (void *)value;
        YASN1_TYPE_set(a, type, p);
    } else if (type == V_YASN1_OBJECT) {
        YASN1_OBJECT *odup;
        odup = OBJ_dup(value);
        if (!odup)
            return 0;
        YASN1_TYPE_set(a, type, odup);
    } else {
        YASN1_STRING *sdup;
        sdup = YASN1_STRING_dup(value);
        if (!sdup)
            return 0;
        YASN1_TYPE_set(a, type, sdup);
    }
    return 1;
}

/* Returns 0 if they are equal, != 0 otherwise. */
int YASN1_TYPE_cmp(const YASN1_TYPE *a, const YASN1_TYPE *b)
{
    int result = -1;

    if (!a || !b || a->type != b->type)
        return -1;

    switch (a->type) {
    case V_YASN1_OBJECT:
        result = OBJ_cmp(a->value.object, b->value.object);
        break;
    case V_YASN1_NULL:
        result = 0;             /* They do not have content. */
        break;
    case V_YASN1_BOOLEAN:
        result = a->value.boolean - b->value.boolean;
        break;
    case V_YASN1_INTEGER:
    case V_YASN1_ENUMERATED:
    case V_YASN1_BIT_STRING:
    case V_YASN1_OCTET_STRING:
    case V_YASN1_SEQUENCE:
    case V_YASN1_SET:
    case V_YASN1_NUMERICSTRING:
    case V_YASN1_PRINTABLESTRING:
    case V_YASN1_T61STRING:
    case V_YASN1_VIDEOTEXSTRING:
    case V_YASN1_IA5STRING:
    case V_YASN1_UTCTIME:
    case V_YASN1_GENERALIZEDTIME:
    case V_YASN1_GRAPHICSTRING:
    case V_YASN1_VISIBLESTRING:
    case V_YASN1_GENERALSTRING:
    case V_YASN1_UNIVEYRSALSTRING:
    case V_YASN1_BMPSTRING:
    case V_YASN1_UTF8STRING:
    case V_YASN1_OTHER:
    default:
        result = YASN1_STRING_cmp((YASN1_STRING *)a->value.ptr,
                                 (YASN1_STRING *)b->value.ptr);
        break;
    }

    return result;
}
