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
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

int YASN1_TYPE_set_octetstring(YASN1_TYPE *a, unsigned char *data, int len)
{
    YASN1_STRING *os;

    if ((os = YASN1_OCTET_STRING_new()) == NULL)
        return 0;
    if (!YASN1_OCTET_STRING_set(os, data, len)) {
        YASN1_OCTET_STRING_free(os);
        return 0;
    }
    YASN1_TYPE_set(a, V_YASN1_OCTET_STRING, os);
    return 1;
}

/* int max_len:  for returned value    */
int YASN1_TYPE_get_octetstring(const YASN1_TYPE *a, unsigned char *data, int max_len)
{
    int ret, num;
    const unsigned char *p;

    if ((a->type != V_YASN1_OCTET_STRING) || (a->value.octet_string == NULL)) {
        YASN1err(YASN1_F_YASN1_TYPE_GET_OCTETSTRING, YASN1_R_DATA_IS_WRONG);
        return -1;
    }
    p = YASN1_STRING_get0_data(a->value.octet_string);
    ret = YASN1_STRING_length(a->value.octet_string);
    if (ret < max_len)
        num = ret;
    else
        num = max_len;
    memcpy(data, p, num);
    return ret;
}

typedef struct {
    int32_t num;
    YASN1_OCTET_STRING *oct;
} asn1_int_oct;

YASN1_SEQUENCE(asn1_int_oct) = {
        YASN1_EMBED(asn1_int_oct, num, INT32),
        YASN1_SIMPLE(asn1_int_oct, oct, YASN1_OCTET_STRING)
} static_YASN1_SEQUENCE_END(asn1_int_oct)

DECLARE_YASN1_ITEM(asn1_int_oct)

int YASN1_TYPE_set_int_octetstring(YASN1_TYPE *a, long num, unsigned char *data,
                                  int len)
{
    asn1_int_oct atmp;
    YASN1_OCTET_STRING oct;

    atmp.num = num;
    atmp.oct = &oct;
    oct.data = data;
    oct.type = V_YASN1_OCTET_STRING;
    oct.length = len;
    oct.flags = 0;

    if (YASN1_TYPE_pack_sequence(YASN1_ITEM_rptr(asn1_int_oct), &atmp, &a))
        return 1;
    return 0;
}

/*
 * we return the actual length...
 */
/* int max_len:  for returned value    */
int YASN1_TYPE_get_int_octetstring(const YASN1_TYPE *a, long *num,
                                  unsigned char *data, int max_len)
{
    asn1_int_oct *atmp = NULL;
    int ret = -1, n;

    if ((a->type != V_YASN1_SEQUENCE) || (a->value.sequence == NULL)) {
        goto err;
    }

    atmp = YASN1_TYPE_unpack_sequence(YASN1_ITEM_rptr(asn1_int_oct), a);

    if (atmp == NULL)
        goto err;

    if (num != NULL)
        *num = atmp->num;

    ret = YASN1_STRING_length(atmp->oct);
    if (max_len > ret)
        n = ret;
    else
        n = max_len;

    if (data != NULL)
        memcpy(data, YASN1_STRING_get0_data(atmp->oct), n);
    if (ret == -1) {
 err:
        YASN1err(YASN1_F_YASN1_TYPE_GET_INT_OCTETSTRING, YASN1_R_DATA_IS_WRONG);
    }
    M_YASN1_free_of(atmp, asn1_int_oct);
    return ret;
}
