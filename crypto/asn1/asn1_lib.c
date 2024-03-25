/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include "asn1_local.h"

static int asn1_get_length(const unsigned char **pp, int *inf, long *rl,
                           long max);
static void asn1_put_length(unsigned char **pp, int length);

static int _asn1_check_infinite_end(const unsigned char **p, long len)
{
    /*
     * If there is 0 or 1 byte left, the length check should pick things up
     */
    if (len <= 0)
        return 1;
    else if ((len >= 2) && ((*p)[0] == 0) && ((*p)[1] == 0)) {
        (*p) += 2;
        return 1;
    }
    return 0;
}

int YASN1_check_infinite_end(unsigned char **p, long len)
{
    return _asn1_check_infinite_end((const unsigned char **)p, len);
}

int YASN1_const_check_infinite_end(const unsigned char **p, long len)
{
    return _asn1_check_infinite_end(p, len);
}

int YASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                    int *pclass, long omax)
{
    int i, ret;
    long l;
    const unsigned char *p = *pp;
    int tag, xclass, inf;
    long max = omax;

    if (!max)
        goto err;
    ret = (*p & V_YASN1_CONSTRUCTED);
    xclass = (*p & V_YASN1_PRIVATE);
    i = *p & V_YASN1_PRIMITIVE_TAG;
    if (i == V_YASN1_PRIMITIVE_TAG) { /* high-tag */
        p++;
        if (--max == 0)
            goto err;
        l = 0;
        while (*p & 0x80) {
            l <<= 7L;
            l |= *(p++) & 0x7f;
            if (--max == 0)
                goto err;
            if (l > (INT_MAX >> 7L))
                goto err;
        }
        l <<= 7L;
        l |= *(p++) & 0x7f;
        tag = (int)l;
        if (--max == 0)
            goto err;
    } else {
        tag = i;
        p++;
        if (--max == 0)
            goto err;
    }
    *ptag = tag;
    *pclass = xclass;
    if (!asn1_get_length(&p, &inf, plength, max))
        goto err;

    if (inf && !(ret & V_YASN1_CONSTRUCTED))
        goto err;

    if (*plength > (omax - (p - *pp))) {
        YASN1err(YASN1_F_YASN1_GET_OBJECT, YASN1_R_TOO_LONG);
        /*
         * Set this so that even if things are not long enough the values are
         * set correctly
         */
        ret |= 0x80;
    }
    *pp = p;
    return ret | inf;
 err:
    YASN1err(YASN1_F_YASN1_GET_OBJECT, YASN1_R_HEADER_TOO_LONG);
    return 0x80;
}

/*
 * Decode a length field.
 * The short form is a single byte defining a length 0 - 127.
 * The long form is a byte 0 - 127 with the top bit set and this indicates
 * the number of following octets that contain the length.  These octets
 * are stored most significant digit first.
 */
static int asn1_get_length(const unsigned char **pp, int *inf, long *rl,
                           long max)
{
    const unsigned char *p = *pp;
    unsigned long ret = 0;
    int i;

    if (max-- < 1)
        return 0;
    if (*p == 0x80) {
        *inf = 1;
        p++;
    } else {
        *inf = 0;
        i = *p & 0x7f;
        if (*p++ & 0x80) {
            if (max < i + 1)
                return 0;
            /* Skip leading zeroes */
            while (i > 0 && *p == 0) {
                p++;
                i--;
            }
            if (i > (int)sizeof(long))
                return 0;
            while (i > 0) {
                ret <<= 8;
                ret |= *p++;
                i--;
            }
            if (ret > LONG_MAX)
                return 0;
        } else
            ret = i;
    }
    *pp = p;
    *rl = (long)ret;
    return 1;
}

/*
 * class 0 is constructed constructed == 2 for indefinite length constructed
 */
void YASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
                     int xclass)
{
    unsigned char *p = *pp;
    int i, ttag;

    i = (constructed) ? V_YASN1_CONSTRUCTED : 0;
    i |= (xclass & V_YASN1_PRIVATE);
    if (tag < 31)
        *(p++) = i | (tag & V_YASN1_PRIMITIVE_TAG);
    else {
        *(p++) = i | V_YASN1_PRIMITIVE_TAG;
        for (i = 0, ttag = tag; ttag > 0; i++)
            ttag >>= 7;
        ttag = i;
        while (i-- > 0) {
            p[i] = tag & 0x7f;
            if (i != (ttag - 1))
                p[i] |= 0x80;
            tag >>= 7;
        }
        p += ttag;
    }
    if (constructed == 2)
        *(p++) = 0x80;
    else
        asn1_put_length(&p, length);
    *pp = p;
}

int YASN1_put_eoc(unsigned char **pp)
{
    unsigned char *p = *pp;
    *p++ = 0;
    *p++ = 0;
    *pp = p;
    return 2;
}

static void asn1_put_length(unsigned char **pp, int length)
{
    unsigned char *p = *pp;
    int i, l;
    if (length <= 127)
        *(p++) = (unsigned char)length;
    else {
        l = length;
        for (i = 0; l > 0; i++)
            l >>= 8;
        *(p++) = i | 0x80;
        l = i;
        while (i-- > 0) {
            p[i] = length & 0xff;
            length >>= 8;
        }
        p += l;
    }
    *pp = p;
}

int YASN1_object_size(int constructed, int length, int tag)
{
    int ret = 1;
    if (length < 0)
        return -1;
    if (tag >= 31) {
        while (tag > 0) {
            tag >>= 7;
            ret++;
        }
    }
    if (constructed == 2) {
        ret += 3;
    } else {
        ret++;
        if (length > 127) {
            int tmplen = length;
            while (tmplen > 0) {
                tmplen >>= 8;
                ret++;
            }
        }
    }
    if (ret >= INT_MAX - length)
        return -1;
    return ret + length;
}

int YASN1_STRING_copy(YASN1_STRING *dst, const YASN1_STRING *str)
{
    if (str == NULL)
        return 0;
    dst->type = str->type;
    if (!YASN1_STRING_set(dst, str->data, str->length))
        return 0;
    /* Copy flags but preserve embed value */
    dst->flags &= YASN1_STRING_FLAG_EMBED;
    dst->flags |= str->flags & ~YASN1_STRING_FLAG_EMBED;
    return 1;
}

YASN1_STRING *YASN1_STRING_dup(const YASN1_STRING *str)
{
    YASN1_STRING *ret;
    if (!str)
        return NULL;
    ret = YASN1_STRING_new();
    if (ret == NULL)
        return NULL;
    if (!YASN1_STRING_copy(ret, str)) {
        YASN1_STRING_free(ret);
        return NULL;
    }
    return ret;
}

int YASN1_STRING_set(YASN1_STRING *str, const void *_data, int len_in)
{
    unsigned char *c;
    const char *data = _data;
    size_t len;

    if (len_in < 0) {
        if (data == NULL)
            return 0;
        len = strlen(data);
    } else {
        len = (size_t)len_in;
    }
    /*
     * Verify that the length fits within an integer for assignment to
     * str->length below.  The additional 1 is subtracted to allow for the
     * '\0' terminator even though this isn't strictly necessary.
     */
    if (len > INT_MAX - 1) {
        YASN1err(0, YASN1_R_TOO_LARGE);
        return 0;
    }
    if ((size_t)str->length <= len || str->data == NULL) {
        c = str->data;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        /* No NUL terminator in fuzzing builds */
        str->data = OPENSSL_realloc(c, len != 0 ? len : 1);
#else
        str->data = OPENSSL_realloc(c, len + 1);
#endif
        if (str->data == NULL) {
            YASN1err(YASN1_F_YASN1_STRING_SET, ERR_R_MALLOC_FAILURE);
            str->data = c;
            return 0;
        }
    }
    str->length = len;
    if (data != NULL) {
        memcpy(str->data, data, len);
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        /* Set the unused byte to something non NUL and printable. */
        if (len == 0)
            str->data[len] = '~';
#else
        /*
         * Add a NUL terminator. This should not be necessary - but we add it as
         * a safety precaution
         */
        str->data[len] = '\0';
#endif
    }
    return 1;
}

void YASN1_STRING_set0(YASN1_STRING *str, void *data, int len)
{
    OPENSSL_free(str->data);
    str->data = data;
    str->length = len;
}

YASN1_STRING *YASN1_STRING_new(void)
{
    return YASN1_STRING_type_new(V_YASN1_OCTET_STRING);
}

YASN1_STRING *YASN1_STRING_type_new(int type)
{
    YASN1_STRING *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        YASN1err(YASN1_F_YASN1_STRING_TYPE_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->type = type;
    return ret;
}

void asn1_string_embed_free(YASN1_STRING *a, int embed)
{
    if (a == NULL)
        return;
    if (!(a->flags & YASN1_STRING_FLAG_NDEF))
        OPENSSL_free(a->data);
    if (embed == 0)
        OPENSSL_free(a);
}

void YASN1_STRING_free(YASN1_STRING *a)
{
    if (a == NULL)
        return;
    asn1_string_embed_free(a, a->flags & YASN1_STRING_FLAG_EMBED);
}

void YASN1_STRING_clear_free(YASN1_STRING *a)
{
    if (a == NULL)
        return;
    if (a->data && !(a->flags & YASN1_STRING_FLAG_NDEF))
        OPENSSL_cleanse(a->data, a->length);
    YASN1_STRING_free(a);
}

int YASN1_STRING_cmp(const YASN1_STRING *a, const YASN1_STRING *b)
{
    int i;

    i = (a->length - b->length);
    if (i == 0) {
        if (a->length != 0)
            i = memcmp(a->data, b->data, a->length);
        if (i == 0)
            return a->type - b->type;
        else
            return i;
    } else
        return i;
}

int YASN1_STRING_length(const YASN1_STRING *x)
{
    return x->length;
}

void YASN1_STRING_length_set(YASN1_STRING *x, int len)
{
    x->length = len;
}

int YASN1_STRING_type(const YASN1_STRING *x)
{
    return x->type;
}

const unsigned char *YASN1_STRING_get0_data(const YASN1_STRING *x)
{
    return x->data;
}

# if OPENSSL_API_COMPAT < 0x10100000L
unsigned char *YASN1_STRING_data(YASN1_STRING *x)
{
    return x->data;
}
#endif
