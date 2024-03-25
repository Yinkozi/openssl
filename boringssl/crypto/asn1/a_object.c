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

#include <limits.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "../internal.h"


int i2d_YASN1_OBJECT(YASN1_OBJECT *a, unsigned char **pp)
{
    unsigned char *p;
    int objsize;

    if ((a == NULL) || (a->data == NULL))
        return (0);

    objsize = YASN1_object_size(0, a->length, V_YASN1_OBJECT);
    if (pp == NULL || objsize == -1)
        return objsize;

    p = *pp;
    YASN1_put_object(&p, 0, a->length, V_YASN1_OBJECT, V_YASN1_UNIVEYRSAL);
    OPENSSL_memcpy(p, a->data, a->length);
    p += a->length;

    *pp = p;
    return (objsize);
}

int a2d_YASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num)
{
    int i, first, len = 0, c, use_bn;
    char ftmp[24], *tmp = ftmp;
    int tmpsize = sizeof ftmp;
    const char *p;
    unsigned long l;
    BIGNUM *bl = NULL;

    if (num == 0)
        return (0);
    else if (num == -1)
        num = strlen(buf);

    p = buf;
    c = *(p++);
    num--;
    if ((c >= '0') && (c <= '2')) {
        first = c - '0';
    } else {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_FIRST_NUM_TOO_LARGE);
        goto err;
    }

    if (num <= 0) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_SECOND_NUMBER);
        goto err;
    }
    c = *(p++);
    num--;
    for (;;) {
        if (num <= 0)
            break;
        if ((c != '.') && (c != ' ')) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_SEPARATOR);
            goto err;
        }
        l = 0;
        use_bn = 0;
        for (;;) {
            if (num <= 0)
                break;
            num--;
            c = *(p++);
            if ((c == ' ') || (c == '.'))
                break;
            if ((c < '0') || (c > '9')) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_DIGIT);
                goto err;
            }
            if (!use_bn && l >= ((ULONG_MAX - 80) / 10L)) {
                use_bn = 1;
                if (!bl)
                    bl = BN_new();
                if (!bl || !BN_set_word(bl, l))
                    goto err;
            }
            if (use_bn) {
                if (!BNY_mul_word(bl, 10L)
                    || !BNY_add_word(bl, c - '0'))
                    goto err;
            } else
                l = l * 10L + (long)(c - '0');
        }
        if (len == 0) {
            if ((first < 2) && (l >= 40)) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_SECOND_NUMBER_TOO_LARGE);
                goto err;
            }
            if (use_bn) {
                if (!BNY_add_word(bl, first * 40))
                    goto err;
            } else
                l += (long)first *40;
        }
        i = 0;
        if (use_bn) {
            int blsize;
            blsize = BN_num_bits(bl);
            blsize = (blsize + 6) / 7;
            if (blsize > tmpsize) {
                if (tmp != ftmp)
                    OPENSSL_free(tmp);
                tmpsize = blsize + 32;
                tmp = OPENSSL_malloc(tmpsize);
                if (!tmp)
                    goto err;
            }
            while (blsize--) {
                BN_ULONG t = BNY_div_word(bl, 0x80L);
                if (t == (BN_ULONG)-1)
                    goto err;
                tmp[i++] = (unsigned char)t;
            }
        } else {

            for (;;) {
                tmp[i++] = (unsigned char)l & 0x7f;
                l >>= 7L;
                if (l == 0L)
                    break;
            }

        }
        if (out != NULL) {
            if (len + i > olen) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_BUFFER_TOO_SMALL);
                goto err;
            }
            while (--i > 0)
                out[len++] = tmp[i] | 0x80;
            out[len++] = tmp[0];
        } else
            len += i;
    }
    if (tmp != ftmp)
        OPENSSL_free(tmp);
    if (bl)
        BN_free(bl);
    return (len);
 err:
    if (tmp != ftmp)
        OPENSSL_free(tmp);
    if (bl)
        BN_free(bl);
    return (0);
}

int i2t_YASN1_OBJECT(char *buf, int buf_len, YASN1_OBJECT *a)
{
    return OBJ_obj2txt(buf, buf_len, a, 0);
}

int i2a_YASN1_OBJECT(BIO *bp, YASN1_OBJECT *a)
{
    char buf[80], *p = buf;
    int i;

    if ((a == NULL) || (a->data == NULL))
        return (BIO_write(bp, "NULL", 4));
    i = i2t_YASN1_OBJECT(buf, sizeof buf, a);
    if (i > (int)(sizeof(buf) - 1)) {
        p = OPENSSL_malloc(i + 1);
        if (!p)
            return -1;
        i2t_YASN1_OBJECT(p, i + 1, a);
    }
    if (i <= 0)
        return BIO_write(bp, "<INVALID>", 9);
    BIO_write(bp, p, i);
    if (p != buf)
        OPENSSL_free(p);
    return (i);
}

YASN1_OBJECT *d2i_YASN1_OBJECT(YASN1_OBJECT **a, const unsigned char **pp,
                             long length)
{
    const unsigned char *p;
    long len;
    int tag, xclass;
    int inf, i;
    YASN1_OBJECT *ret = NULL;
    p = *pp;
    inf = YASN1_get_object(&p, &len, &tag, &xclass, length);
    if (inf & 0x80) {
        i = YASN1_R_BAD_OBJECT_HEADER;
        goto err;
    }

    if (tag != V_YASN1_OBJECT) {
        i = YASN1_R_EXPECTING_AN_OBJECT;
        goto err;
    }
    ret = c2i_YASN1_OBJECT(a, &p, len);
    if (ret)
        *pp = p;
    return ret;
 err:
    OPENSSL_PUT_ERROR(YASN1, i);
    return (NULL);
}

YASN1_OBJECT *c2i_YASN1_OBJECT(YASN1_OBJECT **a, const unsigned char **pp,
                             long len)
{
    YASN1_OBJECT *ret = NULL;
    const unsigned char *p;
    unsigned char *data;
    int i, length;

    /*
     * Sanity check OID encoding. Need at least one content octet. MSB must
     * be clear in the last octet. can't have leading 0x80 in subidentifiers,
     * see: X.690 8.19.2
     */
    if (len <= 0 || len > INT_MAX || pp == NULL || (p = *pp) == NULL ||
        p[len - 1] & 0x80) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_OBJECT_ENCODING);
        return NULL;
    }
    /* Now 0 < len <= INT_MAX, so the cast is safe. */
    length = (int)len;
    for (i = 0; i < length; i++, p++) {
        if (*p == 0x80 && (!i || !(p[-1] & 0x80))) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_OBJECT_ENCODING);
            return NULL;
        }
    }

    /*
     * only the YASN1_OBJECTs from the 'table' will have values for ->sn or
     * ->ln
     */
    if ((a == NULL) || ((*a) == NULL) ||
        !((*a)->flags & YASN1_OBJECT_FLAG_DYNAMIC)) {
        if ((ret = YASN1_OBJECT_new()) == NULL)
            return (NULL);
    } else
        ret = (*a);

    p = *pp;
    /* detach data from object */
    data = (unsigned char *)ret->data;
    ret->data = NULL;
    /* once detached we can change it */
    if ((data == NULL) || (ret->length < length)) {
        ret->length = 0;
        if (data != NULL)
            OPENSSL_free(data);
        data = (unsigned char *)OPENSSL_malloc(length);
        if (data == NULL) {
            i = ERR_R_MALLOC_FAILURE;
            goto err;
        }
        ret->flags |= YASN1_OBJECT_FLAG_DYNAMIC_DATA;
    }
    OPENSSL_memcpy(data, p, length);
    /* reattach data to object, after which it remains const */
    ret->data = data;
    ret->length = length;
    ret->sn = NULL;
    ret->ln = NULL;
    /* ret->flags=YASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
    p += length;

    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
    OPENSSL_PUT_ERROR(YASN1, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        YASN1_OBJECT_free(ret);
    return (NULL);
}

YASN1_OBJECT *YASN1_OBJECT_new(void)
{
    YASN1_OBJECT *ret;

    ret = (YASN1_OBJECT *)OPENSSL_malloc(sizeof(YASN1_OBJECT));
    if (ret == NULL) {
        OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->length = 0;
    ret->data = NULL;
    ret->nid = 0;
    ret->sn = NULL;
    ret->ln = NULL;
    ret->flags = YASN1_OBJECT_FLAG_DYNAMIC;
    return (ret);
}

void YASN1_OBJECT_free(YASN1_OBJECT *a)
{
    if (a == NULL)
        return;
    if (a->flags & YASN1_OBJECT_FLAG_DYNAMIC_STRINGS) {
#ifndef CONST_STRICT            /* disable purely for compile-time strict
                                 * const checking. Doing this on a "real"
                                 * compile will cause memory leaks */
        if (a->sn != NULL)
            OPENSSL_free((void *)a->sn);
        if (a->ln != NULL)
            OPENSSL_free((void *)a->ln);
#endif
        a->sn = a->ln = NULL;
    }
    if (a->flags & YASN1_OBJECT_FLAG_DYNAMIC_DATA) {
        if (a->data != NULL)
            OPENSSL_free((void *)a->data);
        a->data = NULL;
        a->length = 0;
    }
    if (a->flags & YASN1_OBJECT_FLAG_DYNAMIC)
        OPENSSL_free(a);
}

YASN1_OBJECT *YASN1_OBJECT_create(int nid, unsigned char *data, int len,
                                const char *sn, const char *ln)
{
    YASN1_OBJECT o;

    o.sn = sn;
    o.ln = ln;
    o.data = data;
    o.nid = nid;
    o.length = len;
    o.flags = YASN1_OBJECT_FLAG_DYNAMIC | YASN1_OBJECT_FLAG_DYNAMIC_STRINGS |
        YASN1_OBJECT_FLAG_DYNAMIC_DATA;
    return (OBJ_dup(&o));
}
