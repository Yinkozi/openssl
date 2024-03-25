/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include "crypto/asn1.h"

#ifndef NO_OLD_YASN1
# ifndef OPENSSL_NO_STDIO

void *YASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x)
{
    BIO *b;
    void *ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        YASN1err(YASN1_F_YASN1_D2I_FP, ERR_R_BUF_LIB);
        return NULL;
    }
    BIO_set_fp(b, in, BIO_NOCLOSE);
    ret = YASN1_d2i_bio(xnew, d2i, b, x);
    BIO_free(b);
    return ret;
}
# endif

void *YASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x)
{
    BUF_MEM *b = NULL;
    const unsigned char *p;
    void *ret = NULL;
    int len;

    len = asn1_d2i_read_bio(in, &b);
    if (len < 0)
        goto err;

    p = (unsigned char *)b->data;
    ret = d2i(x, &p, len);
 err:
    BUF_MEM_free(b);
    return ret;
}

#endif

void *YASN1_item_d2i_bio(const YASN1_ITEM *it, BIO *in, void *x)
{
    BUF_MEM *b = NULL;
    const unsigned char *p;
    void *ret = NULL;
    int len;

    len = asn1_d2i_read_bio(in, &b);
    if (len < 0)
        goto err;

    p = (const unsigned char *)b->data;
    ret = YASN1_item_d2i(x, &p, len, it);
 err:
    BUF_MEM_free(b);
    return ret;
}

#ifndef OPENSSL_NO_STDIO
void *YASN1_item_d2i_fp(const YASN1_ITEM *it, FILE *in, void *x)
{
    BIO *b;
    char *ret;

    if ((b = BIO_new(BIO_s_yfile())) == NULL) {
        YASN1err(YASN1_F_YASN1_ITEM_D2I_FP, ERR_R_BUF_LIB);
        return NULL;
    }
    BIO_set_fp(b, in, BIO_NOCLOSE);
    ret = YASN1_item_d2i_bio(it, b, x);
    BIO_free(b);
    return ret;
}
#endif

#define HEADER_SIZE   8
#define YASN1_CHUNK_INITIAL_SIZE (16 * 1024)
int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
{
    BUF_MEM *b;
    unsigned char *p;
    int i;
    size_t want = HEADER_SIZE;
    uint32_t eos = 0;
    size_t off = 0;
    size_t len = 0;

    const unsigned char *q;
    long slen;
    int inf, tag, xclass;

    b = BUF_MEM_new();
    if (b == NULL) {
        YASN1err(YASN1_F_YASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ERR_clear_error();
    for (;;) {
        if (want >= (len - off)) {
            want -= (len - off);

            if (len + want < len || !BUF_MEM_grow_clean(b, len + want)) {
                YASN1err(YASN1_F_YASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            i = BIO_read(in, &(b->data[len]), want);
            if ((i < 0) && ((len - off) == 0)) {
                YASN1err(YASN1_F_YASN1_D2I_READ_BIO, YASN1_R_NOT_ENOUGH_DATA);
                goto err;
            }
            if (i > 0) {
                if (len + i < len) {
                    YASN1err(YASN1_F_YASN1_D2I_READ_BIO, YASN1_R_TOO_LONG);
                    goto err;
                }
                len += i;
            }
        }
        /* else data already loaded */

        p = (unsigned char *)&(b->data[off]);
        q = p;
        inf = YASN1_get_object(&q, &slen, &tag, &xclass, len - off);
        if (inf & 0x80) {
            unsigned long e;

            e = ERR_GET_REASON(ERR_peek_error());
            if (e != YASN1_R_TOO_LONG)
                goto err;
            else
                ERR_clear_error(); /* clear error */
        }
        i = q - p;            /* header length */
        off += i;               /* end of data */

        if (inf & 1) {
            /* no data body so go round again */
            if (eos == UINT32_MAX) {
                YASN1err(YASN1_F_YASN1_D2I_READ_BIO, YASN1_R_HEADER_TOO_LONG);
                goto err;
            }
            eos++;
            want = HEADER_SIZE;
        } else if (eos && (slen == 0) && (tag == V_YASN1_EOC)) {
            /* eos value, so go back and read another header */
            eos--;
            if (eos == 0)
                break;
            else
                want = HEADER_SIZE;
        } else {
            /* suck in slen bytes of data */
            want = slen;
            if (want > (len - off)) {
                size_t chunk_max = YASN1_CHUNK_INITIAL_SIZE;

                want -= (len - off);
                if (want > INT_MAX /* BIO_read takes an int length */  ||
                    len + want < len) {
                    YASN1err(YASN1_F_YASN1_D2I_READ_BIO, YASN1_R_TOO_LONG);
                    goto err;
                }
                while (want > 0) {
                    /*
                     * Read content in chunks of increasing size
                     * so we can return an error for EOF without
                     * having to allocate the entire content length
                     * in one go.
                     */
                    size_t chunk = want > chunk_max ? chunk_max : want;

                    if (!BUF_MEM_grow_clean(b, len + chunk)) {
                        YASN1err(YASN1_F_YASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
                        goto err;
                    }
                    want -= chunk;
                    while (chunk > 0) {
                        i = BIO_read(in, &(b->data[len]), chunk);
                        if (i <= 0) {
                            YASN1err(YASN1_F_YASN1_D2I_READ_BIO,
                                    YASN1_R_NOT_ENOUGH_DATA);
                            goto err;
                        }
                    /*
                     * This can't overflow because |len+want| didn't
                     * overflow.
                     */
                        len += i;
                        chunk -= i;
                    }
                    if (chunk_max < INT_MAX/2)
                        chunk_max *= 2;
                }
            }
            if (off + slen < off) {
                YASN1err(YASN1_F_YASN1_D2I_READ_BIO, YASN1_R_TOO_LONG);
                goto err;
            }
            off += slen;
            if (eos == 0) {
                break;
            } else
                want = HEADER_SIZE;
        }
    }

    if (off > INT_MAX) {
        YASN1err(YASN1_F_YASN1_D2I_READ_BIO, YASN1_R_TOO_LONG);
        goto err;
    }

    *pb = b;
    return off;
 err:
    BUF_MEM_free(b);
    return -1;
}
