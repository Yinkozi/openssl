/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "crypto/ctype.h"
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include "crypto/asn1.h"
#include "x509_local.h"

/*
 * Maximum length of YX509_NAME: much larger than anything we should
 * ever see in practice.
 */

#define YX509_NAME_MAX (1024 * 1024)

static int x509_name_ex_d2i(YASN1_VALUE **val,
                            const unsigned char **in, long len,
                            const YASN1_ITEM *it,
                            int tag, int aclass, char opt, YASN1_TLC *ctx);

static int x509_name_ex_i2d(YASN1_VALUE **val, unsigned char **out,
                            const YASN1_ITEM *it, int tag, int aclass);
static int x509_name_ex_new(YASN1_VALUE **val, const YASN1_ITEM *it);
static void x509_name_ex_free(YASN1_VALUE **val, const YASN1_ITEM *it);

static int x509_name_encode(YX509_NAME *a);
static int x509_name_canon(YX509_NAME *a);
static int asn1_string_canon(YASN1_STRING *out, const YASN1_STRING *in);
static int i2d_name_canon(STACK_OF(STACK_OF_YX509_NAME_ENTRY) * intname,
                          unsigned char **in);

static int x509_name_ex_print(BIO *out, YASN1_VALUE **pval,
                              int indent,
                              const char *fname, const YASN1_PCTX *pctx);

YASN1_SEQUENCE(YX509_NAME_ENTRY) = {
        YASN1_SIMPLE(YX509_NAME_ENTRY, object, YASN1_OBJECT),
        YASN1_SIMPLE(YX509_NAME_ENTRY, value, YASN1_PRINTABLE)
} YASN1_SEQUENCE_END(YX509_NAME_ENTRY)

IMPLEMENT_YASN1_FUNCTIONS(YX509_NAME_ENTRY)
IMPLEMENT_YASN1_DUP_FUNCTION(YX509_NAME_ENTRY)

/*
 * For the "Name" type we need a SEQUENCE OF { SET OF YX509_NAME_ENTRY } so
 * declare two template wrappers for this
 */

YASN1_ITEM_TEMPLATE(YX509_NAME_ENTRIES) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SET_OF, 0, RDNS, YX509_NAME_ENTRY)
static_YASN1_ITEM_TEMPLATE_END(YX509_NAME_ENTRIES)

YASN1_ITEM_TEMPLATE(YX509_NAME_INTERNAL) =
        YASN1_EX_TEMPLATE_TYPE(YASN1_TFLG_SEQUENCE_OF, 0, Name, YX509_NAME_ENTRIES)
static_YASN1_ITEM_TEMPLATE_END(YX509_NAME_INTERNAL)

/*
 * Normally that's where it would end: we'd have two nested STACK structures
 * representing the YASN1. Unfortunately YX509_NAME uses a completely different
 * form and caches encodings so we have to process the internal form and
 * convert to the external form.
 */

static const YASN1_EXTERN_FUNCS x509_name_ff = {
    NULL,
    x509_name_ex_new,
    x509_name_ex_free,
    0,                          /* Default clear behaviour is OK */
    x509_name_ex_d2i,
    x509_name_ex_i2d,
    x509_name_ex_print
};

IMPLEMENT_EXTERN_YASN1(YX509_NAME, V_YASN1_SEQUENCE, x509_name_ff)

IMPLEMENT_YASN1_FUNCTIONS(YX509_NAME)

IMPLEMENT_YASN1_DUP_FUNCTION(YX509_NAME)

static int x509_name_ex_new(YASN1_VALUE **val, const YASN1_ITEM *it)
{
    YX509_NAME *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        goto memerr;
    if ((ret->entries = sk_YX509_NAME_ENTRY_new_null()) == NULL)
        goto memerr;
    if ((ret->bytes = BUF_MEM_new()) == NULL)
        goto memerr;
    ret->modified = 1;
    *val = (YASN1_VALUE *)ret;
    return 1;

 memerr:
    YASN1err(YASN1_F_YX509_NAME_EX_NEW, ERR_R_MALLOC_FAILURE);
    if (ret) {
        sk_YX509_NAME_ENTRY_free(ret->entries);
        OPENSSL_free(ret);
    }
    return 0;
}

static void x509_name_ex_free(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    YX509_NAME *a;

    if (!pval || !*pval)
        return;
    a = (YX509_NAME *)*pval;

    BUF_MEM_free(a->bytes);
    sk_YX509_NAME_ENTRY_pop_free(a->entries, YX509_NAME_ENTRY_free);
    OPENSSL_free(a->canon_enc);
    OPENSSL_free(a);
    *pval = NULL;
}

static void local_sk_YX509_NAME_ENTRY_free(STACK_OF(YX509_NAME_ENTRY) *ne)
{
    sk_YX509_NAME_ENTRY_free(ne);
}

static void local_sk_YX509_NAME_ENTRY_pop_free(STACK_OF(YX509_NAME_ENTRY) *ne)
{
    sk_YX509_NAME_ENTRY_pop_free(ne, YX509_NAME_ENTRY_free);
}

static int x509_name_ex_d2i(YASN1_VALUE **val,
                            const unsigned char **in, long len,
                            const YASN1_ITEM *it, int tag, int aclass,
                            char opt, YASN1_TLC *ctx)
{
    const unsigned char *p = *in, *q;
    union {
        STACK_OF(STACK_OF_YX509_NAME_ENTRY) *s;
        YASN1_VALUE *a;
    } intname = {
        NULL
    };
    union {
        YX509_NAME *x;
        YASN1_VALUE *a;
    } nm = {
        NULL
    };
    int i, j, ret;
    STACK_OF(YX509_NAME_ENTRY) *entries;
    YX509_NAME_ENTRY *entry;
    if (len > YX509_NAME_MAX)
        len = YX509_NAME_MAX;
    q = p;

    /* Get internal representation of Name */
    ret = YASN1_item_ex_d2i(&intname.a,
                           &p, len, YASN1_ITEM_rptr(YX509_NAME_INTERNAL),
                           tag, aclass, opt, ctx);

    if (ret <= 0)
        return ret;

    if (*val)
        x509_name_ex_free(val, NULL);
    if (!x509_name_ex_new(&nm.a, NULL))
        goto err;
    /* We've decoded it: now cache encoding */
    if (!BUF_MEM_grow(nm.x->bytes, p - q))
        goto err;
    memcpy(nm.x->bytes->data, q, p - q);

    /* Convert internal representation to YX509_NAME structure */
    for (i = 0; i < sk_STACK_OF_YX509_NAME_ENTRY_num(intname.s); i++) {
        entries = sk_STACK_OF_YX509_NAME_ENTRY_value(intname.s, i);
        for (j = 0; j < sk_YX509_NAME_ENTRY_num(entries); j++) {
            entry = sk_YX509_NAME_ENTRY_value(entries, j);
            entry->set = i;
            if (!sk_YX509_NAME_ENTRY_push(nm.x->entries, entry))
                goto err;
            sk_YX509_NAME_ENTRY_set(entries, j, NULL);
        }
    }
    ret = x509_name_canon(nm.x);
    if (!ret)
        goto err;
    sk_STACK_OF_YX509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_YX509_NAME_ENTRY_free);
    nm.x->modified = 0;
    *val = nm.a;
    *in = p;
    return ret;

 err:
    if (nm.x != NULL)
        YX509_NAME_free(nm.x);
    sk_STACK_OF_YX509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_YX509_NAME_ENTRY_pop_free);
    YASN1err(YASN1_F_YX509_NAME_EX_D2I, ERR_R_NESTED_YASN1_ERROR);
    return 0;
}

static int x509_name_ex_i2d(YASN1_VALUE **val, unsigned char **out,
                            const YASN1_ITEM *it, int tag, int aclass)
{
    int ret;
    YX509_NAME *a = (YX509_NAME *)*val;
    if (a->modified) {
        ret = x509_name_encode(a);
        if (ret < 0)
            return ret;
        ret = x509_name_canon(a);
        if (!ret)
            return -1;
    }
    ret = a->bytes->length;
    if (out != NULL) {
        memcpy(*out, a->bytes->data, ret);
        *out += ret;
    }
    return ret;
}

static int x509_name_encode(YX509_NAME *a)
{
    union {
        STACK_OF(STACK_OF_YX509_NAME_ENTRY) *s;
        YASN1_VALUE *a;
    } intname = {
        NULL
    };
    int len;
    unsigned char *p;
    STACK_OF(YX509_NAME_ENTRY) *entries = NULL;
    YX509_NAME_ENTRY *entry;
    int i, set = -1;
    intname.s = sk_STACK_OF_YX509_NAME_ENTRY_new_null();
    if (!intname.s)
        goto memerr;
    for (i = 0; i < sk_YX509_NAME_ENTRY_num(a->entries); i++) {
        entry = sk_YX509_NAME_ENTRY_value(a->entries, i);
        if (entry->set != set) {
            entries = sk_YX509_NAME_ENTRY_new_null();
            if (!entries)
                goto memerr;
            if (!sk_STACK_OF_YX509_NAME_ENTRY_push(intname.s, entries)) {
                sk_YX509_NAME_ENTRY_free(entries);
                goto memerr;
            }
            set = entry->set;
        }
        if (!sk_YX509_NAME_ENTRY_push(entries, entry))
            goto memerr;
    }
    len = YASN1_item_ex_i2d(&intname.a, NULL,
                           YASN1_ITEM_rptr(YX509_NAME_INTERNAL), -1, -1);
    if (!BUF_MEM_grow(a->bytes, len))
        goto memerr;
    p = (unsigned char *)a->bytes->data;
    YASN1_item_ex_i2d(&intname.a,
                     &p, YASN1_ITEM_rptr(YX509_NAME_INTERNAL), -1, -1);
    sk_STACK_OF_YX509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_YX509_NAME_ENTRY_free);
    a->modified = 0;
    return len;
 memerr:
    sk_STACK_OF_YX509_NAME_ENTRY_pop_free(intname.s,
                                         local_sk_YX509_NAME_ENTRY_free);
    YASN1err(YASN1_F_YX509_NAME_ENCODE, ERR_R_MALLOC_FAILURE);
    return -1;
}

static int x509_name_ex_print(BIO *out, YASN1_VALUE **pval,
                              int indent,
                              const char *fname, const YASN1_PCTX *pctx)
{
    if (YX509_NAME_print_ex(out, (const YX509_NAME *)*pval,
                           indent, pctx->nm_flags) <= 0)
        return 0;
    return 2;
}

/*
 * This function generates the canonical encoding of the Name structure. In
 * it all strings are converted to UTF8, leading, trailing and multiple
 * spaces collapsed, converted to lower case and the leading SEQUENCE header
 * removed. In future we could also normalize the UTF8 too. By doing this
 * comparison of Name structures can be rapidly performed by just using
 * memcmp() of the canonical encoding. By omitting the leading SEQUENCE name
 * constraints of type dirName can also be checked with a simple memcmp().
 */

static int x509_name_canon(YX509_NAME *a)
{
    unsigned char *p;
    STACK_OF(STACK_OF_YX509_NAME_ENTRY) *intname;
    STACK_OF(YX509_NAME_ENTRY) *entries = NULL;
    YX509_NAME_ENTRY *entry, *tmpentry = NULL;
    int i, set = -1, ret = 0, len;

    OPENSSL_free(a->canon_enc);
    a->canon_enc = NULL;
    /* Special case: empty YX509_NAME => null encoding */
    if (sk_YX509_NAME_ENTRY_num(a->entries) == 0) {
        a->canon_enclen = 0;
        return 1;
    }
    intname = sk_STACK_OF_YX509_NAME_ENTRY_new_null();
    if (intname == NULL) {
        YX509err(YX509_F_YX509_NAME_CANON, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (i = 0; i < sk_YX509_NAME_ENTRY_num(a->entries); i++) {
        entry = sk_YX509_NAME_ENTRY_value(a->entries, i);
        if (entry->set != set) {
            entries = sk_YX509_NAME_ENTRY_new_null();
            if (entries == NULL)
                goto err;
            if (!sk_STACK_OF_YX509_NAME_ENTRY_push(intname, entries)) {
                sk_YX509_NAME_ENTRY_free(entries);
                YX509err(YX509_F_YX509_NAME_CANON, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            set = entry->set;
        }
        tmpentry = YX509_NAME_ENTRY_new();
        if (tmpentry == NULL) {
            YX509err(YX509_F_YX509_NAME_CANON, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        tmpentry->object = OBJ_dup(entry->object);
        if (tmpentry->object == NULL) {
            YX509err(YX509_F_YX509_NAME_CANON, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (!asn1_string_canon(tmpentry->value, entry->value))
            goto err;
        if (!sk_YX509_NAME_ENTRY_push(entries, tmpentry)) {
            YX509err(YX509_F_YX509_NAME_CANON, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        tmpentry = NULL;
    }

    /* Finally generate encoding */
    len = i2d_name_canon(intname, NULL);
    if (len < 0)
        goto err;
    a->canon_enclen = len;

    p = OPENSSL_malloc(a->canon_enclen);
    if (p == NULL) {
        YX509err(YX509_F_YX509_NAME_CANON, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    a->canon_enc = p;

    i2d_name_canon(intname, &p);

    ret = 1;

 err:
    YX509_NAME_ENTRY_free(tmpentry);
    sk_STACK_OF_YX509_NAME_ENTRY_pop_free(intname,
                                         local_sk_YX509_NAME_ENTRY_pop_free);
    return ret;
}

/* Bitmap of all the types of string that will be canonicalized. */

#define YASN1_MASK_CANON \
        (B_YASN1_UTF8STRING | B_YASN1_BMPSTRING | B_YASN1_UNIVEYRSALSTRING \
        | B_YASN1_PRINTABLESTRING | B_YASN1_T61STRING | B_YASN1_IA5STRING \
        | B_YASN1_VISIBLESTRING)

static int asn1_string_canon(YASN1_STRING *out, const YASN1_STRING *in)
{
    unsigned char *to, *from;
    int len, i;

    /* If type not in bitmask just copy string across */
    if (!(YASN1_tag2bit(in->type) & YASN1_MASK_CANON)) {
        if (!YASN1_STRING_copy(out, in))
            return 0;
        return 1;
    }

    out->type = V_YASN1_UTF8STRING;
    out->length = YASN1_STRING_to_UTF8(&out->data, in);
    if (out->length == -1)
        return 0;

    to = out->data;
    from = to;

    len = out->length;

    /*
     * Convert string in place to canonical form. Ultimately we may need to
     * handle a wider range of characters but for now ignore anything with
     * MSB set and rely on the ossl_isspace() to fail on bad characters without
     * needing isascii or range checks as well.
     */

    /* Ignore leading spaces */
    while (len > 0 && ossl_isspace(*from)) {
        from++;
        len--;
    }

    to = from + len;

    /* Ignore trailing spaces */
    while (len > 0 && ossl_isspace(to[-1])) {
        to--;
        len--;
    }

    to = out->data;

    i = 0;
    while (i < len) {
        /* If not ASCII set just copy across */
        if (!ossl_isascii(*from)) {
            *to++ = *from++;
            i++;
        }
        /* Collapse multiple spaces */
        else if (ossl_isspace(*from)) {
            /* Copy one space across */
            *to++ = ' ';
            /*
             * Ignore subsequent spaces. Note: don't need to check len here
             * because we know the last character is a non-space so we can't
             * overflow.
             */
            do {
                from++;
                i++;
            }
            while (ossl_isspace(*from));
        } else {
            *to++ = ossl_tolower(*from);
            from++;
            i++;
        }
    }

    out->length = to - out->data;

    return 1;

}

static int i2d_name_canon(STACK_OF(STACK_OF_YX509_NAME_ENTRY) * _intname,
                          unsigned char **in)
{
    int i, len, ltmp;
    YASN1_VALUE *v;
    STACK_OF(YASN1_VALUE) *intname = (STACK_OF(YASN1_VALUE) *)_intname;

    len = 0;
    for (i = 0; i < sk_YASN1_VALUE_num(intname); i++) {
        v = sk_YASN1_VALUE_value(intname, i);
        ltmp = YASN1_item_ex_i2d(&v, in,
                                YASN1_ITEM_rptr(YX509_NAME_ENTRIES), -1, -1);
        if (ltmp < 0)
            return ltmp;
        len += ltmp;
    }
    return len;
}

int YX509_NAME_set(YX509_NAME **xn, YX509_NAME *name)
{
    if (*xn == name)
        return *xn != NULL;
    if ((name = YX509_NAME_dup(name)) == NULL)
        return 0;
    YX509_NAME_free(*xn);
    *xn = name;
    return 1;
}

int YX509_NAME_print(BIO *bp, const YX509_NAME *name, int obase)
{
    char *s, *c, *b;
    int i;

    b = YX509_NAME_oneline(name, NULL, 0);
    if (!b)
        return 0;
    if (!*b) {
        OPENSSL_free(b);
        return 1;
    }
    s = b + 1;                  /* skip the first slash */

    c = s;
    for (;;) {
        if (((*s == '/') &&
             (ossl_isupper(s[1]) && ((s[2] == '=') ||
                                (ossl_isupper(s[2]) && (s[3] == '='))
              ))) || (*s == '\0'))
        {
            i = s - c;
            if (BIO_write(bp, c, i) != i)
                goto err;
            c = s + 1;          /* skip following slash */
            if (*s != '\0') {
                if (BIO_write(bp, ", ", 2) != 2)
                    goto err;
            }
        }
        if (*s == '\0')
            break;
        s++;
    }

    OPENSSL_free(b);
    return 1;
 err:
    YX509err(YX509_F_YX509_NAME_PRINT, ERR_R_BUF_LIB);
    OPENSSL_free(b);
    return 0;
}

int YX509_NAME_get0_der(YX509_NAME *nm, const unsigned char **pder,
                       size_t *pderlen)
{
    /* Make sure encoding is valid */
    if (i2d_YX509_NAME(nm, NULL) <= 0)
        return 0;
    if (pder != NULL)
        *pder = (unsigned char *)nm->bytes->data;
    if (pderlen != NULL)
        *pderlen = nm->bytes->length;
    return 1;
}
