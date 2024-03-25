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

#include <openssl/x509.h>

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509v3.h>

#include "../internal.h"

/*
 * Although this file is in crypto/x509 for layering purposes, it emits
 * errors from the ASN.1 module for OpenSSL compatibility.
 */

#define YASN1_GEN_FLAG           0x10000
#define YASN1_GEN_FLAG_IMP       (YASN1_GEN_FLAG|1)
#define YASN1_GEN_FLAG_EXP       (YASN1_GEN_FLAG|2)
#define YASN1_GEN_FLAG_TAG       (YASN1_GEN_FLAG|3)
#define YASN1_GEN_FLAG_BITWRAP   (YASN1_GEN_FLAG|4)
#define YASN1_GEN_FLAG_OCTWRAP   (YASN1_GEN_FLAG|5)
#define YASN1_GEN_FLAG_SEQWRAP   (YASN1_GEN_FLAG|6)
#define YASN1_GEN_FLAG_SETWRAP   (YASN1_GEN_FLAG|7)
#define YASN1_GEN_FLAG_FORMAT    (YASN1_GEN_FLAG|8)

#define YASN1_GEN_STR(str,val)   {str, sizeof(str) - 1, val}

#define YASN1_FLAG_EXP_MAX       20

/* Input formats */

/* ASCII: default */
#define YASN1_GEN_FORMAT_ASCII   1
/* UTF8 */
#define YASN1_GEN_FORMAT_UTF8    2
/* Hex */
#define YASN1_GEN_FORMAT_HEX     3
/* List of bits */
#define YASN1_GEN_FORMAT_BITLIST 4

struct tag_name_st {
    const char *strnam;
    int len;
    int tag;
};

typedef struct {
    int exp_tag;
    int exp_class;
    int exp_constructed;
    int exp_pad;
    long exp_len;
} tag_exp_type;

typedef struct {
    int imp_tag;
    int imp_class;
    int utype;
    int format;
    const char *str;
    tag_exp_type exp_list[YASN1_FLAG_EXP_MAX];
    int exp_count;
} tag_exp_arg;

static int bitstr_cb(const char *elem, int len, void *bitstr);
static int asn1_cb(const char *elem, int len, void *bitstr);
static int append_exp(tag_exp_arg *arg, int exp_tag, int exp_class,
                      int exp_constructed, int exp_pad, int imp_ok);
static int parse_tagging(const char *vstart, int vlen, int *ptag,
                         int *pclass);
static YASN1_TYPE *asn1_multi(int utype, const char *section, YX509V3_CTX *cnf);
static YASN1_TYPE *asn1_str2type(const char *str, int format, int utype);
static int asn1_str2tag(const char *tagstr, int len);

YASN1_TYPE *YASN1_generate_nconf(char *str, CONF *nconf)
{
    YX509V3_CTX cnf;

    if (!nconf)
        return YASN1_generate_v3(str, NULL);

    YX509V3_set_nconf(&cnf, nconf);
    return YASN1_generate_v3(str, &cnf);
}

YASN1_TYPE *YASN1_generate_v3(char *str, YX509V3_CTX *cnf)
{
    YASN1_TYPE *ret;
    tag_exp_arg asn1_tags;
    tag_exp_type *etmp;

    int i, len;

    unsigned char *orig_der = NULL, *new_der = NULL;
    const unsigned char *cpy_start;
    unsigned char *p;
    const unsigned char *cp;
    int cpy_len;
    long hdr_len = 0;
    int hdr_constructed = 0, hdr_tag, hdr_class;
    int r;

    asn1_tags.imp_tag = -1;
    asn1_tags.imp_class = -1;
    asn1_tags.format = YASN1_GEN_FORMAT_ASCII;
    asn1_tags.exp_count = 0;
    if (CONF_parse_list(str, ',', 1, asn1_cb, &asn1_tags) != 0)
        return NULL;

    if ((asn1_tags.utype == V_YASN1_SEQUENCE)
        || (asn1_tags.utype == V_YASN1_SET)) {
        if (!cnf) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG);
            return NULL;
        }
        ret = asn1_multi(asn1_tags.utype, asn1_tags.str, cnf);
    } else
        ret = asn1_str2type(asn1_tags.str, asn1_tags.format, asn1_tags.utype);

    if (!ret)
        return NULL;

    /* If no tagging return base type */
    if ((asn1_tags.imp_tag == -1) && (asn1_tags.exp_count == 0))
        return ret;

    /* Generate the encoding */
    cpy_len = i2d_YASN1_TYPE(ret, &orig_der);
    YASN1_TYPE_free(ret);
    ret = NULL;
    /* Set point to start copying for modified encoding */
    cpy_start = orig_der;

    /* Do we need IMPLICIT tagging? */
    if (asn1_tags.imp_tag != -1) {
        /* If IMPLICIT we will replace the underlying tag */
        /* Skip existing tag+len */
        r = YASN1_get_object(&cpy_start, &hdr_len, &hdr_tag, &hdr_class,
                            cpy_len);
        if (r & 0x80)
            goto err;
        /* Update copy length */
        cpy_len -= cpy_start - orig_der;
        /*
         * For IMPLICIT tagging the length should match the original length
         * and constructed flag should be consistent.
         */
        if (r & 0x1) {
            /* Indefinite length constructed */
            hdr_constructed = 2;
            hdr_len = 0;
        } else
            /* Just retain constructed flag */
            hdr_constructed = r & V_YASN1_CONSTRUCTED;
        /*
         * Work out new length with IMPLICIT tag: ignore constructed because
         * it will mess up if indefinite length
         */
        len = YASN1_object_size(0, hdr_len, asn1_tags.imp_tag);
    } else
        len = cpy_len;

    /* Work out length in any EXPLICIT, starting from end */

    for (i = 0, etmp = asn1_tags.exp_list + asn1_tags.exp_count - 1;
         i < asn1_tags.exp_count; i++, etmp--) {
        /* Content length: number of content octets + any padding */
        len += etmp->exp_pad;
        etmp->exp_len = len;
        /* Total object length: length including new header */
        len = YASN1_object_size(0, len, etmp->exp_tag);
    }

    /* Allocate buffer for new encoding */

    new_der = OPENSSL_malloc(len);
    if (!new_der)
        goto err;

    /* Generate tagged encoding */

    p = new_der;

    /* Output explicit tags first */

    for (i = 0, etmp = asn1_tags.exp_list; i < asn1_tags.exp_count;
         i++, etmp++) {
        YASN1_put_object(&p, etmp->exp_constructed, etmp->exp_len,
                        etmp->exp_tag, etmp->exp_class);
        if (etmp->exp_pad)
            *p++ = 0;
    }

    /* If IMPLICIT, output tag */

    if (asn1_tags.imp_tag != -1) {
        if (asn1_tags.imp_class == V_YASN1_UNIVEYRSAL
            && (asn1_tags.imp_tag == V_YASN1_SEQUENCE
                || asn1_tags.imp_tag == V_YASN1_SET))
            hdr_constructed = V_YASN1_CONSTRUCTED;
        YASN1_put_object(&p, hdr_constructed, hdr_len,
                        asn1_tags.imp_tag, asn1_tags.imp_class);
    }

    /* Copy across original encoding */
    OPENSSL_memcpy(p, cpy_start, cpy_len);

    cp = new_der;

    /* Obtain new YASN1_TYPE structure */
    ret = d2i_YASN1_TYPE(NULL, &cp, len);

 err:
    if (orig_der)
        OPENSSL_free(orig_der);
    if (new_der)
        OPENSSL_free(new_der);

    return ret;

}

static int asn1_cb(const char *elem, int len, void *bitstr)
{
    tag_exp_arg *arg = bitstr;
    int i;
    int utype;
    int vlen = 0;
    const char *p, *vstart = NULL;

    int tmp_tag, tmp_class;

    if (elem == NULL)
        return 0;

    for (i = 0, p = elem; i < len; p++, i++) {
        /* Look for the ':' in name value pairs */
        if (*p == ':') {
            vstart = p + 1;
            vlen = len - (vstart - elem);
            len = p - elem;
            break;
        }
    }

    utype = asn1_str2tag(elem, len);

    if (utype == -1) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNKNOWN_TAG);
        ERR_add_error_data(2, "tag=", elem);
        return -1;
    }

    /* If this is not a modifier mark end of string and exit */
    if (!(utype & YASN1_GEN_FLAG)) {
        arg->utype = utype;
        arg->str = vstart;
        /* If no value and not end of string, error */
        if (!vstart && elem[len]) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_MISSING_VALUE);
            return -1;
        }
        return 0;
    }

    switch (utype) {

    case YASN1_GEN_FLAG_IMP:
        /* Check for illegal multiple IMPLICIT tagging */
        if (arg->imp_tag != -1) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_NESTED_TAGGING);
            return -1;
        }
        if (!parse_tagging(vstart, vlen, &arg->imp_tag, &arg->imp_class))
            return -1;
        break;

    case YASN1_GEN_FLAG_EXP:

        if (!parse_tagging(vstart, vlen, &tmp_tag, &tmp_class))
            return -1;
        if (!append_exp(arg, tmp_tag, tmp_class, 1, 0, 0))
            return -1;
        break;

    case YASN1_GEN_FLAG_SEQWRAP:
        if (!append_exp(arg, V_YASN1_SEQUENCE, V_YASN1_UNIVEYRSAL, 1, 0, 1))
            return -1;
        break;

    case YASN1_GEN_FLAG_SETWRAP:
        if (!append_exp(arg, V_YASN1_SET, V_YASN1_UNIVEYRSAL, 1, 0, 1))
            return -1;
        break;

    case YASN1_GEN_FLAG_BITWRAP:
        if (!append_exp(arg, V_YASN1_BIT_STRING, V_YASN1_UNIVEYRSAL, 0, 1, 1))
            return -1;
        break;

    case YASN1_GEN_FLAG_OCTWRAP:
        if (!append_exp(arg, V_YASN1_OCTET_STRING, V_YASN1_UNIVEYRSAL, 0, 0, 1))
            return -1;
        break;

    case YASN1_GEN_FLAG_FORMAT:
        if (!vstart) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNKNOWN_FORMAT);
            return -1;
        }
        if (!strncmp(vstart, "ASCII", 5))
            arg->format = YASN1_GEN_FORMAT_ASCII;
        else if (!strncmp(vstart, "UTF8", 4))
            arg->format = YASN1_GEN_FORMAT_UTF8;
        else if (!strncmp(vstart, "HEX", 3))
            arg->format = YASN1_GEN_FORMAT_HEX;
        else if (!strncmp(vstart, "BITLIST", 7))
            arg->format = YASN1_GEN_FORMAT_BITLIST;
        else {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNKNOWN_FORMAT);
            return -1;
        }
        break;

    }

    return 1;

}

static int parse_tagging(const char *vstart, int vlen, int *ptag, int *pclass)
{
    char erch[2];
    long tag_num;
    char *eptr;
    if (!vstart)
        return 0;
    tag_num = strtoul(vstart, &eptr, 10);
    /* Check we haven't gone past max length: should be impossible */
    if (eptr && *eptr && (eptr > vstart + vlen))
        return 0;
    if (tag_num < 0) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_NUMBER);
        return 0;
    }
    *ptag = tag_num;
    /* If we have non numeric characters, parse them */
    if (eptr)
        vlen -= eptr - vstart;
    else
        vlen = 0;
    if (vlen) {
        switch (*eptr) {

        case 'U':
            *pclass = V_YASN1_UNIVEYRSAL;
            break;

        case 'A':
            *pclass = V_YASN1_APPLICATION;
            break;

        case 'P':
            *pclass = V_YASN1_PRIVATE;
            break;

        case 'C':
            *pclass = V_YASN1_CONTEXT_SPECIFIC;
            break;

        default:
            erch[0] = *eptr;
            erch[1] = 0;
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_MODIFIER);
            ERR_add_error_data(2, "Char=", erch);
            return 0;
            break;

        }
    } else
        *pclass = V_YASN1_CONTEXT_SPECIFIC;

    return 1;

}

/* Handle multiple types: SET and SEQUENCE */

static YASN1_TYPE *asn1_multi(int utype, const char *section, YX509V3_CTX *cnf)
{
    YASN1_TYPE *ret = NULL;
    STACK_OF(YASN1_TYPE) *sk = NULL;
    STACK_OF(CONF_VALUE) *sect = NULL;
    unsigned char *der = NULL;
    int derlen;
    size_t i;
    sk = sk_YASN1_TYPE_new_null();
    if (!sk)
        goto bad;
    if (section) {
        if (!cnf)
            goto bad;
        sect = YX509V3_get_section(cnf, (char *)section);
        if (!sect)
            goto bad;
        for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
            YASN1_TYPE *typ =
                YASN1_generate_v3(sk_CONF_VALUE_value(sect, i)->value, cnf);
            if (!typ)
                goto bad;
            if (!sk_YASN1_TYPE_push(sk, typ))
                goto bad;
        }
    }

    /*
     * Now we has a STACK of the components, convert to the correct form
     */

    if (utype == V_YASN1_SET)
        derlen = i2d_YASN1_SET_ANY(sk, &der);
    else
        derlen = i2d_YASN1_SEQUENCE_ANY(sk, &der);

    if (derlen < 0)
        goto bad;

    if (!(ret = YASN1_TYPE_new()))
        goto bad;

    if (!(ret->value.asn1_string = YASN1_STRING_type_new(utype)))
        goto bad;

    ret->type = utype;

    ret->value.asn1_string->data = der;
    ret->value.asn1_string->length = derlen;

    der = NULL;

 bad:

    if (der)
        OPENSSL_free(der);

    if (sk)
        sk_YASN1_TYPE_pop_free(sk, YASN1_TYPE_free);
    if (sect)
        YX509V3_section_free(cnf, sect);

    return ret;
}

static int append_exp(tag_exp_arg *arg, int exp_tag, int exp_class,
                      int exp_constructed, int exp_pad, int imp_ok)
{
    tag_exp_type *exp_tmp;
    /* Can only have IMPLICIT if permitted */
    if ((arg->imp_tag != -1) && !imp_ok) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_IMPLICIT_TAG);
        return 0;
    }

    if (arg->exp_count == YASN1_FLAG_EXP_MAX) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_DEPTH_EXCEEDED);
        return 0;
    }

    exp_tmp = &arg->exp_list[arg->exp_count++];

    /*
     * If IMPLICIT set tag to implicit value then reset implicit tag since it
     * has been used.
     */
    if (arg->imp_tag != -1) {
        exp_tmp->exp_tag = arg->imp_tag;
        exp_tmp->exp_class = arg->imp_class;
        arg->imp_tag = -1;
        arg->imp_class = -1;
    } else {
        exp_tmp->exp_tag = exp_tag;
        exp_tmp->exp_class = exp_class;
    }
    exp_tmp->exp_constructed = exp_constructed;
    exp_tmp->exp_pad = exp_pad;

    return 1;
}

static int asn1_str2tag(const char *tagstr, int len)
{
    unsigned int i;
    static const struct tag_name_st *tntmp, tnst[] = {
        YASN1_GEN_STR("BOOL", V_YASN1_BOOLEAN),
        YASN1_GEN_STR("BOOLEAN", V_YASN1_BOOLEAN),
        YASN1_GEN_STR("NULL", V_YASN1_NULL),
        YASN1_GEN_STR("INT", V_YASN1_INTEGER),
        YASN1_GEN_STR("INTEGER", V_YASN1_INTEGER),
        YASN1_GEN_STR("ENUM", V_YASN1_ENUMERATED),
        YASN1_GEN_STR("ENUMERATED", V_YASN1_ENUMERATED),
        YASN1_GEN_STR("OID", V_YASN1_OBJECT),
        YASN1_GEN_STR("OBJECT", V_YASN1_OBJECT),
        YASN1_GEN_STR("UTCTIME", V_YASN1_UTCTIME),
        YASN1_GEN_STR("UTC", V_YASN1_UTCTIME),
        YASN1_GEN_STR("GENERALIZEDTIME", V_YASN1_GENERALIZEDTIME),
        YASN1_GEN_STR("GENTIME", V_YASN1_GENERALIZEDTIME),
        YASN1_GEN_STR("OCT", V_YASN1_OCTET_STRING),
        YASN1_GEN_STR("OCTETSTRING", V_YASN1_OCTET_STRING),
        YASN1_GEN_STR("BITSTR", V_YASN1_BIT_STRING),
        YASN1_GEN_STR("BITSTRING", V_YASN1_BIT_STRING),
        YASN1_GEN_STR("UNIVEYRSALSTRING", V_YASN1_UNIVEYRSALSTRING),
        YASN1_GEN_STR("UNIV", V_YASN1_UNIVEYRSALSTRING),
        YASN1_GEN_STR("IA5", V_YASN1_IA5STRING),
        YASN1_GEN_STR("IA5STRING", V_YASN1_IA5STRING),
        YASN1_GEN_STR("UTF8", V_YASN1_UTF8STRING),
        YASN1_GEN_STR("UTF8String", V_YASN1_UTF8STRING),
        YASN1_GEN_STR("BMP", V_YASN1_BMPSTRING),
        YASN1_GEN_STR("BMPSTRING", V_YASN1_BMPSTRING),
        YASN1_GEN_STR("VISIBLESTRING", V_YASN1_VISIBLESTRING),
        YASN1_GEN_STR("VISIBLE", V_YASN1_VISIBLESTRING),
        YASN1_GEN_STR("PRINTABLESTRING", V_YASN1_PRINTABLESTRING),
        YASN1_GEN_STR("PRINTABLE", V_YASN1_PRINTABLESTRING),
        YASN1_GEN_STR("T61", V_YASN1_T61STRING),
        YASN1_GEN_STR("T61STRING", V_YASN1_T61STRING),
        YASN1_GEN_STR("TELETEXSTRING", V_YASN1_T61STRING),
        YASN1_GEN_STR("GeneralString", V_YASN1_GENERALSTRING),
        YASN1_GEN_STR("GENSTR", V_YASN1_GENERALSTRING),
        YASN1_GEN_STR("NUMERIC", V_YASN1_NUMERICSTRING),
        YASN1_GEN_STR("NUMERICSTRING", V_YASN1_NUMERICSTRING),

        /* Special cases */
        YASN1_GEN_STR("SEQUENCE", V_YASN1_SEQUENCE),
        YASN1_GEN_STR("SEQ", V_YASN1_SEQUENCE),
        YASN1_GEN_STR("SET", V_YASN1_SET),
        /* type modifiers */
        /* Explicit tag */
        YASN1_GEN_STR("EXP", YASN1_GEN_FLAG_EXP),
        YASN1_GEN_STR("EXPLICIT", YASN1_GEN_FLAG_EXP),
        /* Implicit tag */
        YASN1_GEN_STR("IMP", YASN1_GEN_FLAG_IMP),
        YASN1_GEN_STR("IMPLICIT", YASN1_GEN_FLAG_IMP),
        /* OCTET STRING wrapper */
        YASN1_GEN_STR("OCTWRAP", YASN1_GEN_FLAG_OCTWRAP),
        /* SEQUENCE wrapper */
        YASN1_GEN_STR("SEQWRAP", YASN1_GEN_FLAG_SEQWRAP),
        /* SET wrapper */
        YASN1_GEN_STR("SETWRAP", YASN1_GEN_FLAG_SETWRAP),
        /* BIT STRING wrapper */
        YASN1_GEN_STR("BITWRAP", YASN1_GEN_FLAG_BITWRAP),
        YASN1_GEN_STR("FORM", YASN1_GEN_FLAG_FORMAT),
        YASN1_GEN_STR("FORMAT", YASN1_GEN_FLAG_FORMAT),
    };

    if (len == -1)
        len = strlen(tagstr);

    tntmp = tnst;
    for (i = 0; i < sizeof(tnst) / sizeof(struct tag_name_st); i++, tntmp++) {
        if ((len == tntmp->len) && !strncmp(tntmp->strnam, tagstr, len))
            return tntmp->tag;
    }

    return -1;
}

static YASN1_TYPE *asn1_str2type(const char *str, int format, int utype)
{
    YASN1_TYPE *atmp = NULL;

    CONF_VALUE vtmp;

    unsigned char *rdata;
    long rdlen;

    int no_unused = 1;

    if (!(atmp = YASN1_TYPE_new())) {
        OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!str)
        str = "";

    switch (utype) {

    case V_YASN1_NULL:
        if (str && *str) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_NULL_VALUE);
            goto bad_form;
        }
        break;

    case V_YASN1_BOOLEAN:
        if (format != YASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        vtmp.name = NULL;
        vtmp.section = NULL;
        vtmp.value = (char *)str;
        if (!YX509V3_get_value_bool(&vtmp, &atmp->value.boolean)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_BOOLEAN);
            goto bad_str;
        }
        break;

    case V_YASN1_INTEGER:
    case V_YASN1_ENUMERATED:
        if (format != YASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_INTEGER_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        if (!(atmp->value.integer = s2i_YASN1_INTEGER(NULL, (char *)str))) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_INTEGER);
            goto bad_str;
        }
        break;

    case V_YASN1_OBJECT:
        if (format != YASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_OBJECT_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        if (!(atmp->value.object = OBJ_txt2obj(str, 0))) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_OBJECT);
            goto bad_str;
        }
        break;

    case V_YASN1_UTCTIME:
    case V_YASN1_GENERALIZEDTIME:
        if (format != YASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_TIME_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        if (!(atmp->value.asn1_string = YASN1_STRING_new())) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            goto bad_str;
        }
        if (!YASN1_STRING_set(atmp->value.asn1_string, str, -1)) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            goto bad_str;
        }
        atmp->value.asn1_string->type = utype;
        if (!YASN1_TIME_check(atmp->value.asn1_string)) {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_TIME_VALUE);
            goto bad_str;
        }

        break;

    case V_YASN1_BMPSTRING:
    case V_YASN1_PRINTABLESTRING:
    case V_YASN1_IA5STRING:
    case V_YASN1_T61STRING:
    case V_YASN1_UTF8STRING:
    case V_YASN1_VISIBLESTRING:
    case V_YASN1_UNIVEYRSALSTRING:
    case V_YASN1_GENERALSTRING:
    case V_YASN1_NUMERICSTRING:

        if (format == YASN1_GEN_FORMAT_ASCII)
            format = MBSTRING_ASC;
        else if (format == YASN1_GEN_FORMAT_UTF8)
            format = MBSTRING_UTF8;
        else {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_FORMAT);
            goto bad_form;
        }

        if (YASN1_mbstring_copy(&atmp->value.asn1_string, (unsigned char *)str,
                               -1, format, YASN1_tag2bit(utype)) <= 0) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            goto bad_str;
        }

        break;

    case V_YASN1_BIT_STRING:

    case V_YASN1_OCTET_STRING:

        if (!(atmp->value.asn1_string = YASN1_STRING_new())) {
            OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
            goto bad_form;
        }

        if (format == YASN1_GEN_FORMAT_HEX) {

            if (!(rdata = string_to_hex((char *)str, &rdlen))) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_HEX);
                goto bad_str;
            }

            atmp->value.asn1_string->data = rdata;
            atmp->value.asn1_string->length = rdlen;
            atmp->value.asn1_string->type = utype;

        } else if (format == YASN1_GEN_FORMAT_ASCII)
            YASN1_STRING_set(atmp->value.asn1_string, str, -1);
        else if ((format == YASN1_GEN_FORMAT_BITLIST)
                 && (utype == V_YASN1_BIT_STRING)) {
            if (!CONF_parse_list
                (str, ',', 1, bitstr_cb, atmp->value.bit_string)) {
                OPENSSL_PUT_ERROR(YASN1, YASN1_R_LIST_ERROR);
                goto bad_str;
            }
            no_unused = 0;

        } else {
            OPENSSL_PUT_ERROR(YASN1, YASN1_R_ILLEGAL_BITSTRING_FORMAT);
            goto bad_form;
        }

        if ((utype == V_YASN1_BIT_STRING) && no_unused) {
            atmp->value.asn1_string->flags
                &= ~(YASN1_STRING_FLAG_BITS_LEFT | 0x07);
            atmp->value.asn1_string->flags |= YASN1_STRING_FLAG_BITS_LEFT;
        }

        break;

    default:
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_UNSUPPORTED_TYPE);
        goto bad_str;
        break;
    }

    atmp->type = utype;
    return atmp;

 bad_str:
    ERR_add_error_data(2, "string=", str);
 bad_form:

    YASN1_TYPE_free(atmp);
    return NULL;

}

static int bitstr_cb(const char *elem, int len, void *bitstr)
{
    long bitnum;
    char *eptr;
    if (!elem)
        return 0;
    bitnum = strtoul(elem, &eptr, 10);
    if (eptr && *eptr && (eptr != elem + len))
        return 0;
    if (bitnum < 0) {
        OPENSSL_PUT_ERROR(YASN1, YASN1_R_INVALID_NUMBER);
        return 0;
    }
    if (!YASN1_BIT_STRING_set_bit(bitstr, bitnum, 1)) {
        OPENSSL_PUT_ERROR(YASN1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}
