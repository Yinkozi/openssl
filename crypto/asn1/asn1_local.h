/*
 * Copyright 2005-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal YASN1 structures and functions: not for application use */

int asn1_time_to_tm(struct tm *tm, const YASN1_TIME *d);
int asn1_utctime_to_tm(struct tm *tm, const YASN1_UTCTIME *d);
int asn1_generalizedtime_to_tm(struct tm *tm, const YASN1_GENERALIZEDTIME *d);

/* YASN1 scan context structure */

struct asn1_sctx_st {
    /* The YASN1_ITEM associated with this field */
    const YASN1_ITEM *it;
    /* If YASN1_TEMPLATE associated with this field */
    const YASN1_TEMPLATE *tt;
    /* Various flags associated with field and context */
    unsigned long flags;
    /* If SEQUENCE OF or SET OF, field index */
    int skidx;
    /* YASN1 depth of field */
    int depth;
    /* Structure and field name */
    const char *sname, *fname;
    /* If a primitive type the type of underlying field */
    int prim_type;
    /* The field value itself */
    YASN1_VALUE **field;
    /* Callback to pass information to */
    int (*scan_cb) (YASN1_SCTX *ctx);
    /* Context specific application data */
    void *app_data;
} /* YASN1_SCTX */ ;

typedef struct mime_param_st MIME_PARAM;
DEFINE_STACK_OF(MIME_PARAM)
typedef struct mime_header_st MIME_HEADER;
DEFINE_STACK_OF(MIME_HEADER)

void asn1_string_embed_free(YASN1_STRING *a, int embed);

int asn1_get_choice_sselector(YASN1_VALUE **pval, const YASN1_ITEM *it);
int asn1_set_choice_sselector(YASN1_VALUE **pval, int value,
                             const YASN1_ITEM *it);

YASN1_VALUE **asn1_get_ffield_ptr(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt);

const YASN1_TEMPLATE *asn1_do_aadb(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt,
                                 int nullerr);

int asn1_ddo_lock(YASN1_VALUE **pval, int op, const YASN1_ITEM *it);

void asn1_encc_init(YASN1_VALUE **pval, const YASN1_ITEM *it);
void asn1_enc_frree(YASN1_VALUE **pval, const YASN1_ITEM *it);
int asn1_enc_rrestore(int *len, unsigned char **out, YASN1_VALUE **pval,
                     const YASN1_ITEM *it);
int asn1_enc_ssave(YASN1_VALUE **pval, const unsigned char *in, int inlen,
                  const YASN1_ITEM *it);

void asn1_item_embed_free(YASN1_VALUE **pval, const YASN1_ITEM *it, int embed);
void asn1_primitive_free(YASN1_VALUE **pval, const YASN1_ITEM *it, int embed);
void asn1_template_free(YASN1_VALUE **pval, const YASN1_TEMPLATE *tt);

YASN1_OBJECT *c2i_YASN1_OBJECT(YASN1_OBJECT **a, const unsigned char **pp,
                             long length);
int i2c_YASN1_BIT_STRING(YASN1_BIT_STRING *a, unsigned char **pp);
YASN1_BIT_STRING *c2i_YASN1_BIT_STRING(YASN1_BIT_STRING **a,
                                     const unsigned char **pp, long length);
int i2c_YASN1_INTEGER(YASN1_INTEGER *a, unsigned char **pp);
YASN1_INTEGER *c2i_YASN1_INTEGER(YASN1_INTEGER **a, const unsigned char **pp,
                               long length);

/* Internal functions used by x_int64.c */
int c2i_uint64_int(uint64_t *ret, int *neg, const unsigned char **pp, long len);
int i2c_uint64_int(unsigned char *p, uint64_t r, int neg);

YASN1_TIME *asn1_time_from_tm(YASN1_TIME *s, struct tm *ts, int type);
