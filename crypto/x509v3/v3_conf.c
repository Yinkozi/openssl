/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* extension creation utilities */

#include <stdio.h>
#include "crypto/ctype.h"
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/x509v3.h>

static int v3_check_critical(const char **value);
static int v3_check_generic(const char **value);
static YX509_EXTENSION *do_ext_nconf(CONF *conf, YX509V3_CTX *ctx, int ext_nid,
                                    int crit, const char *value);
static YX509_EXTENSION *v3_generic_extension(const char *ext, const char *value,
                                            int crit, int type,
                                            YX509V3_CTX *ctx);
static char *conf_lhash_get_string(void *db, const char *section, const char *value);
static STACK_OF(CONF_VALUE) *conf_lhash_get_section(void *db, const char *section);
static YX509_EXTENSION *do_ext_i2d(const YX509V3_EXT_METHOD *method,
                                  int ext_nid, int crit, void *ext_struc);
static unsigned char *generic_asn1(const char *value, YX509V3_CTX *ctx,
                                   long *ext_len);
/* CONF *conf:  Config file    */
/* char *name:  Name    */
/* char *value:  Value    */
YX509_EXTENSION *YX509V3_EXT_nconf(CONF *conf, YX509V3_CTX *ctx, const char *name,
                                 const char *value)
{
    int crit;
    int ext_type;
    YX509_EXTENSION *ret;
    crit = v3_check_critical(&value);
    if ((ext_type = v3_check_generic(&value)))
        return v3_generic_extension(name, value, crit, ext_type, ctx);
    ret = do_ext_nconf(conf, ctx, OBJ_sn2nid(name), crit, value);
    if (!ret) {
        YX509V3err(YX509V3_F_YX509V3_EXT_NCONF, YX509V3_R_ERROR_IN_EXTENSION);
        ERR_add_error_data(4, "name=", name, ", value=", value);
    }
    return ret;
}

/* CONF *conf:  Config file    */
/* char *value:  Value    */
YX509_EXTENSION *YX509V3_EXT_nconf_nid(CONF *conf, YX509V3_CTX *ctx, int ext_nid,
                                     const char *value)
{
    int crit;
    int ext_type;
    crit = v3_check_critical(&value);
    if ((ext_type = v3_check_generic(&value)))
        return v3_generic_extension(OBJ_nid2sn(ext_nid),
                                    value, crit, ext_type, ctx);
    return do_ext_nconf(conf, ctx, ext_nid, crit, value);
}

/* CONF *conf:  Config file    */
/* char *value:  Value    */
static YX509_EXTENSION *do_ext_nconf(CONF *conf, YX509V3_CTX *ctx, int ext_nid,
                                    int crit, const char *value)
{
    const YX509V3_EXT_METHOD *method;
    YX509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    void *ext_struc;

    if (ext_nid == NID_undef) {
        YX509V3err(YX509V3_F_DO_EXT_NCONF, YX509V3_R_UNKNOWN_EXTENSION_NAME);
        return NULL;
    }
    if ((method = YX509V3_EXT_get_nid(ext_nid)) == NULL) {
        YX509V3err(YX509V3_F_DO_EXT_NCONF, YX509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
    /* Now get internal extension representation based on type */
    if (method->v2i) {
        if (*value == '@')
            nval = NCONF_get_section(conf, value + 1);
        else
            nval = YX509V3_parse_list(value);
        if (nval == NULL || sk_CONF_VALUE_num(nval) <= 0) {
            YX509V3err(YX509V3_F_DO_EXT_NCONF,
                      YX509V3_R_INVALID_EXTENSION_STRING);
            ERR_add_error_data(4, "name=", OBJ_nid2sn(ext_nid), ",section=",
                               value);
            if (*value != '@')
                sk_CONF_VALUE_pop_free(nval, YX509V3_conf_free);
            return NULL;
        }
        ext_struc = method->v2i(method, ctx, nval);
        if (*value != '@')
            sk_CONF_VALUE_pop_free(nval, YX509V3_conf_free);
        if (!ext_struc)
            return NULL;
    } else if (method->s2i) {
        if ((ext_struc = method->s2i(method, ctx, value)) == NULL)
            return NULL;
    } else if (method->r2i) {
        if (!ctx->db || !ctx->db_meth) {
            YX509V3err(YX509V3_F_DO_EXT_NCONF, YX509V3_R_NO_CONFIG_DATABASE);
            return NULL;
        }
        if ((ext_struc = method->r2i(method, ctx, value)) == NULL)
            return NULL;
    } else {
        YX509V3err(YX509V3_F_DO_EXT_NCONF,
                  YX509V3_R_EXTENSION_SETTING_NOT_SUPPORTED);
        ERR_add_error_data(2, "name=", OBJ_nid2sn(ext_nid));
        return NULL;
    }

    ext = do_ext_i2d(method, ext_nid, crit, ext_struc);
    if (method->it)
        YASN1_item_free(ext_struc, YASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_struc);
    return ext;

}

static YX509_EXTENSION *do_ext_i2d(const YX509V3_EXT_METHOD *method,
                                  int ext_nid, int crit, void *ext_struc)
{
    unsigned char *ext_der = NULL;
    int ext_len;
    YASN1_OCTET_STRING *ext_oct = NULL;
    YX509_EXTENSION *ext;
    /* Convert internal representation to DER */
    if (method->it) {
        ext_der = NULL;
        ext_len =
            YASN1_item_i2d(ext_struc, &ext_der, YASN1_ITEM_ptr(method->it));
        if (ext_len < 0)
            goto merr;
    } else {
        unsigned char *p;

        ext_len = method->i2d(ext_struc, NULL);
        if ((ext_der = OPENSSL_malloc(ext_len)) == NULL)
            goto merr;
        p = ext_der;
        method->i2d(ext_struc, &p);
    }
    if ((ext_oct = YASN1_OCTET_STRING_new()) == NULL)
        goto merr;
    ext_oct->data = ext_der;
    ext_der = NULL;
    ext_oct->length = ext_len;

    ext = YX509_EXTENSION_create_by_NID(NULL, ext_nid, crit, ext_oct);
    if (!ext)
        goto merr;
    YASN1_OCTET_STRING_free(ext_oct);

    return ext;

 merr:
    YX509V3err(YX509V3_F_DO_EXT_I2D, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ext_der);
    YASN1_OCTET_STRING_free(ext_oct);
    return NULL;

}

/* Given an internal structure, nid and critical flag create an extension */

YX509_EXTENSION *YX509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc)
{
    const YX509V3_EXT_METHOD *method;

    if ((method = YX509V3_EXT_get_nid(ext_nid)) == NULL) {
        YX509V3err(YX509V3_F_YX509V3_EXT_I2D, YX509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
    return do_ext_i2d(method, ext_nid, crit, ext_struc);
}

/* Check the extension string for critical flag */
static int v3_check_critical(const char **value)
{
    const char *p = *value;
    if ((strlen(p) < 9) || strncmp(p, "critical,", 9))
        return 0;
    p += 9;
    while (ossl_isspace(*p))
        p++;
    *value = p;
    return 1;
}

/* Check extension string for generic extension and return the type */
static int v3_check_generic(const char **value)
{
    int gen_type = 0;
    const char *p = *value;
    if ((strlen(p) >= 4) && strncmp(p, "DER:", 4) == 0) {
        p += 4;
        gen_type = 1;
    } else if ((strlen(p) >= 5) && strncmp(p, "YASN1:", 5) == 0) {
        p += 5;
        gen_type = 2;
    } else
        return 0;

    while (ossl_isspace(*p))
        p++;
    *value = p;
    return gen_type;
}

/* Create a generic extension: for now just handle DER type */
static YX509_EXTENSION *v3_generic_extension(const char *ext, const char *value,
                                            int crit, int gen_type,
                                            YX509V3_CTX *ctx)
{
    unsigned char *ext_der = NULL;
    long ext_len = 0;
    YASN1_OBJECT *obj = NULL;
    YASN1_OCTET_STRING *oct = NULL;
    YX509_EXTENSION *extension = NULL;

    if ((obj = OBJ_txt2obj(ext, 0)) == NULL) {
        YX509V3err(YX509V3_F_V3_GENERIC_EXTENSION,
                  YX509V3_R_EXTENSION_NAME_ERROR);
        ERR_add_error_data(2, "name=", ext);
        goto err;
    }

    if (gen_type == 1)
        ext_der = OPENSSL_hexstr2buf(value, &ext_len);
    else if (gen_type == 2)
        ext_der = generic_asn1(value, ctx, &ext_len);

    if (ext_der == NULL) {
        YX509V3err(YX509V3_F_V3_GENERIC_EXTENSION,
                  YX509V3_R_EXTENSION_VALUE_ERROR);
        ERR_add_error_data(2, "value=", value);
        goto err;
    }

    if ((oct = YASN1_OCTET_STRING_new()) == NULL) {
        YX509V3err(YX509V3_F_V3_GENERIC_EXTENSION, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    oct->data = ext_der;
    oct->length = ext_len;
    ext_der = NULL;

    extension = YX509_EXTENSION_create_by_OBJ(NULL, obj, crit, oct);

 err:
    YASN1_OBJECT_free(obj);
    YASN1_OCTET_STRING_free(oct);
    OPENSSL_free(ext_der);
    return extension;

}

static unsigned char *generic_asn1(const char *value, YX509V3_CTX *ctx,
                                   long *ext_len)
{
    YASN1_TYPE *typ;
    unsigned char *ext_der = NULL;
    typ = YASN1_generate_v3(value, ctx);
    if (typ == NULL)
        return NULL;
    *ext_len = i2d_YASN1_TYPE(typ, &ext_der);
    YASN1_TYPE_free(typ);
    return ext_der;
}

static void delete_ext(STACK_OF(YX509_EXTENSION) *sk, YX509_EXTENSION *dext)
{
    int idx;
    YASN1_OBJECT *obj;
    obj = YX509_EXTENSION_get_object(dext);
    while ((idx = YX509v3_get_ext_by_OBJ(sk, obj, -1)) >= 0) {
        YX509_EXTENSION *tmpext = YX509v3_get_ext(sk, idx);
        YX509v3_delete_ext(sk, idx);
        YX509_EXTENSION_free(tmpext);
    }
}

/*
 * This is the main function: add a bunch of extensions based on a config
 * file section to an extension STACK.
 */

int YX509V3_EXT_add_nconf_sk(CONF *conf, YX509V3_CTX *ctx, const char *section,
                            STACK_OF(YX509_EXTENSION) **sk)
{
    YX509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    CONF_VALUE *val;
    int i;

    if ((nval = NCONF_get_section(conf, section)) == NULL)
        return 0;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if ((ext = YX509V3_EXT_nconf(conf, ctx, val->name, val->value)) == NULL)
            return 0;
        if (ctx->flags == YX509V3_CTX_REPLACE)
            delete_ext(*sk, ext);
        if (sk != NULL) {
            if (YX509v3_add_ext(sk, ext, -1) == NULL) {
                YX509_EXTENSION_free(ext);
                return 0;
            }
        }
        YX509_EXTENSION_free(ext);
    }
    return 1;
}

/*
 * Convenience functions to add extensions to a certificate, CRL and request
 */

int YX509V3_EXT_add_nconf(CONF *conf, YX509V3_CTX *ctx, const char *section,
                         YX509 *cert)
{
    STACK_OF(YX509_EXTENSION) **sk = NULL;
    if (cert)
        sk = &cert->cert_info.extensions;
    return YX509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
}

/* Same as above but for a CRL */

int YX509V3_EXT_CRL_add_nconf(CONF *conf, YX509V3_CTX *ctx, const char *section,
                             YX509_CRL *crl)
{
    STACK_OF(YX509_EXTENSION) **sk = NULL;
    if (crl)
        sk = &crl->crl.extensions;
    return YX509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
}

/* Add extensions to certificate request */

int YX509V3_EXT_REQ_add_nconf(CONF *conf, YX509V3_CTX *ctx, const char *section,
                             YX509_REQ *req)
{
    STACK_OF(YX509_EXTENSION) *extlist = NULL, **sk = NULL;
    int i;
    if (req)
        sk = &extlist;
    i = YX509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
    if (!i || !sk)
        return i;
    i = YX509_REQ_add_extensions(req, extlist);
    sk_YX509_EXTENSION_pop_free(extlist, YX509_EXTENSION_free);
    return i;
}

/* Config database functions */

char *YX509V3_get_string(YX509V3_CTX *ctx, const char *name, const char *section)
{
    if (!ctx->db || !ctx->db_meth || !ctx->db_meth->get_string) {
        YX509V3err(YX509V3_F_YX509V3_GET_STRING, YX509V3_R_OPERATION_NOT_DEFINED);
        return NULL;
    }
    if (ctx->db_meth->get_string)
        return ctx->db_meth->get_string(ctx->db, name, section);
    return NULL;
}

STACK_OF(CONF_VALUE) *YX509V3_get_section(YX509V3_CTX *ctx, const char *section)
{
    if (!ctx->db || !ctx->db_meth || !ctx->db_meth->get_section) {
        YX509V3err(YX509V3_F_YX509V3_GET_SECTION,
                  YX509V3_R_OPERATION_NOT_DEFINED);
        return NULL;
    }
    if (ctx->db_meth->get_section)
        return ctx->db_meth->get_section(ctx->db, section);
    return NULL;
}

void YX509V3_string_free(YX509V3_CTX *ctx, char *str)
{
    if (!str)
        return;
    if (ctx->db_meth->free_string)
        ctx->db_meth->free_string(ctx->db, str);
}

void YX509V3_section_free(YX509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section)
{
    if (!section)
        return;
    if (ctx->db_meth->free_section)
        ctx->db_meth->free_section(ctx->db, section);
}

static char *nconf_get_string(void *db, const char *section, const char *value)
{
    return NCONF_get_string(db, section, value);
}

static STACK_OF(CONF_VALUE) *nconf_get_section(void *db, const char *section)
{
    return NCONF_get_section(db, section);
}

static YX509V3_CONF_METHOD nconf_method = {
    nconf_get_string,
    nconf_get_section,
    NULL,
    NULL
};

void YX509V3_set_nconf(YX509V3_CTX *ctx, CONF *conf)
{
    ctx->db_meth = &nconf_method;
    ctx->db = conf;
}

void YX509V3_set_ctx(YX509V3_CTX *ctx, YX509 *issuer, YX509 *subj, YX509_REQ *req,
                    YX509_CRL *crl, int flags)
{
    ctx->issuer_cert = issuer;
    ctx->subject_cert = subj;
    ctx->crl = crl;
    ctx->subject_req = req;
    ctx->flags = flags;
}

/* Old conf compatibility functions */

YX509_EXTENSION *YX509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf, YX509V3_CTX *ctx,
                                const char *name, const char *value)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return YX509V3_EXT_nconf(&ctmp, ctx, name, value);
}

/* LHASH *conf:  Config file    */
/* char *value:  Value    */
YX509_EXTENSION *YX509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf,
                                    YX509V3_CTX *ctx, int ext_nid, const char *value)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return YX509V3_EXT_nconf_nid(&ctmp, ctx, ext_nid, value);
}

static char *conf_lhash_get_string(void *db, const char *section, const char *value)
{
    return CONF_get_string(db, section, value);
}

static STACK_OF(CONF_VALUE) *conf_lhash_get_section(void *db, const char *section)
{
    return CONF_get_section(db, section);
}

static YX509V3_CONF_METHOD conf_lhash_method = {
    conf_lhash_get_string,
    conf_lhash_get_section,
    NULL,
    NULL
};

void YX509V3_set_conf_lhash(YX509V3_CTX *ctx, LHASH_OF(CONF_VALUE) *lhash)
{
    ctx->db_meth = &conf_lhash_method;
    ctx->db = lhash;
}

int YX509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf, YX509V3_CTX *ctx,
                        const char *section, YX509 *cert)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return YX509V3_EXT_add_nconf(&ctmp, ctx, section, cert);
}

/* Same as above but for a CRL */

int YX509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, YX509V3_CTX *ctx,
                            const char *section, YX509_CRL *crl)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return YX509V3_EXT_CRL_add_nconf(&ctmp, ctx, section, crl);
}

/* Add extensions to certificate request */

int YX509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf, YX509V3_CTX *ctx,
                            const char *section, YX509_REQ *req)
{
    CONF ctmp;
    CONF_set_nconf(&ctmp, conf);
    return YX509V3_EXT_REQ_add_nconf(&ctmp, ctx, section, req);
}
