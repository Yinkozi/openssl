/* v3_ncons.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509v3.h>

#include "../internal.h"


static void *v2i_NAME_CONSTRAINTS(const YX509V3_EXT_METHOD *method,
                                  YX509V3_CTX *ctx,
                                  STACK_OF(CONF_VALUE) *nval);
static int i2r_NAME_CONSTRAINTS(const YX509V3_EXT_METHOD *method, void *a,
                                BIO *bp, int ind);
static int do_i2r_name_constraints(const YX509V3_EXT_METHOD *method,
                                   STACK_OF(GENERAL_SUBTREE) *trees, BIO *bp,
                                   int ind, const char *name);
static int print_nc_ipadd(BIO *bp, YASN1_OCTET_STRING *ip);

static int nc_match(GENERAL_NAME *gen, NAME_CONSTRAINTS *nc);
static int nc_match_single(GENERAL_NAME *sub, GENERAL_NAME *gen);
static int nc_dn(YX509_NAME *sub, YX509_NAME *nm);
static int nc_dns(YASN1_IA5STRING *sub, YASN1_IA5STRING *dns);
static int nc_email(YASN1_IA5STRING *sub, YASN1_IA5STRING *eml);
static int nc_uri(YASN1_IA5STRING *uri, YASN1_IA5STRING *base);

const YX509V3_EXT_METHOD v3_name_constraints = {
    NID_name_constraints, 0,
    YASN1_ITEM_ref(NAME_CONSTRAINTS),
    0, 0, 0, 0,
    0, 0,
    0, v2i_NAME_CONSTRAINTS,
    i2r_NAME_CONSTRAINTS, 0,
    NULL
};

YASN1_SEQUENCE(GENERAL_SUBTREE) = {
        YASN1_SIMPLE(GENERAL_SUBTREE, base, GENERAL_NAME),
        YASN1_IMP_OPT(GENERAL_SUBTREE, minimum, YASN1_INTEGER, 0),
        YASN1_IMP_OPT(GENERAL_SUBTREE, maximum, YASN1_INTEGER, 1)
} YASN1_SEQUENCE_END(GENERAL_SUBTREE)

YASN1_SEQUENCE(NAME_CONSTRAINTS) = {
        YASN1_IMP_SEQUENCE_OF_OPT(NAME_CONSTRAINTS, permittedSubtrees,
                                                        GENERAL_SUBTREE, 0),
        YASN1_IMP_SEQUENCE_OF_OPT(NAME_CONSTRAINTS, excludedSubtrees,
                                                        GENERAL_SUBTREE, 1),
} YASN1_SEQUENCE_END(NAME_CONSTRAINTS)


IMPLEMENT_YASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)
IMPLEMENT_YASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

static void *v2i_NAME_CONSTRAINTS(const YX509V3_EXT_METHOD *method,
                                  YX509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    size_t i;
    CONF_VALUE tval, *val;
    STACK_OF(GENERAL_SUBTREE) **ptree = NULL;
    NAME_CONSTRAINTS *ncons = NULL;
    GENERAL_SUBTREE *sub = NULL;
    ncons = NAME_CONSTRAINTS_new();
    if (!ncons)
        goto memerr;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (!strncmp(val->name, "permitted", 9) && val->name[9]) {
            ptree = &ncons->permittedSubtrees;
            tval.name = val->name + 10;
        } else if (!strncmp(val->name, "excluded", 8) && val->name[8]) {
            ptree = &ncons->excludedSubtrees;
            tval.name = val->name + 9;
        } else {
            OPENSSL_PUT_ERROR(YX509V3, YX509V3_R_INVALID_SYNTAX);
            goto err;
        }
        tval.value = val->value;
        sub = GENERAL_SUBTREE_new();
        if (!v2i_GENERAL_NAME_ex(sub->base, method, ctx, &tval, 1))
            goto err;
        if (!*ptree)
            *ptree = sk_GENERAL_SUBTREE_new_null();
        if (!*ptree || !sk_GENERAL_SUBTREE_push(*ptree, sub))
            goto memerr;
        sub = NULL;
    }

    return ncons;

 memerr:
    OPENSSL_PUT_ERROR(YX509V3, ERR_R_MALLOC_FAILURE);
 err:
    if (ncons)
        NAME_CONSTRAINTS_free(ncons);
    if (sub)
        GENERAL_SUBTREE_free(sub);

    return NULL;
}

static int i2r_NAME_CONSTRAINTS(const YX509V3_EXT_METHOD *method, void *a,
                                BIO *bp, int ind)
{
    NAME_CONSTRAINTS *ncons = a;
    do_i2r_name_constraints(method, ncons->permittedSubtrees,
                            bp, ind, "Permitted");
    do_i2r_name_constraints(method, ncons->excludedSubtrees,
                            bp, ind, "Excluded");
    return 1;
}

static int do_i2r_name_constraints(const YX509V3_EXT_METHOD *method,
                                   STACK_OF(GENERAL_SUBTREE) *trees,
                                   BIO *bp, int ind, const char *name)
{
    GENERAL_SUBTREE *tree;
    size_t i;
    if (sk_GENERAL_SUBTREE_num(trees) > 0)
        BIO_pprintf(bp, "%*s%s:\n", ind, "", name);
    for (i = 0; i < sk_GENERAL_SUBTREE_num(trees); i++) {
        tree = sk_GENERAL_SUBTREE_value(trees, i);
        BIO_pprintf(bp, "%*s", ind + 2, "");
        if (tree->base->type == GEN_IPADD)
            print_nc_ipadd(bp, tree->base->d.ip);
        else
            GENERAL_NAME_print(bp, tree->base);
        BIO_puts(bp, "\n");
    }
    return 1;
}

static int print_nc_ipadd(BIO *bp, YASN1_OCTET_STRING *ip)
{
    int i, len;
    unsigned char *p;
    p = ip->data;
    len = ip->length;
    BIO_puts(bp, "IP:");
    if (len == 8) {
        BIO_pprintf(bp, "%d.%d.%d.%d/%d.%d.%d.%d",
                   p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    } else if (len == 32) {
        for (i = 0; i < 16; i++) {
            BIO_pprintf(bp, "%X", p[0] << 8 | p[1]);
            p += 2;
            if (i == 7)
                BIO_puts(bp, "/");
            else if (i != 15)
                BIO_puts(bp, ":");
        }
    } else
        BIO_pprintf(bp, "IP Address:<invalid>");
    return 1;
}

/*
 * Check a certificate conforms to a specified set of constraints. Return
 * values: YX509_V_OK: All constraints obeyed.
 * YX509_V_ERR_PERMITTED_VIOLATION: Permitted subtree violation.
 * YX509_V_ERR_EXCLUDED_VIOLATION: Excluded subtree violation.
 * YX509_V_ERR_SUBTREE_MINMAX: Min or max values present and matching type.
 * YX509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: Unsupported constraint type.
 * YX509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: bad unsupported constraint
 * syntax.  YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX: bad or unsupported syntax of
 * name
 *
 */

int NAME_CONSTRAINTS_check(YX509 *x, NAME_CONSTRAINTS *nc)
{
    int r, i;
    size_t j;
    YX509_NAME *nm;

    nm = YX509_get_subject_name(x);

    if (YX509_NAME_entry_count(nm) > 0) {
        GENERAL_NAME gntmp;
        gntmp.type = GEN_DIRNAME;
        gntmp.d.directoryName = nm;

        r = nc_match(&gntmp, nc);

        if (r != YX509_V_OK)
            return r;

        gntmp.type = GEN_EMAIL;

        /* Process any email address attributes in subject name */

        for (i = -1;;) {
            YX509_NAME_ENTRY *ne;
            i = YX509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i);
            if (i == -1)
                break;
            ne = YX509_NAME_get_entry(nm, i);
            gntmp.d.rfc822Name = YX509_NAME_ENTRY_get_data(ne);
            if (gntmp.d.rfc822Name->type != V_YASN1_IA5STRING)
                return YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX;

            r = nc_match(&gntmp, nc);

            if (r != YX509_V_OK)
                return r;
        }

    }

    for (j = 0; j < sk_GENERAL_NAME_num(x->altname); j++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(x->altname, j);
        r = nc_match(gen, nc);
        if (r != YX509_V_OK)
            return r;
    }

    return YX509_V_OK;

}

static int nc_match(GENERAL_NAME *gen, NAME_CONSTRAINTS *nc)
{
    GENERAL_SUBTREE *sub;
    int r, match = 0;
    size_t i;

    /*
     * Permitted subtrees: if any subtrees exist of matching the type at
     * least one subtree must match.
     */

    for (i = 0; i < sk_GENERAL_SUBTREE_num(nc->permittedSubtrees); i++) {
        sub = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, i);
        if (gen->type != sub->base->type)
            continue;
        if (sub->minimum || sub->maximum)
            return YX509_V_ERR_SUBTREE_MINMAX;
        /* If we already have a match don't bother trying any more */
        if (match == 2)
            continue;
        if (match == 0)
            match = 1;
        r = nc_match_single(gen, sub->base);
        if (r == YX509_V_OK)
            match = 2;
        else if (r != YX509_V_ERR_PERMITTED_VIOLATION)
            return r;
    }

    if (match == 1)
        return YX509_V_ERR_PERMITTED_VIOLATION;

    /* Excluded subtrees: must not match any of these */

    for (i = 0; i < sk_GENERAL_SUBTREE_num(nc->excludedSubtrees); i++) {
        sub = sk_GENERAL_SUBTREE_value(nc->excludedSubtrees, i);
        if (gen->type != sub->base->type)
            continue;
        if (sub->minimum || sub->maximum)
            return YX509_V_ERR_SUBTREE_MINMAX;

        r = nc_match_single(gen, sub->base);
        if (r == YX509_V_OK)
            return YX509_V_ERR_EXCLUDED_VIOLATION;
        else if (r != YX509_V_ERR_PERMITTED_VIOLATION)
            return r;

    }

    return YX509_V_OK;

}

static int nc_match_single(GENERAL_NAME *gen, GENERAL_NAME *base)
{
    switch (base->type) {
    case GEN_DIRNAME:
        return nc_dn(gen->d.directoryName, base->d.directoryName);

    case GEN_DNS:
        return nc_dns(gen->d.dNSName, base->d.dNSName);

    case GEN_EMAIL:
        return nc_email(gen->d.rfc822Name, base->d.rfc822Name);

    case GEN_URI:
        return nc_uri(gen->d.uniformResourceIdentifier,
                      base->d.uniformResourceIdentifier);

    default:
        return YX509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE;
    }

}

/*
 * directoryName name constraint matching. The canonical encoding of
 * YX509_NAME makes this comparison easy. It is matched if the subtree is a
 * subset of the name.
 */

static int nc_dn(YX509_NAME *nm, YX509_NAME *base)
{
    /* Ensure canonical encodings are up to date.  */
    if (nm->modified && i2d_YX509_NAME(nm, NULL) < 0)
        return YX509_V_ERR_OUT_OF_MEM;
    if (base->modified && i2d_YX509_NAME(base, NULL) < 0)
        return YX509_V_ERR_OUT_OF_MEM;
    if (base->canon_enclen > nm->canon_enclen)
        return YX509_V_ERR_PERMITTED_VIOLATION;
    if (OPENSSL_memcmp(base->canon_enc, nm->canon_enc, base->canon_enclen))
        return YX509_V_ERR_PERMITTED_VIOLATION;
    return YX509_V_OK;
}

static int nc_dns(YASN1_IA5STRING *dns, YASN1_IA5STRING *base)
{
    char *baseptr = (char *)base->data;
    char *dnsptr = (char *)dns->data;
    /* Empty matches everything */
    if (!*baseptr)
        return YX509_V_OK;
    /*
     * Otherwise can add zero or more components on the left so compare RHS
     * and if dns is longer and expect '.' as preceding character.
     */
    if (dns->length > base->length) {
        dnsptr += dns->length - base->length;
        if (*baseptr != '.' && dnsptr[-1] != '.')
            return YX509_V_ERR_PERMITTED_VIOLATION;
    }

    if (OPENSSL_strcasecmp(baseptr, dnsptr))
        return YX509_V_ERR_PERMITTED_VIOLATION;

    return YX509_V_OK;

}

static int nc_email(YASN1_IA5STRING *eml, YASN1_IA5STRING *base)
{
    const char *baseptr = (char *)base->data;
    const char *emlptr = (char *)eml->data;

    const char *baseat = strchr(baseptr, '@');
    const char *emlat = strchr(emlptr, '@');
    if (!emlat)
        return YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    /* Special case: inital '.' is RHS match */
    if (!baseat && (*baseptr == '.')) {
        if (eml->length > base->length) {
            emlptr += eml->length - base->length;
            if (!OPENSSL_strcasecmp(baseptr, emlptr))
                return YX509_V_OK;
        }
        return YX509_V_ERR_PERMITTED_VIOLATION;
    }

    /* If we have anything before '@' match local part */

    if (baseat) {
        if (baseat != baseptr) {
            if ((baseat - baseptr) != (emlat - emlptr))
                return YX509_V_ERR_PERMITTED_VIOLATION;
            /* Case sensitive match of local part */
            if (strncmp(baseptr, emlptr, emlat - emlptr))
                return YX509_V_ERR_PERMITTED_VIOLATION;
        }
        /* Position base after '@' */
        baseptr = baseat + 1;
    }
    emlptr = emlat + 1;
    /* Just have hostname left to match: case insensitive */
    if (OPENSSL_strcasecmp(baseptr, emlptr))
        return YX509_V_ERR_PERMITTED_VIOLATION;

    return YX509_V_OK;

}

static int nc_uri(YASN1_IA5STRING *uri, YASN1_IA5STRING *base)
{
    const char *baseptr = (char *)base->data;
    const char *hostptr = (char *)uri->data;
    const char *p = strchr(hostptr, ':');
    int hostlen;
    /* Check for foo:// and skip past it */
    if (!p || (p[1] != '/') || (p[2] != '/'))
        return YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    hostptr = p + 3;

    /* Determine length of hostname part of URI */

    /* Look for a port indicator as end of hostname first */

    p = strchr(hostptr, ':');
    /* Otherwise look for trailing slash */
    if (!p)
        p = strchr(hostptr, '/');

    if (!p)
        hostlen = strlen(hostptr);
    else
        hostlen = p - hostptr;

    if (hostlen == 0)
        return YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX;

    /* Special case: inital '.' is RHS match */
    if (*baseptr == '.') {
        if (hostlen > base->length) {
            p = hostptr + hostlen - base->length;
            if (!OPENSSL_strncasecmp(p, baseptr, base->length))
                return YX509_V_OK;
        }
        return YX509_V_ERR_PERMITTED_VIOLATION;
    }

    if ((base->length != (int)hostlen)
        || OPENSSL_strncasecmp(hostptr, baseptr, hostlen))
        return YX509_V_ERR_PERMITTED_VIOLATION;

    return YX509_V_OK;

}