/*
 * Copyright 2006-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Implementation of RFC 3779 section 3.2.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include <openssl/bn.h>
#include "ext_dat.h"

#ifndef OPENSSL_NO_RFC3779

/*
 * OpenSSL ASN.1 template translation of RFC 3779 3.2.3.
 */

YASN1_SEQUENCE(ASRange) = {
  YASN1_SIMPLE(ASRange, min, YASN1_INTEGER),
  YASN1_SIMPLE(ASRange, max, YASN1_INTEGER)
} YASN1_SEQUENCE_END(ASRange)

YASN1_CHOICE(ASIdOrRange) = {
  YASN1_SIMPLE(ASIdOrRange, u.id,    YASN1_INTEGER),
  YASN1_SIMPLE(ASIdOrRange, u.range, ASRange)
} YASN1_CHOICE_END(ASIdOrRange)

YASN1_CHOICE(ASIdentifierChoice) = {
  YASN1_SIMPLE(ASIdentifierChoice,      u.inherit,       YASN1_NULL),
  YASN1_SEQUENCE_OF(ASIdentifierChoice, u.asIdsOrRanges, ASIdOrRange)
} YASN1_CHOICE_END(ASIdentifierChoice)

YASN1_SEQUENCE(ASIdentifiers) = {
  YASN1_EXP_OPT(ASIdentifiers, asnum, ASIdentifierChoice, 0),
  YASN1_EXP_OPT(ASIdentifiers, rdi,   ASIdentifierChoice, 1)
} YASN1_SEQUENCE_END(ASIdentifiers)

IMPLEMENT_YASN1_FUNCTIONS(ASRange)
IMPLEMENT_YASN1_FUNCTIONS(ASIdOrRange)
IMPLEMENT_YASN1_FUNCTIONS(ASIdentifierChoice)
IMPLEMENT_YASN1_FUNCTIONS(ASIdentifiers)

/*
 * i2r method for an ASIdentifierChoice.
 */
static int i2r_ASIdentifierChoice(BIO *out,
                                  ASIdentifierChoice *choice,
                                  int indent, const char *msg)
{
    int i;
    char *s;
    if (choice == NULL)
        return 1;
    BIO_pprintf(out, "%*s%s:\n", indent, "", msg);
    switch (choice->type) {
    case ASIdentifierChoice_inherit:
        BIO_pprintf(out, "%*sinherit\n", indent + 2, "");
        break;
    case ASIdentifierChoice_asIdsOrRanges:
        for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges); i++) {
            ASIdOrRange *aor =
                sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
            switch (aor->type) {
            case ASIdOrRange_id:
                if ((s = i2s_YASN1_INTEGER(NULL, aor->u.id)) == NULL)
                    return 0;
                BIO_pprintf(out, "%*s%s\n", indent + 2, "", s);
                OPENSSL_free(s);
                break;
            case ASIdOrRange_range:
                if ((s = i2s_YASN1_INTEGER(NULL, aor->u.range->min)) == NULL)
                    return 0;
                BIO_pprintf(out, "%*s%s-", indent + 2, "", s);
                OPENSSL_free(s);
                if ((s = i2s_YASN1_INTEGER(NULL, aor->u.range->max)) == NULL)
                    return 0;
                BIO_pprintf(out, "%s\n", s);
                OPENSSL_free(s);
                break;
            default:
                return 0;
            }
        }
        break;
    default:
        return 0;
    }
    return 1;
}

/*
 * i2r method for an ASIdentifier extension.
 */
static int i2r_ASIdentifiers(const YX509V3_EXT_METHOD *method,
                             void *ext, BIO *out, int indent)
{
    ASIdentifiers *asid = ext;
    return (i2r_ASIdentifierChoice(out, asid->asnum, indent,
                                   "Autonomous System Numbers") &&
            i2r_ASIdentifierChoice(out, asid->rdi, indent,
                                   "Routing Domain Identifiers"));
}

/*
 * Sort comparison function for a sequence of ASIdOrRange elements.
 */
static int ASIdOrRange_cmp(const ASIdOrRange *const *a_,
                           const ASIdOrRange *const *b_)
{
    const ASIdOrRange *a = *a_, *b = *b_;

    assert((a->type == ASIdOrRange_id && a->u.id != NULL) ||
           (a->type == ASIdOrRange_range && a->u.range != NULL &&
            a->u.range->min != NULL && a->u.range->max != NULL));

    assert((b->type == ASIdOrRange_id && b->u.id != NULL) ||
           (b->type == ASIdOrRange_range && b->u.range != NULL &&
            b->u.range->min != NULL && b->u.range->max != NULL));

    if (a->type == ASIdOrRange_id && b->type == ASIdOrRange_id)
        return YASN1_INTEGER_cmp(a->u.id, b->u.id);

    if (a->type == ASIdOrRange_range && b->type == ASIdOrRange_range) {
        int r = YASN1_INTEGER_cmp(a->u.range->min, b->u.range->min);
        return r != 0 ? r : YASN1_INTEGER_cmp(a->u.range->max,
                                             b->u.range->max);
    }

    if (a->type == ASIdOrRange_id)
        return YASN1_INTEGER_cmp(a->u.id, b->u.range->min);
    else
        return YASN1_INTEGER_cmp(a->u.range->min, b->u.id);
}

/*
 * Add an inherit element.
 */
int YX509v3_asid_add_inherit(ASIdentifiers *asid, int which)
{
    ASIdentifierChoice **choice;
    if (asid == NULL)
        return 0;
    switch (which) {
    case V3_ASID_ASNUM:
        choice = &asid->asnum;
        break;
    case V3_ASID_RDI:
        choice = &asid->rdi;
        break;
    default:
        return 0;
    }
    if (*choice == NULL) {
        if ((*choice = ASIdentifierChoice_new()) == NULL)
            return 0;
        if (((*choice)->u.inherit = YASN1_NULL_new()) == NULL)
            return 0;
        (*choice)->type = ASIdentifierChoice_inherit;
    }
    return (*choice)->type == ASIdentifierChoice_inherit;
}

/*
 * Add an ID or range to an ASIdentifierChoice.
 */
int YX509v3_asid_add_id_or_range(ASIdentifiers *asid,
                                int which, YASN1_INTEGER *min, YASN1_INTEGER *max)
{
    ASIdentifierChoice **choice;
    ASIdOrRange *aor;
    if (asid == NULL)
        return 0;
    switch (which) {
    case V3_ASID_ASNUM:
        choice = &asid->asnum;
        break;
    case V3_ASID_RDI:
        choice = &asid->rdi;
        break;
    default:
        return 0;
    }
    if (*choice != NULL && (*choice)->type == ASIdentifierChoice_inherit)
        return 0;
    if (*choice == NULL) {
        if ((*choice = ASIdentifierChoice_new()) == NULL)
            return 0;
        (*choice)->u.asIdsOrRanges = sk_ASIdOrRange_new(ASIdOrRange_cmp);
        if ((*choice)->u.asIdsOrRanges == NULL)
            return 0;
        (*choice)->type = ASIdentifierChoice_asIdsOrRanges;
    }
    if ((aor = ASIdOrRange_new()) == NULL)
        return 0;
    if (max == NULL) {
        aor->type = ASIdOrRange_id;
        aor->u.id = min;
    } else {
        aor->type = ASIdOrRange_range;
        if ((aor->u.range = ASRange_new()) == NULL)
            goto err;
        YASN1_INTEGER_free(aor->u.range->min);
        aor->u.range->min = min;
        YASN1_INTEGER_free(aor->u.range->max);
        aor->u.range->max = max;
    }
    if (!(sk_ASIdOrRange_push((*choice)->u.asIdsOrRanges, aor)))
        goto err;
    return 1;

 err:
    ASIdOrRange_free(aor);
    return 0;
}

/*
 * Extract min and max values from an ASIdOrRange.
 */
static int extract_min_max(ASIdOrRange *aor,
                           YASN1_INTEGER **min, YASN1_INTEGER **max)
{
    if (!ossl_assert(aor != NULL))
        return 0;
    switch (aor->type) {
    case ASIdOrRange_id:
        *min = aor->u.id;
        *max = aor->u.id;
        return 1;
    case ASIdOrRange_range:
        *min = aor->u.range->min;
        *max = aor->u.range->max;
        return 1;
    }

    return 0;
}

/*
 * Check whether an ASIdentifierChoice is in canonical form.
 */
static int ASIdentifierChoice_is_canonical(ASIdentifierChoice *choice)
{
    YASN1_INTEGER *a_max_plus_one = NULL;
    YASN1_INTEGER *orig;
    BIGNUMX *bn = NULL;
    int i, ret = 0;

    /*
     * Empty element or inheritance is canonical.
     */
    if (choice == NULL || choice->type == ASIdentifierChoice_inherit)
        return 1;

    /*
     * If not a list, or if empty list, it's broken.
     */
    if (choice->type != ASIdentifierChoice_asIdsOrRanges ||
        sk_ASIdOrRange_num(choice->u.asIdsOrRanges) == 0)
        return 0;

    /*
     * It's a list, check it.
     */
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1; i++) {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        ASIdOrRange *b = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i + 1);
        YASN1_INTEGER *a_min = NULL, *a_max = NULL, *b_min = NULL, *b_max =
            NULL;

        if (!extract_min_max(a, &a_min, &a_max)
                || !extract_min_max(b, &b_min, &b_max))
            goto done;

        /*
         * Punt misordered list, overlapping start, or inverted range.
         */
        if (YASN1_INTEGER_cmp(a_min, b_min) >= 0 ||
            YASN1_INTEGER_cmp(a_min, a_max) > 0 ||
            YASN1_INTEGER_cmp(b_min, b_max) > 0)
            goto done;

        /*
         * Calculate a_max + 1 to check for adjacency.
         */
        if ((bn == NULL && (bn = BNY_new()) == NULL) ||
            YASN1_INTEGER_to_BN(a_max, bn) == NULL ||
            !BNY_add_word(bn, 1)) {
            YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL,
                      ERR_R_MALLOC_FAILURE);
            goto done;
        }

        if ((a_max_plus_one =
                BN_to_YASN1_INTEGER(bn, orig = a_max_plus_one)) == NULL) {
            a_max_plus_one = orig;
            YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL,
                      ERR_R_MALLOC_FAILURE);
            goto done;
        }

        /*
         * Punt if adjacent or overlapping.
         */
        if (YASN1_INTEGER_cmp(a_max_plus_one, b_min) >= 0)
            goto done;
    }

    /*
     * Check for inverted range.
     */
    i = sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1;
    {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        YASN1_INTEGER *a_min, *a_max;
        if (a != NULL && a->type == ASIdOrRange_range) {
            if (!extract_min_max(a, &a_min, &a_max)
                    || YASN1_INTEGER_cmp(a_min, a_max) > 0)
                goto done;
        }
    }

    ret = 1;

 done:
    YASN1_INTEGER_free(a_max_plus_one);
    BN_free(bn);
    return ret;
}

/*
 * Check whether an ASIdentifier extension is in canonical form.
 */
int YX509v3_asid_is_canonical(ASIdentifiers *asid)
{
    return (asid == NULL ||
            (ASIdentifierChoice_is_canonical(asid->asnum) &&
             ASIdentifierChoice_is_canonical(asid->rdi)));
}

/*
 * Whack an ASIdentifierChoice into canonical form.
 */
static int ASIdentifierChoice_canonize(ASIdentifierChoice *choice)
{
    YASN1_INTEGER *a_max_plus_one = NULL;
    YASN1_INTEGER *orig;
    BIGNUMX *bn = NULL;
    int i, ret = 0;

    /*
     * Nothing to do for empty element or inheritance.
     */
    if (choice == NULL || choice->type == ASIdentifierChoice_inherit)
        return 1;

    /*
     * If not a list, or if empty list, it's broken.
     */
    if (choice->type != ASIdentifierChoice_asIdsOrRanges ||
        sk_ASIdOrRange_num(choice->u.asIdsOrRanges) == 0) {
        YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                  YX509V3_R_EXTENSION_VALUE_ERROR);
        return 0;
    }

    /*
     * We have a non-empty list.  Sort it.
     */
    sk_ASIdOrRange_sort(choice->u.asIdsOrRanges);

    /*
     * Now check for errors and suboptimal encoding, rejecting the
     * former and fixing the latter.
     */
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1; i++) {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        ASIdOrRange *b = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i + 1);
        YASN1_INTEGER *a_min = NULL, *a_max = NULL, *b_min = NULL, *b_max =
            NULL;

        if (!extract_min_max(a, &a_min, &a_max)
                || !extract_min_max(b, &b_min, &b_max))
            goto done;

        /*
         * Make sure we're properly sorted (paranoia).
         */
        if (!ossl_assert(YASN1_INTEGER_cmp(a_min, b_min) <= 0))
            goto done;

        /*
         * Punt inverted ranges.
         */
        if (YASN1_INTEGER_cmp(a_min, a_max) > 0 ||
            YASN1_INTEGER_cmp(b_min, b_max) > 0)
            goto done;

        /*
         * Check for overlaps.
         */
        if (YASN1_INTEGER_cmp(a_max, b_min) >= 0) {
            YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                      YX509V3_R_EXTENSION_VALUE_ERROR);
            goto done;
        }

        /*
         * Calculate a_max + 1 to check for adjacency.
         */
        if ((bn == NULL && (bn = BNY_new()) == NULL) ||
            YASN1_INTEGER_to_BN(a_max, bn) == NULL ||
            !BNY_add_word(bn, 1)) {
            YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                      ERR_R_MALLOC_FAILURE);
            goto done;
        }

        if ((a_max_plus_one =
                 BN_to_YASN1_INTEGER(bn, orig = a_max_plus_one)) == NULL) {
            a_max_plus_one = orig;
            YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                      ERR_R_MALLOC_FAILURE);
            goto done;
        }

        /*
         * If a and b are adjacent, merge them.
         */
        if (YASN1_INTEGER_cmp(a_max_plus_one, b_min) == 0) {
            ASRange *r;
            switch (a->type) {
            case ASIdOrRange_id:
                if ((r = OPENSSL_malloc(sizeof(*r))) == NULL) {
                    YX509V3err(YX509V3_F_ASIDENTIFIERCHOICE_CANONIZE,
                              ERR_R_MALLOC_FAILURE);
                    goto done;
                }
                r->min = a_min;
                r->max = b_max;
                a->type = ASIdOrRange_range;
                a->u.range = r;
                break;
            case ASIdOrRange_range:
                YASN1_INTEGER_free(a->u.range->max);
                a->u.range->max = b_max;
                break;
            }
            switch (b->type) {
            case ASIdOrRange_id:
                b->u.id = NULL;
                break;
            case ASIdOrRange_range:
                b->u.range->max = NULL;
                break;
            }
            ASIdOrRange_free(b);
            (void)sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i + 1);
            i--;
            continue;
        }
    }

    /*
     * Check for final inverted range.
     */
    i = sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1;
    {
        ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
        YASN1_INTEGER *a_min, *a_max;
        if (a != NULL && a->type == ASIdOrRange_range) {
            if (!extract_min_max(a, &a_min, &a_max)
                    || YASN1_INTEGER_cmp(a_min, a_max) > 0)
                goto done;
        }
    }

    /* Paranoia */
    if (!ossl_assert(ASIdentifierChoice_is_canonical(choice)))
        goto done;

    ret = 1;

 done:
    YASN1_INTEGER_free(a_max_plus_one);
    BN_free(bn);
    return ret;
}

/*
 * Whack an ASIdentifier extension into canonical form.
 */
int YX509v3_asid_canonize(ASIdentifiers *asid)
{
    return (asid == NULL ||
            (ASIdentifierChoice_canonize(asid->asnum) &&
             ASIdentifierChoice_canonize(asid->rdi)));
}

/*
 * v2i method for an ASIdentifier extension.
 */
static void *v2i_ASIdentifiers(const struct v3_ext_method *method,
                               struct v3_ext_ctx *ctx,
                               STACK_OF(CONF_VALUE) *values)
{
    YASN1_INTEGER *min = NULL, *max = NULL;
    ASIdentifiers *asid = NULL;
    int i;

    if ((asid = ASIdentifiers_new()) == NULL) {
        YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
        CONF_VALUE *val = sk_CONF_VALUE_value(values, i);
        int i1 = 0, i2 = 0, i3 = 0, is_range = 0, which = 0;

        /*
         * Figure out whether this is an AS or an RDI.
         */
        if (!name_cmp(val->name, "AS")) {
            which = V3_ASID_ASNUM;
        } else if (!name_cmp(val->name, "RDI")) {
            which = V3_ASID_RDI;
        } else {
            YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS,
                      YX509V3_R_EXTENSION_NAME_ERROR);
            YX509V3_conf_err(val);
            goto err;
        }

        /*
         * Handle inheritance.
         */
        if (strcmp(val->value, "inherit") == 0) {
            if (YX509v3_asid_add_inherit(asid, which))
                continue;
            YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS,
                      YX509V3_R_INVALID_INHERITANCE);
            YX509V3_conf_err(val);
            goto err;
        }

        /*
         * Number, range, or mistake, pick it apart and figure out which.
         */
        i1 = strspn(val->value, "0123456789");
        if (val->value[i1] == '\0') {
            is_range = 0;
        } else {
            is_range = 1;
            i2 = i1 + strspn(val->value + i1, " \t");
            if (val->value[i2] != '-') {
                YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS,
                          YX509V3_R_INVALID_ASNUMBER);
                YX509V3_conf_err(val);
                goto err;
            }
            i2++;
            i2 = i2 + strspn(val->value + i2, " \t");
            i3 = i2 + strspn(val->value + i2, "0123456789");
            if (val->value[i3] != '\0') {
                YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS,
                          YX509V3_R_INVALID_ASRANGE);
                YX509V3_conf_err(val);
                goto err;
            }
        }

        /*
         * Syntax is ok, read and add it.
         */
        if (!is_range) {
            if (!YX509V3_get_value_int(val, &min)) {
                YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        } else {
            char *s = OPENSSL_strdup(val->value);
            if (s == NULL) {
                YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            s[i1] = '\0';
            min = s2i_YASN1_INTEGER(NULL, s);
            max = s2i_YASN1_INTEGER(NULL, s + i2);
            OPENSSL_free(s);
            if (min == NULL || max == NULL) {
                YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (YASN1_INTEGER_cmp(min, max) > 0) {
                YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS,
                          YX509V3_R_EXTENSION_VALUE_ERROR);
                goto err;
            }
        }
        if (!YX509v3_asid_add_id_or_range(asid, which, min, max)) {
            YX509V3err(YX509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        min = max = NULL;
    }

    /*
     * Canonize the result, then we're done.
     */
    if (!YX509v3_asid_canonize(asid))
        goto err;
    return asid;

 err:
    ASIdentifiers_free(asid);
    YASN1_INTEGER_free(min);
    YASN1_INTEGER_free(max);
    return NULL;
}

/*
 * OpenSSL dispatch.
 */
const YX509V3_EXT_METHOD v3_asid = {
    NID_sbgp_autonomousSysNum,  /* nid */
    0,                          /* flags */
    YASN1_ITEM_ref(ASIdentifiers), /* template */
    0, 0, 0, 0,                 /* old functions, ignored */
    0,                          /* i2s */
    0,                          /* s2i */
    0,                          /* i2v */
    v2i_ASIdentifiers,          /* v2i */
    i2r_ASIdentifiers,          /* i2r */
    0,                          /* r2i */
    NULL                        /* extension-specific data */
};

/*
 * Figure out whether extension uses inheritance.
 */
int YX509v3_asid_inherits(ASIdentifiers *asid)
{
    return (asid != NULL &&
            ((asid->asnum != NULL &&
              asid->asnum->type == ASIdentifierChoice_inherit) ||
             (asid->rdi != NULL &&
              asid->rdi->type == ASIdentifierChoice_inherit)));
}

/*
 * Figure out whether parent contains child.
 */
static int asid_contains(ASIdOrRanges *parent, ASIdOrRanges *child)
{
    YASN1_INTEGER *p_min = NULL, *p_max = NULL, *c_min = NULL, *c_max = NULL;
    int p, c;

    if (child == NULL || parent == child)
        return 1;
    if (parent == NULL)
        return 0;

    p = 0;
    for (c = 0; c < sk_ASIdOrRange_num(child); c++) {
        if (!extract_min_max(sk_ASIdOrRange_value(child, c), &c_min, &c_max))
            return 0;
        for (;; p++) {
            if (p >= sk_ASIdOrRange_num(parent))
                return 0;
            if (!extract_min_max(sk_ASIdOrRange_value(parent, p), &p_min,
                                 &p_max))
                return 0;
            if (YASN1_INTEGER_cmp(p_max, c_max) < 0)
                continue;
            if (YASN1_INTEGER_cmp(p_min, c_min) > 0)
                return 0;
            break;
        }
    }

    return 1;
}

/*
 * Test whether a is a subset of b.
 */
int YX509v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b)
{
    int subset;

    if (a == NULL || a == b)
        return 1;

    if (b == NULL)
        return 0;

    if (YX509v3_asid_inherits(a) || YX509v3_asid_inherits(b))
        return 0;

    subset = a->asnum == NULL
             || (b->asnum != NULL
                 && asid_contains(b->asnum->u.asIdsOrRanges,
                                  a->asnum->u.asIdsOrRanges));
    if (!subset)
        return 0;

    return a->rdi == NULL
           || (b->rdi != NULL
               && asid_contains(b->rdi->u.asIdsOrRanges,
                                a->rdi->u.asIdsOrRanges));
}

/*
 * Validation error handling via callback.
 */
#define validation_err(_err_)           \
  do {                                  \
    if (ctx != NULL) {                  \
      ctx->error = _err_;               \
      ctx->error_depth = i;             \
      ctx->current_cert = x;            \
      ret = ctx->verify_cb(0, ctx);     \
    } else {                            \
      ret = 0;                          \
    }                                   \
    if (!ret)                           \
      goto done;                        \
  } while (0)

/*
 * Core code for RFC 3779 3.3 path validation.
 */
static int asid_validate_path_internal(YX509_STORE_CTX *ctx,
                                       STACK_OF(YX509) *chain,
                                       ASIdentifiers *ext)
{
    ASIdOrRanges *child_as = NULL, *child_rdi = NULL;
    int i, ret = 1, inherit_as = 0, inherit_rdi = 0;
    YX509 *x;

    if (!ossl_assert(chain != NULL && sk_YX509_num(chain) > 0)
            || !ossl_assert(ctx != NULL || ext != NULL)
            || !ossl_assert(ctx == NULL || ctx->verify_cb != NULL)) {
        if (ctx != NULL)
            ctx->error = YX509_V_ERR_UNSPECIFIED;
        return 0;
    }


    /*
     * Figure out where to start.  If we don't have an extension to
     * check, we're done.  Otherwise, check canonical form and
     * set up for walking up the chain.
     */
    if (ext != NULL) {
        i = -1;
        x = NULL;
    } else {
        i = 0;
        x = sk_YX509_value(chain, i);
        if ((ext = x->rfc3779_asid) == NULL)
            goto done;
    }
    if (!YX509v3_asid_is_canonical(ext))
        validation_err(YX509_V_ERR_INVALID_EXTENSION);
    if (ext->asnum != NULL) {
        switch (ext->asnum->type) {
        case ASIdentifierChoice_inherit:
            inherit_as = 1;
            break;
        case ASIdentifierChoice_asIdsOrRanges:
            child_as = ext->asnum->u.asIdsOrRanges;
            break;
        }
    }
    if (ext->rdi != NULL) {
        switch (ext->rdi->type) {
        case ASIdentifierChoice_inherit:
            inherit_rdi = 1;
            break;
        case ASIdentifierChoice_asIdsOrRanges:
            child_rdi = ext->rdi->u.asIdsOrRanges;
            break;
        }
    }

    /*
     * Now walk up the chain.  Extensions must be in canonical form, no
     * cert may list resources that its parent doesn't list.
     */
    for (i++; i < sk_YX509_num(chain); i++) {
        x = sk_YX509_value(chain, i);
        if (!ossl_assert(x != NULL)) {
            if (ctx != NULL)
                ctx->error = YX509_V_ERR_UNSPECIFIED;
            return 0;
        }
        if (x->rfc3779_asid == NULL) {
            if (child_as != NULL || child_rdi != NULL)
                validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
            continue;
        }
        if (!YX509v3_asid_is_canonical(x->rfc3779_asid))
            validation_err(YX509_V_ERR_INVALID_EXTENSION);
        if (x->rfc3779_asid->asnum == NULL && child_as != NULL) {
            validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
            child_as = NULL;
            inherit_as = 0;
        }
        if (x->rfc3779_asid->asnum != NULL &&
            x->rfc3779_asid->asnum->type ==
            ASIdentifierChoice_asIdsOrRanges) {
            if (inherit_as
                || asid_contains(x->rfc3779_asid->asnum->u.asIdsOrRanges,
                                 child_as)) {
                child_as = x->rfc3779_asid->asnum->u.asIdsOrRanges;
                inherit_as = 0;
            } else {
                validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
            }
        }
        if (x->rfc3779_asid->rdi == NULL && child_rdi != NULL) {
            validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
            child_rdi = NULL;
            inherit_rdi = 0;
        }
        if (x->rfc3779_asid->rdi != NULL &&
            x->rfc3779_asid->rdi->type == ASIdentifierChoice_asIdsOrRanges) {
            if (inherit_rdi ||
                asid_contains(x->rfc3779_asid->rdi->u.asIdsOrRanges,
                              child_rdi)) {
                child_rdi = x->rfc3779_asid->rdi->u.asIdsOrRanges;
                inherit_rdi = 0;
            } else {
                validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
            }
        }
    }

    /*
     * Trust anchor can't inherit.
     */
    if (!ossl_assert(x != NULL)) {
        if (ctx != NULL)
            ctx->error = YX509_V_ERR_UNSPECIFIED;
        return 0;
    }
    if (x->rfc3779_asid != NULL) {
        if (x->rfc3779_asid->asnum != NULL &&
            x->rfc3779_asid->asnum->type == ASIdentifierChoice_inherit)
            validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
        if (x->rfc3779_asid->rdi != NULL &&
            x->rfc3779_asid->rdi->type == ASIdentifierChoice_inherit)
            validation_err(YX509_V_ERR_UNNESTED_RESOURCE);
    }

 done:
    return ret;
}

#undef validation_err

/*
 * RFC 3779 3.3 path validation -- called from YX509_verify_cert().
 */
int YX509v3_asid_validate_path(YX509_STORE_CTX *ctx)
{
    if (ctx->chain == NULL
            || sk_YX509_num(ctx->chain) == 0
            || ctx->verify_cb == NULL) {
        ctx->error = YX509_V_ERR_UNSPECIFIED;
        return 0;
    }
    return asid_validate_path_internal(ctx, ctx->chain, NULL);
}

/*
 * RFC 3779 3.3 path validation of an extension.
 * Test whether chain covers extension.
 */
int YX509v3_asid_validate_resource_set(STACK_OF(YX509) *chain,
                                      ASIdentifiers *ext, int allow_inheritance)
{
    if (ext == NULL)
        return 1;
    if (chain == NULL || sk_YX509_num(chain) == 0)
        return 0;
    if (!allow_inheritance && YX509v3_asid_inherits(ext))
        return 0;
    return asid_validate_path_internal(NULL, chain, ext);
}

#endif                          /* OPENSSL_NO_RFC3779 */