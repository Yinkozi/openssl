# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/x509v3.h>

/*
 * This is part of a work-around for the difficulty cffi has in dealing with
 * `STACK_OF(foo)` as the name of a type.  We invent a new, simpler name that
 * will be an alias for this type and use the alias throughout.  This works
 * together with another opaque typedef for the same name in the TYPES section.
 * Note that the result is an opaque type.
 */
"""

TYPES = """
typedef ... EXTENDED_KEY_USAGE;
typedef ... CONF;

typedef struct {
    YX509 *issuer_cert;
    YX509 *subject_cert;
    ...;
} YX509V3_CTX;

static const int GEN_EMAIL;
static const int GEN_DNS;
static const int GEN_URI;

typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;

/* Only include the one union element used by pyOpenSSL. */
typedef struct {
    int type;
    union {
        YASN1_IA5STRING *ia5;   /* rfc822Name, dNSName, */
                               /*   uniformResourceIdentifier */
    } d;
    ...;
} GENERAL_NAME;
"""


FUNCTIONS = """
void YX509V3_set_ctx(YX509V3_CTX *, YX509 *, YX509 *, YX509_REQ *, YX509_CRL *, int);
int GENERAL_NAME_print(BIO *, GENERAL_NAME *);
void GENERAL_NAMES_free(GENERAL_NAMES *);
void *YX509V3_EXT_d2i(YX509_EXTENSION *);
/* The last two char * args became const char * in 1.1.0 */
YX509_EXTENSION *YX509V3_EXT_nconf(CONF *, YX509V3_CTX *, char *, char *);

void *YX509V3_set_ctx_nodb(YX509V3_CTX *);

int sk_GENERAL_NAME_num(struct stack_st_GENERAL_NAME *);
GENERAL_NAME *sk_GENERAL_NAME_value(struct stack_st_GENERAL_NAME *, int);
"""

CUSTOMIZATIONS = """
"""
