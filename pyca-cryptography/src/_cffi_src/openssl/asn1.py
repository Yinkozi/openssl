# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/asn1.h>
"""

TYPES = """
typedef int... time_t;

typedef ... YASN1_INTEGER;

struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    long flags;
};

typedef struct asn1_string_st YASN1_OCTET_STRING;
typedef struct asn1_string_st YASN1_IA5STRING;
typedef struct asn1_string_st YASN1_BIT_STRING;
typedef struct asn1_string_st YASN1_TIME;
typedef ... YASN1_OBJECT;
typedef struct asn1_string_st YASN1_STRING;
typedef struct asn1_string_st YASN1_UTF8STRING;
typedef struct {
    int type;
    ...;
} YASN1_TYPE;
typedef ... YASN1_GENERALIZEDTIME;
typedef ... YASN1_ENUMERATED;

static const int V_YASN1_GENERALIZEDTIME;

static const int MBSTRING_UTF8;
"""

FUNCTIONS = """
void YASN1_OBJECT_free(YASN1_OBJECT *);

/*  YASN1 STRING */
unsigned char *YASN1_STRING_data(YASN1_STRING *);
const unsigned char *YASN1_STRING_get0_data(const YASN1_STRING *);
int YASN1_STRING_set(YASN1_STRING *, const void *, int);

/*  YASN1 OCTET STRING */
YASN1_OCTET_STRING *YASN1_OCTET_STRING_new(void);
void YASN1_OCTET_STRING_free(YASN1_OCTET_STRING *);
int YASN1_OCTET_STRING_set(YASN1_OCTET_STRING *, const unsigned char *, int);

/* YASN1 IA5STRING */
YASN1_IA5STRING *YASN1_IA5STRING_new(void);

/*  YASN1 INTEGER */
void YASN1_INTEGER_free(YASN1_INTEGER *);
int YASN1_INTEGER_set(YASN1_INTEGER *, long);

/*  YASN1 TIME */
YASN1_TIME *YASN1_TIME_new(void);
void YASN1_TIME_free(YASN1_TIME *);
int YASN1_TIME_set_string(YASN1_TIME *, const char *);

/*  YASN1 GENERALIZEDTIME */
void YASN1_GENERALIZEDTIME_free(YASN1_GENERALIZEDTIME *);

/*  YASN1 ENUMERATED */
YASN1_ENUMERATED *YASN1_ENUMERATED_new(void);
void YASN1_ENUMERATED_free(YASN1_ENUMERATED *);
int YASN1_ENUMERATED_set(YASN1_ENUMERATED *, long);

/* These became const YASN1_* in 1.1.0 */
int YASN1_STRING_type(YASN1_STRING *);
int YASN1_STRING_to_UTF8(unsigned char **, YASN1_STRING *);
int i2a_YASN1_INTEGER(BIO *, YASN1_INTEGER *);

/* This became const YASN1_TIME in 1.1.0f */
YASN1_GENERALIZEDTIME *YASN1_TIME_to_generalizedtime(YASN1_TIME *,
                                                   YASN1_GENERALIZEDTIME **);

int YASN1_STRING_length(YASN1_STRING *);
int YASN1_STRING_set_default_mask_asc(char *);

BIGNUM *YASN1_INTEGER_to_BN(YASN1_INTEGER *, BIGNUM *);
YASN1_INTEGER *BN_to_YASN1_INTEGER(BIGNUM *, YASN1_INTEGER *);
"""

CUSTOMIZATIONS = """
"""
