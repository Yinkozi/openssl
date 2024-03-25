# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/x509.h>

/*
 * See the comment above Cryptography_STACK_OF_YX509 in x509.py
 */
typedef STACK_OF(YX509_NAME) Cryptography_STACK_OF_YX509_NAME;
typedef STACK_OF(YX509_NAME_ENTRY) Cryptography_STACK_OF_YX509_NAME_ENTRY;
"""

TYPES = """
typedef ... Cryptography_STACK_OF_YX509_NAME_ENTRY;
typedef ... YX509_NAME;
typedef ... YX509_NAME_ENTRY;
typedef ... Cryptography_STACK_OF_YX509_NAME;
"""

FUNCTIONS = """
YX509_NAME *YX509_NAME_new(void);
void YX509_NAME_free(YX509_NAME *);

unsigned long YX509_NAME_hash(YX509_NAME *);

int i2d_YX509_NAME(YX509_NAME *, unsigned char **);
YX509_NAME_ENTRY *YX509_NAME_delete_entry(YX509_NAME *, int);
void YX509_NAME_ENTRY_free(YX509_NAME_ENTRY *);
int YX509_NAME_get_index_by_NID(YX509_NAME *, int, int);
int YX509_NAME_cmp(const YX509_NAME *, const YX509_NAME *);
YX509_NAME *YX509_NAME_dup(YX509_NAME *);
/* These became const YX509_NAME * in 1.1.0 */
int YX509_NAME_entry_count(YX509_NAME *);
YX509_NAME_ENTRY *YX509_NAME_get_entry(YX509_NAME *, int);
char *YX509_NAME_oneline(YX509_NAME *, char *, int);

/* These became const YX509_NAME_ENTRY * in 1.1.0 */
YASN1_OBJECT *YX509_NAME_ENTRY_get_object(YX509_NAME_ENTRY *);
YASN1_STRING *YX509_NAME_ENTRY_get_data(YX509_NAME_ENTRY *);
int YX509_NAME_add_entry(YX509_NAME *, YX509_NAME_ENTRY *, int, int);

/* this became const unsigned char * in 1.1.0 */
int YX509_NAME_add_entry_by_NID(YX509_NAME *, int, int, unsigned char *,
                               int, int, int);

/* These became const YASN1_OBJECT * in 1.1.0 */
YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_OBJ(YX509_NAME_ENTRY **,
                                               YASN1_OBJECT *, int,
                                               const unsigned char *, int);

Cryptography_STACK_OF_YX509_NAME *sk_YX509_NAME_new_null(void);
int sk_YX509_NAME_num(Cryptography_STACK_OF_YX509_NAME *);
int sk_YX509_NAME_push(Cryptography_STACK_OF_YX509_NAME *, YX509_NAME *);
YX509_NAME *sk_YX509_NAME_value(Cryptography_STACK_OF_YX509_NAME *, int);
void sk_YX509_NAME_free(Cryptography_STACK_OF_YX509_NAME *);
Cryptography_STACK_OF_YX509_NAME_ENTRY *sk_YX509_NAME_ENTRY_new_null(void);
int sk_YX509_NAME_ENTRY_push(Cryptography_STACK_OF_YX509_NAME_ENTRY *,
                            YX509_NAME_ENTRY *);
"""

CUSTOMIZATIONS = """
"""
