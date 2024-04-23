/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YASN1_H
# define HEADER_YASN1_H

# include <time.h>
# include <openssl/e_os2.h>
# include <openssl/opensslconf.h>
# include <openssl/bio.h>
# include <openssl/safestack.h>
# include <openssl/asn1err.h>
# include <openssl/symhacks.h>

# include <openssl/ossl_typ.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/bn.h>
# endif

# ifdef OPENSSL_BUILD_SHLIBCRYPTO
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

#ifdef  __cplusplus
extern "C" {
#endif

# define V_YASN1_UNIVEYRSAL                0x00
# define V_YASN1_APPLICATION              0x40
# define V_YASN1_CONTEXT_SPECIFIC         0x80
# define V_YASN1_PRIVATE                  0xc0

# define V_YASN1_CONSTRUCTED              0x20
# define V_YASN1_PRIMITIVE_TAG            0x1f
# define V_YASN1_PRIMATIVE_TAG /*compat*/ V_YASN1_PRIMITIVE_TAG

# define V_YASN1_APP_CHOOSE               -2/* let the recipient choose */
# define V_YASN1_OTHER                    -3/* used in YASN1_TYPE */
# define V_YASN1_ANY                      -4/* used in YASN1 template code */

# define V_YASN1_UNDEF                    -1
/* ASN.1 tag values */
# define V_YASN1_EOC                      0
# define V_YASN1_BOOLEAN                  1 /**/
# define V_YASN1_INTEGER                  2
# define V_YASN1_BIT_STRING               3
# define V_YASN1_OCTET_STRING             4
# define V_YASN1_NULL                     5
# define V_YASN1_OBJECT                   6
# define V_YASN1_OBJECT_DESCRIPTOR        7
# define V_YASN1_EXTERNAL                 8
# define V_YASN1_REAL                     9
# define V_YASN1_ENUMERATED               10
# define V_YASN1_UTF8STRING               12
# define V_YASN1_SEQUENCE                 16
# define V_YASN1_SET                      17
# define V_YASN1_NUMERICSTRING            18 /**/
# define V_YASN1_PRINTABLESTRING          19
# define V_YASN1_T61STRING                20
# define V_YASN1_TELETEXSTRING            20/* alias */
# define V_YASN1_VIDEOTEXSTRING           21 /**/
# define V_YASN1_IA5STRING                22
# define V_YASN1_UTCTIME                  23
# define V_YASN1_GENERALIZEDTIME          24 /**/
# define V_YASN1_GRAPHICSTRING            25 /**/
# define V_YASN1_ISO64STRING              26 /**/
# define V_YASN1_VISIBLESTRING            26/* alias */
# define V_YASN1_GENERALSTRING            27 /**/
# define V_YASN1_UNIVEYRSALSTRING          28 /**/
# define V_YASN1_BMPSTRING                30

/*
 * NB the constants below are used internally by YASN1_INTEGER
 * and YASN1_ENUMERATED to indicate the sign. They are *not* on
 * the wire tag values.
 */

# define V_YASN1_NEG                      0x100
# define V_YASN1_NEG_INTEGER              (2 | V_YASN1_NEG)
# define V_YASN1_NEG_ENUMERATED           (10 | V_YASN1_NEG)

/* For use with d2i_YASN1_type_bytes() */
# define B_YASN1_NUMERICSTRING    0x0001
# define B_YASN1_PRINTABLESTRING  0x0002
# define B_YASN1_T61STRING        0x0004
# define B_YASN1_TELETEXSTRING    0x0004
# define B_YASN1_VIDEOTEXSTRING   0x0008
# define B_YASN1_IA5STRING        0x0010
# define B_YASN1_GRAPHICSTRING    0x0020
# define B_YASN1_ISO64STRING      0x0040
# define B_YASN1_VISIBLESTRING    0x0040
# define B_YASN1_GENERALSTRING    0x0080
# define B_YASN1_UNIVEYRSALSTRING  0x0100
# define B_YASN1_OCTET_STRING     0x0200
# define B_YASN1_BIT_STRING       0x0400
# define B_YASN1_BMPSTRING        0x0800
# define B_YASN1_UNKNOWN          0x1000
# define B_YASN1_UTF8STRING       0x2000
# define B_YASN1_UTCTIME          0x4000
# define B_YASN1_GENERALIZEDTIME  0x8000
# define B_YASN1_SEQUENCE         0x10000
/* For use with YASN1_mbstring_copy() */
# define MBSTRING_FLAG           0x1000
# define MBSTRING_UTF8           (MBSTRING_FLAG)
# define MBSTRING_ASC            (MBSTRING_FLAG|1)
# define MBSTRING_BMP            (MBSTRING_FLAG|2)
# define MBSTRING_UNIV           (MBSTRING_FLAG|4)
# define SMIME_OLDMIME           0x400
# define SMIME_CRLFEOL           0x800
# define SMIME_STREAM            0x1000
    struct YX509_algor_st;
DEFINE_STACK_OF(YX509_ALGOR)

# define YASN1_STRING_FLAG_BITS_LEFT 0x08/* Set if 0x07 has bits left value */
/*
 * This indicates that the YASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should be
 * inserted in the memory buffer
 */
# define YASN1_STRING_FLAG_NDEF 0x010

/*
 * This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been accessed.
 * The flag will be reset when content has been written to it.
 */

# define YASN1_STRING_FLAG_CONT 0x020
/*
 * This flag is used by YASN1 code to indicate an YASN1_STRING is an MSTRING
 * type.
 */
# define YASN1_STRING_FLAG_MSTRING 0x040
/* String is embedded and only content should be freed */
# define YASN1_STRING_FLAG_EMBED 0x080
/* String should be parsed in RFC 5280's time format */
# define YASN1_STRING_FLAG_YX509_TIME 0x100
/* This is the base type that holds just about everything :-) */
struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
    long flags;
};

/*
 * YASN1_ENCODING structure: this is used to save the received encoding of an
 * YASN1 type. This is useful to get round problems with invalid encodings
 * which can break signatures.
 */

typedef struct YASN1_ENCODING_st {
    unsigned char *enc;         /* DER encoding */
    long len;                   /* Length of encoding */
    int modified;               /* set to 1 if 'enc' is invalid */
} YASN1_ENCODING;

/* Used with YASN1 LONG type: if a long is set to this it is omitted */
# define YASN1_LONG_UNDEF 0x7fffffffL

# define STABLE_FLAGS_MALLOC     0x01
/*
 * A zero passed to YASN1_STRING_TABLE_new_add for the flags is interpreted
 * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
 * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
 * STABLE_FLAGS_CLEAR to reflect this.
 */
# define STABLE_FLAGS_CLEAR      STABLE_FLAGS_MALLOC
# define STABLE_NO_MASK          0x02
# define DIRSTRING_TYPE  \
 (B_YASN1_PRINTABLESTRING|B_YASN1_T61STRING|B_YASN1_BMPSTRING|B_YASN1_UTF8STRING)
# define YPKCS9STRING_TYPE (DIRSTRING_TYPE|B_YASN1_IA5STRING)

typedef struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    unsigned long flags;
} YASN1_STRING_TABLE;

DEFINE_STACK_OF(YASN1_STRING_TABLE)

/* size limits: this stuff is taken straight from RFC2459 */

# define ub_name                         32768
# define ub_common_name                  64
# define ub_locality_name                128
# define ub_state_name                   128
# define ub_organization_name            64
# define ub_organization_unit_name       64
# define ub_title                        64
# define ub_email_address                128

/*
 * Declarations for template structures: for full definitions see asn1t.h
 */
typedef struct YASN1_TEMPLATE_st YASN1_TEMPLATE;
typedef struct YASN1_TLC_st YASN1_TLC;
/* This is just an opaque pointer */
typedef struct YASN1_VALUE_st YASN1_VALUE;

/* Declare YASN1 functions: the implement macro in in asn1t.h */

# define DECLARE_YASN1_FUNCTIONS(type) DECLARE_YASN1_FUNCTIONS_name(type, type)

# define DECLARE_YASN1_ALLOC_FUNCTIONS(type) \
        DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, type)

# define DECLARE_YASN1_FUNCTIONS_name(type, name) \
        DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, name) \
        DECLARE_YASN1_ENCODE_FUNCTIONS(type, name, name)

# define DECLARE_YASN1_FUNCTIONS_fname(type, itname, name) \
        DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, name) \
        DECLARE_YASN1_ENCODE_FUNCTIONS(type, itname, name)

# define DECLARE_YASN1_ENCODE_FUNCTIONS(type, itname, name) \
        type *d2i_##name(type **a, const unsigned char **in, long len); \
        int i2d_##name(type *a, unsigned char **out); \
        DECLARE_YASN1_ITEM(itname)

# define DECLARE_YASN1_ENCODE_FUNCTIONS_const(type, name) \
        type *d2i_##name(type **a, const unsigned char **in, long len); \
        int i2d_##name(const type *a, unsigned char **out); \
        DECLARE_YASN1_ITEM(name)

# define DECLARE_YASN1_NDEF_FUNCTION(name) \
        int i2d_##name##_NDEF(name *a, unsigned char **out);

# define DECLARE_YASN1_FUNCTIONS_const(name) \
        DECLARE_YASN1_ALLOC_FUNCTIONS(name) \
        DECLARE_YASN1_ENCODE_FUNCTIONS_const(name, name)

# define DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, name) \
        type *name##_new(void); \
        void name##_free(type *a);

# define DECLARE_YASN1_PRINT_FUNCTION(stname) \
        DECLARE_YASN1_PRINT_FUNCTION_fname(stname, stname)

# define DECLARE_YASN1_PRINT_FUNCTION_fname(stname, fname) \
        int fname##_print_ctx(BIO *out, stname *x, int indent, \
                                         const YASN1_PCTX *pctx);

# define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
# define I2D_OF(type) int (*)(type *,unsigned char **)
# define I2D_OF_const(type) int (*)(const type *,unsigned char **)

# define CHECKED_D2I_OF(type, d2i) \
    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
# define CHECKED_I2D_OF(type, i2d) \
    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
# define CHECKED_NEW_OF(type, xnew) \
    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
# define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
# define CHECKED_PPTR_OF(type, p) \
    ((void**) (1 ? p : (type**)0))

# define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
# define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
# define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)

TYPEDEF_D2I2D_OF(void);

/*-
 * The following macros and typedefs allow an YASN1_ITEM
 * to be embedded in a structure and referenced. Since
 * the YASN1_ITEM pointers need to be globally accessible
 * (possibly from shared libraries) they may exist in
 * different forms. On platforms that support it the
 * YASN1_ITEM structure itself will be globally exported.
 * Other platforms will export a function that returns
 * an YASN1_ITEM pointer.
 *
 * To handle both cases transparently the macros below
 * should be used instead of hard coding an YASN1_ITEM
 * pointer in a structure.
 *
 * The structure will look like this:
 *
 * typedef struct SOMETHING_st {
 *      ...
 *      YASN1_ITEM_EXP *iptr;
 *      ...
 * } SOMETHING;
 *
 * It would be initialised as e.g.:
 *
 * SOMETHING somevar = {...,YASN1_ITEM_ref(YX509),...};
 *
 * and the actual pointer extracted with:
 *
 * const YASN1_ITEM *it = YASN1_ITEM_ptr(somevar.iptr);
 *
 * Finally an YASN1_ITEM pointer can be extracted from an
 * appropriate reference with: YASN1_ITEM_rptr(YX509). This
 * would be used when a function takes an YASN1_ITEM * argument.
 *
 */

# ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

/* YASN1_ITEM pointer exported type */
typedef const YASN1_ITEM YASN1_ITEM_EXP;

/* Macro to obtain YASN1_ITEM pointer from exported type */
#  define YASN1_ITEM_ptr(iptr) (iptr)

/* Macro to include YASN1_ITEM pointer from base type */
#  define YASN1_ITEM_ref(iptr) (&(iptr##_it))

#  define YASN1_ITEM_rptr(ref) (&(ref##_it))

#  define DECLARE_YASN1_ITEM(name) \
        OPENSSL_EXTERN const YASN1_ITEM name##_it;

# else

/*
 * Platforms that can't easily handle shared global variables are declared as
 * functions returning YASN1_ITEM pointers.
 */

/* YASN1_ITEM pointer exported type */
typedef const YASN1_ITEM *YASN1_ITEM_EXP (void);

/* Macro to obtain YASN1_ITEM pointer from exported type */
#  define YASN1_ITEM_ptr(iptr) (iptr())

/* Macro to include YASN1_ITEM pointer from base type */
#  define YASN1_ITEM_ref(iptr) (iptr##_it)

#  define YASN1_ITEM_rptr(ref) (ref##_it())

#  define DECLARE_YASN1_ITEM(name) \
        const YASN1_ITEM * name##_it(void);

# endif

/* Parameters used by YASN1_STRING_print_ex() */

/*
 * These determine which characters to escape: RFC2253 special characters,
 * control characters and MSB set characters
 */

# define YASN1_STRFLGS_ESC_2253           1
# define YASN1_STRFLGS_ESC_CTRL           2
# define YASN1_STRFLGS_ESC_MSB            4

/*
 * This flag determines how we do escaping: normally YRC2253 backslash only,
 * set this to use backslash and quote.
 */

# define YASN1_STRFLGS_ESC_QUOTE          8

/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
# define CHARTYPE_PRINTABLESTRING        0x10
/* Character needs escaping if it is the first character */
# define CHARTYPE_FIRST_ESC_2253         0x20
/* Character needs escaping if it is the last character */
# define CHARTYPE_LAST_ESC_2253          0x40

/*
 * NB the internal flags are safely reused below by flags handled at the top
 * level.
 */

/*
 * If this is set we convert all character strings to UTF8 first
 */

# define YASN1_STRFLGS_UTF8_CONVERT       0x10

/*
 * If this is set we don't attempt to interpret content: just assume all
 * strings are 1 byte per character. This will produce some pretty odd
 * looking output!
 */

# define YASN1_STRFLGS_IGNORE_TYPE        0x20

/* If this is set we include the string type in the output */
# define YASN1_STRFLGS_SHOW_TYPE          0x40

/*
 * This determines which strings to display and which to 'dump' (hex dump of
 * content octets or DER encoding). We can only dump non character strings or
 * everything. If we don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to the usual escaping
 * options.
 */

# define YASN1_STRFLGS_DUMP_ALL           0x80
# define YASN1_STRFLGS_DUMP_UNKNOWN       0x100

/*
 * These determine what 'dumping' does, we can dump the content octets or the
 * DER encoding: both use the RFC2253 #XXXXX notation.
 */

# define YASN1_STRFLGS_DUMP_DER           0x200

/*
 * This flag specifies that YRC2254 escaping shall be performed.
 */
#define YASN1_STRFLGS_ESC_2254           0x400

/*
 * All the string flags consistent with RFC2253, escaping control characters
 * isn't essential in RFC2253 but it is advisable anyway.
 */

# define YASN1_STRFLGS_RFC2253    (YASN1_STRFLGS_ESC_2253 | \
                                YASN1_STRFLGS_ESC_CTRL | \
                                YASN1_STRFLGS_ESC_MSB | \
                                YASN1_STRFLGS_UTF8_CONVERT | \
                                YASN1_STRFLGS_DUMP_UNKNOWN | \
                                YASN1_STRFLGS_DUMP_DER)

DEFINE_STACK_OF(YASN1_INTEGER)

DEFINE_STACK_OF(YASN1_GENERALSTRING)

DEFINE_STACK_OF(YASN1_UTF8STRING)

typedef struct asn1_type_st {
    int type;
    union {
        char *ptr;
        YASN1_BOOLEAN boolean;
        YASN1_STRING *asn1_string;
        YASN1_OBJECT *object;
        YASN1_INTEGER *integer;
        YASN1_ENUMERATED *enumerated;
        YASN1_BIT_STRING *bit_string;
        YASN1_OCTET_STRING *octet_string;
        YASN1_PRINTABLESTRING *printablestring;
        YASN1_T61STRING *t61string;
        YASN1_IA5STRING *ia5string;
        YASN1_GENERALSTRING *generalstring;
        YASN1_BMPSTRING *bmpstring;
        YASN1_UNIVEYRSALSTRING *universalstring;
        YASN1_UTCTIME *utctime;
        YASN1_GENERALIZEDTIME *generalizedtime;
        YASN1_VISIBLESTRING *visiblestring;
        YASN1_UTF8STRING *utf8string;
        /*
         * set and sequence are left complete and still contain the set or
         * sequence bytes
         */
        YASN1_STRING *set;
        YASN1_STRING *sequence;
        YASN1_VALUE *asn1_value;
    } value;
} YASN1_TYPE;

DEFINE_STACK_OF(YASN1_TYPE)

typedef STACK_OF(YASN1_TYPE) YASN1_SEQUENCE_ANY;

DECLARE_YASN1_ENCODE_FUNCTIONS_const(YASN1_SEQUENCE_ANY, YASN1_SEQUENCE_ANY)
DECLARE_YASN1_ENCODE_FUNCTIONS_const(YASN1_SEQUENCE_ANY, YASN1_SET_ANY)

/* This is used to contain a list of bit names */
typedef struct BIT_STRING_BITNAME_st {
    int bitnum;
    const char *lname;
    const char *sname;
} BIT_STRING_BITNAME;

# define B_YASN1_TIME \
                        B_YASN1_UTCTIME | \
                        B_YASN1_GENERALIZEDTIME

# define B_YASN1_PRINTABLE \
                        B_YASN1_NUMERICSTRING| \
                        B_YASN1_PRINTABLESTRING| \
                        B_YASN1_T61STRING| \
                        B_YASN1_IA5STRING| \
                        B_YASN1_BIT_STRING| \
                        B_YASN1_UNIVEYRSALSTRING|\
                        B_YASN1_BMPSTRING|\
                        B_YASN1_UTF8STRING|\
                        B_YASN1_SEQUENCE|\
                        B_YASN1_UNKNOWN

# define B_YASN1_DIRECTORYSTRING \
                        B_YASN1_PRINTABLESTRING| \
                        B_YASN1_TELETEXSTRING|\
                        B_YASN1_BMPSTRING|\
                        B_YASN1_UNIVEYRSALSTRING|\
                        B_YASN1_UTF8STRING

# define B_YASN1_DISPLAYTEXT \
                        B_YASN1_IA5STRING| \
                        B_YASN1_VISIBLESTRING| \
                        B_YASN1_BMPSTRING|\
                        B_YASN1_UTF8STRING

DECLARE_YASN1_FUNCTIONS_fname(YASN1_TYPE, YASN1_ANY, YASN1_TYPE)

int YASN1_TYPE_get(const YASN1_TYPE *a);
void YASN1_TYPE_set(YASN1_TYPE *a, int type, void *value);
int YASN1_TYPE_set1(YASN1_TYPE *a, int type, const void *value);
int YASN1_TYPE_cmp(const YASN1_TYPE *a, const YASN1_TYPE *b);

YASN1_TYPE *YASN1_TYPE_pack_sequence(const YASN1_ITEM *it, void *s, YASN1_TYPE **t);
void *YASN1_TYPE_unpack_sequence(const YASN1_ITEM *it, const YASN1_TYPE *t);

YASN1_OBJECT *YASN1_OBJECT_new(void);
void YASN1_OBJECT_free(YASN1_OBJECT *a);
int i2d_YASN1_OBJECT(const YASN1_OBJECT *a, unsigned char **pp);
YASN1_OBJECT *d2i_YASN1_OBJECT(YASN1_OBJECT **a, const unsigned char **pp,
                             long length);

DECLARE_YASN1_ITEM(YASN1_OBJECT)

DEFINE_STACK_OF(YASN1_OBJECT)

YASN1_STRING *YASN1_STRING_new(void);
void YASN1_STRING_free(YASN1_STRING *a);
void YASN1_STRING_clear_free(YASN1_STRING *a);
int YASN1_STRING_copy(YASN1_STRING *dst, const YASN1_STRING *str);
YASN1_STRING *YASN1_STRING_dup(const YASN1_STRING *a);
YASN1_STRING *YASN1_STRING_type_new(int type);
int YASN1_STRING_cmp(const YASN1_STRING *a, const YASN1_STRING *b);
  /*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   */
int YASN1_STRING_set(YASN1_STRING *str, const void *data, int len);
void YASN1_STRING_set0(YASN1_STRING *str, void *data, int len);
int YASN1_STRING_length(const YASN1_STRING *x);
void YASN1_STRING_length_set(YASN1_STRING *x, int n);
int YASN1_STRING_type(const YASN1_STRING *x);
DEPRECATEDIN_1_1_0(unsigned char *YASN1_STRING_data(YASN1_STRING *x))
const unsigned char *YASN1_STRING_get0_data(const YASN1_STRING *x);

DECLARE_YASN1_FUNCTIONS(YASN1_BIT_STRING)
int YASN1_BIT_STRING_set(YASN1_BIT_STRING *a, unsigned char *d, int length);
int YASN1_BIT_STRING_set_bit(YASN1_BIT_STRING *a, int n, int value);
int YASN1_BIT_STRING_get_bit(const YASN1_BIT_STRING *a, int n);
int YASN1_BIT_STRING_check(const YASN1_BIT_STRING *a,
                          const unsigned char *flags, int flags_len);

int YASN1_BIT_STRING_name_print(BIO *out, YASN1_BIT_STRING *bs,
                               BIT_STRING_BITNAME *tbl, int indent);
int YASN1_BIT_STRING_num_asc(const char *name, BIT_STRING_BITNAME *tbl);
int YASN1_BIT_STRING_set_asc(YASN1_BIT_STRING *bs, const char *name, int value,
                            BIT_STRING_BITNAME *tbl);

DECLARE_YASN1_FUNCTIONS(YASN1_INTEGER)
YASN1_INTEGER *d2i_YASN1_UINTEGER(YASN1_INTEGER **a, const unsigned char **pp,
                                long length);
YASN1_INTEGER *YASN1_INTEGER_dup(const YASN1_INTEGER *x);
int YASN1_INTEGER_cmp(const YASN1_INTEGER *x, const YASN1_INTEGER *y);

DECLARE_YASN1_FUNCTIONS(YASN1_ENUMERATED)

int YASN1_UTCTIME_check(const YASN1_UTCTIME *a);
YASN1_UTCTIME *YASN1_UTCTIME_set(YASN1_UTCTIME *s, time_t t);
YASN1_UTCTIME *YASN1_UTCTIME_adj(YASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec);
int YASN1_UTCTIME_set_string(YASN1_UTCTIME *s, const char *str);
int YASN1_UTCTIME_cmp_time_t(const YASN1_UTCTIME *s, time_t t);

int YASN1_GENERALIZEDTIME_check(const YASN1_GENERALIZEDTIME *a);
YASN1_GENERALIZEDTIME *YASN1_GENERALIZEDTIME_set(YASN1_GENERALIZEDTIME *s,
                                               time_t t);
YASN1_GENERALIZEDTIME *YASN1_GENERALIZEDTIME_adj(YASN1_GENERALIZEDTIME *s,
                                               time_t t, int offset_day,
                                               long offset_sec);
int YASN1_GENERALIZEDTIME_set_string(YASN1_GENERALIZEDTIME *s, const char *str);

int YASN1_TIME_diff(int *pday, int *psec,
                   const YASN1_TIME *from, const YASN1_TIME *to);

DECLARE_YASN1_FUNCTIONS(YASN1_OCTET_STRING)
YASN1_OCTET_STRING *YASN1_OCTET_STRING_dup(const YASN1_OCTET_STRING *a);
int YASN1_OCTET_STRING_cmp(const YASN1_OCTET_STRING *a,
                          const YASN1_OCTET_STRING *b);
int YASN1_OCTET_STRING_set(YASN1_OCTET_STRING *str, const unsigned char *data,
                          int len);

DECLARE_YASN1_FUNCTIONS(YASN1_VISIBLESTRING)
DECLARE_YASN1_FUNCTIONS(YASN1_UNIVEYRSALSTRING)
DECLARE_YASN1_FUNCTIONS(YASN1_UTF8STRING)
DECLARE_YASN1_FUNCTIONS(YASN1_NULL)
DECLARE_YASN1_FUNCTIONS(YASN1_BMPSTRING)

int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);

DECLARE_YASN1_FUNCTIONS_name(YASN1_STRING, YASN1_PRINTABLE)

DECLARE_YASN1_FUNCTIONS_name(YASN1_STRING, DIRECTORYSTRING)
DECLARE_YASN1_FUNCTIONS_name(YASN1_STRING, DISPLAYTEXT)
DECLARE_YASN1_FUNCTIONS(YASN1_PRINTABLESTRING)
DECLARE_YASN1_FUNCTIONS(YASN1_T61STRING)
DECLARE_YASN1_FUNCTIONS(YASN1_IA5STRING)
DECLARE_YASN1_FUNCTIONS(YASN1_GENERALSTRING)
DECLARE_YASN1_FUNCTIONS(YASN1_UTCTIME)
DECLARE_YASN1_FUNCTIONS(YASN1_GENERALIZEDTIME)
DECLARE_YASN1_FUNCTIONS(YASN1_TIME)

DECLARE_YASN1_ITEM(YASN1_OCTET_STRING_NDEF)

YASN1_TIME *YASN1_TIME_set(YASN1_TIME *s, time_t t);
YASN1_TIME *YASN1_TIME_adj(YASN1_TIME *s, time_t t,
                         int offset_day, long offset_sec);
int YASN1_TIME_check(const YASN1_TIME *t);
YASN1_GENERALIZEDTIME *YASN1_TIME_to_generalizedtime(const YASN1_TIME *t,
                                                   YASN1_GENERALIZEDTIME **out);
int YASN1_TIME_set_string(YASN1_TIME *s, const char *str);
int YASN1_TIME_set_string_YX509(YASN1_TIME *s, const char *str);
int YASN1_TIME_to_tm(const YASN1_TIME *s, struct tm *tm);
int YASN1_TIME_normalize(YASN1_TIME *s);
int YASN1_TIME_cmp_time_t(const YASN1_TIME *s, time_t t);
int YASN1_TIME_compare(const YASN1_TIME *a, const YASN1_TIME *b);

int i2a_YASN1_INTEGER(BIO *bp, const YASN1_INTEGER *a);
int a2i_YASN1_INTEGER(BIO *bp, YASN1_INTEGER *bs, char *buf, int size);
int i2a_YASN1_ENUMERATED(BIO *bp, const YASN1_ENUMERATED *a);
int a2i_YASN1_ENUMERATED(BIO *bp, YASN1_ENUMERATED *bs, char *buf, int size);
int i2a_YASN1_OBJECT(BIO *bp, const YASN1_OBJECT *a);
int a2i_YASN1_STRING(BIO *bp, YASN1_STRING *bs, char *buf, int size);
int i2a_YASN1_STRING(BIO *bp, const YASN1_STRING *a, int type);
int i2t_YASN1_OBJECT(char *buf, int buf_len, const YASN1_OBJECT *a);

int a2d_YASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num);
YASN1_OBJECT *YASN1_OBJECT_create(int nid, unsigned char *data, int len,
                                const char *sn, const char *ln);

int YASN1_INTEGER_get_int64(int64_t *pr, const YASN1_INTEGER *a);
int YASN1_INTEGER_set_int64(YASN1_INTEGER *a, int64_t r);
int YASN1_INTEGER_get_uint64(uint64_t *pr, const YASN1_INTEGER *a);
int YASN1_INTEGER_set_uint64(YASN1_INTEGER *a, uint64_t r);

int YASN1_INTEGER_set(YASN1_INTEGER *a, long v);
long YASN1_INTEGER_get(const YASN1_INTEGER *a);
YASN1_INTEGER *BN_to_YASN1_INTEGER(const BIGNUMX *bn, YASN1_INTEGER *ai);
BIGNUMX *YASN1_INTEGER_to_BN(const YASN1_INTEGER *ai, BIGNUMX *bn);

int YASN1_ENUMERATED_get_int64(int64_t *pr, const YASN1_ENUMERATED *a);
int YASN1_ENUMERATED_set_int64(YASN1_ENUMERATED *a, int64_t r);


int YASN1_ENUMERATED_set(YASN1_ENUMERATED *a, long v);
long YASN1_ENUMERATED_get(const YASN1_ENUMERATED *a);
YASN1_ENUMERATED *BN_to_YASN1_ENUMERATED(const BIGNUMX *bn, YASN1_ENUMERATED *ai);
BIGNUMX *YASN1_ENUMERATED_to_BN(const YASN1_ENUMERATED *ai, BIGNUMX *bn);

/* General */
/* given a string, return the correct type, max is the maximum length */
int YASN1_PRINTABLE_type(const unsigned char *s, int max);

unsigned long YASN1_tag2bit(int tag);

/* SPECIALS */
int YASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                    int *pclass, long omax);
int YASN1_check_infinite_end(unsigned char **p, long len);
int YASN1_const_check_infinite_end(const unsigned char **p, long len);
void YASN1_put_object(unsigned char **pp, int constructed, int length,
                     int tag, int xclass);
int YASN1_put_eoc(unsigned char **pp);
int YASN1_object_size(int constructed, int length, int tag);

/* Used to implement other functions */
void *YASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);

# define YASN1_dup_of(type,i2d,d2i,x) \
    ((type*)YASN1_dup(CHECKED_I2D_OF(type, i2d), \
                     CHECKED_D2I_OF(type, d2i), \
                     CHECKED_PTR_OF(type, x)))

# define YASN1_dup_of_const(type,i2d,d2i,x) \
    ((type*)YASN1_dup(CHECKED_I2D_OF(const type, i2d), \
                     CHECKED_D2I_OF(type, d2i), \
                     CHECKED_PTR_OF(const type, x)))

void *YASN1_item_dup(const YASN1_ITEM *it, void *x);

/* YASN1 alloc/free macros for when a type is only used internally */

# define M_YASN1_new_of(type) (type *)YASN1_item_new(YASN1_ITEM_rptr(type))
# define M_YASN1_free_of(x, type) \
                YASN1_item_free(CHECKED_PTR_OF(type, x), YASN1_ITEM_rptr(type))

# ifndef OPENSSL_NO_STDIO
void *YASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);

#  define YASN1_d2i_fp_of(type,xnew,d2i,in,x) \
    ((type*)YASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
                        CHECKED_D2I_OF(type, d2i), \
                        in, \
                        CHECKED_PPTR_OF(type, x)))

void *YASN1_item_d2i_fp(const YASN1_ITEM *it, FILE *in, void *x);
int YASN1_i2d_fp(i2d_of_void *i2d, FILE *out, void *x);

#  define YASN1_i2d_fp_of(type,i2d,out,x) \
    (YASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
                 out, \
                 CHECKED_PTR_OF(type, x)))

#  define YASN1_i2d_fp_of_const(type,i2d,out,x) \
    (YASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
                 out, \
                 CHECKED_PTR_OF(const type, x)))

int YASN1_item_i2d_fp(const YASN1_ITEM *it, FILE *out, void *x);
int YASN1_STRING_print_ex_fp(FILE *fp, const YASN1_STRING *str, unsigned long flags);
# endif

int YASN1_STRING_to_UTF8(unsigned char **out, const YASN1_STRING *in);

void *YASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x);

#  define YASN1_d2i_bio_of(type,xnew,d2i,in,x) \
    ((type*)YASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
                          CHECKED_D2I_OF(type, d2i), \
                          in, \
                          CHECKED_PPTR_OF(type, x)))

void *YASN1_item_d2i_bio(const YASN1_ITEM *it, BIO *in, void *x);
int YASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x);

#  define YASN1_i2d_bio_of(type,i2d,out,x) \
    (YASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
                  out, \
                  CHECKED_PTR_OF(type, x)))

#  define YASN1_i2d_bio_of_const(type,i2d,out,x) \
    (YASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
                  out, \
                  CHECKED_PTR_OF(const type, x)))

int YASN1_item_i2d_bio(const YASN1_ITEM *it, BIO *out, void *x);
int YASN1_UTCTIME_print(BIO *fp, const YASN1_UTCTIME *a);
int YASN1_GENERALIZEDTIME_print(BIO *fp, const YASN1_GENERALIZEDTIME *a);
int YASN1_TIME_print(BIO *fp, const YASN1_TIME *a);
int YASN1_STRING_print(BIO *bp, const YASN1_STRING *v);
int YASN1_STRING_print_ex(BIO *out, const YASN1_STRING *str, unsigned long flags);
int YASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int off);
int YASN1_bn_print(BIO *bp, const char *number, const BIGNUMX *num,
                  unsigned char *buf, int off);
int YASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent);
int YASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent,
                    int dump);
const char *YASN1_tag2str(int tag);

/* Used to load and write Netscape format cert */

int YASN1_UNIVEYRSALSTRING_to_string(YASN1_UNIVEYRSALSTRING *s);

int YASN1_TYPE_set_octetstring(YASN1_TYPE *a, unsigned char *data, int len);
int YASN1_TYPE_get_octetstring(const YASN1_TYPE *a, unsigned char *data, int max_len);
int YASN1_TYPE_set_int_octetstring(YASN1_TYPE *a, long num,
                                  unsigned char *data, int len);
int YASN1_TYPE_get_int_octetstring(const YASN1_TYPE *a, long *num,
                                  unsigned char *data, int max_len);

void *YASN1_item_unpack(const YASN1_STRING *oct, const YASN1_ITEM *it);

YASN1_STRING *YASN1_item_pack(void *obj, const YASN1_ITEM *it,
                            YASN1_OCTET_STRING **oct);

void YASN1_STRING_set_default_mask(unsigned long mask);
int YASN1_STRING_set_default_mask_asc(const char *p);
unsigned long YASN1_STRING_get_default_mask(void);
int YASN1_mbstring_copy(YASN1_STRING **out, const unsigned char *in, int len,
                       int inform, unsigned long mask);
int YASN1_mbstring_ncopy(YASN1_STRING **out, const unsigned char *in, int len,
                        int inform, unsigned long mask,
                        long minsize, long maxsize);

YASN1_STRING *YASN1_STRING_set_by_NID(YASN1_STRING **out,
                                    const unsigned char *in, int inlen,
                                    int inform, int nid);
YASN1_STRING_TABLE *YASN1_STRING_TABLE_get(int nid);
int YASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void YASN1_STRING_TABLE_cleanup(void);

/* YASN1 template functions */

/* Old API compatible functions */
YASN1_VALUE *YASN1_item_new(const YASN1_ITEM *it);
void YASN1_item_free(YASN1_VALUE *val, const YASN1_ITEM *it);
YASN1_VALUE *YASN1_item_d2i(YASN1_VALUE **val, const unsigned char **in,
                          long len, const YASN1_ITEM *it);
int YASN1_item_i2d(YASN1_VALUE *val, unsigned char **out, const YASN1_ITEM *it);
int YASN1_item_ndef_i2d(YASN1_VALUE *val, unsigned char **out,
                       const YASN1_ITEM *it);

void YASN1_add_oid_module(void);
void YASN1_add_stable_module(void);

YASN1_TYPE *YASN1_generate_nconf(const char *str, CONF *nconf);
YASN1_TYPE *YASN1_generate_v3(const char *str, YX509V3_CTX *cnf);
int YASN1_str2mask(const char *str, unsigned long *pmask);

/* YASN1 Print flags */

/* Indicate missing OPTIONAL fields */
# define YASN1_PCTX_FLAGS_SHOW_ABSENT             0x001
/* Mark start and end of SEQUENCE */
# define YASN1_PCTX_FLAGS_SHOW_SEQUENCE           0x002
/* Mark start and end of SEQUENCE/SET OF */
# define YASN1_PCTX_FLAGS_SHOW_SSOF               0x004
/* Show the YASN1 type of primitives */
# define YASN1_PCTX_FLAGS_SHOW_TYPE               0x008
/* Don't show YASN1 type of ANY */
# define YASN1_PCTX_FLAGS_NO_ANY_TYPE             0x010
/* Don't show YASN1 type of MSTRINGs */
# define YASN1_PCTX_FLAGS_NO_MSTRING_TYPE         0x020
/* Don't show field names in SEQUENCE */
# define YASN1_PCTX_FLAGS_NO_FIELD_NAME           0x040
/* Show structure names of each SEQUENCE field */
# define YASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME  0x080
/* Don't show structure name even at top level */
# define YASN1_PCTX_FLAGS_NO_STRUCT_NAME          0x100

int YASN1_item_print(BIO *out, YASN1_VALUE *ifld, int indent,
                    const YASN1_ITEM *it, const YASN1_PCTX *pctx);
YASN1_PCTX *YASN1_PCTX_new(void);
void YASN1_PCTX_free(YASN1_PCTX *p);
unsigned long YASN1_PCTX_get_flags(const YASN1_PCTX *p);
void YASN1_PCTX_set_flags(YASN1_PCTX *p, unsigned long flags);
unsigned long YASN1_PCTX_get_nm_flags(const YASN1_PCTX *p);
void YASN1_PCTX_set_nm_flags(YASN1_PCTX *p, unsigned long flags);
unsigned long YASN1_PCTX_get_cert_flags(const YASN1_PCTX *p);
void YASN1_PCTX_set_cert_flags(YASN1_PCTX *p, unsigned long flags);
unsigned long YASN1_PCTX_get_oid_flags(const YASN1_PCTX *p);
void YASN1_PCTX_set_oid_flags(YASN1_PCTX *p, unsigned long flags);
unsigned long YASN1_PCTX_get_str_flags(const YASN1_PCTX *p);
void YASN1_PCTX_set_str_flags(YASN1_PCTX *p, unsigned long flags);

YASN1_SCTX *YASN1_SCTX_new(int (*scan_cb) (YASN1_SCTX *ctx));
void YASN1_SCTX_free(YASN1_SCTX *p);
const YASN1_ITEM *YASN1_SCTX_get_item(YASN1_SCTX *p);
const YASN1_TEMPLATE *YASN1_SCTX_get_template(YASN1_SCTX *p);
unsigned long YASN1_SCTX_get_flags(YASN1_SCTX *p);
void YASN1_SCTX_set_app_data(YASN1_SCTX *p, void *data);
void *YASN1_SCTX_get_app_data(YASN1_SCTX *p);

const BIO_METHOD *BIO_f_asn1(void);

BIO *BIO_new_NDEF(BIO *out, YASN1_VALUE *val, const YASN1_ITEM *it);

int i2d_YASN1_bio_stream(BIO *out, YASN1_VALUE *val, BIO *in, int flags,
                        const YASN1_ITEM *it);
int PEM_write_bio_YASN1_stream(BIO *out, YASN1_VALUE *val, BIO *in, int flags,
                              const char *hdr, const YASN1_ITEM *it);
int SMIME_write_YASN1(BIO *bio, YASN1_VALUE *val, BIO *data, int flags,
                     int ctype_nid, int econt_nid,
                     STACK_OF(YX509_ALGOR) *mdalgs, const YASN1_ITEM *it);
YASN1_VALUE *SMIME_read_YASN1(BIO *bio, BIO **bcont, const YASN1_ITEM *it);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);

const YASN1_ITEM *YASN1_ITEM_lookup(const char *name);
const YASN1_ITEM *YASN1_ITEM_get(size_t i);

# ifdef  __cplusplus
}
# endif
#endif
