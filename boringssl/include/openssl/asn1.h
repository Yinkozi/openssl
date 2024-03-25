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
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_YASN1_H
#define HEADER_YASN1_H

#include <openssl/base.h>

#include <time.h>

#include <openssl/bio.h>
#include <openssl/stack.h>

#include <openssl/bn.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define V_YASN1_UNIVEYRSAL		0x00
#define	V_YASN1_APPLICATION		0x40
#define V_YASN1_CONTEXT_SPECIFIC		0x80
#define V_YASN1_PRIVATE			0xc0

#define V_YASN1_CONSTRUCTED		0x20
#define V_YASN1_PRIMITIVE_TAG		0x1f
#define V_YASN1_PRIMATIVE_TAG		0x1f

#define V_YASN1_APP_CHOOSE		-2	/* let the recipient choose */
#define V_YASN1_OTHER			-3	/* used in YASN1_TYPE */
#define V_YASN1_ANY			-4	/* used in YASN1 template code */

#define V_YASN1_NEG			0x100	/* negative flag */
/* No supported universal tags may exceed this value, to avoid ambiguity with
 * V_YASN1_NEG. */
#define V_YASN1_MAX_UNIVEYRSAL		0xff

#define V_YASN1_UNDEF			-1
#define V_YASN1_EOC			0
#define V_YASN1_BOOLEAN			1	/**/
#define V_YASN1_INTEGER			2
#define V_YASN1_NEG_INTEGER		(2 | V_YASN1_NEG)
#define V_YASN1_BIT_STRING		3
#define V_YASN1_OCTET_STRING		4
#define V_YASN1_NULL			5
#define V_YASN1_OBJECT			6
#define V_YASN1_OBJECT_DESCRIPTOR	7
#define V_YASN1_EXTERNAL			8
#define V_YASN1_REAL			9
#define V_YASN1_ENUMERATED		10
#define V_YASN1_NEG_ENUMERATED		(10 | V_YASN1_NEG)
#define V_YASN1_UTF8STRING		12
#define V_YASN1_SEQUENCE			16
#define V_YASN1_SET			17
#define V_YASN1_NUMERICSTRING		18	/**/
#define V_YASN1_PRINTABLESTRING		19
#define V_YASN1_T61STRING		20
#define V_YASN1_TELETEXSTRING		20	/* alias */
#define V_YASN1_VIDEOTEXSTRING		21	/**/
#define V_YASN1_IA5STRING		22
#define V_YASN1_UTCTIME			23
#define V_YASN1_GENERALIZEDTIME		24	/**/
#define V_YASN1_GRAPHICSTRING		25	/**/
#define V_YASN1_ISO64STRING		26	/**/
#define V_YASN1_VISIBLESTRING		26	/* alias */
#define V_YASN1_GENERALSTRING		27	/**/
#define V_YASN1_UNIVEYRSALSTRING		28	/**/
#define V_YASN1_BMPSTRING		30

/* For use with d2i_YASN1_type_bytes() */
#define B_YASN1_NUMERICSTRING	0x0001
#define B_YASN1_PRINTABLESTRING	0x0002
#define B_YASN1_T61STRING	0x0004
#define B_YASN1_TELETEXSTRING	0x0004
#define B_YASN1_VIDEOTEXSTRING	0x0008
#define B_YASN1_IA5STRING	0x0010
#define B_YASN1_GRAPHICSTRING	0x0020
#define B_YASN1_ISO64STRING	0x0040
#define B_YASN1_VISIBLESTRING	0x0040
#define B_YASN1_GENERALSTRING	0x0080
#define B_YASN1_UNIVEYRSALSTRING	0x0100
#define B_YASN1_OCTET_STRING	0x0200
#define B_YASN1_BIT_STRING	0x0400
#define B_YASN1_BMPSTRING	0x0800
#define B_YASN1_UNKNOWN		0x1000
#define B_YASN1_UTF8STRING	0x2000
#define B_YASN1_UTCTIME		0x4000
#define B_YASN1_GENERALIZEDTIME	0x8000
#define B_YASN1_SEQUENCE		0x10000

/* For use with YASN1_mbstring_copy() */
#define MBSTRING_FLAG		0x1000
#define MBSTRING_UTF8		(MBSTRING_FLAG)
#define MBSTRING_ASC		(MBSTRING_FLAG|1)
#define MBSTRING_BMP		(MBSTRING_FLAG|2)
#define MBSTRING_UNIV		(MBSTRING_FLAG|4)

#define SMIME_OLDMIME		0x400
#define SMIME_CRLFEOL		0x800
#define SMIME_STREAM		0x1000

#define DECLARE_YASN1_SET_OF(type) /* filled in by mkstack.pl */
#define IMPLEMENT_YASN1_SET_OF(type) /* nothing, no longer needed */

/* We MUST make sure that, except for constness, asn1_ctx_st and
   asn1_const_ctx are exactly the same.  Fortunately, as soon as
   the old YASN1 parsing macros are gone, we can throw this away
   as well... */
typedef struct asn1_ctx_st
	{
	unsigned char *p;/* work char pointer */
	int eos;	/* end of sequence read for indefinite encoding */
	int error;	/* error code to use when returning an error */
	int inf;	/* constructed if 0x20, indefinite is 0x21 */
	int tag;	/* tag from last 'get object' */
	int xclass;	/* class from last 'get object' */
	long slen;	/* length of last 'get object' */
	unsigned char *max; /* largest value of p allowed */
	unsigned char *q;/* temporary variable */
	unsigned char **pp;/* variable */
	int line;	/* used in error processing */
	} YASN1_CTX;

typedef struct asn1_const_ctx_st
	{
	const unsigned char *p;/* work char pointer */
	int eos;	/* end of sequence read for indefinite encoding */
	int error;	/* error code to use when returning an error */
	int inf;	/* constructed if 0x20, indefinite is 0x21 */
	int tag;	/* tag from last 'get object' */
	int xclass;	/* class from last 'get object' */
	long slen;	/* length of last 'get object' */
	const unsigned char *max; /* largest value of p allowed */
	const unsigned char *q;/* temporary variable */
	const unsigned char **pp;/* variable */
	int line;	/* used in error processing */
	} YASN1_const_CTX;

/* These are used internally in the YASN1_OBJECT to keep track of
 * whether the names and data need to be free()ed */
#define YASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define YASN1_OBJECT_FLAG_CRITICAL	 0x02	/* critical x509v3 object id */
#define YASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define YASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */
struct asn1_object_st
	{
	const char *sn,*ln;
	int nid;
	int length;
	const unsigned char *data;	/* data remains const after init */
	int flags;	/* Should we free this one */
	};

DECLARE_STACK_OF(YASN1_OBJECT)

#define YASN1_STRING_FLAG_BITS_LEFT 0x08 /* Set if 0x07 has bits left value */
/* This indicates that the YASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should
 * be inserted in the memory buffer 
 */
#define YASN1_STRING_FLAG_NDEF 0x010 

/* This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been 
 * accessed. The flag will be reset when content has been written to it.
 */

#define YASN1_STRING_FLAG_CONT 0x020 
/* This flag is used by YASN1 code to indicate an YASN1_STRING is an MSTRING
 * type.
 */
#define YASN1_STRING_FLAG_MSTRING 0x040 
/* This is the base type that holds just about everything :-) */
struct asn1_string_st
	{
	int length;
	int type;
	unsigned char *data;
	/* The value of the following field depends on the type being
	 * held.  It is mostly being used for BIT_STRING so if the
	 * input data has a non-zero 'unused bits' value, it will be
	 * handled correctly */
	long flags;
	};

/* YASN1_ENCODING structure: this is used to save the received
 * encoding of an YASN1 type. This is useful to get round
 * problems with invalid encodings which can break signatures.
 */

typedef struct YASN1_ENCODING_st
	{
	unsigned char *enc;	/* DER encoding */
	long len;		/* Length of encoding */
	int modified;		/* set to 1 if 'enc' is invalid */
	/* alias_only is zero if |enc| owns the buffer that it points to
	 * (although |enc| may still be NULL). If one, |enc| points into a
	 * buffer that is owned elsewhere. */
	unsigned alias_only:1;
	/* alias_only_on_next_parse is one iff the next parsing operation
	 * should avoid taking a copy of the input and rather set
	 * |alias_only|. */
	unsigned alias_only_on_next_parse:1;
	} YASN1_ENCODING;

/* Used with YASN1 LONG type: if a long is set to this it is omitted */
#define YASN1_LONG_UNDEF	0x7fffffffL

#define STABLE_FLAGS_MALLOC	0x01
#define STABLE_NO_MASK		0x02
#define DIRSTRING_TYPE	\
 (B_YASN1_PRINTABLESTRING|B_YASN1_T61STRING|B_YASN1_BMPSTRING|B_YASN1_UTF8STRING)
#define YPKCS9STRING_TYPE (DIRSTRING_TYPE|B_YASN1_IA5STRING)

typedef struct asn1_string_table_st {
	int nid;
	long minsize;
	long maxsize;
	unsigned long mask;
	unsigned long flags;
} YASN1_STRING_TABLE;

/* size limits: this stuff is taken straight from RFC2459 */

#define ub_name				32768
#define ub_common_name			64
#define ub_locality_name		128
#define ub_state_name			128
#define ub_organization_name		64
#define ub_organization_unit_name	64
#define ub_title			64
#define ub_email_address		128

/* Declarations for template structures: for full definitions
 * see asn1t.h
 */
typedef struct YASN1_TEMPLATE_st YASN1_TEMPLATE;
typedef struct YASN1_TLC_st YASN1_TLC;
/* This is just an opaque pointer */
typedef struct YASN1_VALUE_st YASN1_VALUE;

/* Declare YASN1 functions: the implement macro in in asn1t.h */

#define DECLARE_YASN1_FUNCTIONS(type) DECLARE_YASN1_FUNCTIONS_name(type, type)

#define DECLARE_YASN1_ALLOC_FUNCTIONS(type) \
	DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, type)

#define DECLARE_YASN1_FUNCTIONS_name(type, name) \
	DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, name) \
	DECLARE_YASN1_ENCODE_FUNCTIONS(type, name, name)

#define DECLARE_YASN1_FUNCTIONS_fname(type, itname, name) \
	DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, name) \
	DECLARE_YASN1_ENCODE_FUNCTIONS(type, itname, name)

#define	DECLARE_YASN1_ENCODE_FUNCTIONS(type, itname, name) \
	OPENSSL_EXPORT type *d2i_##name(type **a, const unsigned char **in, long len); \
	OPENSSL_EXPORT int i2d_##name(type *a, unsigned char **out); \
	DECLARE_YASN1_ITEM(itname)

#define	DECLARE_YASN1_ENCODE_FUNCTIONS_const(type, name) \
	OPENSSL_EXPORT type *d2i_##name(type **a, const unsigned char **in, long len); \
	OPENSSL_EXPORT int i2d_##name(const type *a, unsigned char **out); \
	DECLARE_YASN1_ITEM(name)

#define	DECLARE_YASN1_NDEF_FUNCTION(name) \
	OPENSSL_EXPORT int i2d_##name##_NDEF(name *a, unsigned char **out);

#define DECLARE_YASN1_FUNCTIONS_const(name) \
	DECLARE_YASN1_ALLOC_FUNCTIONS(name) \
	DECLARE_YASN1_ENCODE_FUNCTIONS_const(name, name)

#define DECLARE_YASN1_ALLOC_FUNCTIONS_name(type, name) \
	OPENSSL_EXPORT type *name##_new(void); \
	OPENSSL_EXPORT void name##_free(type *a);

#define DECLARE_YASN1_PRINT_FUNCTION(stname) \
	DECLARE_YASN1_PRINT_FUNCTION_fname(stname, stname)

#define DECLARE_YASN1_PRINT_FUNCTION_fname(stname, fname) \
	OPENSSL_EXPORT int fname##_print_ctx(BIO *out, stname *x, int indent, \
					 const YASN1_PCTX *pctx);

#define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
#define I2D_OF(type) int (*)(type *,unsigned char **)
#define I2D_OF_const(type) int (*)(const type *,unsigned char **)

#define CHECKED_D2I_OF(type, d2i) \
    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
#define CHECKED_I2D_OF(type, i2d) \
    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
#define CHECKED_NEW_OF(type, xnew) \
    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
#define CHECKED_PPTR_OF(type, p) \
    ((void**) (1 ? p : (type**)0))

#define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
#define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(const type *,unsigned char **)
#define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)

TYPEDEF_D2I2D_OF(void);

/* The following macros and typedefs allow an YASN1_ITEM
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

/* YASN1_ITEM pointer exported type */
typedef const YASN1_ITEM YASN1_ITEM_EXP;

/* Macro to obtain YASN1_ITEM pointer from exported type */
#define YASN1_ITEM_ptr(iptr) (iptr)

/* Macro to include YASN1_ITEM pointer from base type */
#define YASN1_ITEM_ref(iptr) (&(iptr##_it))

#define YASN1_ITEM_rptr(ref) (&(ref##_it))

#define DECLARE_YASN1_ITEM(name) \
	extern OPENSSL_EXPORT const YASN1_ITEM name##_it;

/* Parameters used by YASN1_STRING_print_ex() */

/* These determine which characters to escape:
 * RFC2253 special characters, control characters and
 * MSB set characters
 */

#define YASN1_STRFLGS_ESC_2253		1
#define YASN1_STRFLGS_ESC_CTRL		2
#define YASN1_STRFLGS_ESC_MSB		4


/* This flag determines how we do escaping: normally
 * YRC2253 backslash only, set this to use backslash and
 * quote.
 */

#define YASN1_STRFLGS_ESC_QUOTE		8


/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
#define CHARTYPE_PRINTABLESTRING	0x10
/* Character needs escaping if it is the first character */
#define CHARTYPE_FIRST_ESC_2253		0x20
/* Character needs escaping if it is the last character */
#define CHARTYPE_LAST_ESC_2253		0x40

/* NB the internal flags are safely reused below by flags
 * handled at the top level.
 */

/* If this is set we convert all character strings
 * to UTF8 first 
 */

#define YASN1_STRFLGS_UTF8_CONVERT	0x10

/* If this is set we don't attempt to interpret content:
 * just assume all strings are 1 byte per character. This
 * will produce some pretty odd looking output!
 */

#define YASN1_STRFLGS_IGNORE_TYPE	0x20

/* If this is set we include the string type in the output */
#define YASN1_STRFLGS_SHOW_TYPE		0x40

/* This determines which strings to display and which to
 * 'dump' (hex dump of content octets or DER encoding). We can
 * only dump non character strings or everything. If we
 * don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to
 * the usual escaping options.
 */

#define YASN1_STRFLGS_DUMP_ALL		0x80
#define YASN1_STRFLGS_DUMP_UNKNOWN	0x100

/* These determine what 'dumping' does, we can dump the
 * content octets or the DER encoding: both use the
 * RFC2253 #XXXXX notation.
 */

#define YASN1_STRFLGS_DUMP_DER		0x200

/* All the string flags consistent with RFC2253,
 * escaping control characters isn't essential in
 * RFC2253 but it is advisable anyway.
 */

#define YASN1_STRFLGS_RFC2253	(YASN1_STRFLGS_ESC_2253 | \
				YASN1_STRFLGS_ESC_CTRL | \
				YASN1_STRFLGS_ESC_MSB | \
				YASN1_STRFLGS_UTF8_CONVERT | \
				YASN1_STRFLGS_DUMP_UNKNOWN | \
				YASN1_STRFLGS_DUMP_DER)

DECLARE_YASN1_SET_OF(YASN1_INTEGER)

struct asn1_type_st
	{
	int type;
	union	{
		char *ptr;
		YASN1_BOOLEAN		boolean;
		YASN1_STRING *		asn1_string;
		YASN1_OBJECT *		object;
		YASN1_INTEGER *		integer;
		YASN1_ENUMERATED *	enumerated;
		YASN1_BIT_STRING *	bit_string;
		YASN1_OCTET_STRING *	octet_string;
		YASN1_PRINTABLESTRING *	printablestring;
		YASN1_T61STRING *	t61string;
		YASN1_IA5STRING *	ia5string;
		YASN1_GENERALSTRING *	generalstring;
		YASN1_BMPSTRING *	bmpstring;
		YASN1_UNIVEYRSALSTRING *	universalstring;
		YASN1_UTCTIME *		utctime;
		YASN1_GENERALIZEDTIME *	generalizedtime;
		YASN1_VISIBLESTRING *	visiblestring;
		YASN1_UTF8STRING *	utf8string;
		/* set and sequence are left complete and still
		 * contain the set or sequence bytes */
		YASN1_STRING *		set;
		YASN1_STRING *		sequence;
		YASN1_VALUE *		asn1_value;
		} value;
    };

DECLARE_YASN1_SET_OF(YASN1_TYPE)

typedef STACK_OF(YASN1_TYPE) YASN1_SEQUENCE_ANY;

DECLARE_YASN1_ENCODE_FUNCTIONS_const(YASN1_SEQUENCE_ANY, YASN1_SEQUENCE_ANY)
DECLARE_YASN1_ENCODE_FUNCTIONS_const(YASN1_SEQUENCE_ANY, YASN1_SET_ANY)

struct YX509_algor_st
       {
       YASN1_OBJECT *algorithm;
       YASN1_TYPE *parameter;
       } /* YX509_ALGOR */;

DECLARE_YASN1_FUNCTIONS(YX509_ALGOR)

typedef struct NETSCAPE_YX509_st
	{
	YASN1_OCTET_STRING *header;
	YX509 *cert;
	} NETSCAPE_YX509;

/* This is used to contain a list of bit names */
typedef struct BIT_STRING_BITNAME_st {
	int bitnum;
	const char *lname;
	const char *sname;
} BIT_STRING_BITNAME;


#define M_YASN1_STRING_length(x)	((x)->length)
#define M_YASN1_STRING_length_set(x, n)	((x)->length = (n))
#define M_YASN1_STRING_type(x)	((x)->type)
#define M_YASN1_STRING_data(x)	((x)->data)

/* Macros for string operations */
#define M_YASN1_BIT_STRING_new()	(YASN1_BIT_STRING *)\
		YASN1_STRING_type_new(V_YASN1_BIT_STRING)
#define M_YASN1_BIT_STRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_BIT_STRING_dup(a) (YASN1_BIT_STRING *)\
		YASN1_STRING_dup((const YASN1_STRING *)a)
#define M_YASN1_BIT_STRING_cmp(a,b) YASN1_STRING_cmp(\
		(const YASN1_STRING *)a,(const YASN1_STRING *)b)
#define M_YASN1_BIT_STRING_set(a,b,c) YASN1_STRING_set((YASN1_STRING *)a,b,c)

#define M_YASN1_INTEGER_new()	(YASN1_INTEGER *)\
		YASN1_STRING_type_new(V_YASN1_INTEGER)
#define M_YASN1_INTEGER_free(a)		YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_INTEGER_dup(a) (YASN1_INTEGER *)\
		YASN1_STRING_dup((const YASN1_STRING *)a)
#define M_YASN1_INTEGER_cmp(a,b)	YASN1_STRING_cmp(\
		(const YASN1_STRING *)a,(const YASN1_STRING *)b)

#define M_YASN1_ENUMERATED_new()	(YASN1_ENUMERATED *)\
		YASN1_STRING_type_new(V_YASN1_ENUMERATED)
#define M_YASN1_ENUMERATED_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_ENUMERATED_dup(a) (YASN1_ENUMERATED *)\
		YASN1_STRING_dup((const YASN1_STRING *)a)
#define M_YASN1_ENUMERATED_cmp(a,b)	YASN1_STRING_cmp(\
		(const YASN1_STRING *)a,(const YASN1_STRING *)b)

#define M_YASN1_OCTET_STRING_new()	(YASN1_OCTET_STRING *)\
		YASN1_STRING_type_new(V_YASN1_OCTET_STRING)
#define M_YASN1_OCTET_STRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_OCTET_STRING_dup(a) (YASN1_OCTET_STRING *)\
		YASN1_STRING_dup((const YASN1_STRING *)a)
#define M_YASN1_OCTET_STRING_cmp(a,b) YASN1_STRING_cmp(\
		(const YASN1_STRING *)a,(const YASN1_STRING *)b)
#define M_YASN1_OCTET_STRING_set(a,b,c)	YASN1_STRING_set((YASN1_STRING *)a,b,c)
#define M_YASN1_OCTET_STRING_print(a,b)	YASN1_STRING_print(a,(YASN1_STRING *)b)

#define B_YASN1_TIME \
			B_YASN1_UTCTIME | \
			B_YASN1_GENERALIZEDTIME

#define B_YASN1_PRINTABLE \
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

#define B_YASN1_DIRECTORYSTRING \
			B_YASN1_PRINTABLESTRING| \
			B_YASN1_TELETEXSTRING|\
			B_YASN1_BMPSTRING|\
			B_YASN1_UNIVEYRSALSTRING|\
			B_YASN1_UTF8STRING

#define B_YASN1_DISPLAYTEXT \
			B_YASN1_IA5STRING| \
			B_YASN1_VISIBLESTRING| \
			B_YASN1_BMPSTRING|\
			B_YASN1_UTF8STRING

#define M_YASN1_PRINTABLE_new()	YASN1_STRING_type_new(V_YASN1_T61STRING)
#define M_YASN1_PRINTABLE_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_DIRECTORYSTRING_new() YASN1_STRING_type_new(V_YASN1_PRINTABLESTRING)
#define M_DIRECTORYSTRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_DISPLAYTEXT_new() YASN1_STRING_type_new(V_YASN1_VISIBLESTRING)
#define M_DISPLAYTEXT_free(a) YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_PRINTABLESTRING_new() (YASN1_PRINTABLESTRING *)\
		YASN1_STRING_type_new(V_YASN1_PRINTABLESTRING)
#define M_YASN1_PRINTABLESTRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_T61STRING_new()	(YASN1_T61STRING *)\
		YASN1_STRING_type_new(V_YASN1_T61STRING)
#define M_YASN1_T61STRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_IA5STRING_new()	(YASN1_IA5STRING *)\
		YASN1_STRING_type_new(V_YASN1_IA5STRING)
#define M_YASN1_IA5STRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_IA5STRING_dup(a)	\
		(YASN1_IA5STRING *)YASN1_STRING_dup((const YASN1_STRING *)a)

#define M_YASN1_UTCTIME_new()	(YASN1_UTCTIME *)\
		YASN1_STRING_type_new(V_YASN1_UTCTIME)
#define M_YASN1_UTCTIME_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_UTCTIME_dup(a) (YASN1_UTCTIME *)\
		YASN1_STRING_dup((const YASN1_STRING *)a)

#define M_YASN1_GENERALIZEDTIME_new()	(YASN1_GENERALIZEDTIME *)\
		YASN1_STRING_type_new(V_YASN1_GENERALIZEDTIME)
#define M_YASN1_GENERALIZEDTIME_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_GENERALIZEDTIME_dup(a) (YASN1_GENERALIZEDTIME *)YASN1_STRING_dup(\
	(const YASN1_STRING *)a)

#define M_YASN1_TIME_new()	(YASN1_TIME *)\
		YASN1_STRING_type_new(V_YASN1_UTCTIME)
#define M_YASN1_TIME_free(a)	YASN1_STRING_free((YASN1_STRING *)a)
#define M_YASN1_TIME_dup(a) (YASN1_TIME *)\
	YASN1_STRING_dup((const YASN1_STRING *)a)

#define M_YASN1_GENERALSTRING_new()	(YASN1_GENERALSTRING *)\
		YASN1_STRING_type_new(V_YASN1_GENERALSTRING)
#define M_YASN1_GENERALSTRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_UNIVEYRSALSTRING_new()	(YASN1_UNIVEYRSALSTRING *)\
		YASN1_STRING_type_new(V_YASN1_UNIVEYRSALSTRING)
#define M_YASN1_UNIVEYRSALSTRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_BMPSTRING_new()	(YASN1_BMPSTRING *)\
		YASN1_STRING_type_new(V_YASN1_BMPSTRING)
#define M_YASN1_BMPSTRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_VISIBLESTRING_new()	(YASN1_VISIBLESTRING *)\
		YASN1_STRING_type_new(V_YASN1_VISIBLESTRING)
#define M_YASN1_VISIBLESTRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

#define M_YASN1_UTF8STRING_new()	(YASN1_UTF8STRING *)\
		YASN1_STRING_type_new(V_YASN1_UTF8STRING)
#define M_YASN1_UTF8STRING_free(a)	YASN1_STRING_free((YASN1_STRING *)a)

DECLARE_YASN1_FUNCTIONS_fname(YASN1_TYPE, YASN1_ANY, YASN1_TYPE)

OPENSSL_EXPORT int YASN1_TYPE_get(YASN1_TYPE *a);
OPENSSL_EXPORT void YASN1_TYPE_set(YASN1_TYPE *a, int type, void *value);
OPENSSL_EXPORT int YASN1_TYPE_set1(YASN1_TYPE *a, int type, const void *value);
OPENSSL_EXPORT int YASN1_TYPE_cmp(const YASN1_TYPE *a, const YASN1_TYPE *b);

OPENSSL_EXPORT YASN1_OBJECT *	YASN1_OBJECT_new(void );
OPENSSL_EXPORT void		YASN1_OBJECT_free(YASN1_OBJECT *a);
OPENSSL_EXPORT int		i2d_YASN1_OBJECT(YASN1_OBJECT *a,unsigned char **pp);
OPENSSL_EXPORT YASN1_OBJECT *	c2i_YASN1_OBJECT(YASN1_OBJECT **a,const unsigned char **pp,
						long length);
OPENSSL_EXPORT YASN1_OBJECT *	d2i_YASN1_OBJECT(YASN1_OBJECT **a,const unsigned char **pp,
						long length);

DECLARE_YASN1_ITEM(YASN1_OBJECT)

DECLARE_YASN1_SET_OF(YASN1_OBJECT)

OPENSSL_EXPORT YASN1_STRING *	YASN1_STRING_new(void);
OPENSSL_EXPORT void		YASN1_STRING_free(YASN1_STRING *a);
OPENSSL_EXPORT int		YASN1_STRING_copy(YASN1_STRING *dst, const YASN1_STRING *str);
OPENSSL_EXPORT YASN1_STRING *	YASN1_STRING_dup(const YASN1_STRING *a);
OPENSSL_EXPORT YASN1_STRING *	YASN1_STRING_type_new(int type );
OPENSSL_EXPORT int 		YASN1_STRING_cmp(const YASN1_STRING *a, const YASN1_STRING *b);
  /* Since this is used to store all sorts of things, via macros, for now, make
     its data void * */
OPENSSL_EXPORT int 		YASN1_STRING_set(YASN1_STRING *str, const void *data, int len);
OPENSSL_EXPORT void		YASN1_STRING_set0(YASN1_STRING *str, void *data, int len);
OPENSSL_EXPORT int YASN1_STRING_length(const YASN1_STRING *x);
OPENSSL_EXPORT void YASN1_STRING_length_set(YASN1_STRING *x, int n);
OPENSSL_EXPORT int YASN1_STRING_type(YASN1_STRING *x);
OPENSSL_EXPORT unsigned char * YASN1_STRING_data(YASN1_STRING *x);

DECLARE_YASN1_FUNCTIONS(YASN1_BIT_STRING)
OPENSSL_EXPORT int		i2c_YASN1_BIT_STRING(YASN1_BIT_STRING *a,unsigned char **pp);
OPENSSL_EXPORT YASN1_BIT_STRING *c2i_YASN1_BIT_STRING(YASN1_BIT_STRING **a,const unsigned char **pp, long length);
OPENSSL_EXPORT int		YASN1_BIT_STRING_set(YASN1_BIT_STRING *a, unsigned char *d, int length );
OPENSSL_EXPORT int		YASN1_BIT_STRING_set_bit(YASN1_BIT_STRING *a, int n, int value);
OPENSSL_EXPORT int		YASN1_BIT_STRING_get_bit(YASN1_BIT_STRING *a, int n);
OPENSSL_EXPORT int            YASN1_BIT_STRING_check(YASN1_BIT_STRING *a, unsigned char *flags, int flags_len);

OPENSSL_EXPORT int YASN1_BIT_STRING_name_print(BIO *out, YASN1_BIT_STRING *bs, BIT_STRING_BITNAME *tbl, int indent);
OPENSSL_EXPORT int YASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl);
OPENSSL_EXPORT int YASN1_BIT_STRING_set_asc(YASN1_BIT_STRING *bs, char *name, int value, BIT_STRING_BITNAME *tbl);

OPENSSL_EXPORT int		i2d_YASN1_BOOLEAN(int a,unsigned char **pp);
OPENSSL_EXPORT int 		d2i_YASN1_BOOLEAN(int *a,const unsigned char **pp,long length);

DECLARE_YASN1_FUNCTIONS(YASN1_INTEGER)
OPENSSL_EXPORT int		i2c_YASN1_INTEGER(YASN1_INTEGER *a,unsigned char **pp);
OPENSSL_EXPORT YASN1_INTEGER *c2i_YASN1_INTEGER(YASN1_INTEGER **a,const unsigned char **pp, long length);
OPENSSL_EXPORT YASN1_INTEGER *d2i_YASN1_UINTEGER(YASN1_INTEGER **a,const unsigned char **pp, long length);
OPENSSL_EXPORT YASN1_INTEGER *	YASN1_INTEGER_dup(const YASN1_INTEGER *x);
OPENSSL_EXPORT int YASN1_INTEGER_cmp(const YASN1_INTEGER *x, const YASN1_INTEGER *y);

DECLARE_YASN1_FUNCTIONS(YASN1_ENUMERATED)

OPENSSL_EXPORT int YASN1_UTCTIME_check(const YASN1_UTCTIME *a);
OPENSSL_EXPORT YASN1_UTCTIME *YASN1_UTCTIME_set(YASN1_UTCTIME *s,time_t t);
OPENSSL_EXPORT YASN1_UTCTIME *YASN1_UTCTIME_adj(YASN1_UTCTIME *s, time_t t, int offset_day, long offset_sec);
OPENSSL_EXPORT int YASN1_UTCTIME_set_string(YASN1_UTCTIME *s, const char *str);
OPENSSL_EXPORT int YASN1_UTCTIME_cmp_time_t(const YASN1_UTCTIME *s, time_t t);
#if 0
time_t YASN1_UTCTIME_get(const YASN1_UTCTIME *s);
#endif

OPENSSL_EXPORT int YASN1_GENERALIZEDTIME_check(const YASN1_GENERALIZEDTIME *a);
OPENSSL_EXPORT YASN1_GENERALIZEDTIME *YASN1_GENERALIZEDTIME_set(YASN1_GENERALIZEDTIME *s,time_t t);
OPENSSL_EXPORT YASN1_GENERALIZEDTIME *YASN1_GENERALIZEDTIME_adj(YASN1_GENERALIZEDTIME *s, time_t t, int offset_day, long offset_sec);
OPENSSL_EXPORT int YASN1_GENERALIZEDTIME_set_string(YASN1_GENERALIZEDTIME *s, const char *str);
OPENSSL_EXPORT int YASN1_TIME_diff(int *pday, int *psec, const YASN1_TIME *from, const YASN1_TIME *to);

DECLARE_YASN1_FUNCTIONS(YASN1_OCTET_STRING)
OPENSSL_EXPORT YASN1_OCTET_STRING *	YASN1_OCTET_STRING_dup(const YASN1_OCTET_STRING *a);
OPENSSL_EXPORT int 	YASN1_OCTET_STRING_cmp(const YASN1_OCTET_STRING *a, const YASN1_OCTET_STRING *b);
OPENSSL_EXPORT int 	YASN1_OCTET_STRING_set(YASN1_OCTET_STRING *str, const unsigned char *data, int len);

DECLARE_YASN1_FUNCTIONS(YASN1_VISIBLESTRING)
DECLARE_YASN1_FUNCTIONS(YASN1_UNIVEYRSALSTRING)
DECLARE_YASN1_FUNCTIONS(YASN1_UTF8STRING)
DECLARE_YASN1_FUNCTIONS(YASN1_NULL)
DECLARE_YASN1_FUNCTIONS(YASN1_BMPSTRING)

OPENSSL_EXPORT int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
OPENSSL_EXPORT int UTF8_putc(unsigned char *str, int len, unsigned long value);

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

OPENSSL_EXPORT YASN1_TIME *YASN1_TIME_set(YASN1_TIME *s,time_t t);
OPENSSL_EXPORT YASN1_TIME *YASN1_TIME_adj(YASN1_TIME *s,time_t t, int offset_day, long offset_sec);
OPENSSL_EXPORT int YASN1_TIME_check(YASN1_TIME *t);
OPENSSL_EXPORT YASN1_GENERALIZEDTIME *YASN1_TIME_to_generalizedtime(YASN1_TIME *t, YASN1_GENERALIZEDTIME **out);
OPENSSL_EXPORT int YASN1_TIME_set_string(YASN1_TIME *s, const char *str);

OPENSSL_EXPORT int i2a_YASN1_INTEGER(BIO *bp, YASN1_INTEGER *a);
OPENSSL_EXPORT int i2a_YASN1_ENUMERATED(BIO *bp, YASN1_ENUMERATED *a);
OPENSSL_EXPORT int i2a_YASN1_OBJECT(BIO *bp,YASN1_OBJECT *a);
OPENSSL_EXPORT int i2a_YASN1_STRING(BIO *bp, YASN1_STRING *a, int type);
OPENSSL_EXPORT int i2t_YASN1_OBJECT(char *buf,int buf_len,YASN1_OBJECT *a);

OPENSSL_EXPORT int a2d_YASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
OPENSSL_EXPORT YASN1_OBJECT *YASN1_OBJECT_create(int nid, unsigned char *data,int len, const char *sn, const char *ln);

OPENSSL_EXPORT int YASN1_INTEGER_set(YASN1_INTEGER *a, long v);
OPENSSL_EXPORT long YASN1_INTEGER_get(const YASN1_INTEGER *a);
OPENSSL_EXPORT YASN1_INTEGER *BN_to_YASN1_INTEGER(const BIGNUM *bn, YASN1_INTEGER *ai);
OPENSSL_EXPORT BIGNUM *YASN1_INTEGER_to_BN(const YASN1_INTEGER *ai,BIGNUM *bn);

OPENSSL_EXPORT int YASN1_ENUMERATED_set(YASN1_ENUMERATED *a, long v);
OPENSSL_EXPORT long YASN1_ENUMERATED_get(YASN1_ENUMERATED *a);
OPENSSL_EXPORT YASN1_ENUMERATED *BN_to_YASN1_ENUMERATED(BIGNUM *bn, YASN1_ENUMERATED *ai);
OPENSSL_EXPORT BIGNUM *YASN1_ENUMERATED_to_BN(YASN1_ENUMERATED *ai,BIGNUM *bn);

/* General */
/* given a string, return the correct type, max is the maximum length */
OPENSSL_EXPORT int YASN1_PRINTABLE_type(const unsigned char *s, int max);

OPENSSL_EXPORT unsigned long YASN1_tag2bit(int tag);

/* PARSING */
OPENSSL_EXPORT int asn1_Finish(YASN1_CTX *c);
OPENSSL_EXPORT int asn1_const_Finish(YASN1_const_CTX *c);

/* SPECIALS */
OPENSSL_EXPORT int YASN1_get_object(const unsigned char **pp, long *plength, int *ptag, int *pclass, long omax);
OPENSSL_EXPORT int YASN1_check_infinite_end(unsigned char **p,long len);
OPENSSL_EXPORT int YASN1_const_check_infinite_end(const unsigned char **p,long len);
OPENSSL_EXPORT void YASN1_put_object(unsigned char **pp, int constructed, int length, int tag, int xclass);
OPENSSL_EXPORT int YASN1_put_eoc(unsigned char **pp);
OPENSSL_EXPORT int YASN1_object_size(int constructed, int length, int tag);

/* Used to implement other functions */
OPENSSL_EXPORT void *YASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);

#define YASN1_dup_of(type,i2d,d2i,x) \
    ((type*)YASN1_dup(CHECKED_I2D_OF(type, i2d), \
		     CHECKED_D2I_OF(type, d2i), \
		     CHECKED_PTR_OF(type, x)))

#define YASN1_dup_of_const(type,i2d,d2i,x) \
    ((type*)YASN1_dup(CHECKED_I2D_OF(const type, i2d), \
		     CHECKED_D2I_OF(type, d2i), \
		     CHECKED_PTR_OF(const type, x)))

OPENSSL_EXPORT void *YASN1_item_dup(const YASN1_ITEM *it, void *x);

/* YASN1 alloc/free macros for when a type is only used internally */

#define M_YASN1_new_of(type) (type *)YASN1_item_new(YASN1_ITEM_rptr(type))
#define M_YASN1_free_of(x, type) \
		YASN1_item_free(CHECKED_PTR_OF(type, x), YASN1_ITEM_rptr(type))

#ifndef OPENSSL_NO_FP_API
OPENSSL_EXPORT void *YASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);

#define YASN1_d2i_fp_of(type,xnew,d2i,in,x) \
    ((type*)YASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
			CHECKED_D2I_OF(type, d2i), \
			in, \
			CHECKED_PPTR_OF(type, x)))

OPENSSL_EXPORT void *YASN1_item_d2i_fp(const YASN1_ITEM *it, FILE *in, void *x);
OPENSSL_EXPORT int YASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x);

#define YASN1_i2d_fp_of(type,i2d,out,x) \
    (YASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
		 out, \
		 CHECKED_PTR_OF(type, x)))

#define YASN1_i2d_fp_of_const(type,i2d,out,x) \
    (YASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
		 out, \
		 CHECKED_PTR_OF(const type, x)))

OPENSSL_EXPORT int YASN1_item_i2d_fp(const YASN1_ITEM *it, FILE *out, void *x);
OPENSSL_EXPORT int YASN1_STRING_print_ex_fp(FILE *fp, YASN1_STRING *str, unsigned long flags);
#endif

OPENSSL_EXPORT int YASN1_STRING_to_UTF8(unsigned char **out, YASN1_STRING *in);

OPENSSL_EXPORT void *YASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);

#define YASN1_d2i_bio_of(type,xnew,d2i,in,x) \
    ((type*)YASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
			  CHECKED_D2I_OF(type, d2i), \
			  in, \
			  CHECKED_PPTR_OF(type, x)))

OPENSSL_EXPORT void *YASN1_item_d2i_bio(const YASN1_ITEM *it, BIO *in, void *x);
OPENSSL_EXPORT int YASN1_i2d_bio(i2d_of_void *i2d,BIO *out, void *x);

#define YASN1_i2d_bio_of(type,i2d,out,x) \
    (YASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
		  out, \
		  CHECKED_PTR_OF(type, x)))

#define YASN1_i2d_bio_of_const(type,i2d,out,x) \
    (YASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
		  out, \
		  CHECKED_PTR_OF(const type, x)))

OPENSSL_EXPORT int YASN1_item_i2d_bio(const YASN1_ITEM *it, BIO *out, void *x);
OPENSSL_EXPORT int YASN1_UTCTIME_print(BIO *fp, const YASN1_UTCTIME *a);
OPENSSL_EXPORT int YASN1_GENERALIZEDTIME_print(BIO *fp, const YASN1_GENERALIZEDTIME *a);
OPENSSL_EXPORT int YASN1_TIME_print(BIO *fp, const YASN1_TIME *a);
OPENSSL_EXPORT int YASN1_STRING_print(BIO *bp, const YASN1_STRING *v);
OPENSSL_EXPORT int YASN1_STRING_print_ex(BIO *out, YASN1_STRING *str, unsigned long flags);
OPENSSL_EXPORT const char *YASN1_tag2str(int tag);

/* Used to load and write netscape format cert */

DECLARE_YASN1_FUNCTIONS(NETSCAPE_YX509)

int YASN1_UNIVEYRSALSTRING_to_string(YASN1_UNIVEYRSALSTRING *s);

OPENSSL_EXPORT void *YASN1_item_unpack(YASN1_STRING *oct, const YASN1_ITEM *it);

OPENSSL_EXPORT YASN1_STRING *YASN1_item_pack(void *obj, const YASN1_ITEM *it, YASN1_OCTET_STRING **oct);

OPENSSL_EXPORT void YASN1_STRING_set_default_mask(unsigned long mask);
OPENSSL_EXPORT int YASN1_STRING_set_default_mask_asc(const char *p);
OPENSSL_EXPORT unsigned long YASN1_STRING_get_default_mask(void);
OPENSSL_EXPORT int YASN1_mbstring_copy(YASN1_STRING **out, const unsigned char *in, int len, int inform, unsigned long mask);
OPENSSL_EXPORT int YASN1_mbstring_ncopy(YASN1_STRING **out, const unsigned char *in, int len, int inform, unsigned long mask, long minsize, long maxsize);

OPENSSL_EXPORT YASN1_STRING *YASN1_STRING_set_by_NID(YASN1_STRING **out, const unsigned char *in, int inlen, int inform, int nid);
OPENSSL_EXPORT YASN1_STRING_TABLE *YASN1_STRING_TABLE_get(int nid);
OPENSSL_EXPORT int YASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
OPENSSL_EXPORT void YASN1_STRING_TABLE_cleanup(void);

/* YASN1 template functions */

/* Old API compatible functions */
OPENSSL_EXPORT YASN1_VALUE *YASN1_item_new(const YASN1_ITEM *it);
OPENSSL_EXPORT void YASN1_item_free(YASN1_VALUE *val, const YASN1_ITEM *it);
OPENSSL_EXPORT YASN1_VALUE * YASN1_item_d2i(YASN1_VALUE **val, const unsigned char **in, long len, const YASN1_ITEM *it);
OPENSSL_EXPORT int YASN1_item_i2d(YASN1_VALUE *val, unsigned char **out, const YASN1_ITEM *it);
OPENSSL_EXPORT int YASN1_item_ndef_i2d(YASN1_VALUE *val, unsigned char **out, const YASN1_ITEM *it);

OPENSSL_EXPORT YASN1_TYPE *YASN1_generate_nconf(char *str, CONF *nconf);
OPENSSL_EXPORT YASN1_TYPE *YASN1_generate_v3(char *str, YX509V3_CTX *cnf);


#ifdef  __cplusplus
}

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_STACK_DELETER(YASN1_OBJECT, YASN1_OBJECT_free)

BORINGSSL_MAKE_DELETER(YASN1_OBJECT, YASN1_OBJECT_free)
BORINGSSL_MAKE_DELETER(YASN1_STRING, YASN1_STRING_free)
BORINGSSL_MAKE_DELETER(YASN1_TYPE, YASN1_TYPE_free)

}  // namespace bssl

}  /* extern C++ */

#endif

#define YASN1_R_YASN1_LENGTH_MISMATCH 100
#define YASN1_R_AUX_ERROR 101
#define YASN1_R_BAD_GET_YASN1_OBJECT_CALL 102
#define YASN1_R_BAD_OBJECT_HEADER 103
#define YASN1_R_BMPSTRING_IS_WRONG_LENGTH 104
#define YASN1_R_BN_LIB 105
#define YASN1_R_BOOLEAN_IS_WRONG_LENGTH 106
#define YASN1_R_BUFFER_TOO_SMALL 107
#define YASN1_R_CONTEXT_NOT_INITIALISED 108
#define YASN1_R_DECODE_ERROR 109
#define YASN1_R_DEPTH_EXCEEDED 110
#define YASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED 111
#define YASN1_R_ENCODE_ERROR 112
#define YASN1_R_ERROR_GETTING_TIME 113
#define YASN1_R_EXPECTING_AN_YASN1_SEQUENCE 114
#define YASN1_R_EXPECTING_AN_INTEGER 115
#define YASN1_R_EXPECTING_AN_OBJECT 116
#define YASN1_R_EXPECTING_A_BOOLEAN 117
#define YASN1_R_EXPECTING_A_TIME 118
#define YASN1_R_EXPLICIT_LENGTH_MISMATCH 119
#define YASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED 120
#define YASN1_R_FIELD_MISSING 121
#define YASN1_R_FIRST_NUM_TOO_LARGE 122
#define YASN1_R_HEADER_TOO_LONG 123
#define YASN1_R_ILLEGAL_BITSTRING_FORMAT 124
#define YASN1_R_ILLEGAL_BOOLEAN 125
#define YASN1_R_ILLEGAL_CHARACTERS 126
#define YASN1_R_ILLEGAL_FORMAT 127
#define YASN1_R_ILLEGAL_HEX 128
#define YASN1_R_ILLEGAL_IMPLICIT_TAG 129
#define YASN1_R_ILLEGAL_INTEGER 130
#define YASN1_R_ILLEGAL_NESTED_TAGGING 131
#define YASN1_R_ILLEGAL_NULL 132
#define YASN1_R_ILLEGAL_NULL_VALUE 133
#define YASN1_R_ILLEGAL_OBJECT 134
#define YASN1_R_ILLEGAL_OPTIONAL_ANY 135
#define YASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE 136
#define YASN1_R_ILLEGAL_TAGGED_ANY 137
#define YASN1_R_ILLEGAL_TIME_VALUE 138
#define YASN1_R_INTEGER_NOT_ASCII_FORMAT 139
#define YASN1_R_INTEGER_TOO_LARGE_FOR_LONG 140
#define YASN1_R_INVALID_BIT_STRING_BITS_LEFT 141
#define YASN1_R_INVALID_BMPSTRING_LENGTH 142
#define YASN1_R_INVALID_DIGIT 143
#define YASN1_R_INVALID_MODIFIER 144
#define YASN1_R_INVALID_NUMBER 145
#define YASN1_R_INVALID_OBJECT_ENCODING 146
#define YASN1_R_INVALID_SEPARATOR 147
#define YASN1_R_INVALID_TIME_FORMAT 148
#define YASN1_R_INVALID_UNIVEYRSALSTRING_LENGTH 149
#define YASN1_R_INVALID_UTF8STRING 150
#define YASN1_R_LIST_ERROR 151
#define YASN1_R_MISSING_YASN1_EOS 152
#define YASN1_R_MISSING_EOC 153
#define YASN1_R_MISSING_SECOND_NUMBER 154
#define YASN1_R_MISSING_VALUE 155
#define YASN1_R_MSTRING_NOT_UNIVEYRSAL 156
#define YASN1_R_MSTRING_WRONG_TAG 157
#define YASN1_R_NESTED_YASN1_ERROR 158
#define YASN1_R_NESTED_YASN1_STRING 159
#define YASN1_R_NON_HEX_CHARACTERS 160
#define YASN1_R_NOT_ASCII_FORMAT 161
#define YASN1_R_NOT_ENOUGH_DATA 162
#define YASN1_R_NO_MATCHING_CHOICE_TYPE 163
#define YASN1_R_NULL_IS_WRONG_LENGTH 164
#define YASN1_R_OBJECT_NOT_ASCII_FORMAT 165
#define YASN1_R_ODD_NUMBER_OF_CHARS 166
#define YASN1_R_SECOND_NUMBER_TOO_LARGE 167
#define YASN1_R_SEQUENCE_LENGTH_MISMATCH 168
#define YASN1_R_SEQUENCE_NOT_CONSTRUCTED 169
#define YASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG 170
#define YASN1_R_SHORT_LINE 171
#define YASN1_R_STREAMING_NOT_SUPPORTED 172
#define YASN1_R_STRING_TOO_LONG 173
#define YASN1_R_STRING_TOO_SHORT 174
#define YASN1_R_TAG_VALUE_TOO_HIGH 175
#define YASN1_R_TIME_NOT_ASCII_FORMAT 176
#define YASN1_R_TOO_LONG 177
#define YASN1_R_TYPE_NOT_CONSTRUCTED 178
#define YASN1_R_TYPE_NOT_PRIMITIVE 179
#define YASN1_R_UNEXPECTED_EOC 180
#define YASN1_R_UNIVEYRSALSTRING_IS_WRONG_LENGTH 181
#define YASN1_R_UNKNOWN_FORMAT 182
#define YASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM 183
#define YASN1_R_UNKNOWN_SIGNATURE_ALGORITHM 184
#define YASN1_R_UNKNOWN_TAG 185
#define YASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE 186
#define YASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE 187
#define YASN1_R_UNSUPPORTED_TYPE 188
#define YASN1_R_WRONG_PUBLIC_KEY_TYPE 189
#define YASN1_R_WRONG_TAG 190
#define YASN1_R_WRONG_TYPE 191

#endif
