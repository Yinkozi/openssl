/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999. */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_YX509V3_H
#define HEADER_YX509V3_H

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward reference */
struct v3_ext_method;
struct v3_ext_ctx;

/* Useful typedefs */

typedef void * (*YX509V3_EXT_NEW)(void);
typedef void (*YX509V3_EXT_FREE)(void *);
typedef void * (*YX509V3_EXT_D2I)(void *, const unsigned char ** , long);
typedef int (*YX509V3_EXT_I2D)(void *, unsigned char **);
typedef STACK_OF(CONF_VALUE) *
  (*YX509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
		    STACK_OF(CONF_VALUE) *extlist);
typedef void * (*YX509V3_EXT_V2I)(const struct v3_ext_method *method,
				 struct v3_ext_ctx *ctx,
				 STACK_OF(CONF_VALUE) *values);
typedef char * (*YX509V3_EXT_I2S)(const struct v3_ext_method *method, void *ext);
typedef void * (*YX509V3_EXT_S2I)(const struct v3_ext_method *method,
				 struct v3_ext_ctx *ctx, const char *str);
typedef int (*YX509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
			      BIO *out, int indent);
typedef void * (*YX509V3_EXT_R2I)(const struct v3_ext_method *method,
				 struct v3_ext_ctx *ctx, const char *str);

/* V3 extension structure */

struct v3_ext_method {
int ext_nid;
int ext_flags;
/* If this is set the following four fields are ignored */
YASN1_ITEM_EXP *it;
/* Old style YASN1 calls */
YX509V3_EXT_NEW ext_new;
YX509V3_EXT_FREE ext_free;
YX509V3_EXT_D2I d2i;
YX509V3_EXT_I2D i2d;

/* The following pair is used for string extensions */
YX509V3_EXT_I2S i2s;
YX509V3_EXT_S2I s2i;

/* The following pair is used for multi-valued extensions */
YX509V3_EXT_I2V i2v;
YX509V3_EXT_V2I v2i;

/* The following are used for raw extensions */
YX509V3_EXT_I2R i2r;
YX509V3_EXT_R2I r2i;

void *usr_data;	/* Any extension specific data */
};

typedef struct YX509V3_CONF_METHOD_st {
char * (*get_string)(void *db, char *section, char *value);
STACK_OF(CONF_VALUE) * (*get_section)(void *db, char *section);
void (*free_string)(void *db, char * string);
void (*free_section)(void *db, STACK_OF(CONF_VALUE) *section);
} YX509V3_CONF_METHOD;

/* Context specific info */
struct v3_ext_ctx {
#define CTX_TEST 0x1
int flags;
YX509 *issuer_cert;
YX509 *subject_cert;
YX509_REQ *subject_req;
YX509_CRL *crl;
const YX509V3_CONF_METHOD *db_meth;
void *db;
/* Maybe more here */
};

typedef struct v3_ext_method YX509V3_EXT_METHOD;

DECLARE_STACK_OF(YX509V3_EXT_METHOD)

/* ext_flags values */
#define YX509V3_EXT_DYNAMIC	0x1
#define YX509V3_EXT_CTX_DEP	0x2
#define YX509V3_EXT_MULTILINE	0x4

typedef BIT_STRING_BITNAME ENUMERATED_NAMES;

struct BASIC_CONSTRAINTS_st {
int ca;
YASN1_INTEGER *pathlen;
};


typedef struct PKEY_USAGE_PERIOD_st {
YASN1_GENERALIZEDTIME *notBefore;
YASN1_GENERALIZEDTIME *notAfter;
} PKEY_USAGE_PERIOD;

typedef struct otherName_st {
YASN1_OBJECT *type_id;
YASN1_TYPE *value;
} OTHERNAME;

typedef struct EDIPartyName_st {
	YASN1_STRING *nameAssigner;
	YASN1_STRING *partyName;
} EDIPARTYNAME;

typedef struct GENERAL_NAME_st {

#define GEN_OTHERNAME	0
#define GEN_EMAIL	1
#define GEN_DNS		2
#define GEN_X400	3
#define GEN_DIRNAME	4
#define GEN_EDIPARTY	5
#define GEN_URI		6
#define GEN_IPADD	7
#define GEN_RID		8

int type;
union {
	char *ptr;
	OTHERNAME *otherName; /* otherName */
	YASN1_IA5STRING *rfc822Name;
	YASN1_IA5STRING *dNSName;
	YASN1_TYPE *x400Address;
	YX509_NAME *directoryName;
	EDIPARTYNAME *ediPartyName;
	YASN1_IA5STRING *uniformResourceIdentifier;
	YASN1_OCTET_STRING *iPAddress;
	YASN1_OBJECT *registeredID;

	/* Old names */
	YASN1_OCTET_STRING *ip; /* iPAddress */
	YX509_NAME *dirn;		/* dirn */
	YASN1_IA5STRING *ia5;/* rfc822Name, dNSName, uniformResourceIdentifier */
	YASN1_OBJECT *rid; /* registeredID */
	YASN1_TYPE *other; /* x400Address */
} d;
} GENERAL_NAME;

typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;

typedef struct ACCESS_DESCRIPTION_st {
	YASN1_OBJECT *method;
	GENERAL_NAME *location;
} ACCESS_DESCRIPTION;

typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;

typedef STACK_OF(YASN1_OBJECT) EXTENDED_KEY_USAGE;

DECLARE_STACK_OF(GENERAL_NAME)
DECLARE_YASN1_SET_OF(GENERAL_NAME)

DECLARE_STACK_OF(ACCESS_DESCRIPTION)
DECLARE_YASN1_SET_OF(ACCESS_DESCRIPTION)

typedef struct DIST_POINT_NAME_st {
int type;
union {
	GENERAL_NAMES *fullname;
	STACK_OF(YX509_NAME_ENTRY) *relativename;
} name;
/* If relativename then this contains the full distribution point name */
YX509_NAME *dpname;
} DIST_POINT_NAME;
/* All existing reasons */
#define CRLDP_ALL_REASONS	0x807f

#define CRL_REASON_NONE				(-1)
#define CRL_REASON_UNSPECIFIED			0
#define CRL_REASON_KEY_COMPROMISE		1
#define CRL_REASON_CA_COMPROMISE		2
#define CRL_REASON_AFFILIATION_CHANGED		3
#define CRL_REASON_SUPERSEDED			4
#define CRL_REASON_CESSATION_OF_OPERATION	5
#define CRL_REASON_CERTIFICATE_HOLD		6
#define CRL_REASON_REMOVE_FROM_CRL		8
#define CRL_REASON_PRIVILEGE_WITHDRAWN		9
#define CRL_REASON_AA_COMPROMISE		10

struct DIST_POINT_st {
DIST_POINT_NAME	*distpoint;
YASN1_BIT_STRING *reasons;
GENERAL_NAMES *CRLissuer;
int dp_reasons;
};

typedef STACK_OF(DIST_POINT) CRL_DIST_POINTS;

DECLARE_STACK_OF(DIST_POINT)
DECLARE_YASN1_SET_OF(DIST_POINT)

struct AUTHORITY_KEYID_st {
YASN1_OCTET_STRING *keyid;
GENERAL_NAMES *issuer;
YASN1_INTEGER *serial;
};

/* Strong extranet structures */

typedef struct SXNET_ID_st {
	YASN1_INTEGER *zone;
	YASN1_OCTET_STRING *user;
} SXNETID;

DECLARE_STACK_OF(SXNETID)
DECLARE_YASN1_SET_OF(SXNETID)

typedef struct SXNET_st {
	YASN1_INTEGER *version;
	STACK_OF(SXNETID) *ids;
} SXNET;

typedef struct NOTICEREF_st {
	YASN1_STRING *organization;
	STACK_OF(YASN1_INTEGER) *noticenos;
} NOTICEREF;

typedef struct USERNOTICE_st {
	NOTICEREF *noticeref;
	YASN1_STRING *exptext;
} USERNOTICE;

typedef struct POLICYQUALINFO_st {
	YASN1_OBJECT *pqualid;
	union {
		YASN1_IA5STRING *cpsuri;
		USERNOTICE *usernotice;
		YASN1_TYPE *other;
	} d;
} POLICYQUALINFO;

DECLARE_STACK_OF(POLICYQUALINFO)
DECLARE_YASN1_SET_OF(POLICYQUALINFO)

typedef struct POLICYINFO_st {
	YASN1_OBJECT *policyid;
	STACK_OF(POLICYQUALINFO) *qualifiers;
} POLICYINFO;

typedef STACK_OF(POLICYINFO) CERTIFICATEPOLICIES;

DECLARE_STACK_OF(POLICYINFO)
DECLARE_YASN1_SET_OF(POLICYINFO)

typedef struct POLICY_MAPPING_st {
	YASN1_OBJECT *issuerDomainPolicy;
	YASN1_OBJECT *subjectDomainPolicy;
} POLICY_MAPPING;

DECLARE_STACK_OF(POLICY_MAPPING)

typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;

typedef struct GENERAL_SUBTREE_st {
	GENERAL_NAME *base;
	YASN1_INTEGER *minimum;
	YASN1_INTEGER *maximum;
} GENERAL_SUBTREE;

DECLARE_STACK_OF(GENERAL_SUBTREE)

struct NAME_CONSTRAINTS_st {
	STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
	STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
};

typedef struct POLICY_CONSTRAINTS_st {
	YASN1_INTEGER *requireExplicitPolicy;
	YASN1_INTEGER *inhibitPolicyMapping;
} POLICY_CONSTRAINTS;

/* Proxy certificate structures, see RFC 3820 */
typedef struct PROXY_POLICY_st
	{
	YASN1_OBJECT *policyLanguage;
	YASN1_OCTET_STRING *policy;
	} PROXY_POLICY;

typedef struct PROXY_CERT_INFO_EXTENSION_st
	{
	YASN1_INTEGER *pcPathLengthConstraint;
	PROXY_POLICY *proxyPolicy;
	} PROXY_CERT_INFO_EXTENSION;

DECLARE_YASN1_FUNCTIONS(PROXY_POLICY)
DECLARE_YASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)

struct ISSUING_DIST_POINT_st
	{
	DIST_POINT_NAME *distpoint;
	int onlyuser;
	int onlyCA;
	YASN1_BIT_STRING *onlysomereasons;
	int indirectCRL;
	int onlyattr;
	};

/* Values in idp_flags field */
/* IDP present */
#define	IDP_PRESENT	0x1
/* IDP values inconsistent */
#define IDP_INVALID	0x2
/* onlyuser true */
#define	IDP_ONLYUSER	0x4
/* onlyCA true */
#define	IDP_ONLYCA	0x8
/* onlyattr true */
#define IDP_ONLYATTR	0x10
/* indirectCRL true */
#define IDP_INDIRECT	0x20
/* onlysomereasons present */
#define IDP_REASONS	0x40

#define YX509V3_conf_err(val) ERR_add_error_data(6, "section:", (val)->section, \
",name:", (val)->name, ",value:", (val)->value);

#define YX509V3_set_ctx_test(ctx) \
			YX509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, CTX_TEST)
#define YX509V3_set_ctx_nodb(ctx) (ctx)->db = NULL;

#define EXT_BITSTRING(nid, table) { nid, 0, YASN1_ITEM_ref(YASN1_BIT_STRING), \
			0,0,0,0, \
			0,0, \
			(YX509V3_EXT_I2V)i2v_YASN1_BIT_STRING, \
			(YX509V3_EXT_V2I)v2i_YASN1_BIT_STRING, \
			NULL, NULL, \
			(void *)(table)}

#define EXT_IA5STRING(nid) { nid, 0, YASN1_ITEM_ref(YASN1_IA5STRING), \
			0,0,0,0, \
			(YX509V3_EXT_I2S)i2s_YASN1_IA5STRING, \
			(YX509V3_EXT_S2I)s2i_YASN1_IA5STRING, \
			0,0,0,0, \
			NULL}

#define EXT_END { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}


/* YX509_PURPOSE stuff */

#define EXFLAG_BCONS		0x1
#define EXFLAG_KUSAGE		0x2
#define EXFLAG_XKUSAGE		0x4
#define EXFLAG_NSCERT		0x8

#define EXFLAG_CA		0x10
/* Really self issued not necessarily self signed */
#define EXFLAG_SI		0x20
#define EXFLAG_V1		0x40
#define EXFLAG_INVALID		0x80
#define EXFLAG_SET		0x100
#define EXFLAG_CRITICAL		0x200
#define EXFLAG_PROXY		0x400

#define EXFLAG_INVALID_POLICY	0x800
#define EXFLAG_FRESHEST		0x1000
/* Self signed */
#define EXFLAG_SS		0x2000

#define KU_DIGITAL_SIGNATURE	0x0080
#define KU_NON_REPUDIATION	0x0040
#define KU_KEY_ENCIPHERMENT	0x0020
#define KU_DATA_ENCIPHERMENT	0x0010
#define KU_KEY_AGREEMENT	0x0008
#define KU_KEY_CERT_SIGN	0x0004
#define KU_CRL_SIGN		0x0002
#define KU_ENCIPHER_ONLY	0x0001
#define KU_DECIPHER_ONLY	0x8000

#define NS_SSL_CLIENT		0x80
#define NS_SSL_SERVER		0x40
#define NS_SMIME		0x20
#define NS_OBJSIGN		0x10
#define NS_SSL_CA		0x04
#define NS_SMIME_CA		0x02
#define NS_OBJSIGN_CA		0x01
#define NS_ANY_CA		(NS_SSL_CA|NS_SMIME_CA|NS_OBJSIGN_CA)

#define XKU_SSL_SERVER		0x1	
#define XKU_SSL_CLIENT		0x2
#define XKU_SMIME		0x4
#define XKU_CODE_SIGN		0x8
#define XKU_SGC			0x10
#define XKU_OCSP_SIGN		0x20
#define XKU_TIMESTAMP		0x40
#define XKU_DVCS		0x80
#define XKU_ANYEKU		0x100

#define YX509_PURPOSE_DYNAMIC	0x1
#define YX509_PURPOSE_DYNAMIC_NAME	0x2

typedef struct x509_purpose_st {
	int purpose;
	int trust;		/* Default trust ID */
	int flags;
	int (*check_purpose)(const struct x509_purpose_st *,
				const YX509 *, int);
	char *name;
	char *sname;
	void *usr_data;
} YX509_PURPOSE;

#define YX509_PURPOSE_SSL_CLIENT		1
#define YX509_PURPOSE_SSL_SERVER		2
#define YX509_PURPOSE_NS_SSL_SERVER	3
#define YX509_PURPOSE_SMIME_SIGN		4
#define YX509_PURPOSE_SMIME_ENCRYPT	5
#define YX509_PURPOSE_CRL_SIGN		6
#define YX509_PURPOSE_ANY		7
#define YX509_PURPOSE_OCSP_HELPER	8
#define YX509_PURPOSE_TIMESTAMP_SIGN	9

#define YX509_PURPOSE_MIN		1
#define YX509_PURPOSE_MAX		9

/* Flags for YX509V3_EXT_print() */

#define YX509V3_EXT_UNKNOWN_MASK		(0xfL << 16)
/* Return error for unknown extensions */
#define YX509V3_EXT_DEFAULT		0
/* Print error for unknown extensions */
#define YX509V3_EXT_ERROR_UNKNOWN	(1L << 16)
/* YASN1 parse unknown extensions */
#define YX509V3_EXT_PARSE_UNKNOWN	(2L << 16)
/* BIO_dump unknown extensions */
#define YX509V3_EXT_DUMP_UNKNOWN		(3L << 16)

/* Flags for YX509V3_add1_i2d */

#define YX509V3_ADD_OP_MASK		0xfL
#define YX509V3_ADD_DEFAULT		0L
#define YX509V3_ADD_APPEND		1L
#define YX509V3_ADD_REPLACE		2L
#define YX509V3_ADD_REPLACE_EXISTING	3L
#define YX509V3_ADD_KEEP_EXISTING	4L
#define YX509V3_ADD_DELETE		5L
#define YX509V3_ADD_SILENT		0x10

DECLARE_STACK_OF(YX509_PURPOSE)

DECLARE_YASN1_FUNCTIONS(BASIC_CONSTRAINTS)

DECLARE_YASN1_FUNCTIONS(SXNET)
DECLARE_YASN1_FUNCTIONS(SXNETID)

int SXNET_add_id_asc(SXNET **psx, char *zone, char *user, int userlen); 
int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, char *user, int userlen); 
int SXNET_add_id_INTEGER(SXNET **psx, YASN1_INTEGER *izone, char *user, int userlen); 

YASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, char *zone);
YASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone);
YASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, YASN1_INTEGER *zone);

DECLARE_YASN1_FUNCTIONS(AUTHORITY_KEYID)

DECLARE_YASN1_FUNCTIONS(PKEY_USAGE_PERIOD)

DECLARE_YASN1_FUNCTIONS(GENERAL_NAME)
OPENSSL_EXPORT GENERAL_NAME *GENERAL_NAME_dup(GENERAL_NAME *a);
OPENSSL_EXPORT int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);



OPENSSL_EXPORT YASN1_BIT_STRING *v2i_YASN1_BIT_STRING(YX509V3_EXT_METHOD *method,
				YX509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
OPENSSL_EXPORT STACK_OF(CONF_VALUE) *i2v_YASN1_BIT_STRING(YX509V3_EXT_METHOD *method,
				YASN1_BIT_STRING *bits,
				STACK_OF(CONF_VALUE) *extlist);

OPENSSL_EXPORT STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(YX509V3_EXT_METHOD *method, GENERAL_NAME *gen, STACK_OF(CONF_VALUE) *ret);
OPENSSL_EXPORT int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);

DECLARE_YASN1_FUNCTIONS(GENERAL_NAMES)

OPENSSL_EXPORT STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(YX509V3_EXT_METHOD *method,
		GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
OPENSSL_EXPORT GENERAL_NAMES *v2i_GENERAL_NAMES(const YX509V3_EXT_METHOD *method,
				 YX509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);

DECLARE_YASN1_FUNCTIONS(OTHERNAME)
DECLARE_YASN1_FUNCTIONS(EDIPARTYNAME)
OPENSSL_EXPORT int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b);
OPENSSL_EXPORT void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
OPENSSL_EXPORT void *GENERAL_NAME_get0_value(GENERAL_NAME *a, int *ptype);
OPENSSL_EXPORT int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
				YASN1_OBJECT *oid, YASN1_TYPE *value);
OPENSSL_EXPORT int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen, 
				YASN1_OBJECT **poid, YASN1_TYPE **pvalue);

OPENSSL_EXPORT char *i2s_YASN1_OCTET_STRING(YX509V3_EXT_METHOD *method, YASN1_OCTET_STRING *ia5);
OPENSSL_EXPORT YASN1_OCTET_STRING *s2i_YASN1_OCTET_STRING(YX509V3_EXT_METHOD *method, YX509V3_CTX *ctx, char *str);

DECLARE_YASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
OPENSSL_EXPORT int i2a_ACCESS_DESCRIPTION(BIO *bp, ACCESS_DESCRIPTION* a);

DECLARE_YASN1_FUNCTIONS(CERTIFICATEPOLICIES)
DECLARE_YASN1_FUNCTIONS(POLICYINFO)
DECLARE_YASN1_FUNCTIONS(POLICYQUALINFO)
DECLARE_YASN1_FUNCTIONS(USERNOTICE)
DECLARE_YASN1_FUNCTIONS(NOTICEREF)

DECLARE_YASN1_FUNCTIONS(CRL_DIST_POINTS)
DECLARE_YASN1_FUNCTIONS(DIST_POINT)
DECLARE_YASN1_FUNCTIONS(DIST_POINT_NAME)
DECLARE_YASN1_FUNCTIONS(ISSUING_DIST_POINT)

OPENSSL_EXPORT int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, YX509_NAME *iname);

OPENSSL_EXPORT int NAME_CONSTRAINTS_check(YX509 *x, NAME_CONSTRAINTS *nc);

DECLARE_YASN1_FUNCTIONS(ACCESS_DESCRIPTION)
DECLARE_YASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

DECLARE_YASN1_ITEM(POLICY_MAPPING)
DECLARE_YASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
DECLARE_YASN1_ITEM(POLICY_MAPPINGS)

DECLARE_YASN1_ITEM(GENERAL_SUBTREE)
DECLARE_YASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

DECLARE_YASN1_ITEM(NAME_CONSTRAINTS)
DECLARE_YASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

DECLARE_YASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
DECLARE_YASN1_ITEM(POLICY_CONSTRAINTS)

OPENSSL_EXPORT GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
			       const YX509V3_EXT_METHOD *method, YX509V3_CTX *ctx,
			       int gen_type, char *value, int is_nc);

OPENSSL_EXPORT GENERAL_NAME *v2i_GENERAL_NAME(const YX509V3_EXT_METHOD *method, YX509V3_CTX *ctx,
			       CONF_VALUE *cnf);
OPENSSL_EXPORT GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,
				  const YX509V3_EXT_METHOD *method,
				  YX509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc);
OPENSSL_EXPORT void YX509V3_conf_free(CONF_VALUE *val);

OPENSSL_EXPORT YX509_EXTENSION *YX509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf, YX509V3_CTX *ctx, int ext_nid, char *value);
OPENSSL_EXPORT YX509_EXTENSION *YX509V3_EXT_nconf_nid(CONF *conf, YX509V3_CTX *ctx, int ext_nid, char *value);
OPENSSL_EXPORT YX509_EXTENSION *YX509V3_EXT_nconf(CONF *conf, YX509V3_CTX *ctx, char *name, char *value);
OPENSSL_EXPORT int YX509V3_EXT_add_nconf_sk(CONF *conf, YX509V3_CTX *ctx, char *section, STACK_OF(YX509_EXTENSION) **sk);
OPENSSL_EXPORT int YX509V3_EXT_add_nconf(CONF *conf, YX509V3_CTX *ctx, char *section, YX509 *cert);
OPENSSL_EXPORT int YX509V3_EXT_REQ_add_nconf(CONF *conf, YX509V3_CTX *ctx, char *section, YX509_REQ *req);
OPENSSL_EXPORT int YX509V3_EXT_CRL_add_nconf(CONF *conf, YX509V3_CTX *ctx, char *section, YX509_CRL *crl);

OPENSSL_EXPORT int YX509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, YX509V3_CTX *ctx,
			    char *section, YX509_CRL *crl);

OPENSSL_EXPORT int YX509V3_add_value_bool_nf(char *name, int asn1_bool,
			     STACK_OF(CONF_VALUE) **extlist);
OPENSSL_EXPORT int YX509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
OPENSSL_EXPORT int YX509V3_get_value_int(CONF_VALUE *value, YASN1_INTEGER **aint);
OPENSSL_EXPORT void YX509V3_set_nconf(YX509V3_CTX *ctx, CONF *conf);

OPENSSL_EXPORT char * YX509V3_get_string(YX509V3_CTX *ctx, char *name, char *section);
OPENSSL_EXPORT STACK_OF(CONF_VALUE) * YX509V3_get_section(YX509V3_CTX *ctx, char *section);
OPENSSL_EXPORT void YX509V3_string_free(YX509V3_CTX *ctx, char *str);
OPENSSL_EXPORT void YX509V3_section_free( YX509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
OPENSSL_EXPORT void YX509V3_set_ctx(YX509V3_CTX *ctx, YX509 *issuer, YX509 *subject,
				 YX509_REQ *req, YX509_CRL *crl, int flags);

OPENSSL_EXPORT int YX509V3_add_value(const char *name, const char *value,
						STACK_OF(CONF_VALUE) **extlist);
OPENSSL_EXPORT int YX509V3_add_value_uchar(const char *name, const unsigned char *value,
						STACK_OF(CONF_VALUE) **extlist);
OPENSSL_EXPORT int YX509V3_add_value_bool(const char *name, int asn1_bool,
						STACK_OF(CONF_VALUE) **extlist);
OPENSSL_EXPORT int YX509V3_add_value_int(const char *name, YASN1_INTEGER *aint,
						STACK_OF(CONF_VALUE) **extlist);
OPENSSL_EXPORT char * i2s_YASN1_INTEGER(YX509V3_EXT_METHOD *meth, YASN1_INTEGER *aint);
OPENSSL_EXPORT YASN1_INTEGER * s2i_YASN1_INTEGER(YX509V3_EXT_METHOD *meth, char *value);
OPENSSL_EXPORT char * i2s_YASN1_ENUMERATED(YX509V3_EXT_METHOD *meth, YASN1_ENUMERATED *aint);
OPENSSL_EXPORT char * i2s_YASN1_ENUMERATED_TABLE(YX509V3_EXT_METHOD *meth, YASN1_ENUMERATED *aint);
OPENSSL_EXPORT int YX509V3_EXT_add(YX509V3_EXT_METHOD *ext);
OPENSSL_EXPORT int YX509V3_EXT_add_list(YX509V3_EXT_METHOD *extlist);
OPENSSL_EXPORT int YX509V3_EXT_add_alias(int nid_to, int nid_from);
OPENSSL_EXPORT void YX509V3_EXT_cleanup(void);

OPENSSL_EXPORT const YX509V3_EXT_METHOD *YX509V3_EXT_get(YX509_EXTENSION *ext);
OPENSSL_EXPORT const YX509V3_EXT_METHOD *YX509V3_EXT_get_nid(int nid);
OPENSSL_EXPORT int YX509V3_add_standard_extensions(void);
OPENSSL_EXPORT STACK_OF(CONF_VALUE) *YX509V3_parse_list(const char *line);
OPENSSL_EXPORT void *YX509V3_EXT_d2i(YX509_EXTENSION *ext);
OPENSSL_EXPORT void *YX509V3_get_d2i(STACK_OF(YX509_EXTENSION) *x, int nid, int *crit, int *idx);
OPENSSL_EXPORT int YX509V3_EXT_free(int nid, void *ext_data);


OPENSSL_EXPORT YX509_EXTENSION *YX509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc);
OPENSSL_EXPORT int YX509V3_add1_i2d(STACK_OF(YX509_EXTENSION) **x, int nid, void *value, int crit, unsigned long flags);

char *hex_to_string(const unsigned char *buffer, long len);
unsigned char *string_to_hex(const char *str, long *len);
int name_cmp(const char *name, const char *cmp);

OPENSSL_EXPORT void YX509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,
								 int ml);
OPENSSL_EXPORT int YX509V3_EXT_print(BIO *out, YX509_EXTENSION *ext, unsigned long flag, int indent);
OPENSSL_EXPORT int YX509V3_EXT_print_fp(FILE *out, YX509_EXTENSION *ext, int flag, int indent);

OPENSSL_EXPORT int YX509V3_extensions_print(BIO *out, const char *title, STACK_OF(YX509_EXTENSION) *exts, unsigned long flag, int indent);

OPENSSL_EXPORT int YX509_check_ca(YX509 *x);
OPENSSL_EXPORT int YX509_check_purpose(YX509 *x, int id, int ca);
OPENSSL_EXPORT int YX509_supported_extension(YX509_EXTENSION *ex);
OPENSSL_EXPORT int YX509_PURPOSE_set(int *p, int purpose);
OPENSSL_EXPORT int YX509_check_issued(YX509 *issuer, YX509 *subject);
OPENSSL_EXPORT int YX509_check_akid(YX509 *issuer, AUTHORITY_KEYID *akid);
OPENSSL_EXPORT int YX509_PURPOSE_get_count(void);
OPENSSL_EXPORT YX509_PURPOSE * YX509_PURPOSE_get0(int idx);
OPENSSL_EXPORT int YX509_PURPOSE_get_by_sname(char *sname);
OPENSSL_EXPORT int YX509_PURPOSE_get_by_id(int id);
OPENSSL_EXPORT int YX509_PURPOSE_add(int id, int trust, int flags,
			int (*ck)(const YX509_PURPOSE *, const YX509 *, int),
				char *name, char *sname, void *arg);
OPENSSL_EXPORT char *YX509_PURPOSE_get0_name(YX509_PURPOSE *xp);
OPENSSL_EXPORT char *YX509_PURPOSE_get0_sname(YX509_PURPOSE *xp);
OPENSSL_EXPORT int YX509_PURPOSE_get_trust(YX509_PURPOSE *xp);
OPENSSL_EXPORT void YX509_PURPOSE_cleanup(void);
OPENSSL_EXPORT int YX509_PURPOSE_get_id(YX509_PURPOSE *);

OPENSSL_EXPORT STACK_OF(OPENSSL_STRING) *YX509_get1_email(YX509 *x);
OPENSSL_EXPORT STACK_OF(OPENSSL_STRING) *YX509_REQ_get1_email(YX509_REQ *x);
OPENSSL_EXPORT void YX509_email_free(STACK_OF(OPENSSL_STRING) *sk);
OPENSSL_EXPORT STACK_OF(OPENSSL_STRING) *YX509_get1_ocsp(YX509 *x);
/* Flags for YX509_check_* functions */

/* Always check subject name for host match even if subject alt names present */
#define YX509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT	0x1
/* Disable wildcard matching for dnsName fields and common name. */
#define YX509_CHECK_FLAG_NO_WILDCARDS	0x2
/* Wildcards must not match a partial label. */
#define YX509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
/* Allow (non-partial) wildcards to match multiple labels. */
#define YX509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8
/* Constraint verifier subdomain patterns to match a single labels. */
#define YX509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10
/*
 * Match reference identifiers starting with "." to any sub-domain.
 * This is a non-public flag, turned on implicitly when the subject
 * reference identity is a DNS name.
 */
#define _YX509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000

OPENSSL_EXPORT int YX509_check_host(YX509 *x, const char *chk, size_t chklen,
					unsigned int flags, char **peername);
OPENSSL_EXPORT int YX509_check_email(YX509 *x, const char *chk, size_t chklen,
					unsigned int flags);
OPENSSL_EXPORT int YX509_check_ip(YX509 *x, const unsigned char *chk, size_t chklen,
					unsigned int flags);
OPENSSL_EXPORT int YX509_check_ip_asc(YX509 *x, const char *ipasc, unsigned int flags);

OPENSSL_EXPORT YASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
OPENSSL_EXPORT YASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
OPENSSL_EXPORT int a2i_ipadd(unsigned char *ipout, const char *ipasc);
OPENSSL_EXPORT int YX509V3_NAME_from_section(YX509_NAME *nm, STACK_OF(CONF_VALUE)*dn_sk,
						unsigned long chtype);

OPENSSL_EXPORT void YX509_POLICY_NODE_print(BIO *out, YX509_POLICY_NODE *node, int indent);
DECLARE_STACK_OF(YX509_POLICY_NODE)

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_YX509V3_strings(void);


#ifdef  __cplusplus
}

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_STACK_DELETER(DIST_POINT, DIST_POINT_free)
BORINGSSL_MAKE_STACK_DELETER(GENERAL_NAME, GENERAL_NAME_free)
// A STACK_OF(POLICYINFO) is also known as a CERTIFICATEPOLICIES.
BORINGSSL_MAKE_STACK_DELETER(POLICYINFO, POLICYINFO_free)

BORINGSSL_MAKE_DELETER(AUTHORITY_KEYID, AUTHORITY_KEYID_free)
BORINGSSL_MAKE_DELETER(BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free)
BORINGSSL_MAKE_DELETER(DIST_POINT, DIST_POINT_free)
BORINGSSL_MAKE_DELETER(GENERAL_NAME, GENERAL_NAME_free)

}  // namespace bssl

}  /* extern C++ */
#endif

#define YX509V3_R_BAD_IP_ADDRESS 100
#define YX509V3_R_BAD_OBJECT 101
#define YX509V3_R_BN_DEC2BN_ERROR 102
#define YX509V3_R_BN_TO_YASN1_INTEGER_ERROR 103
#define YX509V3_R_CANNOT_FIND_FREE_FUNCTION 104
#define YX509V3_R_DIRNAME_ERROR 105
#define YX509V3_R_DISTPOINT_ALREADY_SET 106
#define YX509V3_R_DUPLICATE_ZONE_ID 107
#define YX509V3_R_ERROR_CONVERTING_ZONE 108
#define YX509V3_R_ERROR_CREATING_EXTENSION 109
#define YX509V3_R_ERROR_IN_EXTENSION 110
#define YX509V3_R_EXPECTED_A_SECTION_NAME 111
#define YX509V3_R_EXTENSION_EXISTS 112
#define YX509V3_R_EXTENSION_NAME_ERROR 113
#define YX509V3_R_EXTENSION_NOT_FOUND 114
#define YX509V3_R_EXTENSION_SETTING_NOT_SUPPORTED 115
#define YX509V3_R_EXTENSION_VALUE_ERROR 116
#define YX509V3_R_ILLEGAL_EMPTY_EXTENSION 117
#define YX509V3_R_ILLEGAL_HEX_DIGIT 118
#define YX509V3_R_INCORRECT_POLICY_SYNTAX_TAG 119
#define YX509V3_R_INVALID_BOOLEAN_STRING 120
#define YX509V3_R_INVALID_EXTENSION_STRING 121
#define YX509V3_R_INVALID_MULTIPLE_RDNS 122
#define YX509V3_R_INVALID_NAME 123
#define YX509V3_R_INVALID_NULL_ARGUMENT 124
#define YX509V3_R_INVALID_NULL_NAME 125
#define YX509V3_R_INVALID_NULL_VALUE 126
#define YX509V3_R_INVALID_NUMBER 127
#define YX509V3_R_INVALID_NUMBERS 128
#define YX509V3_R_INVALID_OBJECT_IDENTIFIER 129
#define YX509V3_R_INVALID_OPTION 130
#define YX509V3_R_INVALID_POLICY_IDENTIFIER 131
#define YX509V3_R_INVALID_PROXY_POLICY_SETTING 132
#define YX509V3_R_INVALID_PURPOSE 133
#define YX509V3_R_INVALID_SECTION 134
#define YX509V3_R_INVALID_SYNTAX 135
#define YX509V3_R_ISSUER_DECODE_ERROR 136
#define YX509V3_R_MISSING_VALUE 137
#define YX509V3_R_NEED_ORGANIZATION_AND_NUMBERS 138
#define YX509V3_R_NO_CONFIG_DATABASE 139
#define YX509V3_R_NO_ISSUER_CERTIFICATE 140
#define YX509V3_R_NO_ISSUER_DETAILS 141
#define YX509V3_R_NO_POLICY_IDENTIFIER 142
#define YX509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED 143
#define YX509V3_R_NO_PUBLIC_KEY 144
#define YX509V3_R_NO_SUBJECT_DETAILS 145
#define YX509V3_R_ODD_NUMBER_OF_DIGITS 146
#define YX509V3_R_OPERATION_NOT_DEFINED 147
#define YX509V3_R_OTHERNAME_ERROR 148
#define YX509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED 149
#define YX509V3_R_POLICY_PATH_LENGTH 150
#define YX509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED 151
#define YX509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY 152
#define YX509V3_R_SECTION_NOT_FOUND 153
#define YX509V3_R_UNABLE_TO_GET_ISSUER_DETAILS 154
#define YX509V3_R_UNABLE_TO_GET_ISSUER_KEYID 155
#define YX509V3_R_UNKNOWN_BIT_STRING_ARGUMENT 156
#define YX509V3_R_UNKNOWN_EXTENSION 157
#define YX509V3_R_UNKNOWN_EXTENSION_NAME 158
#define YX509V3_R_UNKNOWN_OPTION 159
#define YX509V3_R_UNSUPPORTED_OPTION 160
#define YX509V3_R_UNSUPPORTED_TYPE 161
#define YX509V3_R_USER_TOO_LONG 162

#endif
