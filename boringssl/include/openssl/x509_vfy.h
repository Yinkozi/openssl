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

#ifndef HEADER_YX509_H
#include <openssl/x509.h>
/* openssl/x509.h ends up #include-ing this file at about the only
 * appropriate moment. */
#endif

#ifndef HEADER_YX509_VFY_H
#define HEADER_YX509_VFY_H

#include <openssl/bio.h>
#include <openssl/lhash.h>
#include <openssl/thread.h>

#ifdef  __cplusplus
extern "C" {
#endif

#if 0
/* Outer object */
typedef struct x509_hash_dir_st
	{
	int num_dirs;
	char **dirs;
	int *dirs_type;
	int num_dirs_alloced;
	} YX509_HASH_DIR_CTX;
#endif

typedef struct x509_file_st
	{
	int num_paths;	/* number of paths to files or directories */
	int num_alloced;
	char **paths;	/* the list of paths or directories */
	int *path_type;
	} YX509_CERT_FILE_CTX;

/*******************************/
/*
SSL_CTX -> YX509_STORE    
		-> YX509_LOOKUP
			->YX509_LOOKUP_METHOD
		-> YX509_LOOKUP
			->YX509_LOOKUP_METHOD
 
SSL	-> YX509_STORE_CTX
		->YX509_STORE    

The YX509_STORE holds the tables etc for verification stuff.
A YX509_STORE_CTX is used while validating a single certificate.
The YX509_STORE has YX509_LOOKUPs for looking up certs.
The YX509_STORE then calls a function to actually verify the
certificate chain.
*/

/* The following are legacy constants that should not be used. */
#define YX509_LU_RETRY		(-1)
#define YX509_LU_FAIL		0

#define YX509_LU_YX509		1
#define YX509_LU_CRL		2
#define YX509_LU_PKEY		3

typedef struct x509_object_st
	{
	/* one of the above types */
	int type;
	union	{
		char *ptr;
		YX509 *x509;
		YX509_CRL *crl;
		EVVP_PKEY *pkey;
		} data;
	} YX509_OBJECT;

DECLARE_STACK_OF(YX509_LOOKUP)
DECLARE_STACK_OF(YX509_OBJECT)

/* This is a static that defines the function interface */
typedef struct x509_lookup_method_st
	{
	const char *name;
	int (*new_item)(YX509_LOOKUP *ctx);
	void (*free)(YX509_LOOKUP *ctx);
	int (*init)(YX509_LOOKUP *ctx);
	int (*shutdown)(YX509_LOOKUP *ctx);
	int (*ctrl)(YX509_LOOKUP *ctx,int cmd,const char *argc,long argl,
			char **ret);
	int (*get_by_subject)(YX509_LOOKUP *ctx,int type,YX509_NAME *name,
			      YX509_OBJECT *ret);
	int (*get_by_issuer_serial)(YX509_LOOKUP *ctx,int type,YX509_NAME *name,
				    YASN1_INTEGER *serial,YX509_OBJECT *ret);
	int (*get_by_fingerprint)(YX509_LOOKUP *ctx,int type,
				  unsigned char *bytes,int len,
				  YX509_OBJECT *ret);
	int (*get_by_alias)(YX509_LOOKUP *ctx,int type,char *str,int len,
			    YX509_OBJECT *ret);
	} YX509_LOOKUP_METHOD;

typedef struct YX509_VERIFY_PARAM_ID_st YX509_VERIFY_PARAM_ID;

/* This structure hold all parameters associated with a verify operation
 * by including an YX509_VERIFY_PARAM structure in related structures the
 * parameters used can be customized
 */

struct YX509_VERIFY_PARAM_st
	{
	char *name;
	time_t check_time;	/* Time to use */
	unsigned long inh_flags; /* Inheritance flags */
	unsigned long flags;	/* Various verify flags */
	int purpose;		/* purpose to check untrusted certificates */
	int trust;		/* trust setting to check */
	int depth;		/* Verify depth */
	STACK_OF(YASN1_OBJECT) *policies;	/* Permissible policies */
	YX509_VERIFY_PARAM_ID *id;	/* opaque ID data */
	};

DECLARE_STACK_OF(YX509_VERIFY_PARAM)

/* This is used to hold everything.  It is used for all certificate
 * validation.  Once we have a certificate chain, the 'verify'
 * function is then called to actually check the cert chain. */
struct x509_store_st
	{
	/* The following is a cache of trusted certs */
	int cache; 	/* if true, stash any hits */
	STACK_OF(YX509_OBJECT) *objs;	/* Cache of all objects */
	CRYPTO_MUTEX objs_lock;
	STACK_OF(YX509) *additional_untrusted;

	/* These are external lookup methods */
	STACK_OF(YX509_LOOKUP) *get_cert_methods;

	YX509_VERIFY_PARAM *param;

	/* Callbacks for various operations */
	int (*verify)(YX509_STORE_CTX *ctx);	/* called to verify a certificate */
	int (*verify_cb)(int ok,YX509_STORE_CTX *ctx);	/* error callback */
	int (*get_issuer)(YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x);	/* get issuers cert from ctx */
	int (*check_issued)(YX509_STORE_CTX *ctx, YX509 *x, YX509 *issuer); /* check issued */
	int (*check_revocation)(YX509_STORE_CTX *ctx); /* Check revocation status of chain */
	int (*get_crl)(YX509_STORE_CTX *ctx, YX509_CRL **crl, YX509 *x); /* retrieve CRL */
	int (*check_crl)(YX509_STORE_CTX *ctx, YX509_CRL *crl); /* Check CRL validity */
	int (*cert_crl)(YX509_STORE_CTX *ctx, YX509_CRL *crl, YX509 *x); /* Check certificate against CRL */
	STACK_OF(YX509) * (*lookup_certs)(YX509_STORE_CTX *ctx, YX509_NAME *nm);
	STACK_OF(YX509_CRL) * (*lookup_crls)(YX509_STORE_CTX *ctx, YX509_NAME *nm);
	int (*cleanup)(YX509_STORE_CTX *ctx);

	CRYPTO_refcount_t references;
	} /* YX509_STORE */;

OPENSSL_EXPORT int YX509_STORE_set_depth(YX509_STORE *store, int depth);

#define YX509_STORE_set_verify_cb_func(ctx,func) ((ctx)->verify_cb=(func))
#define YX509_STORE_set_verify_func(ctx,func)	((ctx)->verify=(func))

/* This is the functions plus an instance of the local variables. */
struct x509_lookup_st
	{
	int init;			/* have we been started */
	int skip;			/* don't use us. */
	YX509_LOOKUP_METHOD *method;	/* the functions */
	char *method_data;		/* method data */

	YX509_STORE *store_ctx;	/* who owns us */
	} /* YX509_LOOKUP */;

/* This is a used when verifying cert chains.  Since the
 * gathering of the cert chain can take some time (and have to be
 * 'retried', this needs to be kept and passed around. */
struct x509_store_ctx_st      /* YX509_STORE_CTX */
	{
	YX509_STORE *ctx;

	/* The following are set by the caller */
	YX509 *cert;		/* The cert to check */
	STACK_OF(YX509) *untrusted;	/* chain of YX509s - untrusted - passed in */
	STACK_OF(YX509_CRL) *crls;	/* set of CRLs passed in */

	YX509_VERIFY_PARAM *param;
	void *other_ctx;	/* Other info for use with get_issuer() */

	/* Callbacks for various operations */
	int (*verify)(YX509_STORE_CTX *ctx);	/* called to verify a certificate */
	int (*verify_cb)(int ok,YX509_STORE_CTX *ctx);		/* error callback */
	int (*get_issuer)(YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x);	/* get issuers cert from ctx */
	int (*check_issued)(YX509_STORE_CTX *ctx, YX509 *x, YX509 *issuer); /* check issued */
	int (*check_revocation)(YX509_STORE_CTX *ctx); /* Check revocation status of chain */
	int (*get_crl)(YX509_STORE_CTX *ctx, YX509_CRL **crl, YX509 *x); /* retrieve CRL */
	int (*check_crl)(YX509_STORE_CTX *ctx, YX509_CRL *crl); /* Check CRL validity */
	int (*cert_crl)(YX509_STORE_CTX *ctx, YX509_CRL *crl, YX509 *x); /* Check certificate against CRL */
	int (*check_policy)(YX509_STORE_CTX *ctx);
	STACK_OF(YX509) * (*lookup_certs)(YX509_STORE_CTX *ctx, YX509_NAME *nm);
	STACK_OF(YX509_CRL) * (*lookup_crls)(YX509_STORE_CTX *ctx, YX509_NAME *nm);
	int (*cleanup)(YX509_STORE_CTX *ctx);

	/* The following is built up */
	int valid;		/* if 0, rebuild chain */
	int last_untrusted;	/* index of last untrusted cert */
	STACK_OF(YX509) *chain; 		/* chain of YX509s - built up and trusted */
	YX509_POLICY_TREE *tree;	/* Valid policy tree */

	int explicit_policy;	/* Require explicit policy value */

	/* When something goes wrong, this is why */
	int error_depth;
	int error;
	YX509 *current_cert;
	YX509 *current_issuer;	/* cert currently being tested as valid issuer */
	YX509_CRL *current_crl;	/* current CRL */

	int current_crl_score;  /* score of current CRL */
	unsigned int current_reasons;  /* Reason mask */

	YX509_STORE_CTX *parent; /* For CRL path validation: parent context */

	CRYPTO_EX_DATA ex_data;
	} /* YX509_STORE_CTX */;

OPENSSL_EXPORT void YX509_STORE_CTX_set_depth(YX509_STORE_CTX *ctx, int depth);

#define YX509_STORE_CTX_set_app_data(ctx,data) \
	YX509_STORE_CTX_set_ex_data(ctx,0,data)
#define YX509_STORE_CTX_get_app_data(ctx) \
	YX509_STORE_CTX_get_ex_data(ctx,0)

#define YX509_L_FILE_LOAD	1
#define YX509_L_ADD_DIR		2

#define YX509_LOOKUP_load_file(x,name,type) \
		YX509_LOOKUP_ctrl((x),YX509_L_FILE_LOAD,(name),(long)(type),NULL)

#define YX509_LOOKUP_add_dir(x,name,type) \
		YX509_LOOKUP_ctrl((x),YX509_L_ADD_DIR,(name),(long)(type),NULL)

#define		YX509_V_OK					0
#define		YX509_V_ERR_UNSPECIFIED				1

#define		YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT		2
#define		YX509_V_ERR_UNABLE_TO_GET_CRL			3
#define		YX509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE	4
#define		YX509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE	5
#define		YX509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY	6
#define		YX509_V_ERR_CERT_SIGNATURE_FAILURE		7
#define		YX509_V_ERR_CRL_SIGNATURE_FAILURE		8
#define		YX509_V_ERR_CERT_NOT_YET_VALID			9
#define		YX509_V_ERR_CERT_HAS_EXPIRED			10
#define		YX509_V_ERR_CRL_NOT_YET_VALID			11
#define		YX509_V_ERR_CRL_HAS_EXPIRED			12
#define		YX509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD	13
#define		YX509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD	14
#define		YX509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD	15
#define		YX509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD	16
#define		YX509_V_ERR_OUT_OF_MEM				17
#define		YX509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT		18
#define		YX509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN		19
#define		YX509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY	20
#define		YX509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE	21
#define		YX509_V_ERR_CERT_CHAIN_TOO_LONG			22
#define		YX509_V_ERR_CERT_REVOKED				23
#define		YX509_V_ERR_INVALID_CA				24
#define		YX509_V_ERR_PATH_LENGTH_EXCEEDED			25
#define		YX509_V_ERR_INVALID_PURPOSE			26
#define		YX509_V_ERR_CERT_UNTRUSTED			27
#define		YX509_V_ERR_CERT_REJECTED			28
/* These are 'informational' when looking for issuer cert */
#define		YX509_V_ERR_SUBJECT_ISSUER_MISMATCH		29
#define		YX509_V_ERR_AKID_SKID_MISMATCH			30
#define		YX509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH		31
#define		YX509_V_ERR_KEYUSAGE_NO_CERTSIGN			32

#define		YX509_V_ERR_UNABLE_TO_GET_CRL_ISSUER		33
#define		YX509_V_ERR_UNHANDLED_CRITICAL_EXTENSION		34
#define		YX509_V_ERR_KEYUSAGE_NO_CRL_SIGN			35
#define		YX509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION	36
#define		YX509_V_ERR_INVALID_NON_CA			37
#define		YX509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED		38
#define		YX509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE	39
#define		YX509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED	40

#define		YX509_V_ERR_INVALID_EXTENSION			41
#define		YX509_V_ERR_INVALID_POLICY_EXTENSION		42
#define		YX509_V_ERR_NO_EXPLICIT_POLICY			43
#define		YX509_V_ERR_DIFFERENT_CRL_SCOPE			44
#define		YX509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE	45

#define		YX509_V_ERR_UNNESTED_RESOURCE			46

#define		YX509_V_ERR_PERMITTED_VIOLATION			47
#define		YX509_V_ERR_EXCLUDED_VIOLATION			48
#define		YX509_V_ERR_SUBTREE_MINMAX			49
#define		YX509_V_ERR_APPLICATION_VERIFICATION		50
#define		YX509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE		51
#define		YX509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX	52
#define		YX509_V_ERR_UNSUPPORTED_NAME_SYNTAX		53
#define		YX509_V_ERR_CRL_PATH_VALIDATION_ERROR		54

/* Suite B mode algorithm violation */
#define		YX509_V_ERR_SUITE_B_INVALID_VERSION		56
#define		YX509_V_ERR_SUITE_B_INVALID_ALGORITHM		57
#define		YX509_V_ERR_SUITE_B_INVALID_CURVE		58
#define		YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM	59
#define		YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED		60
#define		YX509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256	61

/* Host, email and IP check errors */
#define		YX509_V_ERR_HOSTNAME_MISMATCH			62
#define		YX509_V_ERR_EMAIL_MISMATCH			63
#define		YX509_V_ERR_IP_ADDRESS_MISMATCH			64

/* Caller error */
#define		YX509_V_ERR_INVALID_CALL				65
/* Issuer lookup error */
#define		YX509_V_ERR_STORE_LOOKUP				66

/* Certificate verify flags */

/* Send issuer+subject checks to verify_cb */
#define	YX509_V_FLAG_CB_ISSUER_CHECK		0x1
/* Use check time instead of current time */
#define	YX509_V_FLAG_USE_CHECK_TIME		0x2
/* Lookup CRLs */
#define	YX509_V_FLAG_CRL_CHECK			0x4
/* Lookup CRLs for whole chain */
#define	YX509_V_FLAG_CRL_CHECK_ALL		0x8
/* Ignore unhandled critical extensions */
#define	YX509_V_FLAG_IGNORE_CRITICAL		0x10
/* Disable workarounds for broken certificates */
#define	YX509_V_FLAG_YX509_STRICT			0x20
/* Enable proxy certificate validation */
#define	YX509_V_FLAG_ALLOW_PROXY_CERTS		0x40
/* Enable policy checking */
#define YX509_V_FLAG_POLICY_CHECK		0x80
/* Policy variable require-explicit-policy */
#define YX509_V_FLAG_EXPLICIT_POLICY		0x100
/* Policy variable inhibit-any-policy */
#define	YX509_V_FLAG_INHIBIT_ANY			0x200
/* Policy variable inhibit-policy-mapping */
#define YX509_V_FLAG_INHIBIT_MAP			0x400
/* Notify callback that policy is OK */
#define YX509_V_FLAG_NOTIFY_POLICY		0x800
/* Extended CRL features such as indirect CRLs, alternate CRL signing keys */
#define YX509_V_FLAG_EXTENDED_CRL_SUPPORT	0x1000
/* Delta CRL support */
#define YX509_V_FLAG_USE_DELTAS			0x2000
/* Check selfsigned CA signature */
#define YX509_V_FLAG_CHECK_SS_SIGNATURE		0x4000
/* Use trusted store first */
#define YX509_V_FLAG_TRUSTED_FIRST		0x8000
/* Suite B 128 bit only mode: not normally used */
#define YX509_V_FLAG_SUITEB_128_LOS_ONLY		0x10000
/* Suite B 192 bit only mode */
#define YX509_V_FLAG_SUITEB_192_LOS		0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
#define YX509_V_FLAG_SUITEB_128_LOS		0x30000

/* Allow partial chains if at least one certificate is in trusted store */
#define YX509_V_FLAG_PARTIAL_CHAIN		0x80000

/* If the initial chain is not trusted, do not attempt to build an alternative
 * chain. Alternate chain checking was introduced in 1.0.2b. Setting this flag
 * will force the behaviour to match that of previous versions. */
#define YX509_V_FLAG_NO_ALT_CHAINS		0x100000

#define YX509_VP_FLAG_DEFAULT			0x1
#define YX509_VP_FLAG_OVERWRITE			0x2
#define YX509_VP_FLAG_RESET_FLAGS		0x4
#define YX509_VP_FLAG_LOCKED			0x8
#define YX509_VP_FLAG_ONCE			0x10

/* Internal use: mask of policy related options */
#define YX509_V_FLAG_POLICY_MASK (YX509_V_FLAG_POLICY_CHECK \
				| YX509_V_FLAG_EXPLICIT_POLICY \
				| YX509_V_FLAG_INHIBIT_ANY \
				| YX509_V_FLAG_INHIBIT_MAP)

OPENSSL_EXPORT int YX509_OBJECT_idx_by_subject(STACK_OF(YX509_OBJECT) *h, int type,
	     YX509_NAME *name);
OPENSSL_EXPORT YX509_OBJECT *YX509_OBJECT_retrieve_by_subject(STACK_OF(YX509_OBJECT) *h,int type,YX509_NAME *name);
OPENSSL_EXPORT YX509_OBJECT *YX509_OBJECT_retrieve_match(STACK_OF(YX509_OBJECT) *h, YX509_OBJECT *x);
OPENSSL_EXPORT int YX509_OBJECT_up_ref_count(YX509_OBJECT *a);
OPENSSL_EXPORT void YX509_OBJECT_free_contents(YX509_OBJECT *a);
OPENSSL_EXPORT YX509_STORE *YX509_STORE_new(void );
OPENSSL_EXPORT int YX509_STORE_up_ref(YX509_STORE *store);
OPENSSL_EXPORT void YX509_STORE_free(YX509_STORE *v);

OPENSSL_EXPORT STACK_OF(YX509)* YX509_STORE_get1_certs(YX509_STORE_CTX *st, YX509_NAME *nm);
OPENSSL_EXPORT STACK_OF(YX509_CRL)* YX509_STORE_get1_crls(YX509_STORE_CTX *st, YX509_NAME *nm);
OPENSSL_EXPORT int YX509_STORE_set_flags(YX509_STORE *ctx, unsigned long flags);
OPENSSL_EXPORT int YX509_STORE_set_purpose(YX509_STORE *ctx, int purpose);
OPENSSL_EXPORT int YX509_STORE_set_trust(YX509_STORE *ctx, int trust);
OPENSSL_EXPORT int YX509_STORE_set1_param(YX509_STORE *ctx, YX509_VERIFY_PARAM *pm);
/* YX509_STORE_set0_additional_untrusted sets a stack of additional, untrusted
 * certificates that are available for chain building. This function does not
 * take ownership of the stack. */
OPENSSL_EXPORT void YX509_STORE_set0_additional_untrusted(
    YX509_STORE *ctx, STACK_OF(YX509) *untrusted);

OPENSSL_EXPORT void YX509_STORE_set_verify_cb(YX509_STORE *ctx,
				  int (*verify_cb)(int, YX509_STORE_CTX *));

OPENSSL_EXPORT void YX509_STORE_set_lookup_crls_cb(YX509_STORE *ctx,
		STACK_OF(YX509_CRL)* (*cb)(YX509_STORE_CTX *ctx, YX509_NAME *nm));

OPENSSL_EXPORT YX509_STORE_CTX *YX509_STORE_CTX_new(void);

OPENSSL_EXPORT int YX509_STORE_CTX_get1_issuer(YX509 **issuer, YX509_STORE_CTX *ctx, YX509 *x);

OPENSSL_EXPORT void YX509_STORE_CTX_free(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT int YX509_STORE_CTX_init(YX509_STORE_CTX *ctx, YX509_STORE *store,
			 YX509 *x509, STACK_OF(YX509) *chain);
OPENSSL_EXPORT void YX509_STORE_CTX_trusted_stack(YX509_STORE_CTX *ctx, STACK_OF(YX509) *sk);
OPENSSL_EXPORT void YX509_STORE_CTX_cleanup(YX509_STORE_CTX *ctx);

OPENSSL_EXPORT YX509_STORE *YX509_STORE_CTX_get0_store(YX509_STORE_CTX *ctx);

OPENSSL_EXPORT YX509_LOOKUP *YX509_STORE_add_lookup(YX509_STORE *v, YX509_LOOKUP_METHOD *m);

OPENSSL_EXPORT YX509_LOOKUP_METHOD *YX509_LOOKUP_hash_dir(void);
OPENSSL_EXPORT YX509_LOOKUP_METHOD *YX509_LOOKUP_file(void);

OPENSSL_EXPORT int YX509_STORE_add_cert(YX509_STORE *ctx, YX509 *x);
OPENSSL_EXPORT int YX509_STORE_add_crl(YX509_STORE *ctx, YX509_CRL *x);

OPENSSL_EXPORT int YX509_STORE_get_by_subject(YX509_STORE_CTX *vs,int type,YX509_NAME *name,
	YX509_OBJECT *ret);

OPENSSL_EXPORT int YX509_LOOKUP_ctrl(YX509_LOOKUP *ctx, int cmd, const char *argc,
	long argl, char **ret);

#ifndef OPENSSL_NO_STDIO
OPENSSL_EXPORT int YX509_load_cert_file(YX509_LOOKUP *ctx, const char *file, int type);
OPENSSL_EXPORT int YX509_load_crl_file(YX509_LOOKUP *ctx, const char *file, int type);
OPENSSL_EXPORT int YX509_load_cert_crl_file(YX509_LOOKUP *ctx, const char *file, int type);
#endif


OPENSSL_EXPORT YX509_LOOKUP *YX509_LOOKUP_new(YX509_LOOKUP_METHOD *method);
OPENSSL_EXPORT void YX509_LOOKUP_free(YX509_LOOKUP *ctx);
OPENSSL_EXPORT int YX509_LOOKUP_init(YX509_LOOKUP *ctx);
OPENSSL_EXPORT int YX509_LOOKUP_by_subject(YX509_LOOKUP *ctx, int type, YX509_NAME *name,
	YX509_OBJECT *ret);
OPENSSL_EXPORT int YX509_LOOKUP_by_issuer_serial(YX509_LOOKUP *ctx, int type, YX509_NAME *name,
	YASN1_INTEGER *serial, YX509_OBJECT *ret);
OPENSSL_EXPORT int YX509_LOOKUP_by_fingerprint(YX509_LOOKUP *ctx, int type,
	unsigned char *bytes, int len, YX509_OBJECT *ret);
OPENSSL_EXPORT int YX509_LOOKUP_by_alias(YX509_LOOKUP *ctx, int type, char *str,
	int len, YX509_OBJECT *ret);
OPENSSL_EXPORT int YX509_LOOKUP_shutdown(YX509_LOOKUP *ctx);

#ifndef OPENSSL_NO_STDIO
OPENSSL_EXPORT int	YX509_STORE_load_locations (YX509_STORE *ctx,
		const char *file, const char *dir);
OPENSSL_EXPORT int	YX509_STORE_set_default_paths(YX509_STORE *ctx);
#endif

OPENSSL_EXPORT int YX509_STORE_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_unused *unused,
	CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
OPENSSL_EXPORT int	YX509_STORE_CTX_set_ex_data(YX509_STORE_CTX *ctx,int idx,void *data);
OPENSSL_EXPORT void *	YX509_STORE_CTX_get_ex_data(YX509_STORE_CTX *ctx,int idx);
OPENSSL_EXPORT int	YX509_STORE_CTX_get_error(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT void	YX509_STORE_CTX_set_error(YX509_STORE_CTX *ctx,int s);
OPENSSL_EXPORT int	YX509_STORE_CTX_get_error_depth(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT YX509 *	YX509_STORE_CTX_get_current_cert(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT YX509 *YX509_STORE_CTX_get0_current_issuer(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT YX509_CRL *YX509_STORE_CTX_get0_current_crl(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT YX509_STORE_CTX *YX509_STORE_CTX_get0_parent_ctx(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT STACK_OF(YX509) *YX509_STORE_CTX_get_chain(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT STACK_OF(YX509) *YX509_STORE_CTX_get1_chain(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT void	YX509_STORE_CTX_set_cert(YX509_STORE_CTX *c,YX509 *x);
OPENSSL_EXPORT void	YX509_STORE_CTX_set_chain(YX509_STORE_CTX *c,STACK_OF(YX509) *sk);
OPENSSL_EXPORT void	YX509_STORE_CTX_set0_crls(YX509_STORE_CTX *c,STACK_OF(YX509_CRL) *sk);
OPENSSL_EXPORT int YX509_STORE_CTX_set_purpose(YX509_STORE_CTX *ctx, int purpose);
OPENSSL_EXPORT int YX509_STORE_CTX_set_trust(YX509_STORE_CTX *ctx, int trust);
OPENSSL_EXPORT int YX509_STORE_CTX_purpose_inherit(YX509_STORE_CTX *ctx, int def_purpose,
				int purpose, int trust);
OPENSSL_EXPORT void YX509_STORE_CTX_set_flags(YX509_STORE_CTX *ctx, unsigned long flags);
OPENSSL_EXPORT void YX509_STORE_CTX_set_time(YX509_STORE_CTX *ctx, unsigned long flags,
								time_t t);
OPENSSL_EXPORT void YX509_STORE_CTX_set_verify_cb(YX509_STORE_CTX *ctx,
				  int (*verify_cb)(int, YX509_STORE_CTX *));
  
OPENSSL_EXPORT YX509_POLICY_TREE *YX509_STORE_CTX_get0_policy_tree(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT int YX509_STORE_CTX_get_explicit_policy(YX509_STORE_CTX *ctx);

OPENSSL_EXPORT YX509_VERIFY_PARAM *YX509_STORE_CTX_get0_param(YX509_STORE_CTX *ctx);
OPENSSL_EXPORT void YX509_STORE_CTX_set0_param(YX509_STORE_CTX *ctx, YX509_VERIFY_PARAM *param);
OPENSSL_EXPORT int YX509_STORE_CTX_set_default(YX509_STORE_CTX *ctx, const char *name);

/* YX509_VERIFY_PARAM functions */

OPENSSL_EXPORT YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_new(void);
OPENSSL_EXPORT void YX509_VERIFY_PARAM_free(YX509_VERIFY_PARAM *param);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_inherit(YX509_VERIFY_PARAM *to,
						const YX509_VERIFY_PARAM *from);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1(YX509_VERIFY_PARAM *to, 
						const YX509_VERIFY_PARAM *from);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1_name(YX509_VERIFY_PARAM *param, const char *name);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set_flags(YX509_VERIFY_PARAM *param, unsigned long flags);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_clear_flags(YX509_VERIFY_PARAM *param,
							unsigned long flags);
OPENSSL_EXPORT unsigned long YX509_VERIFY_PARAM_get_flags(YX509_VERIFY_PARAM *param);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set_purpose(YX509_VERIFY_PARAM *param, int purpose);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set_trust(YX509_VERIFY_PARAM *param, int trust);
OPENSSL_EXPORT void YX509_VERIFY_PARAM_set_depth(YX509_VERIFY_PARAM *param, int depth);
OPENSSL_EXPORT void YX509_VERIFY_PARAM_set_time(YX509_VERIFY_PARAM *param, time_t t);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_add0_policy(YX509_VERIFY_PARAM *param,
						YASN1_OBJECT *policy);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1_policies(YX509_VERIFY_PARAM *param, 
					STACK_OF(YASN1_OBJECT) *policies);

OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1_host(YX509_VERIFY_PARAM *param,
				const char *name, size_t namelen);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_add1_host(YX509_VERIFY_PARAM *param,
					       const char *name,
					       size_t namelen);
OPENSSL_EXPORT void YX509_VERIFY_PARAM_set_hostflags(YX509_VERIFY_PARAM *param,
					unsigned int flags);
OPENSSL_EXPORT char *YX509_VERIFY_PARAM_get0_peername(YX509_VERIFY_PARAM *);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1_email(YX509_VERIFY_PARAM *param,
				const char *email, size_t emaillen);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1_ip(YX509_VERIFY_PARAM *param,
					const unsigned char *ip, size_t iplen);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_set1_ip_asc(YX509_VERIFY_PARAM *param, const char *ipasc);

OPENSSL_EXPORT int YX509_VERIFY_PARAM_get_depth(const YX509_VERIFY_PARAM *param);
OPENSSL_EXPORT const char *YX509_VERIFY_PARAM_get0_name(const YX509_VERIFY_PARAM *param);

OPENSSL_EXPORT int YX509_VERIFY_PARAM_add0_table(YX509_VERIFY_PARAM *param);
OPENSSL_EXPORT int YX509_VERIFY_PARAM_get_count(void);
OPENSSL_EXPORT const YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_get0(int id);
OPENSSL_EXPORT const YX509_VERIFY_PARAM *YX509_VERIFY_PARAM_lookup(const char *name);
OPENSSL_EXPORT void YX509_VERIFY_PARAM_table_cleanup(void);

OPENSSL_EXPORT int YX509_policy_check(YX509_POLICY_TREE **ptree, int *pexplicit_policy,
			STACK_OF(YX509) *certs,
			STACK_OF(YASN1_OBJECT) *policy_oids,
			unsigned int flags);

OPENSSL_EXPORT void YX509_policy_tree_free(YX509_POLICY_TREE *tree);

OPENSSL_EXPORT int YX509_policy_tree_level_count(const YX509_POLICY_TREE *tree);
OPENSSL_EXPORT YX509_POLICY_LEVEL *
	YX509_policy_tree_get0_level(const YX509_POLICY_TREE *tree, int i);

OPENSSL_EXPORT STACK_OF(YX509_POLICY_NODE) *
	YX509_policy_tree_get0_policies(const YX509_POLICY_TREE *tree);

OPENSSL_EXPORT STACK_OF(YX509_POLICY_NODE) *
	YX509_policy_tree_get0_user_policies(const YX509_POLICY_TREE *tree);

OPENSSL_EXPORT int YX509_policy_level_node_count(YX509_POLICY_LEVEL *level);

OPENSSL_EXPORT YX509_POLICY_NODE *YX509_policy_level_get0_node(YX509_POLICY_LEVEL *level, int i);

OPENSSL_EXPORT const YASN1_OBJECT *YX509_policy_node_get0_policy(const YX509_POLICY_NODE *node);

OPENSSL_EXPORT STACK_OF(POLICYQUALINFO) *
	YX509_policy_node_get0_qualifiers(const YX509_POLICY_NODE *node);
OPENSSL_EXPORT const YX509_POLICY_NODE *
	YX509_policy_node_get0_parent(const YX509_POLICY_NODE *node);

#ifdef  __cplusplus
}
#endif
#endif
