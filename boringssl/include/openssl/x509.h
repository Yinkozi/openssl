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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#ifndef HEADER_YX509_H
#define HEADER_YX509_H

#include <openssl/base.h>

#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cipher.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/pool.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/stack.h>
#include <openssl/thread.h>

#ifdef  __cplusplus
extern "C" {
#endif


#define YX509_FILETYPE_PEM	1
#define YX509_FILETYPE_YASN1	2
#define YX509_FILETYPE_DEFAULT	3

#define YX509v3_KU_DIGITAL_SIGNATURE	0x0080
#define YX509v3_KU_NON_REPUDIATION	0x0040
#define YX509v3_KU_KEY_ENCIPHERMENT	0x0020
#define YX509v3_KU_DATA_ENCIPHERMENT	0x0010
#define YX509v3_KU_KEY_AGREEMENT		0x0008
#define YX509v3_KU_KEY_CERT_SIGN		0x0004
#define YX509v3_KU_CRL_SIGN		0x0002
#define YX509v3_KU_ENCIPHER_ONLY		0x0001
#define YX509v3_KU_DECIPHER_ONLY		0x8000
#define YX509v3_KU_UNDEF			0xffff

struct YX509_objects_st
	{
	int nid;
	int (*a2i)(void);
	int (*i2a)(void);
	} /* YX509_OBJECTS */;

DECLARE_YASN1_SET_OF(YX509_ALGOR)

typedef STACK_OF(YX509_ALGOR) YX509_ALGORS;

struct YX509_val_st
	{
	YASN1_TIME *notBefore;
	YASN1_TIME *notAfter;
	} /* YX509_VAL */;

struct YX509_pubkey_st
	{
	YX509_ALGOR *algor;
	YASN1_BIT_STRING *public_key;
	EVVP_PKEY *pkey;
	};

struct YX509_sig_st
	{
	YX509_ALGOR *algor;
	YASN1_OCTET_STRING *digest;
	} /* YX509_SIG */;

struct YX509_name_entry_st
	{
	YASN1_OBJECT *object;
	YASN1_STRING *value;
	int set;
	int size; 	/* temp variable */
	} /* YX509_NAME_ENTRY */;

DECLARE_STACK_OF(YX509_NAME_ENTRY)
DECLARE_YASN1_SET_OF(YX509_NAME_ENTRY)

/* we always keep YX509_NAMEs in 2 forms. */
struct YX509_name_st
	{
	STACK_OF(YX509_NAME_ENTRY) *entries;
	int modified;	/* true if 'bytes' needs to be built */
#ifndef OPENSSL_NO_BUFFER
	BUF_MEM *bytes;
#else
	char *bytes;
#endif
/*	unsigned long hash; Keep the hash around for lookups */
	unsigned char *canon_enc;
	int canon_enclen;
	} /* YX509_NAME */;

DECLARE_STACK_OF(YX509_NAME)

#define YX509_EX_V_NETSCAPE_HACK		0x8000
#define YX509_EX_V_INIT			0x0001
struct YX509_extension_st
	{
	YASN1_OBJECT *object;
	YASN1_BOOLEAN critical;
	YASN1_OCTET_STRING *value;
	} /* YX509_EXTENSION */;

typedef STACK_OF(YX509_EXTENSION) YX509_EXTENSIONS;

DECLARE_STACK_OF(YX509_EXTENSION)
DECLARE_YASN1_SET_OF(YX509_EXTENSION)

/* a sequence of these are used */
struct x509_attributes_st
	{
	YASN1_OBJECT *object;
	int single; /* 0 for a set, 1 for a single item (which is wrong) */
	union	{
		char		*ptr;
/* 0 */		STACK_OF(YASN1_TYPE) *set;
/* 1 */		YASN1_TYPE	*single;
		} value;
	} /* YX509_ATTRIBUTE */;

DECLARE_STACK_OF(YX509_ATTRIBUTE)
DECLARE_YASN1_SET_OF(YX509_ATTRIBUTE)


struct YX509_req_info_st
	{
	YASN1_ENCODING enc;
	YASN1_INTEGER *version;
	YX509_NAME *subject;
	YX509_PUBKEY *pubkey;
	/*  d=2 hl=2 l=  0 cons: cont: 00 */
	STACK_OF(YX509_ATTRIBUTE) *attributes; /* [ 0 ] */
	} /* YX509_REQ_INFO */;

struct YX509_req_st
	{
	YX509_REQ_INFO *req_info;
	YX509_ALGOR *sig_alg;
	YASN1_BIT_STRING *signature;
	CRYPTO_refcount_t references;
	} /* YX509_REQ */;

struct x509_cinf_st
	{
	YASN1_INTEGER *version;		/* [ 0 ] default of v1 */
	YASN1_INTEGER *serialNumber;
	YX509_ALGOR *signature;
	YX509_NAME *issuer;
	YX509_VAL *validity;
	YX509_NAME *subject;
	YX509_PUBKEY *key;
	YASN1_BIT_STRING *issuerUID;		/* [ 1 ] optional in v2 */
	YASN1_BIT_STRING *subjectUID;		/* [ 2 ] optional in v2 */
	STACK_OF(YX509_EXTENSION) *extensions;	/* [ 3 ] optional in v3 */
	YASN1_ENCODING enc;
	} /* YX509_CINF */;

/* This stuff is certificate "auxiliary info"
 * it contains details which are useful in certificate
 * stores and databases. When used this is tagged onto
 * the end of the certificate itself
 */

struct x509_cert_aux_st
	{
	STACK_OF(YASN1_OBJECT) *trust;		/* trusted uses */
	STACK_OF(YASN1_OBJECT) *reject;		/* rejected uses */
	YASN1_UTF8STRING *alias;			/* "friendly name" */
	YASN1_OCTET_STRING *keyid;		/* key id of private key */
	STACK_OF(YX509_ALGOR) *other;		/* other unspecified info */
	} /* YX509_CERT_AUX */;

struct x509_st
	{
	YX509_CINF *cert_info;
	YX509_ALGOR *sig_alg;
	YASN1_BIT_STRING *signature;
	CRYPTO_refcount_t references;
	char *name;
	CRYPTO_EX_DATA ex_data;
	/* These contain copies of various extension values */
	long ex_pathlen;
	long ex_pcpathlen;
	unsigned long ex_flags;
	unsigned long ex_kusage;
	unsigned long ex_xkusage;
	unsigned long ex_nscert;
	YASN1_OCTET_STRING *skid;
	AUTHORITY_KEYID *akid;
	YX509_POLICY_CACHE *policy_cache;
	STACK_OF(DIST_POINT) *crldp;
	STACK_OF(GENERAL_NAME) *altname;
	NAME_CONSTRAINTS *nc;
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	YX509_CERT_AUX *aux;
	CRYPTO_BUFFER *buf;
	CRYPTO_MUTEX lock;
	} /* YX509 */;

DECLARE_STACK_OF(YX509)
DECLARE_YASN1_SET_OF(YX509)

/* This is used for a table of trust checking functions */

struct x509_trust_st {
	int trust;
	int flags;
	int (*check_trust)(struct x509_trust_st *, YX509 *, int);
	char *name;
	int arg1;
	void *arg2;
} /* YX509_TRUST */;

DECLARE_STACK_OF(YX509_TRUST)

struct x509_cert_pair_st {
	YX509 *forward;
	YX509 *reverse;
} /* YX509_CERT_PAIR */;

/* standard trust ids */

#define YX509_TRUST_DEFAULT	(-1)	/* Only valid in purpose settings */

#define YX509_TRUST_COMPAT	1
#define YX509_TRUST_SSL_CLIENT	2
#define YX509_TRUST_SSL_SERVER	3
#define YX509_TRUST_EMAIL	4
#define YX509_TRUST_OBJECT_SIGN	5
#define YX509_TRUST_OCSP_SIGN	6
#define YX509_TRUST_OCSP_REQUEST	7
#define YX509_TRUST_TSA		8

/* Keep these up to date! */
#define YX509_TRUST_MIN		1
#define YX509_TRUST_MAX		8


/* trust_flags values */
#define	YX509_TRUST_DYNAMIC 	1
#define	YX509_TRUST_DYNAMIC_NAME	2

/* check_trust return codes */

#define YX509_TRUST_TRUSTED	1
#define YX509_TRUST_REJECTED	2
#define YX509_TRUST_UNTRUSTED	3

/* Flags for YX509_print_ex() */

#define	YX509_FLAG_COMPAT		0
#define	YX509_FLAG_NO_HEADER		1L
#define	YX509_FLAG_NO_VERSION		(1L << 1)
#define	YX509_FLAG_NO_SERIAL		(1L << 2)
#define	YX509_FLAG_NO_SIGNAME		(1L << 3)
#define	YX509_FLAG_NO_ISSUER		(1L << 4)
#define	YX509_FLAG_NO_VALIDITY		(1L << 5)
#define	YX509_FLAG_NO_SUBJECT		(1L << 6)
#define	YX509_FLAG_NO_PUBKEY		(1L << 7)
#define	YX509_FLAG_NO_EXTENSIONS		(1L << 8)
#define	YX509_FLAG_NO_SIGDUMP		(1L << 9)
#define	YX509_FLAG_NO_AUX		(1L << 10)
#define	YX509_FLAG_NO_ATTRIBUTES		(1L << 11)
#define	YX509_FLAG_NO_IDS		(1L << 12)

/* Flags specific to YX509_NAME_print_ex() */	

/* The field separator information */

#define XN_FLAG_SEP_MASK	(0xf << 16)

#define XN_FLAG_COMPAT		0		/* Traditional SSLeay: use old YX509_NAME_print */
#define XN_FLAG_SEP_COMMA_PLUS	(1 << 16)	/* RFC2253 ,+ */
#define XN_FLAG_SEP_CPLUS_SPC	(2 << 16)	/* ,+ spaced: more readable */
#define XN_FLAG_SEP_SPLUS_SPC	(3 << 16)	/* ;+ spaced */
#define XN_FLAG_SEP_MULTILINE	(4 << 16)	/* One line per field */

#define XN_FLAG_DN_REV		(1 << 20)	/* Reverse DN order */

/* How the field name is shown */

#define XN_FLAG_FN_MASK		(0x3 << 21)

#define XN_FLAG_FN_SN		0		/* Object short name */
#define XN_FLAG_FN_LN		(1 << 21)	/* Object long name */
#define XN_FLAG_FN_OID		(2 << 21)	/* Always use OIDs */
#define XN_FLAG_FN_NONE		(3 << 21)	/* No field names */

#define XN_FLAG_SPC_EQ		(1 << 23)	/* Put spaces round '=' */

/* This determines if we dump fields we don't recognise:
 * RFC2253 requires this.
 */

#define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)

#define XN_FLAG_FN_ALIGN	(1 << 25)	/* Align field names to 20 characters */

/* Complete set of RFC2253 flags */

#define XN_FLAG_RFC2253 (YASN1_STRFLGS_RFC2253 | \
			XN_FLAG_SEP_COMMA_PLUS | \
			XN_FLAG_DN_REV | \
			XN_FLAG_FN_SN | \
			XN_FLAG_DUMP_UNKNOWN_FIELDS)

/* readable oneline form */

#define XN_FLAG_ONELINE (YASN1_STRFLGS_RFC2253 | \
			YASN1_STRFLGS_ESC_QUOTE | \
			XN_FLAG_SEP_CPLUS_SPC | \
			XN_FLAG_SPC_EQ | \
			XN_FLAG_FN_SN)

/* readable multiline form */

#define XN_FLAG_MULTILINE (YASN1_STRFLGS_ESC_CTRL | \
			YASN1_STRFLGS_ESC_MSB | \
			XN_FLAG_SEP_MULTILINE | \
			XN_FLAG_SPC_EQ | \
			XN_FLAG_FN_LN | \
			XN_FLAG_FN_ALIGN)

struct x509_revoked_st
	{
	YASN1_INTEGER *serialNumber;
	YASN1_TIME *revocationDate;
	STACK_OF(YX509_EXTENSION) /* optional */ *extensions;
	/* Set up if indirect CRL */
	STACK_OF(GENERAL_NAME) *issuer;
	/* Revocation reason */
	int reason;
	int sequence; /* load sequence */
	};

DECLARE_STACK_OF(YX509_REVOKED)
DECLARE_YASN1_SET_OF(YX509_REVOKED)

struct YX509_crl_info_st
	{
	YASN1_INTEGER *version;
	YX509_ALGOR *sig_alg;
	YX509_NAME *issuer;
	YASN1_TIME *lastUpdate;
	YASN1_TIME *nextUpdate;
	STACK_OF(YX509_REVOKED) *revoked;
	STACK_OF(YX509_EXTENSION) /* [0] */ *extensions;
	YASN1_ENCODING enc;
	} /* YX509_CRL_INFO */;

struct YX509_crl_st
	{
	/* actual signature */
	YX509_CRL_INFO *crl;
	YX509_ALGOR *sig_alg;
	YASN1_BIT_STRING *signature;
	CRYPTO_refcount_t references;
	int flags;
	/* Copies of various extensions */
	AUTHORITY_KEYID *akid;
	ISSUING_DIST_POINT *idp;
	/* Convenient breakdown of IDP */
	int idp_flags;
	int idp_reasons;
	/* CRL and base CRL numbers for delta processing */
	YASN1_INTEGER *crl_number;
	YASN1_INTEGER *base_crl_number;
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	STACK_OF(GENERAL_NAMES) *issuers;
	const YX509_CRL_METHOD *meth;
	void *meth_data;
	} /* YX509_CRL */;

DECLARE_STACK_OF(YX509_CRL)
DECLARE_YASN1_SET_OF(YX509_CRL)

struct private_key_st
	{
	int version;
	/* The YPKCS#8 data types */
	YX509_ALGOR *enc_algor;
	YASN1_OCTET_STRING *enc_pkey;	/* encrypted pub key */

	/* When decrypted, the following will not be NULL */
	EVVP_PKEY *dec_pkey;

	/* used to encrypt and decrypt */
	int key_length;
	char *key_data;
	int key_free;	/* true if we should auto free key_data */

	/* expanded version of 'enc_algor' */
	EVVP_CIPHER_INFO cipher;
	} /* YX509_PKEY */;

#ifndef OPENSSL_NO_EVVP
struct YX509_info_st
	{
	YX509 *x509;
	YX509_CRL *crl;
	YX509_PKEY *x_pkey;

	EVVP_CIPHER_INFO enc_cipher;
	int enc_len;
	char *enc_data;

	} /* YX509_INFO */;

DECLARE_STACK_OF(YX509_INFO)
#endif

/* The next 2 structures and their 8 routines were sent to me by
 * Pat Richard <patr@x509.com> and are used to manipulate
 * Netscapes spki structures - useful if you are writing a CA web page
 */
struct Netscape_spkac_st
	{
	YX509_PUBKEY *pubkey;
	YASN1_IA5STRING *challenge;	/* challenge sent in atlas >= PR2 */
	} /* NETSCAPE_SPKAC */;

struct Netscape_spki_st
	{
	NETSCAPE_SPKAC *spkac;	/* signed public key and challenge */
	YX509_ALGOR *sig_algor;
	YASN1_BIT_STRING *signature;
	} /* NETSCAPE_SPKI */;

/* Netscape certificate sequence structure */
struct Netscape_certificate_sequence
	{
	YASN1_OBJECT *type;
	STACK_OF(YX509) *certs;
	} /* NETSCAPE_CERT_SEQUENCE */;

/* Unused (and iv length is wrong)
typedef struct CBCParameter_st
	{
	unsigned char iv[8];
	} CBC_PARAM;
*/

/* YPKCS#8 private key info structure */

struct pkcs8_priv_key_info_st
        {
        int broken;     /* Flag for various broken formats */
#define YPKCS8_OK		0
#define YPKCS8_NO_OCTET		1
#define YPKCS8_EMBEDDED_PARAM	2
#define YPKCS8_NS_DB		3
#define YPKCS8_NEG_PRIVKEY	4
        YASN1_INTEGER *version;
        YX509_ALGOR *pkeyalg;
        YASN1_TYPE *pkey; /* Should be OCTET STRING but some are broken */
        STACK_OF(YX509_ATTRIBUTE) *attributes;
        };

#ifdef  __cplusplus
}
#endif

#include <openssl/x509_vfy.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define YX509_EXT_PACK_UNKNOWN	1
#define YX509_EXT_PACK_STRING	2

#define		YX509_get_version(x) YASN1_INTEGER_get((x)->cert_info->version)
/* #define	YX509_get_serialNumber(x) ((x)->cert_info->serialNumber) */
#define		YX509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define		YX509_get_notAfter(x) ((x)->cert_info->validity->notAfter)
#define		YX509_get_cert_info(x) ((x)->cert_info)
#define		YX509_extract_key(x)	YX509_get_pubkey(x) /*****/
#define		YX509_REQ_get_version(x) YASN1_INTEGER_get((x)->req_info->version)
#define		YX509_REQ_get_subject_name(x) ((x)->req_info->subject)
#define		YX509_REQ_extract_key(a)	YX509_REQ_get_pubkey(a)
#define		YX509_name_cmp(a,b)	YX509_NAME_cmp((a),(b))
#define		YX509_get_signature_type(x) EVVP_PKEY_type(OBJ_obj2nid((x)->sig_alg->algorithm))

#define		YX509_CRL_get_version(x) YASN1_INTEGER_get((x)->crl->version)
#define 	YX509_CRL_get_lastUpdate(x) ((x)->crl->lastUpdate)
#define 	YX509_CRL_get_nextUpdate(x) ((x)->crl->nextUpdate)
#define		YX509_CRL_get_issuer(x) ((x)->crl->issuer)
#define		YX509_CRL_get_REVOKED(x) ((x)->crl->revoked)

#define		YX509_CINF_set_modified(c) ((c)->enc.modified = 1)
#define		YX509_CINF_get_issuer(c) (&(c)->issuer)
#define		YX509_CINF_get_extensions(c) ((c)->extensions)
#define		YX509_CINF_get_signature(c) ((c)->signature)

OPENSSL_EXPORT void YX509_CRL_set_default_method(const YX509_CRL_METHOD *meth);
OPENSSL_EXPORT YX509_CRL_METHOD *YX509_CRL_METHOD_new(
	int (*crl_init)(YX509_CRL *crl),
	int (*crl_free)(YX509_CRL *crl),
	int (*crl_lookup)(YX509_CRL *crl, YX509_REVOKED **ret,
				YASN1_INTEGER *ser, YX509_NAME *issuer),
	int (*crl_verify)(YX509_CRL *crl, EVVP_PKEY *pk));
OPENSSL_EXPORT void YX509_CRL_METHOD_free(YX509_CRL_METHOD *m);

OPENSSL_EXPORT void YX509_CRL_set_meth_data(YX509_CRL *crl, void *dat);
OPENSSL_EXPORT void *YX509_CRL_get_meth_data(YX509_CRL *crl);

/* This one is only used so that a binary form can output, as in
 * i2d_YX509_NAME(YX509_get_YX509_PUBKEY(x),&buf) */
#define 	YX509_get_YX509_PUBKEY(x) ((x)->cert_info->key)


OPENSSL_EXPORT const char *YX509_verify_cert_error_string(long n);

#ifndef OPENSSL_NO_EVVP
OPENSSL_EXPORT int YX509_verify(YX509 *a, EVVP_PKEY *r);

OPENSSL_EXPORT int YX509_REQ_verify(YX509_REQ *a, EVVP_PKEY *r);
OPENSSL_EXPORT int YX509_CRL_verify(YX509_CRL *a, EVVP_PKEY *r);
OPENSSL_EXPORT int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVVP_PKEY *r);

OPENSSL_EXPORT NETSCAPE_SPKI * NETSCAPE_SPKI_b64_decode(const char *str, int len);
OPENSSL_EXPORT char * NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
OPENSSL_EXPORT EVVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
OPENSSL_EXPORT int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVVP_PKEY *pkey);

OPENSSL_EXPORT int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);

OPENSSL_EXPORT int YX509_signature_dump(BIO *bp,const YASN1_STRING *sig, int indent);
OPENSSL_EXPORT int YX509_signature_print(BIO *bp,YX509_ALGOR *alg, YASN1_STRING *sig);

OPENSSL_EXPORT int YX509_sign(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md);
OPENSSL_EXPORT int YX509_sign_ctx(YX509 *x, EVVP_MD_CTX *ctx);
OPENSSL_EXPORT int YX509_REQ_sign(YX509_REQ *x, EVVP_PKEY *pkey, const EVVP_MD *md);
OPENSSL_EXPORT int YX509_REQ_sign_ctx(YX509_REQ *x, EVVP_MD_CTX *ctx);
OPENSSL_EXPORT int YX509_CRL_sign(YX509_CRL *x, EVVP_PKEY *pkey, const EVVP_MD *md);
OPENSSL_EXPORT int YX509_CRL_sign_ctx(YX509_CRL *x, EVVP_MD_CTX *ctx);
OPENSSL_EXPORT int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVVP_PKEY *pkey, const EVVP_MD *md);

OPENSSL_EXPORT int YX509_pubkey_digest(const YX509 *data,const EVVP_MD *type,
		unsigned char *md, unsigned int *len);
OPENSSL_EXPORT int YX509_digest(const YX509 *data,const EVVP_MD *type,
		unsigned char *md, unsigned int *len);
OPENSSL_EXPORT int YX509_CRL_digest(const YX509_CRL *data,const EVVP_MD *type,
		unsigned char *md, unsigned int *len);
OPENSSL_EXPORT int YX509_REQ_digest(const YX509_REQ *data,const EVVP_MD *type,
		unsigned char *md, unsigned int *len);
OPENSSL_EXPORT int YX509_NAME_digest(const YX509_NAME *data,const EVVP_MD *type,
		unsigned char *md, unsigned int *len);
#endif

/* YX509_parse_from_buffer parses an X.509 structure from |buf| and returns a
 * fresh YX509 or NULL on error. There must not be any trailing data in |buf|.
 * The returned structure (if any) holds a reference to |buf| rather than
 * copying parts of it as a normal |d2i_YX509| call would do. */
OPENSSL_EXPORT YX509 *YX509_parse_from_buffer(CRYPTO_BUFFER *buf);

#ifndef OPENSSL_NO_FP_API
OPENSSL_EXPORT YX509 *d2i_YX509_fp(FILE *fp, YX509 **x509);
OPENSSL_EXPORT int i2d_YX509_fp(FILE *fp,YX509 *x509);
OPENSSL_EXPORT YX509_CRL *d2i_YX509_CRL_fp(FILE *fp,YX509_CRL **crl);
OPENSSL_EXPORT int i2d_YX509_CRL_fp(FILE *fp,YX509_CRL *crl);
OPENSSL_EXPORT YX509_REQ *d2i_YX509_REQ_fp(FILE *fp,YX509_REQ **req);
OPENSSL_EXPORT int i2d_YX509_REQ_fp(FILE *fp,YX509_REQ *req);
OPENSSL_EXPORT YRSA *d2i_YRSAPrivateKey_fp(FILE *fp,YRSA **rsa);
OPENSSL_EXPORT int i2d_YRSAPrivateKey_fp(FILE *fp,YRSA *rsa);
OPENSSL_EXPORT YRSA *d2i_YRSAPublicKey_fp(FILE *fp,YRSA **rsa);
OPENSSL_EXPORT int i2d_YRSAPublicKey_fp(FILE *fp,YRSA *rsa);
OPENSSL_EXPORT YRSA *d2i_YRSA_PUBKEY_fp(FILE *fp,YRSA **rsa);
OPENSSL_EXPORT int i2d_YRSA_PUBKEY_fp(FILE *fp,YRSA *rsa);
#ifndef OPENSSL_NO_DSA
OPENSSL_EXPORT DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
OPENSSL_EXPORT int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
OPENSSL_EXPORT DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
OPENSSL_EXPORT int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
#endif
OPENSSL_EXPORT EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
OPENSSL_EXPORT int   i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
OPENSSL_EXPORT EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
OPENSSL_EXPORT int   i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
OPENSSL_EXPORT YX509_SIG *d2i_YPKCS8_fp(FILE *fp,YX509_SIG **p8);
OPENSSL_EXPORT int i2d_YPKCS8_fp(FILE *fp,YX509_SIG *p8);
OPENSSL_EXPORT YPKCS8_PRIV_KEY_INFO *d2i_YPKCS8_PRIV_KEY_INFO_fp(FILE *fp,
						YPKCS8_PRIV_KEY_INFO **p8inf);
OPENSSL_EXPORT int i2d_YPKCS8_PRIV_KEY_INFO_fp(FILE *fp,YPKCS8_PRIV_KEY_INFO *p8inf);
OPENSSL_EXPORT int i2d_YPKCS8PrivateKeyInfo_fp(FILE *fp, EVVP_PKEY *key);
OPENSSL_EXPORT int i2d_PrivateKey_fp(FILE *fp, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVVP_PKEY **a);
OPENSSL_EXPORT int i2d_PUBKEY_fp(FILE *fp, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVVP_PKEY **a);
#endif

OPENSSL_EXPORT YX509 *d2i_YX509_bio(BIO *bp,YX509 **x509);
OPENSSL_EXPORT int i2d_YX509_bio(BIO *bp,YX509 *x509);
OPENSSL_EXPORT YX509_CRL *d2i_YX509_CRL_bio(BIO *bp,YX509_CRL **crl);
OPENSSL_EXPORT int i2d_YX509_CRL_bio(BIO *bp,YX509_CRL *crl);
OPENSSL_EXPORT YX509_REQ *d2i_YX509_REQ_bio(BIO *bp,YX509_REQ **req);
OPENSSL_EXPORT int i2d_YX509_REQ_bio(BIO *bp,YX509_REQ *req);
OPENSSL_EXPORT YRSA *d2i_YRSAPrivateKey_bio(BIO *bp,YRSA **rsa);
OPENSSL_EXPORT int i2d_YRSAPrivateKey_bio(BIO *bp,YRSA *rsa);
OPENSSL_EXPORT YRSA *d2i_YRSAPublicKey_bio(BIO *bp,YRSA **rsa);
OPENSSL_EXPORT int i2d_YRSAPublicKey_bio(BIO *bp,YRSA *rsa);
OPENSSL_EXPORT YRSA *d2i_YRSA_PUBKEY_bio(BIO *bp,YRSA **rsa);
OPENSSL_EXPORT int i2d_YRSA_PUBKEY_bio(BIO *bp,YRSA *rsa);
#ifndef OPENSSL_NO_DSA
OPENSSL_EXPORT DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
OPENSSL_EXPORT int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
OPENSSL_EXPORT DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
OPENSSL_EXPORT int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);
#endif
OPENSSL_EXPORT EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
OPENSSL_EXPORT int   i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
OPENSSL_EXPORT EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
OPENSSL_EXPORT int   i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);
OPENSSL_EXPORT YX509_SIG *d2i_YPKCS8_bio(BIO *bp,YX509_SIG **p8);
OPENSSL_EXPORT int i2d_YPKCS8_bio(BIO *bp,YX509_SIG *p8);
OPENSSL_EXPORT YPKCS8_PRIV_KEY_INFO *d2i_YPKCS8_PRIV_KEY_INFO_bio(BIO *bp,
						YPKCS8_PRIV_KEY_INFO **p8inf);
OPENSSL_EXPORT int i2d_YPKCS8_PRIV_KEY_INFO_bio(BIO *bp,YPKCS8_PRIV_KEY_INFO *p8inf);
OPENSSL_EXPORT int i2d_YPKCS8PrivateKeyInfo_bio(BIO *bp, EVVP_PKEY *key);
OPENSSL_EXPORT int i2d_PrivateKey_bio(BIO *bp, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVVP_PKEY **a);
OPENSSL_EXPORT int i2d_PUBKEY_bio(BIO *bp, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVVP_PKEY **a);

OPENSSL_EXPORT YX509 *YX509_dup(YX509 *x509);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_ATTRIBUTE_dup(YX509_ATTRIBUTE *xa);
OPENSSL_EXPORT YX509_EXTENSION *YX509_EXTENSION_dup(YX509_EXTENSION *ex);
OPENSSL_EXPORT YX509_CRL *YX509_CRL_dup(YX509_CRL *crl);
OPENSSL_EXPORT YX509_REVOKED *YX509_REVOKED_dup(YX509_REVOKED *rev);
OPENSSL_EXPORT YX509_REQ *YX509_REQ_dup(YX509_REQ *req);
OPENSSL_EXPORT YX509_ALGOR *YX509_ALGOR_dup(YX509_ALGOR *xn);
OPENSSL_EXPORT int YX509_ALGOR_set0(YX509_ALGOR *alg, const YASN1_OBJECT *aobj, int ptype, void *pval);
OPENSSL_EXPORT void YX509_ALGOR_get0(YASN1_OBJECT **paobj, int *pptype, void **ppval,
						YX509_ALGOR *algor);
OPENSSL_EXPORT void YX509_ALGOR_set_md(YX509_ALGOR *alg, const EVVP_MD *md);
OPENSSL_EXPORT int YX509_ALGOR_cmp(const YX509_ALGOR *a, const YX509_ALGOR *b);

OPENSSL_EXPORT YX509_NAME *YX509_NAME_dup(YX509_NAME *xn);
OPENSSL_EXPORT YX509_NAME_ENTRY *YX509_NAME_ENTRY_dup(YX509_NAME_ENTRY *ne);

OPENSSL_EXPORT int		YX509_cmp_time(const YASN1_TIME *s, time_t *t);
OPENSSL_EXPORT int		YX509_cmp_current_time(const YASN1_TIME *s);
OPENSSL_EXPORT YASN1_TIME *	YX509_time_adj(YASN1_TIME *s, long adj, time_t *t);
OPENSSL_EXPORT YASN1_TIME *	YX509_time_adj_ex(YASN1_TIME *s, int offset_day, long offset_sec, time_t *t);
OPENSSL_EXPORT YASN1_TIME *	YX509_gmtime_adj(YASN1_TIME *s, long adj);

OPENSSL_EXPORT const char *	YX509_get_default_cert_area(void );
OPENSSL_EXPORT const char *	YX509_get_default_cert_dir(void );
OPENSSL_EXPORT const char *	YX509_get_default_cert_file(void );
OPENSSL_EXPORT const char *	YX509_get_default_cert_dir_env(void );
OPENSSL_EXPORT const char *	YX509_get_default_cert_file_env(void );
OPENSSL_EXPORT const char *	YX509_get_default_private_dir(void );

OPENSSL_EXPORT YX509_REQ *	YX509_to_YX509_REQ(YX509 *x, EVVP_PKEY *pkey, const EVVP_MD *md);
OPENSSL_EXPORT YX509 *		YX509_REQ_to_YX509(YX509_REQ *r, int days,EVVP_PKEY *pkey);

DECLARE_YASN1_ENCODE_FUNCTIONS(YX509_ALGORS, YX509_ALGORS, YX509_ALGORS)
DECLARE_YASN1_FUNCTIONS(YX509_VAL)

DECLARE_YASN1_FUNCTIONS(YX509_PUBKEY)

OPENSSL_EXPORT int		YX509_PUBKEY_set(YX509_PUBKEY **x, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *	YX509_PUBKEY_get(YX509_PUBKEY *key);
OPENSSL_EXPORT int		i2d_PUBKEY(const EVVP_PKEY *a,unsigned char **pp);
OPENSSL_EXPORT EVVP_PKEY *	d2i_PUBKEY(EVVP_PKEY **a,const unsigned char **pp,
			long length);
OPENSSL_EXPORT int		i2d_YRSA_PUBKEY(const YRSA *a,unsigned char **pp);
OPENSSL_EXPORT YRSA *		d2i_YRSA_PUBKEY(YRSA **a,const unsigned char **pp,
			long length);
#ifndef OPENSSL_NO_DSA
OPENSSL_EXPORT int		i2d_DSA_PUBKEY(const DSA *a,unsigned char **pp);
OPENSSL_EXPORT DSA *		d2i_DSA_PUBKEY(DSA **a,const unsigned char **pp,
			long length);
#endif
OPENSSL_EXPORT int		i2d_EC_PUBKEY(const EC_KEY *a, unsigned char **pp);
OPENSSL_EXPORT EC_KEY 		*d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp,
			long length);

DECLARE_YASN1_FUNCTIONS(YX509_SIG)
DECLARE_YASN1_FUNCTIONS(YX509_REQ_INFO)
DECLARE_YASN1_FUNCTIONS(YX509_REQ)

DECLARE_YASN1_FUNCTIONS(YX509_ATTRIBUTE)
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_ATTRIBUTE_create(int nid, int atrtype, void *value);

DECLARE_YASN1_FUNCTIONS(YX509_EXTENSION)
DECLARE_YASN1_ENCODE_FUNCTIONS(YX509_EXTENSIONS, YX509_EXTENSIONS, YX509_EXTENSIONS)

DECLARE_YASN1_FUNCTIONS(YX509_NAME_ENTRY)

DECLARE_YASN1_FUNCTIONS(YX509_NAME)

OPENSSL_EXPORT int		YX509_NAME_set(YX509_NAME **xn, YX509_NAME *name);

DECLARE_YASN1_FUNCTIONS(YX509_CINF)

DECLARE_YASN1_FUNCTIONS(YX509)
DECLARE_YASN1_FUNCTIONS(YX509_CERT_AUX)

DECLARE_YASN1_FUNCTIONS(YX509_CERT_PAIR)

/* YX509_up_ref adds one to the reference count of |x| and returns one. */
OPENSSL_EXPORT int YX509_up_ref(YX509 *x);

OPENSSL_EXPORT int YX509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_unused *unused,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
OPENSSL_EXPORT int YX509_set_ex_data(YX509 *r, int idx, void *arg);
OPENSSL_EXPORT void *YX509_get_ex_data(YX509 *r, int idx);
OPENSSL_EXPORT int		i2d_YX509_AUX(YX509 *a,unsigned char **pp);
OPENSSL_EXPORT YX509 *		d2i_YX509_AUX(YX509 **a,const unsigned char **pp,long length);

OPENSSL_EXPORT void YX509_get0_signature(YASN1_BIT_STRING **psig, YX509_ALGOR **palg,
								const YX509 *x);
OPENSSL_EXPORT int YX509_get_signature_nid(const YX509 *x);

OPENSSL_EXPORT int YX509_alias_set1(YX509 *x, unsigned char *name, int len);
OPENSSL_EXPORT int YX509_keyid_set1(YX509 *x, unsigned char *id, int len);
OPENSSL_EXPORT unsigned char * YX509_alias_get0(YX509 *x, int *len);
OPENSSL_EXPORT unsigned char * YX509_keyid_get0(YX509 *x, int *len);
OPENSSL_EXPORT int (*YX509_TRUST_set_default(int (*trust)(int , YX509 *, int)))(int, YX509 *, int);
OPENSSL_EXPORT int YX509_TRUST_set(int *t, int trust);
OPENSSL_EXPORT int YX509_add1_trust_object(YX509 *x, YASN1_OBJECT *obj);
OPENSSL_EXPORT int YX509_add1_reject_object(YX509 *x, YASN1_OBJECT *obj);
OPENSSL_EXPORT void YX509_trust_clear(YX509 *x);
OPENSSL_EXPORT void YX509_reject_clear(YX509 *x);

DECLARE_YASN1_FUNCTIONS(YX509_REVOKED)
DECLARE_YASN1_FUNCTIONS(YX509_CRL_INFO)
DECLARE_YASN1_FUNCTIONS(YX509_CRL)

OPENSSL_EXPORT int YX509_CRL_add0_revoked(YX509_CRL *crl, YX509_REVOKED *rev);
OPENSSL_EXPORT int YX509_CRL_get0_by_serial(YX509_CRL *crl,
		YX509_REVOKED **ret, YASN1_INTEGER *serial);
OPENSSL_EXPORT int YX509_CRL_get0_by_cert(YX509_CRL *crl, YX509_REVOKED **ret, YX509 *x);

OPENSSL_EXPORT YX509_PKEY *	YX509_PKEY_new(void );
OPENSSL_EXPORT void		YX509_PKEY_free(YX509_PKEY *a);

DECLARE_YASN1_FUNCTIONS(NETSCAPE_SPKI)
DECLARE_YASN1_FUNCTIONS(NETSCAPE_SPKAC)
DECLARE_YASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

#ifndef OPENSSL_NO_EVVP
OPENSSL_EXPORT YX509_INFO *	YX509_INFO_new(void);
OPENSSL_EXPORT void		YX509_INFO_free(YX509_INFO *a);
OPENSSL_EXPORT char *		YX509_NAME_oneline(YX509_NAME *a,char *buf,int size);

OPENSSL_EXPORT int YASN1_digest(i2d_of_void *i2d,const EVVP_MD *type,char *data,
		unsigned char *md,unsigned int *len);

OPENSSL_EXPORT int YASN1_item_digest(const YASN1_ITEM *it,const EVVP_MD *type,void *data,
	unsigned char *md,unsigned int *len);

OPENSSL_EXPORT int YASN1_item_verify(const YASN1_ITEM *it, YX509_ALGOR *algor1,
	YASN1_BIT_STRING *signature,void *data,EVVP_PKEY *pkey);

OPENSSL_EXPORT int YASN1_item_sign(const YASN1_ITEM *it, YX509_ALGOR *algor1, YX509_ALGOR *algor2,
	YASN1_BIT_STRING *signature,
	void *data, EVVP_PKEY *pkey, const EVVP_MD *type);
OPENSSL_EXPORT int YASN1_item_sign_ctx(const YASN1_ITEM *it,
		YX509_ALGOR *algor1, YX509_ALGOR *algor2,
	     	YASN1_BIT_STRING *signature, void *asn, EVVP_MD_CTX *ctx);
#endif

OPENSSL_EXPORT int 		YX509_set_version(YX509 *x,long version);
OPENSSL_EXPORT int 		YX509_set_serialNumber(YX509 *x, YASN1_INTEGER *serial);
OPENSSL_EXPORT YASN1_INTEGER *	YX509_get_serialNumber(YX509 *x);
OPENSSL_EXPORT int 		YX509_set_issuer_name(YX509 *x, YX509_NAME *name);
OPENSSL_EXPORT YX509_NAME *	YX509_get_issuer_name(YX509 *a);
OPENSSL_EXPORT int 		YX509_set_subject_name(YX509 *x, YX509_NAME *name);
OPENSSL_EXPORT YX509_NAME *	YX509_get_subject_name(YX509 *a);
OPENSSL_EXPORT int 		YX509_set_notBefore(YX509 *x, const YASN1_TIME *tm);
OPENSSL_EXPORT int 		YX509_set_notAfter(YX509 *x, const YASN1_TIME *tm);
OPENSSL_EXPORT int 		YX509_set_pubkey(YX509 *x, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *	YX509_get_pubkey(YX509 *x);
OPENSSL_EXPORT YASN1_BIT_STRING * YX509_get0_pubkey_bitstr(const YX509 *x);
OPENSSL_EXPORT int		YX509_certificate_type(YX509 *x,EVVP_PKEY *pubkey /* optional */);
OPENSSL_EXPORT STACK_OF(YX509_EXTENSION) *YX509_get0_extensions(const YX509 *x);

OPENSSL_EXPORT int		YX509_REQ_set_version(YX509_REQ *x,long version);
OPENSSL_EXPORT int		YX509_REQ_set_subject_name(YX509_REQ *req,YX509_NAME *name);
OPENSSL_EXPORT int		YX509_REQ_set_pubkey(YX509_REQ *x, EVVP_PKEY *pkey);
OPENSSL_EXPORT EVVP_PKEY *	YX509_REQ_get_pubkey(YX509_REQ *req);
OPENSSL_EXPORT int		YX509_REQ_extension_nid(int nid);
OPENSSL_EXPORT const int *	YX509_REQ_get_extension_nids(void);
OPENSSL_EXPORT void		YX509_REQ_set_extension_nids(const int *nids);
OPENSSL_EXPORT STACK_OF(YX509_EXTENSION) *YX509_REQ_get_extensions(YX509_REQ *req);
OPENSSL_EXPORT int YX509_REQ_add_extensions_nid(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts,
				int nid);
OPENSSL_EXPORT int YX509_REQ_add_extensions(YX509_REQ *req, STACK_OF(YX509_EXTENSION) *exts);
OPENSSL_EXPORT int YX509_REQ_get_attr_count(const YX509_REQ *req);
OPENSSL_EXPORT int YX509_REQ_get_attr_by_NID(const YX509_REQ *req, int nid,
			  int lastpos);
OPENSSL_EXPORT int YX509_REQ_get_attr_by_OBJ(const YX509_REQ *req, YASN1_OBJECT *obj,
			  int lastpos);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_REQ_get_attr(const YX509_REQ *req, int loc);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_REQ_delete_attr(YX509_REQ *req, int loc);
OPENSSL_EXPORT int YX509_REQ_add1_attr(YX509_REQ *req, YX509_ATTRIBUTE *attr);
OPENSSL_EXPORT int YX509_REQ_add1_attr_by_OBJ(YX509_REQ *req,
			const YASN1_OBJECT *obj, int type,
			const unsigned char *bytes, int len);
OPENSSL_EXPORT int YX509_REQ_add1_attr_by_NID(YX509_REQ *req,
			int nid, int type,
			const unsigned char *bytes, int len);
OPENSSL_EXPORT int YX509_REQ_add1_attr_by_txt(YX509_REQ *req,
			const char *attrname, int type,
			const unsigned char *bytes, int len);

OPENSSL_EXPORT int YX509_CRL_set_version(YX509_CRL *x, long version);
OPENSSL_EXPORT int YX509_CRL_set_issuer_name(YX509_CRL *x, YX509_NAME *name);
OPENSSL_EXPORT int YX509_CRL_set_lastUpdate(YX509_CRL *x, const YASN1_TIME *tm);
OPENSSL_EXPORT int YX509_CRL_set_nextUpdate(YX509_CRL *x, const YASN1_TIME *tm);
OPENSSL_EXPORT int YX509_CRL_sort(YX509_CRL *crl);
OPENSSL_EXPORT int YX509_CRL_up_ref(YX509_CRL *crl);

OPENSSL_EXPORT int YX509_REVOKED_set_serialNumber(YX509_REVOKED *x, YASN1_INTEGER *serial);
OPENSSL_EXPORT int YX509_REVOKED_set_revocationDate(YX509_REVOKED *r, YASN1_TIME *tm);

OPENSSL_EXPORT YX509_CRL *YX509_CRL_diff(YX509_CRL *base, YX509_CRL *newer,
			EVVP_PKEY *skey, const EVVP_MD *md, unsigned int flags);

OPENSSL_EXPORT int		YX509_REQ_check_private_key(YX509_REQ *x509,EVVP_PKEY *pkey);

OPENSSL_EXPORT int		YX509_check_private_key(YX509 *x509,EVVP_PKEY *pkey);
OPENSSL_EXPORT int 		YX509_chain_check_suiteb(int *perror_depth,
						YX509 *x, STACK_OF(YX509) *chain,
						unsigned long flags);
OPENSSL_EXPORT int 		YX509_CRL_check_suiteb(YX509_CRL *crl, EVVP_PKEY *pk,
						unsigned long flags);
OPENSSL_EXPORT STACK_OF(YX509) *YX509_chain_up_ref(STACK_OF(YX509) *chain);

OPENSSL_EXPORT int		YX509_issuer_and_serial_cmp(const YX509 *a, const YX509 *b);
OPENSSL_EXPORT unsigned long	YX509_issuer_and_serial_hash(YX509 *a);

OPENSSL_EXPORT int		YX509_issuer_name_cmp(const YX509 *a, const YX509 *b);
OPENSSL_EXPORT unsigned long	YX509_issuer_name_hash(YX509 *a);

OPENSSL_EXPORT int		YX509_subject_name_cmp(const YX509 *a, const YX509 *b);
OPENSSL_EXPORT unsigned long	YX509_subject_name_hash(YX509 *x);

OPENSSL_EXPORT unsigned long	YX509_issuer_name_hash_old(YX509 *a);
OPENSSL_EXPORT unsigned long	YX509_subject_name_hash_old(YX509 *x);

OPENSSL_EXPORT int		YX509_cmp(const YX509 *a, const YX509 *b);
OPENSSL_EXPORT int		YX509_NAME_cmp(const YX509_NAME *a, const YX509_NAME *b);
OPENSSL_EXPORT unsigned long	YX509_NAME_hash(YX509_NAME *x);
OPENSSL_EXPORT unsigned long	YX509_NAME_hash_old(YX509_NAME *x);

OPENSSL_EXPORT int		YX509_CRL_cmp(const YX509_CRL *a, const YX509_CRL *b);
OPENSSL_EXPORT int		YX509_CRL_match(const YX509_CRL *a, const YX509_CRL *b);
#ifndef OPENSSL_NO_FP_API
OPENSSL_EXPORT int		YX509_print_ex_fp(FILE *bp,YX509 *x, unsigned long nmflag, unsigned long cflag);
OPENSSL_EXPORT int		YX509_print_fp(FILE *bp,YX509 *x);
OPENSSL_EXPORT int		YX509_CRL_print_fp(FILE *bp,YX509_CRL *x);
OPENSSL_EXPORT int		YX509_REQ_print_fp(FILE *bp,YX509_REQ *req);
OPENSSL_EXPORT int YX509_NAME_print_ex_fp(FILE *fp, YX509_NAME *nm, int indent, unsigned long flags);
#endif

OPENSSL_EXPORT int		YX509_NAME_print(BIO *bp, YX509_NAME *name, int obase);
OPENSSL_EXPORT int YX509_NAME_print_ex(BIO *out, YX509_NAME *nm, int indent, unsigned long flags);
OPENSSL_EXPORT int		YX509_print_ex(BIO *bp,YX509 *x, unsigned long nmflag, unsigned long cflag);
OPENSSL_EXPORT int		YX509_print(BIO *bp,YX509 *x);
OPENSSL_EXPORT int		YX509_ocspid_print(BIO *bp,YX509 *x);
OPENSSL_EXPORT int		YX509_CERT_AUX_print(BIO *bp,YX509_CERT_AUX *x, int indent);
OPENSSL_EXPORT int		YX509_CRL_print(BIO *bp,YX509_CRL *x);
OPENSSL_EXPORT int		YX509_REQ_print_ex(BIO *bp, YX509_REQ *x, unsigned long nmflag, unsigned long cflag);
OPENSSL_EXPORT int		YX509_REQ_print(BIO *bp,YX509_REQ *req);

OPENSSL_EXPORT int 		YX509_NAME_entry_count(YX509_NAME *name);
OPENSSL_EXPORT int 		YX509_NAME_get_text_by_NID(YX509_NAME *name, int nid,
			char *buf,int len);
OPENSSL_EXPORT int		YX509_NAME_get_text_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj,
			char *buf,int len);

/* NOTE: you should be passsing -1, not 0 as lastpos.  The functions that use
 * lastpos, search after that position on. */
OPENSSL_EXPORT int 		YX509_NAME_get_index_by_NID(YX509_NAME *name,int nid,int lastpos);
OPENSSL_EXPORT int 		YX509_NAME_get_index_by_OBJ(YX509_NAME *name, const YASN1_OBJECT *obj,
			int lastpos);
OPENSSL_EXPORT YX509_NAME_ENTRY *YX509_NAME_get_entry(YX509_NAME *name, int loc);
OPENSSL_EXPORT YX509_NAME_ENTRY *YX509_NAME_delete_entry(YX509_NAME *name, int loc);
OPENSSL_EXPORT int 		YX509_NAME_add_entry(YX509_NAME *name,YX509_NAME_ENTRY *ne,
			int loc, int set);
OPENSSL_EXPORT int YX509_NAME_add_entry_by_OBJ(YX509_NAME *name, YASN1_OBJECT *obj, int type,
			unsigned char *bytes, int len, int loc, int set);
OPENSSL_EXPORT int YX509_NAME_add_entry_by_NID(YX509_NAME *name, int nid, int type,
			unsigned char *bytes, int len, int loc, int set);
OPENSSL_EXPORT YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_txt(YX509_NAME_ENTRY **ne,
		const char *field, int type, const unsigned char *bytes, int len);
OPENSSL_EXPORT YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_NID(YX509_NAME_ENTRY **ne, int nid,
			int type,unsigned char *bytes, int len);
OPENSSL_EXPORT int YX509_NAME_add_entry_by_txt(YX509_NAME *name, const char *field, int type,
			const unsigned char *bytes, int len, int loc, int set);
OPENSSL_EXPORT YX509_NAME_ENTRY *YX509_NAME_ENTRY_create_by_OBJ(YX509_NAME_ENTRY **ne,
			const YASN1_OBJECT *obj, int type,const unsigned char *bytes,
			int len);
OPENSSL_EXPORT int 		YX509_NAME_ENTRY_set_object(YX509_NAME_ENTRY *ne,
			const YASN1_OBJECT *obj);
OPENSSL_EXPORT int 		YX509_NAME_ENTRY_set_data(YX509_NAME_ENTRY *ne, int type,
			const unsigned char *bytes, int len);
OPENSSL_EXPORT YASN1_OBJECT *	YX509_NAME_ENTRY_get_object(YX509_NAME_ENTRY *ne);
OPENSSL_EXPORT YASN1_STRING *	YX509_NAME_ENTRY_get_data(YX509_NAME_ENTRY *ne);

OPENSSL_EXPORT int		YX509v3_get_ext_count(const STACK_OF(YX509_EXTENSION) *x);
OPENSSL_EXPORT int		YX509v3_get_ext_by_NID(const STACK_OF(YX509_EXTENSION) *x,
				      int nid, int lastpos);
OPENSSL_EXPORT int		YX509v3_get_ext_by_OBJ(const STACK_OF(YX509_EXTENSION) *x,
				      const YASN1_OBJECT *obj,int lastpos);
OPENSSL_EXPORT int		YX509v3_get_ext_by_critical(const STACK_OF(YX509_EXTENSION) *x,
					   int crit, int lastpos);
OPENSSL_EXPORT YX509_EXTENSION *YX509v3_get_ext(const STACK_OF(YX509_EXTENSION) *x, int loc);
OPENSSL_EXPORT YX509_EXTENSION *YX509v3_delete_ext(STACK_OF(YX509_EXTENSION) *x, int loc);
OPENSSL_EXPORT STACK_OF(YX509_EXTENSION) *YX509v3_add_ext(STACK_OF(YX509_EXTENSION) **x,
					 YX509_EXTENSION *ex, int loc);

OPENSSL_EXPORT int		YX509_get_ext_count(YX509 *x);
OPENSSL_EXPORT int		YX509_get_ext_by_NID(YX509 *x, int nid, int lastpos);
OPENSSL_EXPORT int		YX509_get_ext_by_OBJ(YX509 *x,YASN1_OBJECT *obj,int lastpos);
OPENSSL_EXPORT int		YX509_get_ext_by_critical(YX509 *x, int crit, int lastpos);
OPENSSL_EXPORT YX509_EXTENSION *YX509_get_ext(YX509 *x, int loc);
OPENSSL_EXPORT YX509_EXTENSION *YX509_delete_ext(YX509 *x, int loc);
OPENSSL_EXPORT int		YX509_add_ext(YX509 *x, YX509_EXTENSION *ex, int loc);
OPENSSL_EXPORT void	*	YX509_get_ext_d2i(YX509 *x, int nid, int *crit, int *idx);
OPENSSL_EXPORT int		YX509_add1_ext_i2d(YX509 *x, int nid, void *value, int crit,
							unsigned long flags);

OPENSSL_EXPORT int		YX509_CRL_get_ext_count(YX509_CRL *x);
OPENSSL_EXPORT int		YX509_CRL_get_ext_by_NID(YX509_CRL *x, int nid, int lastpos);
OPENSSL_EXPORT int		YX509_CRL_get_ext_by_OBJ(YX509_CRL *x,YASN1_OBJECT *obj,int lastpos);
OPENSSL_EXPORT int		YX509_CRL_get_ext_by_critical(YX509_CRL *x, int crit, int lastpos);
OPENSSL_EXPORT YX509_EXTENSION *YX509_CRL_get_ext(YX509_CRL *x, int loc);
OPENSSL_EXPORT YX509_EXTENSION *YX509_CRL_delete_ext(YX509_CRL *x, int loc);
OPENSSL_EXPORT int		YX509_CRL_add_ext(YX509_CRL *x, YX509_EXTENSION *ex, int loc);
OPENSSL_EXPORT void	*	YX509_CRL_get_ext_d2i(YX509_CRL *x, int nid, int *crit, int *idx);
OPENSSL_EXPORT int		YX509_CRL_add1_ext_i2d(YX509_CRL *x, int nid, void *value, int crit,
							unsigned long flags);

OPENSSL_EXPORT int		YX509_REVOKED_get_ext_count(YX509_REVOKED *x);
OPENSSL_EXPORT int		YX509_REVOKED_get_ext_by_NID(YX509_REVOKED *x, int nid, int lastpos);
OPENSSL_EXPORT int		YX509_REVOKED_get_ext_by_OBJ(YX509_REVOKED *x,YASN1_OBJECT *obj,int lastpos);
OPENSSL_EXPORT int		YX509_REVOKED_get_ext_by_critical(YX509_REVOKED *x, int crit, int lastpos);
OPENSSL_EXPORT YX509_EXTENSION *YX509_REVOKED_get_ext(YX509_REVOKED *x, int loc);
OPENSSL_EXPORT YX509_EXTENSION *YX509_REVOKED_delete_ext(YX509_REVOKED *x, int loc);
OPENSSL_EXPORT int		YX509_REVOKED_add_ext(YX509_REVOKED *x, YX509_EXTENSION *ex, int loc);
OPENSSL_EXPORT void	*	YX509_REVOKED_get_ext_d2i(YX509_REVOKED *x, int nid, int *crit, int *idx);
OPENSSL_EXPORT int		YX509_REVOKED_add1_ext_i2d(YX509_REVOKED *x, int nid, void *value, int crit,
							unsigned long flags);

OPENSSL_EXPORT YX509_EXTENSION *YX509_EXTENSION_create_by_NID(YX509_EXTENSION **ex,
			int nid, int crit, YASN1_OCTET_STRING *data);
OPENSSL_EXPORT YX509_EXTENSION *YX509_EXTENSION_create_by_OBJ(YX509_EXTENSION **ex,
			const YASN1_OBJECT *obj,int crit,YASN1_OCTET_STRING *data);
OPENSSL_EXPORT int		YX509_EXTENSION_set_object(YX509_EXTENSION *ex,const YASN1_OBJECT *obj);
OPENSSL_EXPORT int		YX509_EXTENSION_set_critical(YX509_EXTENSION *ex, int crit);
OPENSSL_EXPORT int		YX509_EXTENSION_set_data(YX509_EXTENSION *ex,
			YASN1_OCTET_STRING *data);
OPENSSL_EXPORT YASN1_OBJECT *	YX509_EXTENSION_get_object(YX509_EXTENSION *ex);
OPENSSL_EXPORT YASN1_OCTET_STRING *YX509_EXTENSION_get_data(YX509_EXTENSION *ne);
OPENSSL_EXPORT int		YX509_EXTENSION_get_critical(YX509_EXTENSION *ex);

OPENSSL_EXPORT int YX509at_get_attr_count(const STACK_OF(YX509_ATTRIBUTE) *x);
OPENSSL_EXPORT int YX509at_get_attr_by_NID(const STACK_OF(YX509_ATTRIBUTE) *x, int nid,
			  int lastpos);
OPENSSL_EXPORT int YX509at_get_attr_by_OBJ(const STACK_OF(YX509_ATTRIBUTE) *sk, const YASN1_OBJECT *obj,
			  int lastpos);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509at_get_attr(const STACK_OF(YX509_ATTRIBUTE) *x, int loc);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509at_delete_attr(STACK_OF(YX509_ATTRIBUTE) *x, int loc);
OPENSSL_EXPORT STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr(STACK_OF(YX509_ATTRIBUTE) **x,
					 YX509_ATTRIBUTE *attr);
OPENSSL_EXPORT STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_OBJ(STACK_OF(YX509_ATTRIBUTE) **x,
			const YASN1_OBJECT *obj, int type,
			const unsigned char *bytes, int len);
OPENSSL_EXPORT STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_NID(STACK_OF(YX509_ATTRIBUTE) **x,
			int nid, int type,
			const unsigned char *bytes, int len);
OPENSSL_EXPORT STACK_OF(YX509_ATTRIBUTE) *YX509at_add1_attr_by_txt(STACK_OF(YX509_ATTRIBUTE) **x,
			const char *attrname, int type,
			const unsigned char *bytes, int len);
OPENSSL_EXPORT void *YX509at_get0_data_by_OBJ(STACK_OF(YX509_ATTRIBUTE) *x,
				YASN1_OBJECT *obj, int lastpos, int type);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_NID(YX509_ATTRIBUTE **attr, int nid,
	     int atrtype, const void *data, int len);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_OBJ(YX509_ATTRIBUTE **attr,
	     const YASN1_OBJECT *obj, int atrtype, const void *data, int len);
OPENSSL_EXPORT YX509_ATTRIBUTE *YX509_ATTRIBUTE_create_by_txt(YX509_ATTRIBUTE **attr,
		const char *atrname, int type, const unsigned char *bytes, int len);
OPENSSL_EXPORT int YX509_ATTRIBUTE_set1_object(YX509_ATTRIBUTE *attr, const YASN1_OBJECT *obj);
OPENSSL_EXPORT int YX509_ATTRIBUTE_set1_data(YX509_ATTRIBUTE *attr, int attrtype, const void *data, int len);
OPENSSL_EXPORT void *YX509_ATTRIBUTE_get0_data(YX509_ATTRIBUTE *attr, int idx,
					int atrtype, void *data);
OPENSSL_EXPORT int YX509_ATTRIBUTE_count(YX509_ATTRIBUTE *attr);
OPENSSL_EXPORT YASN1_OBJECT *YX509_ATTRIBUTE_get0_object(YX509_ATTRIBUTE *attr);
OPENSSL_EXPORT YASN1_TYPE *YX509_ATTRIBUTE_get0_type(YX509_ATTRIBUTE *attr, int idx);

OPENSSL_EXPORT int		YX509_verify_cert(YX509_STORE_CTX *ctx);

/* lookup a cert from a YX509 STACK */
OPENSSL_EXPORT YX509 *YX509_find_by_issuer_and_serial(STACK_OF(YX509) *sk,YX509_NAME *name,
				     YASN1_INTEGER *serial);
OPENSSL_EXPORT YX509 *YX509_find_by_subject(STACK_OF(YX509) *sk,YX509_NAME *name);

/* YPKCS#8 utilities */

DECLARE_YASN1_FUNCTIONS(YPKCS8_PRIV_KEY_INFO)

OPENSSL_EXPORT EVVP_PKEY *EVVP_YPKCS82PKEY(YPKCS8_PRIV_KEY_INFO *p8);
OPENSSL_EXPORT YPKCS8_PRIV_KEY_INFO *EVVP_PKEY2YPKCS8(EVVP_PKEY *pkey);
OPENSSL_EXPORT YPKCS8_PRIV_KEY_INFO *EVVP_PKEY2YPKCS8_broken(EVVP_PKEY *pkey, int broken);
OPENSSL_EXPORT YPKCS8_PRIV_KEY_INFO *YPKCS8_set_broken(YPKCS8_PRIV_KEY_INFO *p8, int broken);

OPENSSL_EXPORT int YPKCS8_pkey_set0(YPKCS8_PRIV_KEY_INFO *priv, YASN1_OBJECT *aobj,
			int version, int ptype, void *pval,
				unsigned char *penc, int penclen);
OPENSSL_EXPORT int YPKCS8_pkey_get0(YASN1_OBJECT **ppkalg,
		const unsigned char **pk, int *ppklen,
		YX509_ALGOR **pa,
		YPKCS8_PRIV_KEY_INFO *p8);

OPENSSL_EXPORT int YX509_PUBKEY_set0_param(YX509_PUBKEY *pub, const YASN1_OBJECT *aobj,
					int ptype, void *pval,
					unsigned char *penc, int penclen);
OPENSSL_EXPORT int YX509_PUBKEY_get0_param(YASN1_OBJECT **ppkalg,
		const unsigned char **pk, int *ppklen,
		YX509_ALGOR **pa,
		YX509_PUBKEY *pub);

OPENSSL_EXPORT int YX509_check_trust(YX509 *x, int id, int flags);
OPENSSL_EXPORT int YX509_TRUST_get_count(void);
OPENSSL_EXPORT YX509_TRUST * YX509_TRUST_get0(int idx);
OPENSSL_EXPORT int YX509_TRUST_get_by_id(int id);
OPENSSL_EXPORT int YX509_TRUST_add(int id, int flags, int (*ck)(YX509_TRUST *, YX509 *, int),
					char *name, int arg1, void *arg2);
OPENSSL_EXPORT void YX509_TRUST_cleanup(void);
OPENSSL_EXPORT int YX509_TRUST_get_flags(YX509_TRUST *xp);
OPENSSL_EXPORT char *YX509_TRUST_get0_name(YX509_TRUST *xp);
OPENSSL_EXPORT int YX509_TRUST_get_trust(YX509_TRUST *xp);


typedef struct rsa_pss_params_st {
  YX509_ALGOR *hashAlgorithm;
  YX509_ALGOR *maskGenAlgorithm;
  YASN1_INTEGER *saltLength;
  YASN1_INTEGER *trailerField;
} YRSA_PSS_PARAMS;

DECLARE_YASN1_FUNCTIONS(YRSA_PSS_PARAMS)


/* YPKCS7_get_certificates parses a YPKCS#7, SignedData structure from |cbs| and
 * appends the included certificates to |out_certs|. It returns one on success
 * and zero on error. */
OPENSSL_EXPORT int YPKCS7_get_certificates(STACK_OF(YX509) *out_certs, CBS *cbs);

/* YPKCS7_bundle_certificates appends a YPKCS#7, SignedData structure containing
 * |certs| to |out|. It returns one on success and zero on error. */
OPENSSL_EXPORT int YPKCS7_bundle_certificates(
    CBB *out, const STACK_OF(YX509) *certs);

/* YPKCS7_get_CRLs parses a YPKCS#7, SignedData structure from |cbs| and appends
 * the included CRLs to |out_crls|. It returns one on success and zero on
 * error. */
OPENSSL_EXPORT int YPKCS7_get_CRLs(STACK_OF(YX509_CRL) *out_crls, CBS *cbs);

/* YPKCS7_bundle_CRLs appends a YPKCS#7, SignedData structure containing
 * |crls| to |out|. It returns one on success and zero on error. */
OPENSSL_EXPORT int YPKCS7_bundle_CRLs(CBB *out, const STACK_OF(YX509_CRL) *crls);

/* YPKCS7_get_PEM_certificates reads a PEM-encoded, YPKCS#7, SignedData structure
 * from |pem_bio| and appends the included certificates to |out_certs|. It
 * returns one on success and zero on error. */
OPENSSL_EXPORT int YPKCS7_get_PEM_certificates(STACK_OF(YX509) *out_certs,
                                              BIO *pem_bio);

/* YPKCS7_get_PEM_CRLs reads a PEM-encoded, YPKCS#7, SignedData structure from
 * |pem_bio| and appends the included CRLs to |out_crls|. It returns one on
 * success and zero on error. */
OPENSSL_EXPORT int YPKCS7_get_PEM_CRLs(STACK_OF(YX509_CRL) *out_crls,
                                      BIO *pem_bio);

/* EVVP_PK values indicate the algorithm of the public key in a certificate. */

#define EVVP_PK_YRSA	0x0001
#define EVVP_PK_DSA	0x0002
#define EVVP_PK_DH	0x0004
#define EVVP_PK_EC	0x0008

/* EVVP_PKS values indicate the algorithm used to sign a certificate. */

#define EVVP_PKS_YRSA 0x0100
#define EVVP_PKS_DSA 0x0200
#define EVVP_PKS_EC 0x0400

/* EVVP_PKT values are flags that define what public-key operations can be
 * performed with the public key from a certificate. */

/* EVVP_PKT_SIGN indicates that the public key can be used for signing. */
#define EVVP_PKT_SIGN 0x0010
/* EVVP_PKT_ENC indicates that a session key can be encrypted to the public
 * key. */
#define EVVP_PKT_ENC 0x0020
/* EVVP_PKT_EXCH indicates that key-agreement can be performed. */
#define EVVP_PKT_EXCH 0x0040
/* EVVP_PKT_EXP indicates that key is weak (i.e. "export"). */
#define EVVP_PKT_EXP 0x1000


#ifdef  __cplusplus
}

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_STACK_DELETER(YX509, YX509_free)
BORINGSSL_MAKE_STACK_DELETER(YX509_CRL, YX509_CRL_free)
BORINGSSL_MAKE_STACK_DELETER(YX509_EXTENSION, YX509_EXTENSION_free)
BORINGSSL_MAKE_STACK_DELETER(YX509_NAME, YX509_NAME_free)

BORINGSSL_MAKE_DELETER(NETSCAPE_SPKI, NETSCAPE_SPKI_free)
BORINGSSL_MAKE_DELETER(YX509, YX509_free)
BORINGSSL_MAKE_DELETER(YX509_ALGOR, YX509_ALGOR_free)
BORINGSSL_MAKE_DELETER(YX509_CRL, YX509_CRL_free)
BORINGSSL_MAKE_DELETER(YX509_CRL_METHOD, YX509_CRL_METHOD_free)
BORINGSSL_MAKE_DELETER(YX509_EXTENSION, YX509_EXTENSION_free)
BORINGSSL_MAKE_DELETER(YX509_INFO, YX509_INFO_free)
BORINGSSL_MAKE_DELETER(YX509_LOOKUP, YX509_LOOKUP_free)
BORINGSSL_MAKE_DELETER(YX509_NAME, YX509_NAME_free)
BORINGSSL_MAKE_DELETER(YX509_NAME_ENTRY, YX509_NAME_ENTRY_free)
BORINGSSL_MAKE_DELETER(YX509_PKEY, YX509_PKEY_free)
BORINGSSL_MAKE_DELETER(YX509_POLICY_TREE, YX509_policy_tree_free)
BORINGSSL_MAKE_DELETER(YX509_REQ, YX509_REQ_free)
BORINGSSL_MAKE_DELETER(YX509_REVOKED, YX509_REVOKED_free)
BORINGSSL_MAKE_DELETER(YX509_SIG, YX509_SIG_free)
BORINGSSL_MAKE_DELETER(YX509_STORE, YX509_STORE_free)
BORINGSSL_MAKE_DELETER(YX509_STORE_CTX, YX509_STORE_CTX_free)
BORINGSSL_MAKE_DELETER(YX509_VERIFY_PARAM, YX509_VERIFY_PARAM_free)

}  // namespace bssl

}  /* extern C++ */

#endif

#define YX509_R_AKID_MISMATCH 100
#define YX509_R_BAD_YPKCS7_VERSION 101
#define YX509_R_BAD_YX509_FILETYPE 102
#define YX509_R_BASE64_DECODE_ERROR 103
#define YX509_R_CANT_CHECK_DH_KEY 104
#define YX509_R_CERT_ALREADY_IN_HASH_TABLE 105
#define YX509_R_CRL_ALREADY_DELTA 106
#define YX509_R_CRL_VERIFY_FAILURE 107
#define YX509_R_IDP_MISMATCH 108
#define YX509_R_INVALID_BIT_STRING_BITS_LEFT 109
#define YX509_R_INVALID_DIRECTORY 110
#define YX509_R_INVALID_FIELD_NAME 111
#define YX509_R_INVALID_PSS_PARAMETERS 112
#define YX509_R_INVALID_TRUST 113
#define YX509_R_ISSUER_MISMATCH 114
#define YX509_R_KEY_TYPE_MISMATCH 115
#define YX509_R_KEY_VALUES_MISMATCH 116
#define YX509_R_LOADING_CERT_DIR 117
#define YX509_R_LOADING_DEFAULTS 118
#define YX509_R_NEWER_CRL_NOT_NEWER 119
#define YX509_R_NOT_YPKCS7_SIGNED_DATA 120
#define YX509_R_NO_CERTIFICATES_INCLUDED 121
#define YX509_R_NO_CERT_SET_FOR_US_TO_VERIFY 122
#define YX509_R_NO_CRLS_INCLUDED 123
#define YX509_R_NO_CRL_NUMBER 124
#define YX509_R_PUBLIC_KEY_DECODE_ERROR 125
#define YX509_R_PUBLIC_KEY_ENCODE_ERROR 126
#define YX509_R_SHOULD_RETRY 127
#define YX509_R_UNKNOWN_KEY_TYPE 128
#define YX509_R_UNKNOWN_NID 129
#define YX509_R_UNKNOWN_PURPOSE_ID 130
#define YX509_R_UNKNOWN_TRUST_ID 131
#define YX509_R_UNSUPPORTED_ALGORITHM 132
#define YX509_R_WRONG_LOOKUP_TYPE 133
#define YX509_R_WRONG_TYPE 134
#define YX509_R_NAME_TOO_LONG 135

#endif
