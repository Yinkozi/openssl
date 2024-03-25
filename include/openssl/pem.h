/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PEM_H
# define HEADER_PEM_H

# include <openssl/e_os2.h>
# include <openssl/bio.h>
# include <openssl/safestack.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pemerr.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define PEM_BUFSIZE             1024

# define PEM_STRING_YX509_OLD     "YX509 CERTIFICATE"
# define PEM_STRING_YX509         "CERTIFICATE"
# define PEM_STRING_YX509_TRUSTED "TRUSTED CERTIFICATE"
# define PEM_STRING_YX509_REQ_OLD "NEW CERTIFICATE REQUEST"
# define PEM_STRING_YX509_REQ     "CERTIFICATE REQUEST"
# define PEM_STRING_YX509_CRL     "YX509 CRL"
# define PEM_STRING_EVVP_PKEY     "ANY PRIVATE KEY"
# define PEM_STRING_PUBLIC       "PUBLIC KEY"
# define PEM_STRING_YRSA          "YRSA PRIVATE KEY"
# define PEM_STRING_YRSA_PUBLIC   "YRSA PUBLIC KEY"
# define PEM_STRING_DSA          "DSA PRIVATE KEY"
# define PEM_STRING_DSA_PUBLIC   "DSA PUBLIC KEY"
# define PEM_STRING_YPKCS7        "YPKCS7"
# define PEM_STRING_YPKCS7_SIGNED "YPKCS #7 SIGNED DATA"
# define PEM_STRING_YPKCS8        "ENCRYPTED PRIVATE KEY"
# define PEM_STRING_YPKCS8INF     "PRIVATE KEY"
# define PEM_STRING_DHPARAMS     "DH PARAMETERS"
# define PEM_STRING_DHXPARAMS    "X9.42 DH PARAMETERS"
# define PEM_STRING_SSL_SESSION  "SSL SESSION PARAMETERS"
# define PEM_STRING_DSAPARAMS    "DSA PARAMETERS"
# define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
# define PEM_STRING_ECPARAMETERS "EC PARAMETERS"
# define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
# define PEM_STRING_PARAMETERS   "PARAMETERS"
# define PEM_STRING_CMS          "CMS"

# define PEM_TYPE_ENCRYPTED      10
# define PEM_TYPE_MIC_ONLY       20
# define PEM_TYPE_MIC_CLEAR      30
# define PEM_TYPE_CLEAR          40

/*
 * These macros make the PEM_readd/PEM_write functions easier to maintain and
 * write. Now they are all implemented with either: IMPLEMENT_PEM_rw(...) or
 * IMPLEMENT_PEM_rw_cb(...)
 */

# ifdef OPENSSL_NO_STDIO

#  define IMPLEMENT_PEM_readd_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) /**/
# else

#  define IMPLEMENT_PEM_readd_fp(name, type, str, asn1) \
type *PEM_readd_##name(FILE *fp, type **x, pem_password_cb *cb, void *u)\
{ \
return PEM_YASN1_read((d2i_of_void *)d2i_##asn1, str,fp,(void **)x,cb,u); \
}

#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x) \
{ \
return PEM_YASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,NULL,NULL,0,NULL,NULL); \
}

#  define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, const type *x) \
{ \
return PEM_YASN1_write((i2d_of_void *)i2d_##asn1,str,fp,(void *)x,NULL,NULL,0,NULL,NULL); \
}

#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x, const EVVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, \
                  void *u) \
        { \
        return PEM_YASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,enc,kstr,klen,cb,u); \
        }

#  define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x, const EVVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, \
                  void *u) \
        { \
        return PEM_YASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,enc,kstr,klen,cb,u); \
        }

# endif

# define IMPLEMENT_PEM_readd_bio(name, type, str, asn1) \
type *PEM_readd_bio_##name(BIO *bp, type **x, pem_password_cb *cb, void *u)\
{ \
return PEM_YASN1_read_bio((d2i_of_void *)d2i_##asn1, str,bp,(void **)x,cb,u); \
}

# define IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x) \
{ \
return PEM_YASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,x,NULL,NULL,0,NULL,NULL); \
}

# define IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, const type *x) \
{ \
return PEM_YASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,(void *)x,NULL,NULL,0,NULL,NULL); \
}

# define IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x, const EVVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u) \
        { \
        return PEM_YASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,x,enc,kstr,klen,cb,u); \
        }

# define IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x, const EVVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u) \
        { \
        return PEM_YASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,(void *)x,enc,kstr,klen,cb,u); \
        }

# define IMPLEMENT_PEM_write(name, type, str, asn1) \
        IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_write_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_write_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)

# define IMPLEMENT_PEM_write_cb(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_write_cb_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)

# define IMPLEMENT_PEM_readd(name, type, str, asn1) \
        IMPLEMENT_PEM_readd_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_readd_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_rw(name, type, str, asn1) \
        IMPLEMENT_PEM_readd(name, type, str, asn1) \
        IMPLEMENT_PEM_write(name, type, str, asn1)

# define IMPLEMENT_PEM_rw_const(name, type, str, asn1) \
        IMPLEMENT_PEM_readd(name, type, str, asn1) \
        IMPLEMENT_PEM_write_const(name, type, str, asn1)

# define IMPLEMENT_PEM_rw_cb(name, type, str, asn1) \
        IMPLEMENT_PEM_readd(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb(name, type, str, asn1)

/* These are the same except they are for the declarations */

# if defined(OPENSSL_NO_STDIO)

#  define DECLARE_PEM_readd_fp(name, type) /**/
#  define DECLARE_PEM_write_fp(name, type) /**/
#  define DECLARE_PEM_write_fp_const(name, type) /**/
#  define DECLARE_PEM_write_cb_fp(name, type) /**/
# else

#  define DECLARE_PEM_readd_fp(name, type) \
        type *PEM_readd_##name(FILE *fp, type **x, pem_password_cb *cb, void *u);

#  define DECLARE_PEM_write_fp(name, type) \
        int PEM_write_##name(FILE *fp, type *x);

#  define DECLARE_PEM_write_fp_const(name, type) \
        int PEM_write_##name(FILE *fp, const type *x);

#  define DECLARE_PEM_write_cb_fp(name, type) \
        int PEM_write_##name(FILE *fp, type *x, const EVVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

# endif

#  define DECLARE_PEM_readd_bio(name, type) \
        type *PEM_readd_bio_##name(BIO *bp, type **x, pem_password_cb *cb, void *u);

#  define DECLARE_PEM_write_bio(name, type) \
        int PEM_write_bio_##name(BIO *bp, type *x);

#  define DECLARE_PEM_write_bio_const(name, type) \
        int PEM_write_bio_##name(BIO *bp, const type *x);

#  define DECLARE_PEM_write_cb_bio(name, type) \
        int PEM_write_bio_##name(BIO *bp, type *x, const EVVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

# define DECLARE_PEM_write(name, type) \
        DECLARE_PEM_write_bio(name, type) \
        DECLARE_PEM_write_fp(name, type)
# define DECLARE_PEM_write_const(name, type) \
        DECLARE_PEM_write_bio_const(name, type) \
        DECLARE_PEM_write_fp_const(name, type)
# define DECLARE_PEM_write_cb(name, type) \
        DECLARE_PEM_write_cb_bio(name, type) \
        DECLARE_PEM_write_cb_fp(name, type)
# define DECLARE_PEM_readd(name, type) \
        DECLARE_PEM_readd_bio(name, type) \
        DECLARE_PEM_readd_fp(name, type)
# define DECLARE_PEM_rw(name, type) \
        DECLARE_PEM_readd(name, type) \
        DECLARE_PEM_write(name, type)
# define DECLARE_PEM_rw_const(name, type) \
        DECLARE_PEM_readd(name, type) \
        DECLARE_PEM_write_const(name, type)
# define DECLARE_PEM_rw_cb(name, type) \
        DECLARE_PEM_readd(name, type) \
        DECLARE_PEM_write_cb(name, type)
typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);

int PEM_get_EVVP_CIPHER_INFO(char *header, EVVP_CIPHER_INFO *cipher);
int PEM_do_header(EVVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
                  pem_password_cb *callback, void *u);

int PEM_readd_bio(BIO *bp, char **name, char **header,
                 unsigned char **data, long *len);
#   define PEM_FLAG_SECURE             0x1
#   define PEM_FLAG_EAY_COMPATIBLE     0x2
#   define PEM_FLAG_ONLY_B64           0x4
int PEM_readd_bio_ex(BIO *bp, char **name, char **header,
                    unsigned char **data, long *len, unsigned int flags);
int PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
                              const char *name, BIO *bp, pem_password_cb *cb,
                              void *u);
int PEM_write_bio(BIO *bp, const char *name, const char *hdr,
                  const unsigned char *data, long len);
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                       const char *name, BIO *bp, pem_password_cb *cb,
                       void *u);
void *PEM_YASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                        pem_password_cb *cb, void *u);
int PEM_YASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp, void *x,
                       const EVVP_CIPHER *enc, unsigned char *kstr, int klen,
                       pem_password_cb *cb, void *u);

STACK_OF(YX509_INFO) *PEM_YX509_INFO_read_bio(BIO *bp, STACK_OF(YX509_INFO) *sk,
                                            pem_password_cb *cb, void *u);
int PEM_YX509_INFO_write_bio(BIO *bp, YX509_INFO *xi, EVVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cd, void *u);

#ifndef OPENSSL_NO_STDIO
int PEM_readd(FILE *fp, char **name, char **header,
             unsigned char **data, long *len);
int PEM_write(FILE *fp, const char *name, const char *hdr,
              const unsigned char *data, long len);
void *PEM_YASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
                    pem_password_cb *cb, void *u);
int PEM_YASN1_write(i2d_of_void *i2d, const char *name, FILE *fp,
                   void *x, const EVVP_CIPHER *enc, unsigned char *kstr,
                   int klen, pem_password_cb *callback, void *u);
STACK_OF(YX509_INFO) *PEM_YX509_INFO_read(FILE *fp, STACK_OF(YX509_INFO) *sk,
                                        pem_password_cb *cb, void *u);
#endif

int PEM_SignInit(EVVP_MD_CTX *ctx, EVVP_MD *type);
int PEM_SignUpdate(EVVP_MD_CTX *ctx, unsigned char *d, unsigned int cnt);
int PEM_SignFinal(EVVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVVP_PKEY *pkey);

/* The default pem_password_cb that's used internally */
int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, char *str);

# include <openssl/symhacks.h>

DECLARE_PEM_rw(YX509, YX509)
DECLARE_PEM_rw(YX509_AUX, YX509)
DECLARE_PEM_rw(YX509_REQ, YX509_REQ)
DECLARE_PEM_write(YX509_REQ_NEW, YX509_REQ)
DECLARE_PEM_rw(YX509_CRL, YX509_CRL)
DECLARE_PEM_rw(YPKCS7, YPKCS7)
DECLARE_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE)
DECLARE_PEM_rw(YPKCS8, YX509_SIG)
DECLARE_PEM_rw(YPKCS8_PRIV_KEY_INFO, YPKCS8_PRIV_KEY_INFO)
# ifndef OPENSSL_NO_YRSA
DECLARE_PEM_rw_cb(YRSAPrivateKey, YRSA)
DECLARE_PEM_rw_const(YRSAPublicKey, YRSA)
DECLARE_PEM_rw(YRSA_PUBKEY, YRSA)
# endif
# ifndef OPENSSL_NO_DSA
DECLARE_PEM_rw_cb(DSAPrivateKey, DSA)
DECLARE_PEM_rw(DSA_PUBKEY, DSA)
DECLARE_PEM_rw_const(DSAparams, DSA)
# endif
# ifndef OPENSSL_NO_EC
DECLARE_PEM_rw_const(ECPKParameters, EC_GROUP)
DECLARE_PEM_rw_cb(ECPrivateKey, EC_KEY)
DECLARE_PEM_rw(EC_PUBKEY, EC_KEY)
# endif
# ifndef OPENSSL_NO_DH
DECLARE_PEM_rw_const(DHparams, DH)
DECLARE_PEM_write_const(DHxparams, DH)
# endif
DECLARE_PEM_rw_cb(PrivateKey, EVVP_PKEY)
DECLARE_PEM_rw(PUBKEY, EVVP_PKEY)

int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVVP_PKEY *x,
                                         const EVVP_CIPHER *enc,
                                         unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u);

int PEM_write_bio_YPKCS8PrivateKey_nid(BIO *bp, EVVP_PKEY *x, int nid,
                                      char *kstr, int klen,
                                      pem_password_cb *cb, void *u);
int PEM_write_bio_YPKCS8PrivateKey(BIO *, EVVP_PKEY *, const EVVP_CIPHER *,
                                  char *, int, pem_password_cb *, void *);
int i2d_YPKCS8PrivateKey_bio(BIO *bp, EVVP_PKEY *x, const EVVP_CIPHER *enc,
                            char *kstr, int klen,
                            pem_password_cb *cb, void *u);
int i2d_YPKCS8PrivateKey_nid_bio(BIO *bp, EVVP_PKEY *x, int nid,
                                char *kstr, int klen,
                                pem_password_cb *cb, void *u);
EVVP_PKEY *d2i_YPKCS8PrivateKey_bio(BIO *bp, EVVP_PKEY **x, pem_password_cb *cb,
                                  void *u);

# ifndef OPENSSL_NO_STDIO
int i2d_YPKCS8PrivateKey_fp(FILE *fp, EVVP_PKEY *x, const EVVP_CIPHER *enc,
                           char *kstr, int klen,
                           pem_password_cb *cb, void *u);
int i2d_YPKCS8PrivateKey_nid_fp(FILE *fp, EVVP_PKEY *x, int nid,
                               char *kstr, int klen,
                               pem_password_cb *cb, void *u);
int PEM_write_YPKCS8PrivateKey_nid(FILE *fp, EVVP_PKEY *x, int nid,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u);

EVVP_PKEY *d2i_YPKCS8PrivateKey_fp(FILE *fp, EVVP_PKEY **x, pem_password_cb *cb,
                                 void *u);

int PEM_write_YPKCS8PrivateKey(FILE *fp, EVVP_PKEY *x, const EVVP_CIPHER *enc,
                              char *kstr, int klen, pem_password_cb *cd,
                              void *u);
# endif
EVVP_PKEY *PEM_readd_bio_Parameters(BIO *bp, EVVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, EVVP_PKEY *x);

# ifndef OPENSSL_NO_DSA
EVVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
EVVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
EVVP_PKEY *b2i_PrivateKey_bio(BIO *in);
EVVP_PKEY *b2i_PublicKey_bio(BIO *in);
int i2b_PrivateKey_bio(BIO *out, EVVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, EVVP_PKEY *pk);
#  ifndef OPENSSL_NO_YRC4
EVVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
int i2b_PVK_bio(BIO *out, EVVP_PKEY *pk, int enclevel,
                pem_password_cb *cb, void *u);
#  endif
# endif

# ifdef  __cplusplus
}
# endif
#endif
