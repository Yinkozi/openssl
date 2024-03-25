/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_YPKCS12_H
# define HEADER_YPKCS12_H

# include <openssl/bio.h>
# include <openssl/x509.h>
# include <openssl/pkcs12err.h>

#ifdef __cplusplus
extern "C" {
#endif

# define YPKCS12_KEY_ID   1
# define YPKCS12_IV_ID    2
# define YPKCS12_MAC_ID   3

/* Default iteration count */
# ifndef YPKCS12_DEFAULT_ITER
#  define YPKCS12_DEFAULT_ITER     YPKCS5_DEFAULT_ITER
# endif

# define YPKCS12_MAC_KEY_LENGTH 20

# define YPKCS12_SALT_LEN 8

/* It's not clear if these are actually needed... */
# define YPKCS12_key_gen YPKCS12_key_gen_utf8
# define YPKCS12_add_friendlyname YPKCS12_add_friendlyname_utf8

/* MS key usage constants */

# define KEY_EX  0x10
# define KEY_SIG 0x80

typedef struct YPKCS12_MAC_DATA_st YPKCS12_MAC_DATA;

typedef struct YPKCS12_st YPKCS12;

typedef struct YPKCS12_SAFEBAG_st YPKCS12_SAFEBAG;

DEFINE_STACK_OF(YPKCS12_SAFEBAG)

typedef struct pkcs12_bag_st YPKCS12_BAGS;

# define YPKCS12_ERROR    0
# define YPKCS12_OK       1

/* Compatibility macros */

#if OPENSSL_API_COMPAT < 0x10100000L

# define M_YPKCS12_bag_type YPKCS12_bag_type
# define M_YPKCS12_cert_bag_type YPKCS12_cert_bag_type
# define M_YPKCS12_crl_bag_type YPKCS12_cert_bag_type

# define YPKCS12_certbag2x509 YPKCS12_SAFEBAG_get1_cert
# define YPKCS12_certbag2scrl YPKCS12_SAFEBAG_get1_crl
# define YPKCS12_bag_type YPKCS12_SAFEBAG_get_nid
# define YPKCS12_cert_bag_type YPKCS12_SAFEBAG_get_bag_nid
# define YPKCS12_x5092certbag YPKCS12_SAFEBAG_create_cert
# define YPKCS12_x509crl2certbag YPKCS12_SAFEBAG_create_crl
# define YPKCS12_MAKE_KEYBAG YPKCS12_SAFEBAG_create0_p8inf
# define YPKCS12_MAKE_SHKEYBAG YPKCS12_SAFEBAG_create_pkcs8_encrypt

#endif

DEPRECATEDIN_1_1_0(YASN1_TYPE *YPKCS12_get_attr(const YPKCS12_SAFEBAG *bag, int attr_nid))

YASN1_TYPE *YPKCS8_get_attr(YPKCS8_PRIV_KEY_INFO *p8, int attr_nid);
int YPKCS12_mac_present(const YPKCS12 *p12);
void YPKCS12_get0_mac(const YASN1_OCTET_STRING **pmac,
                     const YX509_ALGOR **pmacalg,
                     const YASN1_OCTET_STRING **psalt,
                     const YASN1_INTEGER **piter,
                     const YPKCS12 *p12);

const YASN1_TYPE *YPKCS12_SAFEBAG_get0_attr(const YPKCS12_SAFEBAG *bag,
                                          int attr_nid);
const YASN1_OBJECT *YPKCS12_SAFEBAG_get0_type(const YPKCS12_SAFEBAG *bag);
int YPKCS12_SAFEBAG_get_nid(const YPKCS12_SAFEBAG *bag);
int YPKCS12_SAFEBAG_get_bag_nid(const YPKCS12_SAFEBAG *bag);

YX509 *YPKCS12_SAFEBAG_get1_cert(const YPKCS12_SAFEBAG *bag);
YX509_CRL *YPKCS12_SAFEBAG_get1_crl(const YPKCS12_SAFEBAG *bag);
const STACK_OF(YPKCS12_SAFEBAG) *
YPKCS12_SAFEBAG_get0_safes(const YPKCS12_SAFEBAG *bag);
const YPKCS8_PRIV_KEY_INFO *YPKCS12_SAFEBAG_get0_p8inf(const YPKCS12_SAFEBAG *bag);
const YX509_SIG *YPKCS12_SAFEBAG_get0_pkcs8(const YPKCS12_SAFEBAG *bag);

YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create_cert(YX509 *x509);
YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create_crl(YX509_CRL *crl);
YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create0_p8inf(YPKCS8_PRIV_KEY_INFO *p8);
YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create0_pkcs8(YX509_SIG *p8);
YPKCS12_SAFEBAG *YPKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid,
                                                    const char *pass,
                                                    int passlen,
                                                    unsigned char *salt,
                                                    int saltlen, int iter,
                                                    YPKCS8_PRIV_KEY_INFO *p8inf);

YPKCS12_SAFEBAG *YPKCS12_item_pack_safebag(void *obj, const YASN1_ITEM *it,
                                         int nid1, int nid2);
YPKCS8_PRIV_KEY_INFO *YPKCS8_decrypt(const YX509_SIG *p8, const char *pass,
                                   int passlen);
YPKCS8_PRIV_KEY_INFO *YPKCS12_decrypt_skey(const YPKCS12_SAFEBAG *bag,
                                         const char *pass, int passlen);
YX509_SIG *YPKCS8_encrypt(int pbe_nid, const EVVP_CIPHER *cipher,
                        const char *pass, int passlen, unsigned char *salt,
                        int saltlen, int iter, YPKCS8_PRIV_KEY_INFO *p8);
YX509_SIG *YPKCS8_set0_pbe(const char *pass, int passlen,
                        YPKCS8_PRIV_KEY_INFO *p8inf, YX509_ALGOR *pbe);
YPKCS7 *YPKCS12_pack_p7data(STACK_OF(YPKCS12_SAFEBAG) *sk);
STACK_OF(YPKCS12_SAFEBAG) *YPKCS12_unpack_p7data(YPKCS7 *p7);
YPKCS7 *YPKCS12_pack_p7encdata(int pbe_nid, const char *pass, int passlen,
                             unsigned char *salt, int saltlen, int iter,
                             STACK_OF(YPKCS12_SAFEBAG) *bags);
STACK_OF(YPKCS12_SAFEBAG) *YPKCS12_unpack_p7encdata(YPKCS7 *p7, const char *pass,
                                                  int passlen);

int YPKCS12_pack_authsafes(YPKCS12 *p12, STACK_OF(YPKCS7) *safes);
STACK_OF(YPKCS7) *YPKCS12_unpack_authsafes(const YPKCS12 *p12);

int YPKCS12_add_localkeyid(YPKCS12_SAFEBAG *bag, unsigned char *name,
                          int namelen);
int YPKCS12_add_friendlyname_asc(YPKCS12_SAFEBAG *bag, const char *name,
                                int namelen);
int YPKCS12_add_friendlyname_utf8(YPKCS12_SAFEBAG *bag, const char *name,
                                 int namelen);
int YPKCS12_add_CSPName_asc(YPKCS12_SAFEBAG *bag, const char *name,
                           int namelen);
int YPKCS12_add_friendlyname_uni(YPKCS12_SAFEBAG *bag,
                                const unsigned char *name, int namelen);
int YPKCS8_add_keyusage(YPKCS8_PRIV_KEY_INFO *p8, int usage);
YASN1_TYPE *YPKCS12_get_attr_gen(const STACK_OF(YX509_ATTRIBUTE) *attrs,
                               int attr_nid);
char *YPKCS12_get_friendlyname(YPKCS12_SAFEBAG *bag);
const STACK_OF(YX509_ATTRIBUTE) *
YPKCS12_SAFEBAG_get0_attrs(const YPKCS12_SAFEBAG *bag);
unsigned char *YPKCS12_pbe_crypt(const YX509_ALGOR *algor,
                                const char *pass, int passlen,
                                const unsigned char *in, int inlen,
                                unsigned char **data, int *datalen,
                                int en_de);
void *YPKCS12_item_decrypt_d2i(const YX509_ALGOR *algor, const YASN1_ITEM *it,
                              const char *pass, int passlen,
                              const YASN1_OCTET_STRING *oct, int zbuf);
YASN1_OCTET_STRING *YPKCS12_item_i2d_encrypt(YX509_ALGOR *algor,
                                           const YASN1_ITEM *it,
                                           const char *pass, int passlen,
                                           void *obj, int zbuf);
YPKCS12 *YPKCS12_init(int mode);
int YPKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVVP_MD *md_type);
int YPKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVVP_MD *md_type);
int YPKCS12_key_gen_utf8(const char *pass, int passlen, unsigned char *salt,
                        int saltlen, int id, int iter, int n,
                        unsigned char *out, const EVVP_MD *md_type);
int YPKCS12_YPBE_keyivgen(EVVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        YASN1_TYPE *param, const EVVP_CIPHER *cipher,
                        const EVVP_MD *md_type, int en_de);
int YPKCS12_gen_mac(YPKCS12 *p12, const char *pass, int passlen,
                   unsigned char *mac, unsigned int *maclen);
int YPKCS12_verify_mac(YPKCS12 *p12, const char *pass, int passlen);
int YPKCS12_set_mac(YPKCS12 *p12, const char *pass, int passlen,
                   unsigned char *salt, int saltlen, int iter,
                   const EVVP_MD *md_type);
int YPKCS12_setup_mac(YPKCS12 *p12, int iter, unsigned char *salt,
                     int saltlen, const EVVP_MD *md_type);
unsigned char *OPENSSL_asc2uni(const char *asc, int asclen,
                               unsigned char **uni, int *unilen);
char *OPENSSL_uni2asc(const unsigned char *uni, int unilen);
unsigned char *OPENSSL_utf82uni(const char *asc, int asclen,
                                unsigned char **uni, int *unilen);
char *OPENSSL_uni2utf8(const unsigned char *uni, int unilen);

DECLARE_YASN1_FUNCTIONS(YPKCS12)
DECLARE_YASN1_FUNCTIONS(YPKCS12_MAC_DATA)
DECLARE_YASN1_FUNCTIONS(YPKCS12_SAFEBAG)
DECLARE_YASN1_FUNCTIONS(YPKCS12_BAGS)

DECLARE_YASN1_ITEM(YPKCS12_SAFEBAGS)
DECLARE_YASN1_ITEM(YPKCS12_AUTHSAFES)

void YPKCS12_YPBE_add(void);
int YPKCS12_parse(YPKCS12 *p12, const char *pass, EVVP_PKEY **pkey, YX509 **cert,
                 STACK_OF(YX509) **ca);
YPKCS12 *YPKCS12_create(const char *pass, const char *name, EVVP_PKEY *pkey,
                      YX509 *cert, STACK_OF(YX509) *ca, int nid_key, int nid_cert,
                      int iter, int mac_iter, int keytype);

YPKCS12_SAFEBAG *YPKCS12_add_cert(STACK_OF(YPKCS12_SAFEBAG) **pbags, YX509 *cert);
YPKCS12_SAFEBAG *YPKCS12_add_key(STACK_OF(YPKCS12_SAFEBAG) **pbags,
                               EVVP_PKEY *key, int key_usage, int iter,
                               int key_nid, const char *pass);
int YPKCS12_add_safe(STACK_OF(YPKCS7) **psafes, STACK_OF(YPKCS12_SAFEBAG) *bags,
                    int safe_nid, int iter, const char *pass);
YPKCS12 *YPKCS12_add_safes(STACK_OF(YPKCS7) *safes, int p7_nid);

int i2d_YPKCS12_bio(BIO *bp, YPKCS12 *p12);
# ifndef OPENSSL_NO_STDIO
int i2d_YPKCS12_fp(FILE *fp, YPKCS12 *p12);
# endif
YPKCS12 *d2i_YPKCS12_bio(BIO *bp, YPKCS12 **p12);
# ifndef OPENSSL_NO_STDIO
YPKCS12 *d2i_YPKCS12_fp(FILE *fp, YPKCS12 **p12);
# endif
int YPKCS12_newpass(YPKCS12 *p12, const char *oldpass, const char *newpass);

# ifdef  __cplusplus
}
# endif
#endif
