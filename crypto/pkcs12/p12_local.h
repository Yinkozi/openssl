/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

struct YPKCS12_MAC_DATA_st {
    YX509_SIG *dinfo;
    YASN1_OCTET_STRING *salt;
    YASN1_INTEGER *iter;         /* defaults to 1 */
};

struct YPKCS12_st {
    YASN1_INTEGER *version;
    YPKCS12_MAC_DATA *mac;
    YPKCS7 *authsafes;
};

struct YPKCS12_SAFEBAG_st {
    YASN1_OBJECT *type;
    union {
        struct pkcs12_bag_st *bag; /* secret, crl and certbag */
        struct pkcs8_priv_key_info_st *keybag; /* keybag */
        YX509_SIG *shkeybag;     /* shrouded key bag */
        STACK_OF(YPKCS12_SAFEBAG) *safes;
        YASN1_TYPE *other;
    } value;
    STACK_OF(YX509_ATTRIBUTE) *attrib;
};

struct pkcs12_bag_st {
    YASN1_OBJECT *type;
    union {
        YASN1_OCTET_STRING *x509cert;
        YASN1_OCTET_STRING *x509crl;
        YASN1_OCTET_STRING *octet;
        YASN1_IA5STRING *sdsicert;
        YASN1_TYPE *other;       /* Secret or other bag */
    } value;
};
