/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

const YX509V3_EXT_METHOD v3_ns_ia5_list[8] = {
    EXT_IA5STRING(NID_netscape_base_url),
    EXT_IA5STRING(NID_netscape_revocation_url),
    EXT_IA5STRING(NID_netscape_ca_revocation_url),
    EXT_IA5STRING(NID_netscape_renewal_url),
    EXT_IA5STRING(NID_netscape_ca_policy_url),
    EXT_IA5STRING(NID_netscape_ssl_server_name),
    EXT_IA5STRING(NID_netscape_comment),
    EXT_END
};

char *i2s_YASN1_IA5STRING(YX509V3_EXT_METHOD *method, YASN1_IA5STRING *ia5)
{
    char *tmp;

    if (!ia5 || !ia5->length)
        return NULL;
    if ((tmp = OPENSSL_malloc(ia5->length + 1)) == NULL) {
        YX509V3err(YX509V3_F_I2S_YASN1_IA5STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memcpy(tmp, ia5->data, ia5->length);
    tmp[ia5->length] = 0;
    return tmp;
}

YASN1_IA5STRING *s2i_YASN1_IA5STRING(YX509V3_EXT_METHOD *method,
                                   YX509V3_CTX *ctx, const char *str)
{
    YASN1_IA5STRING *ia5;
    if (!str) {
        YX509V3err(YX509V3_F_S2I_YASN1_IA5STRING,
                  YX509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if ((ia5 = YASN1_IA5STRING_new()) == NULL)
        goto err;
    if (!YASN1_STRING_set((YASN1_STRING *)ia5, str, strlen(str))) {
        YASN1_IA5STRING_free(ia5);
        return NULL;
    }
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(ia5->data, ia5->data, ia5->length);
#endif                          /* CHARSET_EBCDIC */
    return ia5;
 err:
    YX509V3err(YX509V3_F_S2I_YASN1_IA5STRING, ERR_R_MALLOC_FAILURE);
    return NULL;
}
