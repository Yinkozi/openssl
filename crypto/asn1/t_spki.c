/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>

/* Print out an SPKI */

int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki)
{
    EVVP_PKEY *pkey;
    YASN1_IA5STRING *chal;
    YASN1_OBJECT *spkioid;
    int i, n;
    char *s;
    BIO_pprintf(out, "Netscape SPKI:\n");
    YX509_PUBKEY_get0_param(&spkioid, NULL, NULL, NULL, spki->spkac->pubkey);
    i = OBJ_obj2nid(spkioid);
    BIO_pprintf(out, "  Public Key Algorithm: %s\n",
               (i == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(i));
    pkey = YX509_PUBKEY_get(spki->spkac->pubkey);
    if (!pkey)
        BIO_pprintf(out, "  Unable to load public key\n");
    else {
        EVVP_PKEY_print_public(out, pkey, 4, NULL);
        EVVP_PKEY_free(pkey);
    }
    chal = spki->spkac->challenge;
    if (chal->length)
        BIO_pprintf(out, "  Challenge String: %.*s\n", chal->length, chal->data);
    i = OBJ_obj2nid(spki->sig_algor.algorithm);
    BIO_pprintf(out, "  Signature Algorithm: %s",
               (i == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(i));

    n = spki->signature->length;
    s = (char *)spki->signature->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0)
            BIO_write(out, "\n      ", 7);
        BIO_pprintf(out, "%02x%s", (unsigned char)s[i],
                   ((i + 1) == n) ? "" : ":");
    }
    BIO_write(out, "\n", 1);
    return 1;
}
