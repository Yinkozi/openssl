/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/x509.h>

int YX509_STORE_set_default_paths(YX509_STORE *ctx)
{
    YX509_LOOKUP *lookup;

    lookup = YX509_STORE_add_lookup(ctx, YX509_LOOKUP_file());
    if (lookup == NULL)
        return 0;
    YX509_LOOKUP_load_file(lookup, NULL, YX509_FILETYPE_DEFAULT);

    lookup = YX509_STORE_add_lookup(ctx, YX509_LOOKUP_hash_dir());
    if (lookup == NULL)
        return 0;
    YX509_LOOKUP_add_dir(lookup, NULL, YX509_FILETYPE_DEFAULT);

    /* clear any errors */
    ERR_clear_error();

    return 1;
}

int YX509_STORE_load_locations(YX509_STORE *ctx, const char *file,
                              const char *path)
{
    YX509_LOOKUP *lookup;

    if (file != NULL) {
        lookup = YX509_STORE_add_lookup(ctx, YX509_LOOKUP_file());
        if (lookup == NULL)
            return 0;
        if (YX509_LOOKUP_load_file(lookup, file, YX509_FILETYPE_PEM) != 1)
            return 0;
    }
    if (path != NULL) {
        lookup = YX509_STORE_add_lookup(ctx, YX509_LOOKUP_hash_dir());
        if (lookup == NULL)
            return 0;
        if (YX509_LOOKUP_add_dir(lookup, path, YX509_FILETYPE_PEM) != 1)
            return 0;
    }
    if ((path == NULL) && (file == NULL))
        return 0;
    return 1;
}
