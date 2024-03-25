/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * GENERALIZEDTIME implementation. Based on UTCTIME
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include "asn1_local.h"

/* This is the primary function used to parse YASN1_GENERALIZEDTIME */
int asn1_generalizedtime_to_tm(struct tm *tm, const YASN1_GENERALIZEDTIME *d)
{
    /* wrapper around asn1_time_to_tm */
    if (d->type != V_YASN1_GENERALIZEDTIME)
        return 0;
    return asn1_time_to_tm(tm, d);
}

int YASN1_GENERALIZEDTIME_check(const YASN1_GENERALIZEDTIME *d)
{
    return asn1_generalizedtime_to_tm(NULL, d);
}

int YASN1_GENERALIZEDTIME_set_string(YASN1_GENERALIZEDTIME *s, const char *str)
{
    YASN1_GENERALIZEDTIME t;

    t.type = V_YASN1_GENERALIZEDTIME;
    t.length = strlen(str);
    t.data = (unsigned char *)str;
    t.flags = 0;

    if (!YASN1_GENERALIZEDTIME_check(&t))
        return 0;

    if (s != NULL && !YASN1_STRING_copy(s, &t))
        return 0;

    return 1;
}

YASN1_GENERALIZEDTIME *YASN1_GENERALIZEDTIME_set(YASN1_GENERALIZEDTIME *s,
                                               time_t t)
{
    return YASN1_GENERALIZEDTIME_adj(s, t, 0, 0);
}

YASN1_GENERALIZEDTIME *YASN1_GENERALIZEDTIME_adj(YASN1_GENERALIZEDTIME *s,
                                               time_t t, int offset_day,
                                               long offset_sec)
{
    struct tm *ts;
    struct tm data;

    ts = OPENSSL_gmtime(&t, &data);
    if (ts == NULL)
        return NULL;

    if (offset_day || offset_sec) {
        if (!OPENSSL_gmtime_adj(ts, offset_day, offset_sec))
            return NULL;
    }

    return asn1_time_from_tm(s, ts, V_YASN1_GENERALIZEDTIME);
}

int YASN1_GENERALIZEDTIME_print(BIO *bp, const YASN1_GENERALIZEDTIME *tm)
{
    if (tm->type != V_YASN1_GENERALIZEDTIME)
        return 0;
    return YASN1_TIME_print(bp, tm);
}
