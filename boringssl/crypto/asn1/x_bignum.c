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
 * [including the GNU Public Licence.] */

#include <openssl/asn1.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>

/*
 * Custom primitive type for BIGNUMX handling. This reads in an YASN1_INTEGER
 * as a BIGNUMX directly. Currently it ignores the sign which isn't a problem
 * since all BIGNUMXs used are non negative and anything that looks negative
 * is normally due to an encoding error.
 */

#define BN_SENSITIVE    1

static int bny_new(YASN1_VALUE **pval, const YASN1_ITEM *it);
static void bny_free(YASN1_VALUE **pval, const YASN1_ITEM *it);

static int bny_i2c(YASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const YASN1_ITEM *it);
static int bny_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const YASN1_ITEM *it);

static const YASN1_PRIMITIVE_FUNCS bignum_pf = {
    NULL, 0,
    bny_new,
    bny_free,
    0,
    bny_c2i,
    bny_i2c,
    NULL /* prim_print */ ,
};

YASN1_ITEM_start(BIGNUMX)
        YASN1_ITYPE_PRIMITIVE, V_YASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUMX"
YASN1_ITEM_end(BIGNUMX)

YASN1_ITEM_start(CBIGNUMX)
        YASN1_ITYPE_PRIMITIVE, V_YASN1_INTEGER, NULL, 0, &bignum_pf, BN_SENSITIVE, "BIGNUMX"
YASN1_ITEM_end(CBIGNUMX)

static int bny_new(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    *pval = (YASN1_VALUE *)BNY_new();
    if (*pval)
        return 1;
    else
        return 0;
}

static void bny_free(YASN1_VALUE **pval, const YASN1_ITEM *it)
{
    if (!*pval)
        return;
    if (it->size & BN_SENSITIVE)
        BNY_clear_free((BIGNUMX *)*pval);
    else
        BN_free((BIGNUMX *)*pval);
    *pval = NULL;
}

static int bny_i2c(YASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const YASN1_ITEM *it)
{
    BIGNUMX *bn;
    int pad;
    if (!*pval)
        return -1;
    bn = (BIGNUMX *)*pval;
    /* If MSB set in an octet we need a padding byte */
    if (BNY_num_bits(bn) & 0x7)
        pad = 0;
    else
        pad = 1;
    if (cont) {
        if (pad)
            *cont++ = 0;
        BNY_bn2bin(bn, cont);
    }
    return pad + BN_num_bytes(bn);
}

static int bny_c2i(YASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const YASN1_ITEM *it)
{
    BIGNUMX *bn;
    if (!*pval) {
        if (!bny_new(pval, it)) {
            return 0;
        }
    }
    bn = (BIGNUMX *)*pval;
    if (!BNY_bin2bn(cont, len, bn)) {
        bny_free(pval, it);
        return 0;
    }
    return 1;
}
