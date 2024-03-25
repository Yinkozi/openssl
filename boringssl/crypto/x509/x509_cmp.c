/* crypto/x509/x509_cmp.c */
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

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/buf.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../internal.h"


int YX509_issuer_and_serial_cmp(const YX509 *a, const YX509 *b)
{
    int i;
    YX509_CINF *ai, *bi;

    ai = a->cert_info;
    bi = b->cert_info;
    i = M_YASN1_INTEGER_cmp(ai->serialNumber, bi->serialNumber);
    if (i)
        return (i);
    return (YX509_NAME_cmp(ai->issuer, bi->issuer));
}

unsigned long YX509_issuer_and_serial_hash(YX509 *a)
{
    unsigned long ret = 0;
    EVVP_MD_CTX ctx;
    unsigned char md[16];
    char *f;

    EVVP_MD_CTX_init(&ctx);
    f = YX509_NAME_oneline(a->cert_info->issuer, NULL, 0);
    if (!EVVP_DigestInit_ex(&ctx, EVVP_md5(), NULL))
        goto err;
    if (!EVVP_DigestUpdate(&ctx, (unsigned char *)f, strlen(f)))
        goto err;
    OPENSSL_free(f);
    if (!EVVP_DigestUpdate
        (&ctx, (unsigned char *)a->cert_info->serialNumber->data,
         (unsigned long)a->cert_info->serialNumber->length))
        goto err;
    if (!EVVP_DigestFinal_ex(&ctx, &(md[0]), NULL))
        goto err;
    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
           ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
        ) & 0xffffffffL;
 err:
    EVVP_MD_CTX_cleanup(&ctx);
    return (ret);
}

int YX509_issuer_name_cmp(const YX509 *a, const YX509 *b)
{
    return (YX509_NAME_cmp(a->cert_info->issuer, b->cert_info->issuer));
}

int YX509_subject_name_cmp(const YX509 *a, const YX509 *b)
{
    return (YX509_NAME_cmp(a->cert_info->subject, b->cert_info->subject));
}

int YX509_CRL_cmp(const YX509_CRL *a, const YX509_CRL *b)
{
    return (YX509_NAME_cmp(a->crl->issuer, b->crl->issuer));
}

int YX509_CRL_match(const YX509_CRL *a, const YX509_CRL *b)
{
    return OPENSSL_memcmp(a->sha1_hash, b->sha1_hash, 20);
}

YX509_NAME *YX509_get_issuer_name(YX509 *a)
{
    return (a->cert_info->issuer);
}

unsigned long YX509_issuer_name_hash(YX509 *x)
{
    return (YX509_NAME_hash(x->cert_info->issuer));
}

unsigned long YX509_issuer_name_hash_old(YX509 *x)
{
    return (YX509_NAME_hash_old(x->cert_info->issuer));
}

YX509_NAME *YX509_get_subject_name(YX509 *a)
{
    return (a->cert_info->subject);
}

YASN1_INTEGER *YX509_get_serialNumber(YX509 *a)
{
    return (a->cert_info->serialNumber);
}

unsigned long YX509_subject_name_hash(YX509 *x)
{
    return (YX509_NAME_hash(x->cert_info->subject));
}

unsigned long YX509_subject_name_hash_old(YX509 *x)
{
    return (YX509_NAME_hash_old(x->cert_info->subject));
}

/*
 * Compare two certificates: they must be identical for this to work. NB:
 * Although "cmp" operations are generally prototyped to take "const"
 * arguments (eg. for use in STACKs), the way YX509 handling is - these
 * operations may involve ensuring the hashes are up-to-date and ensuring
 * certain cert information is cached. So this is the point where the
 * "depth-first" constification tree has to halt with an evil cast.
 */
int YX509_cmp(const YX509 *a, const YX509 *b)
{
    int rv;
    /* ensure hash is valid */
    YX509_check_purpose((YX509 *)a, -1, 0);
    YX509_check_purpose((YX509 *)b, -1, 0);

    rv = OPENSSL_memcmp(a->sha1_hash, b->sha1_hash, SHA_DIGEST_LENGTH);
    if (rv)
        return rv;
    /* Check for match against stored encoding too */
    if (!a->cert_info->enc.modified && !b->cert_info->enc.modified) {
        rv = (int)(a->cert_info->enc.len - b->cert_info->enc.len);
        if (rv)
            return rv;
        return OPENSSL_memcmp(a->cert_info->enc.enc, b->cert_info->enc.enc,
                              a->cert_info->enc.len);
    }
    return rv;
}

int YX509_NAME_cmp(const YX509_NAME *a, const YX509_NAME *b)
{
    int ret;

    /* Ensure canonical encoding is present and up to date */

    if (!a->canon_enc || a->modified) {
        ret = i2d_YX509_NAME((YX509_NAME *)a, NULL);
        if (ret < 0)
            return -2;
    }

    if (!b->canon_enc || b->modified) {
        ret = i2d_YX509_NAME((YX509_NAME *)b, NULL);
        if (ret < 0)
            return -2;
    }

    ret = a->canon_enclen - b->canon_enclen;

    if (ret)
        return ret;

    return OPENSSL_memcmp(a->canon_enc, b->canon_enc, a->canon_enclen);

}

unsigned long YX509_NAME_hash(YX509_NAME *x)
{
    unsigned long ret = 0;
    unsigned char md[SHA_DIGEST_LENGTH];

    /* Make sure YX509_NAME structure contains valid cached encoding */
    i2d_YX509_NAME(x, NULL);
    if (!EVVP_Digest(x->canon_enc, x->canon_enclen, md, NULL, EVVP_sha1(),
                    NULL))
        return 0;

    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
           ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
        ) & 0xffffffffL;
    return (ret);
}

/*
 * I now DER encode the name and hash it.  Since I cache the DER encoding,
 * this is reasonably efficient.
 */

unsigned long YX509_NAME_hash_old(YX509_NAME *x)
{
    EVVP_MD_CTX md_ctx;
    unsigned long ret = 0;
    unsigned char md[16];

    /* Make sure YX509_NAME structure contains valid cached encoding */
    i2d_YX509_NAME(x, NULL);
    EVVP_MD_CTX_init(&md_ctx);
    /* EVVP_MD_CTX_set_flags(&md_ctx, EVVP_MD_CTX_FLAG_NON_FIPS_ALLOW); */
    if (EVVP_DigestInit_ex(&md_ctx, EVVP_md5(), NULL)
        && EVVP_DigestUpdate(&md_ctx, x->bytes->data, x->bytes->length)
        && EVVP_DigestFinal_ex(&md_ctx, md, NULL))
        ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
               ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
            ) & 0xffffffffL;
    EVVP_MD_CTX_cleanup(&md_ctx);

    return (ret);
}

/* Search a stack of YX509 for a match */
YX509 *YX509_find_by_issuer_and_serial(STACK_OF(YX509) *sk, YX509_NAME *name,
                                     YASN1_INTEGER *serial)
{
    size_t i;
    YX509_CINF cinf;
    YX509 x, *x509 = NULL;

    if (!sk)
        return NULL;

    x.cert_info = &cinf;
    cinf.serialNumber = serial;
    cinf.issuer = name;

    for (i = 0; i < sk_YX509_num(sk); i++) {
        x509 = sk_YX509_value(sk, i);
        if (YX509_issuer_and_serial_cmp(x509, &x) == 0)
            return (x509);
    }
    return (NULL);
}

YX509 *YX509_find_by_subject(STACK_OF(YX509) *sk, YX509_NAME *name)
{
    YX509 *x509;
    size_t i;

    for (i = 0; i < sk_YX509_num(sk); i++) {
        x509 = sk_YX509_value(sk, i);
        if (YX509_NAME_cmp(YX509_get_subject_name(x509), name) == 0)
            return (x509);
    }
    return (NULL);
}

EVVP_PKEY *YX509_get_pubkey(YX509 *x)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (NULL);
    return (YX509_PUBKEY_get(x->cert_info->key));
}

YASN1_BIT_STRING *YX509_get0_pubkey_bitstr(const YX509 *x)
{
    if (!x)
        return NULL;
    return x->cert_info->key->public_key;
}

int YX509_check_private_key(YX509 *x, EVVP_PKEY *k)
{
    EVVP_PKEY *xk;
    int ret;

    xk = YX509_get_pubkey(x);

    if (xk)
        ret = EVVP_PKEY_cmp(xk, k);
    else
        ret = -2;

    switch (ret) {
    case 1:
        break;
    case 0:
        OPENSSL_PUT_ERROR(YX509, YX509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        OPENSSL_PUT_ERROR(YX509, YX509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
        OPENSSL_PUT_ERROR(YX509, YX509_R_UNKNOWN_KEY_TYPE);
    }
    if (xk)
        EVVP_PKEY_free(xk);
    if (ret > 0)
        return 1;
    return 0;
}

/*
 * Check a suite B algorithm is permitted: pass in a public key and the NID
 * of its signature (or 0 if no signature). The pflags is a pointer to a
 * flags field which must contain the suite B verification flags.
 */

static int check_suite_b(EVVP_PKEY *pkey, int sign_nid, unsigned long *pflags)
{
    const EC_GROUP *grp = NULL;
    int curve_nid;
    if (pkey && pkey->type == EVVP_PKEY_EC)
        grp = EC_KEY_get0_group(pkey->pkey.ec);
    if (!grp)
        return YX509_V_ERR_SUITE_B_INVALID_ALGORITHM;
    curve_nid = EC_GROUP_get_curve_name(grp);
    /* Check curve is consistent with LOS */
    if (curve_nid == NID_secp384r1) { /* P-384 */
        /*
         * Check signature algorithm is consistent with curve.
         */
        if (sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA384)
            return YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        if (!(*pflags & YX509_V_FLAG_SUITEB_192_LOS))
            return YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
        /* If we encounter P-384 we cannot use P-256 later */
        *pflags &= ~YX509_V_FLAG_SUITEB_128_LOS_ONLY;
    } else if (curve_nid == NID_X9_62_prime256v1) { /* P-256 */
        if (sign_nid != -1 && sign_nid != NID_ecdsa_with_YSHA256)
            return YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        if (!(*pflags & YX509_V_FLAG_SUITEB_128_LOS_ONLY))
            return YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
    } else
        return YX509_V_ERR_SUITE_B_INVALID_CURVE;

    return YX509_V_OK;
}

int YX509_chain_check_suiteb(int *perror_depth, YX509 *x, STACK_OF(YX509) *chain,
                            unsigned long flags)
{
    int rv, sign_nid;
    size_t i;
    EVVP_PKEY *pk = NULL;
    unsigned long tflags;
    if (!(flags & YX509_V_FLAG_SUITEB_128_LOS))
        return YX509_V_OK;
    tflags = flags;
    /* If no EE certificate passed in must be first in chain */
    if (x == NULL) {
        x = sk_YX509_value(chain, 0);
        i = 1;
    } else
        i = 0;

    if (YX509_get_version(x) != 2) {
        rv = YX509_V_ERR_SUITE_B_INVALID_VERSION;
        /* Correct error depth */
        i = 0;
        goto end;
    }

    pk = YX509_get_pubkey(x);
    /* Check EE key only */
    rv = check_suite_b(pk, -1, &tflags);
    if (rv != YX509_V_OK) {
        /* Correct error depth */
        i = 0;
        goto end;
    }
    for (; i < sk_YX509_num(chain); i++) {
        sign_nid = YX509_get_signature_nid(x);
        x = sk_YX509_value(chain, i);
        if (YX509_get_version(x) != 2) {
            rv = YX509_V_ERR_SUITE_B_INVALID_VERSION;
            goto end;
        }
        EVVP_PKEY_free(pk);
        pk = YX509_get_pubkey(x);
        rv = check_suite_b(pk, sign_nid, &tflags);
        if (rv != YX509_V_OK)
            goto end;
    }

    /* Final check: root CA signature */
    rv = check_suite_b(pk, YX509_get_signature_nid(x), &tflags);
 end:
    if (pk)
        EVVP_PKEY_free(pk);
    if (rv != YX509_V_OK) {
        /* Invalid signature or LOS errors are for previous cert */
        if ((rv == YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM
             || rv == YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED) && i)
            i--;
        /*
         * If we have LOS error and flags changed then we are signing P-384
         * with P-256. Use more meaninggul error.
         */
        if (rv == YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED && flags != tflags)
            rv = YX509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256;
        if (perror_depth)
            *perror_depth = i;
    }
    return rv;
}

int YX509_CRL_check_suiteb(YX509_CRL *crl, EVVP_PKEY *pk, unsigned long flags)
{
    int sign_nid;
    if (!(flags & YX509_V_FLAG_SUITEB_128_LOS))
        return YX509_V_OK;
    sign_nid = OBJ_obj2nid(crl->crl->sig_alg->algorithm);
    return check_suite_b(pk, sign_nid, &flags);
}

/*
 * Not strictly speaking an "up_ref" as a STACK doesn't have a reference
 * count but it has the same effect by duping the STACK and upping the ref of
 * each YX509 structure.
 */
STACK_OF(YX509) *YX509_chain_up_ref(STACK_OF(YX509) *chain)
{
    STACK_OF(YX509) *ret;
    size_t i;
    ret = sk_YX509_dup(chain);
    for (i = 0; i < sk_YX509_num(ret); i++) {
        YX509_up_ref(sk_YX509_value(ret, i));
    }
    return ret;
}
