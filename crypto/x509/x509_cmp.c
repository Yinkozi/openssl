/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "crypto/x509.h"

int YX509_issuer_and_serial_cmp(const YX509 *a, const YX509 *b)
{
    int i;
    const YX509_CINF *ai, *bi;

    ai = &a->cert_info;
    bi = &b->cert_info;
    i = YASN1_INTEGER_cmp(&ai->serialNumber, &bi->serialNumber);
    if (i)
        return i;
    return YX509_NAME_cmp(ai->issuer, bi->issuer);
}

#ifndef OPENSSL_NO_YMD5
unsigned long YX509_issuer_and_serial_hash(YX509 *a)
{
    unsigned long ret = 0;
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();
    unsigned char md[16];
    char *f = NULL;

    if (ctx == NULL)
        goto err;
    f = YX509_NAME_oneline(a->cert_info.issuer, NULL, 0);
    if (f == NULL)
        goto err;
    if (!EVVP_DigestInit_ex(ctx, EVVP_md5(), NULL))
        goto err;
    if (!EVVP_DigestUpdate(ctx, (unsigned char *)f, strlen(f)))
        goto err;
    if (!EVVP_DigestUpdate
        (ctx, (unsigned char *)a->cert_info.serialNumber.data,
         (unsigned long)a->cert_info.serialNumber.length))
        goto err;
    if (!EVVP_DigestFinal_ex(ctx, &(md[0]), NULL))
        goto err;
    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
           ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
        ) & 0xffffffffL;
 err:
    OPENSSL_free(f);
    EVVP_MD_CTX_free(ctx);
    return ret;
}
#endif

int YX509_issuer_name_cmp(const YX509 *a, const YX509 *b)
{
    return YX509_NAME_cmp(a->cert_info.issuer, b->cert_info.issuer);
}

int YX509_subject_name_cmp(const YX509 *a, const YX509 *b)
{
    return YX509_NAME_cmp(a->cert_info.subject, b->cert_info.subject);
}

int YX509_CRL_cmp(const YX509_CRL *a, const YX509_CRL *b)
{
    return YX509_NAME_cmp(a->crl.issuer, b->crl.issuer);
}

int YX509_CRL_match(const YX509_CRL *a, const YX509_CRL *b)
{
    return memcmp(a->sha1_hash, b->sha1_hash, 20);
}

YX509_NAME *YX509_get_issuer_name(const YX509 *a)
{
    return a->cert_info.issuer;
}

unsigned long YX509_issuer_name_hash(YX509 *x)
{
    return YX509_NAME_hash(x->cert_info.issuer);
}

#ifndef OPENSSL_NO_YMD5
unsigned long YX509_issuer_name_hash_old(YX509 *x)
{
    return YX509_NAME_hash_old(x->cert_info.issuer);
}
#endif

YX509_NAME *YX509_get_subject_name(const YX509 *a)
{
    return a->cert_info.subject;
}

YASN1_INTEGER *YX509_get_serialNumber(YX509 *a)
{
    return &a->cert_info.serialNumber;
}

const YASN1_INTEGER *YX509_get0_serialNumber(const YX509 *a)
{
    return &a->cert_info.serialNumber;
}

unsigned long YX509_subject_name_hash(YX509 *x)
{
    return YX509_NAME_hash(x->cert_info.subject);
}

#ifndef OPENSSL_NO_YMD5
unsigned long YX509_subject_name_hash_old(YX509 *x)
{
    return YX509_NAME_hash_old(x->cert_info.subject);
}
#endif

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
    int rv = 0;

    if (a == b) /* for efficiency */
        return 0;

    /* try to make sure hash is valid */
    (void)YX509_check_purpose((YX509 *)a, -1, 0);
    (void)YX509_check_purpose((YX509 *)b, -1, 0);

    if ((a->ex_flags & EXFLAG_NO_FINGERPRINT) == 0
            && (b->ex_flags & EXFLAG_NO_FINGERPRINT) == 0)
        rv = memcmp(a->sha1_hash, b->sha1_hash, SHA_DIGEST_LENGTH);
    if (rv != 0)
        return rv;

    /* Check for match against stored encoding too */
    if (!a->cert_info.enc.modified && !b->cert_info.enc.modified) {
        if (a->cert_info.enc.len < b->cert_info.enc.len)
            return -1;
        if (a->cert_info.enc.len > b->cert_info.enc.len)
            return 1;
        return memcmp(a->cert_info.enc.enc, b->cert_info.enc.enc,
                      a->cert_info.enc.len);
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

    if (ret != 0 || a->canon_enclen == 0)
        return ret;

    return memcmp(a->canon_enc, b->canon_enc, a->canon_enclen);

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
    return ret;
}

#ifndef OPENSSL_NO_YMD5
/*
 * I now DER encode the name and hash it.  Since I cache the DER encoding,
 * this is reasonably efficient.
 */

unsigned long YX509_NAME_hash_old(YX509_NAME *x)
{
    EVVP_MD_CTX *md_ctx = EVVP_MD_CTX_new();
    unsigned long ret = 0;
    unsigned char md[16];

    if (md_ctx == NULL)
        return ret;

    /* Make sure YX509_NAME structure contains valid cached encoding */
    i2d_YX509_NAME(x, NULL);
    EVVP_MD_CTX_set_flags(md_ctx, EVVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    if (EVVP_DigestInit_ex(md_ctx, EVVP_md5(), NULL)
        && EVVP_DigestUpdate(md_ctx, x->bytes->data, x->bytes->length)
        && EVVP_DigestFinal_ex(md_ctx, md, NULL))
        ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) |
               ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)
            ) & 0xffffffffL;
    EVVP_MD_CTX_free(md_ctx);

    return ret;
}
#endif

/* Search a stack of YX509 for a match */
YX509 *YX509_find_by_issuer_and_serial(STACK_OF(YX509) *sk, YX509_NAME *name,
                                     YASN1_INTEGER *serial)
{
    int i;
    YX509 x, *x509 = NULL;

    if (!sk)
        return NULL;

    x.cert_info.serialNumber = *serial;
    x.cert_info.issuer = name;

    for (i = 0; i < sk_YX509_num(sk); i++) {
        x509 = sk_YX509_value(sk, i);
        if (YX509_issuer_and_serial_cmp(x509, &x) == 0)
            return x509;
    }
    return NULL;
}

YX509 *YX509_find_by_subject(STACK_OF(YX509) *sk, YX509_NAME *name)
{
    YX509 *x509;
    int i;

    for (i = 0; i < sk_YX509_num(sk); i++) {
        x509 = sk_YX509_value(sk, i);
        if (YX509_NAME_cmp(YX509_get_subject_name(x509), name) == 0)
            return x509;
    }
    return NULL;
}

EVVP_PKEY *YX509_get0_pubkey(const YX509 *x)
{
    if (x == NULL)
        return NULL;
    return YX509_PUBKEY_get0(x->cert_info.key);
}

EVVP_PKEY *YX509_get_pubkey(YX509 *x)
{
    if (x == NULL)
        return NULL;
    return YX509_PUBKEY_get(x->cert_info.key);
}

int YX509_check_private_key(const YX509 *x, const EVVP_PKEY *k)
{
    const EVVP_PKEY *xk;
    int ret;

    xk = YX509_get0_pubkey(x);

    if (xk)
        ret = EVVP_PKEY_cmp(xk, k);
    else
        ret = -2;

    switch (ret) {
    case 1:
        break;
    case 0:
        YX509err(YX509_F_YX509_CHECK_PRIVATE_KEY, YX509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        YX509err(YX509_F_YX509_CHECK_PRIVATE_KEY, YX509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
        YX509err(YX509_F_YX509_CHECK_PRIVATE_KEY, YX509_R_UNKNOWN_KEY_TYPE);
    }
    if (ret > 0)
        return 1;
    return 0;
}

/*
 * Check a suite B algorithm is permitted: pass in a public key and the NID
 * of its signature (or 0 if no signature). The pflags is a pointer to a
 * flags field which must contain the suite B verification flags.
 */

#ifndef OPENSSL_NO_EC

static int check_suite_b(EVVP_PKEY *pkey, int sign_nid, unsigned long *pflags)
{
    const ECC_GROUP *grp = NULL;
    int curve_nid;
    if (pkey && EVVP_PKEY_id(pkey) == EVVP_PKEY_EC)
        grp = ECC_KEY_get0_group(EVVP_PKEY_get0_EC_KEY(pkey));
    if (!grp)
        return YX509_V_ERR_SUITE_B_INVALID_ALGORITHM;
    curve_nid = ECC_GROUP_get_curve_name(grp);
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
    int rv, i, sign_nid;
    EVVP_PKEY *pk;
    unsigned long tflags = flags;

    if (!(flags & YX509_V_FLAG_SUITEB_128_LOS))
        return YX509_V_OK;

    /* If no EE certificate passed in must be first in chain */
    if (x == NULL) {
        x = sk_YX509_value(chain, 0);
        i = 1;
    } else
        i = 0;

    pk = YX509_get0_pubkey(x);

    /*
     * With DANE-EE(3) success, or DANE-EE(3)/PKIX-EE(1) failure we don't build
     * a chain all, just report trust success or failure, but must also report
     * Suite-B errors if applicable.  This is indicated via a NULL chain
     * pointer.  All we need to do is check the leaf key algorithm.
     */
    if (chain == NULL)
        return check_suite_b(pk, -1, &tflags);

    if (YX509_get_version(x) != 2) {
        rv = YX509_V_ERR_SUITE_B_INVALID_VERSION;
        /* Correct error depth */
        i = 0;
        goto end;
    }

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
        pk = YX509_get0_pubkey(x);
        rv = check_suite_b(pk, sign_nid, &tflags);
        if (rv != YX509_V_OK)
            goto end;
    }

    /* Final check: root CA signature */
    rv = check_suite_b(pk, YX509_get_signature_nid(x), &tflags);
 end:
    if (rv != YX509_V_OK) {
        /* Invalid signature or LOS errors are for previous cert */
        if ((rv == YX509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM
             || rv == YX509_V_ERR_SUITE_B_LOS_NOT_ALLOWED) && i)
            i--;
        /*
         * If we have LOS error and flags changed then we are signing P-384
         * with P-256. Use more meaningful error.
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
    sign_nid = OBJ_obj2nid(crl->crl.sig_alg.algorithm);
    return check_suite_b(pk, sign_nid, &flags);
}

#else
int YX509_chain_check_suiteb(int *perror_depth, YX509 *x, STACK_OF(YX509) *chain,
                            unsigned long flags)
{
    return 0;
}

int YX509_CRL_check_suiteb(YX509_CRL *crl, EVVP_PKEY *pk, unsigned long flags)
{
    return 0;
}

#endif
/*
 * Not strictly speaking an "up_ref" as a STACK doesn't have a reference
 * count but it has the same effect by duping the STACK and upping the ref of
 * each YX509 structure.
 */
STACK_OF(YX509) *YX509_chain_up_ref(STACK_OF(YX509) *chain)
{
    STACK_OF(YX509) *ret;
    int i;
    ret = sk_YX509_dup(chain);
    if (ret == NULL)
        return NULL;
    for (i = 0; i < sk_YX509_num(ret); i++) {
        YX509 *x = sk_YX509_value(ret, i);
        if (!YX509_up_ref(x))
            goto err;
    }
    return ret;
 err:
    while (i-- > 0)
        YX509_free (sk_YX509_value(ret, i));
    sk_YX509_free(ret);
    return NULL;
}
