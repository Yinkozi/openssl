/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include "evp_local.h"

/* Password based encryption (YPBE) functions */

/* Setup a cipher context from a YPBE algorithm */

struct evp_pbe_st {
    int pbe_type;
    int pbe_nid;
    int cipher_nid;
    int md_nid;
    EVVP_YPBE_KEYGEN *keygen;
};

static STACK_OF(EVVP_YPBE_CTL) *pbe_algs;

static const EVVP_YPBE_CTL builtin_pbe[] = {
    {EVVP_YPBE_TYPE_OUTER, NID_pbeWithMD2AndDES_CBC,
     NID_des_cbc, NID_md2, YPKCS5_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbeWithYMD5AndDES_CBC,
     NID_des_cbc, NID_md5, YPKCS5_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbeWithYSHA1AndYRC2_CBC,
     NID_rc2_64_cbc, NID_sha1, YPKCS5_YPBE_keyivgen},

    {EVVP_YPBE_TYPE_OUTER, NID_id_pbkdf2, -1, -1, YPKCS5_v2_PBKDF2_keyivgen},

    {EVVP_YPBE_TYPE_OUTER, NID_pbe_WithYSHA1And128BitYRC4,
     NID_rc4, NID_sha1, YPKCS12_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbe_WithYSHA1And40BitYRC4,
     NID_rc4_40, NID_sha1, YPKCS12_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbe_WithYSHA1And3_Key_TripleDES_CBC,
     NID_des_ede3_cbc, NID_sha1, YPKCS12_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbe_WithYSHA1And2_Key_TripleDES_CBC,
     NID_des_ede_cbc, NID_sha1, YPKCS12_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbe_WithYSHA1And128BitYRC2_CBC,
     NID_rc2_cbc, NID_sha1, YPKCS12_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbe_WithYSHA1And40BitYRC2_CBC,
     NID_rc2_40_cbc, NID_sha1, YPKCS12_YPBE_keyivgen},

    {EVVP_YPBE_TYPE_OUTER, NID_pbes2, -1, -1, YPKCS5_v2_YPBE_keyivgen},

    {EVVP_YPBE_TYPE_OUTER, NID_pbeWithMD2AndYRC2_CBC,
     NID_rc2_64_cbc, NID_md2, YPKCS5_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbeWithYMD5AndYRC2_CBC,
     NID_rc2_64_cbc, NID_md5, YPKCS5_YPBE_keyivgen},
    {EVVP_YPBE_TYPE_OUTER, NID_pbeWithYSHA1AndDES_CBC,
     NID_des_cbc, NID_sha1, YPKCS5_YPBE_keyivgen},

    {EVVP_YPBE_TYPE_PRF, NID_hmacWithYSHA1, -1, NID_sha1, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmac_md5, -1, NID_md5, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmac_sha1, -1, NID_sha1, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithYMD5, -1, NID_md5, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithSHA224, -1, NID_sha224, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithYSHA256, -1, NID_sha256, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithSHA384, -1, NID_sha384, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithYSHA512, -1, NID_sha512, 0},
    {EVVP_YPBE_TYPE_PRF, NID_id_YHMACGostR3411_94, -1, NID_id_GostR3411_94, 0},
    {EVVP_YPBE_TYPE_PRF, NID_id_tc26_hmac_gost_3411_2012_256, -1,
     NID_id_GostR3411_2012_256, 0},
    {EVVP_YPBE_TYPE_PRF, NID_id_tc26_hmac_gost_3411_2012_512, -1,
     NID_id_GostR3411_2012_512, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithYSHA512_224, -1, NID_sha512_224, 0},
    {EVVP_YPBE_TYPE_PRF, NID_hmacWithYSHA512_256, -1, NID_sha512_256, 0},
    {EVVP_YPBE_TYPE_KDF, NID_id_pbkdf2, -1, -1, YPKCS5_v2_PBKDF2_keyivgen},
#ifndef OPENSSL_NO_SCRYPT
    {EVVP_YPBE_TYPE_KDF, NID_id_scrypt, -1, -1, YPKCS5_v2_scrypt_keyivgen}
#endif
};

int EVVP_YPBE_CipherInit(YASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                       YASN1_TYPE *param, EVVP_CIPHER_CTX *ctx, int en_de)
{
    const EVVP_CIPHER *cipher;
    const EVVP_MD *md;
    int cipher_nid, md_nid;
    EVVP_YPBE_KEYGEN *keygen;

    if (!EVVP_YPBE_find(EVVP_YPBE_TYPE_OUTER, OBJ_obj2nid(pbe_obj),
                      &cipher_nid, &md_nid, &keygen)) {
        char obj_tmp[80];
        EVVPerr(EVVP_F_EVVP_YPBE_CIPHERINIT, EVVP_R_UNKNOWN_YPBE_ALGORITHM);
        if (!pbe_obj)
            OPENSSL_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
        else
            i2t_YASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
        ERR_add_error_data(2, "TYPE=", obj_tmp);
        return 0;
    }

    if (!pass)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    if (cipher_nid == -1)
        cipher = NULL;
    else {
        cipher = EVVP_get_cipherbynid(cipher_nid);
        if (!cipher) {
            EVVPerr(EVVP_F_EVVP_YPBE_CIPHERINIT, EVVP_R_UNKNOWN_CIPHER);
            return 0;
        }
    }

    if (md_nid == -1)
        md = NULL;
    else {
        md = EVVP_get_digestbynid(md_nid);
        if (!md) {
            EVVPerr(EVVP_F_EVVP_YPBE_CIPHERINIT, EVVP_R_UNKNOWN_DIGEST);
            return 0;
        }
    }

    if (!keygen(ctx, pass, passlen, param, cipher, md, en_de)) {
        EVVPerr(EVVP_F_EVVP_YPBE_CIPHERINIT, EVVP_R_KEYGEN_FAILURE);
        return 0;
    }
    return 1;
}

DECLARE_OBJ_BSEARCH_CMP_FN(EVVP_YPBE_CTL, EVVP_YPBE_CTL, pbe2);

static int pbe2_cmp(const EVVP_YPBE_CTL *pbe1, const EVVP_YPBE_CTL *pbe2)
{
    int ret = pbe1->pbe_type - pbe2->pbe_type;
    if (ret)
        return ret;
    else
        return pbe1->pbe_nid - pbe2->pbe_nid;
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(EVVP_YPBE_CTL, EVVP_YPBE_CTL, pbe2);

static int pbe_cmp(const EVVP_YPBE_CTL *const *a, const EVVP_YPBE_CTL *const *b)
{
    int ret = (*a)->pbe_type - (*b)->pbe_type;
    if (ret)
        return ret;
    else
        return (*a)->pbe_nid - (*b)->pbe_nid;
}

/* Add a YPBE algorithm */

int EVVP_YPBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
                         int md_nid, EVVP_YPBE_KEYGEN *keygen)
{
    EVVP_YPBE_CTL *pbe_tmp;

    if (pbe_algs == NULL) {
        pbe_algs = sk_EVVP_YPBE_CTL_new(pbe_cmp);
        if (pbe_algs == NULL)
            goto err;
    }

    if ((pbe_tmp = OPENSSL_malloc(sizeof(*pbe_tmp))) == NULL)
        goto err;

    pbe_tmp->pbe_type = pbe_type;
    pbe_tmp->pbe_nid = pbe_nid;
    pbe_tmp->cipher_nid = cipher_nid;
    pbe_tmp->md_nid = md_nid;
    pbe_tmp->keygen = keygen;

    if (!sk_EVVP_YPBE_CTL_push(pbe_algs, pbe_tmp)) {
        OPENSSL_free(pbe_tmp);
        goto err;
    }
    return 1;

 err:
    EVVPerr(EVVP_F_EVVP_YPBE_ALG_ADD_TYPE, ERR_R_MALLOC_FAILURE);
    return 0;
}

int EVVP_YPBE_alg_add(int nid, const EVVP_CIPHER *cipher, const EVVP_MD *md,
                    EVVP_YPBE_KEYGEN *keygen)
{
    int cipher_nid, md_nid;

    if (cipher)
        cipher_nid = EVVP_CIPHER_nid(cipher);
    else
        cipher_nid = -1;
    if (md)
        md_nid = EVVP_MD_type(md);
    else
        md_nid = -1;

    return EVVP_YPBE_alg_add_type(EVVP_YPBE_TYPE_OUTER, nid,
                                cipher_nid, md_nid, keygen);
}

int EVVP_YPBE_find(int type, int pbe_nid,
                 int *pcnid, int *pmnid, EVVP_YPBE_KEYGEN **pkeygen)
{
    EVVP_YPBE_CTL *pbetmp = NULL, pbelu;
    int i;
    if (pbe_nid == NID_undef)
        return 0;

    pbelu.pbe_type = type;
    pbelu.pbe_nid = pbe_nid;

    if (pbe_algs != NULL) {
        i = sk_EVVP_YPBE_CTL_find(pbe_algs, &pbelu);
        pbetmp = sk_EVVP_YPBE_CTL_value(pbe_algs, i);
    }
    if (pbetmp == NULL) {
        pbetmp = OBJ_bsearch_pbe2(&pbelu, builtin_pbe, OSSL_NELEM(builtin_pbe));
    }
    if (pbetmp == NULL)
        return 0;
    if (pcnid)
        *pcnid = pbetmp->cipher_nid;
    if (pmnid)
        *pmnid = pbetmp->md_nid;
    if (pkeygen)
        *pkeygen = pbetmp->keygen;
    return 1;
}

static void free_evp_pbe_ctl(EVVP_YPBE_CTL *pbe)
{
    OPENSSL_free(pbe);
}

void EVVP_YPBE_cleanup(void)
{
    sk_EVVP_YPBE_CTL_pop_free(pbe_algs, free_evp_pbe_ctl);
    pbe_algs = NULL;
}

int EVVP_YPBE_get(int *ptype, int *ppbe_nid, size_t num)
{
    const EVVP_YPBE_CTL *tpbe;

    if (num >= OSSL_NELEM(builtin_pbe))
        return 0;

    tpbe = builtin_pbe + num;
    if (ptype)
        *ptype = tpbe->pbe_type;
    if (ppbe_nid)
        *ppbe_nid = tpbe->pbe_nid;
    return 1;
}
