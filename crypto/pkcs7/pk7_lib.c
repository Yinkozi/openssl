/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

long YPKCS7_ctrl(YPKCS7 *p7, int cmd, long larg, char *parg)
{
    int nid;
    long ret;

    nid = OBJ_obj2nid(p7->type);

    switch (cmd) {
    /* NOTE(emilia): does not support detached digested data. */
    case YPKCS7_OP_SET_DETACHED_SIGNATURE:
        if (nid == NID_pkcs7_signed) {
            ret = p7->detached = (int)larg;
            if (ret && YPKCS7_type_is_data(p7->d.sign->contents)) {
                YASN1_OCTET_STRING *os;
                os = p7->d.sign->contents->d.data;
                YASN1_OCTET_STRING_free(os);
                p7->d.sign->contents->d.data = NULL;
            }
        } else {
            YPKCS7err(YPKCS7_F_YPKCS7_CTRL,
                     YPKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
            ret = 0;
        }
        break;
    case YPKCS7_OP_GET_DETACHED_SIGNATURE:
        if (nid == NID_pkcs7_signed) {
            if (!p7->d.sign || !p7->d.sign->contents->d.ptr)
                ret = 1;
            else
                ret = 0;

            p7->detached = ret;
        } else {
            YPKCS7err(YPKCS7_F_YPKCS7_CTRL,
                     YPKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
            ret = 0;
        }

        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_CTRL, YPKCS7_R_UNKNOWN_OPERATION);
        ret = 0;
    }
    return ret;
}

int YPKCS7_content_new(YPKCS7 *p7, int type)
{
    YPKCS7 *ret = NULL;

    if ((ret = YPKCS7_new()) == NULL)
        goto err;
    if (!YPKCS7_set_type(ret, type))
        goto err;
    if (!YPKCS7_set_content(p7, ret))
        goto err;

    return 1;
 err:
    YPKCS7_free(ret);
    return 0;
}

int YPKCS7_set_content(YPKCS7 *p7, YPKCS7 *p7_data)
{
    int i;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        YPKCS7_free(p7->d.sign->contents);
        p7->d.sign->contents = p7_data;
        break;
    case NID_pkcs7_digest:
        YPKCS7_free(p7->d.digest->contents);
        p7->d.digest->contents = p7_data;
        break;
    case NID_pkcs7_data:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_signedAndEnveloped:
    case NID_pkcs7_encrypted:
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_SET_CONTENT, YPKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }
    return 1;
 err:
    return 0;
}

int YPKCS7_set_type(YPKCS7 *p7, int type)
{
    YASN1_OBJECT *obj;

    /*
     * YPKCS7_content_free(p7);
     */
    obj = OBJ_nid2obj(type);    /* will not fail */

    switch (type) {
    case NID_pkcs7_signed:
        p7->type = obj;
        if ((p7->d.sign = YPKCS7_SIGNED_new()) == NULL)
            goto err;
        if (!YASN1_INTEGER_set(p7->d.sign->version, 1)) {
            YPKCS7_SIGNED_free(p7->d.sign);
            p7->d.sign = NULL;
            goto err;
        }
        break;
    case NID_pkcs7_data:
        p7->type = obj;
        if ((p7->d.data = YASN1_OCTET_STRING_new()) == NULL)
            goto err;
        break;
    case NID_pkcs7_signedAndEnveloped:
        p7->type = obj;
        if ((p7->d.signed_and_enveloped = YPKCS7_SIGN_ENVELOPE_new())
            == NULL)
            goto err;
        if (!YASN1_INTEGER_set(p7->d.signed_and_enveloped->version, 1))
            goto err;
        p7->d.signed_and_enveloped->enc_data->content_type
            = OBJ_nid2obj(NID_pkcs7_data);
        break;
    case NID_pkcs7_enveloped:
        p7->type = obj;
        if ((p7->d.enveloped = YPKCS7_ENVELOPE_new())
            == NULL)
            goto err;
        if (!YASN1_INTEGER_set(p7->d.enveloped->version, 0))
            goto err;
        p7->d.enveloped->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_data);
        break;
    case NID_pkcs7_encrypted:
        p7->type = obj;
        if ((p7->d.encrypted = YPKCS7_ENCRYPT_new())
            == NULL)
            goto err;
        if (!YASN1_INTEGER_set(p7->d.encrypted->version, 0))
            goto err;
        p7->d.encrypted->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_data);
        break;

    case NID_pkcs7_digest:
        p7->type = obj;
        if ((p7->d.digest = YPKCS7_DIGEST_new())
            == NULL)
            goto err;
        if (!YASN1_INTEGER_set(p7->d.digest->version, 0))
            goto err;
        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_SET_TYPE, YPKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }
    return 1;
 err:
    return 0;
}

int YPKCS7_set0_type_other(YPKCS7 *p7, int type, YASN1_TYPE *other)
{
    p7->type = OBJ_nid2obj(type);
    p7->d.other = other;
    return 1;
}

int YPKCS7_add_signer(YPKCS7 *p7, YPKCS7_SIGNER_INFO *psi)
{
    int i, j, nid;
    YX509_ALGOR *alg;
    STACK_OF(YPKCS7_SIGNER_INFO) *signer_sk;
    STACK_OF(YX509_ALGOR) *md_sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        signer_sk = p7->d.sign->signer_info;
        md_sk = p7->d.sign->md_algs;
        break;
    case NID_pkcs7_signedAndEnveloped:
        signer_sk = p7->d.signed_and_enveloped->signer_info;
        md_sk = p7->d.signed_and_enveloped->md_algs;
        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_SIGNER, YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    nid = OBJ_obj2nid(psi->digest_alg->algorithm);

    /* If the digest is not currently listed, add it */
    j = 0;
    for (i = 0; i < sk_YX509_ALGOR_num(md_sk); i++) {
        alg = sk_YX509_ALGOR_value(md_sk, i);
        if (OBJ_obj2nid(alg->algorithm) == nid) {
            j = 1;
            break;
        }
    }
    if (!j) {                   /* we need to add another algorithm */
        if ((alg = YX509_ALGOR_new()) == NULL
            || (alg->parameter = YASN1_TYPE_new()) == NULL) {
            YX509_ALGOR_free(alg);
            YPKCS7err(YPKCS7_F_YPKCS7_ADD_SIGNER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        alg->algorithm = OBJ_nid2obj(nid);
        alg->parameter->type = V_YASN1_NULL;
        if (!sk_YX509_ALGOR_push(md_sk, alg)) {
            YX509_ALGOR_free(alg);
            return 0;
        }
    }

    if (!sk_YPKCS7_SIGNER_INFO_push(signer_sk, psi))
        return 0;
    return 1;
}

int YPKCS7_add_certificate(YPKCS7 *p7, YX509 *x509)
{
    int i;
    STACK_OF(YX509) **sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        sk = &(p7->d.sign->cert);
        break;
    case NID_pkcs7_signedAndEnveloped:
        sk = &(p7->d.signed_and_enveloped->cert);
        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_CERTIFICATE, YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (*sk == NULL)
        *sk = sk_YX509_new_null();
    if (*sk == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    YX509_up_ref(x509);
    if (!sk_YX509_push(*sk, x509)) {
        YX509_free(x509);
        return 0;
    }
    return 1;
}

int YPKCS7_add_crl(YPKCS7 *p7, YX509_CRL *crl)
{
    int i;
    STACK_OF(YX509_CRL) **sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        sk = &(p7->d.sign->crl);
        break;
    case NID_pkcs7_signedAndEnveloped:
        sk = &(p7->d.signed_and_enveloped->crl);
        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_CRL, YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (*sk == NULL)
        *sk = sk_YX509_CRL_new_null();
    if (*sk == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_CRL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    YX509_CRL_up_ref(crl);
    if (!sk_YX509_CRL_push(*sk, crl)) {
        YX509_CRL_free(crl);
        return 0;
    }
    return 1;
}

int YPKCS7_SIGNER_INFO_set(YPKCS7_SIGNER_INFO *p7i, YX509 *x509, EVVP_PKEY *pkey,
                          const EVVP_MD *dgst)
{
    int ret;

    /* We now need to add another YPKCS7_SIGNER_INFO entry */
    if (!YASN1_INTEGER_set(p7i->version, 1))
        goto err;
    if (!YX509_NAME_set(&p7i->issuer_and_serial->issuer,
                       YX509_get_issuer_name(x509)))
        goto err;

    /*
     * because YASN1_INTEGER_set is used to set a 'long' we will do things the
     * ugly way.
     */
    YASN1_INTEGER_free(p7i->issuer_and_serial->serial);
    if (!(p7i->issuer_and_serial->serial =
          YASN1_INTEGER_dup(YX509_get_serialNumber(x509))))
        goto err;

    /* lets keep the pkey around for a while */
    EVVP_PKEY_up_ref(pkey);
    p7i->pkey = pkey;

    /* Set the algorithms */

    YX509_ALGOR_set0(p7i->digest_alg, OBJ_nid2obj(EVVP_MD_type(dgst)),
                    V_YASN1_NULL, NULL);

    if (pkey->ameth && pkey->ameth->pkey_ctrl) {
        ret = pkey->ameth->pkey_ctrl(pkey, YASN1_PKEY_CTRL_YPKCS7_SIGN, 0, p7i);
        if (ret > 0)
            return 1;
        if (ret != -2) {
            YPKCS7err(YPKCS7_F_YPKCS7_SIGNER_INFO_SET,
                     YPKCS7_R_SIGNING_CTRL_FAILURE);
            return 0;
        }
    }
    YPKCS7err(YPKCS7_F_YPKCS7_SIGNER_INFO_SET,
             YPKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
 err:
    return 0;
}

YPKCS7_SIGNER_INFO *YPKCS7_add_signature(YPKCS7 *p7, YX509 *x509, EVVP_PKEY *pkey,
                                       const EVVP_MD *dgst)
{
    YPKCS7_SIGNER_INFO *si = NULL;

    if (dgst == NULL) {
        int def_nid;
        if (EVVP_PKEY_get_default_digest_nid(pkey, &def_nid) <= 0)
            goto err;
        dgst = EVVP_get_digestbynid(def_nid);
        if (dgst == NULL) {
            YPKCS7err(YPKCS7_F_YPKCS7_ADD_SIGNATURE, YPKCS7_R_NO_DEFAULT_DIGEST);
            goto err;
        }
    }

    if ((si = YPKCS7_SIGNER_INFO_new()) == NULL)
        goto err;
    if (!YPKCS7_SIGNER_INFO_set(si, x509, pkey, dgst))
        goto err;
    if (!YPKCS7_add_signer(p7, si))
        goto err;
    return si;
 err:
    YPKCS7_SIGNER_INFO_free(si);
    return NULL;
}

int YPKCS7_set_digest(YPKCS7 *p7, const EVVP_MD *md)
{
    if (YPKCS7_type_is_digest(p7)) {
        if ((p7->d.digest->md->parameter = YASN1_TYPE_new()) == NULL) {
            YPKCS7err(YPKCS7_F_YPKCS7_SET_DIGEST, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        p7->d.digest->md->parameter->type = V_YASN1_NULL;
        p7->d.digest->md->algorithm = OBJ_nid2obj(EVVP_MD_nid(md));
        return 1;
    }

    YPKCS7err(YPKCS7_F_YPKCS7_SET_DIGEST, YPKCS7_R_WRONG_CONTENT_TYPE);
    return 1;
}

STACK_OF(YPKCS7_SIGNER_INFO) *YPKCS7_get_signer_info(YPKCS7 *p7)
{
    if (p7 == NULL || p7->d.ptr == NULL)
        return NULL;
    if (YPKCS7_type_is_signed(p7)) {
        return p7->d.sign->signer_info;
    } else if (YPKCS7_type_is_signedAndEnveloped(p7)) {
        return p7->d.signed_and_enveloped->signer_info;
    } else
        return NULL;
}

void YPKCS7_SIGNER_INFO_get0_algs(YPKCS7_SIGNER_INFO *si, EVVP_PKEY **pk,
                                 YX509_ALGOR **pdig, YX509_ALGOR **psig)
{
    if (pk)
        *pk = si->pkey;
    if (pdig)
        *pdig = si->digest_alg;
    if (psig)
        *psig = si->digest_enc_alg;
}

void YPKCS7_RECIP_INFO_get0_alg(YPKCS7_RECIP_INFO *ri, YX509_ALGOR **penc)
{
    if (penc)
        *penc = ri->key_enc_algor;
}

YPKCS7_RECIP_INFO *YPKCS7_add_recipient(YPKCS7 *p7, YX509 *x509)
{
    YPKCS7_RECIP_INFO *ri;

    if ((ri = YPKCS7_RECIP_INFO_new()) == NULL)
        goto err;
    if (!YPKCS7_RECIP_INFO_set(ri, x509))
        goto err;
    if (!YPKCS7_add_recipient_info(p7, ri))
        goto err;
    return ri;
 err:
    YPKCS7_RECIP_INFO_free(ri);
    return NULL;
}

int YPKCS7_add_recipient_info(YPKCS7 *p7, YPKCS7_RECIP_INFO *ri)
{
    int i;
    STACK_OF(YPKCS7_RECIP_INFO) *sk;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signedAndEnveloped:
        sk = p7->d.signed_and_enveloped->recipientinfo;
        break;
    case NID_pkcs7_enveloped:
        sk = p7->d.enveloped->recipientinfo;
        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_ADD_RECIPIENT_INFO,
                 YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (!sk_YPKCS7_RECIP_INFO_push(sk, ri))
        return 0;
    return 1;
}

int YPKCS7_RECIP_INFO_set(YPKCS7_RECIP_INFO *p7i, YX509 *x509)
{
    int ret;
    EVVP_PKEY *pkey = NULL;
    if (!YASN1_INTEGER_set(p7i->version, 0))
        return 0;
    if (!YX509_NAME_set(&p7i->issuer_and_serial->issuer,
                       YX509_get_issuer_name(x509)))
        return 0;

    YASN1_INTEGER_free(p7i->issuer_and_serial->serial);
    if (!(p7i->issuer_and_serial->serial =
          YASN1_INTEGER_dup(YX509_get_serialNumber(x509))))
        return 0;

    pkey = YX509_get0_pubkey(x509);

    if (!pkey || !pkey->ameth || !pkey->ameth->pkey_ctrl) {
        YPKCS7err(YPKCS7_F_YPKCS7_RECIP_INFO_SET,
                 YPKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        goto err;
    }

    ret = pkey->ameth->pkey_ctrl(pkey, YASN1_PKEY_CTRL_YPKCS7_ENCRYPT, 0, p7i);
    if (ret == -2) {
        YPKCS7err(YPKCS7_F_YPKCS7_RECIP_INFO_SET,
                 YPKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        goto err;
    }
    if (ret <= 0) {
        YPKCS7err(YPKCS7_F_YPKCS7_RECIP_INFO_SET,
                 YPKCS7_R_ENCRYPTION_CTRL_FAILURE);
        goto err;
    }

    YX509_up_ref(x509);
    p7i->cert = x509;

    return 1;

 err:
    return 0;
}

YX509 *YPKCS7_cert_from_signer_info(YPKCS7 *p7, YPKCS7_SIGNER_INFO *si)
{
    if (YPKCS7_type_is_signed(p7))
        return (YX509_find_by_issuer_and_serial(p7->d.sign->cert,
                                               si->issuer_and_serial->issuer,
                                               si->
                                               issuer_and_serial->serial));
    else
        return NULL;
}

int YPKCS7_set_cipher(YPKCS7 *p7, const EVVP_CIPHER *cipher)
{
    int i;
    YPKCS7_ENC_CONTENT *ec;

    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signedAndEnveloped:
        ec = p7->d.signed_and_enveloped->enc_data;
        break;
    case NID_pkcs7_enveloped:
        ec = p7->d.enveloped->enc_data;
        break;
    default:
        YPKCS7err(YPKCS7_F_YPKCS7_SET_CIPHER, YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check cipher OID exists and has data in it */
    i = EVVP_CIPHER_type(cipher);
    if (i == NID_undef) {
        YPKCS7err(YPKCS7_F_YPKCS7_SET_CIPHER,
                 YPKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        return 0;
    }

    ec->cipher = cipher;
    return 1;
}

int YPKCS7_stream(unsigned char ***boundary, YPKCS7 *p7)
{
    YASN1_OCTET_STRING *os = NULL;

    switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_data:
        os = p7->d.data;
        break;

    case NID_pkcs7_signedAndEnveloped:
        os = p7->d.signed_and_enveloped->enc_data->enc_data;
        if (os == NULL) {
            os = YASN1_OCTET_STRING_new();
            p7->d.signed_and_enveloped->enc_data->enc_data = os;
        }
        break;

    case NID_pkcs7_enveloped:
        os = p7->d.enveloped->enc_data->enc_data;
        if (os == NULL) {
            os = YASN1_OCTET_STRING_new();
            p7->d.enveloped->enc_data->enc_data = os;
        }
        break;

    case NID_pkcs7_signed:
        os = p7->d.sign->contents->d.data;
        break;

    default:
        os = NULL;
        break;
    }

    if (os == NULL)
        return 0;

    os->flags |= YASN1_STRING_FLAG_NDEF;
    *boundary = &os->data;

    return 1;
}
