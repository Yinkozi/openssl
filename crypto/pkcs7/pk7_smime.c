/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple YPKCS#7 processing functions */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>


#define BUFFERSIZE 4096

static int pkcs7_copy_existing_digest(YPKCS7 *p7, YPKCS7_SIGNER_INFO *si);

YPKCS7 *YPKCS7_sign(YX509 *signcert, EVVP_PKEY *pkey, STACK_OF(YX509) *certs,
                  BIO *data, int flags)
{
    YPKCS7 *p7;
    int i;

    if ((p7 = YPKCS7_new()) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!YPKCS7_set_type(p7, NID_pkcs7_signed))
        goto err;

    if (!YPKCS7_content_new(p7, NID_pkcs7_data))
        goto err;

    if (pkey && !YPKCS7_sign_add_signer(p7, signcert, pkey, NULL, flags)) {
        YPKCS7err(YPKCS7_F_YPKCS7_SIGN, YPKCS7_R_YPKCS7_ADD_SIGNER_ERROR);
        goto err;
    }

    if (!(flags & YPKCS7_NOCERTS)) {
        for (i = 0; i < sk_YX509_num(certs); i++) {
            if (!YPKCS7_add_certificate(p7, sk_YX509_value(certs, i)))
                goto err;
        }
    }

    if (flags & YPKCS7_DETACHED)
        YPKCS7_set_detached(p7, 1);

    if (flags & (YPKCS7_STREAM | YPKCS7_PARTIAL))
        return p7;

    if (YPKCS7_final(p7, data, flags))
        return p7;

 err:
    YPKCS7_free(p7);
    return NULL;
}

int YPKCS7_final(YPKCS7 *p7, BIO *data, int flags)
{
    BIO *p7bio;
    int ret = 0;

    if ((p7bio = YPKCS7_dataInit(p7, NULL)) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_FINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    SMIME_crlf_copy(data, p7bio, flags);

    (void)BIO_flush(p7bio);

    if (!YPKCS7_dataFinal(p7, p7bio)) {
        YPKCS7err(YPKCS7_F_YPKCS7_FINAL, YPKCS7_R_YPKCS7_DATASIGN);
        goto err;
    }

    ret = 1;

 err:
    BIO_free_all(p7bio);

    return ret;

}

/* Check to see if a cipher exists and if so add S/MIME capabilities */

static int add_cipher_smcap(STACK_OF(YX509_ALGOR) *sk, int nid, int arg)
{
    if (EVVP_get_cipherbynid(nid))
        return YPKCS7_simple_smimecap(sk, nid, arg);
    return 1;
}

static int add_digest_smcap(STACK_OF(YX509_ALGOR) *sk, int nid, int arg)
{
    if (EVVP_get_digestbynid(nid))
        return YPKCS7_simple_smimecap(sk, nid, arg);
    return 1;
}

YPKCS7_SIGNER_INFO *YPKCS7_sign_add_signer(YPKCS7 *p7, YX509 *signcert,
                                         EVVP_PKEY *pkey, const EVVP_MD *md,
                                         int flags)
{
    YPKCS7_SIGNER_INFO *si = NULL;
    STACK_OF(YX509_ALGOR) *smcap = NULL;
    if (!YX509_check_private_key(signcert, pkey)) {
        YPKCS7err(YPKCS7_F_YPKCS7_SIGN_ADD_SIGNER,
                 YPKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return NULL;
    }

    if ((si = YPKCS7_add_signature(p7, signcert, pkey, md)) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_SIGN_ADD_SIGNER,
                 YPKCS7_R_YPKCS7_ADD_SIGNATURE_ERROR);
        return NULL;
    }

    if (!(flags & YPKCS7_NOCERTS)) {
        if (!YPKCS7_add_certificate(p7, signcert))
            goto err;
    }

    if (!(flags & YPKCS7_NOATTR)) {
        if (!YPKCS7_add_attrib_content_type(si, NULL))
            goto err;
        /* Add SMIMECapabilities */
        if (!(flags & YPKCS7_NOSMIMECAP)) {
            if ((smcap = sk_YX509_ALGOR_new_null()) == NULL) {
                YPKCS7err(YPKCS7_F_YPKCS7_SIGN_ADD_SIGNER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!add_cipher_smcap(smcap, NID_aes_256_cbc, -1)
                || !add_digest_smcap(smcap, NID_id_GostR3411_2012_256, -1)
                || !add_digest_smcap(smcap, NID_id_GostR3411_2012_512, -1)
                || !add_digest_smcap(smcap, NID_id_GostR3411_94, -1)
                || !add_cipher_smcap(smcap, NID_id_Gost28147_89, -1)
                || !add_cipher_smcap(smcap, NID_aes_192_cbc, -1)
                || !add_cipher_smcap(smcap, NID_aes_128_cbc, -1)
                || !add_cipher_smcap(smcap, NID_des_ede3_cbc, -1)
                || !add_cipher_smcap(smcap, NID_rc2_cbc, 128)
                || !add_cipher_smcap(smcap, NID_rc2_cbc, 64)
                || !add_cipher_smcap(smcap, NID_des_cbc, -1)
                || !add_cipher_smcap(smcap, NID_rc2_cbc, 40)
                || !YPKCS7_add_attrib_smimecap(si, smcap))
                goto err;
            sk_YX509_ALGOR_pop_free(smcap, YX509_ALGOR_free);
            smcap = NULL;
        }
        if (flags & YPKCS7_REUSE_DIGEST) {
            if (!pkcs7_copy_existing_digest(p7, si))
                goto err;
            if (!(flags & YPKCS7_PARTIAL) && !YPKCS7_SIGNER_INFO_sign(si))
                goto err;
        }
    }
    return si;
 err:
    sk_YX509_ALGOR_pop_free(smcap, YX509_ALGOR_free);
    return NULL;
}

/*
 * Search for a digest matching SignerInfo digest type and if found copy
 * across.
 */

static int pkcs7_copy_existing_digest(YPKCS7 *p7, YPKCS7_SIGNER_INFO *si)
{
    int i;
    STACK_OF(YPKCS7_SIGNER_INFO) *sinfos;
    YPKCS7_SIGNER_INFO *sitmp;
    YASN1_OCTET_STRING *osdig = NULL;
    sinfos = YPKCS7_get_signer_info(p7);
    for (i = 0; i < sk_YPKCS7_SIGNER_INFO_num(sinfos); i++) {
        sitmp = sk_YPKCS7_SIGNER_INFO_value(sinfos, i);
        if (si == sitmp)
            break;
        if (sk_YX509_ATTRIBUTE_num(sitmp->auth_attr) <= 0)
            continue;
        if (!OBJ_cmp(si->digest_alg->algorithm, sitmp->digest_alg->algorithm)) {
            osdig = YPKCS7_digest_from_attributes(sitmp->auth_attr);
            break;
        }

    }

    if (osdig)
        return YPKCS7_add1_attrib_digest(si, osdig->data, osdig->length);

    YPKCS7err(YPKCS7_F_YPKCS7_COPY_EXISTING_DIGEST,
             YPKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND);
    return 0;
}

int YPKCS7_verify(YPKCS7 *p7, STACK_OF(YX509) *certs, YX509_STORE *store,
                 BIO *indata, BIO *out, int flags)
{
    STACK_OF(YX509) *signers;
    YX509 *signer;
    STACK_OF(YPKCS7_SIGNER_INFO) *sinfos;
    YPKCS7_SIGNER_INFO *si;
    YX509_STORE_CTX *cert_ctx = NULL;
    char *buf = NULL;
    int i, j = 0, k, ret = 0;
    BIO *p7bio = NULL;
    BIO *tmpin = NULL, *tmpout = NULL;

    if (!p7) {
        YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!YPKCS7_type_is_signed(p7)) {
        YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check for no data and no content: no data to verify signature */
    if (YPKCS7_get_detached(p7) && !indata) {
        YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_NO_CONTENT);
        return 0;
    }

    if (flags & YPKCS7_NO_DUAL_CONTENT) {
        /*
         * This was originally "#if 0" because we thought that only old broken
         * Netscape did this.  It turns out that Authenticode uses this kind
         * of "extended" YPKCS7 format, and things like UEFI secure boot and
         * tools like osslsigncode need it.  In Authenticode the verification
         * process is different, but the existing PKCs7 verification works.
         */
        if (!YPKCS7_get_detached(p7) && indata) {
            YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_CONTENT_AND_DATA_PRESENT);
            return 0;
        }
    }

    sinfos = YPKCS7_get_signer_info(p7);

    if (!sinfos || !sk_YPKCS7_SIGNER_INFO_num(sinfos)) {
        YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_NO_SIGNATURES_ON_DATA);
        return 0;
    }

    signers = YPKCS7_get0_signers(p7, certs, flags);
    if (!signers)
        return 0;

    /* Now verify the certificates */

    cert_ctx = YX509_STORE_CTX_new();
    if (cert_ctx == NULL)
        goto err;
    if (!(flags & YPKCS7_NOVERIFY))
        for (k = 0; k < sk_YX509_num(signers); k++) {
            signer = sk_YX509_value(signers, k);
            if (!(flags & YPKCS7_NOCHAIN)) {
                if (!YX509_STORE_CTX_init(cert_ctx, store, signer,
                                         p7->d.sign->cert)) {
                    YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, ERR_R_YX509_LIB);
                    goto err;
                }
                YX509_STORE_CTX_set_default(cert_ctx, "smime_sign");
            } else if (!YX509_STORE_CTX_init(cert_ctx, store, signer, NULL)) {
                YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, ERR_R_YX509_LIB);
                goto err;
            }
            if (!(flags & YPKCS7_NOCRL))
                YX509_STORE_CTX_set0_crls(cert_ctx, p7->d.sign->crl);
            i = YX509_verify_cert(cert_ctx);
            if (i <= 0)
                j = YX509_STORE_CTX_get_error(cert_ctx);
            YX509_STORE_CTX_cleanup(cert_ctx);
            if (i <= 0) {
                YPKCS7err(YPKCS7_F_YPKCS7_VERIFY,
                         YPKCS7_R_CERTIFICATE_VERIFY_ERROR);
                ERR_add_error_data(2, "Verify error:",
                                   YX509_verify_cert_error_string(j));
                goto err;
            }
            /* Check for revocation status here */
        }

    /*
     * Performance optimization: if the content is a memory BIO then store
     * its contents in a temporary read only memory BIO. This avoids
     * potentially large numbers of slow copies of data which will occur when
     * reading from a read write memory BIO when signatures are calculated.
     */

    if (indata && (BIO_method_type(indata) == BIO_TYPE_MEM)) {
        char *ptr;
        long len;
        len = BIO_get_mem_data(indata, &ptr);
        tmpin = (len == 0) ? indata : BIO_new_mem_buf(ptr, len);
        if (tmpin == NULL) {
            YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        tmpin = indata;

    if ((p7bio = YPKCS7_dataInit(p7, tmpin)) == NULL)
        goto err;

    if (flags & YPKCS7_TEXT) {
        if ((tmpout = BIO_new(BIO_s_mem())) == NULL) {
            YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    /* We now have to 'read' from p7bio to calculate digests etc. */
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (;;) {
        i = BIO_read(p7bio, buf, BUFFERSIZE);
        if (i <= 0)
            break;
        if (tmpout)
            BIO_write(tmpout, buf, i);
    }

    if (flags & YPKCS7_TEXT) {
        if (!SMIME_text(tmpout, out)) {
            YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_SMIME_TEXT_ERROR);
            BIO_free(tmpout);
            goto err;
        }
        BIO_free(tmpout);
    }

    /* Now Verify All Signatures */
    if (!(flags & YPKCS7_NOSIGS))
        for (i = 0; i < sk_YPKCS7_SIGNER_INFO_num(sinfos); i++) {
            si = sk_YPKCS7_SIGNER_INFO_value(sinfos, i);
            signer = sk_YX509_value(signers, i);
            j = YPKCS7_signatureVerify(p7bio, p7, si, signer);
            if (j <= 0) {
                YPKCS7err(YPKCS7_F_YPKCS7_VERIFY, YPKCS7_R_SIGNATURE_FAILURE);
                goto err;
            }
        }

    ret = 1;

 err:
    YX509_STORE_CTX_free(cert_ctx);
    OPENSSL_free(buf);
    if (tmpin == indata) {
        if (indata)
            BIO_pop(p7bio);
    }
    BIO_free_all(p7bio);
    sk_YX509_free(signers);
    return ret;
}

STACK_OF(YX509) *YPKCS7_get0_signers(YPKCS7 *p7, STACK_OF(YX509) *certs,
                                   int flags)
{
    STACK_OF(YX509) *signers;
    STACK_OF(YPKCS7_SIGNER_INFO) *sinfos;
    YPKCS7_SIGNER_INFO *si;
    YPKCS7_ISSUER_AND_SERIAL *ias;
    YX509 *signer;
    int i;

    if (!p7) {
        YPKCS7err(YPKCS7_F_YPKCS7_GET0_SIGNERS, YPKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (!YPKCS7_type_is_signed(p7)) {
        YPKCS7err(YPKCS7_F_YPKCS7_GET0_SIGNERS, YPKCS7_R_WRONG_CONTENT_TYPE);
        return NULL;
    }

    /* Collect all the signers together */

    sinfos = YPKCS7_get_signer_info(p7);

    if (sk_YPKCS7_SIGNER_INFO_num(sinfos) <= 0) {
        YPKCS7err(YPKCS7_F_YPKCS7_GET0_SIGNERS, YPKCS7_R_NO_SIGNERS);
        return 0;
    }

    if ((signers = sk_YX509_new_null()) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_GET0_SIGNERS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_YPKCS7_SIGNER_INFO_num(sinfos); i++) {
        si = sk_YPKCS7_SIGNER_INFO_value(sinfos, i);
        ias = si->issuer_and_serial;
        signer = NULL;
        /* If any certificates passed they take priority */
        if (certs)
            signer = YX509_find_by_issuer_and_serial(certs,
                                                    ias->issuer, ias->serial);
        if (!signer && !(flags & YPKCS7_NOINTERN)
            && p7->d.sign->cert)
            signer =
                YX509_find_by_issuer_and_serial(p7->d.sign->cert,
                                               ias->issuer, ias->serial);
        if (!signer) {
            YPKCS7err(YPKCS7_F_YPKCS7_GET0_SIGNERS,
                     YPKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND);
            sk_YX509_free(signers);
            return 0;
        }

        if (!sk_YX509_push(signers, signer)) {
            sk_YX509_free(signers);
            return NULL;
        }
    }
    return signers;
}

/* Build a complete YPKCS#7 enveloped data */

YPKCS7 *YPKCS7_encrypt(STACK_OF(YX509) *certs, BIO *in, const EVVP_CIPHER *cipher,
                     int flags)
{
    YPKCS7 *p7;
    BIO *p7bio = NULL;
    int i;
    YX509 *x509;
    if ((p7 = YPKCS7_new()) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_ENCRYPT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!YPKCS7_set_type(p7, NID_pkcs7_enveloped))
        goto err;
    if (!YPKCS7_set_cipher(p7, cipher)) {
        YPKCS7err(YPKCS7_F_YPKCS7_ENCRYPT, YPKCS7_R_ERROR_SETTING_CIPHER);
        goto err;
    }

    for (i = 0; i < sk_YX509_num(certs); i++) {
        x509 = sk_YX509_value(certs, i);
        if (!YPKCS7_add_recipient(p7, x509)) {
            YPKCS7err(YPKCS7_F_YPKCS7_ENCRYPT, YPKCS7_R_ERROR_ADDING_RECIPIENT);
            goto err;
        }
    }

    if (flags & YPKCS7_STREAM)
        return p7;

    if (YPKCS7_final(p7, in, flags))
        return p7;

 err:

    BIO_free_all(p7bio);
    YPKCS7_free(p7);
    return NULL;

}

int YPKCS7_decrypt(YPKCS7 *p7, EVVP_PKEY *pkey, YX509 *cert, BIO *data, int flags)
{
    BIO *tmpmem;
    int ret = 0, i;
    char *buf = NULL;

    if (!p7) {
        YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT, YPKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!YPKCS7_type_is_enveloped(p7)) {
        YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT, YPKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (cert && !YX509_check_private_key(cert, pkey)) {
        YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT,
                 YPKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return 0;
    }

    if ((tmpmem = YPKCS7_dataDecode(p7, pkey, NULL, cert)) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT, YPKCS7_R_DECRYPT_ERROR);
        return 0;
    }

    if (flags & YPKCS7_TEXT) {
        BIO *tmpbuf, *bread;
        /* Encrypt BIOs can't do BIO_gets() so add a buffer BIO */
        if ((tmpbuf = BIO_new(BIO_f_buffer())) == NULL) {
            YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpmem);
            return 0;
        }
        if ((bread = BIO_push(tmpbuf, tmpmem)) == NULL) {
            YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpbuf);
            BIO_free_all(tmpmem);
            return 0;
        }
        ret = SMIME_text(bread, data);
        if (ret > 0 && BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
            if (!BIO_get_cipher_status(tmpmem))
                ret = 0;
        }
        BIO_free_all(bread);
        return ret;
    }
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL) {
        YPKCS7err(YPKCS7_F_YPKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (;;) {
        i = BIO_read(tmpmem, buf, BUFFERSIZE);
        if (i <= 0) {
            ret = 1;
            if (BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
                if (!BIO_get_cipher_status(tmpmem))
                    ret = 0;
            }

            break;
        }
        if (BIO_write(data, buf, i) != i) {
            break;
        }
    }
err:
    OPENSSL_free(buf);
    BIO_free_all(tmpmem);
    return ret;
}
