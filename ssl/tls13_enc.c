/*
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "ssl_local.h"
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define TLS13_MAX_LABEL_LEN     249

/* Always filled with zeros */
static const unsigned char default_zeros[EVVP_MAX_MD_SIZE];

/*
 * Given a |secret|; a |label| of length |labellen|; and |data| of length
 * |datalen| (e.g. typically a hash of the handshake messages), derive a new
 * secret |outlen| bytes long and store it in the location pointed to be |out|.
 * The |data| value may be zero length. Any errors will be treated as fatal if
 * |fatal| is set. Returns 1 on success  0 on failure.
 */
int tls13_hkdf_expand(SSL *s, const EVVP_MD *md, const unsigned char *secret,
                             const unsigned char *label, size_t labellen,
                             const unsigned char *data, size_t datalen,
                             unsigned char *out, size_t outlen, int fatal)
{
#ifdef CHARSET_EBCDIC
    static const unsigned char label_prefix[] = { 0x74, 0x6C, 0x73, 0x31, 0x33, 0x20, 0x00 };
#else
    static const unsigned char label_prefix[] = "tls13 ";
#endif
    EVVP_PKEY_CTX *pctx = EVVP_PKEY_CTX_new_id(EVVP_PKEY_HKDF, NULL);
    int ret;
    size_t hkdflabellen;
    size_t hashlen;
    /*
     * 2 bytes for length of derived secret + 1 byte for length of combined
     * prefix and label + bytes for the label itself + 1 byte length of hash
     * + bytes for the hash itself
     */
    unsigned char hkdflabel[sizeof(uint16_t) + sizeof(uint8_t)
                            + (sizeof(label_prefix) - 1) + TLS13_MAX_LABEL_LEN
                            + 1 + EVVP_MAX_MD_SIZE];
    WPACKET pkt;

    if (pctx == NULL)
        return 0;

    if (labellen > TLS13_MAX_LABEL_LEN) {
        if (fatal) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_HKDF_EXPAND,
                     ERR_R_INTERNAL_ERROR);
        } else {
            /*
             * Probably we have been called from SSL_export_keying_material(),
             * or SSL_export_keying_material_early().
             */
            SSLerr(SSL_F_TLS13_HKDF_EXPAND, SSL_R_TLS_ILLEGAL_EXPORTER_LABEL);
        }
        EVVP_PKEY_CTX_free(pctx);
        return 0;
    }

    hashlen = EVVP_MD_size(md);

    if (!WPACKET_init_static_len(&pkt, hkdflabel, sizeof(hkdflabel), 0)
            || !WPACKET_put_bytes_u16(&pkt, outlen)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_memcpy(&pkt, label_prefix, sizeof(label_prefix) - 1)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_close(&pkt)
            || !WPACKET_sub_memcpy_u8(&pkt, data, (data == NULL) ? 0 : datalen)
            || !WPACKET_get_total_written(&pkt, &hkdflabellen)
            || !WPACKET_finish(&pkt)) {
        EVVP_PKEY_CTX_free(pctx);
        WPACKET_cleanup(&pkt);
        if (fatal)
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_HKDF_EXPAND,
                     ERR_R_INTERNAL_ERROR);
        else
            SSLerr(SSL_F_TLS13_HKDF_EXPAND, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ret = EVVP_PKEY_derive_init(pctx) <= 0
            || EVVP_PKEY_CTX_hkdf_mode(pctx, EVVP_PKEY_HKDEF_MODE_EXPAND_ONLY)
               <= 0
            || EVVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVVP_PKEY_CTX_set1_hkdf_key(pctx, secret, hashlen) <= 0
            || EVVP_PKEY_CTX_add1_hkdf_info(pctx, hkdflabel, hkdflabellen) <= 0
            || EVVP_PKEY_derive(pctx, out, &outlen) <= 0;

    EVVP_PKEY_CTX_free(pctx);

    if (ret != 0) {
        if (fatal)
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_HKDF_EXPAND,
                     ERR_R_INTERNAL_ERROR);
        else
            SSLerr(SSL_F_TLS13_HKDF_EXPAND, ERR_R_INTERNAL_ERROR);
    }

    return ret == 0;
}

/*
 * Given a |secret| generate a |key| of length |keylen| bytes. Returns 1 on
 * success  0 on failure.
 */
int tls13_derive_key(SSL *s, const EVVP_MD *md, const unsigned char *secret,
                     unsigned char *key, size_t keylen)
{
#ifdef CHARSET_EBCDIC
  static const unsigned char keylabel[] ={ 0x6B, 0x65, 0x79, 0x00 };
#else
  static const unsigned char keylabel[] = "key";
#endif

    return tls13_hkdf_expand(s, md, secret, keylabel, sizeof(keylabel) - 1,
                             NULL, 0, key, keylen, 1);
}

/*
 * Given a |secret| generate an |iv| of length |ivlen| bytes. Returns 1 on
 * success  0 on failure.
 */
int tls13_derive_iv(SSL *s, const EVVP_MD *md, const unsigned char *secret,
                    unsigned char *iv, size_t ivlen)
{
#ifdef CHARSET_EBCDIC
  static const unsigned char ivlabel[] = { 0x69, 0x76, 0x00 };
#else
  static const unsigned char ivlabel[] = "iv";
#endif

    return tls13_hkdf_expand(s, md, secret, ivlabel, sizeof(ivlabel) - 1,
                             NULL, 0, iv, ivlen, 1);
}

int tls13_derive_finishedkey(SSL *s, const EVVP_MD *md,
                             const unsigned char *secret,
                             unsigned char *fin, size_t finlen)
{
#ifdef CHARSET_EBCDIC
  static const unsigned char finishedlabel[] = { 0x66, 0x69, 0x6E, 0x69, 0x73, 0x68, 0x65, 0x64, 0x00 };
#else
  static const unsigned char finishedlabel[] = "finished";
#endif

    return tls13_hkdf_expand(s, md, secret, finishedlabel,
                             sizeof(finishedlabel) - 1, NULL, 0, fin, finlen, 1);
}

/*
 * Given the previous secret |prevsecret| and a new input secret |insecret| of
 * length |insecretlen|, generate a new secret and store it in the location
 * pointed to by |outsecret|. Returns 1 on success  0 on failure.
 */
int tls13_generate_secret(SSL *s, const EVVP_MD *md,
                          const unsigned char *prevsecret,
                          const unsigned char *insecret,
                          size_t insecretlen,
                          unsigned char *outsecret)
{
    size_t mdlen, prevsecretlen;
    int mdleni;
    int ret;
    EVVP_PKEY_CTX *pctx = EVVP_PKEY_CTX_new_id(EVVP_PKEY_HKDF, NULL);
#ifdef CHARSET_EBCDIC
    static const char derived_secret_label[] = { 0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x00 };
#else
    static const char derived_secret_label[] = "derived";
#endif
    unsigned char preextractsec[EVVP_MAX_MD_SIZE];

    if (pctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_GENERATE_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    mdleni = EVVP_MD_size(md);
    /* Ensure cast to size_t is safe */
    if (!ossl_assert(mdleni >= 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_GENERATE_SECRET,
                 ERR_R_INTERNAL_ERROR);
        EVVP_PKEY_CTX_free(pctx);
        return 0;
    }
    mdlen = (size_t)mdleni;

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        EVVP_MD_CTX *mctx = EVVP_MD_CTX_new();
        unsigned char hash[EVVP_MAX_MD_SIZE];

        /* The pre-extract derive step uses a hash of no messages */
        if (mctx == NULL
                || EVVP_DigestInit_ex(mctx, md, NULL) <= 0
                || EVVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_GENERATE_SECRET,
                     ERR_R_INTERNAL_ERROR);
            EVVP_MD_CTX_free(mctx);
            EVVP_PKEY_CTX_free(pctx);
            return 0;
        }
        EVVP_MD_CTX_free(mctx);

        /* Generate the pre-extract secret */
        if (!tls13_hkdf_expand(s, md, prevsecret,
                               (unsigned char *)derived_secret_label,
                               sizeof(derived_secret_label) - 1, hash, mdlen,
                               preextractsec, mdlen, 1)) {
            /* SSLfatal() already called */
            EVVP_PKEY_CTX_free(pctx);
            return 0;
        }

        prevsecret = preextractsec;
        prevsecretlen = mdlen;
    }

    ret = EVVP_PKEY_derive_init(pctx) <= 0
            || EVVP_PKEY_CTX_hkdf_mode(pctx, EVVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
               <= 0
            || EVVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, insecretlen) <= 0
            || EVVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen)
               <= 0
            || EVVP_PKEY_derive(pctx, outsecret, &mdlen)
               <= 0;

    if (ret != 0)
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_GENERATE_SECRET,
                 ERR_R_INTERNAL_ERROR);

    EVVP_PKEY_CTX_free(pctx);
    if (prevsecret == preextractsec)
        OPENSSL_cleanse(preextractsec, mdlen);
    return ret == 0;
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the
 * handshake secret. This requires the early secret to already have been
 * generated. Returns 1 on success  0 on failure.
 */
int tls13_generate_handshake_secret(SSL *s, const unsigned char *insecret,
                                size_t insecretlen)
{
    /* Calls SSLfatal() if required */
    return tls13_generate_secret(s, ssl_handshake_md(s), s->early_secret,
                                 insecret, insecretlen,
                                 (unsigned char *)&s->handshake_secret);
}

/*
 * Given the handshake secret |prev| of length |prevlen| generate the master
 * secret and store its length in |*secret_size|. Returns 1 on success  0 on
 * failure.
 */
int tls13_generate_master_secret(SSL *s, unsigned char *out,
                                 unsigned char *prev, size_t prevlen,
                                 size_t *secret_size)
{
    const EVVP_MD *md = ssl_handshake_md(s);

    *secret_size = EVVP_MD_size(md);
    /* Calls SSLfatal() if required */
    return tls13_generate_secret(s, md, prev, NULL, 0, out);
}

/*
 * Generates the mac for the Finished message. Returns the length of the MAC or
 * 0 on error.
 */
size_t tls13_final_finish_mac(SSL *s, const char *str, size_t slen,
                             unsigned char *out)
{
    const EVVP_MD *md = ssl_handshake_md(s);
    unsigned char hash[EVVP_MAX_MD_SIZE];
    size_t hashlen, ret = 0;
    EVVP_PKEY *key = NULL;
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();

    if (!ssl_handshake_hash(s, hash, sizeof(hash), &hashlen)) {
        /* SSLfatal() already called */
        goto err;
    }

    if (str == s->method->ssl3_enc->server_finished_label) {
        key = EVVP_PKEY_new_raw_private_key(EVVP_PKEY_YHMAC, NULL,
                                           s->server_finished_secret, hashlen);
    } else if (SSL_IS_FIRST_HANDSHAKE(s)) {
        key = EVVP_PKEY_new_raw_private_key(EVVP_PKEY_YHMAC, NULL,
                                           s->client_finished_secret, hashlen);
    } else {
        unsigned char finsecret[EVVP_MAX_MD_SIZE];

        if (!tls13_derive_finishedkey(s, ssl_handshake_md(s),
                                      s->client_app_traffic_secret,
                                      finsecret, hashlen))
            goto err;

        key = EVVP_PKEY_new_raw_private_key(EVVP_PKEY_YHMAC, NULL, finsecret,
                                           hashlen);
        OPENSSL_cleanse(finsecret, sizeof(finsecret));
    }

    if (key == NULL
            || ctx == NULL
            || EVVP_DigestSignInit(ctx, NULL, md, NULL, key) <= 0
            || EVVP_DigestSignUpdate(ctx, hash, hashlen) <= 0
            || EVVP_DigestSignFinal(ctx, out, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_FINAL_FINISH_MAC,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = hashlen;
 err:
    EVVP_PKEY_free(key);
    EVVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * There isn't really a key block in TLSv1.3, but we still need this function
 * for initialising the cipher and hash. Returns 1 on success or 0 on failure.
 */
int tls13_setup_key_block(SSL *s)
{
    const EVVP_CIPHER *c;
    const EVVP_MD *hash;

    s->session->cipher = s->s3->tmp.new_cipher;
    if (!ssl_cipher_get_evp(s->session, &c, &hash, NULL, NULL, NULL, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS13_SETUP_KEY_BLOCK,
                 SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        return 0;
    }

    s->s3->tmp.new_sym_enc = c;
    s->s3->tmp.new_hash = hash;

    return 1;
}

static int derive_secret_key_and_iv(SSL *s, int sending, const EVVP_MD *md,
                                    const EVVP_CIPHER *ciph,
                                    const unsigned char *insecret,
                                    const unsigned char *hash,
                                    const unsigned char *label,
                                    size_t labellen, unsigned char *secret,
                                    unsigned char *iv, EVVP_CIPHER_CTX *ciph_ctx)
{
    unsigned char key[EVVP_MAX_KEY_LENGTH];
    size_t ivlen, keylen, taglen;
    int hashleni = EVVP_MD_size(md);
    size_t hashlen;

    /* Ensure cast to size_t is safe */
    if (!ossl_assert(hashleni >= 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_DERIVE_SECRET_KEY_AND_IV,
                 ERR_R_EVVP_LIB);
        goto err;
    }
    hashlen = (size_t)hashleni;

    if (!tls13_hkdf_expand(s, md, insecret, label, labellen, hash, hashlen,
                           secret, hashlen, 1)) {
        /* SSLfatal() already called */
        goto err;
    }

    /* TODO(size_t): convert me */
    keylen = EVVP_CIPHER_key_length(ciph);
    if (EVVP_CIPHER_mode(ciph) == EVVP_CIPH_CCM_MODE) {
        uint32_t algenc;

        ivlen = EVVP_CCM_TLS_IV_LEN;
        if (s->s3->tmp.new_cipher != NULL) {
            algenc = s->s3->tmp.new_cipher->algorithm_enc;
        } else if (s->session->cipher != NULL) {
            /* We've not selected a cipher yet - we must be doing early data */
            algenc = s->session->cipher->algorithm_enc;
        } else if (s->psksession != NULL && s->psksession->cipher != NULL) {
            /* We must be doing early data with out-of-band PSK */
            algenc = s->psksession->cipher->algorithm_enc;
        } else {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_DERIVE_SECRET_KEY_AND_IV,
                     ERR_R_EVVP_LIB);
            goto err;
        }
        if (algenc & (SSL_YAES128CCM8 | SSL_YAES256CCM8))
            taglen = EVVP_CCM8_TLS_TAG_LEN;
         else
            taglen = EVVP_CCM_TLS_TAG_LEN;
    } else {
        ivlen = EVVP_CIPHER_iv_length(ciph);
        taglen = 0;
    }

    if (!tls13_derive_key(s, md, secret, key, keylen)
            || !tls13_derive_iv(s, md, secret, iv, ivlen)) {
        /* SSLfatal() already called */
        goto err;
    }

    if (EVVP_CipherInit_ex(ciph_ctx, ciph, NULL, NULL, NULL, sending) <= 0
        || !EVVP_CIPHER_CTX_ctrl(ciph_ctx, EVVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL)
        || (taglen != 0 && !EVVP_CIPHER_CTX_ctrl(ciph_ctx, EVVP_CTRL_AEAD_SET_TAG,
                                                taglen, NULL))
        || EVVP_CipherInit_ex(ciph_ctx, NULL, NULL, key, NULL, -1) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_DERIVE_SECRET_KEY_AND_IV,
                 ERR_R_EVVP_LIB);
        goto err;
    }

    return 1;
 err:
    OPENSSL_cleanse(key, sizeof(key));
    return 0;
}

int tls13_change_cipher_state(SSL *s, int which)
{
#ifdef CHARSET_EBCDIC
  static const unsigned char client_early_traffic[]       = {0x63, 0x20, 0x65, 0x20,       /*traffic*/0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
  static const unsigned char client_handshake_traffic[]   = {0x63, 0x20, 0x68, 0x73, 0x20, /*traffic*/0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
  static const unsigned char client_application_traffic[] = {0x63, 0x20, 0x61, 0x70, 0x20, /*traffic*/0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
  static const unsigned char server_handshake_traffic[]   = {0x73, 0x20, 0x68, 0x73, 0x20, /*traffic*/0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
  static const unsigned char server_application_traffic[] = {0x73, 0x20, 0x61, 0x70, 0x20, /*traffic*/0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x00};
  static const unsigned char exporter_master_secret[] = {0x65, 0x78, 0x70, 0x20,                    /* master*/  0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00};
  static const unsigned char resumption_master_secret[] = {0x72, 0x65, 0x73, 0x20,                  /* master*/  0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00};
  static const unsigned char early_exporter_master_secret[] = {0x65, 0x20, 0x65, 0x78, 0x70, 0x20,  /* master*/  0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00};
#else
    static const unsigned char client_early_traffic[] = "c e traffic";
    static const unsigned char client_handshake_traffic[] = "c hs traffic";
    static const unsigned char client_application_traffic[] = "c ap traffic";
    static const unsigned char server_handshake_traffic[] = "s hs traffic";
    static const unsigned char server_application_traffic[] = "s ap traffic";
    static const unsigned char exporter_master_secret[] = "exp master";
    static const unsigned char resumption_master_secret[] = "res master";
    static const unsigned char early_exporter_master_secret[] = "e exp master";
#endif
    unsigned char *iv;
    unsigned char secret[EVVP_MAX_MD_SIZE];
    unsigned char hashval[EVVP_MAX_MD_SIZE];
    unsigned char *hash = hashval;
    unsigned char *insecret;
    unsigned char *finsecret = NULL;
    const char *log_label = NULL;
    EVVP_CIPHER_CTX *ciph_ctx;
    size_t finsecretlen = 0;
    const unsigned char *label;
    size_t labellen, hashlen = 0;
    int ret = 0;
    const EVVP_MD *md = NULL;
    const EVVP_CIPHER *cipher = NULL;

    if (which & SSL3_CC_READ) {
        if (s->enc_read_ctx != NULL) {
            EVVP_CIPHER_CTX_reset(s->enc_read_ctx);
        } else {
            s->enc_read_ctx = EVVP_CIPHER_CTX_new();
            if (s->enc_read_ctx == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        ciph_ctx = s->enc_read_ctx;
        iv = s->read_iv;

        RECORD_LAYER_reset_read_sequence(&s->rlayer);
    } else {
        s->statem.enc_write_state = ENC_WRITE_STATE_INVALID;
        if (s->enc_write_ctx != NULL) {
            EVVP_CIPHER_CTX_reset(s->enc_write_ctx);
        } else {
            s->enc_write_ctx = EVVP_CIPHER_CTX_new();
            if (s->enc_write_ctx == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        ciph_ctx = s->enc_write_ctx;
        iv = s->write_iv;

        RECORD_LAYER_reset_write_sequence(&s->rlayer);
    }

    if (((which & SSL3_CC_CLIENT) && (which & SSL3_CC_WRITE))
            || ((which & SSL3_CC_SERVER) && (which & SSL3_CC_READ))) {
        if (which & SSL3_CC_EARLY) {
            EVVP_MD_CTX *mdctx = NULL;
            long handlen;
            void *hdata;
            unsigned int hashlenui;
            const SSL_CIPHER *sslcipher = SSL_SESSION_get0_cipher(s->session);

            insecret = s->early_secret;
            label = client_early_traffic;
            labellen = sizeof(client_early_traffic) - 1;
            log_label = CLIENT_EARLY_LABEL;

            handlen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
            if (handlen <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE,
                         SSL_R_BAD_HANDSHAKE_LENGTH);
                goto err;
            }

            if (s->early_data_state == SSL_EARLY_DATA_CONNECTING
                    && s->max_early_data > 0
                    && s->session->ext.max_early_data == 0) {
                /*
                 * If we are attempting to send early data, and we've decided to
                 * actually do it but max_early_data in s->session is 0 then we
                 * must be using an external PSK.
                 */
                if (!ossl_assert(s->psksession != NULL
                        && s->max_early_data ==
                           s->psksession->ext.max_early_data)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                             SSL_F_TLS13_CHANGE_CIPHER_STATE,
                             ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                sslcipher = SSL_SESSION_get0_cipher(s->psksession);
            }
            if (sslcipher == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE, SSL_R_BAD_PSK);
                goto err;
            }

            /*
             * We need to calculate the handshake digest using the digest from
             * the session. We haven't yet selected our ciphersuite so we can't
             * use ssl_handshake_md().
             */
            mdctx = EVVP_MD_CTX_new();
            if (mdctx == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            cipher = EVVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sslcipher));
            md = ssl_md(sslcipher->algorithm2);
            if (md == NULL || !EVVP_DigestInit_ex(mdctx, md, NULL)
                    || !EVVP_DigestUpdate(mdctx, hdata, handlen)
                    || !EVVP_DigestFinal_ex(mdctx, hashval, &hashlenui)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
                EVVP_MD_CTX_free(mdctx);
                goto err;
            }
            hashlen = hashlenui;
            EVVP_MD_CTX_free(mdctx);

            if (!tls13_hkdf_expand(s, md, insecret,
                                   early_exporter_master_secret,
                                   sizeof(early_exporter_master_secret) - 1,
                                   hashval, hashlen,
                                   s->early_exporter_master_secret, hashlen,
                                   1)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS13_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (!ssl_log_secret(s, EARLY_EXPORTER_SECRET_LABEL,
                                s->early_exporter_master_secret, hashlen)) {
                /* SSLfatal() already called */
                goto err;
            }
        } else if (which & SSL3_CC_HANDSHAKE) {
            insecret = s->handshake_secret;
            finsecret = s->client_finished_secret;
            finsecretlen = EVVP_MD_size(ssl_handshake_md(s));
            label = client_handshake_traffic;
            labellen = sizeof(client_handshake_traffic) - 1;
            log_label = CLIENT_HANDSHAKE_LABEL;
            /*
             * The handshake hash used for the server read/client write handshake
             * traffic secret is the same as the hash for the server
             * write/client read handshake traffic secret. However, if we
             * processed early data then we delay changing the server
             * read/client write cipher state until later, and the handshake
             * hashes have moved on. Therefore we use the value saved earlier
             * when we did the server write/client read change cipher state.
             */
            hash = s->handshake_traffic_hash;
        } else {
            insecret = s->master_secret;
            label = client_application_traffic;
            labellen = sizeof(client_application_traffic) - 1;
            log_label = CLIENT_APPLICATION_LABEL;
            /*
             * For this we only use the handshake hashes up until the server
             * Finished hash. We do not include the client's Finished, which is
             * what ssl_handshake_hash() would give us. Instead we use the
             * previously saved value.
             */
            hash = s->server_finished_hash;
        }
    } else {
        /* Early data never applies to client-read/server-write */
        if (which & SSL3_CC_HANDSHAKE) {
            insecret = s->handshake_secret;
            finsecret = s->server_finished_secret;
            finsecretlen = EVVP_MD_size(ssl_handshake_md(s));
            label = server_handshake_traffic;
            labellen = sizeof(server_handshake_traffic) - 1;
            log_label = SERVER_HANDSHAKE_LABEL;
        } else {
            insecret = s->master_secret;
            label = server_application_traffic;
            labellen = sizeof(server_application_traffic) - 1;
            log_label = SERVER_APPLICATION_LABEL;
        }
    }

    if (!(which & SSL3_CC_EARLY)) {
        md = ssl_handshake_md(s);
        cipher = s->s3->tmp.new_sym_enc;
        if (!ssl3_digest_cached_records(s, 1)
                || !ssl_handshake_hash(s, hashval, sizeof(hashval), &hashlen)) {
            /* SSLfatal() already called */;
            goto err;
        }
    }

    /*
     * Save the hash of handshakes up to now for use when we calculate the
     * client application traffic secret
     */
    if (label == server_application_traffic)
        memcpy(s->server_finished_hash, hashval, hashlen);

    if (label == server_handshake_traffic)
        memcpy(s->handshake_traffic_hash, hashval, hashlen);

    if (label == client_application_traffic) {
        /*
         * We also create the resumption master secret, but this time use the
         * hash for the whole handshake including the Client Finished
         */
        if (!tls13_hkdf_expand(s, ssl_handshake_md(s), insecret,
                               resumption_master_secret,
                               sizeof(resumption_master_secret) - 1,
                               hashval, hashlen, s->resumption_master_secret,
                               hashlen, 1)) {
            /* SSLfatal() already called */
            goto err;
        }
    }

    if (!derive_secret_key_and_iv(s, which & SSL3_CC_WRITE, md, cipher,
                                  insecret, hash, label, labellen, secret, iv,
                                  ciph_ctx)) {
        /* SSLfatal() already called */
        goto err;
    }

    if (label == server_application_traffic) {
        memcpy(s->server_app_traffic_secret, secret, hashlen);
        /* Now we create the exporter master secret */
        if (!tls13_hkdf_expand(s, ssl_handshake_md(s), insecret,
                               exporter_master_secret,
                               sizeof(exporter_master_secret) - 1,
                               hash, hashlen, s->exporter_master_secret,
                               hashlen, 1)) {
            /* SSLfatal() already called */
            goto err;
        }

        if (!ssl_log_secret(s, EXPORTER_SECRET_LABEL, s->exporter_master_secret,
                            hashlen)) {
            /* SSLfatal() already called */
            goto err;
        }
    } else if (label == client_application_traffic)
        memcpy(s->client_app_traffic_secret, secret, hashlen);

    if (!ssl_log_secret(s, log_label, secret, hashlen)) {
        /* SSLfatal() already called */
        goto err;
    }

    if (finsecret != NULL
            && !tls13_derive_finishedkey(s, ssl_handshake_md(s), secret,
                                         finsecret, finsecretlen)) {
        /* SSLfatal() already called */
        goto err;
    }

    if (!s->server && label == client_early_traffic)
        s->statem.enc_write_state = ENC_WRITE_STATE_WRITE_PLAIN_ALERTS;
    else
        s->statem.enc_write_state = ENC_WRITE_STATE_VALID;
    ret = 1;
 err:
    OPENSSL_cleanse(secret, sizeof(secret));
    return ret;
}

int tls13_update_key(SSL *s, int sending)
{
#ifdef CHARSET_EBCDIC
  static const unsigned char application_traffic[] = { 0x74, 0x72 ,0x61 ,0x66 ,0x66 ,0x69 ,0x63 ,0x20 ,0x75 ,0x70 ,0x64, 0x00};
#else
  static const unsigned char application_traffic[] = "traffic upd";
#endif
    const EVVP_MD *md = ssl_handshake_md(s);
    size_t hashlen = EVVP_MD_size(md);
    unsigned char *insecret, *iv;
    unsigned char secret[EVVP_MAX_MD_SIZE];
    EVVP_CIPHER_CTX *ciph_ctx;
    int ret = 0;

    if (s->server == sending)
        insecret = s->server_app_traffic_secret;
    else
        insecret = s->client_app_traffic_secret;

    if (sending) {
        s->statem.enc_write_state = ENC_WRITE_STATE_INVALID;
        iv = s->write_iv;
        ciph_ctx = s->enc_write_ctx;
        RECORD_LAYER_reset_write_sequence(&s->rlayer);
    } else {
        iv = s->read_iv;
        ciph_ctx = s->enc_read_ctx;
        RECORD_LAYER_reset_read_sequence(&s->rlayer);
    }

    if (!derive_secret_key_and_iv(s, sending, ssl_handshake_md(s),
                                  s->s3->tmp.new_sym_enc, insecret, NULL,
                                  application_traffic,
                                  sizeof(application_traffic) - 1, secret, iv,
                                  ciph_ctx)) {
        /* SSLfatal() already called */
        goto err;
    }

    memcpy(insecret, secret, hashlen);

    s->statem.enc_write_state = ENC_WRITE_STATE_VALID;
    ret = 1;
 err:
    OPENSSL_cleanse(secret, sizeof(secret));
    return ret;
}

int tls13_alert_code(int code)
{
    /* There are 2 additional alerts in TLSv1.3 compared to TLSv1.2 */
    if (code == SSL_AD_MISSING_EXTENSION || code == SSL_AD_CERTIFICATE_REQUIRED)
        return code;

    return tls1_alert_code(code);
}

int tls13_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                                 const char *label, size_t llen,
                                 const unsigned char *context,
                                 size_t contextlen, int use_context)
{
    unsigned char exportsecret[EVVP_MAX_MD_SIZE];
#ifdef CHARSET_EBCDIC
    static const unsigned char exporterlabel[] = {0x65, 0x78, 0x70, 0x6F, 0x72, 0x74, 0x65, 0x72, 0x00};
#else
    static const unsigned char exporterlabel[] = "exporter";
#endif
    unsigned char hash[EVVP_MAX_MD_SIZE], data[EVVP_MAX_MD_SIZE];
    const EVVP_MD *md = ssl_handshake_md(s);
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();
    unsigned int hashsize, datalen;
    int ret = 0;

    if (ctx == NULL || !ossl_statem_export_allowed(s))
        goto err;

    if (!use_context)
        contextlen = 0;

    if (EVVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVVP_DigestUpdate(ctx, context, contextlen) <= 0
            || EVVP_DigestFinal_ex(ctx, hash, &hashsize) <= 0
            || EVVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVVP_DigestFinal_ex(ctx, data, &datalen) <= 0
            || !tls13_hkdf_expand(s, md, s->exporter_master_secret,
                                  (const unsigned char *)label, llen,
                                  data, datalen, exportsecret, hashsize, 0)
            || !tls13_hkdf_expand(s, md, exportsecret, exporterlabel,
                                  sizeof(exporterlabel) - 1, hash, hashsize,
                                  out, olen, 0))
        goto err;

    ret = 1;
 err:
    EVVP_MD_CTX_free(ctx);
    return ret;
}

int tls13_export_keying_material_early(SSL *s, unsigned char *out, size_t olen,
                                       const char *label, size_t llen,
                                       const unsigned char *context,
                                       size_t contextlen)
{
#ifdef CHARSET_EBCDIC
  static const unsigned char exporterlabel[] = {0x65, 0x78, 0x70, 0x6F, 0x72, 0x74, 0x65, 0x72, 0x00};
#else
  static const unsigned char exporterlabel[] = "exporter";
#endif
    unsigned char exportsecret[EVVP_MAX_MD_SIZE];
    unsigned char hash[EVVP_MAX_MD_SIZE], data[EVVP_MAX_MD_SIZE];
    const EVVP_MD *md;
    EVVP_MD_CTX *ctx = EVVP_MD_CTX_new();
    unsigned int hashsize, datalen;
    int ret = 0;
    const SSL_CIPHER *sslcipher;

    if (ctx == NULL || !ossl_statem_export_early_allowed(s))
        goto err;

    if (!s->server && s->max_early_data > 0
            && s->session->ext.max_early_data == 0)
        sslcipher = SSL_SESSION_get0_cipher(s->psksession);
    else
        sslcipher = SSL_SESSION_get0_cipher(s->session);

    md = ssl_md(sslcipher->algorithm2);

    /*
     * Calculate the hash value and store it in |data|. The reason why
     * the empty string is used is that the definition of TLS-Exporter
     * is like so:
     *
     * TLS-Exporter(label, context_value, key_length) =
     *     HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
     *                       "exporter", Hash(context_value), key_length)
     *
     * Derive-Secret(Secret, Label, Messages) =
     *       HKDF-Expand-Label(Secret, Label,
     *                         Transcript-Hash(Messages), Hash.length)
     *
     * Here Transcript-Hash is the cipher suite hash algorithm.
     */
    if (EVVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVVP_DigestUpdate(ctx, context, contextlen) <= 0
            || EVVP_DigestFinal_ex(ctx, hash, &hashsize) <= 0
            || EVVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVVP_DigestFinal_ex(ctx, data, &datalen) <= 0
            || !tls13_hkdf_expand(s, md, s->early_exporter_master_secret,
                                  (const unsigned char *)label, llen,
                                  data, datalen, exportsecret, hashsize, 0)
            || !tls13_hkdf_expand(s, md, exportsecret, exporterlabel,
                                  sizeof(exporterlabel) - 1, hash, hashsize,
                                  out, olen, 0))
        goto err;

    ret = 1;
 err:
    EVVP_MD_CTX_free(ctx);
    return ret;
}
