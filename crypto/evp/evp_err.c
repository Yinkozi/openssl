/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/evperr.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA EVP_str_functs[] = {
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AESNI_INIT_KEY, 0), "aesni_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AESNI_XTS_INIT_KEY, 0), "aesni_xts_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_GCM_CTRL, 0), "aes_gcm_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_INIT_KEY, 0), "aes_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_OCB_CIPHER, 0), "aes_ocb_cipher"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_T4_INIT_KEY, 0), "aes_t4_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_T4_XTS_INIT_KEY, 0),
     "aes_t4_xts_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_WRAP_CIPHER, 0), "aes_wrap_cipher"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_AES_XTS_INIT_KEY, 0), "aes_xts_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_ALG_MODULE_INIT, 0), "alg_module_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_ARIA_CCM_INIT_KEY, 0), "aria_ccm_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_ARIA_GCM_CTRL, 0), "aria_gcm_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_ARIA_GCM_INIT_KEY, 0), "aria_gcm_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_ARIA_INIT_KEY, 0), "aria_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_B64_NEW, 0), "b64_new"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_CAMELLIA_INIT_KEY, 0), "camellia_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_CHACHA20_POLY1305_CTRL, 0),
     "chacha20_poly1305_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_CMLL_T4_INIT_KEY, 0), "cmll_t4_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_DES_EDE3_WRAP_CIPHER, 0),
     "des_ede3_wrap_cipher"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_DO_SIGVER_INIT, 0), "do_sigver_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_ENC_NEW, 0), "enc_new"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_CIPHERINIT_EX, 0), "EVP_CipherInit_ex"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_CIPHER_ASN1_TO_PARAM, 0),
     "EVP_CIPHER_asn1_to_param"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_CIPHER_CTX_COPY, 0),
     "EVP_CIPHER_CTX_copy"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_CIPHER_CTX_CTRL, 0),
     "EVP_CIPHER_CTX_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH, 0),
     "EVP_CIPHER_CTX_set_key_length"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_CIPHER_PARAM_TO_ASN1, 0),
     "EVP_CIPHER_param_to_asn1"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DECRYPTFINAL_EX, 0),
     "_EVP_DecryptFinal_ex"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DECRYPTUPDATE, 0), "_EVP_DecryptUpdate"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DIGESTFINALXOF, 0), "EVP_DigestFinalXOF"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DIGESTINIT_EX, 0), "EVP_DigestInit_ex"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_ENCRYPTDECRYPTUPDATE, 0),
     "evp_EncryptDecryptUpdate"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_ENCRYPTFINAL_EX, 0),
     "_EVP_EncryptFinal_ex"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_ENCRYPTUPDATE, 0), "_EVP_EncryptUpdate"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_MD_CTX_COPY_EX, 0), "EVP_MD_CTX_copy_ex"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_MD_SIZE, 0), "EVP_MD_size"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_OPENINIT, 0), "EVP_OpenInit"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PBE_ALG_ADD, 0), "EVP_PBE_alg_add"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PBE_ALG_ADD_TYPE, 0),
     "EVP_PBE_alg_add_type"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PBE_CIPHERINIT, 0), "EVP_PBE_CipherInit"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PBE_SCRYPT, 0), "EVP_PBE_scrypt"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKCS82PKEY, 0), "EVP_PKCS82PKEY"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY2PKCS8, 0), "EVP_PKEY2PKCS8"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_ASN1_ADD0, 0), "EVP_PKEY_asn1_add0"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CHECK, 0), "EVP_PKEY_check"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_COPY_PARAMETERS, 0),
     "EVP_PKEY_copy_parameters"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CTX_CTRL, 0), "EVP_PKEY_CTX_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CTX_CTRL_STR, 0),
     "EVP_PKEY_CTX_ctrl_str"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CTX_DUP, 0), "EVP_PKEY_CTX_dup"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CTX_MD, 0), "EVP_PKEY_CTX_md"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DECRYPT, 0), "EVP_PKEY_decrypt"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DECRYPT_INIT, 0),
     "EVP_PKEY_decrypt_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DECRYPT_OLD, 0),
     "EVP_PKEY_decrypt_old"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DERIVE, 0), "EVP_PKEY_derive"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DERIVE_INIT, 0),
     "EVP_PKEY_derive_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DERIVE_SET_PEER, 0),
     "EVP_PKEY_derive_set_peer"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_ENCRYPT, 0), "EVP_PKEY_encrypt"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_ENCRYPT_INIT, 0),
     "EVP_PKEY_encrypt_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_ENCRYPT_OLD, 0),
     "EVP_PKEY_encrypt_old"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_DH, 0), "EVP_PKEY_get0_DH"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_DSA, 0), "EVP_PKEY_get0_DSA"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_EC_KEY, 0),
     "EVP_PKEY_get0_EC_KEY"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_HMAC, 0), "EVP_PKEY_get0_hmac"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_POLY1305, 0),
     "EVP_PKEY_get0_poly1305"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_RSA, 0), "EVP_PKEY_get0_RSA"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET0_SIPHASH, 0),
     "EVP_PKEY_get0_siphash"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET_RAW_PRIVATE_KEY, 0),
     "EVP_PKEY_get_raw_private_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_GET_RAW_PUBLIC_KEY, 0),
     "EVP_PKEY_get_raw_public_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_KEYGEN, 0), "EVP_PKEY_keygen"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_KEYGEN_INIT, 0),
     "EVP_PKEY_keygen_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_METH_ADD0, 0), "EVP_PKEY_meth_add0"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_METH_NEW, 0), "EVP_PKEY_meth_new"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_NEW, 0), "EVP_PKEY_new"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_NEW_CMAC_KEY, 0),
     "EVP_PKEY_new_CMAC_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_NEW_RAW_PRIVATE_KEY, 0),
     "EVP_PKEY_new_raw_private_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_NEW_RAW_PUBLIC_KEY, 0),
     "EVP_PKEY_new_raw_public_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_PARAMGEN, 0), "EVP_PKEY_paramgen"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_PARAMGEN_INIT, 0),
     "EVP_PKEY_paramgen_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_PARAM_CHECK, 0),
     "EVP_PKEY_param_check"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_PUBLIC_CHECK, 0),
     "EVP_PKEY_public_check"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_SET1_ENGINE, 0),
     "EVP_PKEY_set1_engine"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_SET_ALIAS_TYPE, 0),
     "EVP_PKEY_set_alias_type"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_SIGN, 0), "EVP_PKEY_sign"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_SIGN_INIT, 0), "EVP_PKEY_sign_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_VERIFY, 0), "EVP_PKEY_verify"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_VERIFY_INIT, 0),
     "EVP_PKEY_verify_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_VERIFY_RECOVER, 0),
     "EVP_PKEY_verify_recover"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT, 0),
     "EVP_PKEY_verify_recover_init"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_SIGNFINAL, 0), "EVP_SignFinal"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_VERIFYFINAL, 0), "EVP_VerifyFinal"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_INT_CTX_NEW, 0), "int_ctx_new"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_OK_NEW, 0), "ok_new"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_PKCS5_PBE_KEYIVGEN, 0), "PKCS5_PBE_keyivgen"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_PKCS5_V2_PBE_KEYIVGEN, 0),
     "PKCS5_v2_PBE_keyivgen"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, 0),
     "PKCS5_v2_PBKDF2_keyivgen"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_PKCS5_V2_SCRYPT_KEYIVGEN, 0),
     "PKCS5_v2_scrypt_keyivgen"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_PKEY_SET_TYPE, 0), "pkey_set_type"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_RC2_MAGIC_TO_METH, 0), "rc2_magic_to_meth"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_RC5_CTRL, 0), "rc5_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_R_32_12_16_INIT_KEY, 0),
     "r_32_12_16_init_key"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_S390X_AES_GCM_CTRL, 0), "s390x_aes_gcm_ctrl"},
    {ERR_PACK(ERR_LIB_EVP, EVP_F_UPDATE, 0), "update"},
    {0, NULL}
};

static const ERR_STRING_DATA EVP_str_reasons[] = {
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_AES_KEY_SETUP_FAILED),
    "aes key setup failed"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_ARIA_KEY_SETUP_FAILED),
    "aria key setup failed"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT), "bad decrypt"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BAD_KEY_LENGTH), "bad key length"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_CAMELLIA_KEY_SETUP_FAILED),
    "camellia key setup failed"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_CIPHER_PARAMETER_ERROR),
    "cipher parameter error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_COMMAND_NOT_SUPPORTED),
    "command not supported"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_COPY_ERROR), "copy error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_CTRL_NOT_IMPLEMENTED),
    "ctrl not implemented"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED),
    "ctrl operation not implemented"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH),
    "data not multiple of block length"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_DECODE_ERROR), "decode error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_DIFFERENT_KEY_TYPES),
    "different key types"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_DIFFERENT_PARAMETERS),
    "different parameters"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_ERROR_LOADING_SECTION),
    "error loading section"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_ERROR_SETTING_FIPS_MODE),
    "error setting fips mode"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_AN_HMAC_KEY),
    "expecting an hmac key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_AN_RSA_KEY),
    "expecting an rsa key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_A_DH_KEY), "expecting a dh key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_A_DSA_KEY),
    "expecting a dsa key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_A_EC_KEY), "expecting a ec key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_A_POLY1305_KEY),
    "expecting a poly1305 key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_EXPECTING_A_SIPHASH_KEY),
    "expecting a siphash key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_FIPS_MODE_NOT_SUPPORTED),
    "fips mode not supported"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_GET_RAW_KEY_FAILED), "get raw key failed"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_ILLEGAL_SCRYPT_PARAMETERS),
    "illegal scrypt parameters"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INITIALIZATION_ERROR),
    "initialization error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INPUT_NOT_INITIALIZED),
    "input not initialized"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INVALID_DIGEST), "invalid digest"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INVALID_FIPS_MODE), "invalid fips mode"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INVALID_IV_LENGTH), "invalid iv length"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INVALID_KEY), "invalid key"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INVALID_KEY_LENGTH), "invalid key length"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_INVALID_OPERATION), "invalid operation"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_KEYGEN_FAILURE), "keygen failure"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_KEY_SETUP_FAILED), "key setup failed"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_MEMORY_LIMIT_EXCEEDED),
    "memory limit exceeded"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_MESSAGE_DIGEST_IS_NULL),
    "message digest is null"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_METHOD_NOT_SUPPORTED),
    "method not supported"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_MISSING_PARAMETERS), "missing parameters"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_NOT_XOF_OR_INVALID_LENGTH),
    "not XOF or invalid length"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_NO_CIPHER_SET), "no cipher set"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_NO_DEFAULT_DIGEST), "no default digest"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_NO_DIGEST_SET), "no digest set"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_NO_KEY_SET), "no key set"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_NO_OPERATION_SET), "no operation set"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_ONLY_ONESHOT_SUPPORTED),
    "only oneshot supported"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE),
    "operation not supported for this keytype"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_OPERATON_NOT_INITIALIZED),
    "operaton not initialized"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_OUTPUT_WOULD_OVERFLOW),
    "output would overflow"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_PARTIALLY_OVERLAPPING),
    "partially overlapping buffers"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_PBKDF2_ERROR), "pbkdf2 error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_PKEY_APPLICATION_ASN1_METHOD_ALREADY_REGISTERED),
    "pkey application asn1 method already registered"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_PRIVATE_KEY_DECODE_ERROR),
    "private key decode error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_PRIVATE_KEY_ENCODE_ERROR),
    "private key encode error"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_PUBLIC_KEY_NOT_RSA), "public key not rsa"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNKNOWN_CIPHER), "unknown cipher"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNKNOWN_DIGEST), "unknown digest"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNKNOWN_OPTION), "unknown option"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNKNOWN_PBE_ALGORITHM),
    "unknown pbe algorithm"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_ALGORITHM),
    "unsupported algorithm"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_CIPHER), "unsupported cipher"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_KEYLENGTH),
    "unsupported keylength"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION),
    "unsupported key derivation function"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_KEY_SIZE),
    "unsupported key size"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_NUMBER_OF_ROUNDS),
    "unsupported number of rounds"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_PRF), "unsupported prf"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM),
    "unsupported private key algorithm"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_UNSUPPORTED_SALT_TYPE),
    "unsupported salt type"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_WRAP_MODE_NOT_ALLOWED),
    "wrap mode not allowed"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_WRONG_FINAL_BLOCK_LENGTH),
    "wrong final block length"},
    {ERR_PACK(ERR_LIB_EVP, 0, EVP_R_XTS_DUPLICATED_KEYS),
    "xts duplicated keys"},
    {0, NULL}
};

#endif

int ERR_load_EVP_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(EVP_str_functs[0].error) == NULL) {
        ERR_load_strings_const(EVP_str_functs);
        ERR_load_strings_const(EVP_str_reasons);
    }
#endif
    return 1;
}
