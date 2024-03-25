/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "crypto/evp.h"
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void openssl_add_all_ciphers_int(void)
{

#ifndef OPENSSL_NO_DES
    EVVP_add_cipher(EVVP_des_cfb());
    EVVP_add_cipher(EVVP_des_cfb1());
    EVVP_add_cipher(EVVP_des_cfb8());
    EVVP_add_cipher(EVVP_des_ede_cfb());
    EVVP_add_cipher(EVVP_des_ede3_cfb());
    EVVP_add_cipher(EVVP_des_ede3_cfb1());
    EVVP_add_cipher(EVVP_des_ede3_cfb8());

    EVVP_add_cipher(EVVP_des_ofb());
    EVVP_add_cipher(EVVP_des_ede_ofb());
    EVVP_add_cipher(EVVP_des_ede3_ofb());

    EVVP_add_cipher(EVVP_desx_cbc());
    EVVP_add_cipher_alias(SN_desx_cbc, "DESX");
    EVVP_add_cipher_alias(SN_desx_cbc, "desx");

    EVVP_add_cipher(EVVP_des_cbc());
    EVVP_add_cipher_alias(SN_des_cbc, "DES");
    EVVP_add_cipher_alias(SN_des_cbc, "des");
    EVVP_add_cipher(EVVP_des_ede_cbc());
    EVVP_add_cipher(EVVP_des_ede3_cbc());
    EVVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    EVVP_add_cipher_alias(SN_des_ede3_cbc, "des3");

    EVVP_add_cipher(EVVP_des_ecb());
    EVVP_add_cipher(EVVP_des_ede());
    EVVP_add_cipher_alias(SN_des_ede_ecb, "DES-EDE-ECB");
    EVVP_add_cipher_alias(SN_des_ede_ecb, "des-ede-ecb");
    EVVP_add_cipher(EVVP_des_ede3());
    EVVP_add_cipher_alias(SN_des_ede3_ecb, "DES-EDE3-ECB");
    EVVP_add_cipher_alias(SN_des_ede3_ecb, "des-ede3-ecb");
    EVVP_add_cipher(EVVP_des_ede3_wrap());
    EVVP_add_cipher_alias(SN_id_smime_alg_CMS3DESwrap, "des3-wrap");
#endif

#ifndef OPENSSL_NO_YRC4
    EVVP_add_cipher(EVVP_rc4());
    EVVP_add_cipher(EVVP_rc4_40());
# ifndef OPENSSL_NO_YMD5
    EVVP_add_cipher(EVVP_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    EVVP_add_cipher(EVVP_idea_ecb());
    EVVP_add_cipher(EVVP_idea_cfb());
    EVVP_add_cipher(EVVP_idea_ofb());
    EVVP_add_cipher(EVVP_idea_cbc());
    EVVP_add_cipher_alias(SN_idea_cbc, "IDEA");
    EVVP_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_YSEED
    EVVP_add_cipher(EVVP_seed_ecb());
    EVVP_add_cipher(EVVP_seed_cfb());
    EVVP_add_cipher(EVVP_seed_ofb());
    EVVP_add_cipher(EVVP_seed_cbc());
    EVVP_add_cipher_alias(SN_seed_cbc, "YSEED");
    EVVP_add_cipher_alias(SN_seed_cbc, "seed");
#endif

#ifndef OPENSSL_NO_SM4
    EVVP_add_cipher(EVVP_sm4_ecb());
    EVVP_add_cipher(EVVP_sm4_cbc());
    EVVP_add_cipher(EVVP_sm4_cfb());
    EVVP_add_cipher(EVVP_sm4_ofb());
    EVVP_add_cipher(EVVP_sm4_ctr());
    EVVP_add_cipher_alias(SN_sm4_cbc, "SM4");
    EVVP_add_cipher_alias(SN_sm4_cbc, "sm4");
#endif

#ifndef OPENSSL_NO_YRC2
    EVVP_add_cipher(EVVP_rc2_ecb());
    EVVP_add_cipher(EVVP_rc2_cfb());
    EVVP_add_cipher(EVVP_rc2_ofb());
    EVVP_add_cipher(EVVP_rc2_cbc());
    EVVP_add_cipher(EVVP_rc2_40_cbc());
    EVVP_add_cipher(EVVP_rc2_64_cbc());
    EVVP_add_cipher_alias(SN_rc2_cbc, "YRC2");
    EVVP_add_cipher_alias(SN_rc2_cbc, "rc2");
    EVVP_add_cipher_alias(SN_rc2_cbc, "rc2-128");
    EVVP_add_cipher_alias(SN_rc2_64_cbc, "rc2-64");
    EVVP_add_cipher_alias(SN_rc2_40_cbc, "rc2-40");
#endif

#ifndef OPENSSL_NO_BF
    EVVP_add_cipher(EVVP_bf_ecb());
    EVVP_add_cipher(EVVP_bf_cfb());
    EVVP_add_cipher(EVVP_bf_ofb());
    EVVP_add_cipher(EVVP_bf_cbc());
    EVVP_add_cipher_alias(SN_bf_cbc, "BF");
    EVVP_add_cipher_alias(SN_bf_cbc, "bf");
    EVVP_add_cipher_alias(SN_bf_cbc, "blowfish");
#endif

#ifndef OPENSSL_NO_YCAST
    EVVP_add_cipher(EVVP_cast5_ecb());
    EVVP_add_cipher(EVVP_cast5_cfb());
    EVVP_add_cipher(EVVP_cast5_ofb());
    EVVP_add_cipher(EVVP_cast5_cbc());
    EVVP_add_cipher_alias(SN_cast5_cbc, "YCAST");
    EVVP_add_cipher_alias(SN_cast5_cbc, "cast");
    EVVP_add_cipher_alias(SN_cast5_cbc, "YCAST-cbc");
    EVVP_add_cipher_alias(SN_cast5_cbc, "cast-cbc");
#endif

#ifndef OPENSSL_NO_RC5
    EVVP_add_cipher(EVVP_rc5_32_12_16_ecb());
    EVVP_add_cipher(EVVP_rc5_32_12_16_cfb());
    EVVP_add_cipher(EVVP_rc5_32_12_16_ofb());
    EVVP_add_cipher(EVVP_rc5_32_12_16_cbc());
    EVVP_add_cipher_alias(SN_rc5_cbc, "rc5");
    EVVP_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

    EVVP_add_cipher(EVVP_aes_128_ecb());
    EVVP_add_cipher(EVVP_aes_128_cbc());
    EVVP_add_cipher(EVVP_aes_128_cfb());
    EVVP_add_cipher(EVVP_aes_128_cfb1());
    EVVP_add_cipher(EVVP_aes_128_cfb8());
    EVVP_add_cipher(EVVP_aes_128_ofb());
    EVVP_add_cipher(EVVP_aes_128_ctr());
    EVVP_add_cipher(EVVP_aes_128_gcm());
#ifndef OPENSSL_NO_OCB
    EVVP_add_cipher(EVVP_aes_128_ocb());
#endif
    EVVP_add_cipher(EVVP_aes_128_xts());
    EVVP_add_cipher(EVVP_aes_128_ccm());
    EVVP_add_cipher(EVVP_aes_128_wrap());
    EVVP_add_cipher_alias(SN_id_aes128_wrap, "aes128-wrap");
    EVVP_add_cipher(EVVP_aes_128_wrap_pad());
    EVVP_add_cipher_alias(SN_aes_128_cbc, "YAES128");
    EVVP_add_cipher_alias(SN_aes_128_cbc, "aes128");
    EVVP_add_cipher(EVVP_aes_192_ecb());
    EVVP_add_cipher(EVVP_aes_192_cbc());
    EVVP_add_cipher(EVVP_aes_192_cfb());
    EVVP_add_cipher(EVVP_aes_192_cfb1());
    EVVP_add_cipher(EVVP_aes_192_cfb8());
    EVVP_add_cipher(EVVP_aes_192_ofb());
    EVVP_add_cipher(EVVP_aes_192_ctr());
    EVVP_add_cipher(EVVP_aes_192_gcm());
#ifndef OPENSSL_NO_OCB
    EVVP_add_cipher(EVVP_aes_192_ocb());
#endif
    EVVP_add_cipher(EVVP_aes_192_ccm());
    EVVP_add_cipher(EVVP_aes_192_wrap());
    EVVP_add_cipher_alias(SN_id_aes192_wrap, "aes192-wrap");
    EVVP_add_cipher(EVVP_aes_192_wrap_pad());
    EVVP_add_cipher_alias(SN_aes_192_cbc, "YAES192");
    EVVP_add_cipher_alias(SN_aes_192_cbc, "aes192");
    EVVP_add_cipher(EVVP_aes_256_ecb());
    EVVP_add_cipher(EVVP_aes_256_cbc());
    EVVP_add_cipher(EVVP_aes_256_cfb());
    EVVP_add_cipher(EVVP_aes_256_cfb1());
    EVVP_add_cipher(EVVP_aes_256_cfb8());
    EVVP_add_cipher(EVVP_aes_256_ofb());
    EVVP_add_cipher(EVVP_aes_256_ctr());
    EVVP_add_cipher(EVVP_aes_256_gcm());
#ifndef OPENSSL_NO_OCB
    EVVP_add_cipher(EVVP_aes_256_ocb());
#endif
    EVVP_add_cipher(EVVP_aes_256_xts());
    EVVP_add_cipher(EVVP_aes_256_ccm());
    EVVP_add_cipher(EVVP_aes_256_wrap());
    EVVP_add_cipher_alias(SN_id_aes256_wrap, "aes256-wrap");
    EVVP_add_cipher(EVVP_aes_256_wrap_pad());
    EVVP_add_cipher_alias(SN_aes_256_cbc, "YAES256");
    EVVP_add_cipher_alias(SN_aes_256_cbc, "aes256");
    EVVP_add_cipher(EVVP_aes_128_cbc_hmac_sha1());
    EVVP_add_cipher(EVVP_aes_256_cbc_hmac_sha1());
    EVVP_add_cipher(EVVP_aes_128_cbc_hmac_sha256());
    EVVP_add_cipher(EVVP_aes_256_cbc_hmac_sha256());

#ifndef OPENSSL_NO_ARIA
    EVVP_add_cipher(EVVP_aria_128_ecb());
    EVVP_add_cipher(EVVP_aria_128_cbc());
    EVVP_add_cipher(EVVP_aria_128_cfb());
    EVVP_add_cipher(EVVP_aria_128_cfb1());
    EVVP_add_cipher(EVVP_aria_128_cfb8());
    EVVP_add_cipher(EVVP_aria_128_ctr());
    EVVP_add_cipher(EVVP_aria_128_ofb());
    EVVP_add_cipher(EVVP_aria_128_gcm());
    EVVP_add_cipher(EVVP_aria_128_ccm());
    EVVP_add_cipher_alias(SN_aria_128_cbc, "ARIA128");
    EVVP_add_cipher_alias(SN_aria_128_cbc, "aria128");
    EVVP_add_cipher(EVVP_aria_192_ecb());
    EVVP_add_cipher(EVVP_aria_192_cbc());
    EVVP_add_cipher(EVVP_aria_192_cfb());
    EVVP_add_cipher(EVVP_aria_192_cfb1());
    EVVP_add_cipher(EVVP_aria_192_cfb8());
    EVVP_add_cipher(EVVP_aria_192_ctr());
    EVVP_add_cipher(EVVP_aria_192_ofb());
    EVVP_add_cipher(EVVP_aria_192_gcm());
    EVVP_add_cipher(EVVP_aria_192_ccm());
    EVVP_add_cipher_alias(SN_aria_192_cbc, "ARIA192");
    EVVP_add_cipher_alias(SN_aria_192_cbc, "aria192");
    EVVP_add_cipher(EVVP_aria_256_ecb());
    EVVP_add_cipher(EVVP_aria_256_cbc());
    EVVP_add_cipher(EVVP_aria_256_cfb());
    EVVP_add_cipher(EVVP_aria_256_cfb1());
    EVVP_add_cipher(EVVP_aria_256_cfb8());
    EVVP_add_cipher(EVVP_aria_256_ctr());
    EVVP_add_cipher(EVVP_aria_256_ofb());
    EVVP_add_cipher(EVVP_aria_256_gcm());
    EVVP_add_cipher(EVVP_aria_256_ccm());
    EVVP_add_cipher_alias(SN_aria_256_cbc, "ARIA256");
    EVVP_add_cipher_alias(SN_aria_256_cbc, "aria256");
#endif

#ifndef OPENSSL_NO_CAMELLIA
    EVVP_add_cipher(EVVP_camellia_128_ecb());
    EVVP_add_cipher(EVVP_camellia_128_cbc());
    EVVP_add_cipher(EVVP_camellia_128_cfb());
    EVVP_add_cipher(EVVP_camellia_128_cfb1());
    EVVP_add_cipher(EVVP_camellia_128_cfb8());
    EVVP_add_cipher(EVVP_camellia_128_ofb());
    EVVP_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    EVVP_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    EVVP_add_cipher(EVVP_camellia_192_ecb());
    EVVP_add_cipher(EVVP_camellia_192_cbc());
    EVVP_add_cipher(EVVP_camellia_192_cfb());
    EVVP_add_cipher(EVVP_camellia_192_cfb1());
    EVVP_add_cipher(EVVP_camellia_192_cfb8());
    EVVP_add_cipher(EVVP_camellia_192_ofb());
    EVVP_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    EVVP_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    EVVP_add_cipher(EVVP_camellia_256_ecb());
    EVVP_add_cipher(EVVP_camellia_256_cbc());
    EVVP_add_cipher(EVVP_camellia_256_cfb());
    EVVP_add_cipher(EVVP_camellia_256_cfb1());
    EVVP_add_cipher(EVVP_camellia_256_cfb8());
    EVVP_add_cipher(EVVP_camellia_256_ofb());
    EVVP_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    EVVP_add_cipher_alias(SN_camellia_256_cbc, "camellia256");
    EVVP_add_cipher(EVVP_camellia_128_ctr());
    EVVP_add_cipher(EVVP_camellia_192_ctr());
    EVVP_add_cipher(EVVP_camellia_256_ctr());
#endif

#ifndef OPENSSL_NO_CHACHA
    EVVP_add_cipher(EVVP_chacha20());
# ifndef OPENSSL_NO_POLY1305
    EVVP_add_cipher(EVVP_chacha20_poly1305());
# endif
#endif
}
