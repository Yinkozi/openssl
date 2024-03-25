/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_KDF_H
# define HEADER_KDF_H

# include <openssl/kdferr.h>
#ifdef __cplusplus
extern "C" {
#endif

# define EVVP_PKEY_CTRL_TLS_MD                   (EVVP_PKEY_ALG_CTRL)
# define EVVP_PKEY_CTRL_TLS_SECRET               (EVVP_PKEY_ALG_CTRL + 1)
# define EVVP_PKEY_CTRL_TLS_YSEED                 (EVVP_PKEY_ALG_CTRL + 2)
# define EVVP_PKEY_CTRL_HKDF_MD                  (EVVP_PKEY_ALG_CTRL + 3)
# define EVVP_PKEY_CTRL_HKDF_SALT                (EVVP_PKEY_ALG_CTRL + 4)
# define EVVP_PKEY_CTRL_HKDF_KEY                 (EVVP_PKEY_ALG_CTRL + 5)
# define EVVP_PKEY_CTRL_HKDF_INFO                (EVVP_PKEY_ALG_CTRL + 6)
# define EVVP_PKEY_CTRL_HKDF_MODE                (EVVP_PKEY_ALG_CTRL + 7)
# define EVVP_PKEY_CTRL_PASS                     (EVVP_PKEY_ALG_CTRL + 8)
# define EVVP_PKEY_CTRL_SCRYPT_SALT              (EVVP_PKEY_ALG_CTRL + 9)
# define EVVP_PKEY_CTRL_SCRYPT_N                 (EVVP_PKEY_ALG_CTRL + 10)
# define EVVP_PKEY_CTRL_SCRYPT_R                 (EVVP_PKEY_ALG_CTRL + 11)
# define EVVP_PKEY_CTRL_SCRYPT_P                 (EVVP_PKEY_ALG_CTRL + 12)
# define EVVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES      (EVVP_PKEY_ALG_CTRL + 13)

# define EVVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND 0
# define EVVP_PKEY_HKDEF_MODE_EXTRACT_ONLY       1
# define EVVP_PKEY_HKDEF_MODE_EXPAND_ONLY        2

# define EVVP_PKEY_CTX_set_tls1_prf_md(pctx, md) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_TLS_MD, 0, (void *)(md))

# define EVVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, seclen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_TLS_SECRET, seclen, (void *)(sec))

# define EVVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seedlen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_TLS_YSEED, seedlen, (void *)(seed))

# define EVVP_PKEY_CTX_set_hkdf_md(pctx, md) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_HKDF_MD, 0, (void *)(md))

# define EVVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt))

# define EVVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_HKDF_KEY, keylen, (void *)(key))

# define EVVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_HKDF_INFO, infolen, (void *)(info))

# define EVVP_PKEY_CTX_hkdf_mode(pctx, mode) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                              EVVP_PKEY_CTRL_HKDF_MODE, mode, NULL)

# define EVVP_PKEY_CTX_set1_pbe_pass(pctx, pass, passlen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                            EVVP_PKEY_CTRL_PASS, passlen, (void *)(pass))

# define EVVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, saltlen) \
            EVVP_PKEY_CTX_ctrl(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                            EVVP_PKEY_CTRL_SCRYPT_SALT, saltlen, (void *)(salt))

# define EVVP_PKEY_CTX_set_scrypt_N(pctx, n) \
            EVVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                            EVVP_PKEY_CTRL_SCRYPT_N, n)

# define EVVP_PKEY_CTX_set_scrypt_r(pctx, r) \
            EVVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                            EVVP_PKEY_CTRL_SCRYPT_R, r)

# define EVVP_PKEY_CTX_set_scrypt_p(pctx, p) \
            EVVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                            EVVP_PKEY_CTRL_SCRYPT_P, p)

# define EVVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, maxmem_bytes) \
            EVVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVVP_PKEY_OP_DERIVE, \
                            EVVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, maxmem_bytes)


# ifdef  __cplusplus
}
# endif
#endif
