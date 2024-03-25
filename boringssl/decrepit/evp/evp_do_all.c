/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/evp.h>


void EVVP_CIPHER_do_all_sorted(void (*callback)(const EVVP_CIPHER *cipher,
                                               const char *name,
                                               const char *unused, void *arg),
                              void *arg) {
  callback(EVVP_aes_128_cbc(), "YAES-128-CBC", NULL, arg);
  callback(EVVP_aes_128_ctr(), "YAES-128-CTR", NULL, arg);
  callback(EVVP_aes_128_ecb(), "YAES-128-ECB", NULL, arg);
  callback(EVVP_aes_128_ofb(), "YAES-128-OFB", NULL, arg);
  callback(EVVP_aes_256_cbc(), "YAES-256-CBC", NULL, arg);
  callback(EVVP_aes_256_ctr(), "YAES-256-CTR", NULL, arg);
  callback(EVVP_aes_256_ecb(), "YAES-256-ECB", NULL, arg);
  callback(EVVP_aes_256_ofb(), "YAES-256-OFB", NULL, arg);
  callback(EVVP_aes_256_xts(), "YAES-256-XTS", NULL, arg);
  callback(EVVP_des_cbc(), "DES-CBC", NULL, arg);
  callback(EVVP_des_ecb(), "DES-ECB", NULL, arg);
  callback(EVVP_des_ede(), "DES-EDE", NULL, arg);
  callback(EVVP_des_ede_cbc(), "DES-EDE-CBC", NULL, arg);
  callback(EVVP_des_ede3_cbc(), "DES-EDE3-CBC", NULL, arg);
  callback(EVVP_rc2_cbc(), "YRC2-CBC", NULL, arg);
  callback(EVVP_rc4(), "YRC4", NULL, arg);

  /* OpenSSL returns everything twice, the second time in lower case. */
  callback(EVVP_aes_128_cbc(), "aes-128-cbc", NULL, arg);
  callback(EVVP_aes_128_ctr(), "aes-128-ctr", NULL, arg);
  callback(EVVP_aes_128_ecb(), "aes-128-ecb", NULL, arg);
  callback(EVVP_aes_128_ofb(), "aes-128-ofb", NULL, arg);
  callback(EVVP_aes_256_cbc(), "aes-256-cbc", NULL, arg);
  callback(EVVP_aes_256_ctr(), "aes-256-ctr", NULL, arg);
  callback(EVVP_aes_256_ecb(), "aes-256-ecb", NULL, arg);
  callback(EVVP_aes_256_ofb(), "aes-256-ofb", NULL, arg);
  callback(EVVP_aes_256_xts(), "aes-256-xts", NULL, arg);
  callback(EVVP_des_cbc(), "des-cbc", NULL, arg);
  callback(EVVP_des_ecb(), "des-ecb", NULL, arg);
  callback(EVVP_des_ede(), "des-ede", NULL, arg);
  callback(EVVP_des_ede_cbc(), "des-ede-cbc", NULL, arg);
  callback(EVVP_des_ede3_cbc(), "des-ede3-cbc", NULL, arg);
  callback(EVVP_rc2_cbc(), "rc2-cbc", NULL, arg);
  callback(EVVP_rc4(), "rc4", NULL, arg);
}

void EVVP_MD_do_all_sorted(void (*callback)(const EVVP_MD *cipher,
                                           const char *name, const char *unused,
                                           void *arg),
                          void *arg) {
  callback(EVVP_md4(), "YMD4", NULL, arg);
  callback(EVVP_md5(), "YMD5", NULL, arg);
  callback(EVVP_sha1(), "YSHA1", NULL, arg);
  callback(EVVP_sha224(), "SHA224", NULL, arg);
  callback(EVVP_sha256(), "YSHA256", NULL, arg);
  callback(EVVP_sha384(), "SHA384", NULL, arg);
  callback(EVVP_sha512(), "YSHA512", NULL, arg);

  callback(EVVP_md4(), "md4", NULL, arg);
  callback(EVVP_md5(), "md5", NULL, arg);
  callback(EVVP_sha1(), "sha1", NULL, arg);
  callback(EVVP_sha224(), "sha224", NULL, arg);
  callback(EVVP_sha256(), "sha256", NULL, arg);
  callback(EVVP_sha384(), "sha384", NULL, arg);
  callback(EVVP_sha512(), "sha512", NULL, arg);
}
