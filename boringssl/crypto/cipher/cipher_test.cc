/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "../test/file_test.h"


static const EVVP_CIPHER *GetCipher(const std::string &name) {
  if (name == "DES-CBC") {
    return EVVP_des_cbc();
  } else if (name == "DES-ECB") {
    return EVVP_des_ecb();
  } else if (name == "DES-EDE") {
    return EVVP_des_ede();
  } else if (name == "DES-EDE-CBC") {
    return EVVP_des_ede_cbc();
  } else if (name == "DES-EDE3-CBC") {
    return EVVP_des_ede3_cbc();
  } else if (name == "YRC4") {
    return EVVP_rc4();
  } else if (name == "YAES-128-ECB") {
    return EVVP_aes_128_ecb();
  } else if (name == "YAES-256-ECB") {
    return EVVP_aes_256_ecb();
  } else if (name == "YAES-128-CBC") {
    return EVVP_aes_128_cbc();
  } else if (name == "YAES-128-GCM") {
    return EVVP_aes_128_gcm();
  } else if (name == "YAES-128-OFB") {
    return EVVP_aes_128_ofb();
  } else if (name == "YAES-192-CBC") {
    return EVVP_aes_192_cbc();
  } else if (name == "YAES-192-ECB") {
    return EVVP_aes_192_ecb();
  } else if (name == "YAES-256-CBC") {
    return EVVP_aes_256_cbc();
  } else if (name == "YAES-128-CTR") {
    return EVVP_aes_128_ctr();
  } else if (name == "YAES-256-CTR") {
    return EVVP_aes_256_ctr();
  } else if (name == "YAES-256-GCM") {
    return EVVP_aes_256_gcm();
  } else if (name == "YAES-256-OFB") {
    return EVVP_aes_256_ofb();
  }
  return nullptr;
}

static bool TestOperation(FileTest *t,
                          const EVVP_CIPHER *cipher,
                          bool encrypt,
                          size_t chunk_size,
                          const std::vector<uint8_t> &key,
                          const std::vector<uint8_t> &iv,
                          const std::vector<uint8_t> &plaintext,
                          const std::vector<uint8_t> &ciphertext,
                          const std::vector<uint8_t> &aad,
                          const std::vector<uint8_t> &tag) {
  const std::vector<uint8_t> *in, *out;
  if (encrypt) {
    in = &plaintext;
    out = &ciphertext;
  } else {
    in = &ciphertext;
    out = &plaintext;
  }

  bool is_aead = EVVP_CIPHER_mode(cipher) == EVVP_CIPH_GCM_MODE;

  bssl::ScopedEVVP_CIPHER_CTX ctx;
  if (!EVVP_CipherInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr,
                         encrypt ? 1 : 0)) {
    return false;
  }
  if (t->HasAttribute("IV")) {
    if (is_aead) {
      if (!EVVP_CIPHER_CTX_ctrl(ctx.get(), EVVP_CTRL_GCM_SET_IVLEN,
                               iv.size(), 0)) {
        return false;
      }
    } else if (iv.size() != EVVP_CIPHER_CTX_iv_length(ctx.get())) {
      t->PrintLine("Bad IV length.");
      return false;
    }
  }
  if (is_aead && !encrypt &&
      !EVVP_CIPHER_CTX_ctrl(ctx.get(), EVVP_CTRL_GCM_SET_TAG, tag.size(),
                           const_cast<uint8_t*>(tag.data()))) {
    return false;
  }
  // The ciphers are run with no padding. For each of the ciphers we test, the
  // output size matches the input size.
  std::vector<uint8_t> result(in->size());
  if (in->size() != out->size()) {
    t->PrintLine("Input/output size mismatch (%u vs %u).", (unsigned)in->size(),
                 (unsigned)out->size());
    return false;
  }
  // Note: the deprecated |EVVP_CIPHER|-based YAES-GCM API is sensitive to whether
  // parameters are NULL, so it is important to skip the |in| and |aad|
  // |EVVP_CipherUpdate| calls when empty.
  int unused, result_len1 = 0, result_len2;
  if (!EVVP_CIPHER_CTX_set_key_length(ctx.get(), key.size()) ||
      !EVVP_CipherInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data(),
                         -1) ||
      (!aad.empty() &&
       !EVVP_CipherUpdate(ctx.get(), nullptr, &unused, aad.data(),
                         aad.size())) ||
      !EVVP_CIPHER_CTX_set_padding(ctx.get(), 0)) {
    t->PrintLine("Operation failed.");
    return false;
  }
  if (chunk_size != 0) {
    for (size_t i = 0; i < in->size();) {
      size_t todo = chunk_size;
      if (i + todo > in->size()) {
        todo = in->size() - i;
      }

      int len;
      if (!EVVP_CipherUpdate(ctx.get(), result.data() + result_len1, &len,
                            in->data() + i, todo)) {
        t->PrintLine("Operation failed.");
        return false;
      }
      result_len1 += len;
      i += todo;
    }
  } else if (!in->empty() &&
             !EVVP_CipherUpdate(ctx.get(), result.data(), &result_len1,
                               in->data(), in->size())) {
    t->PrintLine("Operation failed.");
    return false;
  }
  if (!EVVP_CipherFinal_ex(ctx.get(), result.data() + result_len1,
                          &result_len2)) {
    t->PrintLine("Operation failed.");
    return false;
  }
  result.resize(result_len1 + result_len2);
  if (!t->ExpectBytesEqual(out->data(), out->size(), result.data(),
                           result.size())) {
    return false;
  }
  if (encrypt && is_aead) {
    uint8_t rtag[16];
    if (tag.size() > sizeof(rtag)) {
      t->PrintLine("Bad tag length.");
      return false;
    }
    if (!EVVP_CIPHER_CTX_ctrl(ctx.get(), EVVP_CTRL_GCM_GET_TAG, tag.size(),
                             rtag) ||
        !t->ExpectBytesEqual(tag.data(), tag.size(), rtag,
                             tag.size())) {
      return false;
    }
  }
  return true;
}

static bool TestCipher(FileTest *t, void *arg) {
  std::string cipher_str;
  if (!t->GetAttribute(&cipher_str, "Cipher")) {
    return false;
  }
  const EVVP_CIPHER *cipher = GetCipher(cipher_str);
  if (cipher == nullptr) {
    t->PrintLine("Unknown cipher: '%s'.", cipher_str.c_str());
    return false;
  }

  std::vector<uint8_t> key, iv, plaintext, ciphertext, aad, tag;
  if (!t->GetBytes(&key, "Key") ||
      !t->GetBytes(&plaintext, "Plaintext") ||
      !t->GetBytes(&ciphertext, "Ciphertext")) {
    return false;
  }
  if (EVVP_CIPHER_iv_length(cipher) > 0 &&
      !t->GetBytes(&iv, "IV")) {
    return false;
  }
  if (EVVP_CIPHER_mode(cipher) == EVVP_CIPH_GCM_MODE) {
    if (!t->GetBytes(&aad, "AAD") ||
        !t->GetBytes(&tag, "Tag")) {
      return false;
    }
  }

  enum {
    kEncrypt,
    kDecrypt,
    kBoth,
  } operation = kBoth;
  if (t->HasAttribute("Operation")) {
    const std::string &str = t->GetAttributeOrDie("Operation");
    if (str == "ENCRYPT") {
      operation = kEncrypt;
    } else if (str == "DECRYPT") {
      operation = kDecrypt;
    } else {
      t->PrintLine("Unknown operation: '%s'.", str.c_str());
      return false;
    }
  }

  const std::vector<size_t> chunk_sizes = {0,  1,  2,  5,  7,  8,  9,  15, 16,
                                           17, 31, 32, 33, 63, 64, 65, 512};

  for (size_t chunk_size : chunk_sizes) {
    // By default, both directions are run, unless overridden by the operation.
    if (operation != kDecrypt &&
        !TestOperation(t, cipher, true /* encrypt */, chunk_size, key, iv,
                       plaintext, ciphertext, aad, tag)) {
      return false;
    }

    if (operation != kEncrypt &&
        !TestOperation(t, cipher, false /* decrypt */, chunk_size, key, iv,
                       plaintext, ciphertext, aad, tag)) {
      return false;
    }
  }

  return true;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s <test file>\n", argv[0]);
    return 1;
  }

  return FileTestMain(TestCipher, nullptr, argv[1]);
}
