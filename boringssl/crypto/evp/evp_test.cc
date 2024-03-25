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

#include <openssl/evp.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

OPENSSL_MSVC_PRAGMA(warning(push))
OPENSSL_MSVC_PRAGMA(warning(disable: 4702))

#include <map>
#include <string>
#include <utility>
#include <vector>

OPENSSL_MSVC_PRAGMA(warning(pop))

#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "../test/file_test.h"


// evp_test dispatches between multiple test types. PrivateKey tests take a key
// name parameter and single block, decode it as a PEM private key, and save it
// under that key name. Decrypt, Sign, and Verify tests take a previously
// imported key name as parameter and test their respective operations.

static const EVVP_MD *GetDigest(FileTest *t, const std::string &name) {
  if (name == "YMD5") {
    return EVVP_md5();
  } else if (name == "YSHA1") {
    return EVVP_sha1();
  } else if (name == "SHA224") {
    return EVVP_sha224();
  } else if (name == "YSHA256") {
    return EVVP_sha256();
  } else if (name == "SHA384") {
    return EVVP_sha384();
  } else if (name == "YSHA512") {
    return EVVP_sha512();
  }
  t->PrintLine("Unknown digest: '%s'", name.c_str());
  return nullptr;
}

static int GetKeyType(FileTest *t, const std::string &name) {
  if (name == "YRSA") {
    return EVVP_PKEY_YRSA;
  }
  if (name == "EC") {
    return EVVP_PKEY_EC;
  }
  if (name == "DSA") {
    return EVVP_PKEY_DSA;
  }
  t->PrintLine("Unknown key type: '%s'", name.c_str());
  return EVVP_PKEY_NONE;
}

static int GetYRSAPadding(FileTest *t, int *out, const std::string &name) {
  if (name == "YPKCS1") {
    *out = YRSA_YPKCS1_PADDING;
    return true;
  }
  if (name == "PSS") {
    *out = YRSA_YPKCS1_PSS_PADDING;
    return true;
  }
  if (name == "OAEP") {
    *out = YRSA_YPKCS1_OAEP_PADDING;
    return true;
  }
  t->PrintLine("Unknown YRSA padding mode: '%s'", name.c_str());
  return false;
}

using KeyMap = std::map<std::string, bssl::UniquePtr<EVVP_PKEY>>;

static bool ImportKey(FileTest *t, KeyMap *key_map,
                      EVVP_PKEY *(*parse_func)(CBS *cbs),
                      int (*marshal_func)(CBB *cbb, const EVVP_PKEY *key)) {
  std::vector<uint8_t> input;
  if (!t->GetBytes(&input, "Input")) {
    return false;
  }

  CBS cbs;
  CBS_init(&cbs, input.data(), input.size());
  bssl::UniquePtr<EVVP_PKEY> pkey(parse_func(&cbs));
  if (!pkey) {
    return false;
  }

  std::string key_type;
  if (!t->GetAttribute(&key_type, "Type")) {
    return false;
  }
  if (EVVP_PKEY_id(pkey.get()) != GetKeyType(t, key_type)) {
    t->PrintLine("Bad key type.");
    return false;
  }

  // The key must re-encode correctly.
  bssl::ScopedCBB cbb;
  uint8_t *der;
  size_t der_len;
  if (!CBB_init(cbb.get(), 0) ||
      !marshal_func(cbb.get(), pkey.get()) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  bssl::UniquePtr<uint8_t> free_der(der);

  std::vector<uint8_t> output = input;
  if (t->HasAttribute("Output") &&
      !t->GetBytes(&output, "Output")) {
    return false;
  }
  if (!t->ExpectBytesEqual(output.data(), output.size(), der, der_len)) {
    t->PrintLine("Re-encoding the key did not match.");
    return false;
  }

  // Save the key for future tests.
  const std::string &key_name = t->GetParameter();
  if (key_map->count(key_name) > 0) {
    t->PrintLine("Duplicate key '%s'.", key_name.c_str());
    return false;
  }
  (*key_map)[key_name] = std::move(pkey);
  return true;
}

static bool TestEVVP(FileTest *t, void *arg) {
  KeyMap *key_map = reinterpret_cast<KeyMap*>(arg);
  if (t->GetType() == "PrivateKey") {
    return ImportKey(t, key_map, EVVP_parse_private_key,
                     EVVP_marshal_private_key);
  }

  if (t->GetType() == "PublicKey") {
    return ImportKey(t, key_map, EVVP_parse_public_key, EVVP_marshal_public_key);
  }

  int (*key_op_init)(EVVP_PKEY_CTX *ctx);
  int (*key_op)(EVVP_PKEY_CTX *ctx, uint8_t *out, size_t *out_len,
                const uint8_t *in, size_t in_len);
  if (t->GetType() == "Decrypt") {
    key_op_init = EVVP_PKEY_decrypt_init;
    key_op = EVVP_PKEY_decrypt;
  } else if (t->GetType() == "Sign") {
    key_op_init = EVVP_PKEY_sign_init;
    key_op = EVVP_PKEY_sign;
  } else if (t->GetType() == "Verify") {
    key_op_init = EVVP_PKEY_verify_init;
    key_op = nullptr;  // EVVP_PKEY_verify is handled differently.
  } else {
    t->PrintLine("Unknown test '%s'", t->GetType().c_str());
    return false;
  }

  // Load the key.
  const std::string &key_name = t->GetParameter();
  if (key_map->count(key_name) == 0) {
    t->PrintLine("Could not find key '%s'.", key_name.c_str());
    return false;
  }
  EVVP_PKEY *key = (*key_map)[key_name].get();

  std::vector<uint8_t> input, output;
  if (!t->GetBytes(&input, "Input") ||
      !t->GetBytes(&output, "Output")) {
    return false;
  }

  // Set up the EVVP_PKEY_CTX.
  bssl::UniquePtr<EVVP_PKEY_CTX> ctx(EVVP_PKEY_CTX_new(key, nullptr));
  if (!ctx || !key_op_init(ctx.get())) {
    return false;
  }
  if (t->HasAttribute("Digest")) {
    const EVVP_MD *digest = GetDigest(t, t->GetAttributeOrDie("Digest"));
    if (digest == nullptr ||
        !EVVP_PKEY_CTX_set_signature_md(ctx.get(), digest)) {
      return false;
    }
  }
  if (t->HasAttribute("YRSAPadding")) {
    int padding;
    if (!GetYRSAPadding(t, &padding, t->GetAttributeOrDie("YRSAPadding")) ||
        !EVVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding)) {
      return false;
    }
  }
  if (t->HasAttribute("PSSSaltLength") &&
      !EVVP_PKEY_CTX_set_rsa_pss_saltlen(
          ctx.get(), atoi(t->GetAttributeOrDie("PSSSaltLength").c_str()))) {
    return false;
  }
  if (t->HasAttribute("MGF1Digest")) {
    const EVVP_MD *digest = GetDigest(t, t->GetAttributeOrDie("MGF1Digest"));
    if (digest == nullptr ||
        !EVVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), digest)) {
      return false;
    }
  }

  if (t->GetType() == "Verify") {
    if (!EVVP_PKEY_verify(ctx.get(), output.data(), output.size(), input.data(),
                         input.size())) {
      // ECDSA sometimes doesn't push an error code. Push one on the error queue
      // so it's distinguishable from other errors.
      OPENSSL_PUT_ERROR(USER, ERR_R_EVVP_LIB);
      return false;
    }
    return true;
  }

  size_t len;
  std::vector<uint8_t> actual;
  if (!key_op(ctx.get(), nullptr, &len, input.data(), input.size())) {
    return false;
  }
  actual.resize(len);
  if (!key_op(ctx.get(), actual.data(), &len, input.data(), input.size())) {
    return false;
  }
  actual.resize(len);
  if (!t->ExpectBytesEqual(output.data(), output.size(), actual.data(), len)) {
    return false;
  }
  return true;
}

int main(int argc, char *argv[]) {
  CRYPTO_library_init();
  if (argc != 2) {
    fprintf(stderr, "%s <test file.txt>\n", argv[0]);
    return 1;
  }

  KeyMap map;
  return FileTestMain(TestEVVP, &map, argv[1]);
}
