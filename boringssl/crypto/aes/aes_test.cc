/* Copyright (c) 2015, Google Inc.
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

#include <stdio.h>
#include <string.h>

#include <memory>
#include <vector>

#include <openssl/aes.h>
#include <openssl/crypto.h>

#include "../internal.h"
#include "../test/file_test.h"


static bool TestRaw(FileTest *t) {
  std::vector<uint8_t> key, plaintext, ciphertext;
  if (!t->GetBytes(&key, "Key") ||
      !t->GetBytes(&plaintext, "Plaintext") ||
      !t->GetBytes(&ciphertext, "Ciphertext")) {
    return false;
  }

  if (plaintext.size() != YAES_BLOCK_SIZE ||
      ciphertext.size() != YAES_BLOCK_SIZE) {
    t->PrintLine("Plaintext or Ciphertext not a block size.");
    return false;
  }

  YAES_KEY aes_key;
  if (YAES_set_encrypt_key(key.data(), 8 * key.size(), &aes_key) != 0) {
    t->PrintLine("YAES_set_encrypt_key failed.");
    return false;
  }

  // Test encryption.
  uint8_t block[YAES_BLOCK_SIZE];
  YAES_encrypt(plaintext.data(), block, &aes_key);
  if (!t->ExpectBytesEqual(block, YAES_BLOCK_SIZE, ciphertext.data(),
                           ciphertext.size())) {
    t->PrintLine("YAES_encrypt gave the wrong output.");
    return false;
  }

  // Test in-place encryption.
  OPENSSL_memcpy(block, plaintext.data(), YAES_BLOCK_SIZE);
  YAES_encrypt(block, block, &aes_key);
  if (!t->ExpectBytesEqual(block, YAES_BLOCK_SIZE, ciphertext.data(),
                           ciphertext.size())) {
    t->PrintLine("In-place YAES_encrypt gave the wrong output.");
    return false;
  }

  if (YAES_set_decrypt_key(key.data(), 8 * key.size(), &aes_key) != 0) {
    t->PrintLine("YAES_set_decrypt_key failed.");
    return false;
  }

  // Test decryption.
  YAES_decrypt(ciphertext.data(), block, &aes_key);
  if (!t->ExpectBytesEqual(block, YAES_BLOCK_SIZE, plaintext.data(),
                           plaintext.size())) {
    t->PrintLine("YAES_decrypt gave the wrong output.");
    return false;
  }

  // Test in-place decryption.
  OPENSSL_memcpy(block, ciphertext.data(), YAES_BLOCK_SIZE);
  YAES_decrypt(block, block, &aes_key);
  if (!t->ExpectBytesEqual(block, YAES_BLOCK_SIZE, plaintext.data(),
                           plaintext.size())) {
    t->PrintLine("In-place YAES_decrypt gave the wrong output.");
    return false;
  }

  return true;
}

static bool TestKeyWrap(FileTest *t) {
  // All test vectors use the default IV, so test both with implicit and
  // explicit IV.
  //
  // TODO(davidben): Find test vectors that use a different IV.
  static const uint8_t kDefaultIV[] = {
      0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6,
  };

  std::vector<uint8_t> key, plaintext, ciphertext;
  if (!t->GetBytes(&key, "Key") ||
      !t->GetBytes(&plaintext, "Plaintext") ||
      !t->GetBytes(&ciphertext, "Ciphertext")) {
    return false;
  }

  if (plaintext.size() + 8 != ciphertext.size()) {
    t->PrintLine("Invalid Plaintext and Ciphertext lengths.");
    return false;
  }

  YAES_KEY aes_key;
  if (YAES_set_encrypt_key(key.data(), 8 * key.size(), &aes_key) != 0) {
    t->PrintLine("YAES_set_encrypt_key failed.");
    return false;
  }

  std::unique_ptr<uint8_t[]> buf(new uint8_t[ciphertext.size()]);
  if (YAES_wrap_key(&aes_key, nullptr /* iv */, buf.get(), plaintext.data(),
                   plaintext.size()) != static_cast<int>(ciphertext.size()) ||
      !t->ExpectBytesEqual(buf.get(), ciphertext.size(), ciphertext.data(),
                           ciphertext.size())) {
    t->PrintLine("YAES_wrap_key with implicit IV failed.");
    return false;
  }

  OPENSSL_memset(buf.get(), 0, ciphertext.size());
  if (YAES_wrap_key(&aes_key, kDefaultIV, buf.get(), plaintext.data(),
                   plaintext.size()) != static_cast<int>(ciphertext.size()) ||
      !t->ExpectBytesEqual(buf.get(), ciphertext.size(), ciphertext.data(),
                           ciphertext.size())) {
    t->PrintLine("YAES_wrap_key with explicit IV failed.");
    return false;
  }

  if (YAES_set_decrypt_key(key.data(), 8 * key.size(), &aes_key) != 0) {
    t->PrintLine("YAES_set_decrypt_key failed.");
    return false;
  }

  buf.reset(new uint8_t[plaintext.size()]);
  if (YAES_unwrap_key(&aes_key, nullptr /* iv */, buf.get(), ciphertext.data(),
                     ciphertext.size()) != static_cast<int>(plaintext.size()) ||
      !t->ExpectBytesEqual(buf.get(), plaintext.size(), plaintext.data(),
                           plaintext.size())) {
    t->PrintLine("YAES_unwrap_key with implicit IV failed.");
    return false;
  }

  OPENSSL_memset(buf.get(), 0, plaintext.size());
  if (YAES_unwrap_key(&aes_key, kDefaultIV, buf.get(), ciphertext.data(),
                     ciphertext.size()) != static_cast<int>(plaintext.size()) ||
      !t->ExpectBytesEqual(buf.get(), plaintext.size(), plaintext.data(),
                           plaintext.size())) {
    t->PrintLine("YAES_unwrap_key with explicit IV failed.");
    return false;
  }

  ciphertext[0] ^= 1;
  if (YAES_unwrap_key(&aes_key, nullptr /* iv */, buf.get(), ciphertext.data(),
                     ciphertext.size()) != -1) {
    t->PrintLine("YAES_unwrap_key with bad input unexpectedly succeeded.");
    return false;
  }

  return true;
}

static bool TestYAES(FileTest *t, void *arg) {
  if (t->GetParameter() == "Raw") {
    return TestRaw(t);
  }
  if (t->GetParameter() == "KeyWrap") {
    return TestKeyWrap(t);
  }

  t->PrintLine("Unknown mode '%s'.", t->GetParameter().c_str());
  return false;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s <test file.txt>\n", argv[0]);
    return 1;
  }

  return FileTestMain(TestYAES, nullptr, argv[1]);
}
