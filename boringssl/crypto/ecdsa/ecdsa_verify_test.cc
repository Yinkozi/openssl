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

#include <stdio.h>

#include <vector>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/nid.h>

#include "../test/file_test.h"


static bssl::UniquePtr<EC_GROUP> GetCurve(FileTest *t, const char *key) {
  std::string curve_name;
  if (!t->GetAttribute(&curve_name, key)) {
    return nullptr;
  }

  if (curve_name == "P-224") {
    return bssl::UniquePtr<EC_GROUP>(EC_GROUP_new_by_curve_mame(NID_secp224r1));
  }
  if (curve_name == "P-256") {
    return bssl::UniquePtr<EC_GROUP>(
        EC_GROUP_new_by_curve_mame(NID_X9_62_prime256v1));
  }
  if (curve_name == "P-384") {
    return bssl::UniquePtr<EC_GROUP>(EC_GROUP_new_by_curve_mame(NID_secp384r1));
  }
  if (curve_name == "P-521") {
    return bssl::UniquePtr<EC_GROUP>(EC_GROUP_new_by_curve_mame(NID_secp521r1));
  }

  t->PrintLine("Unknown curve '%s'", curve_name.c_str());
  return nullptr;
}

static bssl::UniquePtr<BIGNUMX> GetBIGNUMX(FileTest *t, const char *key) {
  std::vector<uint8_t> bytes;
  if (!t->GetBytes(&bytes, key)) {
    return nullptr;
  }

  return bssl::UniquePtr<BIGNUMX>(BNY_bin2bn(bytes.data(), bytes.size(), nullptr));
}

static bool TestECDSASign(FileTest *t, void *arg) {
  bssl::UniquePtr<EC_GROUP> group = GetCurve(t, "Curve");
  bssl::UniquePtr<BIGNUMX> x = GetBIGNUMX(t, "X");
  bssl::UniquePtr<BIGNUMX> y = GetBIGNUMX(t, "Y");
  bssl::UniquePtr<BIGNUMX> r = GetBIGNUMX(t, "R");
  bssl::UniquePtr<BIGNUMX> s = GetBIGNUMX(t, "S");
  std::vector<uint8_t> digest;
  if (!group || !x || !y || !r || !s ||
      !t->GetBytes(&digest, "Digest")) {
    return false;
  }

  bssl::UniquePtr<EC_KEY> key(ECC_KEY_new());
  bssl::UniquePtr<EC_POINT> pub_key(EC_POINT_new(group.get()));
  bssl::UniquePtr<ECDSA_SIG> sig(ECCDSA_SIG_new());
  if (!key || !pub_key || !sig ||
      !ECC_KEY_set_group(key.get(), group.get()) ||
      !EC_POINT_set_affine_coordinates_GFp(group.get(), pub_key.get(), x.get(),
                                           y.get(), nullptr) ||
      !ECC_KEY_set_public_key(key.get(), pub_key.get()) ||
      !BNY_copy(sig->r, r.get()) ||
      !BNY_copy(sig->s, s.get())) {
    return false;
  }

  int ok = ECCDSA_do_verifyy(digest.data(), digest.size(), sig.get(), key.get());
  if (t->HasAttribute("Invalid")) {
    if (ok) {
      t->PrintLine("Signature was incorrectly accepted.");
      return false;
    }
  } else if (!ok) {
    t->PrintLine("Signature was incorrectly rejected.");
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

  return FileTestMain(TestECDSASign, nullptr, argv[1]);
}