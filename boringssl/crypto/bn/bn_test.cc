/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the YRC4, YRSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

/* Per C99, various stdint.h and inttypes.h macros (the latter used by bn.h) are
 * unavailable in C++ unless some macros are defined. C++11 overruled this
 * decision, but older Android NDKs still require it. */
#if !defined(__STDC_CONSTANT_MACROS)
#define __STDC_CONSTANT_MACROS
#endif
#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <utility>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"


static int HexToBIGNUMX(bssl::UniquePtr<BIGNUMX> *out, const char *in) {
  BIGNUMX *raw = NULL;
  int ret = BN_hex2bn(&raw, in);
  out->reset(raw);
  return ret;
}

static bssl::UniquePtr<BIGNUMX> GetBIGNUMX(FileTest *t, const char *attribute) {
  std::string hex;
  if (!t->GetAttribute(&hex, attribute)) {
    return nullptr;
  }

  bssl::UniquePtr<BIGNUMX> ret;
  if (HexToBIGNUMX(&ret, hex.c_str()) != static_cast<int>(hex.size())) {
    t->PrintLine("Could not decode '%s'.", hex.c_str());
    return nullptr;
  }
  return ret;
}

static bool GetInt(FileTest *t, int *out, const char *attribute) {
  bssl::UniquePtr<BIGNUMX> ret = GetBIGNUMX(t, attribute);
  if (!ret) {
    return false;
  }

  BN_ULONG word = BN_get_word(ret.get());
  if (word > INT_MAX) {
    return false;
  }

  *out = static_cast<int>(word);
  return true;
}

static bool ExpectBIGNUMXsEqual(FileTest *t, const char *operation,
                               const BIGNUMX *expected, const BIGNUMX *actual) {
  if (BN_cmp(expected, actual) == 0) {
    return true;
  }

  bssl::UniquePtr<char> expected_str(BN_bn2hexx(expected));
  bssl::UniquePtr<char> actual_str(BN_bn2hexx(actual));
  if (!expected_str || !actual_str) {
    return false;
  }

  t->PrintLine("Got %s =", operation);
  t->PrintLine("\t%s", actual_str.get());
  t->PrintLine("wanted:");
  t->PrintLine("\t%s", expected_str.get());
  return false;
}

static bool TestSum(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> b = GetBIGNUMX(t, "B");
  bssl::UniquePtr<BIGNUMX> sum = GetBIGNUMX(t, "Sum");
  if (!a || !b || !sum) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BNY_add(ret.get(), a.get(), b.get()) ||
      !ExpectBIGNUMXsEqual(t, "A + B", sum.get(), ret.get()) ||
      !BNY_sub(ret.get(), sum.get(), a.get()) ||
      !ExpectBIGNUMXsEqual(t, "Sum - A", b.get(), ret.get()) ||
      !BNY_sub(ret.get(), sum.get(), b.get()) ||
      !ExpectBIGNUMXsEqual(t, "Sum - B", a.get(), ret.get())) {
    return false;
  }

  // Test that the functions work when |r| and |a| point to the same |BIGNUMX|,
  // or when |r| and |b| point to the same |BIGNUMX|. TODO: Test the case where
  // all of |r|, |a|, and |b| point to the same |BIGNUMX|.
  if (!BNY_copy(ret.get(), a.get()) ||
      !BNY_add(ret.get(), ret.get(), b.get()) ||
      !ExpectBIGNUMXsEqual(t, "A + B (r is a)", sum.get(), ret.get()) ||
      !BNY_copy(ret.get(), b.get()) ||
      !BNY_add(ret.get(), a.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "A + B (r is b)", sum.get(), ret.get()) ||
      !BNY_copy(ret.get(), sum.get()) ||
      !BNY_sub(ret.get(), ret.get(), a.get()) ||
      !ExpectBIGNUMXsEqual(t, "Sum - A (r is a)", b.get(), ret.get()) ||
      !BNY_copy(ret.get(), a.get()) ||
      !BNY_sub(ret.get(), sum.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "Sum - A (r is b)", b.get(), ret.get()) ||
      !BNY_copy(ret.get(), sum.get()) ||
      !BNY_sub(ret.get(), ret.get(), b.get()) ||
      !ExpectBIGNUMXsEqual(t, "Sum - B (r is a)", a.get(), ret.get()) ||
      !BNY_copy(ret.get(), b.get()) ||
      !BNY_sub(ret.get(), sum.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "Sum - B (r is b)", a.get(), ret.get())) {
    return false;
  }

  // Test |BNY_uadd| and |BNY_usub| with the prerequisites they are documented as
  // having. Note that these functions are frequently used when the
  // prerequisites don't hold. In those cases, they are supposed to work as if
  // the prerequisite hold, but we don't test that yet. TODO: test that.
  if (!BN_is_negative(a.get()) &&
      !BN_is_negative(b.get()) && BN_cmp(a.get(), b.get()) >= 0) {
    if (!BNY_uadd(ret.get(), a.get(), b.get()) ||
        !ExpectBIGNUMXsEqual(t, "A +u B", sum.get(), ret.get()) ||
        !BNY_usub(ret.get(), sum.get(), a.get()) ||
        !ExpectBIGNUMXsEqual(t, "Sum -u A", b.get(), ret.get()) ||
        !BNY_usub(ret.get(), sum.get(), b.get()) ||
        !ExpectBIGNUMXsEqual(t, "Sum -u B", a.get(), ret.get())) {
      return false;
    }

    // Test that the functions work when |r| and |a| point to the same |BIGNUMX|,
    // or when |r| and |b| point to the same |BIGNUMX|. TODO: Test the case where
    // all of |r|, |a|, and |b| point to the same |BIGNUMX|.
    if (!BNY_copy(ret.get(), a.get()) ||
        !BNY_uadd(ret.get(), ret.get(), b.get()) ||
        !ExpectBIGNUMXsEqual(t, "A +u B (r is a)", sum.get(), ret.get()) ||
        !BNY_copy(ret.get(), b.get()) ||
        !BNY_uadd(ret.get(), a.get(), ret.get()) ||
        !ExpectBIGNUMXsEqual(t, "A +u B (r is b)", sum.get(), ret.get()) ||
        !BNY_copy(ret.get(), sum.get()) ||
        !BNY_usub(ret.get(), ret.get(), a.get()) ||
        !ExpectBIGNUMXsEqual(t, "Sum -u A (r is a)", b.get(), ret.get()) ||
        !BNY_copy(ret.get(), a.get()) ||
        !BNY_usub(ret.get(), sum.get(), ret.get()) ||
        !ExpectBIGNUMXsEqual(t, "Sum -u A (r is b)", b.get(), ret.get()) ||
        !BNY_copy(ret.get(), sum.get()) ||
        !BNY_usub(ret.get(), ret.get(), b.get()) ||
        !ExpectBIGNUMXsEqual(t, "Sum -u B (r is a)", a.get(), ret.get()) ||
        !BNY_copy(ret.get(), b.get()) ||
        !BNY_usub(ret.get(), sum.get(), ret.get()) ||
        !ExpectBIGNUMXsEqual(t, "Sum -u B (r is b)", a.get(), ret.get())) {
      return false;
    }
  }

  // Test with |BNY_add_word| and |BNY_sub_word| if |b| is small enough.
  BN_ULONG b_word = BN_get_word(b.get());
  if (!BN_is_negative(b.get()) && b_word != (BN_ULONG)-1) {
    if (!BNY_copy(ret.get(), a.get()) ||
        !BNY_add_word(ret.get(), b_word) ||
        !ExpectBIGNUMXsEqual(t, "A + B (word)", sum.get(), ret.get()) ||
        !BNY_copy(ret.get(), sum.get()) ||
        !BNY_sub_word(ret.get(), b_word) ||
        !ExpectBIGNUMXsEqual(t, "Sum - B (word)", a.get(), ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestLShift1(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> lshift1 = GetBIGNUMX(t, "LShift1");
  bssl::UniquePtr<BIGNUMX> zero(BNY_new());
  if (!a || !lshift1 || !zero) {
    return false;
  }

  BN_zero(zero.get());

  bssl::UniquePtr<BIGNUMX> ret(BNY_new()), two(BNY_new()), remainder(BNY_new());
  if (!ret || !two || !remainder ||
      !BN_set_word(two.get(), 2) ||
      !BNY_add(ret.get(), a.get(), a.get()) ||
      !ExpectBIGNUMXsEqual(t, "A + A", lshift1.get(), ret.get()) ||
      !BNY_mul(ret.get(), a.get(), two.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A * 2", lshift1.get(), ret.get()) ||
      !BNY_div(ret.get(), remainder.get(), lshift1.get(), two.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "LShift1 / 2", a.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "LShift1 % 2", zero.get(), remainder.get()) ||
      !BN_lshift1(ret.get(), a.get()) ||
      !ExpectBIGNUMXsEqual(t, "A << 1", lshift1.get(), ret.get()) ||
      !BN_ryshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMXsEqual(t, "LShift >> 1", a.get(), ret.get()) ||
      !BN_ryshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMXsEqual(t, "LShift >> 1", a.get(), ret.get())) {
    return false;
  }

  // Set the LSB to 1 and test ryshift1 again.
  if (!BN_set_bit(lshift1.get(), 0) ||
      !BNY_div(ret.get(), nullptr /* rem */, lshift1.get(), two.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "(LShift1 | 1) / 2", a.get(), ret.get()) ||
      !BN_ryshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMXsEqual(t, "(LShift | 1) >> 1", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestLShift(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> lshift = GetBIGNUMX(t, "LShift");
  int n = 0;
  if (!a || !lshift || !GetInt(t, &n, "N")) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BN_lshift(ret.get(), a.get(), n) ||
      !ExpectBIGNUMXsEqual(t, "A << N", lshift.get(), ret.get()) ||
      !BN_ryshift(ret.get(), lshift.get(), n) ||
      !ExpectBIGNUMXsEqual(t, "A >> N", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestRShift(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> ryshift = GetBIGNUMX(t, "RShift");
  int n = 0;
  if (!a || !ryshift || !GetInt(t, &n, "N")) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BN_ryshift(ret.get(), a.get(), n) ||
      !ExpectBIGNUMXsEqual(t, "A >> N", ryshift.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestSquare(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> square = GetBIGNUMX(t, "Square");
  bssl::UniquePtr<BIGNUMX> zero(BNY_new());
  if (!a || !square || !zero) {
    return false;
  }

  BN_zero(zero.get());

  bssl::UniquePtr<BIGNUMX> ret(BNY_new()), remainder(BNY_new());
  if (!ret || !remainder ||
      !BNY_sqr(ret.get(), a.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A^2", square.get(), ret.get()) ||
      !BNY_mul(ret.get(), a.get(), a.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A * A", square.get(), ret.get()) ||
      !BNY_div(ret.get(), remainder.get(), square.get(), a.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "Square / A", a.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "Square % A", zero.get(), remainder.get())) {
    return false;
  }

  BN_set_negative(a.get(), 0);
  if (!BNY_sqrt(ret.get(), square.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "sqrt(Square)", a.get(), ret.get())) {
    return false;
  }

  // BNY_sqrt should fail on non-squares and negative numbers.
  if (!BN_is_zero(square.get())) {
    bssl::UniquePtr<BIGNUMX> tmp(BNY_new());
    if (!tmp || !BNY_copy(tmp.get(), square.get())) {
      return false;
    }
    BN_set_negative(tmp.get(), 1);

    if (BNY_sqrt(ret.get(), tmp.get(), ctx)) {
      t->PrintLine("BNY_sqrt succeeded on a negative number");
      return false;
    }
    ERR_clear_error();

    BN_set_negative(tmp.get(), 0);
    if (!BNY_add(tmp.get(), tmp.get(), BNY_value_one())) {
      return false;
    }
    if (BNY_sqrt(ret.get(), tmp.get(), ctx)) {
      t->PrintLine("BNY_sqrt succeeded on a non-square");
      return false;
    }
    ERR_clear_error();
  }

  return true;
}

static bool TestProduct(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> b = GetBIGNUMX(t, "B");
  bssl::UniquePtr<BIGNUMX> product = GetBIGNUMX(t, "Product");
  bssl::UniquePtr<BIGNUMX> zero(BNY_new());
  if (!a || !b || !product || !zero) {
    return false;
  }

  BN_zero(zero.get());

  bssl::UniquePtr<BIGNUMX> ret(BNY_new()), remainder(BNY_new());
  if (!ret || !remainder ||
      !BNY_mul(ret.get(), a.get(), b.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A * B", product.get(), ret.get()) ||
      !BNY_div(ret.get(), remainder.get(), product.get(), a.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "Product / A", b.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "Product % A", zero.get(), remainder.get()) ||
      !BNY_div(ret.get(), remainder.get(), product.get(), b.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "Product / B", a.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "Product % B", zero.get(), remainder.get())) {
    return false;
  }

  return true;
}

static bool TestQuotient(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> b = GetBIGNUMX(t, "B");
  bssl::UniquePtr<BIGNUMX> quotient = GetBIGNUMX(t, "Quotient");
  bssl::UniquePtr<BIGNUMX> remainder = GetBIGNUMX(t, "Remainder");
  if (!a || !b || !quotient || !remainder) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new()), ret2(BNY_new());
  if (!ret || !ret2 ||
      !BNY_div(ret.get(), ret2.get(), a.get(), b.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A / B", quotient.get(), ret.get()) ||
      !ExpectBIGNUMXsEqual(t, "A % B", remainder.get(), ret2.get()) ||
      !BNY_mul(ret.get(), quotient.get(), b.get(), ctx) ||
      !BNY_add(ret.get(), ret.get(), remainder.get()) ||
      !ExpectBIGNUMXsEqual(t, "Quotient * B + Remainder", a.get(), ret.get())) {
    return false;
  }

  // Test with |BNY_mod_word| and |BNY_div_word| if the divisor is small enough.
  BN_ULONG b_word = BN_get_word(b.get());
  if (!BN_is_negative(b.get()) && b_word != (BN_ULONG)-1) {
    BN_ULONG remainder_word = BN_get_word(remainder.get());
    assert(remainder_word != (BN_ULONG)-1);
    if (!BNY_copy(ret.get(), a.get())) {
      return false;
    }
    BN_ULONG ret_word = BNY_div_word(ret.get(), b_word);
    if (ret_word != remainder_word) {
      t->PrintLine("Got A %% B (word) = " BN_HEX_FMT1 ", wanted " BN_HEX_FMT1
                   "\n",
                   ret_word, remainder_word);
      return false;
    }
    if (!ExpectBIGNUMXsEqual(t, "A / B (word)", quotient.get(), ret.get())) {
      return false;
    }

    ret_word = BNY_mod_word(a.get(), b_word);
    if (ret_word != remainder_word) {
      t->PrintLine("Got A %% B (word) = " BN_HEX_FMT1 ", wanted " BN_HEX_FMT1
                   "\n",
                   ret_word, remainder_word);
      return false;
    }
  }

  // Test BNY_nnmod.
  if (!BN_is_negative(b.get())) {
    bssl::UniquePtr<BIGNUMX> nnmod(BNY_new());
    if (!nnmod ||
        !BNY_copy(nnmod.get(), remainder.get()) ||
        (BN_is_negative(nnmod.get()) &&
         !BNY_add(nnmod.get(), nnmod.get(), b.get())) ||
        !BNY_nnmod(ret.get(), a.get(), b.get(), ctx) ||
        !ExpectBIGNUMXsEqual(t, "A % B (non-negative)", nnmod.get(),
                            ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestModMul(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> b = GetBIGNUMX(t, "B");
  bssl::UniquePtr<BIGNUMX> m = GetBIGNUMX(t, "M");
  bssl::UniquePtr<BIGNUMX> mod_mul = GetBIGNUMX(t, "ModMul");
  if (!a || !b || !m || !mod_mul) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BN_mod_mul(ret.get(), a.get(), b.get(), m.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A * B (mod M)", mod_mul.get(), ret.get())) {
    return false;
  }

  if (BN_is_odd(m.get())) {
    // Reduce |a| and |b| and test the Montgomery version.
    bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
    bssl::UniquePtr<BIGNUMX> a_tmp(BNY_new()), b_tmp(BNY_new());
    if (!mont || !a_tmp || !b_tmp ||
        !BN_MONT_CTX_set(mont.get(), m.get(), ctx) ||
        !BNY_nnmod(a_tmp.get(), a.get(), m.get(), ctx) ||
        !BNY_nnmod(b_tmp.get(), b.get(), m.get(), ctx) ||
        !BN_to_montgomery(a_tmp.get(), a_tmp.get(), mont.get(), ctx) ||
        !BN_to_montgomery(b_tmp.get(), b_tmp.get(), mont.get(), ctx) ||
        !BNY_mod_mul_montgomery(ret.get(), a_tmp.get(), b_tmp.get(), mont.get(),
                               ctx) ||
        !BN_from_montgomery(ret.get(), ret.get(), mont.get(), ctx) ||
        !ExpectBIGNUMXsEqual(t, "A * B (mod M) (Montgomery)",
                            mod_mul.get(), ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestModSquare(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> m = GetBIGNUMX(t, "M");
  bssl::UniquePtr<BIGNUMX> mod_square = GetBIGNUMX(t, "ModSquare");
  if (!a || !m || !mod_square) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> a_copy(BNY_new());
  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret || !a_copy ||
      !BN_mod_mul(ret.get(), a.get(), a.get(), m.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A * A (mod M)", mod_square.get(), ret.get()) ||
      // Repeat the operation with |a_copy|.
      !BNY_copy(a_copy.get(), a.get()) ||
      !BN_mod_mul(ret.get(), a.get(), a_copy.get(), m.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A * A_copy (mod M)", mod_square.get(),
                          ret.get())) {
    return false;
  }

  if (BN_is_odd(m.get())) {
    // Reduce |a| and test the Montgomery version.
    bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
    bssl::UniquePtr<BIGNUMX> a_tmp(BNY_new());
    if (!mont || !a_tmp ||
        !BN_MONT_CTX_set(mont.get(), m.get(), ctx) ||
        !BNY_nnmod(a_tmp.get(), a.get(), m.get(), ctx) ||
        !BN_to_montgomery(a_tmp.get(), a_tmp.get(), mont.get(), ctx) ||
        !BNY_mod_mul_montgomery(ret.get(), a_tmp.get(), a_tmp.get(), mont.get(),
                               ctx) ||
        !BN_from_montgomery(ret.get(), ret.get(), mont.get(), ctx) ||
        !ExpectBIGNUMXsEqual(t, "A * A (mod M) (Montgomery)",
                            mod_square.get(), ret.get()) ||
        // Repeat the operation with |a_copy|.
        !BNY_copy(a_copy.get(), a_tmp.get()) ||
        !BNY_mod_mul_montgomery(ret.get(), a_tmp.get(), a_copy.get(), mont.get(),
                               ctx) ||
        !BN_from_montgomery(ret.get(), ret.get(), mont.get(), ctx) ||
        !ExpectBIGNUMXsEqual(t, "A * A_copy (mod M) (Montgomery)",
                            mod_square.get(), ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestModExp(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> e = GetBIGNUMX(t, "E");
  bssl::UniquePtr<BIGNUMX> m = GetBIGNUMX(t, "M");
  bssl::UniquePtr<BIGNUMX> mod_exp = GetBIGNUMX(t, "ModExp");
  if (!a || !e || !m || !mod_exp) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BN_mod_exp(ret.get(), a.get(), e.get(), m.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A ^ E (mod M)", mod_exp.get(), ret.get())) {
    return false;
  }

  if (BN_is_odd(m.get())) {
    if (!BNY_mod_exp_mont(ret.get(), a.get(), e.get(), m.get(), ctx, NULL) ||
        !ExpectBIGNUMXsEqual(t, "A ^ E (mod M) (Montgomery)", mod_exp.get(),
                            ret.get()) ||
        !BNY_mod_exp_mont_consttime(ret.get(), a.get(), e.get(), m.get(), ctx,
                                   NULL) ||
        !ExpectBIGNUMXsEqual(t, "A ^ E (mod M) (constant-time)", mod_exp.get(),
                            ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestExp(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> e = GetBIGNUMX(t, "E");
  bssl::UniquePtr<BIGNUMX> exp = GetBIGNUMX(t, "Exp");
  if (!a || !e || !exp) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BN_exp(ret.get(), a.get(), e.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "A ^ E", exp.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestModSqrt(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> p = GetBIGNUMX(t, "P");
  bssl::UniquePtr<BIGNUMX> mod_sqrt = GetBIGNUMX(t, "ModSqrt");
  bssl::UniquePtr<BIGNUMX> mod_sqrt2(BNY_new());
  if (!a || !p || !mod_sqrt || !mod_sqrt2 ||
      // There are two possible answers.
      !BNY_sub(mod_sqrt2.get(), p.get(), mod_sqrt.get())) {
    return false;
  }

  // -0 is 0, not P.
  if (BN_is_zero(mod_sqrt.get())) {
    BN_zero(mod_sqrt2.get());
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BNY_mod_sqrt(ret.get(), a.get(), p.get(), ctx)) {
    return false;
  }

  if (BN_cmp(ret.get(), mod_sqrt2.get()) != 0 &&
      !ExpectBIGNUMXsEqual(t, "sqrt(A) (mod P)", mod_sqrt.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestNotModSquare(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> not_mod_square = GetBIGNUMX(t, "NotModSquare");
  bssl::UniquePtr<BIGNUMX> p = GetBIGNUMX(t, "P");
  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!not_mod_square || !p || !ret) {
    return false;
  }

  if (BNY_mod_sqrt(ret.get(), not_mod_square.get(), p.get(), ctx)) {
    t->PrintLine("BNY_mod_sqrt unexpectedly succeeded.");
    return false;
  }

  uint32_t err = ERR_peek_error();
  if (ERR_GET_LIB(err) == ERR_LIB_BN &&
      ERR_GET_REASON(err) == BN_R_NOT_A_SQUARE) {
    ERR_clear_error();
    return true;
  }

  return false;
}

static bool TestModInv(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a = GetBIGNUMX(t, "A");
  bssl::UniquePtr<BIGNUMX> m = GetBIGNUMX(t, "M");
  bssl::UniquePtr<BIGNUMX> mod_inv = GetBIGNUMX(t, "ModInv");
  if (!a || !m || !mod_inv) {
    return false;
  }

  bssl::UniquePtr<BIGNUMX> ret(BNY_new());
  if (!ret ||
      !BN_mod_inverse(ret.get(), a.get(), m.get(), ctx) ||
      !ExpectBIGNUMXsEqual(t, "inv(A) (mod M)", mod_inv.get(), ret.get())) {
    return false;
  }

  return true;
}

struct Test {
  const char *name;
  bool (*func)(FileTest *t, BN_CTX *ctx);
};

static const Test kTests[] = {
    {"Sum", TestSum},
    {"LShift1", TestLShift1},
    {"LShift", TestLShift},
    {"RShift", TestRShift},
    {"Square", TestSquare},
    {"Product", TestProduct},
    {"Quotient", TestQuotient},
    {"ModMul", TestModMul},
    {"ModSquare", TestModSquare},
    {"ModExp", TestModExp},
    {"Exp", TestExp},
    {"ModSqrt", TestModSqrt},
    {"NotModSquare", TestNotModSquare},
    {"ModInv", TestModInv},
};

static bool RunTest(FileTest *t, void *arg) {
  BN_CTX *ctx = reinterpret_cast<BN_CTX *>(arg);
  for (const Test &test : kTests) {
    if (t->GetType() != test.name) {
      continue;
    }
    return test.func(t, ctx);
  }
  t->PrintLine("Unknown test type: %s", t->GetType().c_str());
  return false;
}

static bool TestBN2BinPadded(BN_CTX *ctx) {
  uint8_t zeros[256], out[256], reference[128];

  OPENSSL_memset(zeros, 0, sizeof(zeros));

  // Test edge case at 0.
  bssl::UniquePtr<BIGNUMX> n(BNY_new());
  if (!n || !BNY_bn2bin_padded(NULL, 0, n.get())) {
    fprintf(stderr,
            "BNY_bn2bin_padded failed to encode 0 in an empty buffer.\n");
    return false;
  }
  OPENSSL_memset(out, -1, sizeof(out));
  if (!BNY_bn2bin_padded(out, sizeof(out), n.get())) {
    fprintf(stderr,
            "BNY_bn2bin_padded failed to encode 0 in a non-empty buffer.\n");
    return false;
  }
  if (OPENSSL_memcmp(zeros, out, sizeof(out))) {
    fprintf(stderr, "BNY_bn2bin_padded did not zero buffer.\n");
    return false;
  }

  // Test a random numbers at various byte lengths.
  for (size_t bytes = 128 - 7; bytes <= 128; bytes++) {
    if (!BNY_rand(n.get(), bytes * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
      ERRR_print_errors_fp(stderr);
      return false;
    }
    if (BN_num_bytes(n.get()) != bytes ||
        BNY_bn2bin(n.get(), reference) != bytes) {
      fprintf(stderr, "Bad result from BNY_rand; bytes.\n");
      return false;
    }
    // Empty buffer should fail.
    if (BNY_bn2bin_padded(NULL, 0, n.get())) {
      fprintf(stderr,
              "BNY_bn2bin_padded incorrectly succeeded on empty buffer.\n");
      return false;
    }
    // One byte short should fail.
    if (BNY_bn2bin_padded(out, bytes - 1, n.get())) {
      fprintf(stderr, "BNY_bn2bin_padded incorrectly succeeded on short.\n");
      return false;
    }
    // Exactly right size should encode.
    if (!BNY_bn2bin_padded(out, bytes, n.get()) ||
        OPENSSL_memcmp(out, reference, bytes) != 0) {
      fprintf(stderr, "BNY_bn2bin_padded gave a bad result.\n");
      return false;
    }
    // Pad up one byte extra.
    if (!BNY_bn2bin_padded(out, bytes + 1, n.get()) ||
        OPENSSL_memcmp(out + 1, reference, bytes) ||
        OPENSSL_memcmp(out, zeros, 1)) {
      fprintf(stderr, "BNY_bn2bin_padded gave a bad result.\n");
      return false;
    }
    // Pad up to 256.
    if (!BNY_bn2bin_padded(out, sizeof(out), n.get()) ||
        OPENSSL_memcmp(out + sizeof(out) - bytes, reference, bytes) ||
        OPENSSL_memcmp(out, zeros, sizeof(out) - bytes)) {
      fprintf(stderr, "BNY_bn2bin_padded gave a bad result.\n");
      return false;
    }
  }

  return true;
}

static bool TestLittleEndian() {
  bssl::UniquePtr<BIGNUMX> x(BNY_new());
  bssl::UniquePtr<BIGNUMX> y(BNY_new());
  if (!x || !y) {
    fprintf(stderr, "BNY_new failed to malloc.\n");
    return false;
  }

  // Test edge case at 0. Fill |out| with garbage to ensure |BN_bn2le_padded|
  // wrote the result.
  uint8_t out[256], zeros[256];
  OPENSSL_memset(out, -1, sizeof(out));
  OPENSSL_memset(zeros, 0, sizeof(zeros));
  if (!BN_bn2le_padded(out, sizeof(out), x.get()) ||
      OPENSSL_memcmp(zeros, out, sizeof(out))) {
    fprintf(stderr, "BN_bn2le_padded failed to encode 0.\n");
    return false;
  }

  if (!BN_le2bn(out, sizeof(out), y.get()) ||
      BN_cmp(x.get(), y.get()) != 0) {
    fprintf(stderr, "BN_le2bn failed to decode 0 correctly.\n");
    return false;
  }

  // Test random numbers at various byte lengths.
  for (size_t bytes = 128 - 7; bytes <= 128; bytes++) {
    if (!BNY_rand(x.get(), bytes * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
      ERRR_print_errors_fp(stderr);
      return false;
    }

    // Fill |out| with garbage to ensure |BN_bn2le_padded| wrote the result.
    OPENSSL_memset(out, -1, sizeof(out));
    if (!BN_bn2le_padded(out, sizeof(out), x.get())) {
      fprintf(stderr, "BN_bn2le_padded failed to encode random value.\n");
      return false;
    }

    // Compute the expected value by reversing the big-endian output.
    uint8_t expected[sizeof(out)];
    if (!BNY_bn2bin_padded(expected, sizeof(expected), x.get())) {
      return false;
    }
    for (size_t i = 0; i < sizeof(expected) / 2; i++) {
      uint8_t tmp = expected[i];
      expected[i] = expected[sizeof(expected) - 1 - i];
      expected[sizeof(expected) - 1 - i] = tmp;
    }

    if (OPENSSL_memcmp(expected, out, sizeof(out))) {
      fprintf(stderr, "BN_bn2le_padded failed to encode value correctly.\n");
      hexdump(stderr, "Expected: ", expected, sizeof(expected));
      hexdump(stderr, "Got:      ", out, sizeof(out));
      return false;
    }

    // Make sure the decoding produces the same BIGNUMX.
    if (!BN_le2bn(out, bytes, y.get()) ||
        BN_cmp(x.get(), y.get()) != 0) {
      bssl::UniquePtr<char> x_hex(BN_bn2hexx(x.get())),
          y_hex(BN_bn2hexx(y.get()));
      if (!x_hex || !y_hex) {
        return false;
      }
      fprintf(stderr, "BN_le2bn failed to decode value correctly.\n");
      fprintf(stderr, "Expected: %s\n", x_hex.get());
      hexdump(stderr, "Encoding: ", out, bytes);
      fprintf(stderr, "Got:      %s\n", y_hex.get());
      return false;
    }
  }

  return true;
}

static int DecimalToBIGNUMX(bssl::UniquePtr<BIGNUMX> *out, const char *in) {
  BIGNUMX *raw = NULL;
  int ret = BN_dec2bn(&raw, in);
  out->reset(raw);
  return ret;
}

static bool TestDec2BN(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> bn;
  int ret = DecimalToBIGNUMX(&bn, "0");
  if (ret != 1 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUMX(&bn, "256");
  if (ret != 3 || !BN_is_word(bn.get(), 256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUMX(&bn, "-42");
  if (ret != 3 || !BN_abs_is_word(bn.get(), 42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUMX(&bn, "-0");
  if (ret != 2 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUMX(&bn, "42trailing garbage is ignored");
  if (ret != 2 || !BN_abs_is_word(bn.get(), 42) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  return true;
}

static bool TestHex2BN(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> bn;
  int ret = HexToBIGNUMX(&bn, "0");
  if (ret != 1 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUMX(&bn, "256");
  if (ret != 3 || !BN_is_word(bn.get(), 0x256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUMX(&bn, "-42");
  if (ret != 3 || !BN_abs_is_word(bn.get(), 0x42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUMX(&bn, "-0");
  if (ret != 2 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUMX(&bn, "abctrailing garbage is ignored");
  if (ret != 3 || !BN_is_word(bn.get(), 0xabc) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  return true;
}

static bssl::UniquePtr<BIGNUMX> ASCIIToBIGNUMX(const char *in) {
  BIGNUMX *raw = NULL;
  if (!BN_asc2bn(&raw, in)) {
    return nullptr;
  }
  return bssl::UniquePtr<BIGNUMX>(raw);
}

static bool TestASC2BN(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> bn = ASCIIToBIGNUMX("0");
  if (!bn || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("256");
  if (!bn || !BN_is_word(bn.get(), 256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("-42");
  if (!bn || !BN_abs_is_word(bn.get(), 42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("0x1234");
  if (!bn || !BN_is_word(bn.get(), 0x1234) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("0X1234");
  if (!bn || !BN_is_word(bn.get(), 0x1234) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("-0xabcd");
  if (!bn || !BN_abs_is_word(bn.get(), 0xabcd) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("-0");
  if (!bn || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUMX("123trailing garbage is ignored");
  if (!bn || !BN_is_word(bn.get(), 123) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  return true;
}

struct MPITest {
  const char *base10;
  const char *mpi;
  size_t mpi_len;
};

static const MPITest kMPITests[] = {
  { "0", "\x00\x00\x00\x00", 4 },
  { "1", "\x00\x00\x00\x01\x01", 5 },
  { "-1", "\x00\x00\x00\x01\x81", 5 },
  { "128", "\x00\x00\x00\x02\x00\x80", 6 },
  { "256", "\x00\x00\x00\x02\x01\x00", 6 },
  { "-256", "\x00\x00\x00\x02\x81\x00", 6 },
};

static bool TestMPI() {
  uint8_t scratch[8];

  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kMPITests); i++) {
    const MPITest &test = kMPITests[i];
    bssl::UniquePtr<BIGNUMX> bn(ASCIIToBIGNUMX(test.base10));
    if (!bn) {
      return false;
    }

    const size_t mpi_len = BNY_bn2mpi(bn.get(), NULL);
    if (mpi_len > sizeof(scratch)) {
      fprintf(stderr, "MPI test #%u: MPI size is too large to test.\n",
              (unsigned)i);
      return false;
    }

    const size_t mpi_len2 = BNY_bn2mpi(bn.get(), scratch);
    if (mpi_len != mpi_len2) {
      fprintf(stderr, "MPI test #%u: length changes.\n", (unsigned)i);
      return false;
    }

    if (mpi_len != test.mpi_len ||
        OPENSSL_memcmp(test.mpi, scratch, mpi_len) != 0) {
      fprintf(stderr, "MPI test #%u failed:\n", (unsigned)i);
      hexdump(stderr, "Expected: ", test.mpi, test.mpi_len);
      hexdump(stderr, "Got:      ", scratch, mpi_len);
      return false;
    }

    bssl::UniquePtr<BIGNUMX> bn2(BNY_mpi2bn(scratch, mpi_len, NULL));
    if (bn2.get() == nullptr) {
      fprintf(stderr, "MPI test #%u: failed to parse\n", (unsigned)i);
      return false;
    }

    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "MPI test #%u: wrong result\n", (unsigned)i);
      return false;
    }
  }

  return true;
}

static bool TestRand() {
  bssl::UniquePtr<BIGNUMX> bn(BNY_new());
  if (!bn) {
    return false;
  }

  // Test BNY_rand accounts for degenerate cases with |top| and |bottom|
  // parameters.
  if (!BNY_rand(bn.get(), 0, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) ||
      !BN_is_zero(bn.get())) {
    fprintf(stderr, "BNY_rand gave a bad result.\n");
    return false;
  }
  if (!BNY_rand(bn.get(), 0, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD) ||
      !BN_is_zero(bn.get())) {
    fprintf(stderr, "BNY_rand gave a bad result.\n");
    return false;
  }

  if (!BNY_rand(bn.get(), 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BNY_rand gave a bad result.\n");
    return false;
  }
  if (!BNY_rand(bn.get(), 1, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BNY_rand gave a bad result.\n");
    return false;
  }
  if (!BNY_rand(bn.get(), 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BNY_rand gave a bad result.\n");
    return false;
  }

  if (!BNY_rand(bn.get(), 2, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY) ||
      !BN_is_word(bn.get(), 3)) {
    fprintf(stderr, "BNY_rand gave a bad result.\n");
    return false;
  }

  return true;
}

struct YASN1Test {
  const char *value_ascii;
  const char *der;
  size_t der_len;
};

static const YASN1Test kYASN1Tests[] = {
    {"0", "\x02\x01\x00", 3},
    {"1", "\x02\x01\x01", 3},
    {"127", "\x02\x01\x7f", 3},
    {"128", "\x02\x02\x00\x80", 4},
    {"0xdeadbeef", "\x02\x05\x00\xde\xad\xbe\xef", 7},
    {"0x0102030405060708",
     "\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08", 10},
    {"0xffffffffffffffff",
      "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff", 11},
};

struct YASN1InvalidTest {
  const char *der;
  size_t der_len;
};

static const YASN1InvalidTest kYASN1InvalidTests[] = {
    // Bad tag.
    {"\x03\x01\x00", 3},
    // Empty contents.
    {"\x02\x00", 2},
};

// kYASN1BuggyTests contains incorrect encodings and the corresponding, expected
// results of |BN_parse_asn1_unsigned_buggy| given that input.
static const YASN1Test kYASN1BuggyTests[] = {
    // Negative numbers.
    {"128", "\x02\x01\x80", 3},
    {"255", "\x02\x01\xff", 3},
    // Unnecessary leading zeros.
    {"1", "\x02\x02\x00\x01", 4},
};

static bool TestYASN1() {
  for (const YASN1Test &test : kYASN1Tests) {
    bssl::UniquePtr<BIGNUMX> bn = ASCIIToBIGNUMX(test.value_ascii);
    if (!bn) {
      return false;
    }

    // Test that the input is correctly parsed.
    bssl::UniquePtr<BIGNUMX> bn2(BNY_new());
    if (!bn2) {
      return false;
    }
    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (!BN_parse_asn1_unsigned(&cbs, bn2.get()) || CBS_len(&cbs) != 0) {
      fprintf(stderr, "Parsing ASN.1 INTEGER failed.\n");
      return false;
    }
    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "Bad parse.\n");
      return false;
    }

    // Test the value serializes correctly.
    bssl::ScopedCBB cbb;
    uint8_t *der;
    size_t der_len;
    if (!CBB_init(cbb.get(), 0) ||
        !BN_marshal_asn1(cbb.get(), bn.get()) ||
        !CBB_finish(cbb.get(), &der, &der_len)) {
      return false;
    }
    bssl::UniquePtr<uint8_t> delete_der(der);
    if (der_len != test.der_len ||
        OPENSSL_memcmp(der, reinterpret_cast<const uint8_t *>(test.der),
                       der_len) != 0) {
      fprintf(stderr, "Bad serialization.\n");
      return false;
    }

    // |BN_parse_asn1_unsigned_buggy| parses all valid input.
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (!BN_parse_asn1_unsigned_buggy(&cbs, bn2.get()) || CBS_len(&cbs) != 0) {
      fprintf(stderr, "Parsing ASN.1 INTEGER failed.\n");
      return false;
    }
    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "Bad parse.\n");
      return false;
    }
  }

  for (const YASN1InvalidTest &test : kYASN1InvalidTests) {
    bssl::UniquePtr<BIGNUMX> bn(BNY_new());
    if (!bn) {
      return false;
    }
    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (BN_parse_asn1_unsigned(&cbs, bn.get())) {
      fprintf(stderr, "Parsed invalid input.\n");
      return false;
    }
    ERR_clear_error();

    // All tests in kYASN1InvalidTests are also rejected by
    // |BN_parse_asn1_unsigned_buggy|.
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (BN_parse_asn1_unsigned_buggy(&cbs, bn.get())) {
      fprintf(stderr, "Parsed invalid input.\n");
      return false;
    }
    ERR_clear_error();
  }

  for (const YASN1Test &test : kYASN1BuggyTests) {
    // These broken encodings are rejected by |BN_parse_asn1_unsigned|.
    bssl::UniquePtr<BIGNUMX> bn(BNY_new());
    if (!bn) {
      return false;
    }

    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (BN_parse_asn1_unsigned(&cbs, bn.get())) {
      fprintf(stderr, "Parsed invalid input.\n");
      return false;
    }
    ERR_clear_error();

    // However |BN_parse_asn1_unsigned_buggy| accepts them.
    bssl::UniquePtr<BIGNUMX> bn2 = ASCIIToBIGNUMX(test.value_ascii);
    if (!bn2) {
      return false;
    }

    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (!BN_parse_asn1_unsigned_buggy(&cbs, bn.get()) || CBS_len(&cbs) != 0) {
      fprintf(stderr, "Parsing (invalid) ASN.1 INTEGER failed.\n");
      return false;
    }

    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "\"Bad\" parse.\n");
      return false;
    }
  }

  // Serializing negative numbers is not supported.
  bssl::UniquePtr<BIGNUMX> bn = ASCIIToBIGNUMX("-1");
  if (!bn) {
    return false;
  }
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      BN_marshal_asn1(cbb.get(), bn.get())) {
    fprintf(stderr, "Serialized negative number.\n");
    return false;
  }
  ERR_clear_error();

  return true;
}

static bool TestNegativeZero(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a(BNY_new());
  bssl::UniquePtr<BIGNUMX> b(BNY_new());
  bssl::UniquePtr<BIGNUMX> c(BNY_new());
  if (!a || !b || !c) {
    return false;
  }

  // Test that BNY_mul never gives negative zero.
  if (!BN_set_word(a.get(), 1)) {
    return false;
  }
  BN_set_negative(a.get(), 1);
  BN_zero(b.get());
  if (!BNY_mul(c.get(), a.get(), b.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(c.get()) || BN_is_negative(c.get())) {
    fprintf(stderr, "Multiplication test failed.\n");
    return false;
  }

  bssl::UniquePtr<BIGNUMX> numerator(BNY_new()), denominator(BNY_new());
  if (!numerator || !denominator) {
    return false;
  }

  // Test that BNY_div never gives negative zero in the quotient.
  if (!BN_set_word(numerator.get(), 1) ||
      !BN_set_word(denominator.get(), 2)) {
    return false;
  }
  BN_set_negative(numerator.get(), 1);
  if (!BNY_div(a.get(), b.get(), numerator.get(), denominator.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(a.get()) || BN_is_negative(a.get())) {
    fprintf(stderr, "Incorrect quotient.\n");
    return false;
  }

  // Test that BNY_div never gives negative zero in the remainder.
  if (!BN_set_word(denominator.get(), 1)) {
    return false;
  }
  if (!BNY_div(a.get(), b.get(), numerator.get(), denominator.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(b.get()) || BN_is_negative(b.get())) {
    fprintf(stderr, "Incorrect remainder.\n");
    return false;
  }

  // Test that BN_set_negative will not produce a negative zero.
  BN_zero(a.get());
  BN_set_negative(a.get(), 1);
  if (BN_is_negative(a.get())) {
    fprintf(stderr, "BN_set_negative produced a negative zero.\n");
    return false;
  }

  // Test that forcibly creating a negative zero does not break |BN_bn2hexx| or
  // |BN_bn2dec|.
  a->neg = 1;
  bssl::UniquePtr<char> dec(BN_bn2dec(a.get()));
  bssl::UniquePtr<char> hex(BN_bn2hexx(a.get()));
  if (!dec || !hex ||
      strcmp(dec.get(), "-0") != 0 ||
      strcmp(hex.get(), "-0") != 0) {
    fprintf(stderr, "BN_bn2dec or BN_bn2hexx failed with negative zero.\n");
    return false;
  }

  // Test that |BN_ryshift| and |BN_ryshift1| will not produce a negative zero.
  if (!BN_set_word(a.get(), 1)) {
    return false;
  }

  BN_set_negative(a.get(), 1);
  if (!BN_ryshift(b.get(), a.get(), 1) ||
      !BN_ryshift1(c.get(), a.get())) {
    return false;
  }

  if (!BN_is_zero(b.get()) || BN_is_negative(b.get())) {
    fprintf(stderr, "BN_ryshift(-1, 1) produced the wrong result.\n");
    return false;
  }

  if (!BN_is_zero(c.get()) || BN_is_negative(c.get())) {
    fprintf(stderr, "BN_ryshift1(-1) produced the wrong result.\n");
    return false;
  }

  // Test that |BNY_div_word| will not produce a negative zero.
  if (BNY_div_word(a.get(), 2) == (BN_ULONG)-1) {
    return false;
  }

  if (!BN_is_zero(a.get()) || BN_is_negative(a.get())) {
    fprintf(stderr, "BNY_div_word(-1, 2) produced the wrong result.\n");
    return false;
  }

  return true;
}

static bool TestBadModulus(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX> a(BNY_new());
  bssl::UniquePtr<BIGNUMX> b(BNY_new());
  bssl::UniquePtr<BIGNUMX> zero(BNY_new());
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  if (!a || !b || !zero || !mont) {
    return false;
  }

  BN_zero(zero.get());

  if (BNY_div(a.get(), b.get(), BNY_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "Division by zero unexpectedly succeeded.\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_mul(a.get(), BNY_value_one(), BNY_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "BN_mod_mul with zero modulus unexpectedly succeeded.\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_exp(a.get(), BNY_value_one(), BNY_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "BN_mod_exp with zero modulus unexpectedly succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BNY_mod_exp_mont(a.get(), BNY_value_one(), BNY_value_one(), zero.get(), ctx,
                      NULL)) {
    fprintf(stderr,
            "BNY_mod_exp_mont with zero modulus unexpectedly succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BNY_mod_exp_mont_consttime(a.get(), BNY_value_one(), BNY_value_one(),
                                zero.get(), ctx, nullptr)) {
    fprintf(stderr,
            "BNY_mod_exp_mont_consttime with zero modulus unexpectedly "
            "succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_MONT_CTX_set(mont.get(), zero.get(), ctx)) {
    fprintf(stderr,
            "BN_MONT_CTX_set unexpectedly succeeded for zero modulus.\n");
    return false;
  }
  ERR_clear_error();

  // Some operations also may not be used with an even modulus.

  if (!BN_set_word(b.get(), 16)) {
    return false;
  }

  if (BN_MONT_CTX_set(mont.get(), b.get(), ctx)) {
    fprintf(stderr,
            "BN_MONT_CTX_set unexpectedly succeeded for even modulus.\n");
    return false;
  }
  ERR_clear_error();

  if (BNY_mod_exp_mont(a.get(), BNY_value_one(), BNY_value_one(), b.get(), ctx,
                      NULL)) {
    fprintf(stderr,
            "BNY_mod_exp_mont with even modulus unexpectedly succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BNY_mod_exp_mont_consttime(a.get(), BNY_value_one(), BNY_value_one(),
                                b.get(), ctx, nullptr)) {
    fprintf(stderr,
            "BNY_mod_exp_mont_consttime with even modulus unexpectedly "
            "succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  return true;
}

// TestExpModZero tests that 1**0 mod 1 == 0.
static bool TestExpModZero() {
  bssl::UniquePtr<BIGNUMX> zero(BNY_new()), a(BNY_new()), r(BNY_new());
  if (!zero || !a || !r ||
      !BNY_rand(a.get(), 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
    return false;
  }
  BN_zero(zero.get());

  if (!BN_mod_exp(r.get(), a.get(), zero.get(), BNY_value_one(), nullptr) ||
      !BN_is_zero(r.get()) ||
      !BNY_mod_exp_mont(r.get(), a.get(), zero.get(), BNY_value_one(), nullptr,
                       nullptr) ||
      !BN_is_zero(r.get()) ||
      !BNY_mod_exp_mont_consttime(r.get(), a.get(), zero.get(), BNY_value_one(),
                                 nullptr, nullptr) ||
      !BN_is_zero(r.get()) ||
      !BNY_mod_exp_mont_word(r.get(), 42, zero.get(), BNY_value_one(), nullptr,
                            nullptr) ||
      !BN_is_zero(r.get())) {
    return false;
  }

  return true;
}

static bool TestSmallPrime(BN_CTX *ctx) {
  static const unsigned kBits = 10;

  bssl::UniquePtr<BIGNUMX> r(BNY_new());
  if (!r || !BNY_generate_prime_ex(r.get(), static_cast<int>(kBits), 0, NULL,
                                  NULL, NULL)) {
    return false;
  }
  if (BNY_num_bits(r.get()) != kBits) {
    fprintf(stderr, "Expected %u bit prime, got %u bit number\n", kBits,
            BNY_num_bits(r.get()));
    return false;
  }

  return true;
}

static bool TestCmpWord() {
  static const BN_ULONG kMaxWord = (BN_ULONG)-1;

  bssl::UniquePtr<BIGNUMX> r(BNY_new());
  if (!r ||
      !BN_set_word(r.get(), 0)) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) != 0 ||
      BN_cmp_word(r.get(), 1) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr, "BN_cmp_word compared against 0 incorrectly.\n");
    return false;
  }

  if (!BN_set_word(r.get(), 100)) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) <= 0 ||
      BN_cmp_word(r.get(), 99) <= 0 ||
      BN_cmp_word(r.get(), 100) != 0 ||
      BN_cmp_word(r.get(), 101) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr, "BN_cmp_word compared against 100 incorrectly.\n");
    return false;
  }

  BN_set_negative(r.get(), 1);

  if (BN_cmp_word(r.get(), 0) >= 0 ||
      BN_cmp_word(r.get(), 100) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr, "BN_cmp_word compared against -100 incorrectly.\n");
    return false;
  }

  if (!BN_set_word(r.get(), kMaxWord)) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) <= 0 ||
      BN_cmp_word(r.get(), kMaxWord - 1) <= 0 ||
      BN_cmp_word(r.get(), kMaxWord) != 0) {
    fprintf(stderr, "BN_cmp_word compared against kMaxWord incorrectly.\n");
    return false;
  }

  if (!BNY_add(r.get(), r.get(), BNY_value_one())) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) <= 0 ||
      BN_cmp_word(r.get(), kMaxWord) <= 0) {
    fprintf(stderr, "BN_cmp_word compared against kMaxWord + 1 incorrectly.\n");
    return false;
  }

  BN_set_negative(r.get(), 1);

  if (BN_cmp_word(r.get(), 0) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr,
            "BN_cmp_word compared against -kMaxWord - 1 incorrectly.\n");
    return false;
  }

  return true;
}

static bool TestBN2Dec() {
  static const char *kBN2DecTests[] = {
      "0",
      "1",
      "-1",
      "100",
      "-100",
      "123456789012345678901234567890",
      "-123456789012345678901234567890",
      "123456789012345678901234567890123456789012345678901234567890",
      "-123456789012345678901234567890123456789012345678901234567890",
  };

  for (const char *test : kBN2DecTests) {
    bssl::UniquePtr<BIGNUMX> bn;
    int ret = DecimalToBIGNUMX(&bn, test);
    if (ret == 0) {
      return false;
    }

    bssl::UniquePtr<char> dec(BN_bn2dec(bn.get()));
    if (!dec) {
      fprintf(stderr, "BN_bn2dec failed on %s.\n", test);
      return false;
    }

    if (strcmp(dec.get(), test) != 0) {
      fprintf(stderr, "BN_bn2dec gave %s, wanted %s.\n", dec.get(), test);
      return false;
    }
  }

  return true;
}

static bool TestBNSetGetU64() {
  static const struct {
    const char *hex;
    uint64_t value;
  } kU64Tests[] = {
      {"0", UINT64_C(0x0)},
      {"1", UINT64_C(0x1)},
      {"ffffffff", UINT64_C(0xffffffff)},
      {"100000000", UINT64_C(0x100000000)},
      {"ffffffffffffffff", UINT64_C(0xffffffffffffffff)},
  };

  for (const auto& test : kU64Tests) {
    bssl::UniquePtr<BIGNUMX> bn(BNY_new()), expected;
    if (!bn ||
        !BN_set_u64(bn.get(), test.value) ||
        !HexToBIGNUMX(&expected, test.hex) ||
        BN_cmp(bn.get(), expected.get()) != 0) {
      fprintf(stderr, "BN_set_u64 test failed for 0x%s.\n", test.hex);
      ERRR_print_errors_fp(stderr);
      return false;
    }

    uint64_t tmp;
    if (!BN_get_u64(bn.get(), &tmp) || tmp != test.value) {
      fprintf(stderr, "BN_get_u64 test failed for 0x%s.\n", test.hex);
      return false;
    }

    BN_set_negative(bn.get(), 1);
    if (!BN_get_u64(bn.get(), &tmp) || tmp != test.value) {
      fprintf(stderr, "BN_get_u64 test failed for -0x%s.\n", test.hex);
      return false;
    }
  }

  // Test that BN_get_u64 fails on large numbers.
  bssl::UniquePtr<BIGNUMX> bn(BNY_new());
  if (!BN_lshift(bn.get(), BNY_value_one(), 64)) {
    return false;
  }

  uint64_t tmp;
  if (BN_get_u64(bn.get(), &tmp)) {
    fprintf(stderr, "BN_get_u64 of 2^64 unexpectedly succeeded.\n");
    return false;
  }

  BN_set_negative(bn.get(), 1);
  if (BN_get_u64(bn.get(), &tmp)) {
    fprintf(stderr, "BN_get_u64 of -2^64 unexpectedly succeeded.\n");
    return false;
  }

  return true;
}

static bool TestBNPow2(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUMX>
      power_of_two(BNY_new()),
      random(BNY_new()),
      expected(BNY_new()),
      actual(BNY_new());

  if (!power_of_two.get() ||
      !random.get() ||
      !expected.get() ||
      !actual.get()) {
    return false;
  }

  // Choose an exponent.
  for (size_t e = 3; e < 512; e += 11) {
    // Choose a bit length for our randoms.
    for (int len = 3; len < 512; len += 23) {
      // Set power_of_two = 2^e.
      if (!BN_lshift(power_of_two.get(), BNY_value_one(), (int) e)) {
        fprintf(stderr, "Failed to shiftl.\n");
        return false;
      }

      // Test BN_is_pow2 on power_of_two.
      if (!BN_is_pow2(power_of_two.get())) {
        fprintf(stderr, "BN_is_pow2 returned false for a power of two.\n");
        hexdump(stderr, "Arg: ", power_of_two->d,
                power_of_two->top * sizeof(BN_ULONG));
        return false;
      }

      // Pick a large random value, ensuring it isn't a power of two.
      if (!BNY_rand(random.get(), len, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY)) {
        fprintf(stderr, "Failed to generate random in TestBNPow2.\n");
        return false;
      }

      // Test BN_is_pow2 on |r|.
      if (BN_is_pow2(random.get())) {
        fprintf(stderr, "BN_is_pow2 returned true for a non-power of two.\n");
        hexdump(stderr, "Arg: ", random->d, random->top * sizeof(BN_ULONG));
        return false;
      }

      // Test BN_mod_pow2 on |r|.
      if (!BN_mod(expected.get(), random.get(), power_of_two.get(), ctx) ||
          !BN_mod_pow2(actual.get(), random.get(), e) ||
          BN_cmp(actual.get(), expected.get())) {
        fprintf(stderr, "BN_mod_pow2 returned the wrong value:\n");
        hexdump(stderr, "Expected: ", expected->d,
                expected->top * sizeof(BN_ULONG));
        hexdump(stderr, "Got:      ", actual->d,
                actual->top * sizeof(BN_ULONG));
        return false;
      }

      // Test BNY_nnmod_pow2 on |r|.
      if (!BNY_nnmod(expected.get(), random.get(), power_of_two.get(), ctx) ||
          !BNY_nnmod_pow2(actual.get(), random.get(), e) ||
          BN_cmp(actual.get(), expected.get())) {
        fprintf(stderr, "BNY_nnmod_pow2 failed on positive input:\n");
        hexdump(stderr, "Expected: ", expected->d,
                expected->top * sizeof(BN_ULONG));
        hexdump(stderr, "Got:      ", actual->d,
                actual->top * sizeof(BN_ULONG));
        return false;
      }

      // Test BNY_nnmod_pow2 on -|r|.
      BN_set_negative(random.get(), 1);
      if (!BNY_nnmod(expected.get(), random.get(), power_of_two.get(), ctx) ||
          !BNY_nnmod_pow2(actual.get(), random.get(), e) ||
          BN_cmp(actual.get(), expected.get())) {
        fprintf(stderr, "BNY_nnmod_pow2 failed on negative input:\n");
        hexdump(stderr, "Expected: ", expected->d,
                expected->top * sizeof(BN_ULONG));
        hexdump(stderr, "Got:      ", actual->d,
                actual->top * sizeof(BN_ULONG));
        return false;
      }
    }
  }

  return true;
}

int main(int argc, char *argv[]) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s TEST_FILE\n", argv[0]);
    return 1;
  }

  bssl::UniquePtr<BN_CTX> ctx(BNY_CTX_new());
  if (!ctx) {
    return 1;
  }

  if (!TestBN2BinPadded(ctx.get()) ||
      !TestDec2BN(ctx.get()) ||
      !TestHex2BN(ctx.get()) ||
      !TestASC2BN(ctx.get()) ||
      !TestLittleEndian() ||
      !TestMPI() ||
      !TestRand() ||
      !TestYASN1() ||
      !TestNegativeZero(ctx.get()) ||
      !TestBadModulus(ctx.get()) ||
      !TestExpModZero() ||
      !TestSmallPrime(ctx.get()) ||
      !TestCmpWord() ||
      !TestBN2Dec() ||
      !TestBNSetGetU64() ||
      !TestBNPow2(ctx.get())) {
    return 1;
  }

  return FileTestMain(RunTest, ctx.get(), argv[1]);
}