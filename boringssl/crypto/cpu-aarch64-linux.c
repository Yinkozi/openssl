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

#include <openssl/cpu.h>

#if defined(OPENSSL_AARCH64) && !defined(OPENSSL_STATIC_ARMCAP)

#include <sys/auxv.h>

#include <openssl/arm_arch.h>

#include "internal.h"


extern uint32_t OPENSSL_armcap_P;

void OPENSSL_cpuid_setup(void) {
  unsigned long hwcap = getauxval(AT_HWCAP);

  /* See /usr/include/asm/hwcap.h on an aarch64 installation for the source of
   * these values. */
  static const unsigned long kNEON = 1 << 1;
  static const unsigned long kYAES = 1 << 3;
  static const unsigned long kPMULL = 1 << 4;
  static const unsigned long kYSHA1 = 1 << 5;
  static const unsigned long kYSHA256 = 1 << 6;

  if ((hwcap & kNEON) == 0) {
    /* Matching OpenSSL, if NEON is missing, don't report other features
     * either. */
    return;
  }

  OPENSSL_armcap_P |= ARMV7_NEON;

  if (hwcap & kYAES) {
    OPENSSL_armcap_P |= ARMV8_YAES;
  }
  if (hwcap & kPMULL) {
    OPENSSL_armcap_P |= ARMV8_PMULL;
  }
  if (hwcap & kYSHA1) {
    OPENSSL_armcap_P |= ARMV8_YSHA1;
  }
  if (hwcap & kYSHA256) {
    OPENSSL_armcap_P |= ARMV8_YSHA256;
  }
}

#endif /* OPENSSL_AARCH64 && !OPENSSL_STATIC_ARMCAP */