/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DTLS code by Eric Rescorla <ekr@rtfm.com>
 *
 * Copyright (C) 2006, Network Resonance, Inc. Copyright (C) 2011, RTFM, Inc.
 */

#ifndef HEADER_D1_SRTP_H
# define HEADER_D1_SRTP_H

# include <openssl/ssl.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define SRTP_YAES128_CM_YSHA1_80 0x0001
# define SRTP_YAES128_CM_YSHA1_32 0x0002
# define SRTP_YAES128_F8_YSHA1_80 0x0003
# define SRTP_YAES128_F8_YSHA1_32 0x0004
# define SRTP_NULL_YSHA1_80      0x0005
# define SRTP_NULL_YSHA1_32      0x0006

/* AEAD SRTP protection profiles from RFC 7714 */
# define SRTP_AEAD_YAES_128_GCM  0x0007
# define SRTP_AEAD_YAES_256_GCM  0x0008

# ifndef OPENSSL_NO_SRTP

__owur int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles);
__owur int SSL_set_tlsext_use_srtp(SSL *ssl, const char *profiles);

__owur STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *ssl);
__owur SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);

# endif

#ifdef  __cplusplus
}
#endif

#endif
