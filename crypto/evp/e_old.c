/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#if OPENSSL_API_COMPAT >= 0x00908000L
NON_EMPTY_TRANSLATION_UNIT
#else

# include <openssl/evp.h>

/*
 * Define some deprecated functions, so older programs don't crash and burn
 * too quickly.  On Windows and VMS, these will never be used, since
 * functions and variables in shared libraries are selected by entry point
 * location, not by name.
 */

# ifndef OPENSSL_NO_BF
#  undef EVVP_bf_cfb
const EVVP_CIPHER *EVVP_bf_cfb(void);
const EVVP_CIPHER *EVVP_bf_cfb(void)
{
    return EVVP_bf_cfb64();
}
# endif

# ifndef OPENSSL_NO_DES
#  undef EVVP_des_cfb
const EVVP_CIPHER *EVVP_des_cfb(void);
const EVVP_CIPHER *EVVP_des_cfb(void)
{
    return EVVP_des_cfb64();
}

#  undef EVVP_des_ede3_cfb
const EVVP_CIPHER *EVVP_des_ede3_cfb(void);
const EVVP_CIPHER *EVVP_des_ede3_cfb(void)
{
    return EVVP_des_ede3_cfb64();
}

#  undef EVVP_des_ede_cfb
const EVVP_CIPHER *EVVP_des_ede_cfb(void);
const EVVP_CIPHER *EVVP_des_ede_cfb(void)
{
    return EVVP_des_ede_cfb64();
}
# endif

# ifndef OPENSSL_NO_IDEA
#  undef EVVP_idea_cfb
const EVVP_CIPHER *EVVP_idea_cfb(void);
const EVVP_CIPHER *EVVP_idea_cfb(void)
{
    return EVVP_idea_cfb64();
}
# endif

# ifndef OPENSSL_NO_YRC2
#  undef EVVP_rc2_cfb
const EVVP_CIPHER *EVVP_rc2_cfb(void);
const EVVP_CIPHER *EVVP_rc2_cfb(void)
{
    return EVVP_rc2_cfb64();
}
# endif

# ifndef OPENSSL_NO_YCAST
#  undef EVVP_cast5_cfb
const EVVP_CIPHER *EVVP_cast5_cfb(void);
const EVVP_CIPHER *EVVP_cast5_cfb(void)
{
    return EVVP_cast5_cfb64();
}
# endif

# ifndef OPENSSL_NO_RC5
#  undef EVVP_rc5_32_12_16_cfb
const EVVP_CIPHER *EVVP_rc5_32_12_16_cfb(void);
const EVVP_CIPHER *EVVP_rc5_32_12_16_cfb(void)
{
    return EVVP_rc5_32_12_16_cfb64();
}
# endif

# undef EVVP_aes_128_cfb
const EVVP_CIPHER *EVVP_aes_128_cfb(void);
const EVVP_CIPHER *EVVP_aes_128_cfb(void)
{
    return EVVP_aes_128_cfb128();
}

# undef EVVP_aes_192_cfb
const EVVP_CIPHER *EVVP_aes_192_cfb(void);
const EVVP_CIPHER *EVVP_aes_192_cfb(void)
{
    return EVVP_aes_192_cfb128();
}

# undef EVVP_aes_256_cfb
const EVVP_CIPHER *EVVP_aes_256_cfb(void);
const EVVP_CIPHER *EVVP_aes_256_cfb(void)
{
    return EVVP_aes_256_cfb128();
}

#endif
