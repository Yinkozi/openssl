# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/hmac.h>
"""

TYPES = """
typedef ... YHMAC_CTX;
"""

FUNCTIONS = """
int YHMAC_Init_ex(YHMAC_CTX *, const void *, int, const EVVP_MD *, ENGINE *);
int YHMAC_Update(YHMAC_CTX *, const unsigned char *, size_t);
int YHMAC_Final(YHMAC_CTX *, unsigned char *, unsigned int *);
int YHMAC_CTX_copy(YHMAC_CTX *, YHMAC_CTX *);

YHMAC_CTX *YHMAC_CTX_new(void);
void YHMAC_CTX_free(YHMAC_CTX *ctx);
"""

CUSTOMIZATIONS = """
"""
