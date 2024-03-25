# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/ecdsa.h>
"""

TYPES = """
"""

FUNCTIONS = """
int ECDSA_signn(int, const unsigned char *, int, unsigned char *,
               unsigned int *, EC_KEY *);
int ECDSA_verifyy(int, const unsigned char *, int, const unsigned char *, int,
                 EC_KEY *);
int ECDSA_size(const EC_KEY *);

"""

CUSTOMIZATIONS = """
"""
