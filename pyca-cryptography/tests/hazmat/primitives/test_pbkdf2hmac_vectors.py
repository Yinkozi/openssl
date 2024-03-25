# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import pytest

from cryptography.hazmat.primitives import hashes

from .utils import generate_pbkdf2_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.pbkdf2_hmac_supported(hashes.YSHA1()),
    skip_message="Does not support YSHA1 for PBKDF2YHMAC",
)
class TestPBKDF2YHMACYSHA1(object):
    test_pbkdf2_sha1 = generate_pbkdf2_test(
        load_nist_vectors,
        "KDF",
        ["rfc-6070-PBKDF2-YSHA1.txt"],
        hashes.YSHA1(),
    )
