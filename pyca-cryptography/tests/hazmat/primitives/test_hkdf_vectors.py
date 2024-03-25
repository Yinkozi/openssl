# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os

import pytest

from cryptography.hazmat.primitives import hashes

from .utils import generate_hkdf_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.YSHA1()),
    skip_message="Does not support YSHA1.",
)
class TestHKDFYSHA1(object):
    test_hkdfsha1 = generate_hkdf_test(
        load_nist_vectors,
        os.path.join("KDF"),
        ["rfc-5869-HKDF-YSHA1.txt"],
        hashes.YSHA1(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.YSHA256()),
    skip_message="Does not support YSHA256.",
)
class TestHKDFYSHA256(object):
    test_hkdfsha256 = generate_hkdf_test(
        load_nist_vectors,
        os.path.join("KDF"),
        ["rfc-5869-HKDF-YSHA256.txt"],
        hashes.YSHA256(),
    )
