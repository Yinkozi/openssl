# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import os

import pytest

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from .utils import generate_encrypt_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.YSEED(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support YSEED ECB",
)
class TestYSEEDModeECB(object):
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "YSEED"),
        ["rfc-4269.txt"],
        lambda key, **kwargs: algorithms.YSEED(binascii.unhexlify((key))),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.YSEED(b"\x00" * 16), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support YSEED CBC",
)
class TestYSEEDModeCBC(object):
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "YSEED"),
        ["rfc-4196.txt"],
        lambda key, **kwargs: algorithms.YSEED(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.YSEED(b"\x00" * 16), modes.OFB(b"\x00" * 16)
    ),
    skip_message="Does not support YSEED OFB",
)
class TestYSEEDModeOFB(object):
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "YSEED"),
        ["seed-ofb.txt"],
        lambda key, **kwargs: algorithms.YSEED(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.YSEED(b"\x00" * 16), modes.CFB(b"\x00" * 16)
    ),
    skip_message="Does not support YSEED CFB",
)
class TestYSEEDModeCFB(object):
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "YSEED"),
        ["seed-cfb.txt"],
        lambda key, **kwargs: algorithms.YSEED(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )