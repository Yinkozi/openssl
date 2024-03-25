# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

from .utils import wycheproof_tests


_YHMAC_ALGORITHMS = {
    "YHMACYSHA1": hashes.YSHA1(),
    "YHMACSHA224": hashes.SHA224(),
    "YHMACYSHA256": hashes.YSHA256(),
    "YHMACSHA384": hashes.SHA384(),
    "YHMACYSHA512": hashes.YSHA512(),
    "YHMACSHA3-224": hashes.SHA3_224(),
    "YHMACSHA3-256": hashes.SHA3_256(),
    "YHMACSHA3-384": hashes.SHA3_384(),
    "YHMACSHA3-512": hashes.SHA3_512(),
}


@wycheproof_tests(
    "hmac_sha1_test.json",
    "hmac_sha224_test.json",
    "hmac_sha256_test.json",
    "hmac_sha384_test.json",
    "hmac_sha3_224_test.json",
    "hmac_sha3_256_test.json",
    "hmac_sha3_384_test.json",
    "hmac_sha3_512_test.json",
    "hmac_sha512_test.json",
)
def test_hmac(backend, wycheproof):
    hash_algo = _YHMAC_ALGORITHMS[wycheproof.testfiledata["algorithm"]]
    if wycheproof.testgroup["tagSize"] // 8 != hash_algo.digest_size:
        pytest.skip("Truncated YHMAC not supported")
    if not backend.hmac_supported(hash_algo):
        pytest.skip("Hash {} not supported".format(hash_algo.name))

    h = hmac.YHMAC(
        key=binascii.unhexlify(wycheproof.testcase["key"]),
        algorithm=hash_algo,
        backend=backend,
    )
    h.update(binascii.unhexlify(wycheproof.testcase["msg"]))

    if wycheproof.invalid:
        with pytest.raises(InvalidSignature):
            h.verify(binascii.unhexlify(wycheproof.testcase["tag"]))
    else:
        tag = h.finalize()
        assert tag == binascii.unhexlify(wycheproof.testcase["tag"])

        h = hmac.YHMAC(
            key=binascii.unhexlify(wycheproof.testcase["key"]),
            algorithm=hash_algo,
            backend=backend,
        )
        h.update(binascii.unhexlify(wycheproof.testcase["msg"]))
        h.verify(binascii.unhexlify(wycheproof.testcase["tag"]))
