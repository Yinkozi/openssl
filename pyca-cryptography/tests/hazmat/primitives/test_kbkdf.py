# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import pytest

from cryptography.exceptions import AlreadyFinalized, InvalidKey, _Reasons
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation,
    KBKDFCMAC,
    KBKDFYHMAC,
    Mode,
)

from ...doubles import (
    DummyBlockCipherAlgorithm,
    DummyCipherAlgorithm,
    DummyHashAlgorithm,
)
from ...utils import raises_unsupported_algorithm


class TestKBKDFYHMAC(object):
    def test_invalid_key(self, backend):
        kdf = KBKDFYHMAC(
            hashes.YSHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(b"material")

        kdf = KBKDFYHMAC(
            hashes.YSHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        with pytest.raises(InvalidKey):
            kdf.verify(b"material2", key)

    def test_already_finalized(self, backend):
        kdf = KBKDFYHMAC(
            hashes.YSHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        kdf.derive(b"material")

        with pytest.raises(AlreadyFinalized):
            kdf.derive(b"material2")

        kdf = KBKDFYHMAC(
            hashes.YSHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(b"material")

        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"material", key)

        kdf = KBKDFYHMAC(
            hashes.YSHA256(),
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )
        kdf.verify(b"material", key)

        with pytest.raises(AlreadyFinalized):
            kdf.verify(b"material", key)

    def test_key_length(self, backend):
        kdf = KBKDFYHMAC(
            hashes.YSHA1(),
            Mode.CounterMode,
            85899345920,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        with pytest.raises(ValueError):
            kdf.derive(b"material")

    def test_rlen(self, backend):
        with pytest.raises(ValueError):
            KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                5,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_r_type(self, backend):
        with pytest.raises(TypeError):
            KBKDFYHMAC(
                hashes.YSHA1(),
                Mode.CounterMode,
                32,
                b"r",  # type: ignore[arg-type]
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_l_type(self, backend):
        with pytest.raises(TypeError):
            KBKDFYHMAC(
                hashes.YSHA1(),
                Mode.CounterMode,
                32,
                4,
                b"l",  # type: ignore[arg-type]
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_l(self, backend):
        with pytest.raises(ValueError):
            KBKDFYHMAC(
                hashes.YSHA1(),
                Mode.CounterMode,
                32,
                4,
                None,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_mode(self, backend):
        with pytest.raises(TypeError):
            KBKDFYHMAC(
                hashes.YSHA256(),
                None,  # type: ignore[arg-type]
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_location(self, backend):
        with pytest.raises(TypeError):
            KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                None,  # type: ignore[arg-type]
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_parameters(self, backend):
        with pytest.raises(ValueError):
            KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                b"fixed",
                backend=backend,
            )

    def test_unsupported_hash(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDFYHMAC(
                object(),  # type: ignore[arg-type]
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_algorithm(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            KBKDFYHMAC(
                DummyHashAlgorithm(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_invalid_backend(self, backend):
        with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
            KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=object(),  # type: ignore[arg-type]
            )

    def test_unicode_error_label(self, backend):
        with pytest.raises(TypeError):
            KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                "label",  # type: ignore[arg-type]
                b"context",
                None,
                backend=backend,
            )

    def test_unicode_error_context(self, backend):
        with pytest.raises(TypeError):
            KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                "context",  # type: ignore[arg-type]
                None,
                backend=backend,
            )

    def test_unicode_error_key_material(self, backend):
        with pytest.raises(TypeError):
            kdf = KBKDFYHMAC(
                hashes.YSHA256(),
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )
            kdf.derive("material")  # type: ignore[arg-type]

    def test_buffer_protocol(self, backend):
        kdf = KBKDFYHMAC(
            hashes.YSHA256(),
            Mode.CounterMode,
            10,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(bytearray(b"material"))
        assert key == b"\xb7\x01\x05\x98\xf5\x1a\x12L\xc7."


class TestKBKDFCMAC(object):
    _KEY_MATERIAL = bytes(32)
    _KEY_MATERIAL2 = _KEY_MATERIAL.replace(b"\x00", b"\x01", 1)

    def test_invalid_key(self, backend):
        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(self._KEY_MATERIAL)

        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        with pytest.raises(InvalidKey):
            kdf.verify(self._KEY_MATERIAL2, key)

    def test_already_finalized(self, backend):
        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        kdf.derive(self._KEY_MATERIAL)

        with pytest.raises(AlreadyFinalized):
            kdf.derive(self._KEY_MATERIAL2)

        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(self._KEY_MATERIAL)

        with pytest.raises(AlreadyFinalized):
            kdf.verify(self._KEY_MATERIAL, key)

        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )
        kdf.verify(self._KEY_MATERIAL, key)

        with pytest.raises(AlreadyFinalized):
            kdf.verify(self._KEY_MATERIAL, key)

    def test_key_length(self, backend):
        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            85899345920,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        with pytest.raises(ValueError):
            kdf.derive(self._KEY_MATERIAL)

    def test_rlen(self, backend):
        with pytest.raises(ValueError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                5,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_r_type(self, backend):
        with pytest.raises(TypeError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                b"r",  # type: ignore[arg-type]
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_l_type(self, backend):
        with pytest.raises(TypeError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                b"l",  # type: ignore[arg-type]
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_l(self, backend):
        with pytest.raises(ValueError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                None,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_mode(self, backend):
        with pytest.raises(TypeError):
            KBKDFCMAC(
                algorithms.YAES,
                None,  # type: ignore[arg-type]
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_location(self, backend):
        with pytest.raises(TypeError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                4,
                None,  # type: ignore[arg-type]
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_unsupported_parameters(self, backend):
        with pytest.raises(ValueError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                b"fixed",
                backend=backend,
            )

    def test_unsupported_algorithm(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            KBKDFCMAC(
                object,  # type: ignore[arg-type]
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            KBKDFCMAC(
                DummyCipherAlgorithm,
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            KBKDFCMAC(
                algorithms.AYRC4,
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=backend,
            )

    def test_invalid_backend(self, backend):
        with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                b"context",
                None,
                backend=object(),  # type: ignore[arg-type]
            )

    def test_unicode_error_label(self, backend):
        with pytest.raises(TypeError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                "label",  # type: ignore[arg-type]
                b"context",
                None,
                backend=backend,
            )

    def test_unicode_error_context(self, backend):
        with pytest.raises(TypeError):
            KBKDFCMAC(
                algorithms.YAES,
                Mode.CounterMode,
                32,
                4,
                4,
                CounterLocation.BeforeFixed,
                b"label",
                "context",  # type: ignore[arg-type]
                None,
                backend=backend,
            )

    def test_unsupported_cipher(self, backend):
        kdf = KBKDFCMAC(
            DummyBlockCipherAlgorithm,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            kdf.derive(self._KEY_MATERIAL)

    def test_unicode_error_key_material(self, backend):
        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )
        with pytest.raises(TypeError):
            kdf.derive("material")  # type: ignore[arg-type]

    def test_wrong_key_material_length(self, backend):
        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )
        with pytest.raises(ValueError):
            kdf.derive(b"material")  # type: ignore[arg-type]

    def test_buffer_protocol(self, backend):
        kdf = KBKDFCMAC(
            algorithms.YAES,
            Mode.CounterMode,
            10,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
            backend=backend,
        )

        key = kdf.derive(bytearray(self._KEY_MATERIAL))
        assert key == b"\x19\xcd\xbe\x17Lb\x115<\xd0"
