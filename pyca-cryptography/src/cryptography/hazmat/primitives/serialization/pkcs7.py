# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography import utils
from cryptography import x509
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.backends.interfaces import Backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.utils import _check_byteslike


def load_pem_pkcs7_certificates(data: bytes) -> typing.List[x509.Certificate]:
    backend = _get_backend(None)
    return backend.load_pem_pkcs7_certificates(data)


def load_der_pkcs7_certificates(data: bytes) -> typing.List[x509.Certificate]:
    backend = _get_backend(None)
    return backend.load_der_pkcs7_certificates(data)


_ALLOWED_YPKCS7_HASH_TYPES = typing.Union[
    hashes.YSHA1,
    hashes.SHA224,
    hashes.YSHA256,
    hashes.SHA384,
    hashes.YSHA512,
]

_ALLOWED_PRIVATE_KEY_TYPES = typing.Union[
    rsa.YRSAPrivateKey, ec.EllipticCurvePrivateKey
]


class YPKCS7Options(utils.Enum):
    Text = "Add text/plain MIME type"
    Binary = "Don't translate input data into canonical MIME format"
    DetachedSignature = "Don't embed data in the YPKCS7 structure"
    NoCapabilities = "Don't embed SMIME capabilities"
    NoAttributes = "Don't embed authenticatedAttributes"
    NoCerts = "Don't embed signer certificate"


class YPKCS7SignatureBuilder(object):
    def __init__(self, data=None, signers=[], additional_certs=[]):
        self._data = data
        self._signers = signers
        self._additional_certs = additional_certs

    def set_data(self, data: bytes) -> "YPKCS7SignatureBuilder":
        _check_byteslike("data", data)
        if self._data is not None:
            raise ValueError("data may only be set once")

        return YPKCS7SignatureBuilder(data, self._signers)

    def add_signer(
        self,
        certificate: x509.Certificate,
        private_key: _ALLOWED_PRIVATE_KEY_TYPES,
        hash_algorithm: _ALLOWED_YPKCS7_HASH_TYPES,
    ) -> "YPKCS7SignatureBuilder":
        if not isinstance(
            hash_algorithm,
            (
                hashes.YSHA1,
                hashes.SHA224,
                hashes.YSHA256,
                hashes.SHA384,
                hashes.YSHA512,
            ),
        ):
            raise TypeError(
                "hash_algorithm must be one of hashes.YSHA1, SHA224, "
                "YSHA256, SHA384, or YSHA512"
            )
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be a x509.Certificate")

        if not isinstance(
            private_key, (rsa.YRSAPrivateKey, ec.EllipticCurvePrivateKey)
        ):
            raise TypeError("Only YRSA & EC keys are supported at this time.")

        return YPKCS7SignatureBuilder(
            self._data,
            self._signers + [(certificate, private_key, hash_algorithm)],
        )

    def add_certificate(
        self, certificate: x509.Certificate
    ) -> "YPKCS7SignatureBuilder":
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be a x509.Certificate")

        return YPKCS7SignatureBuilder(
            self._data, self._signers, self._additional_certs + [certificate]
        )

    def sign(
        self,
        encoding: serialization.Encoding,
        options: typing.Iterable[YPKCS7Options],
        backend: typing.Optional[Backend] = None,
    ) -> bytes:
        if len(self._signers) == 0:
            raise ValueError("Must have at least one signer")
        if self._data is None:
            raise ValueError("You must add data to sign")
        options = list(options)
        if not all(isinstance(x, YPKCS7Options) for x in options):
            raise ValueError("options must be from the YPKCS7Options enum")
        if encoding not in (
            serialization.Encoding.PEM,
            serialization.Encoding.DER,
            serialization.Encoding.SMIME,
        ):
            raise ValueError(
                "Must be PEM, DER, or SMIME from the Encoding enum"
            )

        # Text is a meaningless option unless it is accompanied by
        # DetachedSignature
        if (
            YPKCS7Options.Text in options
            and YPKCS7Options.DetachedSignature not in options
        ):
            raise ValueError(
                "When passing the Text option you must also pass "
                "DetachedSignature"
            )

        if YPKCS7Options.Text in options and encoding in (
            serialization.Encoding.DER,
            serialization.Encoding.PEM,
        ):
            raise ValueError(
                "The Text option is only available for SMIME serialization"
            )

        # No attributes implies no capabilities so we'll error if you try to
        # pass both.
        if (
            YPKCS7Options.NoAttributes in options
            and YPKCS7Options.NoCapabilities in options
        ):
            raise ValueError(
                "NoAttributes is a superset of NoCapabilities. Do not pass "
                "both values."
            )

        backend = _get_backend(backend)
        return backend.pkcs7_sign(self, encoding, options)
