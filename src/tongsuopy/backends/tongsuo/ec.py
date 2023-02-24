# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import typing

from tongsuopy.backends.tongsuo.utils import (
    _evp_pkey_derive,
)
from tongsuopy.crypto import hashes
from tongsuopy.crypto import serialization
from tongsuopy.crypto.asymciphers import ec
from tongsuopy.crypto.exceptions import (
    InvalidSignature,
    UnsupportedAlgorithm,
    _Reasons,
)


if typing.TYPE_CHECKING:
    from tongsuopy.backends.tongsuo.backend import Backend


def _check_signature_algorithm(
    signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
) -> None:
    if not isinstance(signature_algorithm, ec.ECDSA):
        raise UnsupportedAlgorithm(
            "Unsupported elliptic curve signature algorithm.",
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
        )


def check_evp_pkey_algorithm(backend: "Backend", evp_pkey) -> None:
    if backend._lib.EVP_PKEY_is_sm2(evp_pkey):
        return
    raise UnsupportedAlgorithm(
        "Unsupported EVP_PKEY algorithm",
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
    )


def _ec_key_curve_sn(backend: "Backend", ec_key) -> str:
    group = backend._lib.EC_KEY_get0_group(ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    nid = backend._lib.EC_GROUP_get_curve_name(group)
    # The following check is to find EC keys with unnamed curves and raise
    # an error for now.
    if nid == backend._lib.NID_undef:
        raise ValueError(
            "ECDSA keys with explicit parameters are unsupported at this time"
        )

    # This is like the above check, but it also catches the case where you
    # explicitly encoded a curve with the same parameters as a named curve.
    # Don't do that.
    if backend._lib.EC_GROUP_get_asn1_flag(group) == 0:
        raise ValueError(
            "ECDSA keys with explicit parameters are unsupported at this time"
        )

    curve_name = backend._lib.OBJ_nid2sn(nid)
    backend.openssl_assert(curve_name != backend._ffi.NULL)

    sn = backend._ffi.string(curve_name).decode("ascii")
    return sn


def _mark_asn1_named_ec_curve(backend: "Backend", ec_cdata):
    """
    Set the named curve flag on the EC_KEY. This causes OpenSSL to
    serialize EC keys along with their curve OID which makes
    deserialization easier.
    """

    backend._lib.EC_KEY_set_asn1_flag(
        ec_cdata, backend._lib.OPENSSL_EC_NAMED_CURVE
    )


def _check_key_infinity(backend: "Backend", ec_cdata) -> None:
    point = backend._lib.EC_KEY_get0_public_key(ec_cdata)
    backend.openssl_assert(point != backend._ffi.NULL)
    group = backend._lib.EC_KEY_get0_group(ec_cdata)
    backend.openssl_assert(group != backend._ffi.NULL)
    if backend._lib.EC_POINT_is_at_infinity(group, point):
        raise ValueError(
            "Cannot load an EC public key where the point is at infinity"
        )


def _sn_to_elliptic_curve(backend: "Backend", sn: str) -> ec.EllipticCurve:
    try:
        return ec._CURVE_TYPES[sn]()
    except KeyError:
        raise UnsupportedAlgorithm(
            "{} is not a supported elliptic curve".format(sn),
            _Reasons.UNSUPPORTED_ELLIPTIC_CURVE,
        )


def _ecdsa_sig_sign(
    backend: "Backend",
    algorithm: hashes.HashAlgorithm,
    private_key: "_EllipticCurvePrivateKey",
    data: bytes,
) -> bytes:
    mctx = _ecdsa_sig_setup(
        backend,
        algorithm,
        private_key,
        backend._lib.EVP_DigestSignInit,
    )

    buflen = backend._ffi.new("size_t *")
    res = backend._lib.EVP_DigestSign(
        mctx, backend._ffi.NULL, buflen, data, len(data)
    )
    backend.openssl_assert(res == 1)
    buf = backend._ffi.new("unsigned char[]", buflen[0])
    res = backend._lib.EVP_DigestSign(mctx, buf, buflen, data, len(data))
    if res != 1:
        errors = backend._consume_errors_with_text()
        raise ValueError(
            "Digest length too long for key size",
            errors,
        )
    return backend._ffi.buffer(buf)[: buflen[0]]


def _ecdsa_sig_verify(
    backend: "Backend",
    algorithm: hashes.HashAlgorithm,
    public_key: "_EllipticCurvePublicKey",
    signature: bytes,
    data: bytes,
) -> None:
    mctx = _ecdsa_sig_setup(
        backend,
        algorithm,
        public_key,
        backend._lib.EVP_DigestVerifyInit,
    )

    res = backend._lib.EVP_DigestVerify(
        mctx, signature, len(signature), data, len(data)
    )
    # The previous call can return negative numbers in the event of an
    # error. This is not a signature failure but we need to fail if it
    # occurs.
    backend.openssl_assert(res >= 0)
    if res == 0:
        backend._consume_errors()
        raise InvalidSignature


def _ecdsa_sig_setup(
    backend: "Backend",
    algorithm: hashes.HashAlgorithm,
    key: typing.Union["_EllipticCurvePublicKey", "_EllipticCurvePrivateKey"],
    init_func: typing.Callable[
        [typing.Any, typing.Any, typing.Any, typing.Any, typing.Any], int
    ],
):
    mctx = backend._lib.EVP_MD_CTX_new()
    mctx = backend._ffi.gc(mctx, backend._lib.EVP_MD_CTX_free)
    evp_md = backend._evp_md_from_algorithm(algorithm)
    if evp_md == backend._ffi.NULL:
        raise UnsupportedAlgorithm(
            "{} is not a supported hash on this backend.".format(
                algorithm.name
            ),
            _Reasons.UNSUPPORTED_HASH,
        )

    res = init_func(
        mctx, backend._ffi.NULL, evp_md, backend._ffi.NULL, key._evp_pkey
    )
    if res != 1:
        errors = backend._consume_errors()
        raise ValueError("Unable to sign/verify with this key", errors)

    return mctx


def _sm2_crypt_setup(
    backend: "Backend",
    data: bytes,
    key: typing.Union["_EllipticCurvePublicKey", "_EllipticCurvePrivateKey"],
    init_func: typing.Callable[[typing.Any], int],
    exec_func: typing.Callable[
        [typing.Any, typing.Any, typing.Any, typing.Any, typing.Any], int
    ],
) -> bytes:
    pctx = backend._lib.EVP_PKEY_CTX_new(key._evp_pkey, backend._ffi.NULL)
    if pctx == backend._ffi.NULL:
        errors = backend._consume_errors_with_text()
        raise ValueError(
            "Unable to allocate key algorithm context "
            "using the algorithm specified in pkey",
            errors,
        )

    pctx = backend._ffi.gc(pctx, backend._lib.EVP_PKEY_CTX_free)

    if init_func(pctx) <= 0:
        errors = backend._consume_errors_with_text()
        raise ValueError("Unable to initialize key algorithm context", errors)

    buflen = backend._ffi.new("size_t *")
    res = exec_func(pctx, backend._ffi.NULL, buflen, data, len(data))
    backend.openssl_assert(res == 1)
    buf = backend._ffi.new("unsigned char[]", buflen[0])
    res = exec_func(pctx, buf, buflen, data, len(data))
    if res != 1:
        errors = backend._consume_errors_with_text()
        action = ("encrypt", "decrypt")[
            exec_func == backend._lib.EVP_PKEY_decrypt
        ]
        raise ValueError("Failed to {action}".format(action=action), errors)

    return backend._ffi.buffer(buf)[: buflen[0]]


def _sm2_encrypt(
    backend: "Backend",
    public_key: "_EllipticCurvePublicKey",
    data: bytes,
) -> bytes:
    if len(data) == 0:
        # Empty content does not need to be encrypted, and returns b"".
        return b""
    return _sm2_crypt_setup(
        backend,
        data,
        public_key,
        backend._lib.EVP_PKEY_encrypt_init,
        backend._lib.EVP_PKEY_encrypt,
    )


def _sm2_decrypt(
    backend: "Backend",
    private_key: "_EllipticCurvePrivateKey",
    data: bytes,
) -> bytes:
    if len(data) == 0:
        # Empty ciphertext is considered to be the encrypted result of
        # empty content.
        return b""
    return _sm2_crypt_setup(
        backend,
        data,
        private_key,
        backend._lib.EVP_PKEY_decrypt_init,
        backend._lib.EVP_PKEY_decrypt,
    )


class _EllipticCurvePrivateKey(ec.EllipticCurvePrivateKey):
    def __init__(self, backend: "Backend", ec_key_cdata, evp_pkey):
        self._backend = backend
        self._ec_key = ec_key_cdata
        self._evp_pkey = evp_pkey

        sn = _ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = _sn_to_elliptic_curve(backend, sn)
        _mark_asn1_named_ec_curve(backend, ec_key_cdata)
        _check_key_infinity(backend, ec_key_cdata)

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._curve

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def exchange(
        self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        if not (
            self._backend.elliptic_curve_exchange_algorithm_supported(
                algorithm, self.curve
            )
        ):
            raise UnsupportedAlgorithm(
                "This backend does not support the ECDH algorithm.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        if peer_public_key.curve.name != self.curve.name:
            raise ValueError(
                "peer_public_key and self are not on the same curve"
            )

        return _evp_pkey_derive(self._backend, self._evp_pkey, peer_public_key)

    def public_key(self) -> ec.EllipticCurvePublicKey:
        group = self._backend._lib.EC_KEY_get0_group(self._ec_key)
        self._backend.openssl_assert(group != self._backend._ffi.NULL)

        curve_nid = self._backend._lib.EC_GROUP_get_curve_name(group)
        public_ec_key = self._backend._ec_key_new_by_curve_nid(curve_nid)

        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)

        res = self._backend._lib.EC_KEY_set_public_key(public_ec_key, point)
        self._backend.openssl_assert(res == 1)

        evp_pkey = self._backend._ec_cdata_to_evp_pkey(public_ec_key)

        return _EllipticCurvePublicKey(self._backend, public_ec_key, evp_pkey)

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        bn = self._backend._lib.EC_KEY_get0_private_key(self._ec_key)
        private_value = self._backend._bn_to_int(bn)
        return ec.EllipticCurvePrivateNumbers(
            private_value=private_value,
            public_numbers=self.public_key().public_numbers(),
        )

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        return self._backend._private_key_bytes(
            encoding,
            format,
            encryption_algorithm,
            self,
            self._evp_pkey,
            self._ec_key,
        )

    def sign(
        self,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        _check_signature_algorithm(signature_algorithm)
        return _ecdsa_sig_sign(
            self._backend, signature_algorithm.algorithm, self, data
        )

    def decrypt(self, data: bytes) -> bytes:
        check_evp_pkey_algorithm(self._backend, self._evp_pkey)
        return _sm2_decrypt(self._backend, self, data)


class _EllipticCurvePublicKey(ec.EllipticCurvePublicKey):
    def __init__(self, backend: "Backend", ec_key_cdata, evp_pkey):
        self._backend = backend
        self._ec_key = ec_key_cdata
        self._evp_pkey = evp_pkey

        sn = _ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = _sn_to_elliptic_curve(backend, sn)
        _mark_asn1_named_ec_curve(backend, ec_key_cdata)
        _check_key_infinity(backend, ec_key_cdata)

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._curve

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def public_numbers(self) -> ec.EllipticCurvePublicNumbers:
        get_func, group = self._backend._ec_key_determine_group_get_func(
            self._ec_key
        )
        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)

        with self._backend._tmp_bn_ctx() as bn_ctx:
            bn_x = self._backend._lib.BN_CTX_get(bn_ctx)
            bn_y = self._backend._lib.BN_CTX_get(bn_ctx)

            res = get_func(group, point, bn_x, bn_y, bn_ctx)
            self._backend.openssl_assert(res == 1)

            x = self._backend._bn_to_int(bn_x)
            y = self._backend._bn_to_int(bn_y)

        return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=self._curve)

    def _encode_point(self, format: serialization.PublicFormat) -> bytes:
        if format is serialization.PublicFormat.CompressedPoint:
            conversion = self._backend._lib.POINT_CONVERSION_COMPRESSED
        else:
            assert format is serialization.PublicFormat.UncompressedPoint
            conversion = self._backend._lib.POINT_CONVERSION_UNCOMPRESSED

        group = self._backend._lib.EC_KEY_get0_group(self._ec_key)
        self._backend.openssl_assert(group != self._backend._ffi.NULL)
        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)
        with self._backend._tmp_bn_ctx() as bn_ctx:
            buflen = self._backend._lib.EC_POINT_point2oct(
                group, point, conversion, self._backend._ffi.NULL, 0, bn_ctx
            )
            self._backend.openssl_assert(buflen > 0)
            buf = self._backend._ffi.new("char[]", buflen)
            res = self._backend._lib.EC_POINT_point2oct(
                group, point, conversion, buf, buflen, bn_ctx
            )
            self._backend.openssl_assert(buflen == res)

        return self._backend._ffi.buffer(buf)[:]

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        if (
            encoding is serialization.Encoding.X962
            or format is serialization.PublicFormat.CompressedPoint
            or format is serialization.PublicFormat.UncompressedPoint
        ):
            if encoding is not serialization.Encoding.X962 or format not in (
                serialization.PublicFormat.CompressedPoint,
                serialization.PublicFormat.UncompressedPoint,
            ):
                raise ValueError(
                    "X962 encoding must be used with CompressedPoint or "
                    "UncompressedPoint format"
                )

            return self._encode_point(format)
        else:
            return self._backend._public_key_bytes(
                encoding, format, self, self._evp_pkey, None
            )

    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> None:
        _check_signature_algorithm(signature_algorithm)
        _ecdsa_sig_verify(
            self._backend, signature_algorithm.algorithm, self, signature, data
        )

    def encrypt(self, data: bytes) -> bytes:
        check_evp_pkey_algorithm(self._backend, self._evp_pkey)
        return _sm2_encrypt(self._backend, self, data)
