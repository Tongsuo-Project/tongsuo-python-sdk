# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import binascii
import itertools
import os
import typing

import pytest

from tongsuopy.crypto import exceptions, hashes, serialization
from tongsuopy.crypto.asymciphers import ec
from tongsuopy.crypto.asymciphers.utils import encode_dss_signature

from ..doubles import DummyKeySerializationEncryption
from ..utils import (
    load_decrypt_vectors,
    load_fips_ecdsa_key_pair_vectors,
    load_fips_ecdsa_signing_vectors,
    load_nist_vectors,
    load_vectors_from_file,
    raises_unsupported_algorithm,
)

_HASH_TYPES: typing.Dict[str, typing.Type[hashes.HashAlgorithm]] = {
    "SM3": hashes.SM3
}


class DummyCurve(ec.EllipticCurve):
    name = "dummy-curve"
    key_size = 1


class DummySignatureAlgorithm(ec.EllipticCurveSignatureAlgorithm):
    algorithm = hashes.SM3()


def _skip_curve_unsupported(backend, curve):
    if not backend.elliptic_curve_supported(curve):
        pytest.skip(
            "Curve {} is not supported by this backend {}".format(
                curve.name, backend
            )
        )


def _skip_ecdsa_vector(backend, curve_type, hash_type):
    if not backend.elliptic_curve_signature_algorithm_supported(
        ec.ECDSA(hash_type()), curve_type()
    ):
        pytest.skip(
            "ECDSA not supported with this hash {} and curve {}.".format(
                hash_type().name, curve_type().name
            )
        )


def test_derive_private_key_success(backend):
    curve = ec.SM2()
    _skip_curve_unsupported(backend, curve)

    private_numbers = ec.generate_private_key(curve, backend).private_numbers()

    derived_key = ec.derive_private_key(
        private_numbers.private_value, curve, backend
    )

    assert private_numbers == derived_key.private_numbers()


def test_derive_private_key_errors(backend):
    curve = ec.SM2()
    _skip_curve_unsupported(backend, curve)

    with pytest.raises(TypeError):
        ec.derive_private_key("one", curve, backend)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        ec.derive_private_key(10, "five", backend)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        ec.derive_private_key(-7, curve, backend)


def test_derive_point_at_infinity(backend):
    curve = ec.SM2()
    _skip_curve_unsupported(backend, curve)
    # order of the curve
    q = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    with pytest.raises(ValueError, match="Unable to derive"):
        ec.derive_private_key(q, ec.SM2())


def test_ec_numbers():
    numbers = ec.EllipticCurvePrivateNumbers(
        1, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )

    assert numbers.private_value == 1
    assert numbers.public_numbers.x == 2
    assert numbers.public_numbers.y == 3
    assert isinstance(numbers.public_numbers.curve, DummyCurve)


@pytest.mark.parametrize(
    ("private_value", "x", "y", "curve"),
    [
        (None, 2, 3, DummyCurve()),
        (1, None, 3, DummyCurve()),
        (1, 2, None, DummyCurve()),
        (1, 2, 3, None),
    ],
)
def test_invalid_ec_numbers_args(private_value, x, y, curve):
    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(
            private_value, ec.EllipticCurvePublicNumbers(x, y, curve)
        )


def test_invalid_private_numbers_public_numbers():
    with pytest.raises(TypeError):
        ec.EllipticCurvePrivateNumbers(1, None)  # type: ignore[arg-type]


def test_ec_public_numbers_repr():
    pn = ec.EllipticCurvePublicNumbers(2, 3, ec.SM2())
    assert repr(pn) == "<EllipticCurvePublicNumbers(curve=SM2, x=2, y=3>"


def test_ec_public_numbers_hash():
    pn1 = ec.EllipticCurvePublicNumbers(2, 3, ec.SM2())
    pn2 = ec.EllipticCurvePublicNumbers(2, 3, ec.SM2())
    pn3 = ec.EllipticCurvePublicNumbers(1, 3, ec.SM2())

    assert hash(pn1) == hash(pn2)
    assert hash(pn1) != hash(pn3)


def test_ec_private_numbers_hash():
    numbers1 = ec.EllipticCurvePrivateNumbers(
        1, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )
    numbers2 = ec.EllipticCurvePrivateNumbers(
        1, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )
    numbers3 = ec.EllipticCurvePrivateNumbers(
        2, ec.EllipticCurvePublicNumbers(2, 3, DummyCurve())
    )

    assert hash(numbers1) == hash(numbers2)
    assert hash(numbers1) != hash(numbers3)


def test_ec_key_key_size(backend):
    curve = ec.SM2()
    _skip_curve_unsupported(backend, curve)
    key = ec.generate_private_key(curve, backend)
    assert key.key_size == 256
    assert key.public_key().key_size == 256


class TestECWithNumbers:
    def test_sm2_with_numbers(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join(
                "asymciphers", "SM2", "GB_32918.5-2017", "KeyPair.rsp"
            ),
            load_fips_ecdsa_key_pair_vectors,
        )
        for vector in vectors:
            with subtests.test():
                curve_type: typing.Type[ec.EllipticCurve] = ec._CURVE_TYPES[
                    vector["curve"]
                ]

                key = ec.EllipticCurvePrivateNumbers(
                    vector["d"],
                    ec.EllipticCurvePublicNumbers(
                        vector["x"], vector["y"], curve_type()
                    ),
                ).private_key(backend)
                assert key

                priv_num = key.private_numbers()
                assert priv_num.private_value == vector["d"]
                assert priv_num.public_numbers.x == vector["x"]
                assert priv_num.public_numbers.y == vector["y"]
                assert curve_type().name == priv_num.public_numbers.curve.name


class TestECDSAVectors:
    def test_sm2_signing_with_example_keys(self, backend, subtests):
        vectors = itertools.product(
            load_vectors_from_file(
                os.path.join(
                    "asymciphers", "SM2", "GB_32918.5-2017", "KeyPair.rsp"
                ),
                load_fips_ecdsa_key_pair_vectors,
            ),
            [hashes.SM3],
        )
        for vector, hash_type in vectors:
            with subtests.test():
                curve_type = ec._CURVE_TYPES[vector["curve"]]

                _skip_ecdsa_vector(backend, curve_type, hash_type)

                key = ec.EllipticCurvePrivateNumbers(
                    vector["d"],
                    ec.EllipticCurvePublicNumbers(
                        vector["x"], vector["y"], curve_type()
                    ),
                ).private_key(backend)
                assert key

                pkey = key.public_key()
                assert pkey

                signature = key.sign(
                    b"YELLOW SUBMARINE", ec.ECDSA(hash_type())
                )

                pkey.verify(
                    signature, b"YELLOW SUBMARINE", ec.ECDSA(hash_type())
                )

    @pytest.mark.parametrize("curve", ec._CURVE_TYPES.values())
    def test_generate_vector_curves(self, backend, curve):
        _skip_curve_unsupported(backend, curve())

        key = ec.generate_private_key(curve(), backend)
        assert key
        assert isinstance(key.curve, curve)
        assert key.curve.key_size

        pkey = key.public_key()
        assert pkey
        assert isinstance(pkey.curve, curve)
        assert key.curve.key_size == pkey.curve.key_size

    def test_generate_unknown_curve(self, backend):
        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        ):
            ec.generate_private_key(DummyCurve(), backend)

        assert (
            backend.elliptic_curve_signature_algorithm_supported(
                ec.ECDSA(hashes.SM3()), DummyCurve()
            )
            is False
        )

    def test_unknown_signature_algorithm(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())

        key = ec.generate_private_key(ec.SM2(), backend)

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.sign(b"somedata", DummySignatureAlgorithm())

        with raises_unsupported_algorithm(
            exceptions._Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            key.public_key().verify(
                b"signature", b"data", DummySignatureAlgorithm()
            )

        assert (
            backend.elliptic_curve_signature_algorithm_supported(
                DummySignatureAlgorithm(), ec.SM2()
            )
            is False
        )

    def test_load_invalid_ec_key_from_numbers(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())

        numbers = ec.EllipticCurvePrivateNumbers(
            357646505660320080863666618182642070958081774038609089496899025506,
            ec.EllipticCurvePublicNumbers(
                47250808410327023131573602008345894927686381772325561185532964,
                1120253292479243545483756778742719537373113335231773536789915,
                ec.SM2(),
            ),
        )
        with pytest.raises(ValueError):
            numbers.private_key(backend)

        numbers = ec.EllipticCurvePrivateNumbers(
            357646505660320080863666618182642070958081774038609089496899025506,
            ec.EllipticCurvePublicNumbers(
                -4725080841032702313157360200834589492768638177232556118553296,
                1120253292479243545483756778742719537373113335231773536789915,
                ec.SM2(),
            ),
        )
        with pytest.raises(ValueError):
            numbers.private_key(backend)

        numbers = ec.EllipticCurvePrivateNumbers(
            357646505660320080863666618182642070958081774038609089496899025506,
            ec.EllipticCurvePublicNumbers(
                47250808410327023131573602008345894927686381772325561185532964,
                -1120253292479243545483756778742719537373113335231773536789915,
                ec.SM2(),
            ),
        )
        with pytest.raises(ValueError):
            numbers.private_key(backend)

    def test_load_invalid_public_ec_key_from_numbers(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())

        # Bad X coordinate
        numbers = ec.EllipticCurvePublicNumbers(
            int(
                "000003647356b91f8ace114c7247ecf4f4a622553fc025e04a178f179ef27"
                "9090c184af678a4c78f635483bdd8aa544851c6ef291c1f0d6a241ebfd145"
                "77d1d30d9903ce",
                16,
            ),
            int(
                "000001499bc7e079322ea0fcfbd6b40103fa6a1536c2257b182db0df4b369"
                "6ec643adf100eb4f2025d1b873f82e5a475d6e4400ba777090eeb4563a115"
                "09e4c87319dc26",
                16,
            ),
            ec.SM2(),
        )
        with pytest.raises(ValueError):
            numbers.public_key(backend)

        # Bad Y coordinate
        numbers = ec.EllipticCurvePublicNumbers(
            int(
                "0000019aadc221cc0525118ab6d5aa1f64720603de0be128cbfea0b381ad8"
                "02a2facc6370bb58cf88b3f0c692bc654ee19d6cad198f10d4b681b396f20"
                "d2e40603fa945b",
                16,
            ),
            int(
                "0000025da392803a320717a08d4cb3dea932039badff363b71bdb8064e726"
                "6c7f4f4b748d4d425347fc33e3885d34b750fa7fcd5691f4d90c89522ce33"
                "feff5db10088a5",
                16,
            ),
            ec.SM2(),
        )
        with pytest.raises(ValueError):
            numbers.public_key(backend)

    def test_signatures(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join(
                "asymciphers", "SM2", "GB_32918.5-2017", "SigGen.txt"
            ),
            load_fips_ecdsa_signing_vectors,
        )

        for vector in vectors:
            with subtests.test():
                hash_type = _HASH_TYPES[vector["digest_algorithm"]]
                curve_type: typing.Type[ec.EllipticCurve] = ec._CURVE_TYPES[
                    vector["curve"]
                ]

                _skip_ecdsa_vector(backend, curve_type, hash_type)

                key = ec.EllipticCurvePublicNumbers(
                    vector["x"], vector["y"], curve_type()
                ).public_key(backend)

                signature = encode_dss_signature(vector["r"], vector["s"])
                key.verify(signature, vector["message"], ec.ECDSA(hash_type()))

    def test_signature_failures(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join(
                "asymciphers", "SM2", "GB_32918.5-2017", "SigFail.txt"
            ),
            load_fips_ecdsa_signing_vectors,
        )
        for vector in vectors:
            with subtests.test():
                hash_type = _HASH_TYPES[vector["digest_algorithm"]]
                curve_type = ec._CURVE_TYPES[vector["curve"]]

                _skip_ecdsa_vector(backend, curve_type, hash_type)

                key = ec.EllipticCurvePublicNumbers(
                    vector["x"], vector["y"], curve_type()
                ).public_key(backend)

                signature = encode_dss_signature(vector["r"], vector["s"])

                if vector["fail"] is True:
                    with pytest.raises(exceptions.InvalidSignature):
                        key.verify(
                            signature, vector["message"], ec.ECDSA(hash_type())
                        )
                else:
                    key.verify(
                        signature, vector["message"], ec.ECDSA(hash_type())
                    )

    def test_sign(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        message = b"one little message"
        algorithm = ec.ECDSA(hashes.SM3())
        private_key = ec.generate_private_key(ec.SM2(), backend)
        signature = private_key.sign(message, algorithm)
        public_key = private_key.public_key()
        public_key.verify(signature, message, algorithm)

    def test_verify(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        message = b"one little message"
        algorithm = ec.ECDSA(hashes.SM3())
        private_key = ec.generate_private_key(ec.SM2(), backend)
        signature = private_key.sign(message, algorithm)
        public_key = private_key.public_key()
        public_key.verify(signature, message, algorithm)

    def test_encrypt_decrypt(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        message = b"one little message"
        private_key = ec.generate_private_key(ec.SM2(), backend)
        public_key = private_key.public_key()
        ciphertext = public_key.encrypt(message)
        assert private_key.decrypt(ciphertext) == message

    def test_encrypt_decrypt_with_empty_message(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        message = b""
        private_key = ec.generate_private_key(ec.SM2(), backend)
        public_key = private_key.public_key()
        ciphertext = public_key.encrypt(message)
        assert ciphertext == b""
        assert private_key.decrypt(ciphertext) == message


class TestECNumbersEquality:
    def test_public_numbers_eq(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())
        assert pub == ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())

    def test_public_numbers_ne(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())
        assert pub != ec.EllipticCurvePublicNumbers(1, 2, DummyCurve())
        assert pub != ec.EllipticCurvePublicNumbers(1, 3, ec.SM2())
        assert pub != ec.EllipticCurvePublicNumbers(2, 2, ec.SM2())
        assert pub != object()

    def test_private_numbers_eq(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())
        priv = ec.EllipticCurvePrivateNumbers(1, pub)
        assert priv == ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())
        )

    def test_private_numbers_ne(self):
        pub = ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())
        priv = ec.EllipticCurvePrivateNumbers(1, pub)
        assert priv != ec.EllipticCurvePrivateNumbers(
            2, ec.EllipticCurvePublicNumbers(1, 2, ec.SM2())
        )
        assert priv != ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(2, 2, ec.SM2())
        )
        assert priv != ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(1, 3, ec.SM2())
        )
        assert priv != ec.EllipticCurvePrivateNumbers(
            1, ec.EllipticCurvePublicNumbers(1, 2, DummyCurve())
        )
        assert priv != object()


class TestECSerialization:
    @pytest.mark.parametrize(
        ("fmt", "password"),
        itertools.product(
            [
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.PrivateFormat.PKCS8,
            ],
            [
                b"s",
                b"longerpassword",
                b"!*$&(@#$*&($T@%_somesymbols",
                b"\x01" * 1000,
            ],
        ),
    )
    def test_private_bytes_encrypted_pem(self, backend, fmt, password):
        _skip_curve_unsupported(backend, ec.SM2())
        key_bytes = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: pemfile.read().encode(),
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        serialized = key.private_bytes(
            serialization.Encoding.PEM,
            fmt,
            serialization.BestAvailableEncryption(password),
        )
        loaded_key = serialization.load_pem_private_key(
            serialized, password, backend
        )
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("encoding", "fmt"),
        [
            (serialization.Encoding.Raw, serialization.PrivateFormat.PKCS8),
            (serialization.Encoding.DER, serialization.PrivateFormat.Raw),
            (serialization.Encoding.Raw, serialization.PrivateFormat.Raw),
            (serialization.Encoding.X962, serialization.PrivateFormat.PKCS8),
        ],
    )
    def test_private_bytes_rejects_invalid(self, encoding, fmt, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = ec.generate_private_key(ec.SM2(), backend)
        with pytest.raises(ValueError):
            key.private_bytes(encoding, fmt, serialization.NoEncryption())

    @pytest.mark.parametrize(
        ("fmt", "password"),
        [
            [serialization.PrivateFormat.PKCS8, b"s"],
            [serialization.PrivateFormat.PKCS8, b"longerpassword"],
            [serialization.PrivateFormat.PKCS8, b"!*$&(@#$*&($T@%_somesymbol"],
            [serialization.PrivateFormat.PKCS8, b"\x01" * 1000],
        ],
    )
    def test_private_bytes_encrypted_der(self, backend, fmt, password):
        _skip_curve_unsupported(backend, ec.SM2())
        key_bytes = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: pemfile.read().encode(),
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        serialized = key.private_bytes(
            serialization.Encoding.DER,
            fmt,
            serialization.BestAvailableEncryption(password),
        )
        loaded_key = serialization.load_der_private_key(
            serialized, password, backend
        )
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("encoding", "fmt", "loader_func"),
        [
            [
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.load_pem_private_key,
            ],
            [
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.load_der_private_key,
            ],
            [
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.load_pem_private_key,
            ],
            [
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.load_der_private_key,
            ],
        ],
    )
    def test_private_bytes_unencrypted(
        self, backend, encoding, fmt, loader_func
    ):
        _skip_curve_unsupported(backend, ec.SM2())
        key_bytes = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: pemfile.read().encode(),
        )
        key = serialization.load_pem_private_key(key_bytes, None, backend)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        serialized = key.private_bytes(
            encoding, fmt, serialization.NoEncryption()
        )
        loaded_key = loader_func(serialized, None, backend)
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        loaded_priv_num = loaded_key.private_numbers()
        priv_num = key.private_numbers()
        assert loaded_priv_num == priv_num

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader_func"),
        [
            [
                os.path.join(
                    "asymciphers", "PEM_Serialization", "sm2_private_key.pem"
                ),
                serialization.Encoding.PEM,
                serialization.load_pem_private_key,
            ],
            [
                os.path.join(
                    "asymciphers", "DER_Serialization", "sm2_private_key.der"
                ),
                serialization.Encoding.DER,
                serialization.load_der_private_key,
            ],
        ],
    )
    def test_private_bytes_traditional_openssl_unencrypted(
        self, backend, key_path, encoding, loader_func
    ):
        _skip_curve_unsupported(backend, ec.SM2())
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        key = loader_func(key_bytes, None, backend)
        serialized = key.private_bytes(
            encoding,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        assert serialized.splitlines() == key_bytes.splitlines()

    def test_private_bytes_traditional_der_encrypted_invalid(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(b"password"),
            )

    def test_private_bytes_invalid_encoding(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                "notencoding",  # type: ignore[arg-type]
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

    def test_private_bytes_invalid_format(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.PEM,
                "invalidformat",  # type: ignore[arg-type]
                serialization.NoEncryption(),
            )

    def test_private_bytes_invalid_encryption_algorithm(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                "notanencalg",  # type: ignore[arg-type]
            )

    def test_private_bytes_unsupported_encryption_type(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                DummyKeySerializationEncryption(),
            )

    def test_public_bytes_from_derived_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join("asymciphers", "PKCS8", "sm2_private_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        public = key.public_key()
        pem = public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        parsed_public = serialization.load_pem_public_key(pem, backend)
        assert parsed_public


class TestEllipticCurvePEMPublicKeySerialization:
    @pytest.mark.parametrize(
        ("key_path", "loader_func", "encoding"),
        [
            (
                os.path.join(
                    "asymciphers", "PEM_Serialization", "sm2_public_key.pem"
                ),
                serialization.load_pem_public_key,
                serialization.Encoding.PEM,
            ),
            (
                os.path.join(
                    "asymciphers", "DER_Serialization", "sm2_public_key.der"
                ),
                serialization.load_der_public_key,
                serialization.Encoding.DER,
            ),
        ],
    )
    def test_public_bytes_match(
        self, key_path, loader_func, encoding, backend
    ):
        _skip_curve_unsupported(backend, ec.SM2())
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        key = loader_func(key_bytes, backend)
        serialized = key.public_bytes(
            encoding,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert serialized.splitlines() == key_bytes.splitlines()

    def test_public_bytes_invalid_encoding(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        with pytest.raises(TypeError):
            key.public_bytes(
                "notencoding",  # type: ignore[arg-type]
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    @pytest.mark.parametrize(
        ("encoding", "fmt"),
        list(
            itertools.product(
                [
                    serialization.Encoding.Raw,
                    serialization.Encoding.X962,
                    serialization.Encoding.PEM,
                    serialization.Encoding.DER,
                ],
                [serialization.PublicFormat.Raw],
            )
        )
        + list(
            itertools.product(
                [serialization.Encoding.Raw],
                [
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                    serialization.PublicFormat.PKCS1,
                    serialization.PublicFormat.UncompressedPoint,
                    serialization.PublicFormat.CompressedPoint,
                ],
            )
        ),
    )
    def test_public_bytes_rejects_invalid(self, encoding, fmt, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = ec.generate_private_key(ec.SM2(), backend).public_key()
        with pytest.raises(ValueError):
            key.public_bytes(encoding, fmt)

    def test_public_bytes_invalid_format(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        with pytest.raises(TypeError):
            key.public_bytes(
                serialization.Encoding.PEM,
                "invalidformat",  # type: ignore[arg-type]
            )

    def test_public_bytes_pkcs1_unsupported(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        key = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
            )

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymciphers", "SM2", "compressed_points.txt"),
            load_nist_vectors,
        ),
    )
    def test_from_encoded_point_compressed(self, vector, backend):
        curve = {b"SM2": ec.SM2()}[vector["curve"]]
        _skip_curve_unsupported(backend, curve)
        point = binascii.unhexlify(vector["point"])
        pn = ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
        public_num = pn.public_numbers()
        assert public_num.x == int(vector["x"], 16)
        assert public_num.y == int(vector["y"], 16)

    def test_from_encoded_point_notoncurve(self):
        uncompressed_point = binascii.unhexlify(
            "047399336a9edf2197c2f8eb3d39aed9c34a66e45d918a07dc7684c42c9b37ac"
            "686699ececc4f5f0d756d3c450708a0694eb0a07a68b805070b40b058d27271f"
            "6e"
        )
        with pytest.raises(ValueError):
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SM2(), uncompressed_point
            )

    def test_from_encoded_point_uncompressed(self):
        uncompressed_point = binascii.unhexlify(
            "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F350"
            "20CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD"
            "13"
        )
        pn = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SM2(), uncompressed_point
        )
        assert pn.public_numbers().x == int(
            "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020",
            16,
        )
        assert pn.public_numbers().y == int(
            "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13",
            16,
        )

    def test_from_encoded_point_invalid_length(self):
        bad_data = binascii.unhexlify(
            "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F350"
            "20CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD"
        )
        with pytest.raises(ValueError):
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SM2(), bad_data)

    def test_from_encoded_point_empty_byte_string(self):
        with pytest.raises(ValueError):
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SM2(), b"")

    def test_from_encoded_point_not_a_curve(self):
        with pytest.raises(TypeError):
            ec.EllipticCurvePublicKey.from_encoded_point(
                "notacurve", b"\x04data"  # type: ignore[arg-type]
            )

    def test_from_encoded_point_unsupported_encoding(self):
        unsupported_type = binascii.unhexlify(
            "057399336a9edf2197c2f8eb3d39aed9c34a66e45d918a07dc7684c42c9b37ac6"
            "8"
        )
        with pytest.raises(ValueError):
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SM2(), unsupported_type
            )

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("asymciphers", "SM2", "compressed_points.txt"),
            load_nist_vectors,
        ),
    )
    def test_serialize_point(self, vector, backend):
        curve = {b"SM2": ec.SM2()}[vector["curve"]]
        _skip_curve_unsupported(backend, curve)
        point = binascii.unhexlify(vector["point"])
        key = ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
        key2 = ec.EllipticCurvePublicKey.from_encoded_point(
            curve,
            key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            ),
        )
        assert (
            key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
            == point
        )
        assert (
            key2.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
            == point
        )


class TestECDSAWithPEM:
    def test_verify_with_pem_pubkey(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        msg = b"hello"
        key = ec.generate_private_key(ec.SM2(), backend)

        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pubkey = serialization.load_pem_public_key(pem, backend)

        signature = key.sign(msg, ec.ECDSA(hashes.SM3()))
        pubkey.verify(signature, msg, ec.ECDSA(hashes.SM3()))

    def test_encrypt_decrypt_with_gen_pem(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        msg = b"hello"
        key = ec.generate_private_key(ec.SM2(), backend)

        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pubkey = serialization.load_pem_public_key(pem, backend)
        ciphertext = pubkey.encrypt(msg)
        assert key.decrypt(ciphertext) == msg

    def test_sign_verify_from_pem(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        msg = b"hello"
        privkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_private_key.pem"
            ),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        assert isinstance(privkey, ec.EllipticCurvePrivateKey)
        signature = privkey.sign(msg, ec.ECDSA(hashes.SM3()))

        pubkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        assert isinstance(pubkey, ec.EllipticCurvePublicKey)
        pubkey.verify(signature, msg, ec.ECDSA(hashes.SM3()))

    def test_encrypt_decrypt_from_pem(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        msg = b"hello"
        privkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_private_key.pem"
            ),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )

        pubkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "PEM_Serialization", "sm2_public_key.pem"
            ),
            lambda pemfile: serialization.load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )

        ciphertext = pubkey.encrypt(msg)
        assert privkey.decrypt(ciphertext) == msg

    def test_sign_verify_from_der(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        msg = b"hello"

        privkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "DER_Serialization", "sm2_private_key.der"
            ),
            lambda pemfile: serialization.load_der_private_key(
                pemfile.read(), None, backend
            ),
            mode="rb",
        )
        assert isinstance(privkey, ec.EllipticCurvePrivateKey)
        signature = privkey.sign(msg, ec.ECDSA(hashes.SM3()))

        pubkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "DER_Serialization", "sm2_public_key.der"
            ),
            lambda pemfile: serialization.load_der_public_key(
                pemfile.read(), backend
            ),
            mode="rb",
        )
        assert isinstance(pubkey, ec.EllipticCurvePublicKey)
        pubkey.verify(signature, msg, ec.ECDSA(hashes.SM3()))

    def test_encrypt_decrypt_from_der(self, backend):
        _skip_curve_unsupported(backend, ec.SM2())
        msg = b"hello"

        privkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "DER_Serialization", "sm2_private_key.der"
            ),
            lambda pemfile: serialization.load_der_private_key(
                pemfile.read(), None, backend
            ),
            mode="rb",
        )

        pubkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "DER_Serialization", "sm2_public_key.der"
            ),
            lambda pemfile: serialization.load_der_public_key(
                pemfile.read(), backend
            ),
            mode="rb",
        )

        ciphertext = pubkey.encrypt(msg)
        assert privkey.decrypt(ciphertext) == msg

    def test_decrypt_with_vectors_from_pem(self, backend, subtests):
        _skip_curve_unsupported(backend, ec.SM2())
        privkey = load_vectors_from_file(
            os.path.join(
                "asymciphers", "SM2", "Decrypt", "sm2_private_key.pem"
            ),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        vectors = load_vectors_from_file(
            os.path.join("asymciphers", "SM2", "Decrypt", "DecryptGen.txt"),
            load_decrypt_vectors,
        )
        for vector in vectors:
            with subtests.test():
                assert privkey.decrypt(vector["input"]) == vector["output"]
