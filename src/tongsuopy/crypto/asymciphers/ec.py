# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import abc
import typing

from tongsuopy.crypto import _serialization, hashes, utils


class EllipticCurve(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def name(self) -> str:
        """
        The name of the curve. e.g. secp256r1.
        """

    @abc.abstractproperty
    def key_size(self) -> int:
        """
        Bit size of a secret scalar for the curve.
        """


class SM2(EllipticCurve):
    name = "SM2"
    key_size = 256


class EllipticCurveSignatureAlgorithm(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def algorithm(
        self,
    ) -> hashes.HashAlgorithm:
        """
        The digest algorithm used with this signature.
        """


class EllipticCurvePrivateKey(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def exchange(
        self, algorithm: "ECDH", peer_public_key: "EllipticCurvePublicKey"
    ) -> bytes:
        """
        Performs a key exchange operation using the provided algorithm with the
        provided peer's public key.
        """

    @abc.abstractmethod
    def public_key(self) -> "EllipticCurvePublicKey":
        """
        The EllipticCurvePublicKey for this private key.
        """

    @abc.abstractproperty
    def curve(self) -> EllipticCurve:
        """
        The EllipticCurve that this key is on.
        """

    @abc.abstractproperty
    def key_size(self) -> int:
        """
        Bit size of a secret scalar for the curve.
        """

    @abc.abstractmethod
    def sign(
        self,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        """
        Signs the data
        """

    @abc.abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts the data
        """

    @abc.abstractmethod
    def private_numbers(self) -> "EllipticCurvePrivateNumbers":
        """
        Returns an EllipticCurvePrivateNumbers.
        """

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Returns the key serialized as bytes.
        """


EllipticCurvePrivateKeyWithSerialization = EllipticCurvePrivateKey


class EllipticCurvePublicKey(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def curve(self) -> EllipticCurve:
        """
        The EllipticCurve that this key is on.
        """

    @abc.abstractproperty
    def key_size(self) -> int:
        """
        Bit size of a secret scalar for the curve.
        """

    @abc.abstractmethod
    def public_numbers(self) -> "EllipticCurvePublicNumbers":
        """
        Returns an EllipticCurvePublicNumbers.
        """

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        Returns the key serialized as bytes.
        """

    @abc.abstractmethod
    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> None:
        """
        Verifies the signature of the data.
        """

    @abc.abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts the data
        """

    @classmethod
    def from_encoded_point(
        cls, curve: EllipticCurve, data: bytes
    ) -> "EllipticCurvePublicKey":
        utils._check_bytes("data", data)

        if not isinstance(curve, EllipticCurve):
            raise TypeError("curve must be an EllipticCurve instance")

        if len(data) == 0:
            raise ValueError("data must not be an empty byte string")

        if data[0] not in [0x02, 0x03, 0x04]:
            raise ValueError("Unsupported elliptic curve point type")

        from tongsuopy.backends.tongsuo import backend

        return backend.load_elliptic_curve_public_bytes(curve, data)


EllipticCurvePublicKeyWithSerialization = EllipticCurvePublicKey


_CURVE_TYPES: typing.Dict[str, typing.Type[EllipticCurve]] = {
    "SM2": SM2,
}


class ECDSA(EllipticCurveSignatureAlgorithm):
    def __init__(
        self,
        algorithm: hashes.HashAlgorithm,
    ):
        self._algorithm = algorithm

    @property
    def algorithm(
        self,
    ) -> hashes.HashAlgorithm:
        return self._algorithm


def generate_private_key(
    curve: EllipticCurve, backend: typing.Any = None
) -> EllipticCurvePrivateKey:
    from tongsuopy.backends.tongsuo import backend as ossl

    return ossl.generate_elliptic_curve_private_key(curve)


def derive_private_key(
    private_value: int,
    curve: EllipticCurve,
    backend: typing.Any = None,
) -> EllipticCurvePrivateKey:
    from tongsuopy.backends.tongsuo import backend as ossl

    if not isinstance(private_value, int):
        raise TypeError("private_value must be an integer type.")

    if private_value <= 0:
        raise ValueError("private_value must be a positive integer.")

    if not isinstance(curve, EllipticCurve):
        raise TypeError("curve must provide the EllipticCurve interface.")

    return ossl.derive_elliptic_curve_private_key(private_value, curve)


class EllipticCurvePublicNumbers:
    def __init__(self, x: int, y: int, curve: EllipticCurve):
        if not isinstance(x, int) or not isinstance(y, int):
            raise TypeError("x and y must be integers.")

        if not isinstance(curve, EllipticCurve):
            raise TypeError("curve must provide the EllipticCurve interface.")

        self._y = y
        self._x = x
        self._curve = curve

    def public_key(self, backend: typing.Any = None) -> EllipticCurvePublicKey:
        from tongsuopy.backends.tongsuo import backend as ossl

        return ossl.load_elliptic_curve_public_numbers(self)

    @property
    def curve(self) -> EllipticCurve:
        return self._curve

    @property
    def x(self) -> int:
        return self._x

    @property
    def y(self) -> int:
        return self._y

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EllipticCurvePublicNumbers):
            return NotImplemented

        return (
            self.x == other.x
            and self.y == other.y
            and self.curve.name == other.curve.name
            and self.curve.key_size == other.curve.key_size
        )

    def __hash__(self) -> int:
        return hash((self.x, self.y, self.curve.name, self.curve.key_size))

    def __repr__(self) -> str:
        return (
            "<EllipticCurvePublicNumbers(curve={0.curve.name}, x={0.x}, "
            "y={0.y}>".format(self)
        )


class EllipticCurvePrivateNumbers:
    def __init__(
        self, private_value: int, public_numbers: EllipticCurvePublicNumbers
    ):
        if not isinstance(private_value, int):
            raise TypeError("private_value must be an integer.")

        if not isinstance(public_numbers, EllipticCurvePublicNumbers):
            raise TypeError(
                "public_numbers must be an EllipticCurvePublicNumbers "
                "instance."
            )

        self._private_value = private_value
        self._public_numbers = public_numbers

    def private_key(
        self, backend: typing.Any = None
    ) -> EllipticCurvePrivateKey:
        from tongsuopy.backends.tongsuo import backend as ossl

        return ossl.load_elliptic_curve_private_numbers(self)

    @property
    def private_value(self) -> int:
        return self._private_value

    @property
    def public_numbers(self) -> EllipticCurvePublicNumbers:
        return self._public_numbers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EllipticCurvePrivateNumbers):
            return NotImplemented

        return (
            self.private_value == other.private_value
            and self.public_numbers == other.public_numbers
        )

    def __hash__(self) -> int:
        return hash((self.private_value, self.public_numbers))


class ECDH:
    pass
