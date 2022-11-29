# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import abc
import enum
import typing


# We use a UserWarning subclass, instead of DeprecationWarning, because CPython
# decided deprecation warnings should be invisble by default.
class CryptographyDeprecationWarning(UserWarning):
    pass


# Several APIs were deprecated with no specific end-of-life date because of the
# ubiquity of their use. They should not be removed until we agree on when that
# cycle ends.
DeprecatedIn36 = CryptographyDeprecationWarning
DeprecatedIn37 = CryptographyDeprecationWarning
DeprecatedIn39 = CryptographyDeprecationWarning


def _check_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError("{} must be bytes".format(name))


def _check_byteslike(name: str, value: bytes) -> None:
    try:
        memoryview(value)
    except TypeError:
        raise TypeError("{} must be bytes-like".format(name))


def int_to_bytes(integer: int, length: typing.Optional[int] = None) -> bytes:
    return integer.to_bytes(
        length or (integer.bit_length() + 7) // 8 or 1, "big"
    )


class InterfaceNotImplemented(Exception):
    pass


# DeprecatedIn39 -- Our only known consumer is aws-encryption-sdk, but we've
# made this a no-op to avoid breaking old versions.
def verify_interface(
    iface: abc.ABCMeta, klass: object, *, check_annotations: bool = False
):
    # Exists exclusively for `aws-encryption-sdk` which relies on it existing,
    # even though it was never a public API.
    pass


class _DeprecatedValue:
    def __init__(self, value: object, message: str, warning_class):
        self.value = value
        self.message = message
        self.warning_class = warning_class


# Python 3.10 changed representation of enums. We use well-defined object
# representation and string representation from Python 3.9.
class Enum(enum.Enum):
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}.{self._name_}: {self._value_!r}>"

    def __str__(self) -> str:
        return f"{self.__class__.__name__}.{self._name_}"
