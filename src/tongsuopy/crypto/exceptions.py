# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import typing

from tongsuopy.crypto import utils

if typing.TYPE_CHECKING:
    from tongsuopy.backends.tongsuo.binding import (
        _OpenSSLErrorWithText,
    )


class _Reasons(utils.Enum):
    BACKEND_MISSING_INTERFACE = 0
    UNSUPPORTED_HASH = 1
    UNSUPPORTED_CIPHER = 2
    UNSUPPORTED_PADDING = 3
    UNSUPPORTED_MGF = 4
    UNSUPPORTED_PUBLIC_KEY_ALGORITHM = 5
    UNSUPPORTED_ELLIPTIC_CURVE = 6
    UNSUPPORTED_SERIALIZATION = 7
    UNSUPPORTED_X509 = 8
    UNSUPPORTED_EXCHANGE_ALGORITHM = 9
    UNSUPPORTED_DIFFIE_HELLMAN = 10
    UNSUPPORTED_MAC = 11


class UnsupportedAlgorithm(Exception):
    def __init__(
        self, message: str, reason: typing.Optional[_Reasons] = None
    ) -> None:
        super(UnsupportedAlgorithm, self).__init__(message)
        self._reason = reason


class AlreadyFinalized(Exception):
    pass


class AlreadyUpdated(Exception):
    pass


class NotYetFinalized(Exception):
    pass


class InvalidTag(Exception):
    pass


class InvalidSignature(Exception):
    pass


class InternalError(Exception):
    def __init__(
        self, msg: str, err_code: typing.List["_OpenSSLErrorWithText"]
    ) -> None:
        super(InternalError, self).__init__(msg)
        self.err_code = err_code


class InvalidKey(Exception):
    pass
