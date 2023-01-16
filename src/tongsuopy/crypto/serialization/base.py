# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import typing

from tongsuopy.crypto.asymciphers.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)


def load_pem_private_key(
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Any = None,
    *,
    unsafe_skip_rsa_key_validation: bool = False,
) -> PRIVATE_KEY_TYPES:
    from tongsuopy.backends.tongsuo import backend as ossl

    return ossl.load_pem_private_key(
        data, password, unsafe_skip_rsa_key_validation
    )


def load_pem_public_key(
    data: bytes, backend: typing.Any = None
) -> PUBLIC_KEY_TYPES:
    from tongsuopy.backends.tongsuo import backend as ossl

    return ossl.load_pem_public_key(data)


def load_der_private_key(
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Any = None,
    *,
    unsafe_skip_rsa_key_validation: bool = False,
) -> PRIVATE_KEY_TYPES:
    from tongsuopy.backends.tongsuo import backend as ossl

    return ossl.load_der_private_key(
        data, password, unsafe_skip_rsa_key_validation
    )


def load_der_public_key(
    data: bytes, backend: typing.Any = None
) -> PUBLIC_KEY_TYPES:
    from tongsuopy.backends.tongsuo import backend as ossl

    return ossl.load_der_public_key(data)
