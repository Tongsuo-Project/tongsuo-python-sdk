# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import typing

from tongsuopy.crypto.exceptions import InvalidTag


if typing.TYPE_CHECKING:
    from tongsuopy.backends.tongsuo.backend import Backend
    from tongsuopy.crypto.ciphers.aead import (
        SM4GCM,
        SM4CCM,
    )

    _AEAD_TYPES = typing.Union[
        SM4GCM,
        SM4CCM,
    ]

_ENCRYPT = 1
_DECRYPT = 0


def _aead_cipher_name(cipher: "_AEAD_TYPES") -> bytes:
    from tongsuopy.crypto.ciphers.aead import (
        SM4CCM,
        SM4GCM,
    )

    if isinstance(cipher, SM4CCM):
        return b"sm4-ccm"
    else:
        assert isinstance(cipher, SM4GCM)
        return b"sm4-gcm"


def _evp_cipher(cipher_name: bytes, backend: "Backend"):
    evp_cipher = backend._lib.EVP_get_cipherbyname(cipher_name)
    backend.openssl_assert(evp_cipher != backend._ffi.NULL)

    return evp_cipher


def _aead_setup(
    backend: "Backend",
    cipher_name: bytes,
    key: bytes,
    nonce: bytes,
    tag: typing.Optional[bytes],
    tag_len: int,
    operation: int,
):
    evp_cipher = _evp_cipher(cipher_name, backend)
    ctx = backend._lib.EVP_CIPHER_CTX_new()
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_CIPHER_CTX_free)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        evp_cipher,
        backend._ffi.NULL,
        backend._ffi.NULL,
        backend._ffi.NULL,
        int(operation == _ENCRYPT),
    )
    backend.openssl_assert(res != 0)
    # CCM requires the IVLEN to be set before calling SET_TAG on decrypt
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx,
        backend._lib.EVP_CTRL_AEAD_SET_IVLEN,
        len(nonce),
        backend._ffi.NULL,
    )
    backend.openssl_assert(res != 0)
    if operation == _DECRYPT:
        assert tag is not None
        _set_tag(backend, ctx, tag)
    elif cipher_name.endswith(b"-ccm"):
        res = backend._lib.EVP_CIPHER_CTX_ctrl(
            ctx, backend._lib.EVP_CTRL_AEAD_SET_TAG, tag_len, backend._ffi.NULL
        )
        backend.openssl_assert(res != 0)

    nonce_ptr = backend._ffi.from_buffer(nonce)
    key_ptr = backend._ffi.from_buffer(key)
    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        backend._ffi.NULL,
        backend._ffi.NULL,
        key_ptr,
        nonce_ptr,
        int(operation == _ENCRYPT),
    )
    backend.openssl_assert(res != 0)
    return ctx


def _set_tag(backend, ctx, tag: bytes) -> None:
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx, backend._lib.EVP_CTRL_AEAD_SET_TAG, len(tag), tag
    )
    backend.openssl_assert(res != 0)


def _set_length(backend: "Backend", ctx, data_len: int) -> None:
    intptr = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx, backend._ffi.NULL, intptr, backend._ffi.NULL, data_len
    )
    backend.openssl_assert(res != 0)


def _process_aad(backend: "Backend", ctx, associated_data: bytes) -> None:
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx, backend._ffi.NULL, outlen, associated_data, len(associated_data)
    )
    backend.openssl_assert(res != 0)


def _process_data(backend: "Backend", ctx, data: bytes) -> bytes:
    outlen = backend._ffi.new("int *")
    buf = backend._ffi.new("unsigned char[]", len(data))
    res = backend._lib.EVP_CipherUpdate(ctx, buf, outlen, data, len(data))
    if res == 0:
        # AES SIV can error here if the data is invalid on decrypt
        backend._consume_errors()
        raise InvalidTag
    return backend._ffi.buffer(buf, outlen[0])[:]


def _encrypt(
    backend: "Backend",
    cipher: "_AEAD_TYPES",
    nonce: bytes,
    data: bytes,
    associated_data: typing.List[bytes],
    tag_length: int,
) -> bytes:
    from tongsuopy.crypto.ciphers.aead import SM4CCM

    cipher_name = _aead_cipher_name(cipher)
    ctx = _aead_setup(
        backend,
        cipher_name,
        cipher._key,
        nonce,
        None,
        tag_length,
        _ENCRYPT,
    )

    # CCM requires us to pass the length of the data before processing anything
    # However calling this with any other AEAD results in an error
    if isinstance(cipher, SM4CCM):
        _set_length(backend, ctx, len(data))

    for ad in associated_data:
        _process_aad(backend, ctx, ad)
    processed_data = _process_data(backend, ctx, data)
    outlen = backend._ffi.new("int *")
    # All AEADs we support besides OCB are streaming so they return nothing
    # in finalization. OCB can return up to (16 byte block - 1) bytes so
    # we need a buffer here too.
    buf = backend._ffi.new("unsigned char[]", 16)
    res = backend._lib.EVP_CipherFinal_ex(ctx, buf, outlen)
    backend.openssl_assert(res != 0)
    processed_data += backend._ffi.buffer(buf, outlen[0])[:]
    tag_buf = backend._ffi.new("unsigned char[]", tag_length)
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx, backend._lib.EVP_CTRL_AEAD_GET_TAG, tag_length, tag_buf
    )
    backend.openssl_assert(res != 0)
    tag = backend._ffi.buffer(tag_buf)[:]

    return processed_data + tag


def _decrypt(
    backend: "Backend",
    cipher: "_AEAD_TYPES",
    nonce: bytes,
    data: bytes,
    associated_data: typing.List[bytes],
    tag_length: int,
) -> bytes:
    from tongsuopy.crypto.ciphers.aead import SM4CCM

    if len(data) < tag_length:
        raise InvalidTag

    tag = data[-tag_length:]
    data = data[:-tag_length]
    cipher_name = _aead_cipher_name(cipher)
    ctx = _aead_setup(
        backend, cipher_name, cipher._key, nonce, tag, tag_length, _DECRYPT
    )

    # CCM requires us to pass the length of the data before processing anything
    # However calling this with any other AEAD results in an error
    if isinstance(cipher, SM4CCM):
        _set_length(backend, ctx, len(data))

    for ad in associated_data:
        _process_aad(backend, ctx, ad)
    # CCM has a different error path if the tag doesn't match. Errors are
    # raised in Update and Final is irrelevant.
    if isinstance(cipher, SM4CCM):
        outlen = backend._ffi.new("int *")
        buf = backend._ffi.new("unsigned char[]", len(data))
        res = backend._lib.EVP_CipherUpdate(ctx, buf, outlen, data, len(data))
        if res != 1:
            backend._consume_errors()
            raise InvalidTag

        processed_data = backend._ffi.buffer(buf, outlen[0])[:]
    else:
        processed_data = _process_data(backend, ctx, data)
        outlen = backend._ffi.new("int *")
        # OCB can return up to 15 bytes (16 byte block - 1) in finalization
        buf = backend._ffi.new("unsigned char[]", 16)
        res = backend._lib.EVP_CipherFinal_ex(ctx, buf, outlen)
        processed_data += backend._ffi.buffer(buf, outlen[0])[:]
        if res == 0:
            backend._consume_errors()
            raise InvalidTag

    return processed_data
