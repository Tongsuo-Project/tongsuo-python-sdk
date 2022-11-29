# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import binascii
import os

import pytest

from tongsuopy.crypto import hashes
from tongsuopy.crypto.ciphers import Cipher
from tongsuopy.crypto.ciphers.modes import GCM
from tongsuopy.crypto.exceptions import InvalidTag

from ..utils import load_vectors_from_file


def _load_all_params(path, file_names, param_loader):
    all_params = []
    for file_name in file_names:
        all_params.extend(
            load_vectors_from_file(os.path.join(path, file_name), param_loader)
        )
    return all_params


def generate_encrypt_test(
    param_loader, path, file_names, cipher_factory, mode_factory
):
    def test_encryption(self, backend, subtests):
        for params in _load_all_params(path, file_names, param_loader):
            with subtests.test():
                encrypt_test(backend, cipher_factory, mode_factory, params)

    return test_encryption


def encrypt_test(backend, cipher_factory, mode_factory, params):
    assert backend.cipher_supported(
        cipher_factory(**params), mode_factory(**params)
    )

    plaintext = params["plaintext"]
    ciphertext = params["ciphertext"]
    cipher = Cipher(
        cipher_factory(**params), mode_factory(**params), backend=backend
    )
    encryptor = cipher.encryptor()
    actual_ciphertext = encryptor.update(binascii.unhexlify(plaintext))
    actual_ciphertext += encryptor.finalize()
    assert actual_ciphertext == binascii.unhexlify(ciphertext)
    decryptor = cipher.decryptor()
    actual_plaintext = decryptor.update(binascii.unhexlify(ciphertext))
    actual_plaintext += decryptor.finalize()
    assert actual_plaintext == binascii.unhexlify(plaintext)


def generate_aead_test(
    param_loader, path, file_names, cipher_factory, mode_factory
):
    assert mode_factory is GCM

    def test_aead(self, backend, subtests):
        all_params = _load_all_params(path, file_names, param_loader)
        # We don't support IVs < 64-bit in GCM mode so just strip them out
        all_params = [i for i in all_params if len(i["iv"]) >= 16]
        for params in all_params:
            with subtests.test():
                aead_test(backend, cipher_factory, mode_factory, params)

    return test_aead


def aead_test(backend, cipher_factory, mode_factory, params):
    mode = mode_factory(
        binascii.unhexlify(params["iv"]),
        binascii.unhexlify(params["tag"]),
        len(binascii.unhexlify(params["tag"])),
    )
    assert isinstance(mode, GCM)
    if params.get("pt") is not None:
        plaintext = binascii.unhexlify(params["pt"])
    ciphertext = binascii.unhexlify(params["ct"])
    aad = binascii.unhexlify(params["aad"])
    if params.get("fail") is True:
        cipher = Cipher(
            cipher_factory(binascii.unhexlify(params["key"])),
            mode,
            backend,
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        actual_plaintext = decryptor.update(ciphertext)
        with pytest.raises(InvalidTag):
            decryptor.finalize()
    else:
        cipher = Cipher(
            cipher_factory(binascii.unhexlify(params["key"])),
            mode_factory(binascii.unhexlify(params["iv"]), None),
            backend,
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        actual_ciphertext = encryptor.update(plaintext)
        actual_ciphertext += encryptor.finalize()
        tag_len = len(binascii.unhexlify(params["tag"]))
        assert (
            binascii.hexlify(encryptor.tag[:tag_len]).upper()
            == params["tag"].upper()
        )
        cipher = Cipher(
            cipher_factory(binascii.unhexlify(params["key"])),
            mode_factory(
                binascii.unhexlify(params["iv"]),
                binascii.unhexlify(params["tag"]),
                min_tag_length=tag_len,
            ),
            backend,
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        actual_plaintext = decryptor.update(ciphertext)
        actual_plaintext += decryptor.finalize()
        assert actual_plaintext == plaintext


def generate_hash_test(param_loader, path, file_names, hash_cls):
    def test_hash(self, backend, subtests):
        for params in _load_all_params(path, file_names, param_loader):
            with subtests.test():
                hash_test(backend, hash_cls, params)

    return test_hash


def hash_test(backend, algorithm, params):
    msg, md = params
    m = hashes.Hash(algorithm, backend=backend)
    m.update(binascii.unhexlify(msg))
    expected_md = md.replace(" ", "").lower().encode("ascii")
    assert m.finalize() == binascii.unhexlify(expected_md)


def generate_base_hash_test(algorithm, digest_size):
    def test_base_hash(self, backend):
        base_hash_test(backend, algorithm, digest_size)

    return test_base_hash


def base_hash_test(backend, algorithm, digest_size):
    m = hashes.Hash(algorithm, backend=backend)
    assert m.algorithm.digest_size == digest_size
    m_copy = m.copy()
    assert m != m_copy
    assert m._ctx != m_copy._ctx

    m.update(b"abc")
    copy = m.copy()
    copy.update(b"123")
    m.update(b"123")
    assert copy.finalize() == m.finalize()
