# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

from tongsuopy.crypto import utils
from tongsuopy.crypto.cipheralgorithm import (
    BlockCipherAlgorithm,
    CipherAlgorithm,
)


def _verify_key_size(algorithm: CipherAlgorithm, key: bytes) -> bytes:
    # Verify that the key is instance of bytes
    utils._check_byteslike("key", key)

    # Verify that the key size matches the expected key size
    if len(key) * 8 not in algorithm.key_sizes:
        raise ValueError(
            "Invalid key size ({}) for {}.".format(
                len(key) * 8, algorithm.name
            )
        )
    return key


class SM4(CipherAlgorithm, BlockCipherAlgorithm):
    name = "SM4"
    block_size = 128
    key_sizes = frozenset([128])
    key_size = 128

    def __init__(self, key: bytes):
        self.key = _verify_key_size(self, key)
