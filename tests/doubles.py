# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

from tongsuopy.crypto import hashes, serialization
from tongsuopy.crypto.ciphers import (
    CipherAlgorithm,
)


class DummyCipherAlgorithm(CipherAlgorithm):
    name = "dummy-cipher"
    block_size = 128
    key_size = 256
    key_sizes = frozenset([256])


class DummyHashAlgorithm(hashes.HashAlgorithm):
    name = "dummy-hash"
    block_size = None
    digest_size = 32


class DummyKeySerializationEncryption(
    serialization.KeySerializationEncryption
):
    pass
