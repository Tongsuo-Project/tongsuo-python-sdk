# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

from tongsuopy.crypto import hashes

class HMAC:
    def __init__(self, key: bytes, algorithm: hashes.HashAlgorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError("Expected instance of hashes.HashAlgorithm.")
        self.algorithm = algorithm
        block_size = self.algorithm.block_size
        if len(key) > block_size:
            # 如果key长度大于块大小，则用相应散列算法散列key
            hash_ctx = hashes.Hash(self.algorithm)
            hash_ctx.update(key)
            key = hash_ctx.finalize()
        # 如果key短于块大小，用0x00填充到块大小
        self.key = key.ljust(block_size, b'\x00')
        # 创建内部和外部pad
        self.o_key_pad = bytes((x ^ 0x5c) for x in self.key)
        self.i_key_pad = bytes((x ^ 0x36) for x in self.key)

    def calculate(self, message: bytes) -> bytes:
        # 对内部消息进行散列
        inner_hash = hashes.Hash(self.algorithm)
        inner_hash.update(self.i_key_pad + message)
        inner_digest = inner_hash.finalize()
        
        # 对外部消息进行散列
        outer_hash = hashes.Hash(self.algorithm)
        outer_hash.update(self.o_key_pad + inner_digest)
        return outer_hash.finalize()

def hmac_sm3(key: bytes, message: bytes) -> bytes:
    return HMAC(key, hashes.SM3()).calculate(message)
