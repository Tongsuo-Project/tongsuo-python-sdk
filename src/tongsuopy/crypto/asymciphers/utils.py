# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


from tongsuopy.crypto import hashes


def encode_dss_signature(r: int, s: int) -> bytes:
    from tongsuopy.backends.tongsuo import backend as ossl

    return ossl.new_ecdsa_sig(r, s)


class Prehashed:
    def __init__(self, algorithm: hashes.HashAlgorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError("Expected instance of HashAlgorithm.")

        self._algorithm = algorithm
        self._digest_size = algorithm.digest_size

    @property
    def digest_size(self) -> int:
        return self._digest_size
