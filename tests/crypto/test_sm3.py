# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import os

import pytest

from tongsuopy.crypto import hashes
from tongsuopy.crypto.exceptions import AlreadyFinalized, _Reasons

from ..doubles import DummyHashAlgorithm
from ..utils import load_hash_vectors, raises_unsupported_algorithm
from .utils import generate_base_hash_test, generate_hash_test


class TestHashContext:
    def test_hash_reject_unicode(self, backend):
        m = hashes.Hash(hashes.SM3(), backend=backend)
        with pytest.raises(TypeError):
            m.update("\u00fc")  # type: ignore[arg-type]

    def test_hash_algorithm_instance(self, backend):
        with pytest.raises(TypeError):
            hashes.Hash(hashes.SM3, backend=backend)  # type: ignore[arg-type]

    def test_raises_after_finalize(self, backend):
        h = hashes.Hash(hashes.SM3(), backend=backend)
        h.finalize()

        with pytest.raises(AlreadyFinalized):
            h.update(b"foo")

        with pytest.raises(AlreadyFinalized):
            h.copy()

        with pytest.raises(AlreadyFinalized):
            h.finalize()

    def test_unsupported_hash(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hashes.Hash(DummyHashAlgorithm(), backend)


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SM3()),
    skip_message="Does not support SM3",
)
class TestSM3:
    test_sm3 = generate_base_hash_test(
        hashes.SM3(),
        digest_size=32,
    )

    test_sm3_vectors = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "SM3"),
        ["oscca.txt", "draft-shen-sm2-ecdsa-02.txt"],
        hashes.SM3(),
    )
