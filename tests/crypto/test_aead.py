# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import binascii
import os

import pytest

from tongsuopy.crypto.ciphers.aead import SM4CCM, SM4GCM
from tongsuopy.crypto.exceptions import InvalidTag

from .utils import _load_all_params
from ..utils import (
    load_nist_ccm_vectors,
    load_nist_vectors,
)


class FakeData(bytes):
    def __len__(self):
        return 2**31


def _load_sm4gcm_vectors():
    vectors = _load_all_params(
        os.path.join("ciphers", "SM4"),
        [
            "rfc8998-sm4-gcm.txt",
        ],
        load_nist_vectors,
    )
    return [x for x in vectors if len(x["tag"]) == 32 and len(x["iv"]) >= 16]


class TestSM4GCM:
    def test_data_too_large(self):
        key = SM4GCM.generate_key()
        sm4gcm = SM4GCM(key)
        nonce = b"0" * 12

        with pytest.raises(OverflowError):
            sm4gcm.encrypt(nonce, FakeData(), b"")

        with pytest.raises(OverflowError):
            sm4gcm.encrypt(nonce, b"", FakeData())

    def test_vectors(self, backend, subtests):
        vectors = _load_sm4gcm_vectors()
        for vector in vectors:
            with subtests.test():
                nonce = binascii.unhexlify(vector["iv"])

                key = binascii.unhexlify(vector["key"])
                aad = binascii.unhexlify(vector["aad"])
                ct = binascii.unhexlify(vector["ct"])
                pt = binascii.unhexlify(vector.get("pt", b""))
                tag = binascii.unhexlify(vector["tag"])
                sm4gcm = SM4GCM(key)
                if vector.get("fail") is True:
                    with pytest.raises(InvalidTag):
                        sm4gcm.decrypt(nonce, ct + tag, aad)
                else:
                    computed_ct = sm4gcm.encrypt(nonce, pt, aad)
                    assert computed_ct[:-16] == ct
                    assert computed_ct[-16:] == tag
                    computed_pt = sm4gcm.decrypt(nonce, ct + tag, aad)
                    assert computed_pt == pt

    @pytest.mark.parametrize(
        ("nonce", "data", "associated_data"),
        [
            [object(), b"data", b""],
            [b"0" * 12, object(), b""],
            [b"0" * 12, b"data", object()],
        ],
    )
    def test_params_not_bytes(self, nonce, data, associated_data, backend):
        key = SM4GCM.generate_key()
        sm4gcm = SM4GCM(key)
        with pytest.raises(TypeError):
            sm4gcm.encrypt(nonce, data, associated_data)

        with pytest.raises(TypeError):
            sm4gcm.decrypt(nonce, data, associated_data)

    @pytest.mark.parametrize("length", [7, 129])
    def test_invalid_nonce_length(self, length, backend):
        key = SM4GCM.generate_key()
        sm4gcm = SM4GCM(key)
        with pytest.raises(ValueError):
            sm4gcm.encrypt(b"\x00" * length, b"hi", None)

    def test_bad_key(self, backend):
        with pytest.raises(TypeError):
            SM4GCM(object())  # type:ignore[arg-type]

        with pytest.raises(ValueError):
            SM4GCM(b"0" * 31)

    def test_associated_data_none_equal_to_empty_bytestring(self, backend):
        key = SM4GCM.generate_key()
        sm4gcm = SM4GCM(key)
        nonce = os.urandom(12)
        ct1 = sm4gcm.encrypt(nonce, b"some_data", None)
        ct2 = sm4gcm.encrypt(nonce, b"some_data", b"")
        assert ct1 == ct2
        pt1 = sm4gcm.decrypt(nonce, ct1, None)
        pt2 = sm4gcm.decrypt(nonce, ct2, b"")
        assert pt1 == pt2

    def test_buffer_protocol(self, backend):
        key = SM4GCM.generate_key()
        sm4gcm = SM4GCM(key)
        pt = b"encrypt me"
        ad = b"additional"
        nonce = os.urandom(12)
        ct = sm4gcm.encrypt(nonce, pt, ad)
        computed_pt = sm4gcm.decrypt(nonce, ct, ad)
        assert computed_pt == pt
        aesgcm2 = SM4GCM(bytearray(key))
        ct2 = aesgcm2.encrypt(bytearray(nonce), pt, ad)
        assert ct2 == ct
        computed_pt2 = aesgcm2.decrypt(bytearray(nonce), ct2, ad)
        assert computed_pt2 == pt


class TestAESCCM:
    def test_data_too_large(self):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        nonce = b"0" * 12

        with pytest.raises(OverflowError):
            sm4ccm.encrypt(nonce, FakeData(), b"")

        with pytest.raises(OverflowError):
            sm4ccm.encrypt(nonce, b"", FakeData())

    def test_default_tag_length(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        nonce = os.urandom(12)
        pt = b"hello"
        ct = sm4ccm.encrypt(nonce, pt, None)
        assert len(ct) == len(pt) + 16

    def test_invalid_tag_length(self, backend):
        key = SM4CCM.generate_key()
        with pytest.raises(ValueError):
            SM4CCM(key, tag_length=7)

        with pytest.raises(ValueError):
            SM4CCM(key, tag_length=2)

        with pytest.raises(TypeError):
            SM4CCM(key, tag_length="notanint")  # type:ignore[arg-type]

    def test_invalid_nonce_length(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        pt = b"hello"
        nonce = os.urandom(14)
        with pytest.raises(ValueError):
            sm4ccm.encrypt(nonce, pt, None)

        with pytest.raises(ValueError):
            sm4ccm.encrypt(nonce[:6], pt, None)

    def test_vectors(self, subtests, backend):
        vectors = _load_all_params(
            os.path.join("ciphers", "SM4"),
            [
                "rfc8998-sm4-ccm.txt",
            ],
            load_nist_ccm_vectors,
        )
        for vector in vectors:
            with subtests.test():
                key = binascii.unhexlify(vector["key"])
                nonce = binascii.unhexlify(vector["nonce"])
                adata = binascii.unhexlify(vector["adata"])[: vector["alen"]]
                ct = binascii.unhexlify(vector["ct"])
                pt = binascii.unhexlify(vector["payload"])[: vector["plen"]]
                sm4ccm = SM4CCM(key, vector["tlen"])
                if vector.get("fail"):
                    with pytest.raises(InvalidTag):
                        sm4ccm.decrypt(nonce, ct, adata)
                else:
                    computed_pt = sm4ccm.decrypt(nonce, ct, adata)
                    assert computed_pt == pt
                    assert sm4ccm.encrypt(nonce, pt, adata) == ct

    def test_roundtrip(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        pt = b"encrypt me"
        ad = b"additional"
        nonce = os.urandom(12)
        ct = sm4ccm.encrypt(nonce, pt, ad)
        computed_pt = sm4ccm.decrypt(nonce, ct, ad)
        assert computed_pt == pt

    def test_nonce_too_long(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        pt = b"encrypt me" * 6600
        # pt can be no more than 65536 bytes when nonce is 13 bytes
        nonce = os.urandom(13)
        with pytest.raises(ValueError):
            sm4ccm.encrypt(nonce, pt, None)

    @pytest.mark.parametrize(
        ("nonce", "data", "associated_data"),
        [
            [object(), b"data", b""],
            [b"0" * 12, object(), b""],
            [b"0" * 12, b"data", object()],
        ],
    )
    def test_params_not_bytes(self, nonce, data, associated_data, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        with pytest.raises(TypeError):
            sm4ccm.encrypt(nonce, data, associated_data)

    def test_bad_key(self, backend):
        with pytest.raises(TypeError):
            SM4CCM(object())  # type:ignore[arg-type]

        with pytest.raises(ValueError):
            SM4CCM(b"0" * 31)

    def test_associated_data_none_equal_to_empty_bytestring(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        nonce = os.urandom(12)
        ct1 = sm4ccm.encrypt(nonce, b"some_data", None)
        ct2 = sm4ccm.encrypt(nonce, b"some_data", b"")
        assert ct1 == ct2
        pt1 = sm4ccm.decrypt(nonce, ct1, None)
        pt2 = sm4ccm.decrypt(nonce, ct2, b"")
        assert pt1 == pt2

    def test_decrypt_data_too_short(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        with pytest.raises(InvalidTag):
            sm4ccm.decrypt(b"0" * 12, b"0", None)

    def test_buffer_protocol(self, backend):
        key = SM4CCM.generate_key()
        sm4ccm = SM4CCM(key)
        pt = b"encrypt me"
        ad = b"additional"
        nonce = os.urandom(12)
        ct = sm4ccm.encrypt(nonce, pt, ad)
        computed_pt = sm4ccm.decrypt(nonce, ct, ad)
        assert computed_pt == pt
        sm4ccm2 = SM4CCM(bytearray(key))
        ct2 = sm4ccm2.encrypt(bytearray(nonce), pt, ad)
        assert ct2 == ct
        computed_pt2 = sm4ccm2.decrypt(bytearray(nonce), ct2, ad)
        assert computed_pt2 == pt
