# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


import binascii
import collections
import re
import typing
from contextlib import contextmanager

import pytest

from tests import open_vector_file
from tongsuopy.crypto.exceptions import UnsupportedAlgorithm

HashVector = collections.namedtuple("HashVector", ["message", "digest"])
KeyedHashVector = collections.namedtuple(
    "KeyedHashVector", ["message", "digest", "key"]
)


def check_backend_support(backend, item):
    for mark in item.node.iter_markers("supported"):
        if not mark.kwargs["only_if"](backend):
            pytest.skip("{} ({})".format(mark.kwargs["skip_message"], backend))


@contextmanager
def raises_unsupported_algorithm(reason):
    with pytest.raises(UnsupportedAlgorithm) as exc_info:
        yield exc_info

    assert exc_info.value._reason is reason


T = typing.TypeVar("T")


def load_vectors_from_file(
    filename, loader: typing.Callable[..., T], mode="r"
) -> T:
    with open_vector_file(filename, mode) as vector_file:
        return loader(vector_file)


def load_nist_vectors(vector_data):
    test_data = {}
    data = []

    for line in vector_data:
        line = line.strip()

        # Blank lines, comments, and section headers are ignored
        if (
            not line
            or line.startswith("#")
            or (line.startswith("[") and line.endswith("]"))
        ):
            continue

        if line.strip().upper() == "FAIL":
            test_data["fail"] = True
            continue

        # Build our data using a simple Key = Value format
        name, value = (c.strip() for c in line.split("="))

        # Some tests (PBKDF2) contain \0, which should be interpreted as a
        # null character rather than literal.
        value = value.replace("\\0", "\0")

        # COUNT is a special token that indicates a new block of data
        if name.upper() == "COUNT":
            test_data = {}
            data.append(test_data)
            continue
        # For all other tokens we simply want the name, value stored in
        # the dictionary
        else:
            test_data[name.lower()] = value.encode("ascii")

    return data


def load_hash_vectors(vector_data):
    vectors: typing.List[typing.Union[KeyedHashVector, HashVector]] = []
    key = None
    msg = None
    md = None

    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#") or line.startswith("["):
            continue

        if line.startswith("Len"):
            length = int(line.split(" = ")[1])
        elif line.startswith("Key"):
            # HMAC vectors contain a key attribute. Hash vectors do not.
            key = line.split(" = ")[1].encode("ascii")
        elif line.startswith("Msg"):
            # In the NIST vectors they have chosen to represent an empty
            # string as hex 00, which is of course not actually an empty
            # string. So we parse the provided length and catch this edge case.
            msg = line.split(" = ")[1].encode("ascii") if length > 0 else b""
        elif line.startswith("MD") or line.startswith("Output"):
            md = line.split(" = ")[1]
            # after MD is found the Msg+MD (+ potential key) tuple is complete
            if key is not None:
                vectors.append(KeyedHashVector(msg, md, key))
                key = None
                msg = None
                md = None
            else:
                vectors.append(HashVector(msg, md))
                msg = None
                md = None
        else:
            raise ValueError("Unknown line in hash vector")
    return vectors


FIPS_SHA_REGEX = re.compile(
    r"\[mod = L=...., N=..., SHA-(?P<sha>1|224|256|384|512)\]"
)


# https://tools.ietf.org/html/rfc4492#appendix-A
_ECDSA_CURVE_NAMES = {
    "P-192": "secp192r1",
    "P-224": "secp224r1",
    "P-256": "secp256r1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
    "K-163": "sect163k1",
    "K-233": "sect233k1",
    "K-256": "secp256k1",
    "K-283": "sect283k1",
    "K-409": "sect409k1",
    "K-571": "sect571k1",
    "B-163": "sect163r2",
    "B-233": "sect233r1",
    "B-283": "sect283r1",
    "B-409": "sect409r1",
    "B-571": "sect571r1",
    "SM2": "SM2",
}


def load_fips_ecdsa_key_pair_vectors(vector_data):
    """
    Loads data out of the FIPS ECDSA KeyPair vector files.
    """
    vectors = []
    key_data = None
    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line[1:-1] in _ECDSA_CURVE_NAMES:
            curve_name = _ECDSA_CURVE_NAMES[line[1:-1]]

        elif line.startswith("d = "):
            if key_data is not None:
                vectors.append(key_data)

            key_data = {"curve": curve_name, "d": int(line.split("=")[1], 16)}

        elif key_data is not None:
            if line.startswith("Qx = "):
                key_data["x"] = int(line.split("=")[1], 16)
            elif line.startswith("Qy = "):
                key_data["y"] = int(line.split("=")[1], 16)

    assert key_data is not None
    vectors.append(key_data)

    return vectors


CURVE_REGEX = re.compile(r"\[(?P<curve>.*),(?P<hash>.*)\]")


def load_fips_ecdsa_signing_vectors(vector_data):
    """
    Loads data out of the FIPS ECDSA SigGen vector files.
    """
    vectors = []

    data: typing.Optional[typing.Dict[str, object]] = None
    for line in vector_data:
        line = line.strip()

        curve_match = CURVE_REGEX.match(line)
        if curve_match:
            curve_name = _ECDSA_CURVE_NAMES[curve_match.group("curve")]
            digest_name = "{}".format(curve_match.group("hash"))

        elif line.startswith("Msg = "):
            if data is not None:
                vectors.append(data)

            hexmsg = line.split("=")[1].strip().encode("ascii")

            data = {
                "curve": curve_name,
                "digest_algorithm": digest_name,
                "message": binascii.unhexlify(hexmsg),
            }

        elif data is not None:
            if line.startswith("Qx = "):
                data["x"] = int(line.split("=")[1], 16)
            elif line.startswith("Qy = "):
                data["y"] = int(line.split("=")[1], 16)
            elif line.startswith("R = "):
                data["r"] = int(line.split("=")[1], 16)
            elif line.startswith("S = "):
                data["s"] = int(line.split("=")[1], 16)
            elif line.startswith("d = "):
                data["d"] = int(line.split("=")[1], 16)
            elif line.startswith("Result = "):
                data["fail"] = line.split("=")[1].strip()[0] == "F"

    assert data is not None
    vectors.append(data)
    return vectors


KASVS_RESULT_REGEX = re.compile(r"([FP]) \(([0-9]+) -")


def load_nist_ccm_vectors(vector_data):
    test_data = {}
    section_data = None
    global_data = {}
    new_section = False
    data = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments should be ignored
        if not line or line.startswith("#"):
            continue

        # Some of the CCM vectors have global values for this. They are always
        # at the top before the first section header (see: VADT, VNT, VPT)
        if line.startswith(("Alen", "Plen", "Nlen", "Tlen")):
            name, value = (c.strip() for c in line.split("="))
            global_data[name.lower()] = int(value)
            continue

        # section headers contain length data we might care about
        if line.startswith("["):
            new_section = True
            section_data = {}
            section = line[1:-1]
            items = [c.strip() for c in section.split(",")]
            for item in items:
                name, value = (c.strip() for c in item.split("="))
                section_data[name.lower()] = int(value)
            continue

        name, value = (c.strip() for c in line.split("="))

        if name.lower() in ("key", "nonce") and new_section:
            section_data[name.lower()] = value.encode("ascii")
            continue

        new_section = False

        # Payload is sometimes special because these vectors are absurd. Each
        # example may or may not have a payload. If it does not then the
        # previous example's payload should be used. We accomplish this by
        # writing it into the section_data. Because we update each example
        # with the section data it will be overwritten if a new payload value
        # is present. NIST should be ashamed of their vector creation.
        if name.lower() == "payload":
            section_data[name.lower()] = value.encode("ascii")

        # Result is a special token telling us if the test should pass/fail.
        # This is only present in the DVPT CCM tests
        if name.lower() == "result":
            if value.lower() == "pass":
                test_data["fail"] = False
            else:
                test_data["fail"] = True
            continue

        # COUNT is a special token that indicates a new block of data
        if name.lower() == "count":
            test_data = {}
            test_data.update(global_data)
            test_data.update(section_data)
            data.append(test_data)
            continue
        # For all other tokens we simply want the name, value stored in
        # the dictionary
        else:
            test_data[name.lower()] = value.encode("ascii")

    return data


def load_decrypt_vectors(vector_data):
    data = []
    test_data = {}

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments should be ignored
        if not line or line.startswith("#"):
            continue

        name, value = (c.strip() for c in line.split("="))
        name = name.lower()

        if name in ["input"]:
            test_data[name] = binascii.unhexlify(value)
        elif name in ["output"]:
            # Remove quotes and convert to bytes.
            test_data[name] = value[1:-1].encode("ascii")
        else:
            test_data[name] = value

        # COUNT is a special token that indicates a new block of data
        if name.lower() == "count":
            test_data = {}
            data.append(test_data)
            continue

    return data
