# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import binascii

from tongsuopy.crypto import hashes

data = b"abc"
expected = b"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

h = hashes.Hash(hashes.SM3())
h.update(data)
res = h.finalize()

assert (binascii.hexlify(res) == expected)

print("SM3({})={}".format(data.decode("utf8"), binascii.hexlify(res).decode("utf-8")))
