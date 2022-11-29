# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import binascii

from tongsuopy.crypto.ciphers import Cipher, algorithms, modes

key = b"0123456789ABCDEFFEDCBA9876543210"
iv = b"0123456789ABCDEFFEDCBA9876543210"
plaintext = b"0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210"
ciphertext = (
    b"2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B"
)

c = Cipher(
    algorithms.SM4(binascii.unhexlify(key)), modes.CBC(binascii.unhexlify(iv))
)

enc = c.encryptor()
actual_ciphertext = enc.update(binascii.unhexlify(plaintext))
actual_ciphertext += enc.finalize()

assert binascii.hexlify(actual_ciphertext).upper() == ciphertext

dec = c.decryptor()
actual_plaintext = dec.update(binascii.unhexlify(ciphertext))
actual_plaintext += dec.finalize()

assert binascii.hexlify(actual_plaintext).upper() == plaintext
