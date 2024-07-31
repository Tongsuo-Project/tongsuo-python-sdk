# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import binascii

from tongsuopy.crypto.ciphers import Cipher, algorithms, modes

key = b"0123456789ABCDEFFEDCBA9876543210"
plaintext = b"0123456789ABCDEFFEDCBA9876543210"
ciphertext = b"681EDF34D206965E86B3E94F536E4246"

cipher = Cipher(
    algorithms.SM4(binascii.unhexlify(key)), modes.ECB()
)

enc = cipher.encryptor()
actual_ciphertext = enc.update(binascii.unhexlify(plaintext))
actual_ciphertext += enc.finalize()

assert binascii.hexlify(actual_ciphertext).upper() == ciphertext

print("SM4-ECB\nkey={}\nplaintext={}\nciphertext={}".format(key, plaintext, binascii.hexlify(actual_ciphertext)))

dec = cipher.decryptor()
actual_plaintext = dec.update(binascii.unhexlify(ciphertext))
actual_plaintext += dec.finalize()

assert binascii.hexlify(actual_plaintext).upper() == plaintext
