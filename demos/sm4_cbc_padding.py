# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import binascii
import os

from tongsuopy.crypto.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
iv = os.urandom(16)
plaintext = "hello"

cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), padding=True)

enc = cipher.encryptor()
ciphertext = enc.update(plaintext.encode()) + enc.finalize()

print(
    f"SM4-CBC\nkey={binascii.hexlify(key).decode()}\niv={binascii.hexlify(iv).decode()}\nplaintext={plaintext}\nciphertext={binascii.hexlify(ciphertext).decode()}"
)
