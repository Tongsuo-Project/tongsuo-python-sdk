# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import binascii

from tongsuopy.crypto.ciphers import Cipher, algorithms, modes

key = "0123456789ABCDEFFEDCBA9876543210"
iv = "00001234567800000000ABCD"
aad = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"
tag = "83DE3541E4C2B58177E065A9BF7B62EC"
plaintext = (
    "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"
    "DDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
    "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
)
ciphertext = (
    "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD37564890"
    "69157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC"
    "15A56834CBCF98C397B4024A2691233B8D"
)

print(
    f"SM4-GCM\nkey={key}\niv={iv}\naad={aad}\nplaintext={plaintext}\ntag={tag}\nciphertext={ciphertext}"
)

cipher = Cipher(
    algorithms.SM4(binascii.unhexlify(key)), modes.GCM(binascii.unhexlify(iv))
)

enc = cipher.encryptor()
enc.authenticate_additional_data(binascii.unhexlify(aad))
actual_ciphertext = enc.update(binascii.unhexlify(plaintext))
actual_ciphertext += enc.finalize()

assert binascii.hexlify(enc.tag).decode().upper() == tag
assert binascii.hexlify(actual_ciphertext).decode().upper() == ciphertext

cipher = Cipher(
    algorithms.SM4(binascii.unhexlify(key)),
    modes.GCM(binascii.unhexlify(iv), binascii.unhexlify(tag)),
)

dec = cipher.decryptor()
dec.authenticate_additional_data(binascii.unhexlify(aad))
actual_plaintext = dec.update(binascii.unhexlify(ciphertext))
actual_plaintext += dec.finalize()
assert binascii.hexlify(actual_plaintext).decode().upper() == plaintext
