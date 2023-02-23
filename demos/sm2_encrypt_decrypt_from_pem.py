# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

from tongsuopy.crypto import serialization
from tongsuopy.crypto.asymciphers import ec

msg = b"hello"
key = ec.generate_private_key(ec.SM2())

pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
pubkey = serialization.load_pem_public_key(pem)

ciphertext = pubkey.encrypt(msg)
decrypt_text = key.decrypt(ciphertext)
assert decrypt_text == msg
