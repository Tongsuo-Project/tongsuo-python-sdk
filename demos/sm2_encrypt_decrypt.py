# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

from tongsuopy.crypto import hashes
from tongsuopy.crypto.asymciphers import ec

msg = "message digest"
d = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
Qx = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
Qy = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"

key = ec.EllipticCurvePrivateNumbers(
    int(d, 16),
    ec.EllipticCurvePublicNumbers(int(Qx, 16), int(Qy, 16), ec.SM2()),
).private_key()
signature = key.sign(msg.encode(), ec.ECDSA(hashes.SM3()))

pubkey = key.public_key()
ciphertext = pubkey.encrypt(msg.encode())
decrypt_text = key.decrypt(ciphertext)
assert decrypt_text == msg.encode()
