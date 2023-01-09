# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

from tongsuopy.crypto import hashes
from tongsuopy.crypto.asymciphers import ec
from tongsuopy.crypto.asymciphers.utils import encode_dss_signature


msg = b"message digest"
Qx = b"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
Qy = b"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
R = b"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"
S = b"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"

signature = encode_dss_signature(int(R, 16), int(S, 16))

pubkey = ec.EllipticCurvePublicNumbers(
    int(Qx, 16), int(Qy, 16), ec.SM2()
).public_key()
pubkey.verify(signature, msg, ec.ECDSA(hashes.SM3()))
