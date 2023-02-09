# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import typing

from tongsuopy.crypto.asymciphers import ec

# Every asymmetric key type
PUBLIC_KEY_TYPES = typing.Union[ec.EllipticCurvePublicKey,]
# Every asymmetric key type
PRIVATE_KEY_TYPES = typing.Union[ec.EllipticCurvePrivateKey,]
# Just the key types we allow to be used for x509 signing. This mirrors
# the certificate public key types
CERTIFICATE_PRIVATE_KEY_TYPES = typing.Union[ec.EllipticCurvePrivateKey,]
# Just the key types we allow to be used for x509 signing. This mirrors
# the certificate private key types
CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES = typing.Union[ec.EllipticCurvePublicKey,]
# This type removes DHPublicKey. x448/x25519 can be a public key
# but cannot be used in signing so they are allowed here.
CERTIFICATE_PUBLIC_KEY_TYPES = typing.Union[ec.EllipticCurvePublicKey,]
