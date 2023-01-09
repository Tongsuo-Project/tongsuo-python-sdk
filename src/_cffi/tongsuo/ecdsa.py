# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#include <openssl/ecdsa.h>
"""

TYPES = """
typedef ... ECDSA_SIG;
"""

FUNCTIONS = """
int ECDSA_sign(int, const unsigned char *, int, unsigned char *,
               unsigned int *, EC_KEY *);
int ECDSA_verify(int, const unsigned char *, int, const unsigned char *, int,
                 EC_KEY *);
int ECDSA_size(const EC_KEY *);
ECDSA_SIG *ECDSA_SIG_new(void);
void ECDSA_SIG_free(ECDSA_SIG *sig);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);
"""

CUSTOMIZATIONS = """
"""
