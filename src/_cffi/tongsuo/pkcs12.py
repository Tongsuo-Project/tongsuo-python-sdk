# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#include <openssl/pkcs12.h>
"""

TYPES = """
static const long Cryptography_HAS_PKCS12_SET_MAC;

typedef ... PKCS12;
"""

FUNCTIONS = """
void PKCS12_free(PKCS12 *);

PKCS12 *d2i_PKCS12_bio(BIO *, PKCS12 **);
int i2d_PKCS12_bio(BIO *, PKCS12 *);
int PKCS12_parse(PKCS12 *, const char *, EVP_PKEY **, X509 **,
                 Cryptography_STACK_OF_X509 **);
PKCS12 *PKCS12_create(char *, char *, EVP_PKEY *, X509 *,
                      Cryptography_STACK_OF_X509 *, int, int, int, int, int);
int PKCS12_set_mac(PKCS12 *, const char *, int, unsigned char *, int, int,
                   const EVP_MD *);
"""

CUSTOMIZATIONS = """
static const long Cryptography_HAS_PKCS12_SET_MAC = 1;
"""
