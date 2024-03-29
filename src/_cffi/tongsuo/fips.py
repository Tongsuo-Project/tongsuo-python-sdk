# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
static const long Cryptography_HAS_FIPS;
"""

FUNCTIONS = """
int FIPS_mode_set(int);
int FIPS_mode(void);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
static const long Cryptography_HAS_FIPS = 0;
int (*FIPS_mode_set)(int) = NULL;
int (*FIPS_mode)(void) = NULL;
#else
static const long Cryptography_HAS_FIPS = 1;
#endif
"""
