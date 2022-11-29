# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#include <openssl/opensslv.h>
"""

TYPES = """
/* Note that these will be resolved when cryptography is compiled and are NOT
   guaranteed to be the version that it actually loads. */
static const int OPENSSL_VERSION_NUMBER;
static const char *const OPENSSL_VERSION_TEXT;
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
