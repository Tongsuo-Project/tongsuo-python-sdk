# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
/* define our OpenSSL API compatibility level to 1.1.0. Any symbols older than
   that will raise an error during compilation. */
#define OPENSSL_API_COMPAT 0x10100000L

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Wincrypt.h>
#include <Winsock2.h>
/*
    undef some macros that are defined by wincrypt.h but are also types in
    boringssl. openssl has worked around this but boring has not yet. see:
    https://chromium.googlesource.com/chromium/src/+/refs/heads/main/base
    /win/wincrypt_shim.h
*/
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_SIGNER_INFO
#endif

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000
    #error "tongsuopy MUST be linked with Tongsuo(Openssl 1.1.1) or later"
#endif

#define CRYPTOGRAPHY_OPENSSL_111D_OR_GREATER \
    OPENSSL_VERSION_NUMBER >= 0x10101040
#define CRYPTOGRAPHY_OPENSSL_300_OR_GREATER \
    OPENSSL_VERSION_NUMBER >= 0x30000000

#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_111B OPENSSL_VERSION_NUMBER < 0x10101020
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_111D OPENSSL_VERSION_NUMBER < 0x10101040
#define CRYPTOGRAPHY_OPENSSL_LESS_THAN_111E OPENSSL_VERSION_NUMBER < 0x10101050
#if (CRYPTOGRAPHY_OPENSSL_LESS_THAN_111D && !defined(OPENSSL_NO_ENGINE)) \
    || defined(USE_OSRANDOM_RNG_FOR_TESTING)
#define CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE 1
#else
#define CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE 0
#endif
/* Ed25519 support is available from OpenSSL 1.1.1b. */
#define CRYPTOGRAPHY_HAS_WORKING_ED25519 !CRYPTOGRAPHY_OPENSSL_LESS_THAN_111B
"""

TYPES = """
static const int CRYPTOGRAPHY_OPENSSL_111D_OR_GREATER;
static const int CRYPTOGRAPHY_OPENSSL_300_OR_GREATER;

static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_111B;
static const int CRYPTOGRAPHY_OPENSSL_LESS_THAN_111E;
static const int CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE;
static const int CRYPTOGRAPHY_HAS_WORKING_ED25519;
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
