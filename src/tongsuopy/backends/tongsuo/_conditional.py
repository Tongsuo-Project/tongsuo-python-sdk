# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import typing


def cryptography_has_ssl_st() -> typing.List[str]:
    return [
        "SSL_ST_BEFORE",
        "SSL_ST_OK",
        "SSL_ST_INIT",
        "SSL_ST_RENEGOTIATE",
    ]


def cryptography_has_providers() -> typing.List[str]:
    return [
        "OSSL_PROVIDER_load",
        "OSSL_PROVIDER_unload",
        "ERR_LIB_PROV",
        "PROV_R_WRONG_FINAL_BLOCK_LENGTH",
        "PROV_R_BAD_DECRYPT",
    ]


def cryptography_has_300_fips() -> typing.List[str]:
    return [
        "EVP_default_properties_is_fips_enabled",
        "EVP_default_properties_enable_fips",
    ]


def cryptography_has_300_evp_cipher() -> typing.List[str]:
    return ["EVP_CIPHER_fetch", "EVP_CIPHER_free"]


def cryptography_has_unexpected_eof_while_reading() -> typing.List[str]:
    return ["SSL_R_UNEXPECTED_EOF_WHILE_READING"]


def cryptography_has_ssl_op_ignore_unexpected_eof() -> typing.List[str]:
    return [
        "SSL_OP_IGNORE_UNEXPECTED_EOF",
    ]


# This is a mapping of
# {condition: function-returning-names-dependent-on-that-condition} so we can
# loop over them and delete unsupported names at runtime. It will be removed
# when tongsuo supports #if in cdef. We use functions instead of just a dict of
# lists so we can use coverage to measure which are used.
CONDITIONAL_NAMES = {
    "Cryptography_HAS_SSL_ST": cryptography_has_ssl_st,
    "Cryptography_HAS_PROVIDERS": cryptography_has_providers,
    "Cryptography_HAS_300_FIPS": cryptography_has_300_fips,
    "Cryptography_HAS_300_EVP_CIPHER": cryptography_has_300_evp_cipher,
    "Cryptography_HAS_UNEXPECTED_EOF_WHILE_READING": (
        cryptography_has_unexpected_eof_while_reading
    ),
    "Cryptography_HAS_SSL_OP_IGNORE_UNEXPECTED_EOF": (
        cryptography_has_ssl_op_ignore_unexpected_eof
    ),
}
