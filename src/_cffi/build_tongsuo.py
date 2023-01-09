# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import os
import sys
from distutils import dist
from distutils.ccompiler import get_default_compiler
from distutils.command.config import config

from _cffi.utils import build_ffi_for_binding, compiler_type


def _get_openssl_libraries(platform):
    if os.environ.get("CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS", None):
        return []
    if platform == "win32" and compiler_type() == "msvc":
        return [
            "libssl",
            "libcrypto",
            "advapi32",
            "crypt32",
            "gdi32",
            "user32",
            "ws2_32",
        ]
    else:
        # statically link libssl.a and libcrypto.a
        # -lpthread required due to usage of pthread an potential
        # existance of a static part containing e.g. pthread_atfork
        # (https://github.com/pyca/cryptography/issues/5084)
        return ["pthread"]


def _extra_objects(platform):
    if platform == "win32" and compiler_type() == "msvc":
        return None

    lib_dir = _get_tongsuo_lib_dir(platform)
    if lib_dir is None:
        return None

    suffix = ".a"
    return [
        os.path.join(lib_dir, "libssl{}".format(suffix)),
        os.path.join(lib_dir, "libcrypto{}").format(suffix),
    ]


def _extra_compile_args(platform):
    """
    We set -Wconversion args here so that we only do Wconversion checks on the
    code we're compiling and not on cffi itself (as passing -Wconversion in
    CFLAGS would do). We set no error on sign conversion because some
    function signatures in LibreSSL differ from OpenSSL have changed on long
    vs. unsigned long in the past. Since that isn't a precision issue we don't
    care.
    """
    # make sure the compiler used supports the flags to be added
    is_gcc = False
    if get_default_compiler() == "unix":
        d = dist.Distribution()
        cmd = config(d)
        cmd._check_compiler()
        is_gcc = (
            "gcc" in cmd.compiler.compiler[0]
            or "clang" in cmd.compiler.compiler[0]
        )
    if is_gcc or not (
        platform in ["win32", "hp-ux11", "sunos5"]
        or platform.startswith("aix")
    ):
        return ["-Wconversion", "-Wno-error=sign-conversion"]
    else:
        return []


def _get_tongsuo_include_dir(platform):
    tongsuo_home = os.environ.get("TONGSUO_HOME", None)

    if tongsuo_home is None:
        return None
    else:
        return os.path.join(tongsuo_home, "include")


def _get_tongsuo_lib_dir(platform):
    tongsuo_home = os.environ.get("TONGSUO_HOME", None)

    if tongsuo_home is None:
        return None
    else:
        if os.path.exists(os.path.join(tongsuo_home, "lib64")):
            return os.path.join(tongsuo_home, "lib64")
        else:
            return os.path.join(tongsuo_home, "lib")


# Don't use runtime_library_dirs for MSVC, error:
# don't know how to set runtime library search path for MSVC
ffi = build_ffi_for_binding(
    module_name="tongsuopy.backends._tongsuo",
    module_prefix="_cffi.tongsuo.",
    modules=[
        # This goes first so we can define some cryptography-wide symbols.
        "cryptography",
        # Provider comes early as well so we define OSSL_LIB_CTX
        "provider",
        "asn1",
        "bignum",
        "bio",
        "cmac",
        "crypto",
        "dh",
        "dsa",
        "ec",
        "ecdsa",
        "engine",
        "err",
        "evp",
        "fips",
        "hmac",
        "nid",
        "objects",
        "opensslv",
        "pem",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
        "x509_vfy",
        "pkcs7",
        "callbacks",
    ],
    libraries=_get_openssl_libraries(sys.platform),
    extra_compile_args=_extra_compile_args(sys.platform),
    include_dirs=[_get_tongsuo_include_dir(sys.platform)],
    library_dirs=[_get_tongsuo_lib_dir(sys.platform)],
    runtime_library_dirs=None,
    extra_link_args=None,
    extra_objects=_extra_objects(sys.platform),
)

if __name__ == "__main__":
    ffi.compile(target="_tongsuo.so")
