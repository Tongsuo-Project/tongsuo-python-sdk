# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import os
import sys
from distutils.ccompiler import new_compiler
from distutils.dist import Distribution

from cffi import FFI

# Load the tongsuopy/__about__ to get the current package version
base_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
about = {}
with open(os.path.join(base_src, "tongsuopy", "__about__.py")) as f:
    exec(f.read(), about)


def build_ffi_for_binding(
    module_name,
    module_prefix,
    modules,
    libraries,
    extra_compile_args,
    **kwargs,
):
    """
    Modules listed in ``modules`` should have the following attributes:

    * ``INCLUDES``: A string containing C includes.
    * ``TYPES``: A string containing C declarations for types.
    * ``FUNCTIONS``: A string containing C declarations for functions & macros.
    * ``CUSTOMIZATIONS``: A string containing arbitrary top-level C code, this
        can be used to do things like test for a define and provide an
        alternate implementation based on that.
    """
    types = []
    includes = []
    functions = []
    customizations = []
    for name in modules:
        __import__(module_prefix + name)
        module = sys.modules[module_prefix + name]

        types.append(module.TYPES)
        functions.append(module.FUNCTIONS)
        includes.append(module.INCLUDES)
        customizations.append(module.CUSTOMIZATIONS)

    verify_source = "\n".join(includes + customizations)
    return build_ffi(
        module_name,
        cdef_source="\n".join(types + functions),
        verify_source=verify_source,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        **kwargs,
    )


def build_ffi(
    module_name,
    cdef_source,
    verify_source,
    libraries,
    extra_compile_args,
    **kwargs,
):
    ffi = FFI()
    # Always add the CRYPTOGRAPHY_PACKAGE_VERSION to the shared object
    cdef_source += "\nstatic const char *const CRYPTOGRAPHY_PACKAGE_VERSION;"
    verify_source += '\n#define CRYPTOGRAPHY_PACKAGE_VERSION "{}"'.format(
        about["__version__"]
    )
    ffi.cdef(cdef_source)

    ffi.set_source(
        module_name,
        verify_source,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        **kwargs,
    )
    return ffi


def compiler_type():
    """
    Gets the compiler type from distutils. On Windows with MSVC it will be
    "msvc". On macOS and linux it is "unix".
    """
    dist = Distribution()
    dist.parse_config_files()
    cmd = dist.get_command_obj("build")
    cmd.ensure_finalized()
    compiler = new_compiler(compiler=cmd.compiler)
    return compiler.compiler_type
