#!/usr/bin/env python

# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import os
import sys
import warnings

from setuptools import setup

# distutils emits this warning if you pass `setup()` an unknown option. This
# is what happens if you somehow run this file without `cffi` installed:
# `cffi_modules` is an unknown option.
warnings.filterwarnings("error", message="Unknown distribution option")

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

setup(cffi_modules=["src/_cffi/build_tongsuo.py:ffi"])
