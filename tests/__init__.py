# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import os
import typing


def open_vector_file(filename: str, mode: str) -> typing.IO:
    base = os.path.dirname(__file__)
    return open(os.path.join(base, "vectors", filename), mode)
