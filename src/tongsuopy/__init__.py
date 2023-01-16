# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import sys
import warnings

from tongsuopy.__about__ import (
    __author__,
    __copyright__,
    __version__,
)
from tongsuopy.crypto.utils import CryptographyDeprecationWarning


__all__ = [
    "__version__",
    "__author__",
    "__copyright__",
]

if sys.version_info[:2] == (3, 6):
    warnings.warn(
        "Python 3.6 is no longer supported by the Python core team. "
        "Therefore, support for it is deprecated in tongsuopy. The next "
        "release of tongsuopy (2.0) will be the last to support Python "
        "3.6.",
        CryptographyDeprecationWarning,
        stacklevel=2,
    )
