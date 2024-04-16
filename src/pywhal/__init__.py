"""
Copyright (c) 2024 Shai List. All rights reserved.

pywhal: Python Windows HAcking Library
"""

from ._version import version as __version__
from ._core import add, subtract

__all__ = ["__version__", "add", "subtract"]
