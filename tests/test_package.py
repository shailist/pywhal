from __future__ import annotations

import importlib.metadata

import pywhal as m


def test_version():
    assert importlib.metadata.version("pywhal") == m.__version__
