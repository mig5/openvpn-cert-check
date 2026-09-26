import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "openvpn-cert-check"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def mod():
    """Load the script as an importable module."""
    loader = SourceFileLoader("cert_check", str(SCRIPT))
    spec = importlib.util.spec_from_loader("cert_check", loader)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cert_check"] = m
    loader.exec_module(m)
    return m


@pytest.fixture
def fx():
    """Return the fixtures directory path."""
    return FIXTURES
