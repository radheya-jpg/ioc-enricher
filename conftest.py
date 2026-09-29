# Ensures the project root is importable when running pytest from anywhere
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

# Must be set before any test module imports reliability.py / sources/*,
# since retry timing is read from config at decoration time.
os.environ["IOC_ENRICHER_FAST_RETRY"] = "1"

import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Keeps each test's rate-limit/circuit-breaker state independent."""
    from reliability import _reset_for_tests
    _reset_for_tests()
    yield


@pytest.fixture(autouse=True)
def _reset_allowlist():
    """Restores the real allowlist.txt before every test, so a test that
    disabled it (via monkeypatch) never leaks that state into the next
    test regardless of file/ordering. Individual tests can still override
    config.ALLOWLIST_PATH + call allowlist.reload() themselves."""
    import allowlist
    allowlist.reload()
    yield
