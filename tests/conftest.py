"""Shared helpers. Every test runs offline; keys and certificates are generated
in memory or read from tests/fixtures (which holds certificates and public keys only)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqc_kit.detectors.golang import scan_go
from pqc_kit.detectors.java import scan_java
from pqc_kit.detectors.javascript import scan_javascript
from pqc_kit.detectors.material import scan_text_material
from pqc_kit.detectors.python import scan_python
from pqc_kit.scan import finalize

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "sample-app"


def detect(language: str, source: str, path: str = "src/app") -> list:
    """Run one detector on a snippet and classify the results."""
    if language == "python":
        found, err = scan_python(path + ".py", source, False)
        assert err is None, err
    elif language == "java":
        found = scan_java(path + ".java", source, False)
    elif language == "go":
        found = scan_go(path + ".go", source, False)
    elif language == "js":
        found = scan_javascript(path + ".ts", source, False)
    elif language == "pem":
        found, errs = scan_text_material(path + ".pem", source, False)
        assert not errs, errs
    else:
        raise ValueError(language)
    finalize(found)
    return sorted(found, key=lambda f: (f.line or 0, f.column or 0))


def names(findings) -> list[str]:
    return [f.name for f in findings]


def by_name(findings, name):
    matches = [f for f in findings if f.name == name]
    assert matches, f"{name!r} not in {names(findings)}"
    return matches[0]


@pytest.fixture
def sample_result():
    from pqc_kit.scan import scan_path

    return scan_path(SAMPLE)
