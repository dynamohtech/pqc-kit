"""Checks against real post-quantum certificates from other implementations.

These run in the "Live data" GitHub Actions workflow, which clones the IETF
Hackathon pqc-certificates repository (https://github.com/IETF-Hackathon/pqc-certificates)
and sets PQC_KIT_LIVE=1 and PQC_KIT_HACKATHON_DIR. They are skipped elsewhere.
"""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path

import pytest

from pqc_kit.detectors.material import scan_der
from pqc_kit.model import CERTIFICATE, SAFE
from pqc_kit.scan import finalize

LIVE = os.environ.get("PQC_KIT_LIVE") == "1"
HACKATHON = Path(os.environ.get("PQC_KIT_HACKATHON_DIR", "pqc-certificates"))

pytestmark = pytest.mark.skipif(not LIVE, reason="set PQC_KIT_LIVE=1 to run the live checks")

# NIST-registered OIDs for the standardised algorithms (FIPS 203, 204, 205).
STANDARD = {
    **{f"2.16.840.1.101.3.4.4.{i}": "ML-KEM" for i in (1, 2, 3)},
    **{f"2.16.840.1.101.3.4.3.{i}": "ML-DSA" for i in (17, 18, 19)},
    **{f"2.16.840.1.101.3.4.3.{i}": "SLH-DSA" for i in range(20, 32)},
}
CERT_FILE = re.compile(r"_(ta|ca|ee)\.der$")
OID_IN_NAME = re.compile(r"-((?:\d+\.)+\d+)_(?:ta|ca|ee)\.der$")


def _certificates():
    zips = sorted(HACKATHON.glob("providers/*/artifacts_certs_r5.zip"))
    assert zips, f"no artifacts_certs_r5.zip files under {HACKATHON}/providers"
    for z in zips:
        with zipfile.ZipFile(z) as zf:
            for name in zf.namelist():
                if CERT_FILE.search(name):
                    yield z.parent.name, name, zf.read(name)


def test_every_hackathon_certificate_parses_and_standard_algorithms_are_recognised():
    parsed, standard, problems = 0, 0, []
    providers = set()
    for provider, name, data in _certificates():
        providers.add(provider)
        found, errors = scan_der(name, data, False)
        finalize(found)
        certs = [f for f in found if f.asset == CERTIFICATE]
        if not certs:
            problems.append(f"{provider}/{name}: not parsed ({'; '.join(errors)})")
            continue
        parsed += 1
        m = OID_IN_NAME.search(name)
        expected = STANDARD.get(m.group(1)) if m else None
        if expected:
            standard += 1
            cert = certs[0]
            if cert.family != expected or cert.status != SAFE:
                problems.append(f"{provider}/{name}: read as {cert.name} ({cert.status}), expected {expected}")
    print(f"{parsed} certificates from {len(providers)} providers; {standard} use a standardised algorithm")
    assert parsed > 100 and standard > 50
    assert not problems, "\n".join(problems[:50])
