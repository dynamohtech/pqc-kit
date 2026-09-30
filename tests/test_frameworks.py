"""Deadline mapping: which milestones cover which findings."""

from __future__ import annotations

from datetime import date

import pytest

from pqc_kit.catalog import classify
from pqc_kit.frameworks import BY_KEY, FRAMEWORKS, earliest_deadlines, selects
from pqc_kit.model import ALGORITHM, CERTIFICATE, PROTOCOL, Finding


def make(family: str, **kw) -> Finding:
    kw.setdefault("asset", ALGORITHM)
    f = Finding(family=family, path="src/x.py", **kw)
    classify(f)
    return f


def test_every_framework_is_sourced_and_dated():
    assert [f.key for f in FRAMEWORKS] == ["nist", "us", "cnsa2", "ncsc", "eu"]
    for fw in FRAMEWORKS:
        assert fw.sources and all(url.startswith("https://") for _, url in fw.sources)
        dates = [date.fromisoformat(m.date) for m in fw.milestones]
        assert dates == sorted(dates), fw.key
        for m in fw.milestones:
            assert m.selector in {"all", "vulnerable", "vulnerable-112", "vulnerable-kex", "vulnerable-sig",
                                  "tls-below-1.3", "sha1-224", "not-cnsa2", "weak"}


def test_rsa_2048_key_establishment_deadlines():
    rsa = make("RSA", key_size=2048, primitive="pke", padding="oaep", hash="SHA-256")
    assert rsa.role == "key-establishment" and rsa.classical_bits == 112
    d = {k: m.date for k, m in earliest_deadlines(rsa).items()}
    assert d == {"nist": "2030-12-31", "us": "2030-12-31", "cnsa2": "2026-12-31", "ncsc": "2031-12-31",
                 "eu": "2030-12-31"}


def test_ecdsa_p256_signature_gets_the_later_us_date():
    sig = make("ECDSA", curve="P-256", primitive="signature", hash="SHA-256")
    assert sig.role == "signature" and sig.classical_bits == 128
    d = {k: m.date for k, m in earliest_deadlines(sig).items()}
    assert d["us"] == "2031-12-31"
    assert d["nist"] == "2035-12-31"  # 128-bit strength: only the 2035 disallowance applies


def test_key_of_unknown_use_is_counted_under_the_earlier_us_date():
    key = make("RSA", key_size=3072)
    assert key.role == "other"
    assert selects("vulnerable-kex", key) and not selects("vulnerable-sig", key)


def test_certificates_fall_under_signatures():
    cert = make("RSA", asset=CERTIFICATE, key_size=2048, details={"signature": {"hash": "SHA-256"}})
    assert selects("vulnerable-sig", cert) and not selects("vulnerable-kex", cert)


@pytest.mark.parametrize("family,version,expected", [
    ("SSL", "3.0", True), ("TLS", "1.0", True), ("TLS", "1.2", True), ("TLS", "1.3", False),
    ("DTLS", "1.2", True), ("DTLS", "1.3", False), ("TLS", None, False),
])
def test_tls_below_13(family, version, expected):
    f = make(family, asset=PROTOCOL, version=version)
    assert selects("tls-below-1.3", f) is expected


def test_post_quantum_and_symmetric_have_no_quantum_deadline():
    mlkem = make("ML-KEM", parameter_set="ML-KEM-1024", primitive="kem")
    assert earliest_deadlines(mlkem) == {}
    aes = make("AES", key_size=128, mode="gcm")
    assert set(earliest_deadlines(aes)) == {"cnsa2"}  # CNSA 2.0 wants AES-256
    assert earliest_deadlines(make("AES", key_size=256, mode="gcm")) == {}


def test_sha1_is_retired_by_2030():
    sha1 = make("SHA-1", primitive="hash")
    assert earliest_deadlines(sha1)["nist"].date == "2030-12-31"


def test_programme_milestones_are_not_per_finding_deadlines():
    rsa = make("RSA", key_size=2048, primitive="pke")
    # The NCSC "discovery by 2028" and EU "first steps by 2026" milestones apply to the programme.
    assert earliest_deadlines(rsa, [BY_KEY["ncsc"]])["ncsc"].date == "2031-12-31"
    assert earliest_deadlines(rsa, [BY_KEY["eu"]])["eu"].date == "2030-12-31"
