"""CycloneDX 1.6 CBOM output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from conftest import SAMPLE

from pqc_kit.cbom import build_cbom
from pqc_kit.scan import scan_path

FIXED = dict(timestamp=datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc),
             serial="urn:uuid:00000000-0000-4000-8000-000000000000")


@pytest.fixture(scope="module")
def bom():
    return build_cbom(scan_path(SAMPLE), "sample-app", "1.0.0", **FIXED)


def props(component: dict) -> dict:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def test_validates_against_the_cyclonedx_16_schema(bom):
    pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert errors is None, errors


def test_structure_and_references(bom):
    assert bom["specVersion"] == "1.6" and bom["bomFormat"] == "CycloneDX"
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
    known = set(refs) | {"root-component"}
    for dep in bom["dependencies"]:
        assert dep["ref"] in known
        assert set(dep["dependsOn"]) <= known
    assert all(c["type"] == "cryptographic-asset" for c in bom["components"])
    assert bom["metadata"]["component"] == {"type": "application", "bom-ref": "root-component",
                                            "name": "sample-app", "version": "1.0.0"}


def test_every_component_carries_a_verdict_and_evidence(bom):
    for c in bom["components"]:
        p = props(c)
        assert p["pqc-kit:status"] in {"weak", "quantum-vulnerable", "retiring", "unknown", "ok", "quantum-safe"}
        assert p["pqc-kit:cnsa2"] in {"approved", "not approved", "check"}
    located = [c for c in bom["components"] if c.get("evidence")]
    assert located and all(o["location"] for c in located for o in c["evidence"]["occurrences"])


def test_certificates_link_key_and_signature(bom):
    certs = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "certificate"]
    assert certs
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    for cert in certs:
        cp = cert["cryptoProperties"]["certificateProperties"]
        assert cp["subjectPublicKeyRef"] in by_ref
        assert cp["subjectPublicKeyRef"] in deps[cert["bom-ref"]]
        if "signatureAlgorithmRef" in cp:
            assert by_ref[cp["signatureAlgorithmRef"]]["cryptoProperties"]["assetType"] == "algorithm"
        assert len(props(cert)["pqc-kit:sha256-fingerprint"]) == 64


def test_deadlines_are_recorded_per_component(bom):
    rsa = [c for c in bom["components"] if c["name"].startswith("RSA-2048")]
    assert rsa
    p = props(rsa[0])
    assert p["pqc-kit:deadline:nist"].startswith("2030-12-31")
    assert p["pqc-kit:deadline:us"].startswith(("2030-12-31", "2031-12-31"))
    pqc = [c for c in bom["components"] if props(c)["pqc-kit:status"] == "quantum-safe"]
    assert pqc and not any(k.startswith("pqc-kit:deadline:nist") for c in pqc for k in props(c))


def test_no_private_key_material_is_written(bom):
    text = json.dumps(bom)
    assert "PRIVATE KEY" not in text and "BEGIN " not in text


def test_output_is_deterministic():
    a = build_cbom(scan_path(SAMPLE), "sample-app", **FIXED)
    b = build_cbom(scan_path(SAMPLE), "sample-app", **FIXED)
    assert json.dumps(a) == json.dumps(b)
