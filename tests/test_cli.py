"""End-to-end: scan, cbom and assess through the command line, on the sample project."""

from __future__ import annotations

import json
import os
import sys
from datetime import date

import pytest
from conftest import SAMPLE

from pqc_kit import __version__
from pqc_kit.cli import main
from pqc_kit.scan import scan_path

TEST_FINDING_PATH = "test/test_crypto.py"


def run(capsys, *args) -> tuple[int, str, str]:
    code = main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"pqc-kit {__version__}"


def test_scan_table_lists_findings(capsys):
    code, out, _ = run(capsys, "scan", SAMPLE)
    assert code == 0
    assert out.startswith("Scanned ")
    assert "RSA-2048" in out and "ML-DSA-65" in out
    assert "pqc-kit assess" in out


def test_scan_json_is_complete_and_marks_test_code(capsys):
    code, out, _ = run(capsys, "scan", SAMPLE, "--format", "json")
    assert code == 0
    data = json.loads(out)
    assert data["tool"]["name"] == "pqc-kit"
    assert sum(data["summary"].values()) == len(data["findings"])
    tests = [f for f in data["findings"] if f["path"].startswith("test/")]
    assert tests and all(f["in_tests"] for f in tests)
    assert all(not f["in_tests"] for f in data["findings"] if not f["path"].startswith("test/"))


def test_no_tests_skips_test_code(capsys):
    code, out, _ = run(capsys, "scan", SAMPLE, "--format", "json", "--no-tests")
    data = json.loads(out)
    assert not any(f["in_tests"] for f in data["findings"])


def test_exclude(capsys):
    _, out, _ = run(capsys, "scan", SAMPLE, "--format", "json", "--exclude", "certs")
    assert not any(f["path"].startswith("certs/") for f in json.loads(out)["findings"])


@pytest.mark.parametrize("fail_on,expected", [("none", 0), ("weak", 1), ("vulnerable", 1), ("not-cnsa2", 1)])
def test_fail_on_exit_codes(capsys, fail_on, expected):
    code, _, err = run(capsys, "scan", SAMPLE, "--no-tests", "--fail-on", fail_on)
    assert code == expected
    if expected:
        assert f"match --fail-on {fail_on}" in err


def test_fail_on_passes_on_clean_code(capsys, tmp_path):
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.sha384(b'x')\n", encoding="utf-8")
    code, _, _ = run(capsys, "scan", tmp_path, "--fail-on", "vulnerable")
    assert code == 0


def test_missing_path_is_an_error(capsys, tmp_path):
    code, _, err = run(capsys, "scan", tmp_path / "missing")
    assert code == 2 and "pqc-kit: error" in err


def test_cbom_command_writes_a_file(capsys, tmp_path):
    out_file = tmp_path / "cbom.cdx.json"
    code, out, _ = run(capsys, "cbom", SAMPLE, "-o", out_file, "--name", "Sample", "--product-version", "2.0")
    assert code == 0 and "cryptographic assets" in out
    bom = json.loads(out_file.read_text(encoding="utf-8"))
    assert bom["metadata"]["component"]["name"] == "Sample"
    assert bom["metadata"]["component"]["version"] == "2.0"


def test_assess_markdown_covers_every_framework(capsys):
    code, out, _ = run(capsys, "assess", SAMPLE, "--as-of", "2026-09-30")
    assert code == 0
    for heading in ("NIST post-quantum transition", "US federal PQC migration", "NSA CNSA 2.0",
                    "UK NCSC migration timelines", "EU coordinated PQC roadmap"):
        assert f"### {heading}" in out
    assert "Not legal advice" in out
    assert "## 1. Fix first: weak today" in out


def test_assess_framework_filter_and_json(capsys):
    code, out, _ = run(capsys, "assess", SAMPLE, "--framework", "us", "--framework", "ncsc", "--format", "json",
                       "--as-of", "2026-09-30")
    data = json.loads(out)
    assert [f["key"] for f in data["frameworks"]] == ["us", "ncsc"]
    us = data["frameworks"][0]["milestones"]
    assert [m["date"] for m in us] == ["2030-01-02", "2030-12-31", "2031-12-31", "2035-12-31"]
    assert us[1]["days_left"] == (date(2030, 12, 31) - date(2026, 9, 30)).days
    assert data["cnsa2_categories"] == []


def test_assess_from_saved_scan_matches_a_fresh_scan(capsys, tmp_path):
    scan_file = tmp_path / "scan.json"
    run(capsys, "scan", SAMPLE, "--format", "json", "-o", scan_file)
    _, from_file, _ = run(capsys, "assess", "--scan", scan_file, "--format", "json", "--as-of", "2026-09-30",
                          "--name", "x")
    _, fresh, _ = run(capsys, "assess", SAMPLE, "--format", "json", "--as-of", "2026-09-30", "--name", "x")
    a, b = json.loads(from_file), json.loads(fresh)
    for key in ("counts", "test_counts", "headline", "frameworks", "cnsa2"):
        assert a[key] == b[key], key


def test_assess_rejects_a_file_that_is_not_a_scan(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{\"hello\": 1}", encoding="utf-8")
    code, _, err = run(capsys, "assess", "--scan", bad)
    assert code == 2 and "not the JSON output" in err


def test_private_keys_are_reported_without_their_contents(capsys, tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (tmp_path / "deploy.key").write_bytes(pem)
    body = pem.decode().splitlines()[1]
    for args in (("scan", tmp_path, "--format", "json"), ("assess", tmp_path),
                 ("cbom", tmp_path, "-o", tmp_path / "c.json")):
        _, out, _ = run(capsys, *args)
        assert body not in out
    assert body not in (tmp_path / "c.json").read_text(encoding="utf-8")
    _, out, _ = run(capsys, "assess", tmp_path)
    assert "private key(s) stored in the repository" in out


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need extra rights on Windows")
def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    os.symlink(outside, project / "link")
    os.symlink(outside / "secret.py", project / "file.py")
    assert scan_path(project).findings == []
