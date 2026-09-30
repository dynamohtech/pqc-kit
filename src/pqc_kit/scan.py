"""Walk a project, run the detectors and classify what they find."""

from __future__ import annotations

import fnmatch
import os
from datetime import datetime, timezone
from pathlib import Path

from pqc_kit.catalog import add_note, classify, combine
from pqc_kit.detectors.golang import scan_go
from pqc_kit.detectors.java import scan_java
from pqc_kit.detectors.javascript import scan_javascript
from pqc_kit.detectors.material import (
    DER_EXTENSIONS, KEYSTORE_EXTENSIONS, keystore_finding, scan_der, scan_text_material,
)
from pqc_kit.detectors.python import scan_python
from pqc_kit.detectors.text import is_test_path
from pqc_kit.model import CERTIFICATE, STATUS_RANK, Finding, ScanResult

DEFAULT_EXCLUDES = [
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build", "target", "vendor", ".next",
    ".nuxt", "coverage", ".gradle", ".idea", ".vscode", "*.min.js", "*.bundle.js", "*.d.ts", "*.map",
]
MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024

PYTHON = {".py", ".pyw"}
JVM = {".java", ".kt", ".kts", ".scala", ".groovy"}
GO = {".go"}
JS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
LANG_OF = {**{e: "python" for e in PYTHON}, **{e: "java" for e in JVM}, **{e: "go" for e in GO},
           **{e: "javascript" for e in JS}}

NIST_2030 = datetime(2031, 1, 1, tzinfo=timezone.utc)
NIST_2035 = datetime(2036, 1, 1, tzinfo=timezone.utc)


def _excluded(rel: str, patterns: list[str]) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(p, pat) for p in parts):
            return True
    return False


def iter_files(root: Path, excludes: list[str]):
    """Yield (path, relative posix path). Symbolic links are skipped, never followed."""
    if root.is_file():
        yield root, root.name
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        rel_dir = base.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(d for d in dirnames
                             if not (base / d).is_symlink() and not _excluded(rel_dir + d, excludes))
        for name in sorted(filenames):
            p = base / name
            rel = rel_dir + name
            if p.is_symlink() or _excluded(rel, excludes):
                continue
            yield p, rel


def scan_path(target: str | Path, excludes: list[str] | None = None, include_tests: bool = True,
              use_default_excludes: bool = True, now: datetime | None = None) -> ScanResult:
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"{target} does not exist")
    patterns = (DEFAULT_EXCLUDES if use_default_excludes else []) + list(excludes or [])
    result = ScanResult(root=str(root))
    kinds: dict[str, int] = {}
    for path, rel in iter_files(root, patterns):
        in_tests = is_test_path(rel)
        if in_tests and not include_tests:
            continue
        findings, errors, kind = _scan_file(path, rel, in_tests)
        if kind:
            result.files_scanned += 1
            kinds[kind] = kinds.get(kind, 0) + 1
        result.findings.extend(findings)
        result.errors.extend(errors)
    result.files_by_kind = dict(sorted(kinds.items()))
    finalize(result.findings, now=now)
    result.findings.sort(key=lambda f: (STATUS_RANK[f.status], f.path, f.line or 0, f.column or 0))
    return result


def _scan_file(path: Path, rel: str, in_tests: bool) -> tuple[list[Finding], list[str], str | None]:
    ext = path.suffix.lower()
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [], [f"{rel}: {exc.strerror}"], None
    if ext in KEYSTORE_EXTENSIONS:
        return [keystore_finding(rel, KEYSTORE_EXTENSIONS[ext], in_tests)], [], "keystore"
    if size > MAX_TEXT_BYTES:
        return [], [], None
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [], [f"{rel}: {exc.strerror}"], None
    head = data[:8192]
    if b"\x00" in head:
        if ext in DER_EXTENSIONS and size <= MAX_BINARY_BYTES:
            found, errs = scan_der(rel, data, in_tests)
            return found, errs, "certificate/key" if found else None
        return [], [], None
    text = data.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    errors: list[str] = []
    lang = LANG_OF.get(ext)
    kind = None
    if lang == "python":
        found, err = scan_python(rel, text, in_tests)
        findings += found
        if err:
            errors.append(err)
    elif lang == "java":
        findings += scan_java(rel, text, in_tests)
    elif lang == "go":
        findings += scan_go(rel, text, in_tests)
    elif lang == "javascript":
        findings += scan_javascript(rel, text, in_tests)
    if lang:
        kind = lang
    material, merrs = scan_text_material(rel, text, in_tests)
    findings += material
    errors += merrs
    if material and not kind:
        kind = "certificate/key"
    if not findings and not kind and ext in DER_EXTENSIONS and data[:1] == b"\x30":
        found, errs = scan_der(rel, data, in_tests)
        if found:
            return found, errs, "certificate/key"
    return findings, errors, kind


def finalize(findings: list[Finding], now: datetime | None = None) -> None:
    """Classify every finding; certificates also take their signature algorithm and dates into account."""
    now = now or datetime.now(timezone.utc)
    for f in findings:
        classify(f)
        if f.asset == CERTIFICATE:
            _certificate(f, now)


def _certificate(f: Finding, now: datetime) -> None:
    sig = f.details.get("signature") or {}
    if sig.get("family"):
        s = Finding(asset="algorithm", family=sig["family"], path=f.path, hash=sig.get("hash"),
                    padding=sig.get("padding"), parameter_set=sig.get("parameter_set"),
                    key_size=sig.get("key_size"), curve=sig.get("curve"), primitive="signature", oid=sig.get("oid"))
        classify(s)
        sig.update(name=s.name, status=s.status, reasons=s.reasons, classical_bits=s.classical_bits, cnsa2=s.cnsa2)
        root = f.details.get("self_signed") and f.details.get("is_ca")
        if STATUS_RANK[s.status] < STATUS_RANK[f.status]:
            if root and s.status == "weak" and s.hash in ("SHA-1", "MD5", "MD2"):
                # Relying parties trust a root by its key, not by its self-signature (RFC 5280, section 6).
                add_note(f, f"Root CA self-signed with {s.name}; the self-signature is not relied on, but some "
                            "policies still flag it.")
            else:
                combine(f, s.status, f"Signed with {s.name}: {s.reasons[0] if s.reasons else ''}".strip())
        if f.cnsa2 and not s.cnsa2:
            f.cnsa2 = s.cnsa2
    try:
        not_after = datetime.strptime(f.details["not_after"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return
    if not_after < now:
        add_note(f, f"Expired on {not_after:%Y-%m-%d}.")
    elif f.status in ("quantum-vulnerable", "weak"):
        if f.classical_bits == 112 and not_after >= NIST_2030:
            add_note(f, f"Valid until {not_after:%Y-%m-%d}, past the end of 2030 when NIST (draft IR 8547) "
                           "deprecates 112-bit keys.")
        elif not_after >= NIST_2035:
            add_note(f, f"Valid until {not_after:%Y-%m-%d}, past the end of 2035 when NIST (draft IR 8547) "
                           "disallows quantum-vulnerable algorithms.")
