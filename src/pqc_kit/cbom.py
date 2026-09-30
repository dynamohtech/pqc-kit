"""Write a CycloneDX 1.6 cryptography bill of materials (CBOM).

Each algorithm, protocol, certificate and key becomes a component of type
"cryptographic-asset" with cryptoProperties, and every place it was found is
listed under evidence.occurrences. pqc-kit's own verdict travels in
namespaced properties (pqc-kit:status, pqc-kit:reason, pqc-kit:cnsa2, and
pqc-kit:deadline:<framework> for the first migration deadline that covers it).
Private key material is never written; keys are identified by a SHA-256
fingerprint of their public part where available.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pqc_kit import __version__
from pqc_kit.catalog import classify
from pqc_kit.frameworks import Milestone, earliest_deadlines
from pqc_kit.model import ALGORITHM, CERTIFICATE, KEY, PROTOCOL, STATUS_ORDER, STATUS_RANK, Finding, ScanResult

SPEC_VERSION = "1.6"
ROOT_REF = "root-component"

_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
_PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw"}
_FUNCTIONS = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify",
              "encapsulate", "decapsulate", "other", "unknown"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


class _Builder:
    def __init__(self):
        self.components: dict[str, dict] = {}
        self.verdicts: dict[str, tuple[str, str]] = {}
        self.cnsa2: dict[str, list[bool | None]] = {}
        self.deps: dict[str, set[str]] = {}
        self.deadlines: dict[str, dict[str, Milestone]] = {}

    # -- algorithms and protocols ---------------------------------------------------------------

    def algorithm(self, f: Finding, with_evidence: bool = True) -> str:
        ref = f"crypto/algorithm/{_slug(f.name)}"
        comp = self.components.get(ref)
        if comp is None:
            props: dict = {}
            if f.primitive:
                props["primitive"] = f.primitive
            ps = _parameter_set(f)
            if ps:
                props["parameterSetIdentifier"] = ps
            if f.curve:
                props["curve"] = f.curve
            if f.mode:
                props["mode"] = f.mode if f.mode in _MODES else "other"
            if f.padding:
                props["padding"] = f.padding if f.padding in _PADDINGS else "other"
            if f.classical_bits is not None:
                props["classicalSecurityLevel"] = f.classical_bits
            if f.quantum_category is not None:
                props["nistQuantumSecurityLevel"] = f.quantum_category
            crypto: dict = {"assetType": "algorithm", "algorithmProperties": props}
            if f.oid and f.asset == ALGORITHM:
                crypto["oid"] = f.oid
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": f.name, "cryptoProperties": crypto}
            self.components[ref] = comp
        self._verdict(ref, f)
        funcs = [fn for fn in f.functions if fn in _FUNCTIONS]
        if funcs:
            ap = comp["cryptoProperties"]["algorithmProperties"]
            ap["cryptoFunctions"] = sorted(set(ap.get("cryptoFunctions", [])) | set(funcs))
        if with_evidence:
            self._occurrence(comp, f)
        return ref

    def protocol(self, f: Finding) -> str:
        if f.family == "TLS-CipherSuite":
            ref = "crypto/protocol/tls-cipher-suites"
            comp = self.components.setdefault(ref, {
                "type": "cryptographic-asset", "bom-ref": ref, "name": "TLS cipher suites",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls",
                                                                                     "cipherSuites": []}}})
            suites = comp["cryptoProperties"]["protocolProperties"]["cipherSuites"]
            if f.parameter_set and all(s["name"] != f.parameter_set for s in suites):
                suites.append({"name": f.parameter_set})
        else:
            ref = f"crypto/protocol/{_slug(f.name)}"
            ptype = "tls" if f.family == "TLS" else "other"
            pp: dict = {"type": ptype}
            if f.version:
                pp["version"] = f.version
            comp = self.components.setdefault(ref, {
                "type": "cryptographic-asset", "bom-ref": ref, "name": f.name,
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp}})
        self._verdict(ref, f)
        self._occurrence(comp, f)
        return ref

    # -- keys and certificates ------------------------------------------------------------------

    def key(self, f: Finding, algorithm_ref: str | None) -> str:
        kind = f.details.get("kind", "key")
        fp = f.details.get("fingerprint_sha256") or f.details.get("key_fingerprint_sha256")
        ident = fp[:16] if fp else _slug(f"{f.path}-{f.line}")
        ref = f"crypto/key/{kind}/{ident}"
        comp = self.components.get(ref)
        if comp is None:
            rtype = {"private": "private-key", "public": "public-key", "parameters": "other",
                     "keystore": "key"}.get(kind, "key")
            label = {"private": "private key", "public": "public key", "keystore": ""}.get(kind, "key")
            name = f"{f.name} {label}".strip() if f.family != "Unknown" else f.name
            rcm: dict = {"type": rtype}
            if fp:
                rcm["id"] = f"sha256:{fp}"
            if algorithm_ref:
                rcm["algorithmRef"] = algorithm_ref
            if f.key_size:
                rcm["size"] = f.key_size
            if f.details.get("format"):
                rcm["format"] = f.details["format"]
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                    "cryptoProperties": {"assetType": "related-crypto-material",
                                         "relatedCryptoMaterialProperties": rcm}}
            if f.oid:
                comp["cryptoProperties"]["oid"] = f.oid
            self.components[ref] = comp
        self._verdict(ref, f)
        self._occurrence(comp, f)
        if algorithm_ref:
            self.deps.setdefault(ref, set()).add(algorithm_ref)
        return ref

    def certificate(self, f: Finding) -> str:
        d = f.details
        ref = f"crypto/certificate/{d.get('sha256', _slug(f.where))[:16]}"
        key_alg = self._derived_algorithm(f, f.family, key=True)
        pub = Finding(asset=KEY, family=f.family, path=f.path, line=f.line, key_size=f.key_size, curve=f.curve,
                      parameter_set=f.parameter_set, oid=f.oid, in_tests=f.in_tests,
                      details={"kind": "public", "format": "X.509 SubjectPublicKeyInfo",
                               "fingerprint_sha256": d.get("key_fingerprint_sha256")})
        classify(pub)
        key_ref = self.key(pub, key_alg)
        sig = d.get("signature") or {}
        sig_ref = None
        if sig.get("name"):
            s = Finding(asset=ALGORITHM, family=sig["family"], path=f.path, hash=sig.get("hash"),
                        padding=sig.get("padding"), parameter_set=sig.get("parameter_set"),
                        key_size=sig.get("key_size"), curve=sig.get("curve"), primitive="signature",
                        oid=sig.get("oid"), functions=["sign", "verify"], in_tests=f.in_tests)
            classify(s)
            sig_ref = self.algorithm(s, with_evidence=False)
            if s.oid:
                self.components[sig_ref]["cryptoProperties"]["oid"] = s.oid
        ext = Path(f.path).suffix.lstrip(".").lower() or None
        cp: dict = {"subjectName": d.get("subject", ""), "issuerName": d.get("issuer", ""),
                    "notValidBefore": d.get("not_before"), "notValidAfter": d.get("not_after"),
                    "certificateFormat": "X.509"}
        if sig_ref:
            cp["signatureAlgorithmRef"] = sig_ref
        cp["subjectPublicKeyRef"] = key_ref
        if ext:
            cp["certificateExtension"] = ext
        comp = self.components.get(ref)
        if comp is None:
            comp = {"type": "cryptographic-asset", "bom-ref": ref,
                    "name": d.get("common_name") or d.get("subject") or "certificate",
                    "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
                    "properties": [{"name": "pqc-kit:sha256-fingerprint", "value": d.get("sha256", "")},
                                   {"name": "pqc-kit:serial", "value": d.get("serial", "")}]}
            self.components[ref] = comp
        self._verdict(ref, f)
        self._occurrence(comp, f)
        self.deps.setdefault(ref, set()).update(r for r in (sig_ref, key_ref) if r)
        return ref

    def _derived_algorithm(self, f: Finding, family: str, key: bool = False) -> str | None:
        if family == "Unknown":
            return None
        a = Finding(asset=ALGORITHM, family=family, path=f.path, key_size=f.key_size, curve=f.curve,
                    parameter_set=f.parameter_set, oid=f.oid, primitive=_key_primitive(family), in_tests=f.in_tests)
        classify(a)
        ref = self.algorithm(a, with_evidence=False)
        if f.oid:
            self.components[ref]["cryptoProperties"].setdefault("oid", f.oid)
        return ref

    # -- shared -----------------------------------------------------------------------------------

    def _verdict(self, ref: str, f: Finding) -> None:
        prev = self.verdicts.get(ref)
        if prev is None or STATUS_RANK[f.status] < STATUS_RANK[prev[0]]:
            self.verdicts[ref] = (f.status, f.reasons[0] if f.reasons else "")
        self.cnsa2.setdefault(ref, []).append(f.cnsa2)
        known = self.deadlines.setdefault(ref, {})
        for key, m in earliest_deadlines(f).items():
            if key not in known or m.date < known[key].date:
                known[key] = m

    def finish(self) -> None:
        for ref, (status, reason) in self.verdicts.items():
            comp = self.components[ref]
            values = self.cnsa2.get(ref, [])
            cnsa = "not approved" if False in values else "check" if None in values else "approved"
            props = [p for p in comp.get("properties", []) if not p["name"].startswith("pqc-kit:")
                     or p["name"] in ("pqc-kit:sha256-fingerprint", "pqc-kit:serial")]
            props.append({"name": "pqc-kit:status", "value": status})
            if reason:
                props.append({"name": "pqc-kit:reason", "value": reason})
            props.append({"name": "pqc-kit:cnsa2", "value": cnsa})
            for key, m in self.deadlines.get(ref, {}).items():
                props.append({"name": f"pqc-kit:deadline:{key}", "value": f"{m.date} ({m.when})"})
            comp["properties"] = props

    @staticmethod
    def _occurrence(comp: dict, f: Finding) -> None:
        occ: dict = {"location": f.path}
        if f.line:
            occ["line"] = f.line
        if f.column:
            occ["offset"] = f.column
        if f.symbol:
            occ["symbol"] = f.symbol
        ctx = f.detector + (" (test code)" if f.in_tests else "")
        if ctx:
            occ["additionalContext"] = ctx
        occurrences = comp.setdefault("evidence", {}).setdefault("occurrences", [])
        if occ not in occurrences:
            occurrences.append(occ)


def _parameter_set(f: Finding) -> str | None:
    if f.parameter_set:
        m = re.search(r"(\d+[sf]?)$", f.parameter_set)
        return m.group(1) if m else None
    if f.key_size:
        return str(f.key_size)
    return None


def _key_primitive(family: str) -> str:
    if family in ("ML-KEM", "X25519", "X448", "DH", "ECDH", "FrodoKEM"):
        return "kem" if family in ("ML-KEM", "FrodoKEM") else "key-agree"
    if family in ("ML-DSA", "SLH-DSA", "Ed25519", "Ed448", "DSA", "ECDSA", "HSS", "LMS", "XMSS"):
        return "signature"
    return "unknown"


def build_cbom(result: ScanResult, name: str, version: str | None = None, timestamp: datetime | None = None,
               serial: str | None = None) -> dict:
    b = _Builder()
    for f in result.findings:
        if f.asset == CERTIFICATE:
            b.certificate(f)
        elif f.asset == KEY:
            b.key(f, b._derived_algorithm(f, f.family))
        elif f.asset == PROTOCOL or f.family in ("TLS", "SSL", "DTLS", "TLS-CipherSuite"):
            b.protocol(f)
        else:
            b.algorithm(f)
    b.finish()
    ts = (timestamp or datetime.now(timezone.utc)).replace(microsecond=0)
    root: dict = {"type": "application", "bom-ref": ROOT_REF, "name": name}
    if version:
        root["version"] = version
    counts = result.counts()
    metadata = {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "tools": {"components": [{"type": "application", "name": "pqc-kit", "version": __version__,
                                  "externalReferences": [{"type": "vcs",
                                                          "url": "https://github.com/dynamohtech/pqc-kit"}]}]},
        "component": root,
        "properties": [{"name": f"pqc-kit:summary:{s}", "value": str(counts[s])} for s in STATUS_ORDER],
    }
    components = sorted(b.components.values(), key=lambda c: (c["cryptoProperties"]["assetType"], c["name"]))
    top = sorted(c["bom-ref"] for c in components)
    deps = [{"ref": ROOT_REF, "dependsOn": top}]
    for c in components:
        deps.append({"ref": c["bom-ref"], "dependsOn": sorted(b.deps.get(c["bom-ref"], set()))})
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": deps,
    }


def write_cbom(bom: dict, path: Path) -> None:
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
