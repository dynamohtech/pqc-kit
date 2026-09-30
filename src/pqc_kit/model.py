"""Data model shared by the detectors, the classifier and the reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Status values, from most to least urgent. The order is used for sorting and
# for picking the worst status when a finding combines several algorithms.
WEAK = "weak"  # insecure or disallowed today, regardless of quantum computers
VULNERABLE = "quantum-vulnerable"  # public-key crypto a quantum computer breaks (Shor)
RETIRING = "retiring"  # acceptable today, on NIST's retirement schedule for the end of 2030
UNKNOWN = "unknown"  # could not tell the algorithm or its parameters
OK = "ok"  # symmetric crypto or hash at a size NIST considers adequate
SAFE = "quantum-safe"  # NIST post-quantum algorithm, or a hybrid that includes one

STATUS_ORDER = [WEAK, VULNERABLE, RETIRING, UNKNOWN, OK, SAFE]
STATUS_RANK = {s: i for i, s in enumerate(STATUS_ORDER)}

STATUS_TEXT = {
    WEAK: "Weak today",
    VULNERABLE: "Quantum-vulnerable",
    RETIRING: "Retiring after 2030",
    UNKNOWN: "Needs review",
    OK: "OK",
    SAFE: "Quantum-safe",
}

# Asset types, named after CycloneDX 1.6 cryptoProperties.assetType.
ALGORITHM = "algorithm"
CERTIFICATE = "certificate"
KEY = "related-crypto-material"
PROTOCOL = "protocol"


def worst(*statuses: str) -> str:
    present = [s for s in statuses if s]
    return min(present, key=lambda s: STATUS_RANK[s]) if present else UNKNOWN


@dataclass
class Finding:
    """One place where cryptography is used, declared or stored.

    Detectors fill in what they see (family and parameters); classify() in
    catalog.py adds the name, status and reasons.
    """

    asset: str  # ALGORITHM, CERTIFICATE, KEY or PROTOCOL
    family: str  # canonical algorithm family, e.g. "RSA", "ECDSA", "AES", "SHA-1", "TLS"
    path: str  # relative to the scan root, with forward slashes
    line: int | None = None
    column: int | None = None
    symbol: str = ""  # the API, constant or file type that revealed it
    detector: str = ""  # python | java | go | javascript | pem | der | ssh | keystore
    primitive: str = "unknown"  # CycloneDX algorithm primitive
    key_size: int | None = None
    curve: str | None = None
    parameter_set: str | None = None  # e.g. "ML-KEM-768", "SLH-DSA-SHA2-128s"
    mode: str | None = None  # block cipher mode, lower case: ecb, cbc, gcm ...
    padding: str | None = None  # pkcs1v15, oaep, pss ...
    hash: str | None = None  # hash used by a signature, HMAC or KDF
    version: str | None = None  # protocol version, e.g. "1.2"
    functions: list[str] = field(default_factory=list)  # CycloneDX cryptoFunctions
    oid: str | None = None
    in_tests: bool = False
    confidence: str = "high"  # high | medium | low
    notes: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)  # certificate and key metadata
    # Filled in by catalog.classify()
    name: str = ""
    status: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)
    classical_bits: int | None = None
    quantum_category: int | None = None  # NIST PQC security category; 0 = broken by a quantum computer
    cnsa2: bool | None = None  # approved in NSA CNSA 2.0? None = depends / unknown
    role: str = "other"  # key-establishment | signature | symmetric | hash | protocol | other

    @property
    def where(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict:
        data = asdict(self)
        return {k: v for k, v in data.items() if v not in (None, [], {}, "")} | {
            "status": self.status,
            "in_tests": self.in_tests,
        }


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_by_kind: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)  # files that could not be read or parsed

    def counts(self, include_tests: bool = True) -> dict:
        out = {s: 0 for s in STATUS_ORDER}
        for f in self.findings:
            if include_tests or not f.in_tests:
                out[f.status] += 1
        return out
