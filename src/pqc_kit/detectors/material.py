"""Certificates, keys and parameters stored in files: PEM blocks (in any text
file, including source code and config), binary DER files, SSH public keys
and keystore files. Only metadata is recorded; key material never leaves
this module.
"""

from __future__ import annotations

import base64
import binascii
import re

from pqc_kit import asn1, pkix
from pqc_kit.asn1 import DERError
from pqc_kit.model import ALGORITHM, CERTIFICATE, KEY, Finding

PEM = re.compile(r"-----BEGIN ([A-Z0-9 .#]{3,40})-----(.*?)-----END \1-----", re.S)
SSH_LINE = re.compile(r"(?<![\w@-])(ssh-rsa|ssh-dss|ssh-ed25519|ssh-ed448|ecdsa-sha2-nistp(?:256|384|521)|"
                      r"sk-ecdsa-sha2-nistp256@openssh\.com|sk-ssh-ed25519@openssh\.com)\s+(AAAA[A-Za-z0-9+/]{20,}=*)")
DER_EXTENSIONS = {".der", ".cer", ".crt", ".cert", ".key", ".p8", ".pk8", ".spki", ".pub", ".csr", ".pem"}
KEYSTORE_EXTENSIONS = {".p12": "PKCS#12", ".pfx": "PKCS#12", ".jks": "Java KeyStore", ".jceks": "Java JCEKS",
                       ".keystore": "Java KeyStore", ".truststore": "Java KeyStore", ".bks": "Bouncy Castle keystore"}
WEAK_PROTECTION = {"DES", "3DES", "RC2", "RC4"}


def _clean_base64(body: str) -> bytes:
    # PEM pasted into source code: drop string concatenation ("..." + "...") and escaped newlines.
    body = re.sub(r"[\"'`]\s*\+\s*(?:\\n)?\s*[\"'`]", "", body)
    lines = []
    for line in body.replace("\\n", "\n").replace("\\r", "\n").splitlines():
        if ":" in line:  # RFC 1421 headers such as Proc-Type / DEK-Info (base64 never contains ':')
            continue
        lines.append(re.sub(r"[^A-Za-z0-9+/=]", "", line))
    data = "".join(lines).replace("=", "")
    return base64.b64decode(data + "=" * (-len(data) % 4))


def _headers(body: str) -> dict[str, str]:
    out = {}
    for line in body.replace("\\n", "\n").splitlines():
        line = line.strip().strip("\"'")
        m = re.match(r"([A-Za-z-]+):\s*(.+)", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
        elif out and line:
            break
    return out


class _Material:
    def __init__(self, path: str, in_tests: bool):
        self.path = path
        self.in_tests = in_tests
        self.findings: list[Finding] = []
        self.errors: list[str] = []

    def key_finding(self, info: pkix.KeyInfo, line: int | None, symbol: str, detector: str) -> Finding:
        f = Finding(asset=KEY, family=info.family, path=self.path, line=line, symbol=symbol, detector=detector,
                    in_tests=self.in_tests, key_size=info.key_size, curve=info.curve,
                    parameter_set=info.parameter_set, oid=info.oid)
        f.primitive = "unknown"
        f.details = {"kind": info.kind, "format": info.format, "encrypted": info.encrypted}
        if info.fingerprint:
            f.details["fingerprint_sha256"] = info.fingerprint
        if info.ssh_type:
            f.details["ssh_type"] = info.ssh_type
        if info.protection:
            f.details["protection"] = info.protection
            weak = _weak_protection(info.protection)
            if weak:
                f.details["force_weak"] = weak
        if info.kind == "private":
            if self.in_tests:
                f.notes.append("Private key in test files: make sure it is a test-only key.")
            else:
                f.notes.append("Private key stored in the repository: move it to a secrets manager and rotate it.")
        if info.family == "Unknown" and info.encrypted:
            f.notes.append("Encrypted private key: the algorithm is only visible after decryption.")
        self.findings.append(f)
        return f

    def cert_finding(self, cert: pkix.CertInfo, line: int | None, symbol: str, detector: str) -> Finding:
        k = cert.key
        f = Finding(asset=CERTIFICATE, family=k.family, path=self.path, line=line, symbol=symbol, detector=detector,
                    in_tests=self.in_tests, key_size=k.key_size, curve=k.curve, parameter_set=k.parameter_set,
                    oid=k.oid)
        s = cert.signature
        f.details = {
            "subject": cert.subject,
            "issuer": cert.issuer,
            "common_name": pkix.common_name(cert.subject),
            "not_before": cert.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": cert.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "serial": cert.serial,
            "sha256": cert.sha256,
            "is_ca": cert.is_ca,
            "self_signed": cert.self_signed,
            "dns_names": cert.dns_names[:20],
            "key_fingerprint_sha256": k.fingerprint,
            "signature": {"family": s.family, "hash": s.hash, "padding": s.padding, "parameter_set": s.parameter_set,
                          "oid": s.oid, "key_size": s.key_size,
                          "curve": k.curve if (cert.self_signed and s.family == "ECDSA") else None},
        }
        self.findings.append(f)
        return f

    def algorithm_finding(self, info: pkix.KeyInfo, line: int | None, symbol: str) -> Finding:
        f = Finding(asset=ALGORITHM, family=info.family, path=self.path, line=line, symbol=symbol, detector="pem",
                    in_tests=self.in_tests, key_size=info.key_size, curve=info.curve,
                    primitive="key-agree" if info.family == "DH" else "unknown")
        self.findings.append(f)
        return f


def _weak_protection(p: dict) -> str | None:
    cipher = str(p.get("cipher", ""))
    h = p.get("hash")
    if cipher.upper().startswith("DES-EDE3") or cipher.upper().startswith("DES-"):
        cipher = "3DES" if "EDE3" in cipher.upper() else "DES"
    if cipher in WEAK_PROTECTION or h in ("MD5", "MD2"):
        return f"Private key encrypted with a weak scheme ({h + ' + ' if h else ''}{cipher})."
    return None


def _pem_block(m: _Material, label: str, body: str, line: int) -> None:
    headers = _headers(body)
    encrypted_legacy = "ENCRYPTED" in headers.get("Proc-Type", "")
    sym = f"PEM {label}"
    if encrypted_legacy and label in ("RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"):
        fam = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "EC", "DSA PRIVATE KEY": "DSA"}[label]
        dek = headers.get("DEK-Info", "").split(",")[0]
        info = pkix.KeyInfo(family=fam, kind="private", format="PEM (legacy encryption)", encrypted=True,
                            protection={"cipher": dek or "unknown", "kdf": "EVP_BytesToKey (MD5)"})
        f = m.key_finding(info, line, sym, "pem")
        f.notes.append("Legacy PEM encryption derives the key with a single MD5 iteration; re-encrypt as PKCS#8.")
        return
    der = _clean_base64(body)
    tlv = asn1.parse(der) if label not in ("OPENSSH PRIVATE KEY",) else None
    if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
        m.cert_finding(pkix.certificate_info(tlv), line, "X.509 certificate (PEM)", "pem")
    elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
        subject, key, sig = pkix.csr_info(tlv)
        f = m.key_finding(key, line, "PKCS#10 certificate request", "pem")
        f.details.update(subject=subject, signature_hash=sig.hash)
    elif label == "PUBLIC KEY":
        m.key_finding(pkix.spki_info(tlv), line, sym, "pem")
    elif label == "RSA PUBLIC KEY":
        m.key_finding(pkix.rsa_public_key_info(tlv), line, sym, "pem")
    elif label == "PRIVATE KEY":
        m.key_finding(pkix.pkcs8_info(tlv), line, sym, "pem")
    elif label == "ENCRYPTED PRIVATE KEY":
        m.key_finding(pkix.encrypted_pkcs8_info(tlv), line, sym, "pem")
    elif label == "RSA PRIVATE KEY":
        m.key_finding(pkix.rsa_private_key_info(tlv), line, sym, "pem")
    elif label == "EC PRIVATE KEY":
        m.key_finding(pkix.sec1_info(tlv), line, sym, "pem")
    elif label == "DSA PRIVATE KEY":
        m.key_finding(pkix.dsa_private_key_info(tlv), line, sym, "pem")
    elif label == "OPENSSH PRIVATE KEY":
        m.key_finding(pkix.openssh_private_info(der), line, sym, "pem")
    elif label in ("DH PARAMETERS", "X9.42 DH PARAMETERS"):
        m.algorithm_finding(pkix.dh_params_info(tlv), line, sym)
    elif label == "EC PARAMETERS":
        m.algorithm_finding(pkix.ec_params_info(tlv), line, sym)


def scan_text_material(path: str, text: str, in_tests: bool) -> tuple[list[Finding], list[str]]:
    """PEM blocks and SSH public keys inside any text file."""
    m = _Material(path, in_tests)
    if "-----BEGIN " in text:
        for block in PEM.finditer(text):
            label = block.group(1).strip()
            line = text.count("\n", 0, block.start()) + 1
            try:
                _pem_block(m, label, block.group(2), line)
            except (DERError, IndexError, ValueError, binascii.Error) as exc:
                m.errors.append(f"{path}:{line}: could not read PEM {label} ({exc})")
    if "AAAA" in text:
        for sm in SSH_LINE.finditer(text):
            line = text.count("\n", 0, sm.start()) + 1
            try:
                info = pkix.ssh_public_line_info(sm.group(2))
                m.key_finding(info, line, f"SSH public key ({sm.group(1)})", "ssh")
            except (DERError, ValueError, binascii.Error):
                continue
    return m.findings, m.errors


def scan_der(path: str, data: bytes, in_tests: bool) -> tuple[list[Finding], list[str]]:
    """A binary file that may hold a DER certificate, key or request."""
    m = _Material(path, in_tests)
    if not data or data[0] != 0x30:
        return [], []
    try:
        tlv = asn1.parse(data)
    except DERError:
        return [], []
    attempts = (
        lambda: m.cert_finding(pkix.certificate_info(tlv), None, "X.509 certificate (DER)", "der"),
        lambda: m.key_finding(pkix.pkcs8_info(tlv), None, "PKCS#8 private key (DER)", "der"),
        lambda: m.key_finding(pkix.spki_info(tlv), None, "Public key (DER)", "der"),
        lambda: m.key_finding(pkix.encrypted_pkcs8_info(tlv), None, "Encrypted PKCS#8 private key (DER)", "der"),
        lambda: m.key_finding(pkix.rsa_private_key_info(tlv), None, "RSA private key (DER)", "der"),
        lambda: m.key_finding(pkix.sec1_info(tlv), None, "EC private key (DER)", "der"),
    )
    for attempt in attempts:
        try:
            attempt()
            return m.findings, []
        except (DERError, IndexError, ValueError):
            m.findings.clear()
    return [], []


def keystore_finding(path: str, kind: str, in_tests: bool) -> Finding:
    f = Finding(asset=KEY, family="Unknown", path=path, symbol=f"{kind} file", detector="keystore",
                in_tests=in_tests)
    f.details = {"kind": "keystore", "format": kind, "encrypted": True}
    f.notes.append(f"{kind} file: its keys and certificates are encrypted; list them with keytool or openssl.")
    return f
