"""Read X.509 certificates, CSRs, public and private keys (PKCS#1, PKCS#8, SEC1,
OpenSSH) and DH/EC parameters, returning only metadata.

Private key material is never returned, printed or stored: for a private key
we record its algorithm and size, and a fingerprint of its public part where
the format carries one.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime

from pqc_kit import asn1, oids
from pqc_kit.asn1 import DERError


@dataclass
class KeyInfo:
    family: str
    kind: str  # public | private
    format: str
    key_size: int | None = None
    curve: str | None = None
    parameter_set: str | None = None
    oid: str | None = None
    encrypted: bool = False
    fingerprint: str | None = None  # SHA-256 over the public part, when available
    protection: dict | None = None  # for encrypted keys: how they are protected
    ssh_type: str | None = None  # e.g. ssh-ed25519


@dataclass
class SignatureInfo:
    family: str
    hash: str | None = None
    parameter_set: str | None = None
    padding: str | None = None
    oid: str = ""
    key_size: int | None = None  # RSA: length of the signature value


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial: str
    sha256: str
    key: KeyInfo
    signature: SignatureInfo
    is_ca: bool = False
    self_signed: bool = False
    dns_names: list[str] = field(default_factory=list)
    version: int = 1


# ---------------------------------------------------------------------------
# Public keys
# ---------------------------------------------------------------------------


def _fp(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def spki_info(tlv: asn1.TLV, fmt: str = "SubjectPublicKeyInfo") -> KeyInfo:
    parts = asn1.seq(tlv)
    if len(parts) < 2:
        raise DERError("short SubjectPublicKeyInfo")
    alg_oid, params = asn1.algorithm_identifier(parts[0])
    key_bytes = asn1.bit_string(parts[1])
    info = _key_from_oid(alg_oid, params, "public", fmt)
    info.fingerprint = _fp(tlv.raw)
    if info.family == "RSA":
        rsa = asn1.seq(asn1.parse(key_bytes))
        info.key_size = asn1.unsigned_bits(asn1.expect(rsa[0], asn1.INTEGER).value)
    elif info.family == "EC" and not info.curve and key_bytes:
        info.key_size = _ec_point_bits(key_bytes)
    return info


def _key_from_oid(alg_oid: str, params: asn1.TLV | None, kind: str, fmt: str) -> KeyInfo:
    fam, ps = oids.PUBLIC_KEY.get(alg_oid, ("Unknown", None))
    info = KeyInfo(family=fam, kind=kind, format=fmt, oid=alg_oid)
    if fam == "RSA" and ps == "RSASSA-PSS":
        info.parameter_set = None
    elif fam in ("ML-KEM", "ML-DSA", "SLH-DSA", "Composite", "HSS", "FrodoKEM"):
        info.parameter_set = ps
    if fam in ("EC", "ECDH") and params is not None:
        if params.is_(asn1.OID):
            curve_oid = asn1.oid(params)
            info.curve = oids.CURVES.get(curve_oid, curve_oid)
            if curve_oid == "1.2.156.10197.1.301":
                info.family = "SM2"
        else:
            info.curve = "explicit parameters"
    elif fam in ("DSA", "DH") and params is not None and params.is_(asn1.SEQUENCE):
        p = asn1.seq(params)
        if p:
            info.key_size = asn1.unsigned_bits(asn1.expect(p[0], asn1.INTEGER).value)
    return info


def _ec_point_bits(point: bytes) -> int | None:
    if point[:1] == b"\x04":
        return (len(point) - 1) // 2 * 8
    if point[:1] in (b"\x02", b"\x03"):
        return (len(point) - 1) * 8
    return None


def rsa_public_key_info(tlv: asn1.TLV) -> KeyInfo:
    """PKCS#1 RSAPublicKey (PEM label RSA PUBLIC KEY)."""
    parts = asn1.seq(tlv)
    n = asn1.expect(parts[0], asn1.INTEGER).value
    return KeyInfo(family="RSA", kind="public", format="PKCS#1", key_size=asn1.unsigned_bits(n),
                   oid="1.2.840.113549.1.1.1", fingerprint=_fp(tlv.raw))


# ---------------------------------------------------------------------------
# Private keys
# ---------------------------------------------------------------------------


def pkcs8_info(tlv: asn1.TLV) -> KeyInfo:
    """PrivateKeyInfo / OneAsymmetricKey (PEM label PRIVATE KEY)."""
    parts = asn1.seq(tlv)
    if len(parts) < 3:
        raise DERError("short PrivateKeyInfo")
    asn1.integer(parts[0])
    alg_oid, params = asn1.algorithm_identifier(parts[1])
    info = _key_from_oid(alg_oid, params, "private", "PKCS#8")
    inner = asn1.octet_string(parts[2])
    try:
        if info.family == "RSA":
            pub = rsa_private_key_info(asn1.parse(inner))
            info.key_size, info.fingerprint = pub.key_size, pub.fingerprint
        elif info.family in ("EC", "SM2", "ECDH"):
            sec1 = sec1_info(asn1.parse(inner))
            info.curve = info.curve or sec1.curve
            info.key_size = info.key_size or sec1.key_size
            info.fingerprint = sec1.fingerprint
    except (DERError, IndexError):
        pass  # algorithm is known from the OID even if the inner structure is unusual
    for extra in parts[3:]:
        if extra.cls == asn1.CONTEXT and extra.tag == 1:  # [1] publicKey (OneAsymmetricKey v2)
            info.fingerprint = _fp(extra.value)
    return info


def rsa_private_key_info(tlv: asn1.TLV) -> KeyInfo:
    """PKCS#1 RSAPrivateKey (PEM label RSA PRIVATE KEY)."""
    parts = asn1.seq(tlv)
    n, e = parts[1], parts[2]
    asn1.expect(n, asn1.INTEGER)
    asn1.expect(e, asn1.INTEGER)
    fingerprint = _fp(n.raw + e.raw)
    return KeyInfo(family="RSA", kind="private", format="PKCS#1", key_size=asn1.unsigned_bits(n.value),
                   oid="1.2.840.113549.1.1.1", fingerprint=fingerprint)


def sec1_info(tlv: asn1.TLV) -> KeyInfo:
    """SEC 1 ECPrivateKey (PEM label EC PRIVATE KEY)."""
    parts = asn1.seq(tlv)
    info = KeyInfo(family="EC", kind="private", format="SEC1", oid="1.2.840.10045.2.1")
    priv = asn1.octet_string(parts[1])
    info.key_size = len(priv) * 8 if len(priv) not in (66,) else 521
    for p in parts[2:]:
        if p.cls == asn1.CONTEXT and p.tag == 0 and p.constructed:
            inner = asn1.parse(p.value)
            if inner.is_(asn1.OID):
                c = asn1.oid(inner)
                info.curve = oids.CURVES.get(c, c)
                if c == "1.2.156.10197.1.301":
                    info.family = "SM2"
        elif p.cls == asn1.CONTEXT and p.tag == 1 and p.constructed:
            info.fingerprint = _fp(asn1.bit_string(asn1.parse(p.value)))
    return info


def dsa_private_key_info(tlv: asn1.TLV) -> KeyInfo:
    """OpenSSL DSAPrivateKey: SEQUENCE { version, p, q, g, y, x } (PEM label DSA PRIVATE KEY)."""
    parts = asn1.seq(tlv)
    p = asn1.expect(parts[1], asn1.INTEGER).value
    return KeyInfo(family="DSA", kind="private", format="OpenSSL DSA", key_size=asn1.unsigned_bits(p),
                   oid="1.2.840.10040.4.1", fingerprint=_fp(parts[4].raw) if len(parts) > 4 else None)


def encrypted_pkcs8_info(tlv: asn1.TLV) -> KeyInfo:
    """EncryptedPrivateKeyInfo: the key algorithm is hidden, but the protection scheme is visible."""
    parts = asn1.seq(tlv)
    alg_oid, params = asn1.algorithm_identifier(parts[0])
    return KeyInfo(family="Unknown", kind="private", format="PKCS#8 (encrypted)", encrypted=True,
                   protection=pbe_scheme(alg_oid, params))


def pbe_scheme(alg_oid: str, params: asn1.TLV | None) -> dict:
    if alg_oid in oids.PBE_LEGACY:
        h, cipher, size = oids.PBE_LEGACY[alg_oid]
        return {"kdf": "PBKDF1/PKCS#12", "hash": h, "cipher": cipher, "key_size": size, "oid": alg_oid}
    if alg_oid == oids.PBES2 and params is not None:
        kdf_alg, enc_alg = asn1.seq(params)[:2]
        kdf_oid, kdf_params = asn1.algorithm_identifier(kdf_alg)
        enc_oid, _ = asn1.algorithm_identifier(enc_alg)
        out: dict = {"oid": alg_oid}
        if kdf_oid == oids.PBKDF2 and kdf_params is not None:
            out["kdf"] = "PBKDF2"
            prf_hash = "SHA-1"  # default PRF is hmacWithSHA1 (RFC 8018)
            for p in asn1.seq(kdf_params)[1:]:
                if p.is_(asn1.INTEGER) and "iterations" not in out:
                    out["iterations"] = asn1.integer(p)
                elif p.is_(asn1.SEQUENCE):
                    prf_oid, _ = asn1.algorithm_identifier(p)
                    prf_hash = oids.HMAC.get(prf_oid, prf_oid)
            out["hash"] = prf_hash
        elif kdf_oid == "1.3.6.1.4.1.11591.4.11":
            out["kdf"] = "scrypt"
        else:
            out["kdf"] = kdf_oid
        fam, size, mode = oids.CIPHER.get(enc_oid, (enc_oid, None, None))
        out.update(cipher=fam, key_size=size, mode=mode)
        return out
    return {"oid": alg_oid}


def openssh_private_info(blob: bytes) -> KeyInfo:
    """openssh-key-v1: the public key is stored unencrypted even when the private part is encrypted."""
    magic = b"openssh-key-v1\x00"
    if not blob.startswith(magic):
        raise DERError("not an openssh-key-v1 blob")
    r = _SSHReader(blob[len(magic):])
    cipher = r.string().decode("ascii", "replace")
    r.string()  # kdf name
    r.string()  # kdf options
    count = r.uint32()
    if count < 1 or count > 16:
        raise DERError("unexpected key count")
    pub = r.string()
    info = ssh_public_blob_info(pub)
    info.kind = "private"
    info.format = "OpenSSH"
    info.encrypted = cipher != "none"
    if info.encrypted:
        info.protection = {"cipher": cipher}
    return info


def ssh_public_blob_info(blob: bytes) -> KeyInfo:
    r = _SSHReader(blob)
    key_type = r.string().decode("ascii", "replace")
    info = KeyInfo(family="Unknown", kind="public", format="SSH", fingerprint=_fp(blob), ssh_type=key_type)
    if key_type == "ssh-rsa":
        r.string()  # e
        info.family, info.key_size = "RSA", _mpint_bits(r.string())
    elif key_type == "ssh-dss":
        info.family, info.key_size = "DSA", _mpint_bits(r.string())
    elif key_type.startswith(("ecdsa-sha2-", "sk-ecdsa-sha2-")):
        curve = key_type.split("-")[-1].split("@")[0]
        info.family = "ECDSA"
        info.curve = {"nistp256": "P-256", "nistp384": "P-384", "nistp521": "P-521"}.get(curve, curve)
    elif key_type in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        info.family = "Ed25519"
    elif key_type == "ssh-ed448":
        info.family = "Ed448"
    else:
        info.family = "Unknown"
    info.oid = None
    return info


def _mpint_bits(value: bytes) -> int:
    return int.from_bytes(value, "big").bit_length()


class _SSHReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def uint32(self) -> int:
        if self.pos + 4 > len(self.data):
            raise DERError("truncated SSH data")
        (v,) = struct.unpack(">I", self.data[self.pos:self.pos + 4])
        self.pos += 4
        return v

    def string(self) -> bytes:
        n = self.uint32()
        if n > len(self.data) - self.pos:
            raise DERError("truncated SSH string")
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v


def ssh_public_line_info(b64: str) -> KeyInfo:
    return ssh_public_blob_info(base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False))


# ---------------------------------------------------------------------------
# Parameters and CSRs
# ---------------------------------------------------------------------------


def dh_params_info(tlv: asn1.TLV) -> KeyInfo:
    parts = asn1.seq(tlv)
    p = asn1.expect(parts[0], asn1.INTEGER).value
    return KeyInfo(family="DH", kind="parameters", format="DH parameters", key_size=asn1.unsigned_bits(p))


def ec_params_info(tlv: asn1.TLV) -> KeyInfo:
    if tlv.is_(asn1.OID):
        c = asn1.oid(tlv)
        return KeyInfo(family="EC", kind="parameters", format="EC parameters", curve=oids.CURVES.get(c, c))
    return KeyInfo(family="EC", kind="parameters", format="EC parameters", curve="explicit parameters")


def csr_info(tlv: asn1.TLV) -> tuple[str, KeyInfo, SignatureInfo]:
    """PKCS#10 CertificationRequest -> subject, public key, signature algorithm."""
    parts = asn1.seq(tlv)
    cri = asn1.seq(parts[0])
    subject = name_string(cri[1])
    key = spki_info(cri[2])
    key.format = "PKCS#10 request"
    sig = signature_info(parts[1], asn1.bit_string(parts[2]) if len(parts) > 2 else b"")
    return subject, key, sig


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


def signature_info(alg_tlv: asn1.TLV, value: bytes) -> SignatureInfo:
    sig_oid, params = asn1.algorithm_identifier(alg_tlv)
    fam, h, ps = oids.SIGNATURE.get(sig_oid, ("Unknown", None, None))
    info = SignatureInfo(family=fam, hash=h, parameter_set=ps if fam not in ("RSA",) else None, oid=sig_oid)
    if fam == "RSA":
        info.padding = "pss" if ps == "RSASSA-PSS" else "pkcs1v15"
        if ps == "RSASSA-PSS":
            info.hash = "SHA-1"  # RFC 4055 default when hashAlgorithm is absent
            if params is not None and params.is_(asn1.SEQUENCE):
                for p in asn1.seq(params):
                    if p.cls == asn1.CONTEXT and p.tag == 0:
                        h_oid, _ = asn1.algorithm_identifier(asn1.parse(p.value))
                        info.hash = oids.DIGEST.get(h_oid, h_oid)
        if value:
            info.key_size = len(value) * 8  # PKCS#1 signatures are exactly as long as the modulus
    return info


def name_string(tlv: asn1.TLV) -> str:
    """RFC 4514-style string, most specific attribute first."""
    rdns = []
    for rdn in asn1.seq(tlv):
        attrs = []
        for atv in rdn.children():
            t, v = asn1.seq(atv)[:2]
            key = oids.NAME_ATTRS.get(asn1.oid(t), asn1.oid(t))
            try:
                val = asn1.string(v)
            except Exception:  # noqa: BLE001 - never fail a scan on an odd name
                val = v.value.hex()
            attrs.append(f"{key}={_escape(val)}")
        rdns.append("+".join(attrs))
    return ",".join(reversed(rdns))


def _escape(value: str) -> str:
    out = value.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+").replace('"', '\\"')
    out = out.replace("<", "\\<").replace(">", "\\>").replace(";", "\\;")
    if out.startswith(("#", " ")):
        out = "\\" + out
    if out.endswith(" "):
        out = out[:-1] + "\\ "
    return "".join(ch if ch.isprintable() else f"\\{ord(ch):02x}" for ch in out)


def common_name(name: str) -> str | None:
    for part in _split_unescaped(name, ","):
        if part.startswith("CN="):
            return part[3:].replace("\\,", ",")
    return None


def _split_unescaped(s: str, sep: str) -> list[str]:
    out, cur, esc = [], [], False
    for ch in s:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == sep:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def certificate_info(tlv: asn1.TLV) -> CertInfo:
    parts = asn1.seq(tlv)
    if len(parts) != 3:
        raise DERError("a certificate has three parts")
    tbs = asn1.seq(parts[0])
    i = 0
    version = 1
    if tbs[0].cls == asn1.CONTEXT and tbs[0].tag == 0:
        version = asn1.integer(asn1.parse(tbs[0].value)) + 1
        i = 1
    serial = asn1.expect(tbs[i], asn1.INTEGER).value.hex()
    issuer = name_string(tbs[i + 2])
    validity = asn1.seq(tbs[i + 3])
    not_before, not_after = asn1.time(validity[0]), asn1.time(validity[1])
    subject = name_string(tbs[i + 4])
    key = spki_info(tbs[i + 5])
    key.format = "X.509"
    sig = signature_info(parts[1], asn1.bit_string(parts[2]))
    cert = CertInfo(subject=subject, issuer=issuer, not_before=not_before, not_after=not_after, serial=serial,
                    sha256=_fp(tlv.raw), key=key, signature=sig, version=version)
    cert.self_signed = subject == issuer
    for ext_holder in tbs[i + 6:]:
        if ext_holder.cls == asn1.CONTEXT and ext_holder.tag == 3:
            _read_extensions(cert, asn1.parse(ext_holder.value))
    if sig.family == "RSA" and cert.self_signed and key.key_size:
        sig.key_size = key.key_size
    if sig.family == "ECDSA" and cert.self_signed and key.curve:
        sig.parameter_set = None
    return cert


def _read_extensions(cert: CertInfo, exts: asn1.TLV) -> None:
    for ext in asn1.seq(exts):
        items = asn1.seq(ext)
        ext_oid = asn1.oid(items[0])
        value = asn1.octet_string(items[-1])
        try:
            if ext_oid == "2.5.29.19":  # basicConstraints
                bc = asn1.seq(asn1.parse(value))
                cert.is_ca = bool(bc and bc[0].is_(asn1.BOOLEAN) and bc[0].value not in (b"", b"\x00"))
            elif ext_oid == "2.5.29.17":  # subjectAltName
                for gn in asn1.seq(asn1.parse(value)):
                    if gn.cls == asn1.CONTEXT and gn.tag == 2:
                        cert.dns_names.append(gn.value.decode("ascii", "replace"))
        except (DERError, IndexError):
            continue
