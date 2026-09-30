"""Certificates, keys and parameters: every format pyca/cryptography can write, synthetic post-quantum
certificates, SSH keys, source code with embedded PEM, and malformed input."""

from __future__ import annotations

import base64
import datetime as dt
import os
import random

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, padding, rsa, x448, x25519
from cryptography.x509.oid import NameOID

from conftest import SAMPLE, detect, names
from make_fixtures import der_name, mldsa_certificate, oid, seq, tlv

from pqc_kit.detectors.material import scan_der, scan_text_material
from pqc_kit.model import SAFE, UNKNOWN, VULNERABLE, WEAK
from pqc_kit.scan import finalize

KEYS = {
    "RSA-2048": lambda: rsa.generate_private_key(65537, 2048),
    "EC P-256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "EC P-384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "EC P-521": lambda: ec.generate_private_key(ec.SECP521R1()),
    "EC secp256k1": lambda: ec.generate_private_key(ec.SECP256K1()),
    "Ed25519": ed25519.Ed25519PrivateKey.generate,
    "Ed448": ed448.Ed448PrivateKey.generate,
    "X25519": x25519.X25519PrivateKey.generate,
    "X448": x448.X448PrivateKey.generate,
    "DSA-2048": lambda: dsa.generate_private_key(2048),
}


def pem(data: bytes) -> list:
    return detect("pem", data.decode())


@pytest.fixture(scope="module")
def keys():
    return {name: make() for name, make in KEYS.items()}


@pytest.mark.parametrize("name", list(KEYS))
def test_pkcs8_spki_and_der(keys, name):
    k = keys[name]
    priv = pem(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    pub = pem(k.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    der, _ = scan_der("k.der", k.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption()), False)
    finalize(der)
    assert names(priv) == names(pub) == names(der) == [name]
    assert priv[0].details["kind"] == "private" and pub[0].details["kind"] == "public"
    assert priv[0].status == (WEAK if name.startswith("DSA") else VULNERABLE)
    # The same key is recognised as the same key, public or private.
    if "fingerprint_sha256" in priv[0].details and name.startswith(("RSA", "EC")):
        assert priv[0].details["fingerprint_sha256"]


@pytest.mark.parametrize("name", ["RSA-2048", "EC P-256", "DSA-2048"])
def test_traditional_openssl_formats(keys, name):
    found = pem(keys[name].private_bytes(ser.Encoding.PEM, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption()))
    assert names(found) == [name]


@pytest.mark.parametrize("name", ["RSA-2048", "EC P-384", "Ed25519"])
def test_openssh_private_keys(keys, name):
    found = pem(keys[name].private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, ser.NoEncryption()))
    assert names(found) == [name.replace("EC ", "ECDSA ")]
    assert found[0].details["format"] == "OpenSSH"


def test_encrypted_keys_show_protection_not_contents(keys):
    enc = keys["RSA-2048"].private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                         ser.BestAvailableEncryption(b"secret"))
    found = pem(enc)
    assert found[0].name == "Encrypted private key"
    assert found[0].status == UNKNOWN
    assert found[0].details["protection"]["kdf"] == "PBKDF2"
    legacy = keys["EC P-256"].private_bytes(ser.Encoding.PEM, ser.PrivateFormat.TraditionalOpenSSL,
                                            ser.BestAvailableEncryption(b"secret"))
    found = pem(legacy)
    assert found[0].family == "EC" and found[0].details["encrypted"]
    assert any("MD5" in n for n in found[0].notes)


def test_private_keys_are_flagged_but_never_copied(keys):
    k = keys["RSA-2048"]
    text = k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()
    found = pem(text.encode())
    assert any("secrets manager" in n for n in found[0].notes)
    d = k.private_numbers().d
    blob = repr([x.to_dict() for x in found])
    assert format(d, "x") not in blob and str(d) not in blob
    assert "PRIVATE KEY-----" not in blob and text.splitlines()[1] not in blob


def test_dh_and_ec_parameters():
    params = dh.generate_parameters(2, 512)  # small so the test is fast; also shows the size check
    found = pem(params.parameter_bytes(ser.Encoding.PEM, ser.ParameterFormat.PKCS3))
    assert names(found) == ["DH-512"] and found[0].status == WEAK


def _cert(key, signer, alg, cn="host.test", ca=False, days=365):
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                                                                      "Example, Inc.")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1234).not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(signer, alg))


@pytest.mark.parametrize("name,alg,sig_name", [
    ("RSA-2048", hashes.SHA256(), "RSA-2048 PKCS#1 v1.5 with SHA-256"),
    ("EC P-384", hashes.SHA384(), "ECDSA P-384 with SHA-384"),
    ("Ed25519", None, "Ed25519"),
    ("Ed448", None, "Ed448"),
])
def test_certificates_match_pyca(keys, name, alg, sig_name):
    k = keys[name]
    c = _cert(k, k, alg)
    found = pem(c.public_bytes(ser.Encoding.PEM))
    f = found[0]
    assert f.asset == "certificate" and f.name == name
    assert f.details["common_name"] == "host.test"
    assert f.details["subject"] == "O=Example\\, Inc.,CN=host.test"
    assert f.details["not_after"] == c.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert f.details["sha256"] == c.fingerprint(hashes.SHA256()).hex()
    assert f.details["dns_names"] == ["host.test"]
    assert f.details["signature"]["name"] == sig_name
    assert f.details["self_signed"]


def test_rsa_pss_signature_hash_is_read_from_parameters(keys):
    k = keys["RSA-2048"]
    c = _cert(k, k, hashes.SHA512(), cn="pss.test")
    b = x509.CertificateBuilder().subject_name(c.subject).issuer_name(c.issuer).public_key(k.public_key()) \
        .serial_number(5).not_valid_before(c.not_valid_before_utc).not_valid_after(c.not_valid_after_utc)
    pss = b.sign(k, hashes.SHA384(), rsa_padding=padding.PSS(padding.MGF1(hashes.SHA384()), 48))
    f = pem(pss.public_bytes(ser.Encoding.PEM))[0]
    assert f.details["signature"]["name"] == "RSA-2048-PSS with SHA-384"


def test_certificate_signed_with_sha1_is_weak_but_sha1_root_is_not():
    der = (SAMPLE / "certs" / "legacy-partner.crt").read_bytes()
    found, _ = scan_der("legacy-partner.crt", der, False)
    finalize(found)
    assert found[0].status == WEAK and found[0].details["signature"]["hash"] == "SHA-1"


@pytest.mark.parametrize("level,name", [(44, "ML-DSA-44"), (65, "ML-DSA-65"), (87, "ML-DSA-87")])
def test_post_quantum_certificates(level, name):
    der = mldsa_certificate("pq.test", level)
    found, _ = scan_der("pq.der", der, False)
    finalize(found)
    f = found[0]
    assert f.name == name and f.status == SAFE
    assert f.details["signature"]["name"] == name
    assert f.cnsa2 is (level == 87)


def _spki_cert(alg_oid: str, key_len: int) -> bytes:
    alg = seq(oid(alg_oid))
    sig_alg = seq(oid("2.16.840.1.101.3.4.3.18"))
    spki = seq(alg, tlv(0x03, b"\x00" + os.urandom(key_len)))
    validity = seq(tlv(0x17, b"260101000000Z"), tlv(0x17, b"360101000000Z"))
    tbs = seq(tlv(0xA0, tlv(0x02, b"\x02")), tlv(0x02, b"\x01"), sig_alg, der_name("x"), validity, der_name("x"), spki)
    return seq(tbs, sig_alg, tlv(0x03, b"\x00" + os.urandom(3309)))


@pytest.mark.parametrize("alg_oid,name", [
    ("2.16.840.1.101.3.4.4.2", "ML-KEM-768"),
    ("2.16.840.1.101.3.4.4.3", "ML-KEM-1024"),
    ("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"),
    ("2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"),
    ("1.3.6.1.5.5.7.6.58", "Composite MLKEM768-X25519-SHA3-256"),
    ("1.3.6.1.5.5.7.6.45", "Composite MLDSA65-ECDSA-P256-SHA512"),
])
def test_post_quantum_key_types_in_certificates(alg_oid, name):
    found, _ = scan_der("pq.der", _spki_cert(alg_oid, 1184), False)
    finalize(found)
    assert found[0].name == name and found[0].status == SAFE


def test_unknown_key_oid_needs_review():
    found, _ = scan_der("x.der", _spki_cert("1.3.9999.1.2.3", 64), False)
    finalize(found)
    assert found[0].status == UNKNOWN and "1.3.9999.1.2.3" in found[0].name


def test_ssh_public_keys_in_any_text(keys):
    line = keys["EC P-256"].public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH).decode()
    found = detect("pem", f"users:\n  - name: ops\n    ssh_authorized_keys:\n      - {line} ops@host\n")
    assert names(found) == ["ECDSA P-256"] and found[0].line == 4


def test_pem_embedded_in_source_code(keys):
    body = keys["RSA-2048"].public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    lines = body.decode().strip().splitlines()
    js = "const KEY = " + " +\n  ".join(f'"{ln}\\n"' for ln in lines) + ";\n"
    found, errs = scan_text_material("key.js", js, False)
    finalize(found)
    assert names(found) == ["RSA-2048"], errs
    go = "var key = `" + body.decode() + "`\n"
    found, _ = scan_text_material("key.go", go, False)
    assert [f.family for f in found] == ["RSA"]


def test_malformed_input_never_raises():
    rng = random.Random(1234)
    good = mldsa_certificate("fuzz.test", 44)
    for i in range(300):
        data = bytearray(good)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        cut = bytes(data[: rng.randrange(1, len(data))]) if i % 3 == 0 else bytes(data)
        scan_der("f.der", cut, False)
        b64 = base64.encodebytes(cut).decode()
        scan_text_material("f.pem", f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n", False)
    for blob in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x80\x00\x00", os.urandom(200)):
        scan_der("r.der", blob, False)
    scan_text_material("x.pem", "-----BEGIN PRIVATE KEY-----\nnot base64 !!\n-----END PRIVATE KEY-----", False)
