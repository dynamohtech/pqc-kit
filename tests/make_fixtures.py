"""Regenerate the certificate and public-key fixtures in tests/fixtures/sample-app/certs.

Run from the repository root:  python tests/make_fixtures.py
Needs the dev dependency `cryptography`. Only certificates and public keys are
written; private keys stay in memory, so no private key is committed.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).parent / "fixtures" / "sample-app" / "certs"


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                                                                      "Example Bank Ltd")])


def build(subject, issuer, pub, signer, alg, start, end, ca=False, dns=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if dns:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]), critical=False)
    return b.sign(signer, alg)


# --- a minimal DER writer for the synthetic ML-DSA certificate -------------------------------------


def _len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def der_name(cn: str) -> bytes:
    return seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0C, cn.encode()))))


def mldsa_certificate(cn: str, level: int = 65) -> bytes:
    """Structurally valid ML-DSA certificate with random key and signature bytes (not verifiable)."""
    sizes = {44: (17, 1312, 2420), 65: (18, 1952, 3309), 87: (19, 2592, 4627)}
    arc, pk_len, sig_len = sizes[level]
    alg = seq(oid(f"2.16.840.1.101.3.4.3.{arc}"))
    spki = seq(alg, tlv(0x03, b"\x00" + os.urandom(pk_len)))
    validity = seq(tlv(0x17, b"260101000000Z"), tlv(0x18, b"20451231000000Z"))
    tbs = seq(tlv(0xA0, tlv(0x02, b"\x02")), tlv(0x02, b"\x01\x23\x45"), alg, der_name(cn), validity, der_name(cn),
              spki)
    return seq(tbs, alg, tlv(0x03, b"\x00" + os.urandom(sig_len)))


def legacy_sha1_certificate(cn: str) -> bytes:
    """RSA-1024 certificate signed with SHA-1 (the cryptography X.509 builder refuses SHA-1, so sign by hand)."""
    from cryptography.hazmat.primitives.asymmetric import padding

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    alg = seq(oid("1.2.840.113549.1.1.5"), b"\x05\x00")  # sha1WithRSAEncryption
    validity = seq(tlv(0x17, b"200101000000Z"), tlv(0x17, b"300630000000Z"))
    tbs = seq(tlv(0xA0, tlv(0x02, b"\x02")), tlv(0x02, b"\x0a\x0b"), alg, der_name(cn), validity, der_name(cn), spki)
    sig = key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    return seq(tbs, alg, tlv(0x03, b"\x00" + sig))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    start = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = build(name("Example Bank Root CA"), name("Example Bank Root CA"), ca_key.public_key(), ca_key,
               hashes.SHA256(), start, dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc), ca=True)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = build(name("api.example-bank.test"), ca.subject, leaf_key.public_key(), ca_key, hashes.SHA256(), start,
                 dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc), dns=["api.example-bank.test"])
    (OUT / "server-chain.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM)
                                           + ca.public_bytes(serialization.Encoding.PEM))

    (OUT / "legacy-partner.crt").write_bytes(legacy_sha1_certificate("legacy-partner.example-bank.test"))

    import base64
    pq = mldsa_certificate("pq-pilot.example-bank.test")
    body = base64.encodebytes(pq).decode().replace("\n", "")
    pem = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    (OUT / "pq-pilot-mldsa65.pem").write_text(
        "Synthetic ML-DSA-65 certificate for pqc-kit tests: key and signature are random bytes.\n"
        f"-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----\n")

    deploy = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    ops = ed25519.Ed25519PrivateKey.generate().public_key()
    lines = [
        deploy.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        + " deploy@ci",
        ops.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + " ops@bastion",
    ]
    (OUT / "authorized_keys").write_text("\n".join(lines) + "\n")

    signing = ec.generate_private_key(ec.SECP384R1()).public_key()
    (OUT / "webhook-signing.pub.pem").write_bytes(
        signing.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"wrote fixtures to {OUT}")


if __name__ == "__main__":
    main()
