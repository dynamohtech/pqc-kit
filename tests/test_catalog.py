"""Classification rules and algorithm-name parsing."""

from __future__ import annotations

import pytest

from pqc_kit.catalog import (
    apply, classify, norm_hash, parse_cipher_suite, parse_jca_cipher, parse_jca_signature, parse_jwt_alg,
    parse_openssl_cipher, parse_pqc_name, parse_tls_version,
)
from pqc_kit.model import OK, RETIRING, SAFE, UNKNOWN, VULNERABLE, WEAK, Finding


def f(family, **kw):
    return classify(Finding(asset=kw.pop("asset", "algorithm"), family=family, path="x", **kw))


@pytest.mark.parametrize("family,kw,status,bits", [
    ("RSA", {"key_size": 1024}, WEAK, 80),
    ("RSA", {"key_size": 2048}, VULNERABLE, 112),
    ("RSA", {"key_size": 3072}, VULNERABLE, 128),
    ("RSA", {"key_size": 4096}, VULNERABLE, 128),
    ("RSA", {}, VULNERABLE, None),
    ("DH", {"key_size": 1024}, WEAK, 80),
    ("DSA", {"key_size": 3072}, WEAK, 128),
    ("ECDSA", {"curve": "P-192"}, WEAK, 96),
    ("ECDSA", {"curve": "P-224"}, VULNERABLE, 112),
    ("ECDSA", {"curve": "prime256v1"}, VULNERABLE, 128),
    ("ECDH", {"curve": "secp384r1"}, VULNERABLE, 192),
    ("Ed25519", {}, VULNERABLE, 128),
    ("X448", {}, VULNERABLE, 224),
])
def test_public_key_status_and_strength(family, kw, status, bits):
    r = f(family, **kw)
    assert r.status == status
    assert r.classical_bits == bits
    assert r.quantum_category == 0
    assert r.cnsa2 is False


def test_nist_dates_depend_on_strength():
    assert any("deprecates it after 2030" in x for x in f("RSA", key_size=2048).reasons)
    assert not any("deprecates it after 2030" in x for x in f("RSA", key_size=3072).reasons)
    assert any("after 2035" in x for x in f("RSA", key_size=3072).reasons)


def test_weak_signature_hash_makes_signature_weak():
    r = f("RSA", key_size=4096, hash="SHA-1", primitive="signature")
    assert r.status == WEAK
    assert r.name == "RSA-4096 with SHA-1"


def test_sha1_in_oaep_is_not_weak_but_retiring():
    r = f("RSA", key_size=3072, padding="oaep", hash="SHA-1", primitive="pke")
    assert r.status == VULNERABLE
    assert any("31 December 2030" in x for x in r.reasons)


def test_key_establishment_reason_mentions_harvest_now():
    r = f("RSA", padding="oaep", primitive="pke")
    assert r.role == "key-establishment"
    assert "harvest now" in r.reasons[0]


@pytest.mark.parametrize("family,kw,status,cnsa2,category", [
    ("ML-KEM", {"parameter_set": "ML-KEM-512"}, SAFE, False, 1),
    ("ML-KEM", {"parameter_set": "ML-KEM-768"}, SAFE, False, 3),
    ("ML-KEM", {"parameter_set": "ML-KEM-1024"}, SAFE, True, 5),
    ("ML-DSA", {"parameter_set": "ML-DSA-44"}, SAFE, False, 2),
    ("ML-DSA", {"parameter_set": "ML-DSA-87"}, SAFE, True, 5),
    ("ML-DSA", {}, SAFE, None, None),
    ("SLH-DSA", {"parameter_set": "SLH-DSA-SHA2-192s"}, SAFE, False, 3),
    ("LMS", {}, SAFE, True, None),
    ("HSS", {}, SAFE, False, None),
    ("XMSS^MT", {}, SAFE, False, None),
    ("Hybrid", {"parameter_set": "X25519MLKEM768"}, SAFE, None, None),
])
def test_post_quantum(family, kw, status, cnsa2, category):
    r = f(family, **kw)
    assert (r.status, r.cnsa2, r.quantum_category) == (status, cnsa2, category)


def test_pre_standard_kyber_is_flagged_to_move():
    r = f("Kyber", parameter_set="Kyber768")
    assert r.status == SAFE
    assert "ML-KEM" in r.reasons[0]


@pytest.mark.parametrize("family,kw,status,cnsa2", [
    ("AES", {"key_size": 128, "mode": "gcm"}, OK, False),
    ("AES", {"key_size": 256, "mode": "gcm"}, OK, True),
    ("AES", {"mode": "gcm"}, OK, None),
    ("AES", {"key_size": 256, "mode": "ecb"}, WEAK, True),
    ("3DES", {"mode": "cbc"}, WEAK, False),
    ("DES", {}, WEAK, False),
    ("RC4", {}, WEAK, False),
    ("Blowfish", {}, WEAK, False),
    ("ChaCha20-Poly1305", {"key_size": 256}, OK, False),
    ("MD5", {}, WEAK, False),
    ("SHA-1", {}, WEAK, False),
    ("SHA-224", {}, RETIRING, False),
    ("SHA-256", {}, OK, False),
    ("SHA-384", {}, OK, True),
    ("HMAC", {"hash": "SHA-1"}, RETIRING, False),
    ("HMAC", {"hash": "MD5"}, WEAK, False),
    ("HMAC", {"hash": "SHA-256"}, OK, False),
    ("PBKDF2", {"hash": "SHA-512"}, OK, None),
    ("scrypt", {}, OK, False),
])
def test_symmetric_and_hashes(family, kw, status, cnsa2):
    r = f(family, **kw)
    assert (r.status, r.cnsa2) == (status, cnsa2)


def test_non_security_md5_is_not_weak():
    r = f("MD5", details={"non_security": True})
    assert r.status == OK
    assert "usedforsecurity=False" in r.reasons[0]


@pytest.mark.parametrize("version,status", [("1.0", WEAK), ("1.1", WEAK), ("1.2", VULNERABLE), ("1.3", UNKNOWN)])
def test_tls_versions(version, status):
    assert f("TLS", version=version, asset="protocol").status == status


def test_ssl3_is_weak():
    assert f("SSL", version="3.0", asset="protocol").status == WEAK


def test_jwt_none_is_weak():
    r = classify(apply(Finding(asset="algorithm", family="", path="x"), parse_jwt_alg("none")))
    assert r.status == WEAK
    assert r.name == "JWT alg=none"


@pytest.mark.parametrize("name,expected", [
    ("aes-256-gcm", ("AES", 256, "gcm")),
    ("aes128", ("AES", 128, "cbc")),
    ("aes-128-ecb", ("AES", 128, "ecb")),
    ("des-ede3-cbc", ("3DES", 168, "cbc")),
    ("des-ede3", ("3DES", 168, "ecb")),
    ("des-cbc", ("DES", 56, "cbc")),
    ("bf-cbc", ("Blowfish", None, "cbc")),
    ("chacha20-poly1305", ("ChaCha20-Poly1305", 256, None)),
    ("id-aes256-wrap", ("AES", 256, "kw")),
    ("camellia-128-cbc", ("Camellia", 128, "cbc")),
])
def test_openssl_cipher_names(name, expected):
    s = parse_openssl_cipher(name)
    assert (s["family"], s.get("key_size"), s.get("mode")) == expected


@pytest.mark.parametrize("name,expected", [
    ("AES/GCM/NoPadding", ("AES", "gcm", None)),
    ("AES", ("AES", "ecb", None)),
    ("AES_256/CBC/PKCS5Padding", ("AES", "cbc", None)),
    ("DESede/CBC/PKCS5Padding", ("3DES", "cbc", None)),
    ("RSA/ECB/PKCS1Padding", ("RSA", None, "pkcs1v15")),
    ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", ("RSA", None, "oaep")),
    ("PBEWithMD5AndDES", ("DES", None, None)),
])
def test_jca_cipher_names(name, expected):
    s = parse_jca_cipher(name)
    assert (s["family"], s.get("mode"), s.get("padding")) == expected


def test_jca_oaep_hash():
    assert parse_jca_cipher("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")["hash"] == "SHA-256"


@pytest.mark.parametrize("name,expected", [
    ("SHA256withRSA", ("RSA", "SHA-256", "pkcs1v15")),
    ("SHA1withDSA", ("DSA", "SHA-1", None)),
    ("SHA384withECDSA", ("ECDSA", "SHA-384", None)),
    ("SHA256withRSA/PSS", ("RSA", "SHA-256", "pss")),
    ("RSASSA-PSS", ("RSA", None, "pss")),
    ("Ed25519", ("Ed25519", None, None)),
    ("ML-DSA-65", ("ML-DSA", None, None)),
    ("SHA3-256withECDSA", ("ECDSA", "SHA3-256", None)),
])
def test_jca_signature_names(name, expected):
    s = parse_jca_signature(name)
    assert (s["family"], s.get("hash"), s.get("padding")) == expected


@pytest.mark.parametrize("name,family,ps", [
    ("ML-KEM-768", "ML-KEM", "ML-KEM-768"),
    ("ml_kem_1024", "ML-KEM", "ML-KEM-1024"),
    ("MLDSA87", "ML-DSA", "ML-DSA-87"),
    ("SLH-DSA-SHAKE-256f", "SLH-DSA", "SLH-DSA-SHAKE-256f"),
    ("X25519MLKEM768", "Hybrid", "X25519MLKEM768"),
    ("SecP256r1MLKEM768", "Hybrid", "SecP256r1MLKEM768"),
    ("Kyber512", "Kyber", "Kyber512"),
    ("Dilithium3", "Dilithium", "Dilithium3"),
])
def test_pqc_names(name, family, ps):
    s = parse_pqc_name(name)
    assert (s["family"], s["parameter_set"]) == (family, ps)


def test_unrelated_names_are_not_pqc():
    for name in ("RSA", "AES", "lmsomething", "hqcx"):
        assert parse_pqc_name(name) is None


@pytest.mark.parametrize("name,expected", [
    ("sha1", "SHA-1"), ("SHA", "SHA-1"), ("sha-256", "SHA-256"), ("RSA-SHA256", "SHA-256"),
    ("sha3_512", "SHA3-512"), ("SHA-512/256", "SHA-512/256"), ("HmacSHA384", "SHA-384"), ("md5", "MD5"),
])
def test_hash_names(name, expected):
    assert norm_hash(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("TLSv1", ("TLS", "1.0")), ("TLSv1.2", ("TLS", "1.2")), ("TLS1_1", ("TLS", "1.1")), ("SSLv3", ("SSL", "3.0")),
    ("TLSv1_method", ("TLS", "1.0")), ("DTLSv1.2", ("DTLS", "1.2")),
])
def test_tls_version_names(name, expected):
    s = parse_tls_version(name)
    assert (s["family"], s["version"]) == expected


def test_cipher_suites():
    assert parse_cipher_suite("TLS_RSA_WITH_RC4_128_SHA")["details"]["suite_status"] == WEAK
    assert parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")["details"]["suite_status"] == VULNERABLE
    assert parse_cipher_suite("TLS_AES_256_GCM_SHA384")["details"]["suite_status"] == OK
