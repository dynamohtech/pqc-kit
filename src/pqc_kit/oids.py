"""Object identifiers for the algorithms found in certificates and keys.

Post-quantum OIDs are from the NIST Computer Security Objects Register
(nistAlgorithms = 2.16.840.1.101.3.4; sigAlgs = .3, kems = .4). Composite
(hybrid) OIDs are the early allocations in the IANA "SMI Security for PKIX
Algorithms" arc (1.3.6.1.5.5.7.6) used by the IETF LAMPS composite drafts; the
drafts are not final, so these may change.
"""

from __future__ import annotations

NIST_SIG = "2.16.840.1.101.3.4.3."
NIST_KEM = "2.16.840.1.101.3.4.4."

# Public-key algorithm OIDs (SubjectPublicKeyInfo / PKCS#8) -> family, parameter set
PUBLIC_KEY: dict[str, tuple[str, str | None]] = {
    "1.2.840.113549.1.1.1": ("RSA", None),
    "1.2.840.113549.1.1.10": ("RSA", "RSASSA-PSS"),
    "1.2.840.113549.1.1.7": ("RSA", "RSAES-OAEP"),
    "2.5.8.1.1": ("RSA", None),  # X.500 rsa
    "1.2.840.10045.2.1": ("EC", None),
    "1.3.132.1.12": ("ECDH", None),  # id-ecDH
    "1.3.132.1.13": ("EC", None),  # id-ecMQV
    "1.2.840.10040.4.1": ("DSA", None),
    "1.3.14.3.2.12": ("DSA", None),
    "1.2.840.10046.2.1": ("DH", None),  # X9.42 dhpublicnumber
    "1.2.840.113549.1.3.1": ("DH", None),  # PKCS#3 dhKeyAgreement
    "1.3.101.110": ("X25519", None),
    "1.3.101.111": ("X448", None),
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
    NIST_KEM + "1": ("ML-KEM", "ML-KEM-512"),
    NIST_KEM + "2": ("ML-KEM", "ML-KEM-768"),
    NIST_KEM + "3": ("ML-KEM", "ML-KEM-1024"),
    NIST_SIG + "17": ("ML-DSA", "ML-DSA-44"),
    NIST_SIG + "18": ("ML-DSA", "ML-DSA-65"),
    NIST_SIG + "19": ("ML-DSA", "ML-DSA-87"),
    "1.2.840.113549.1.9.16.3.17": ("HSS", "HSS/LMS"),  # id-alg-hss-lms-hashsig (RFC 8708)
}

SLH_DSA_SETS = [
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
]
for _i, _name in enumerate(SLH_DSA_SETS):
    PUBLIC_KEY[f"{NIST_SIG}{20 + _i}"] = ("SLH-DSA", _name)
    PUBLIC_KEY[f"{NIST_SIG}{35 + _i}"] = ("SLH-DSA", _name)  # HashSLH-DSA keys
for _i, _name in enumerate(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]):
    PUBLIC_KEY[f"{NIST_SIG}{32 + _i}"] = ("ML-DSA", _name)  # HashML-DSA keys

# FrodoKEM, ISO/IEC 18033-2 arc, as used in the IETF hackathon interoperability artifacts.
for _i, _name in enumerate(["FrodoKEM-976-SHAKE", "FrodoKEM-1344-SHAKE", "eFrodoKEM-976-SHAKE",
                            "eFrodoKEM-1344-SHAKE", "FrodoKEM-976-AES", "FrodoKEM-1344-AES", "eFrodoKEM-976-AES",
                            "eFrodoKEM-1344-AES"]):
    PUBLIC_KEY[f"1.0.18033.2.2.7.{_i + 1}"] = ("FrodoKEM", _name)

# Composite ML-DSA (1.3.6.1.5.5.7.6.37-54) and composite ML-KEM (55-66).
COMPOSITE: dict[str, str] = {
    "1.3.6.1.5.5.7.6.37": "MLDSA44-RSA2048-PSS-SHA256",
    "1.3.6.1.5.5.7.6.38": "MLDSA44-RSA2048-PKCS15-SHA256",
    "1.3.6.1.5.5.7.6.39": "MLDSA44-Ed25519-SHA512",
    "1.3.6.1.5.5.7.6.40": "MLDSA44-ECDSA-P256-SHA256",
    "1.3.6.1.5.5.7.6.41": "MLDSA65-RSA3072-PSS-SHA512",
    "1.3.6.1.5.5.7.6.42": "MLDSA65-RSA3072-PKCS15-SHA512",
    "1.3.6.1.5.5.7.6.43": "MLDSA65-RSA4096-PSS-SHA512",
    "1.3.6.1.5.5.7.6.44": "MLDSA65-RSA4096-PKCS15-SHA512",
    "1.3.6.1.5.5.7.6.45": "MLDSA65-ECDSA-P256-SHA512",
    "1.3.6.1.5.5.7.6.46": "MLDSA65-ECDSA-P384-SHA512",
    "1.3.6.1.5.5.7.6.47": "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
    "1.3.6.1.5.5.7.6.48": "MLDSA65-Ed25519-SHA512",
    "1.3.6.1.5.5.7.6.49": "MLDSA87-ECDSA-P384-SHA512",
    "1.3.6.1.5.5.7.6.50": "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
    "1.3.6.1.5.5.7.6.51": "MLDSA87-Ed448-SHAKE256",
    "1.3.6.1.5.5.7.6.52": "MLDSA87-RSA3072-PSS-SHA512",
    "1.3.6.1.5.5.7.6.53": "MLDSA87-RSA4096-PSS-SHA512",
    "1.3.6.1.5.5.7.6.54": "MLDSA87-ECDSA-P521-SHA512",
    "1.3.6.1.5.5.7.6.55": "MLKEM768-RSA2048-SHA3-256",
    "1.3.6.1.5.5.7.6.56": "MLKEM768-RSA3072-SHA3-256",
    "1.3.6.1.5.5.7.6.57": "MLKEM768-RSA4096-SHA3-256",
    "1.3.6.1.5.5.7.6.58": "MLKEM768-X25519-SHA3-256",
    "1.3.6.1.5.5.7.6.59": "MLKEM768-ECDH-P256-SHA3-256",
    "1.3.6.1.5.5.7.6.60": "MLKEM768-ECDH-P384-SHA3-256",
    "1.3.6.1.5.5.7.6.61": "MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
    "1.3.6.1.5.5.7.6.62": "MLKEM1024-RSA3072-SHA3-256",
    "1.3.6.1.5.5.7.6.63": "MLKEM1024-ECDH-P384-SHA3-256",
    "1.3.6.1.5.5.7.6.64": "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
    "1.3.6.1.5.5.7.6.65": "MLKEM1024-X448-SHA3-256",
    "1.3.6.1.5.5.7.6.66": "MLKEM1024-ECDH-P521-SHA3-256",
}
for _oid, _name in COMPOSITE.items():
    PUBLIC_KEY[_oid] = ("Composite", _name)

CURVES: dict[str, str] = {
    "1.2.840.10045.3.1.1": "P-192",
    "1.3.132.0.33": "P-224",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.3.132.0.31": "secp192k1",
    "1.3.132.0.32": "secp224k1",
    "1.3.132.0.10": "secp256k1",
    "1.3.36.3.3.2.8.1.1.1": "brainpoolP160r1",
    "1.3.36.3.3.2.8.1.1.3": "brainpoolP192r1",
    "1.3.36.3.3.2.8.1.1.5": "brainpoolP224r1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.9": "brainpoolP320r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
    "1.2.156.10197.1.301": "SM2",
    "1.3.132.0.1": "sect163k1",
    "1.3.132.0.15": "sect163r2",
    "1.3.132.0.26": "sect233k1",
    "1.3.132.0.27": "sect233r1",
    "1.3.132.0.16": "sect283k1",
    "1.3.132.0.17": "sect283r1",
    "1.3.132.0.36": "sect409k1",
    "1.3.132.0.37": "sect409r1",
    "1.3.132.0.38": "sect571k1",
    "1.3.132.0.39": "sect571r1",
}

# Signature algorithm OIDs -> (key family, hash, parameter set)
SIGNATURE: dict[str, tuple[str, str | None, str | None]] = {
    "1.2.840.113549.1.1.2": ("RSA", "MD2", None),
    "1.2.840.113549.1.1.3": ("RSA", "MD4", None),
    "1.2.840.113549.1.1.4": ("RSA", "MD5", None),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1", None),
    "1.3.14.3.2.29": ("RSA", "SHA-1", None),
    "1.2.840.113549.1.1.14": ("RSA", "SHA-224", None),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256", None),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384", None),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512", None),
    "1.2.840.113549.1.1.15": ("RSA", "SHA-512/224", None),
    "1.2.840.113549.1.1.16": ("RSA", "SHA-512/256", None),
    "1.2.840.113549.1.1.10": ("RSA", None, "RSASSA-PSS"),  # hash is in the parameters
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1", None),
    "1.2.840.10045.4.3.1": ("ECDSA", "SHA-224", None),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256", None),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384", None),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512", None),
    "1.2.840.10040.4.3": ("DSA", "SHA-1", None),
    "1.3.14.3.2.27": ("DSA", "SHA-1", None),
    NIST_SIG + "1": ("DSA", "SHA-224", None),
    NIST_SIG + "2": ("DSA", "SHA-256", None),
    NIST_SIG + "3": ("DSA", "SHA-384", None),
    NIST_SIG + "4": ("DSA", "SHA-512", None),
    NIST_SIG + "5": ("DSA", "SHA3-224", None),
    NIST_SIG + "6": ("DSA", "SHA3-256", None),
    NIST_SIG + "7": ("DSA", "SHA3-384", None),
    NIST_SIG + "8": ("DSA", "SHA3-512", None),
    NIST_SIG + "9": ("ECDSA", "SHA3-224", None),
    NIST_SIG + "10": ("ECDSA", "SHA3-256", None),
    NIST_SIG + "11": ("ECDSA", "SHA3-384", None),
    NIST_SIG + "12": ("ECDSA", "SHA3-512", None),
    NIST_SIG + "13": ("RSA", "SHA3-224", None),
    NIST_SIG + "14": ("RSA", "SHA3-256", None),
    NIST_SIG + "15": ("RSA", "SHA3-384", None),
    NIST_SIG + "16": ("RSA", "SHA3-512", None),
    "1.3.101.112": ("Ed25519", None, None),
    "1.3.101.113": ("Ed448", None, None),
    "1.2.156.10197.1.501": ("SM2", "SM3", None),
    NIST_SIG + "17": ("ML-DSA", None, "ML-DSA-44"),
    NIST_SIG + "18": ("ML-DSA", None, "ML-DSA-65"),
    NIST_SIG + "19": ("ML-DSA", None, "ML-DSA-87"),
    NIST_SIG + "32": ("ML-DSA", "SHA-512", "ML-DSA-44"),  # HashML-DSA
    NIST_SIG + "33": ("ML-DSA", "SHA-512", "ML-DSA-65"),
    NIST_SIG + "34": ("ML-DSA", "SHA-512", "ML-DSA-87"),
    "1.2.840.113549.1.9.16.3.17": ("HSS", None, "HSS/LMS"),
}
for _i, _name in enumerate(SLH_DSA_SETS):
    SIGNATURE[f"{NIST_SIG}{20 + _i}"] = ("SLH-DSA", None, _name)
_HASH_SLH = ["SHA-256", "SHA-256", "SHA-512", "SHA-512", "SHA-512", "SHA-512",
             "SHAKE128", "SHAKE128", "SHAKE256", "SHAKE256", "SHAKE256", "SHAKE256"]
for _i, (_name, _h) in enumerate(zip(SLH_DSA_SETS, _HASH_SLH)):
    SIGNATURE[f"{NIST_SIG}{35 + _i}"] = ("SLH-DSA", _h, _name)  # HashSLH-DSA
for _oid, _name in COMPOSITE.items():
    if _name.startswith("MLDSA"):
        SIGNATURE[_oid] = ("Composite", None, _name)

DIGEST: dict[str, str] = {
    "1.2.840.113549.2.2": "MD2",
    "1.2.840.113549.2.4": "MD4",
    "1.2.840.113549.2.5": "MD5",
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
    "2.16.840.1.101.3.4.2.4": "SHA-224",
    "2.16.840.1.101.3.4.2.5": "SHA-512/224",
    "2.16.840.1.101.3.4.2.6": "SHA-512/256",
    "2.16.840.1.101.3.4.2.7": "SHA3-224",
    "2.16.840.1.101.3.4.2.8": "SHA3-256",
    "2.16.840.1.101.3.4.2.9": "SHA3-384",
    "2.16.840.1.101.3.4.2.10": "SHA3-512",
    "2.16.840.1.101.3.4.2.11": "SHAKE128",
    "2.16.840.1.101.3.4.2.12": "SHAKE256",
}

HMAC: dict[str, str] = {
    "1.2.840.113549.2.7": "SHA-1",
    "1.2.840.113549.2.8": "SHA-224",
    "1.2.840.113549.2.9": "SHA-256",
    "1.2.840.113549.2.10": "SHA-384",
    "1.2.840.113549.2.11": "SHA-512",
}

# Content-encryption algorithms seen in PBES2 -> (family, key size, mode)
CIPHER: dict[str, tuple[str, int | None, str | None]] = {
    "2.16.840.1.101.3.4.1.1": ("AES", 128, "ecb"),
    "2.16.840.1.101.3.4.1.2": ("AES", 128, "cbc"),
    "2.16.840.1.101.3.4.1.6": ("AES", 128, "gcm"),
    "2.16.840.1.101.3.4.1.21": ("AES", 192, "ecb"),
    "2.16.840.1.101.3.4.1.22": ("AES", 192, "cbc"),
    "2.16.840.1.101.3.4.1.26": ("AES", 192, "gcm"),
    "2.16.840.1.101.3.4.1.41": ("AES", 256, "ecb"),
    "2.16.840.1.101.3.4.1.42": ("AES", 256, "cbc"),
    "2.16.840.1.101.3.4.1.46": ("AES", 256, "gcm"),
    "1.2.840.113549.3.7": ("3DES", 168, "cbc"),
    "1.3.14.3.2.7": ("DES", 56, "cbc"),
    "1.2.840.113549.3.2": ("RC2", None, "cbc"),
}

PBES2 = "1.2.840.113549.1.5.13"
PBKDF2 = "1.2.840.113549.1.5.12"

# Older password-based encryption schemes -> (hash, cipher family, key size)
PBE_LEGACY: dict[str, tuple[str, str, int | None]] = {
    "1.2.840.113549.1.5.1": ("MD2", "DES", 56),
    "1.2.840.113549.1.5.3": ("MD5", "DES", 56),
    "1.2.840.113549.1.5.4": ("MD2", "RC2", 64),
    "1.2.840.113549.1.5.6": ("MD5", "RC2", 64),
    "1.2.840.113549.1.5.10": ("SHA-1", "DES", 56),
    "1.2.840.113549.1.5.11": ("SHA-1", "RC2", 64),
    "1.2.840.113549.1.12.1.1": ("SHA-1", "RC4", 128),
    "1.2.840.113549.1.12.1.2": ("SHA-1", "RC4", 40),
    "1.2.840.113549.1.12.1.3": ("SHA-1", "3DES", 168),
    "1.2.840.113549.1.12.1.4": ("SHA-1", "3DES", 112),
    "1.2.840.113549.1.12.1.5": ("SHA-1", "RC2", 128),
    "1.2.840.113549.1.12.1.6": ("SHA-1", "RC2", 40),
}

# Distinguished-name attribute types, for readable subject and issuer names.
NAME_ATTRS: dict[str, str] = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
    "2.5.4.11": "OU", "2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.17": "postalCode",
    "2.5.4.12": "title", "2.5.4.42": "GN", "2.5.4.4": "SN", "2.5.4.97": "organizationIdentifier",
    "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
    "1.2.840.113549.1.9.1": "emailAddress",
}
