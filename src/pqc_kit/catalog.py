"""What each algorithm is, how strong it is, and what the standards say about it.

classify() turns a detector's raw finding into a status with reasons. The
rules and dates come from these primary sources (see README for links):

- NIST IR 8547, initial public draft (Nov 2024): quantum-vulnerable public-key
  algorithms at 112-bit security deprecated after 2030; all disallowed after 2035.
- NIST SP 800-131A Rev. 2 (2019) and the Rev. 3 initial public draft (Oct 2024).
- FIPS 186-5 (Feb 2023), FIPS 203/204/205 (Aug 2024), NIST SP 800-208, SP 800-57 Part 1.
- NSA CNSA 2.0 algorithm list (CNSA 2.0 FAQ, Ver. 2.1, Dec 2024).
"""

from __future__ import annotations

import re

from pqc_kit.model import (
    CERTIFICATE, KEY, OK, PROTOCOL, RETIRING, SAFE, UNKNOWN, VULNERABLE, WEAK, Finding, worst,
)

# ---------------------------------------------------------------------------
# Families
# ---------------------------------------------------------------------------

ASYMMETRIC = {"RSA", "DSA", "DH", "EC", "ECDSA", "ECDH", "EdDSA", "Ed25519", "Ed448", "X25519", "X448",
              "SM2", "ElGamal", "ECIES", "ECMQV", "Signature"}
PQC = {"ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "HSS", "XMSS", "XMSS^MT", "FN-DSA", "HQC", "Kyber", "Dilithium",
       "SPHINCS+", "Falcon", "FrodoKEM", "Classic-McEliece", "BIKE", "NTRU", "Composite", "Hybrid"}
PRE_STANDARD = {"Kyber": "ML-KEM (FIPS 203)", "Dilithium": "ML-DSA (FIPS 204)", "SPHINCS+": "SLH-DSA (FIPS 205)",
                "Falcon": "FN-DSA (FIPS 206, not yet published)"}
NOT_YET_STANDARD = {"FN-DSA", "HQC", "FrodoKEM", "Classic-McEliece", "BIKE", "NTRU"}
SYMMETRIC_OK = {"AES", "ChaCha20", "ChaCha20-Poly1305", "XChaCha20-Poly1305", "Camellia", "SM4", "ARIA", "SEED",
                "Twofish", "Serpent", "Salsa20", "XSalsa20", "BlockCipher"}
NIST_SYMMETRIC = {"AES"}
SYMMETRIC_WEAK = {"DES", "3DES", "RC4", "RC2", "Blowfish", "CAST5", "IDEA", "TEA", "XTEA", "Skipjack", "RC5"}
HASHES = {"MD2", "MD4", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
          "Keccak-256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256", "BLAKE2b", "BLAKE2s", "BLAKE3",
          "RIPEMD-160", "SM3", "Whirlpool"}
MACS = {"HMAC", "CMAC", "GMAC", "Poly1305", "KMAC128", "KMAC256"}
KDFS = {"PBKDF2", "HKDF", "scrypt", "bcrypt", "Argon2", "ConcatKDF", "X963KDF", "KBKDF", "EVP_BytesToKey"}
PROTOCOLS = {"TLS", "SSL", "DTLS", "TLS-CipherSuite"}

BROKEN_HASHES = {"MD2", "MD4", "MD5", "SHA-1"}
HASHES_224 = {"SHA-224", "SHA-512/224", "SHA3-224"}

KEY_ESTABLISHMENT_FAMILIES = {"DH", "ECDH", "X25519", "X448", "ECIES", "ECMQV", "ML-KEM", "Kyber", "HQC",
                              "FrodoKEM", "Classic-McEliece", "BIKE", "NTRU", "Hybrid"}
SIGNATURE_FAMILIES = {"DSA", "ECDSA", "EdDSA", "Ed25519", "Ed448", "ML-DSA", "SLH-DSA", "LMS", "HSS", "XMSS",
                      "XMSS^MT", "FN-DSA", "Dilithium", "SPHINCS+", "Falcon", "Signature"}

# SP 800-57 Part 1 Rev. 5, Table 2 (IFC/FFC modulus size -> bits of security), rounded down to the table.
_IFC_FFC = [(15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80)]

CURVE_BITS = {
    "P-192": 96, "P-224": 112, "P-256": 128, "P-384": 192, "P-521": 256,
    "secp192k1": 96, "secp224k1": 112, "secp256k1": 128,
    "brainpoolP160r1": 80, "brainpoolP192r1": 96, "brainpoolP224r1": 112, "brainpoolP256r1": 128,
    "brainpoolP320r1": 160, "brainpoolP384r1": 192, "brainpoolP512r1": 256,
    "Curve25519": 128, "Curve448": 224, "SM2": 128,
    "sect163k1": 80, "sect163r2": 80, "sect233k1": 112, "sect233r1": 112, "sect283k1": 128, "sect283r1": 128,
    "sect409k1": 192, "sect409r1": 192, "sect571k1": 256, "sect571r1": 256,
}
FAMILY_BITS = {"Ed25519": 128, "X25519": 128, "Ed448": 224, "X448": 224}

# NIST IR 8547 ipd, Table 7 (collision resistance) and Table 1 categories.
HASH_BITS = {"SHA-1": 80, "SHA-224": 112, "SHA-512/224": 112, "SHA3-224": 112, "SHA-256": 128, "SHA-512/256": 128,
             "SHA3-256": 128, "SHAKE128": 128, "SHA-384": 192, "SHA3-384": 192, "SHA-512": 256, "SHA3-512": 256,
             "SHAKE256": 256}
HASH_CATEGORY = {"SHA-1": 0, "SHA-224": 0, "SHA-512/224": 0, "SHA3-224": 0, "SHA-256": 2, "SHA-512/256": 2,
                 "SHA3-256": 2, "SHAKE128": 2, "SHA-384": 4, "SHA3-384": 4, "SHA-512": 5, "SHA3-512": 5, "SHAKE256": 5}

# FIPS 203 / 204 / 205 security categories (also NIST IR 8547 ipd Tables 3 and 5).
PQC_CATEGORY = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5, "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}

CNSA2_PARAMETER_SETS = {"ML-KEM-1024", "ML-DSA-87"}

# ---------------------------------------------------------------------------
# Name normalisation
# ---------------------------------------------------------------------------

_HASH_ALIASES = {
    "md2": "MD2", "md4": "MD4", "md5": "MD5", "sha": "SHA-1", "sha1": "SHA-1", "sha-1": "SHA-1",
    "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
    "sha512224": "SHA-512/224", "sha512256": "SHA-512/256",
    "sha3224": "SHA3-224", "sha3256": "SHA3-256", "sha3384": "SHA3-384", "sha3512": "SHA3-512",
    "shake128": "SHAKE128", "shake256": "SHAKE256",
    "blake2b": "BLAKE2b", "blake2b512": "BLAKE2b", "blake2s": "BLAKE2s", "blake2s256": "BLAKE2s", "blake3": "BLAKE3",
    "ripemd160": "RIPEMD-160", "rmd160": "RIPEMD-160", "ripemd": "RIPEMD-160", "sm3": "SM3", "whirlpool": "Whirlpool",
}


def norm_hash(name: str | None) -> str | None:
    if not name:
        return None
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    key = key.removeprefix("rsa").removeprefix("hmac")
    return _HASH_ALIASES.get(key)


_CURVE_ALIASES = {
    "p192": "P-192", "prime192v1": "P-192", "secp192r1": "P-192", "nistp192": "P-192",
    "p224": "P-224", "secp224r1": "P-224", "nistp224": "P-224",
    "p256": "P-256", "prime256v1": "P-256", "secp256r1": "P-256", "nistp256": "P-256",
    "p384": "P-384", "secp384r1": "P-384", "nistp384": "P-384",
    "p521": "P-521", "secp521r1": "P-521", "nistp521": "P-521",
    "secp192k1": "secp192k1", "secp224k1": "secp224k1", "secp256k1": "secp256k1", "k256": "secp256k1",
    "curve25519": "Curve25519", "x25519": "Curve25519", "ed25519": "Curve25519",
    "curve448": "Curve448", "x448": "Curve448", "ed448": "Curve448", "sm2": "SM2",
}
for _c in CURVE_BITS:
    _CURVE_ALIASES.setdefault(re.sub(r"[^a-z0-9]", "", _c.lower()), _c)


def norm_curve(name: str | None) -> str | None:
    if not name:
        return None
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    return _CURVE_ALIASES.get(key, name)


def curve_from_size(bits: int | None) -> str | None:
    return {192: "P-192", 224: "P-224", 256: "P-256", 384: "P-384", 521: "P-521"}.get(bits or 0)


_BLOCK = {"aes": "AES", "des": "DES", "desede": "3DES", "tripledes": "3DES", "3des": "3DES", "des3": "3DES",
          "tdea": "3DES", "desede3": "3DES", "blowfish": "Blowfish", "bf": "Blowfish", "rc2": "RC2", "arc2": "RC2",
          "rc4": "RC4", "arcfour": "RC4", "arc4": "RC4", "cast": "CAST5", "cast5": "CAST5", "cast128": "CAST5",
          "idea": "IDEA", "camellia": "Camellia", "aria": "ARIA", "sm4": "SM4", "seed": "SEED",
          "chacha20": "ChaCha20", "chacha20poly1305": "ChaCha20-Poly1305", "xchacha20poly1305": "XChaCha20-Poly1305",
          "twofish": "Twofish", "serpent": "Serpent", "salsa20": "Salsa20", "xsalsa20": "XSalsa20", "tea": "TEA",
          "xtea": "XTEA", "rc5": "RC5", "skipjack": "Skipjack"}
_MODES = {"ecb", "cbc", "cfb", "cfb1", "cfb8", "cfb128", "ofb", "ctr", "gcm", "ccm", "ocb", "xts", "siv", "gcmsiv",
          "kw", "kwp", "wrap", "pcbc", "cts", "eax", "cbc-cts", "gcm-siv"}


def norm_cipher(name: str | None) -> str | None:
    if not name:
        return None
    return _BLOCK.get(re.sub(r"[^a-z0-9]", "", name.lower()))


def parse_openssl_cipher(name: str) -> dict | None:
    """OpenSSL / Node.js cipher names: aes-256-gcm, aes128, des-ede3-cbc, bf-cbc, chacha20-poly1305 ..."""
    n = name.strip().lower().removeprefix("id-")
    if not n:
        return None
    if n in ("chacha20-poly1305", "chacha20poly1305"):
        return {"family": "ChaCha20-Poly1305", "key_size": 256, "primitive": "ae"}
    if n == "chacha20":
        return {"family": "ChaCha20", "key_size": 256, "primitive": "stream-cipher"}
    if n.startswith("rc4"):
        m = re.match(r"rc4(?:-(\d+))?", n)
        return {"family": "RC4", "key_size": int(m.group(1)) if m and m.group(1) else None, "primitive": "stream-cipher"}
    if n.startswith("des-ede3") or n in ("des3", "des-ede3", "3des"):
        mode = n.split("-")[-1] if n.count("-") >= 2 else ("ecb" if n == "des-ede3" else "cbc")
        return {"family": "3DES", "key_size": 168, "mode": _mode(mode) or "cbc", "primitive": "block-cipher"}
    if n.startswith("des-ede"):
        mode = n.split("-")[-1] if n.count("-") >= 2 else "ecb"
        return {"family": "3DES", "key_size": 112, "mode": _mode(mode) or "ecb", "primitive": "block-cipher"}
    m = re.match(r"(aes|aria|camellia)-?(128|192|256)(?:-(\w+))?(?:-(\w+))?$", n)
    if m:
        fam = {"aes": "AES", "aria": "ARIA", "camellia": "Camellia"}[m.group(1)]
        mode = m.group(3) or "cbc"
        if mode == "wrap" or (m.group(4) or "") == "wrap":
            mode = "kw"
        md = _mode(mode)
        return {"family": fam, "key_size": int(m.group(2)), "mode": md,
                "primitive": "ae" if md in ("gcm", "ccm", "ocb", "siv", "gcm-siv") else "block-cipher"}
    m = re.match(r"aes(128|192|256)-?(wrap|wrap-pad)$", n)
    if m:
        return {"family": "AES", "key_size": int(m.group(1)), "mode": "kw", "primitive": "block-cipher"}
    m = re.match(r"(des|bf|blowfish|cast5?|idea|rc2|seed|sm4)(?:-(\d+))?(?:-(\w+))?$", n)
    if m:
        fam = norm_cipher(m.group(1))
        size = int(m.group(2)) if m.group(2) else {"DES": 56}.get(fam or "")
        mode = _mode(m.group(3)) or "cbc"
        if fam == "DES" and n == "des":
            mode = "cbc"
        return {"family": fam, "key_size": size, "mode": mode, "primitive": "block-cipher"}
    return None


def _mode(mode: str | None) -> str | None:
    if not mode:
        return None
    m = mode.lower().replace("_", "-")
    if m.startswith("cfb"):
        return "cfb"
    if m in ("wrap", "kw", "kwp", "wrap-pad"):
        return "kw"
    return m if m in _MODES else None


def parse_jca_cipher(transformation: str) -> dict | None:
    """javax.crypto.Cipher transformations: "AES/GCM/NoPadding", "DESede", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"."""
    parts = transformation.strip().split("/")
    alg = parts[0]
    mode = parts[1] if len(parts) > 1 else None
    padding = parts[2] if len(parts) > 2 else None
    low = alg.lower()
    if low.startswith("pbewith"):
        return parse_pbe_name(alg)
    if low in ("rsa", "rsa/ecb") or low.startswith("rsa"):
        out = {"family": "RSA", "primitive": "pke", "functions": ["encrypt", "decrypt"]}
        pad = (padding or "").lower()
        if "oaep" in pad:
            out["padding"] = "oaep"
            m = re.search(r"oaepwith(.+?)andmgf1", pad)
            if m:
                out["hash"] = norm_hash(m.group(1))
        elif "pkcs1" in pad:
            out["padding"] = "pkcs1v15"
        elif pad == "nopadding":
            out["padding"] = "raw"
        return out
    if low in ("ecies",):
        return {"family": "ECIES", "primitive": "pke"}
    m = re.match(r"(aes|aria|camellia)_?(128|192|256)?$", low)
    if m:
        fam = {"aes": "AES", "aria": "ARIA", "camellia": "Camellia"}[m.group(1)]
        out = {"family": fam, "primitive": "block-cipher"}
        if m.group(2):
            out["key_size"] = int(m.group(2))
    elif low in ("aeswrap", "aeswrappad") or re.match(r"aeswrap(pad)?_(128|192|256)", low):
        size = re.search(r"(128|192|256)", low)
        return {"family": "AES", "mode": "kw", "primitive": "block-cipher",
                "key_size": int(size.group(1)) if size else None}
    elif low in ("chacha20-poly1305",):
        return {"family": "ChaCha20-Poly1305", "key_size": 256, "primitive": "ae"}
    elif low == "chacha20":
        return {"family": "ChaCha20", "key_size": 256, "primitive": "stream-cipher"}
    else:
        fam = norm_cipher(low)
        if not fam:
            return None
        out = {"family": fam, "primitive": "stream-cipher" if fam == "RC4" else "block-cipher"}
        if fam == "DES":
            out["key_size"] = 56
    if out["primitive"] == "block-cipher":
        if mode is None:
            # SunJCE and SunPKCS11 default to ECB when the mode is omitted (JDK Providers documentation).
            out["mode"] = "ecb"
            out["notes"] = ["No mode given: the SunJCE provider defaults to ECB."]
        else:
            out["mode"] = _mode(mode) or mode.lower()
        if out.get("mode") in ("gcm", "ccm"):
            out["primitive"] = "ae"
    return out


def parse_pbe_name(name: str) -> dict | None:
    """PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithHmacSHA256AndAES_256, PBKDF2WithHmacSHA1 ..."""
    low = name.lower()
    m = re.match(r"pbkdf2withhmac(sha[\w-]*?)(?:and8bit)?$", low)
    if m:
        return {"family": "PBKDF2", "hash": norm_hash(m.group(1)), "primitive": "kdf", "functions": ["keyderive"]}
    m = re.match(r"pbewith(?:hmac)?(md5|sha1|sha|sha224|sha256|sha384|sha512(?:/2(?:24|56))?)and(\w+?)(?:_(\d+))?$", low)
    if not m:
        return {"family": "PBKDF2", "primitive": "kdf"} if low.startswith("pbkdf2") else None
    cipher = m.group(2)
    size = int(m.group(3)) if m.group(3) else None
    fam = {"des": "DES", "desede": "3DES", "tripledes": "3DES", "rc2": "RC2", "rc4": "RC4", "aes": "AES"}.get(
        re.sub(r"\d+$", "", cipher) if cipher.startswith("rc") else cipher)
    if cipher.startswith("rc2") or cipher.startswith("rc4"):
        digits = re.search(r"(\d+)$", cipher)
        if digits and digits.group(1) not in ("2", "4"):
            size = int(digits.group(1))
    return {"family": fam or "PBE", "hash": norm_hash(m.group(1)), "key_size": size, "primitive": "block-cipher",
            "functions": ["encrypt", "decrypt"], "notes": [f"Password-based encryption ({name})."]}


def parse_jca_signature(name: str) -> dict | None:
    """java.security.Signature names: SHA256withRSA, SHA1withDSA, SHA384withECDSA, RSASSA-PSS, Ed25519, ML-DSA-65."""
    n = name.strip()
    low = n.lower()
    pq = parse_pqc_name(n)
    if pq:
        return pq
    if low in ("rsassa-pss", "rsapss"):
        return {"family": "RSA", "padding": "pss", "primitive": "signature", "functions": ["sign", "verify"]}
    if low in ("ed25519", "ed448", "eddsa"):
        return {"family": {"ed25519": "Ed25519", "ed448": "Ed448", "eddsa": "EdDSA"}[low], "primitive": "signature",
                "functions": ["sign", "verify"]}
    m = re.match(r"(\w[\w-]*?)with(rsa|ecdsa|dsa|ecnr|plain-ecdsa|sm2|rsaandmgf1|rsa/pss|rsa/iso9796-2)"
                 r"(?:inp1363format)?(?:/pss)?$", low.replace("/pss", "/pss"))
    if m:
        hash_ = None if m.group(1) == "none" else norm_hash(m.group(1))
        key = m.group(2)
        fam = {"rsa": "RSA", "ecdsa": "ECDSA", "plain-ecdsa": "ECDSA", "dsa": "DSA", "sm2": "SM2"}.get(
            key, "RSA" if key.startswith("rsa") else "ECDSA")
        out = {"family": fam, "hash": hash_, "primitive": "signature", "functions": ["sign", "verify"]}
        if fam == "RSA":
            out["padding"] = "pss" if ("pss" in low or "mgf1" in low) else "pkcs1v15"
        return out
    return None


def parse_pqc_name(name: str) -> dict | None:
    """ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s, Kyber768, Dilithium3, sphincs+, falcon-512, X25519MLKEM768 ..."""
    n = name.strip()
    low = re.sub(r"[\s_]", "-", n.lower())
    compact = low.replace("-", "")
    m = re.match(r"mlkem(512|768|1024)?$", compact)
    if m:
        ps = f"ML-KEM-{m.group(1)}" if m.group(1) else None
        return {"family": "ML-KEM", "parameter_set": ps, "primitive": "kem",
                "functions": ["keygen", "encapsulate", "decapsulate"]}
    m = re.match(r"(?:hash)?mldsa(44|65|87)?$", compact)
    if m:
        return {"family": "ML-DSA", "parameter_set": f"ML-DSA-{m.group(1)}" if m.group(1) else None,
                "primitive": "signature", "functions": ["sign", "verify"]}
    m = re.match(r"slhdsa(sha2|shake)?(128|192|256)?([sf])?$", compact)
    if m:
        ps = None
        if m.group(1) and m.group(2) and m.group(3):
            ps = f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}{m.group(3)}"
        return {"family": "SLH-DSA", "parameter_set": ps, "primitive": "signature", "functions": ["sign", "verify"]}
    m = re.match(r"(x25519|secp256r1|p256|secp384r1|p384|x448)mlkem(512|768|1024)$", compact)
    if m:
        classical = {"x25519": "X25519", "secp256r1": "P-256", "p256": "P-256", "secp384r1": "P-384",
                     "p384": "P-384", "x448": "X448"}[m.group(1)]
        return {"family": "Hybrid", "parameter_set": f"{n}", "primitive": "kem",
                "notes": [f"Hybrid key exchange: ML-KEM-{m.group(2)} combined with {classical}."],
                "details": {"pq": f"ML-KEM-{m.group(2)}", "classical": classical}}
    m = re.match(r"(?:kyber)(512|768|1024)$", compact)
    if m:
        return {"family": "Kyber", "parameter_set": f"Kyber{m.group(1)}", "primitive": "kem"}
    m = re.match(r"dilithium([235])(?:aes)?$", compact)
    if m:
        return {"family": "Dilithium", "parameter_set": f"Dilithium{m.group(1)}", "primitive": "signature"}
    m = re.match(r"(?:falcon|fndsa)(?:padded)?(512|1024)?$", compact)
    if m and ("falcon" in compact or "fndsa" in compact):
        fam = "FN-DSA" if "fndsa" in compact else "Falcon"
        return {"family": fam, "parameter_set": f"{fam}-{m.group(1)}" if m.group(1) else None,
                "primitive": "signature"}
    if compact.startswith("sphincs"):
        return {"family": "SPHINCS+", "parameter_set": n, "primitive": "signature"}
    if re.match(r"hqc(128|192|256)?$", compact):
        return {"family": "HQC", "parameter_set": n.upper() if compact != "hqc" else None, "primitive": "kem"}
    if compact.startswith("frodokem"):
        return {"family": "FrodoKEM", "parameter_set": n, "primitive": "kem"}
    if compact.startswith("classicmceliece"):
        return {"family": "Classic-McEliece", "parameter_set": n, "primitive": "kem"}
    if re.match(r"bikel[135]$", compact):
        return {"family": "BIKE", "parameter_set": n, "primitive": "kem"}
    if compact in ("hsslms", "hss", "lms") or compact.startswith("lmssha256") or compact.startswith("lms-"):
        return {"family": "HSS" if compact.startswith("hss") else "LMS", "primitive": "signature",
                "parameter_set": None}
    if compact.startswith("xmssmt"):
        return {"family": "XMSS^MT", "primitive": "signature"}
    if compact.startswith("xmss"):
        return {"family": "XMSS", "primitive": "signature"}
    return None


def parse_key_algorithm(name: str) -> dict | None:
    """Key-pair / key-agreement / key-factory names: RSA, EC, DSA, DH, XDH, X25519, Ed25519, ML-KEM-768 ..."""
    n = name.strip()
    low = n.lower()
    pq = parse_pqc_name(n)
    if pq:
        return pq
    table = {
        "rsa": ("RSA", "unknown"), "rsassa-pss": ("RSA", "signature"), "rsa-pss": ("RSA", "signature"),
        "dsa": ("DSA", "signature"), "dh": ("DH", "key-agree"), "diffiehellman": ("DH", "key-agree"),
        "ec": ("EC", "unknown"), "ecdsa": ("ECDSA", "signature"), "ecdh": ("ECDH", "key-agree"),
        "ecmqv": ("ECMQV", "key-agree"),
        "xdh": ("ECDH", "key-agree"), "x25519": ("X25519", "key-agree"), "x448": ("X448", "key-agree"),
        "eddsa": ("EdDSA", "signature"), "ed25519": ("Ed25519", "signature"), "ed448": ("Ed448", "signature"),
        "sm2": ("SM2", "unknown"), "elgamal": ("ElGamal", "pke"),
    }
    if low in table:
        fam, prim = table[low]
        out = {"family": fam, "primitive": prim}
        if fam == "RSA" and "pss" in low:
            out["padding"] = "pss"
        return out
    return None


def parse_digest(name: str) -> dict | None:
    h = norm_hash(name)
    if h:
        return {"family": h, "primitive": "xof" if h.startswith("SHAKE") else "hash", "functions": ["digest"]}
    return None


def parse_mac(name: str) -> dict | None:
    """HmacSHA256, HMAC-SHA1, hmacWithSHA256, CMAC, Poly1305, KMAC256, AESCMAC ..."""
    low = name.strip().lower()
    m = re.match(r"hmac(?:with)?[-_]?(.+)$", low)
    if m:
        return {"family": "HMAC", "hash": norm_hash(m.group(1)), "primitive": "mac", "functions": ["tag"]}
    if "cmac" in low:
        return {"family": "CMAC", "primitive": "mac"}
    if low.startswith("kmac"):
        return {"family": "KMAC256" if "256" in low else "KMAC128", "primitive": "mac"}
    if "poly1305" in low:
        return {"family": "Poly1305", "primitive": "mac"}
    if "gmac" in low:
        return {"family": "GMAC", "primitive": "mac"}
    return None


_TLS_VERSIONS = {
    "sslv2": ("SSL", "2.0"), "ssl2": ("SSL", "2.0"), "sslv3": ("SSL", "3.0"), "ssl3": ("SSL", "3.0"),
    "ssl30": ("SSL", "3.0"), "sslv30": ("SSL", "3.0"), "tlsv1": ("TLS", "1.0"), "tls1": ("TLS", "1.0"), "tlsv10": ("TLS", "1.0"),
    "tls10": ("TLS", "1.0"), "tlsv11": ("TLS", "1.1"), "tls11": ("TLS", "1.1"), "tlsv12": ("TLS", "1.2"),
    "tls12": ("TLS", "1.2"), "tlsv13": ("TLS", "1.3"), "tls13": ("TLS", "1.3"), "dtlsv1": ("DTLS", "1.0"),
    "dtls1": ("DTLS", "1.0"), "dtlsv10": ("DTLS", "1.0"), "dtlsv12": ("DTLS", "1.2"), "dtls12": ("DTLS", "1.2"),
    "dtlsv13": ("DTLS", "1.3"), "dtls13": ("DTLS", "1.3"),
}


def parse_tls_version(name: str) -> dict | None:
    key = re.sub(r"[^a-z0-9]", "", name.lower()).removesuffix("method").removesuffix("client").removesuffix("server")
    if key in _TLS_VERSIONS:
        fam, ver = _TLS_VERSIONS[key]
        return {"family": fam, "version": ver}
    return None


def parse_cipher_suite(name: str) -> dict | None:
    """TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_RSA_WITH_RC4_128_SHA ..."""
    n = name.strip().upper()
    if not n.startswith(("TLS_", "SSL_")):
        return None
    m = re.match(r"(?:TLS|SSL)_(\w+?)_WITH_(\w+)$", n)
    kx, bulk = (m.group(1), m.group(2)) if m else (None, n[4:])
    notes = []
    status = OK
    if kx is None:  # TLS 1.3 suites carry only the symmetric part
        version = "1.3"
    else:
        version = None
        status = VULNERABLE
        if kx.startswith("RSA") and "PSK" not in kx:
            notes.append("RSA key transport: no forward secrecy.")
        if "EXPORT" in kx or "ANON" in kx or kx.startswith("NULL"):
            status = WEAK
    if re.search(r"RC4|DES|NULL|EXPORT|MD5|RC2|IDEA", bulk) or (kx and "ANON" in kx):
        status = WEAK
    return {"family": "TLS-CipherSuite", "parameter_set": n, "version": version,
            "details": {"suite_status": status}, "notes": notes}


JWT_ALGS = {
    "HS256": {"family": "HMAC", "hash": "SHA-256", "primitive": "mac"},
    "HS384": {"family": "HMAC", "hash": "SHA-384", "primitive": "mac"},
    "HS512": {"family": "HMAC", "hash": "SHA-512", "primitive": "mac"},
    "RS256": {"family": "RSA", "hash": "SHA-256", "padding": "pkcs1v15", "primitive": "signature"},
    "RS384": {"family": "RSA", "hash": "SHA-384", "padding": "pkcs1v15", "primitive": "signature"},
    "RS512": {"family": "RSA", "hash": "SHA-512", "padding": "pkcs1v15", "primitive": "signature"},
    "PS256": {"family": "RSA", "hash": "SHA-256", "padding": "pss", "primitive": "signature"},
    "PS384": {"family": "RSA", "hash": "SHA-384", "padding": "pss", "primitive": "signature"},
    "PS512": {"family": "RSA", "hash": "SHA-512", "padding": "pss", "primitive": "signature"},
    "ES256": {"family": "ECDSA", "curve": "P-256", "hash": "SHA-256", "primitive": "signature"},
    "ES384": {"family": "ECDSA", "curve": "P-384", "hash": "SHA-384", "primitive": "signature"},
    "ES512": {"family": "ECDSA", "curve": "P-521", "hash": "SHA-512", "primitive": "signature"},
    "ES256K": {"family": "ECDSA", "curve": "secp256k1", "hash": "SHA-256", "primitive": "signature"},
    "EdDSA": {"family": "EdDSA", "primitive": "signature"},
    "Ed25519": {"family": "Ed25519", "primitive": "signature"},
    "Ed448": {"family": "Ed448", "primitive": "signature"},
    "none": {"family": "JWT-none", "primitive": "signature"},
    "RSA1_5": {"family": "RSA", "padding": "pkcs1v15", "primitive": "pke"},
    "RSA-OAEP": {"family": "RSA", "padding": "oaep", "hash": "SHA-1", "primitive": "pke"},
    "RSA-OAEP-256": {"family": "RSA", "padding": "oaep", "hash": "SHA-256", "primitive": "pke"},
    "ECDH-ES": {"family": "ECDH", "primitive": "key-agree"},
    "A128KW": {"family": "AES", "key_size": 128, "mode": "kw", "primitive": "block-cipher"},
    "A192KW": {"family": "AES", "key_size": 192, "mode": "kw", "primitive": "block-cipher"},
    "A256KW": {"family": "AES", "key_size": 256, "mode": "kw", "primitive": "block-cipher"},
    "A128GCM": {"family": "AES", "key_size": 128, "mode": "gcm", "primitive": "ae"},
    "A192GCM": {"family": "AES", "key_size": 192, "mode": "gcm", "primitive": "ae"},
    "A256GCM": {"family": "AES", "key_size": 256, "mode": "gcm", "primitive": "ae"},
    "ML-DSA-44": {"family": "ML-DSA", "parameter_set": "ML-DSA-44", "primitive": "signature"},
    "ML-DSA-65": {"family": "ML-DSA", "parameter_set": "ML-DSA-65", "primitive": "signature"},
    "ML-DSA-87": {"family": "ML-DSA", "parameter_set": "ML-DSA-87", "primitive": "signature"},
}
for _k in ("ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"):
    JWT_ALGS[_k] = {"family": "ECDH", "primitive": "key-agree"}
JWT_ALG_PATTERN = "|".join(sorted((re.escape(k) for k in JWT_ALGS), key=len, reverse=True))


def parse_jwt_alg(name: str) -> dict | None:
    spec = JWT_ALGS.get(name.strip())
    if not spec:
        return None
    out = dict(spec)
    out["notes"] = [f"JWT/JOSE algorithm {name.strip()}."]
    return out


WEBCRYPTO = {
    "RSA-OAEP": {"family": "RSA", "padding": "oaep", "primitive": "pke"},
    "RSA-PSS": {"family": "RSA", "padding": "pss", "primitive": "signature"},
    "RSASSA-PKCS1-v1_5": {"family": "RSA", "padding": "pkcs1v15", "primitive": "signature"},
    "ECDSA": {"family": "ECDSA", "primitive": "signature"},
    "ECDH": {"family": "ECDH", "primitive": "key-agree"},
    "Ed25519": {"family": "Ed25519", "primitive": "signature"},
    "Ed448": {"family": "Ed448", "primitive": "signature"},
    "X25519": {"family": "X25519", "primitive": "key-agree"},
    "X448": {"family": "X448", "primitive": "key-agree"},
    "AES-GCM": {"family": "AES", "mode": "gcm", "primitive": "ae"},
    "AES-CBC": {"family": "AES", "mode": "cbc", "primitive": "block-cipher"},
    "AES-CTR": {"family": "AES", "mode": "ctr", "primitive": "block-cipher"},
    "AES-KW": {"family": "AES", "mode": "kw", "primitive": "block-cipher"},
    "HMAC": {"family": "HMAC", "primitive": "mac"},
    "PBKDF2": {"family": "PBKDF2", "primitive": "kdf"},
    "HKDF": {"family": "HKDF", "primitive": "kdf"},
    "SHA-1": {"family": "SHA-1", "primitive": "hash"},
    "SHA-256": {"family": "SHA-256", "primitive": "hash"},
    "SHA-384": {"family": "SHA-384", "primitive": "hash"},
    "SHA-512": {"family": "SHA-512", "primitive": "hash"},
    "ML-KEM-512": {"family": "ML-KEM", "parameter_set": "ML-KEM-512", "primitive": "kem"},
    "ML-KEM-768": {"family": "ML-KEM", "parameter_set": "ML-KEM-768", "primitive": "kem"},
    "ML-KEM-1024": {"family": "ML-KEM", "parameter_set": "ML-KEM-1024", "primitive": "kem"},
    "ML-DSA-44": {"family": "ML-DSA", "parameter_set": "ML-DSA-44", "primitive": "signature"},
    "ML-DSA-65": {"family": "ML-DSA", "parameter_set": "ML-DSA-65", "primitive": "signature"},
    "ML-DSA-87": {"family": "ML-DSA", "parameter_set": "ML-DSA-87", "primitive": "signature"},
}
WEBCRYPTO_PATTERN = "|".join(sorted((re.escape(k) for k in WEBCRYPTO), key=len, reverse=True))

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

R_SHOR_KE = ("Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today "
             "can be decrypted later ('harvest now, decrypt later'), so migrate this first.")
R_SHOR_SIG = "Signature algorithm that a large quantum computer can break (Shor's algorithm)."
R_SHOR = "Public-key algorithm that a large quantum computer can break (Shor's algorithm)."
R_NIST_112 = "At 112-bit security, NIST IR 8547 (draft) deprecates it after 2030 and disallows it after 2035."
R_NIST_128 = "NIST IR 8547 (draft) disallows it after 2035."
R_NIST_ANY = "NIST IR 8547 (draft) disallows it after 2035 (and deprecates it after 2030 at 112-bit security)."

WEAK_CIPHER_REASONS = {
    "DES": "DES has a 56-bit key that can be brute-forced; NIST withdrew FIPS 46-3 in 2005.",
    "3DES": ("NIST disallows Triple DES for encryption after 2023 (SP 800-131A Rev. 2); its 64-bit block is exposed "
             "to birthday attacks (Sweet32)."),
    "RC4": "RC4 keystream biases make it insecure; RFC 7465 prohibits it in TLS.",
    "RC2": "RC2 is obsolete: weak key schedule and 64-bit block; not approved by NIST.",
    "RC5": "RC5 is not approved by NIST and commonly used with a 64-bit block.",
}
R_64BIT = ("64-bit block size is exposed to birthday attacks such as Sweet32 (CVE-2016-2183 for DES/3DES, "
           "CVE-2016-6329 for Blowfish); not approved by NIST.")
WEAK_HASH_REASONS = {
    "MD5": ("MD5 collisions are practical; RFC 6151 says MD5 is no longer acceptable where collision resistance is "
            "required, such as digital signatures. It is not a NIST-approved hash."),
    "MD4": "MD4 is broken and historic (RFC 6150).",
    "MD2": "MD2 is broken and historic (RFC 6149).",
    "SHA-1": ("SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) "
              "and is retiring it in all uses by 31 December 2030."),
}
R_SHA1_RETIRING = "NIST is retiring SHA-1 in all uses by 31 December 2030 (NIST announcement, December 2022)."
R_224 = "NIST SP 800-131A Rev. 3 (draft) proposes disallowing 224-bit hash functions after 2030."
R_ECB = ("ECB mode reveals patterns in the plaintext; NIST SP 800-131A Rev. 3 (draft) proposes disallowing it for "
         "encryption.")
R_DSA = ("FIPS 186-5 (2023) no longer approves DSA for signature generation; it may only verify signatures made "
         "before then.")
R_UNKNOWN = "The algorithm or its parameters are chosen at run time or could not be read; check it by hand."


def classical_bits(f: Finding) -> int | None:
    fam = f.family
    if fam in ("RSA", "DSA", "DH", "ElGamal"):
        if not f.key_size:
            return None
        for size, bits in _IFC_FFC:
            if f.key_size >= size:
                return bits
        return 0
    if fam in FAMILY_BITS:
        return FAMILY_BITS[fam]
    if fam in ("EC", "ECDSA", "ECDH", "ECMQV", "SM2", "ECIES"):
        if f.curve in CURVE_BITS:
            return CURVE_BITS[f.curve]
        if f.key_size:
            return f.key_size // 2
        return 128 if fam == "SM2" else None
    if fam == "EdDSA":
        return 128 if not f.curve else CURVE_BITS.get(f.curve, 128)
    if fam in ("AES", "Camellia", "ARIA", "SM4", "SEED", "Twofish", "Serpent"):
        return f.key_size
    if fam in ("ChaCha20", "ChaCha20-Poly1305", "XChaCha20-Poly1305", "Salsa20", "XSalsa20"):
        return 256
    if fam == "3DES":
        return 80 if f.key_size == 112 else 112
    if fam == "DES":
        return 56
    if fam in HASH_BITS:
        return HASH_BITS[fam]
    return None


def role_of(f: Finding) -> str:
    if f.asset == CERTIFICATE:
        return "certificate"
    if f.asset == PROTOCOL or f.family in PROTOCOLS:
        return "protocol"
    fam, prim = f.family, f.primitive
    if prim in ("pke", "key-agree", "kem") or fam in KEY_ESTABLISHMENT_FAMILIES:
        return "key-establishment"
    if prim == "signature" or fam in SIGNATURE_FAMILIES or fam == "JWT-none":
        return "signature"
    if fam == "Composite":
        return "key-establishment" if (f.parameter_set or "").startswith("MLKEM") else "signature"
    if fam in ASYMMETRIC:
        return "other"
    if fam in SYMMETRIC_OK or fam in SYMMETRIC_WEAK:
        return "symmetric"
    if fam in HASHES or fam in MACS or fam in KDFS:
        return "hash"
    return "other"


def display_name(f: Finding) -> str:
    fam = f.family
    if fam == "Unknown":
        if f.details.get("kind") == "keystore":
            return f"Keystore ({f.details.get('format', 'unknown format')})"
        if f.asset == KEY and f.details.get("encrypted"):
            return "Encrypted private key"
        if f.oid:
            return f"Unrecognised algorithm {f.oid}"
        if f.details.get("unrecognised_name"):
            return f"Unrecognised algorithm \"{f.details['unrecognised_name']}\""
        if f.primitive == "hash":
            return "Hash chosen at run time"
        return "Algorithm chosen at run time"
    if f.asset == PROTOCOL or fam in ("TLS", "SSL", "DTLS"):
        if fam == "TLS-CipherSuite":
            return f.parameter_set or "TLS cipher suite"
        return f"{fam} {f.version}" if f.version else fam
    if fam in PQC and f.parameter_set:
        return f.parameter_set if fam not in ("Composite",) else f"Composite {f.parameter_set}"
    if fam == "JWT-none":
        return "JWT alg=none"
    if fam == "Signature":
        base = "Signature (key type set at run time)"
        return f"{base} with {f.hash}" if f.hash else base
    if fam == "RSA":
        base = f"RSA-{f.key_size}" if f.key_size else "RSA"
        base += {"oaep": "-OAEP", "pss": "-PSS", "pkcs1v15": " PKCS#1 v1.5"}.get(f.padding or "", "")
    elif fam in ("EC", "ECDSA", "ECDH", "ECMQV", "ECIES"):
        base = f"{fam} {f.curve}" if f.curve else fam
    elif fam in ("DSA", "DH", "ElGamal"):
        base = f"{fam}-{f.key_size}" if f.key_size else fam
    elif fam in ("HMAC", "PBKDF2", "HKDF"):
        base = f"{fam}-{f.hash}" if f.hash else fam
        return base
    elif fam in SYMMETRIC_OK or fam in SYMMETRIC_WEAK:
        base = fam
        if f.key_size and fam not in ("DES", "3DES", "ChaCha20", "ChaCha20-Poly1305", "XChaCha20-Poly1305"):
            base += f"-{f.key_size}"
        if f.mode:
            base += f"-{f.mode.upper()}"
        if fam == "BlockCipher":
            base = f"Block cipher in {f.mode.upper()} mode" if f.mode else "Block cipher"
        return base
    else:
        base = fam
    if f.hash and fam in ASYMMETRIC:
        base += f" with {f.hash}"
    return base


def classify(f: Finding) -> Finding:
    """Fill in name, status, reasons, strength, CNSA 2.0 approval and role."""
    fam = f.family
    reasons: list[str] = []
    status = UNKNOWN
    f.curve = norm_curve(f.curve) if f.curve else f.curve
    f.role = role_of(f)
    bits = classical_bits(f)
    f.classical_bits = bits
    cnsa2: bool | None = False

    if fam in ("TLS", "SSL", "DTLS"):
        status, reason = _protocol_status(fam, f.version)
        reasons.append(reason)
        cnsa2 = None if (f.version == "1.3") else False
    elif fam == "TLS-CipherSuite":
        status = f.details.get("suite_status", UNKNOWN)
        if status == WEAK:
            reasons.append("Cipher suite with broken or export-grade parts (RC4, DES, 3DES, NULL, EXPORT or anonymous).")
        elif status == VULNERABLE:
            reasons.append("TLS 1.2 cipher suite: the key exchange (RSA, DHE or ECDHE) is quantum-vulnerable.")
        else:
            reasons.append("TLS 1.3 cipher suite: symmetric parts only; the key exchange is set by the groups.")
        cnsa2 = None
    elif fam in ASYMMETRIC:
        if fam == "Signature":
            status = UNKNOWN
            reasons.append("The key type (RSA, ECDSA, Ed25519 ...) comes from the key at run time. "
                           "Unless it is a post-quantum key, it is quantum-vulnerable.")
        else:
            status = VULNERABLE
            f.quantum_category = 0
            reasons.append({"key-establishment": R_SHOR_KE, "signature": R_SHOR_SIG}.get(f.role, R_SHOR))
            if bits is None:
                reasons.append(R_NIST_ANY)
            elif bits <= 112:
                reasons.append(R_NIST_112)
            else:
                reasons.append(R_NIST_128)
            if bits is not None and bits < 112:
                status = WEAK
                reasons.insert(0, f"{display_name(f)} gives under 112 bits of security; NIST SP 800-131A "
                                  "disallows it for protecting data.")
            if fam == "DSA":
                status = WEAK
                reasons.insert(0, R_DSA)
            if fam == "RSA" and f.padding == "pkcs1v15" and f.primitive == "pke":
                add_note(f, "PKCS#1 v1.5 encryption padding is prone to padding-oracle attacks "
                            "(Bleichenbacher); prefer OAEP.")
        if f.hash in BROKEN_HASHES and (f.role == "signature" or f.hash != "SHA-1"):
            status = WEAK
            reasons.insert(0, WEAK_HASH_REASONS[f.hash])
        elif f.hash == "SHA-1":  # e.g. OAEP, where SHA-1 does not need collision resistance
            reasons.append(R_SHA1_RETIRING)
        elif f.hash in HASHES_224:
            reasons.append(R_224)
    elif fam in PQC:
        status = SAFE
        reasons.append(_pqc_reason(f))
        cat = PQC_CATEGORY.get(f.parameter_set or "")
        if fam == "SLH-DSA" and f.parameter_set:
            m = re.search(r"-(128|192|256)[sf]", f.parameter_set)
            cat = {"128": 1, "192": 3, "256": 5}[m.group(1)] if m else None
        f.quantum_category = cat
        if fam in ("LMS", "XMSS"):
            cnsa2 = True
        elif fam in ("ML-KEM", "ML-DSA"):
            cnsa2 = (f.parameter_set in CNSA2_PARAMETER_SETS) if f.parameter_set else None
        elif fam in ("Composite", "Hybrid"):
            cnsa2 = None
        else:
            cnsa2 = False
    elif fam in SYMMETRIC_OK:
        status = OK
        if fam == "BlockCipher":
            status = UNKNOWN
            reasons.append(R_UNKNOWN)
        elif fam in NIST_SYMMETRIC:
            reasons.append("Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks.")
            f.quantum_category = {128: 1, 192: 3, 256: 5}.get(f.key_size or 0)
            cnsa2 = (f.key_size == 256) if f.key_size else None
        else:
            reasons.append("Symmetric cipher with an adequate key size; not a NIST-approved algorithm.")
    elif fam in SYMMETRIC_WEAK:
        status = WEAK
        reasons.append(WEAK_CIPHER_REASONS.get(fam, R_64BIT))
    elif fam in HASHES:
        f.quantum_category = HASH_CATEGORY.get(fam)
        if fam in BROKEN_HASHES:
            status = WEAK
            reasons.append(WEAK_HASH_REASONS[fam])
        elif fam in HASHES_224:
            status = RETIRING
            reasons.append(R_224)
        else:
            status = OK
            reasons.append("Hash function with adequate strength against quantum attacks.")
        # CNSA 2.0 allows SHA3-384/512 only for internal hardware functions such as boot integrity checks.
        cnsa2 = True if fam in ("SHA-384", "SHA-512") else None if fam in ("SHA3-384", "SHA3-512") else False
    elif fam in MACS or fam in KDFS:
        status, reason = _keyed_hash_status(f)
        reasons.append(reason)
        cnsa2 = None if f.hash in ("SHA-384", "SHA-512") else False
    elif fam == "JWT-none":
        status = WEAK
        reasons.append("Unsigned JWT (alg=none): anyone can forge the token.")
    else:
        status = UNKNOWN
        reasons.append(R_UNKNOWN)
        cnsa2 = None

    if f.mode == "ecb" and (fam in SYMMETRIC_OK or fam in SYMMETRIC_WEAK):
        if status != WEAK:
            status = WEAK
        reasons.insert(0, R_ECB)

    if f.details.get("force_weak"):
        status = WEAK
        reasons.insert(0, f.details["force_weak"])
    elif f.details.get("force_unknown") and status in (OK, RETIRING):
        status = UNKNOWN
        reasons.insert(0, f.details["force_unknown"])

    if f.details.get("non_security") and status in (WEAK, RETIRING):
        reasons.insert(0, "Declared as not used for security (usedforsecurity=False), so not counted as weak.")
        status = OK

    if f.asset in (KEY, CERTIFICATE) and f.details.get("encrypted") and not fam:
        status = UNKNOWN

    f.name = display_name(f)
    f.status = status
    f.reasons = _dedupe(reasons)
    f.cnsa2 = cnsa2
    return f


def add_note(f: Finding, text: str) -> None:
    if text not in f.notes:
        f.notes.append(text)


def combine(f: Finding, other_status: str, reason: str | None = None) -> None:
    """Raise a finding's status when a second algorithm in it is worse (e.g. a certificate's signature)."""
    new = worst(f.status, other_status)
    if new != f.status and reason:
        f.reasons.insert(0, reason)
    f.status = new


def _protocol_status(fam: str, version: str | None) -> tuple[str, str]:
    if fam == "SSL":
        return WEAK, ("SSL 2.0 is prohibited (RFC 6176)." if version == "2.0" else "SSL 3.0 is deprecated (RFC 7568).")
    if version in ("1.0", "1.1"):
        if fam == "DTLS":
            return WEAK, "DTLS 1.0 is deprecated (RFC 8996)."
        return WEAK, "TLS 1.0 and 1.1 are deprecated (RFC 8996)."
    if version == "1.2":
        return VULNERABLE, ("TLS 1.2 has no standard post-quantum key exchange, so its handshake is "
                            "quantum-vulnerable.")
    if version == "1.3":
        return UNKNOWN, ("TLS 1.3 is quantum-safe only if a post-quantum or hybrid group such as X25519MLKEM768 is "
                         "negotiated; check the configured groups.")
    return UNKNOWN, "TLS version not set here; the library default applies. Check the configured versions and groups."


def _keyed_hash_status(f: Finding) -> tuple[str, str]:
    h = f.hash
    fam = f.family
    if fam == "EVP_BytesToKey":
        return WEAK, "EVP_BytesToKey-style key derivation (one MD5 iteration by default) is too fast for passwords."
    if h == "MD5":
        return WEAK, (f"{fam} built on MD5: MD5 is not a NIST-approved hash, and RFC 6151 says new protocols should "
                      "not use HMAC-MD5. Use SHA-256 or stronger.")
    if h in ("MD4", "MD2"):
        return WEAK, f"{fam} built on {h}: {WEAK_HASH_REASONS[h]}"
    if h == "SHA-1":
        return RETIRING, f"{fam} with SHA-1. {R_SHA1_RETIRING}"
    if h in HASHES_224:
        return RETIRING, f"{fam} with {h}. {R_224}"
    if fam in ("HMAC", "PBKDF2", "HKDF") and not h:
        return OK, f"{fam}; hash function not visible here (check it is SHA-256 or stronger)."
    return OK, "Symmetric construction with adequate strength against quantum attacks."


def _pqc_reason(f: Finding) -> str:
    fam = f.family
    if fam == "ML-KEM":
        return "NIST FIPS 203 (2024) post-quantum key encapsulation."
    if fam == "ML-DSA":
        return "NIST FIPS 204 (2024) post-quantum signature."
    if fam == "SLH-DSA":
        return "NIST FIPS 205 (2024) stateless hash-based post-quantum signature."
    if fam in ("LMS", "HSS", "XMSS", "XMSS^MT"):
        return ("Stateful hash-based signature (NIST SP 800-208); the signer must never reuse a one-time key. "
                + ("CNSA 2.0 allows only single-tree LMS and XMSS." if fam in ("HSS", "XMSS^MT") else ""))
    if fam in PRE_STANDARD:
        return (f"Pre-standard {fam}: quantum-resistant design, but it differs from the final {PRE_STANDARD[fam]}; "
                "move to the standard version.")
    if fam in NOT_YET_STANDARD:
        return f"{fam}: post-quantum algorithm without a final NIST standard yet."
    if fam == "Composite":
        return ("Composite signature or KEM: a post-quantum and a classical algorithm together (IETF LAMPS draft); "
                "stays secure while either part holds.")
    if fam == "Hybrid":
        return ("Hybrid key exchange that includes ML-KEM, so recorded traffic stays protected even against a "
                "future quantum computer.")
    return "Post-quantum algorithm."


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def apply(f: Finding, spec: dict | None) -> Finding | None:
    """Copy the fields of a parsed name spec onto a finding."""
    if not spec or not spec.get("family"):
        return None
    for key, value in spec.items():
        if key == "notes":
            f.notes.extend(value)
        elif key == "details":
            f.details.update(value)
        elif key == "functions":
            f.functions = sorted(set(f.functions) | set(value))
        elif value is not None:
            setattr(f, key, value)
    return f
