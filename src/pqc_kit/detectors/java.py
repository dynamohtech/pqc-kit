"""Java and other JVM languages (Kotlin, Scala, Groovy).

Reads Java Cryptography Architecture calls (Cipher/Signature/MessageDigest/
Mac/KeyPairGenerator/... .getInstance), Bouncy Castle classes, TLS protocol
settings and JWT libraries (jjwt, auth0 java-jwt, Nimbus). Comments are
ignored; string constants declared in the same file are resolved.
"""

from __future__ import annotations

import re

from pqc_kit.catalog import (
    apply, norm_cipher, norm_curve, norm_hash, parse_digest, parse_jca_cipher, parse_jca_signature, parse_jwt_alg,
    parse_key_algorithm, parse_mac, parse_pbe_name, parse_pqc_name, parse_tls_version,
)
from pqc_kit.detectors.text import Lines, call_args, int_literal, string_literal, strip_comments
from pqc_kit.model import ALGORITHM, PROTOCOL, Finding

GET_INSTANCE = re.compile(
    r"\b(Cipher|Signature|MessageDigest|Mac|KeyPairGenerator|KeyGenerator|KeyAgreement|KeyFactory|"
    r"SecretKeyFactory|SSLContext|KEM|AlgorithmParameterGenerator)\s*\.\s*getInstance\s*(\()")
ASSIGNED = re.compile(r"(\w+)\s*=\s*(?:\w+\.)*(KeyPairGenerator|KeyGenerator)\s*\.\s*getInstance\b")
STRING_CONST = re.compile(r"\b(?:final\s+|static\s+|private\s+|public\s+|protected\s+|const\s+|val\s+|var\s+)*"
                          r"(?:String\s+)?(\w+)\s*(?::\s*String\s*)?=\s*\"([^\"\n]{1,80})\"\s*;?")
INT_CONST = re.compile(r"\b(?:final\s+|static\s+|private\s+|public\s+|const\s+|val\s+)*(?:int\s+)?(\w+)\s*"
                       r"(?::\s*Int\s*)?=\s*(\d{3,5})\s*;?")
NEW_CLASS = re.compile(r"\bnew\s+(?:[\w.]+\.)?(\w+)\s*\(|\b(AESEngine)\s*\.\s*newInstance\s*\(")
EC_SPEC = re.compile(r"\bnew\s+ECGenParameterSpec\s*\(\s*(\"[^\"]*\"|\w+)")
NAMED_SPEC = re.compile(r"\bNamedParameterSpec\s*\.\s*(X25519|X448|ED25519|ED448|ML_KEM_512|ML_KEM_768|ML_KEM_1024|"
                        r"ML_DSA_44|ML_DSA_65|ML_DSA_87)\b|\bnew\s+NamedParameterSpec\s*\(\s*\"([^\"]+)\"")
BC_PARAMS = re.compile(r"\b(?:MLKEM|MLDSA|SLHDSA|Kyber|Dilithium)Parameter(?:s|Spec)\s*\.\s*(\w+)")
PROTOCOL_ARRAY = re.compile(r"\bset(?:Enabled)?Protocols\s*\(\s*(?:new\s+String\s*\[\s*\]\s*)?\{?([^;)]*)")
OKHTTP_TLS = re.compile(r"\bTlsVersion\s*\.\s*(TLS_1_[0-3]|SSL_3_0)\b")
JJWT = re.compile(r"\b(?:SignatureAlgorithm|Jwts\s*\.\s*SIG)\s*\.\s*(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|"
                  r"ES512|PS256|PS384|PS512|EdDSA|Ed25519|Ed448|NONE)\b")
AUTH0 = re.compile(r"\bAlgorithm\s*\.\s*(RSA256|RSA384|RSA512|ECDSA256K|ECDSA256|ECDSA384|ECDSA512|HMAC256|HMAC384|"
                   r"HMAC512|none)\s*\(")
NIMBUS = re.compile(r"\b(?:JWSAlgorithm|JWEAlgorithm)\s*\.\s*(\w+)\b")

_AUTH0 = {"RSA256": "RS256", "RSA384": "RS384", "RSA512": "RS512", "ECDSA256": "ES256", "ECDSA256K": "ES256K",
          "ECDSA384": "ES384", "ECDSA512": "ES512", "HMAC256": "HS256", "HMAC384": "HS384", "HMAC512": "HS512",
          "none": "none"}

# Bouncy Castle lightweight API classes -> (family, primitive, extra)
BC_CLASSES: dict[str, tuple[str, str, dict]] = {
    "RSAKeyPairGenerator": ("RSA", "unknown", {"functions": ["keygen"]}),
    "RSAEngine": ("RSA", "pke", {}), "RSABlindedEngine": ("RSA", "pke", {}),
    "OAEPEncoding": ("RSA", "pke", {"padding": "oaep"}), "PKCS1Encoding": ("RSA", "pke", {"padding": "pkcs1v15"}),
    "PSSSigner": ("RSA", "signature", {"padding": "pss"}),
    "RSADigestSigner": ("RSA", "signature", {"padding": "pkcs1v15"}),
    "DSASigner": ("DSA", "signature", {}), "DSAKeyPairGenerator": ("DSA", "signature", {"functions": ["keygen"]}),
    "ECDSASigner": ("ECDSA", "signature", {}), "ECKeyPairGenerator": ("EC", "unknown", {"functions": ["keygen"]}),
    "ECDHBasicAgreement": ("ECDH", "key-agree", {}), "ECDHCBasicAgreement": ("ECDH", "key-agree", {}),
    "DHBasicAgreement": ("DH", "key-agree", {}), "DHKeyPairGenerator": ("DH", "key-agree", {"functions": ["keygen"]}),
    "Ed25519Signer": ("Ed25519", "signature", {}), "Ed25519KeyPairGenerator": ("Ed25519", "signature", {}),
    "Ed448Signer": ("Ed448", "signature", {}), "X25519Agreement": ("X25519", "key-agree", {}),
    "X25519KeyPairGenerator": ("X25519", "key-agree", {}), "X448Agreement": ("X448", "key-agree", {}),
    "SM2Signer": ("SM2", "signature", {}), "SM2Engine": ("SM2", "pke", {}),
    "DESEngine": ("DES", "block-cipher", {"key_size": 56}), "DESedeEngine": ("3DES", "block-cipher", {}),
    "RC4Engine": ("RC4", "stream-cipher", {}), "RC2Engine": ("RC2", "block-cipher", {}),
    "BlowfishEngine": ("Blowfish", "block-cipher", {}), "CAST5Engine": ("CAST5", "block-cipher", {}),
    "IDEAEngine": ("IDEA", "block-cipher", {}), "TEAEngine": ("TEA", "block-cipher", {}),
    "XTEAEngine": ("XTEA", "block-cipher", {}), "AESEngine": ("AES", "block-cipher", {}),
    "AESFastEngine": ("AES", "block-cipher", {}), "AESLightEngine": ("AES", "block-cipher", {}),
    "ChaCha7539Engine": ("ChaCha20", "stream-cipher", {}), "ChaChaEngine": ("ChaCha20", "stream-cipher", {}),
    "TwofishEngine": ("Twofish", "block-cipher", {}), "SerpentEngine": ("Serpent", "block-cipher", {}),
    "CamelliaEngine": ("Camellia", "block-cipher", {}), "SM4Engine": ("SM4", "block-cipher", {}),
    "SEEDEngine": ("SEED", "block-cipher", {}),
    "MD5Digest": ("MD5", "hash", {}), "MD4Digest": ("MD4", "hash", {}), "MD2Digest": ("MD2", "hash", {}),
    "SHA1Digest": ("SHA-1", "hash", {}), "SHA224Digest": ("SHA-224", "hash", {}),
    "SHA256Digest": ("SHA-256", "hash", {}), "SHA384Digest": ("SHA-384", "hash", {}),
    "SHA512Digest": ("SHA-512", "hash", {}), "RIPEMD160Digest": ("RIPEMD-160", "hash", {}),
    "SM3Digest": ("SM3", "hash", {}), "Blake2bDigest": ("BLAKE2b", "hash", {}),
    "Blake2sDigest": ("BLAKE2s", "hash", {}), "WhirlpoolDigest": ("Whirlpool", "hash", {}),
    "MLKEMKeyPairGenerator": ("ML-KEM", "kem", {}), "MLKEMGenerator": ("ML-KEM", "kem", {}),
    "MLKEMExtractor": ("ML-KEM", "kem", {}), "MLDSASigner": ("ML-DSA", "signature", {}),
    "HashMLDSASigner": ("ML-DSA", "signature", {}), "MLDSAKeyPairGenerator": ("ML-DSA", "signature", {}),
    "SLHDSASigner": ("SLH-DSA", "signature", {}), "HashSLHDSASigner": ("SLH-DSA", "signature", {}),
    "SLHDSAKeyPairGenerator": ("SLH-DSA", "signature", {}),
    "KyberKeyPairGenerator": ("Kyber", "kem", {}), "KyberKEMGenerator": ("Kyber", "kem", {}),
    "DilithiumSigner": ("Dilithium", "signature", {}), "DilithiumKeyPairGenerator": ("Dilithium", "signature", {}),
    "SPHINCSPlusSigner": ("SPHINCS+", "signature", {}), "FalconSigner": ("Falcon", "signature", {}),
    "LMSSigner": ("LMS", "signature", {}), "LMSKeyPairGenerator": ("LMS", "signature", {}),
    "HSSSigner": ("HSS", "signature", {}), "XMSSSigner": ("XMSS", "signature", {}),
    "XMSSMTSigner": ("XMSS^MT", "signature", {}), "HQCKEMGenerator": ("HQC", "kem", {}),
    "FrodoKEMGenerator": ("FrodoKEM", "kem", {}), "NTRUKEMGenerator": ("NTRU", "kem", {}),
    "BIKEKEMGenerator": ("BIKE", "kem", {}), "CMCEKEMGenerator": ("Classic-McEliece", "kem", {}),
}


class _File:
    def __init__(self, path: str, source: str, in_tests: bool):
        self.path = path
        self.in_tests = in_tests
        self.text = strip_comments(source)
        self.lines = Lines(self.text)
        self.findings: list[Finding] = []
        self.strings = {m.group(1): m.group(2) for m in STRING_CONST.finditer(self.text)}
        self.ints = {m.group(1): int(m.group(2)) for m in INT_CONST.finditer(self.text)}
        self.consumed: set[int] = set()  # offsets already explained by a richer finding

    def add(self, offset: int, spec: dict | None, symbol: str, asset: str = ALGORITHM, **extra) -> Finding | None:
        if not spec or not spec.get("family"):
            return None
        line, col = self.lines.at(offset)
        f = Finding(asset=asset, family="", path=self.path, line=line, column=col, symbol=symbol, detector="java",
                    in_tests=self.in_tests)
        apply(f, spec)
        for k, v in extra.items():
            if v is not None:
                if k == "notes":
                    f.notes.extend(v)
                else:
                    setattr(f, k, v)
        self.findings.append(f)
        return f

    def resolve_str(self, expr: str | None) -> str | None:
        lit = string_literal(expr)
        if lit is not None:
            return lit
        if expr and re.fullmatch(r"(?:\w+\.)*\w+", expr.strip()):
            return self.strings.get(expr.strip().split(".")[-1])
        return None


def _spec_for(kind: str, name: str) -> dict | None:
    if kind == "Cipher":
        return parse_jca_cipher(name)
    if kind == "Signature":
        return parse_jca_signature(name)
    if kind == "MessageDigest":
        return parse_digest(name)
    if kind == "Mac":
        return parse_mac(name)
    if kind in ("KeyPairGenerator", "KeyFactory", "KeyAgreement", "AlgorithmParameterGenerator"):
        spec = parse_key_algorithm(name)
        if spec and kind == "KeyPairGenerator":
            spec = dict(spec, functions=["keygen"])
        return spec
    if kind == "KeyGenerator":
        if name.lower().startswith("hmac"):
            return parse_mac(name)
        fam = norm_cipher(name) or (parse_pqc_name(name) or {}).get("family")
        if fam:
            return {"family": fam, "primitive": "stream-cipher" if fam in ("RC4", "ChaCha20") else "block-cipher",
                    "functions": ["keygen"]}
        return None
    if kind == "SecretKeyFactory":
        spec = parse_pbe_name(name)
        if spec:
            return spec
        fam = norm_cipher(name)
        return {"family": fam, "primitive": "block-cipher"} if fam else None
    if kind == "SSLContext":
        if name.upper() in ("TLS", "SSL", "DEFAULT", "DTLS"):
            return {"family": "DTLS" if name.upper() == "DTLS" else "TLS", "version": None}
        return parse_tls_version(name)
    if kind == "KEM":
        if name.upper() == "DHKEM":
            return {"family": "ECDH", "primitive": "kem", "notes": ["DHKEM (RFC 9180): a classical KEM built on DH."]}
        return parse_pqc_name(name)
    return None


def scan_java(path: str, source: str, in_tests: bool) -> list[Finding]:
    j = _File(path, source, in_tests)
    text = j.text

    var_kind = {m.group(1): (m.group(2), m.start()) for m in ASSIGNED.finditer(text)}

    for m in GET_INSTANCE.finditer(text):
        kind = m.group(1)
        paren = m.start(2)
        args = call_args(text, paren) or []
        name = j.resolve_str(args[0]) if args else None
        symbol = f"{kind}.getInstance"
        if name is None:
            j.add(m.start(), {"family": "Unknown"}, symbol, confidence="low",
                  notes=[f"{kind} algorithm is not a literal: {args[0][:60] if args else '?'}"],
                  asset=PROTOCOL if kind == "SSLContext" else ALGORITHM)
            continue
        spec = _spec_for(kind, name)
        if spec is None:
            j.add(m.start(), {"family": "Unknown", "details": {"unrecognised_name": name}}, symbol,
                  confidence="low", notes=[f"Unrecognised {kind} algorithm name \"{name}\"."])
            continue
        f = j.add(m.start(), spec, f'{symbol}("{name}")', asset=PROTOCOL if kind == "SSLContext" else ALGORITHM)
        if f and kind in ("KeyPairGenerator", "KeyGenerator"):
            _attach_size(j, f, m, var_kind)

    for m in EC_SPEC.finditer(text):
        if m.start() in j.consumed:
            continue
        curve = j.resolve_str(m.group(1))
        j.add(m.start(), {"family": "EC", "curve": norm_curve(curve)}, "ECGenParameterSpec")
    for m in NAMED_SPEC.finditer(text):
        if m.start() in j.consumed:
            continue
        name = (m.group(1) or m.group(2) or "").replace("_", "-")
        spec = parse_key_algorithm(name)
        if spec:
            j.add(m.start(), spec, "NamedParameterSpec")
    for m in BC_PARAMS.finditer(text):
        spec = parse_pqc_name(m.group(1).replace("_", "-"))
        if spec and spec.get("parameter_set"):
            j.add(m.start(), spec, m.group(0).replace(" ", ""))

    for m in NEW_CLASS.finditer(text):
        cls = m.group(1) or m.group(2)
        if cls == "HMac":
            inner = re.match(r"\s*new\s+(?:[\w.]+\.)?(\w+)Digest\s*\(", text[m.end():])
            h = None
            if inner:
                digest = BC_CLASSES.get(inner.group(1) + "Digest")
                h = digest[0] if digest else norm_hash(inner.group(1))
                j.consumed.add(_class_offset(text, m.end()))
            j.add(m.start(), {"family": "HMAC", "hash": h, "primitive": "mac"}, "new HMac")
            continue
        if cls in BC_CLASSES and m.start() not in j.consumed:
            fam, prim, extra = BC_CLASSES[cls]
            spec = {"family": fam, "primitive": prim, **extra}
            j.add(m.start(), spec, f"new {cls}" if m.group(1) else f"{cls}.newInstance")

    for m in PROTOCOL_ARRAY.finditer(text):
        for s in re.findall(r"\"([^\"]+)\"", m.group(1)):
            spec = parse_tls_version(s)
            if spec:
                j.add(m.start(), spec, "setEnabledProtocols", asset=PROTOCOL)
    for m in OKHTTP_TLS.finditer(text):
        spec = parse_tls_version(m.group(1).replace("_", "").replace("TLS1", "TLSv1").replace("SSL30", "SSLv3"))
        if spec:
            j.add(m.start(), spec, f"TlsVersion.{m.group(1)}", asset=PROTOCOL)

    for m in JJWT.finditer(text):
        alg = "none" if m.group(1) == "NONE" else m.group(1)
        j.add(m.start(), parse_jwt_alg(alg), m.group(0).replace(" ", ""))
    for m in AUTH0.finditer(text):
        j.add(m.start(), parse_jwt_alg(_AUTH0[m.group(1)]), f"Algorithm.{m.group(1)}")
    for m in NIMBUS.finditer(text):
        name = m.group(1)
        alg = {"RSA_OAEP_256": "RSA-OAEP-256", "RSA_OAEP": "RSA-OAEP", "ECDH_ES": "ECDH-ES"}.get(name, name)
        j.add(m.start(), parse_jwt_alg(alg), m.group(0).replace(" ", ""))

    return j.findings


def _class_offset(text: str, pos: int) -> int:
    m = re.compile(r"\bnew\s").search(text, pos)
    return m.start() if m else pos


def _attach_size(j: _File, f: Finding, m: re.Match, var_kind: dict) -> None:
    """Find initialize(2048) / init(256) / ECGenParameterSpec for a key generator."""
    text = j.text
    var = None
    for name, (kind, start) in var_kind.items():
        if kind == m.group(1) and start <= m.start() <= start + 200 + len(name):
            var = name
    call = "initialize" if m.group(1) == "KeyPairGenerator" else "init"
    region = None
    if var:
        vm = re.compile(r"\b" + re.escape(var) + r"\s*\.\s*" + call + r"\s*\(").search(text, m.end())
        if vm:
            region = vm.end() - 1
    if region is None:
        wm = re.compile(r"\b" + call + r"\s*\(").search(text, m.end(), m.end() + 300)
        nxt = GET_INSTANCE.search(text, m.end())
        if wm and (not nxt or wm.start() < nxt.start()):
            region = wm.end() - 1
    if region is None:
        return
    args = call_args(text, region) or []
    if not args:
        return
    first = args[0]
    size = int_literal(first, j.ints)
    if size:
        if f.family in ("EC", "ECDSA", "ECDH"):
            from pqc_kit.catalog import curve_from_size
            f.curve = curve_from_size(size)
        else:
            f.key_size = size
        return
    ec = re.match(r"new\s+ECGenParameterSpec\s*\(\s*(\"[^\"]*\"|\w+)", first)
    if ec:
        f.curve = norm_curve(j.resolve_str(ec.group(1)))
        j.consumed.add(region + 1 + first.find("new"))
        for em in EC_SPEC.finditer(text, region, region + len(first) + 2):
            j.consumed.add(em.start())
        return
    rsa = re.match(r"new\s+RSAKeyGenParameterSpec\s*\(\s*(\w+)", first)
    if rsa:
        f.key_size = int_literal(rsa.group(1), j.ints)
        return
    ns = NAMED_SPEC.search(first)
    if ns:
        spec = parse_key_algorithm((ns.group(1) or ns.group(2) or "").replace("_", "-"))
        if spec:
            apply(f, spec)
        for nm in NAMED_SPEC.finditer(text, region, region + len(first) + 2):
            j.consumed.add(nm.start())
