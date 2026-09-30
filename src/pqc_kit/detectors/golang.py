"""Go detector: the standard library crypto packages, golang.org/x/crypto,
Cloudflare CIRCL post-quantum packages and the common JWT libraries.

Import aliases are resolved, so `import r "crypto/rsa"` is understood.
Comments are ignored; integer constants in the same file are resolved.
"""

from __future__ import annotations

import re

from pqc_kit.catalog import apply, norm_hash, parse_cipher_suite, parse_jwt_alg, parse_tls_version
from pqc_kit.detectors.text import Lines, call_args, int_literal, strip_comments
from pqc_kit.model import ALGORITHM, PROTOCOL, Finding

IMPORT_BLOCK = re.compile(r"\bimport\s*\((.*?)\)", re.S)
IMPORT_ONE = re.compile(r"\bimport\s+(?:([\w.]+)\s+)?\"([^\"]+)\"")
IMPORT_LINE = re.compile(r"^\s*(?:([\w.]+)\s+)?\"([^\"]+)\"", re.M)
INT_CONST = re.compile(r"\b(\w+)\s*(?::=|=)\s*(\d{3,5})\b")

XC = "golang.org/x/crypto/"

HASH_FUNCS = {
    "crypto/md5": {"New": "MD5", "Sum": "MD5"},
    "crypto/sha1": {"New": "SHA-1", "Sum": "SHA-1"},
    "crypto/sha256": {"New": "SHA-256", "Sum256": "SHA-256", "New224": "SHA-224", "Sum224": "SHA-224"},
    "crypto/sha512": {"New": "SHA-512", "Sum512": "SHA-512", "New384": "SHA-384", "Sum384": "SHA-384",
                      "New512_224": "SHA-512/224", "Sum512_224": "SHA-512/224", "New512_256": "SHA-512/256",
                      "Sum512_256": "SHA-512/256"},
    XC + "md4": {"New": "MD4"},
    XC + "ripemd160": {"New": "RIPEMD-160"},
    XC + "blake2b": {"New": "BLAKE2b", "New256": "BLAKE2b", "New384": "BLAKE2b", "New512": "BLAKE2b",
                     "Sum256": "BLAKE2b", "Sum384": "BLAKE2b", "Sum512": "BLAKE2b"},
    XC + "blake2s": {"New256": "BLAKE2s", "New128": "BLAKE2s", "Sum256": "BLAKE2s"},
}
_SHA3 = {"New224": "SHA3-224", "New256": "SHA3-256", "New384": "SHA3-384", "New512": "SHA3-512",
         "Sum224": "SHA3-224", "Sum256": "SHA3-256", "Sum384": "SHA3-384", "Sum512": "SHA3-512",
         "NewSHAKE128": "SHAKE128", "NewSHAKE256": "SHAKE256", "SumSHAKE128": "SHAKE128", "SumSHAKE256": "SHAKE256",
         "ShakeSum128": "SHAKE128", "ShakeSum256": "SHAKE256", "NewShake128": "SHAKE128", "NewShake256": "SHAKE256",
         "NewLegacyKeccak256": "Keccak-256", "NewLegacyKeccak512": "Keccak-256"}
HASH_FUNCS["crypto/sha3"] = _SHA3
HASH_FUNCS[XC + "sha3"] = _SHA3
CRYPTO_HASH_CONSTS = {"MD4": "MD4", "MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
                      "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA512_224": "SHA-512/224",
                      "SHA512_256": "SHA-512/256", "SHA3_224": "SHA3-224", "SHA3_256": "SHA3-256",
                      "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512", "RIPEMD160": "RIPEMD-160",
                      "BLAKE2b_256": "BLAKE2b", "BLAKE2b_512": "BLAKE2b", "BLAKE2s_256": "BLAKE2s"}

CIPHERS = {
    "crypto/aes": {"NewCipher": ("AES", "block-cipher")},
    "crypto/des": {"NewCipher": ("DES", "block-cipher"), "NewTripleDESCipher": ("3DES", "block-cipher")},
    "crypto/rc4": {"NewCipher": ("RC4", "stream-cipher")},
    XC + "blowfish": {"NewCipher": ("Blowfish", "block-cipher"), "NewSaltedCipher": ("Blowfish", "block-cipher")},
    XC + "cast5": {"NewCipher": ("CAST5", "block-cipher")},
    XC + "tea": {"NewCipher": ("TEA", "block-cipher"), "NewCipherWithRounds": ("TEA", "block-cipher")},
    XC + "xtea": {"NewCipher": ("XTEA", "block-cipher")},
    XC + "twofish": {"NewCipher": ("Twofish", "block-cipher")},
    XC + "chacha20poly1305": {"New": ("ChaCha20-Poly1305", "ae"), "NewX": ("XChaCha20-Poly1305", "ae")},
    XC + "chacha20": {"NewUnauthenticatedCipher": ("ChaCha20", "stream-cipher")},
    XC + "salsa20": {"XORKeyStream": ("Salsa20", "stream-cipher")},
    XC + "nacl/secretbox": {"Seal": ("XSalsa20", "ae"), "Open": ("XSalsa20", "ae")},
}

X509_SIGS = {
    "MD2WithRSA": ("RSA", "MD2"), "MD5WithRSA": ("RSA", "MD5"), "SHA1WithRSA": ("RSA", "SHA-1"),
    "SHA256WithRSA": ("RSA", "SHA-256"), "SHA384WithRSA": ("RSA", "SHA-384"), "SHA512WithRSA": ("RSA", "SHA-512"),
    "DSAWithSHA1": ("DSA", "SHA-1"), "DSAWithSHA256": ("DSA", "SHA-256"), "ECDSAWithSHA1": ("ECDSA", "SHA-1"),
    "ECDSAWithSHA256": ("ECDSA", "SHA-256"), "ECDSAWithSHA384": ("ECDSA", "SHA-384"),
    "ECDSAWithSHA512": ("ECDSA", "SHA-512"), "SHA256WithRSAPSS": ("RSA", "SHA-256"),
    "SHA384WithRSAPSS": ("RSA", "SHA-384"), "SHA512WithRSAPSS": ("RSA", "SHA-512"), "PureEd25519": ("Ed25519", None),
}

CIRCL = re.compile(r"github\.com/cloudflare/circl/(?:kem/(mlkem)/mlkem(\d+)|sign/(mldsa)/mldsa(\d+)|"
                   r"kem/(kyber)/kyber(\d+)|sign/(dilithium)/mode(\d))")
JWT_PATH = re.compile(r"(?:^|/)jwt(?:-go)?(?:/v\d+)?$")


def _local_name(path: str) -> str:
    parts = path.split("/")
    last = parts[-1]
    if re.fullmatch(r"v\d+", last) and len(parts) > 1:
        last = parts[-2]
    return re.sub(r"[^\w]", "_", last.removesuffix("-go").removeprefix("go-"))


class _File:
    def __init__(self, path: str, source: str, in_tests: bool):
        self.path = path
        self.in_tests = in_tests
        self.text = strip_comments(source, backtick_strings=True, raw_backticks=True)
        self.lines = Lines(self.text)
        self.findings: list[Finding] = []
        self.consumed: set[int] = set()
        self.ints = {m.group(1): int(m.group(2)) for m in INT_CONST.finditer(self.text)}
        self.imports: dict[str, str] = {}  # local name -> import path
        self.import_offsets: dict[str, int] = {}
        for block in IMPORT_BLOCK.finditer(self.text):
            for m in IMPORT_LINE.finditer(block.group(1)):
                self._import(m.group(1), m.group(2), block.start(1) + m.start(2))
        for m in IMPORT_ONE.finditer(self.text):
            self._import(m.group(1), m.group(2), m.start(2))

    def _import(self, alias: str | None, path: str, offset: int) -> None:
        if alias in ("_", "."):
            return
        name = alias or _local_name(path)
        self.imports[name] = path
        self.import_offsets[path] = offset

    def add(self, offset: int, spec: dict | None, symbol: str, asset: str = ALGORITHM, **extra) -> Finding | None:
        if not spec or not spec.get("family"):
            return None
        line, col = self.lines.at(offset)
        f = Finding(asset=asset, family="", path=self.path, line=line, column=col, symbol=symbol, detector="go",
                    in_tests=self.in_tests)
        apply(f, spec)
        for k, v in extra.items():
            if v is not None:
                setattr(f, k, v)
        self.findings.append(f)
        return f

    def ref(self, expr: str) -> tuple[str, str] | None:
        """'sha256.New' or 'sha256.New()' or 'crypto.SHA256' -> (import path, member)."""
        m = re.match(r"\s*(\w+)\s*\.\s*(\w+)", expr or "")
        if not m or m.group(1) not in self.imports:
            return None
        return self.imports[m.group(1)], m.group(2)

    def hash_of(self, expr: str | None, offset: int | None = None) -> str | None:
        r = self.ref(expr or "")
        if not r:
            return None
        path, member = r
        if offset is not None:
            self.consumed.add(offset)
        if path == "crypto":
            return CRYPTO_HASH_CONSTS.get(member)
        return HASH_FUNCS.get(path, {}).get(member)

    def size_of(self, expr: str | None) -> int | None:
        size = int_literal(expr, self.ints)
        if size:
            return size
        m = re.search(r"\bL(\d{4})N\d+\b", expr or "")
        return int(m.group(1)) if m else None


def scan_go(path: str, source: str, in_tests: bool) -> list[Finding]:
    g = _File(path, source, in_tests)
    text = g.text
    if not g.imports:
        return []

    for ipath, offset in g.import_offsets.items():
        m = CIRCL.search(ipath)
        if m:
            kind, num = next((m.group(i), m.group(i + 1)) for i in (1, 3, 5, 7) if m.group(i))
            spec = {"mlkem": {"family": "ML-KEM", "parameter_set": f"ML-KEM-{num}", "primitive": "kem"},
                    "mldsa": {"family": "ML-DSA", "parameter_set": f"ML-DSA-{num}", "primitive": "signature"},
                    "kyber": {"family": "Kyber", "parameter_set": f"Kyber{num}", "primitive": "kem"},
                    "dilithium": {"family": "Dilithium", "parameter_set": f"Dilithium{num}",
                                  "primitive": "signature"}}[kind]
            g.add(offset, spec, f'import "{ipath}"')

    names = "|".join(re.escape(n) for n in g.imports)
    member_re = re.compile(r"\b(" + names + r")\s*\.\s*([A-Z]\w*)")
    matches = [m for m in member_re.finditer(text)
               if text[max(0, m.start() - 1)] not in ".\"" and not _in_import(text, m.start())]

    # First pass: calls whose arguments name other algorithms, so those get consumed.
    for m in matches:
        _rich_call(g, m)
    for m in matches:
        if m.start() in g.consumed:
            continue
        _simple_member(g, m)
    return g.findings


def _in_import(text: str, pos: int) -> bool:
    line_start = text.rfind("\n", 0, pos) + 1
    return text[line_start:pos].lstrip().startswith("import")


def _args_after(g: _File, m: re.Match) -> list[str] | None:
    rest = g.text[m.end():m.end() + 5]
    idx = rest.find("(")
    if idx == -1 or rest[:idx].strip():
        return None
    return call_args(g.text, m.end() + idx)


def _consume_args(g: _File, m: re.Match, args: list[str] | None) -> None:
    if not args:
        return
    start = m.end()
    end = start + sum(len(a) for a in args) + 8 * len(args) + 20
    for other in re.finditer(r"\b\w+\s*\.\s*[A-Z]\w*", g.text[start:end]):
        g.consumed.add(start + other.start())


def _rich_call(g: _File, m: re.Match) -> None:
    ipath = g.imports.get(m.group(1), "")
    member = m.group(2)
    sym = f"{m.group(1)}.{member}"
    if ipath == "crypto/rsa":
        args = _args_after(g, m) or []
        spec: dict | None = None
        if member in ("GenerateKey", "GenerateMultiPrimeKey"):
            size = g.size_of(args[2] if member == "GenerateMultiPrimeKey" and len(args) > 2 else
                             args[1] if len(args) > 1 else None)
            spec = {"family": "RSA", "key_size": size, "functions": ["keygen"]}
        elif member in ("SignPKCS1v15", "VerifyPKCS1v15"):
            idx = 2 if member == "SignPKCS1v15" else 1
            h = g.hash_of(args[idx]) if len(args) > idx else None
            spec = {"family": "RSA", "padding": "pkcs1v15", "hash": h, "primitive": "signature"}
        elif member in ("SignPSS", "VerifyPSS"):
            idx = 2 if member == "SignPSS" else 1
            h = g.hash_of(args[idx]) if len(args) > idx else None
            spec = {"family": "RSA", "padding": "pss", "hash": h, "primitive": "signature"}
        elif member in ("EncryptOAEP", "DecryptOAEP"):
            h = g.hash_of(args[0]) if args else None
            spec = {"family": "RSA", "padding": "oaep", "hash": h, "primitive": "pke"}
        elif member in ("EncryptPKCS1v15", "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey"):
            spec = {"family": "RSA", "padding": "pkcs1v15", "primitive": "pke"}
        if spec:
            _consume_args(g, m, args)
            g.add(m.start(), spec, sym)
            g.consumed.add(m.start())
    elif ipath == "crypto/ecdsa" and member == "GenerateKey":
        args = _args_after(g, m) or []
        curve = _curve(g, args[0]) if args else None
        _consume_args(g, m, args)
        g.add(m.start(), {"family": "ECDSA", "curve": curve, "functions": ["keygen"], "primitive": "signature"}, sym)
        g.consumed.add(m.start())
    elif ipath == "crypto/dsa" and member == "GenerateParameters":
        args = _args_after(g, m) or []
        size = g.size_of(args[2]) if len(args) > 2 else None
        _consume_args(g, m, args)
        g.add(m.start(), {"family": "DSA", "key_size": size, "primitive": "signature"}, sym)
        g.consumed.add(m.start())
    elif ipath == "crypto/hmac" and member == "New":
        args = _args_after(g, m) or []
        h = g.hash_of(args[0]) if args else None
        _consume_args(g, m, args[:1])
        g.add(m.start(), {"family": "HMAC", "hash": h, "primitive": "mac"}, sym)
        g.consumed.add(m.start())
    elif (ipath == "crypto/pbkdf2" and member == "Key") or (ipath == XC + "pbkdf2" and member == "Key"):
        args = _args_after(g, m) or []
        idx = 0 if ipath == "crypto/pbkdf2" else 4
        h = g.hash_of(args[idx]) if len(args) > idx else None
        _consume_args(g, m, args)
        g.add(m.start(), {"family": "PBKDF2", "hash": h, "primitive": "kdf"}, sym)
        g.consumed.add(m.start())
    elif ipath in ("crypto/hkdf", XC + "hkdf") and member in ("New", "Key", "Extract", "Expand"):
        args = _args_after(g, m) or []
        h = g.hash_of(args[0]) if args else None
        _consume_args(g, m, args[:1])
        g.add(m.start(), {"family": "HKDF", "hash": h, "primitive": "kdf"}, sym)
        g.consumed.add(m.start())


def _curve(g: _File, expr: str) -> str | None:
    r = g.ref(expr)
    if r and r[0] in ("crypto/elliptic", "crypto/ecdh"):
        return {"P224": "P-224", "P256": "P-256", "P384": "P-384", "P521": "P-521"}.get(r[1])
    return None


def _simple_member(g: _File, m: re.Match) -> None:  # noqa: C901 - flat rule table
    ipath = g.imports.get(m.group(1), "")
    member = m.group(2)
    sym = f"{m.group(1)}.{member}"
    at = m.start()
    if ipath in HASH_FUNCS and member in HASH_FUNCS[ipath]:
        h = HASH_FUNCS[ipath][member]
        g.add(at, {"family": h, "primitive": "xof" if h.startswith("SHAKE") else "hash"}, sym)
    elif ipath == "crypto" and member in CRYPTO_HASH_CONSTS:
        g.add(at, {"family": CRYPTO_HASH_CONSTS[member], "primitive": "hash"}, sym)
    elif ipath in CIPHERS and member in CIPHERS[ipath]:
        fam, prim = CIPHERS[ipath][member]
        g.add(at, {"family": fam, "primitive": prim, "key_size": 256 if "ChaCha" in fam else None}, sym)
    elif ipath == "crypto/rsa" and member in ("GenerateKey",):
        g.add(at, {"family": "RSA"}, sym)
    elif ipath == "crypto/ecdsa" and member in ("Sign", "SignASN1", "Verify", "VerifyASN1"):
        g.add(at, {"family": "ECDSA", "primitive": "signature"}, sym)
    elif ipath == "crypto/elliptic" and member in ("P224", "P256", "P384", "P521"):
        g.add(at, {"family": "EC", "curve": _curve(g, sym)}, sym)
    elif ipath in ("crypto/ed25519", XC + "ed25519") and member in ("GenerateKey", "Sign", "Verify",
                                                                     "NewKeyFromSeed", "VerifyWithOptions"):
        g.add(at, {"family": "Ed25519", "primitive": "signature"}, sym)
    elif ipath == "crypto/ecdh":
        if member == "X25519":
            g.add(at, {"family": "X25519", "primitive": "key-agree"}, sym)
        elif member in ("P256", "P384", "P521"):
            g.add(at, {"family": "ECDH", "curve": _curve(g, sym), "primitive": "key-agree"}, sym)
    elif ipath == XC + "curve25519" and member in ("X25519", "ScalarMult", "ScalarBaseMult"):
        g.add(at, {"family": "X25519", "primitive": "key-agree"}, sym)
    elif ipath == XC + "nacl/box" and member in ("GenerateKey", "Seal", "Open", "Precompute", "SealAnonymous"):
        g.add(at, {"family": "X25519", "primitive": "key-agree", "notes": ["NaCl box: X25519 + XSalsa20-Poly1305."]},
              sym)
    elif ipath == "crypto/dsa" and member in ("GenerateKey", "Sign", "Verify"):
        g.add(at, {"family": "DSA", "primitive": "signature"}, sym)
    elif ipath == "crypto/mlkem":
        ps = "ML-KEM-1024" if member.endswith("1024") else "ML-KEM-768" if member.endswith("768") else None
        if ps and member.startswith(("GenerateKey", "NewDecapsulationKey", "NewEncapsulationKey")):
            g.add(at, {"family": "ML-KEM", "parameter_set": ps, "primitive": "kem"}, sym)
    elif ipath == "crypto/tls":
        if member.startswith("Version"):
            spec = parse_tls_version(member.removeprefix("Version").replace("TLS", "TLSv").replace("SSL", "SSLv"))
            if spec:
                g.add(at, spec, sym, asset=PROTOCOL)
        elif member == "X25519MLKEM768":
            g.add(at, {"family": "Hybrid", "parameter_set": "X25519MLKEM768", "primitive": "kem",
                       "notes": ["Hybrid TLS key exchange: ML-KEM-768 with X25519."]}, sym)
        elif member == "X25519":
            g.add(at, {"family": "X25519", "primitive": "key-agree"}, sym)
        elif member in ("CurveP256", "CurveP384", "CurveP521"):
            g.add(at, {"family": "ECDH", "curve": "P-" + member[-3:].lstrip("P"), "primitive": "key-agree"}, sym)
        elif member.startswith("TLS_"):
            g.add(at, parse_cipher_suite(member), sym, asset=PROTOCOL)
    elif ipath == "crypto/x509" and member in X509_SIGS:
        fam, h = X509_SIGS[member]
        spec = {"family": fam, "hash": h, "primitive": "signature"}
        if fam == "RSA":
            spec["padding"] = "pss" if member.endswith("PSS") else "pkcs1v15"
        g.add(at, spec, sym)
    elif ipath in (XC + "bcrypt",) and member in ("GenerateFromPassword", "CompareHashAndPassword"):
        g.add(at, {"family": "bcrypt", "primitive": "kdf"}, sym)
    elif ipath == XC + "scrypt" and member == "Key":
        g.add(at, {"family": "scrypt", "primitive": "kdf"}, sym)
    elif ipath == XC + "argon2" and member in ("Key", "IDKey"):
        g.add(at, {"family": "Argon2", "primitive": "kdf"}, sym)
    elif JWT_PATH.search(ipath) and member.startswith("SigningMethod"):
        alg = member.removeprefix("SigningMethod")
        alg = {"None": "none", "Ed25519": "EdDSA"}.get(alg, alg)
        g.add(at, parse_jwt_alg(alg), sym)
