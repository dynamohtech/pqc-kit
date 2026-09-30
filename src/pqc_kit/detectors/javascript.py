"""JavaScript and TypeScript detector.

Covers the Node.js crypto and tls modules, the Web Crypto API (crypto.subtle),
jsonwebtoken / jose JWT algorithms, node-forge, crypto-js, @noble/curves and
@noble/post-quantum. Comments are ignored.
"""

from __future__ import annotations

import re

from pqc_kit.catalog import (
    WEBCRYPTO, WEBCRYPTO_PATTERN, JWT_ALG_PATTERN, apply, norm_curve, norm_hash, parse_jwt_alg,
    parse_key_algorithm, parse_openssl_cipher, parse_pqc_name, parse_tls_version,
)
from pqc_kit.detectors.text import Lines, call_args, int_literal, object_block, string_literal, strip_comments
from pqc_kit.model import ALGORITHM, PROTOCOL, Finding

Q = r"""['"`]"""
CREATE_HASH = re.compile(r"\bcreateHash\s*\(\s*" + Q + r"([\w./-]+)" + Q)
CREATE_HMAC = re.compile(r"\bcreateHmac\s*\(\s*" + Q + r"([\w./-]+)" + Q)
CREATE_CIPHERIV = re.compile(r"\bcreate(?:De)?[Cc]ipheriv\s*\(\s*" + Q + r"([\w.-]+)" + Q)
CREATE_CIPHER_OLD = re.compile(r"(?<!cipher\.)\bcreate(?:De)?[Cc]ipher\s*\(\s*" + Q + r"([\w.-]+)" + Q)
CREATE_SIGN = re.compile(r"\bcreate(?:Sign|Verify)\s*\(\s*" + Q + r"([\w.-]+)" + Q)
ONE_SHOT_SIGN = re.compile(r"\bcrypto\s*\.\s*(sign|verify)\s*\(\s*(" + Q + r"[\w.-]+" + Q + r"|null|undefined)")
KEYPAIR = re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*" + Q + r"([\w-]+)" + Q)
GENKEY = re.compile(r"\bgenerateKey(?:Sync)?\s*\(\s*" + Q + r"(aes|hmac)" + Q + r"\s*,\s*\{[^}]*?length\s*:\s*(\d+)")
ECDH = re.compile(r"\bcreateECDH\s*\(\s*" + Q + r"([\w-]+)" + Q)
DH = re.compile(r"\b(createDiffieHellman(?:Group)?|getDiffieHellman)\s*\(")
RSA_ENC = re.compile(r"\b(publicEncrypt|privateDecrypt|privateEncrypt|publicDecrypt)\s*\(")
PBKDF2 = re.compile(r"\bpbkdf2(?:Sync)?\s*\(")
HKDF = re.compile(r"\bhkdf(?:Sync)?\s*\(\s*" + Q + r"([\w-]+)" + Q)
SCRYPT = re.compile(r"\bscrypt(?:Sync)?\s*\(")
WEBCRYPTO_NAME = re.compile(r"\bname\s*:\s*" + Q + r"(" + WEBCRYPTO_PATTERN + r")" + Q)
SUBTLE_CALL = re.compile(r"\bsubtle\s*\.\s*(encrypt|decrypt|sign|verify|digest|generateKey|importKey|deriveKey|"
                         r"deriveBits|wrapKey|unwrapKey|encapsulateKey|encapsulateBits|decapsulateKey|"
                         r"decapsulateBits)\s*\(")
TLS_VERSION = re.compile(r"\b(minVersion|maxVersion)\s*:\s*" + Q + r"(TLSv1(?:\.[123])?|SSLv3)" + Q)
SECURE_PROTOCOL = re.compile(r"\bsecureProtocol\s*:\s*" + Q + r"(\w+?)_(?:client_|server_)?method" + Q)
ECDH_CURVE = re.compile(r"\becdhCurve\s*:\s*" + Q + r"([\w:.-]+)" + Q)
JWT_ALG = re.compile(r"\b(algorithm|alg)\s*:\s*" + Q + r"(" + JWT_ALG_PATTERN + r")" + Q)
JWT_ALGS = re.compile(r"\balgorithms\s*:\s*\[([^\]]*)\]")
FORGE_RSA = re.compile(r"\bpki\s*\.\s*rsa\s*\.\s*generateKeyPair\s*\(")
FORGE_MD = re.compile(r"\bforge\s*\.\s*md\s*\.\s*(md5|sha1|sha256|sha384|sha512)\s*\.\s*create\s*\(")
FORGE_CIPHER = re.compile(r"\bcipher\s*\.\s*create(?:De)?[Cc]ipher\s*\(\s*" + Q + r"([\w-]+)" + Q)
CRYPTOJS = re.compile(r"\bCryptoJS\s*\.\s*(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160|HmacMD5|HmacSHA1|"
                      r"HmacSHA224|HmacSHA256|HmacSHA384|HmacSHA512|PBKDF2|AES|DES|TripleDES|RC4|RC4Drop|Rabbit)\b")
CRYPTOJS_ECB = re.compile(r"\bCryptoJS\s*\.\s*mode\s*\.\s*ECB\b")
NOBLE_IMPORT = re.compile(r"""(?:from\s+|require\s*\(\s*)['"](@noble/(?:curves|post-quantum)[\w/.-]*)['"]""")
NOBLE_PQ = re.compile(r"\b(ml_kem(?:512|768|1024)|ml_dsa(?:44|65|87)|slh_dsa_(?:sha2|shake)_(?:128|192|256)[sf])\b")
NOBLE_CURVES = {"secp256k1": ("ECDSA", "secp256k1"), "p256": ("ECDSA", "P-256"), "p384": ("ECDSA", "P-384"),
                "p521": ("ECDSA", "P-521"), "ed25519": ("Ed25519", None), "ed448": ("Ed448", None),
                "x25519": ("X25519", None), "x448": ("X448", None), "nist": ("ECDSA", None)}

_DH_GROUPS = {"modp1": 768, "modp2": 1024, "modp5": 1536, "modp14": 2048, "modp15": 3072, "modp16": 4096,
              "modp17": 6144, "modp18": 8192}


class _File:
    def __init__(self, path: str, source: str, in_tests: bool):
        self.path = path
        self.in_tests = in_tests
        self.text = strip_comments(source, backtick_strings=True)
        self.lines = Lines(self.text)
        self.findings: list[Finding] = []

    def add(self, offset: int, spec: dict | None, symbol: str, asset: str = ALGORITHM, **extra) -> Finding | None:
        if not spec or not spec.get("family"):
            return None
        line, col = self.lines.at(offset)
        f = Finding(asset=asset, family="", path=self.path, line=line, column=col, symbol=symbol,
                    detector="javascript", in_tests=self.in_tests)
        apply(f, spec)
        for k, v in extra.items():
            if v is not None:
                if k == "notes":
                    f.notes.extend(v)
                else:
                    setattr(f, k, v)
        self.findings.append(f)
        return f


def _digest_spec(name: str) -> dict | None:
    h = norm_hash(name)
    return {"family": h, "primitive": "xof" if h and h.startswith("SHAKE") else "hash"} if h else None


def scan_javascript(path: str, source: str, in_tests: bool) -> list[Finding]:  # noqa: C901 - flat rule list
    js = _File(path, source, in_tests)
    t = js.text

    for m in CREATE_HASH.finditer(t):
        js.add(m.start(), _digest_spec(m.group(1)) or {"family": "Unknown"}, f"createHash('{m.group(1)}')")
    for m in CREATE_HMAC.finditer(t):
        js.add(m.start(), {"family": "HMAC", "hash": norm_hash(m.group(1)), "primitive": "mac"},
               f"createHmac('{m.group(1)}')")
    for m in CREATE_CIPHERIV.finditer(t):
        spec = parse_openssl_cipher(m.group(1))
        js.add(m.start(), spec or {"family": "Unknown"}, f"createCipheriv('{m.group(1)}')")
    for m in CREATE_CIPHER_OLD.finditer(t):
        spec = parse_openssl_cipher(m.group(1)) or {"family": "Unknown"}
        f = js.add(m.start(), spec, f"createCipher('{m.group(1)}')")
        if f:
            f.family = "EVP_BytesToKey" if f.family == "Unknown" else f.family
            f.notes.append("crypto.createCipher derives the key with MD5 and no salt and uses a static IV; "
                           "Node.js has removed it (DEP0106).")
            f.details["force_weak"] = "crypto.createCipher (DEP0106): MD5 key derivation without salt, static IV."
    for m in CREATE_SIGN.finditer(t):
        name = m.group(1)
        low = name.lower()
        if low.startswith("rsa-") or low.startswith("sha") and "withrsa" in low:
            spec = {"family": "RSA", "hash": norm_hash(low.removeprefix("rsa-")), "padding": "pkcs1v15",
                    "primitive": "signature"}
        elif low.startswith("ecdsa-with-"):
            spec = {"family": "ECDSA", "hash": norm_hash(low.removeprefix("ecdsa-with-")), "primitive": "signature"}
        else:
            spec = {"family": "Signature", "hash": norm_hash(name), "primitive": "signature"}
        js.add(m.start(), spec, f"createSign('{name}')")
    for m in ONE_SHOT_SIGN.finditer(t):
        name = string_literal(m.group(2))
        js.add(m.start(), {"family": "Signature", "hash": norm_hash(name) if name else None, "primitive": "signature"},
               f"crypto.{m.group(1)}")
    for m in KEYPAIR.finditer(t):
        kind = m.group(1).lower()
        args = call_args(t, t.index("(", m.start())) or []
        opts = args[1] if len(args) > 1 else ""
        spec = _keypair_spec(kind, opts)
        js.add(m.start(), spec or {"family": "Unknown"}, f"generateKeyPair('{m.group(1)}')",
               functions=["keygen"])
    for m in GENKEY.finditer(t):
        fam = "AES" if m.group(1) == "aes" else "HMAC"
        size = int(m.group(2))
        js.add(m.start(), {"family": fam, "key_size": size if fam == "AES" else None,
                           "primitive": "block-cipher" if fam == "AES" else "mac"}, f"generateKey('{m.group(1)}')")
    for m in ECDH.finditer(t):
        js.add(m.start(), {"family": "ECDH", "curve": norm_curve(m.group(1)), "primitive": "key-agree"},
               f"createECDH('{m.group(1)}')")
    for m in DH.finditer(t):
        args = call_args(t, m.end() - 1) or []
        size = None
        if args:
            s = string_literal(args[0])
            size = _DH_GROUPS.get(s.lower()) if s else int_literal(args[0])
        js.add(m.start(), {"family": "DH", "key_size": size, "primitive": "key-agree"}, m.group(1))
    for m in RSA_ENC.finditer(t):
        region = t[m.end():m.end() + 300]
        pad = "pkcs1v15" if "RSA_PKCS1_PADDING" in region else "raw" if "RSA_NO_PADDING" in region else None
        if pad is None and m.group(1) in ("publicEncrypt", "privateDecrypt"):
            pad = "oaep"  # Node.js default padding for publicEncrypt/privateDecrypt
        prim = "pke" if m.group(1) in ("publicEncrypt", "privateDecrypt") else "signature"
        js.add(m.start(), {"family": "RSA", "padding": pad, "primitive": prim}, f"crypto.{m.group(1)}")
    for m in PBKDF2.finditer(t):
        args = call_args(t, m.end() - 1) or []
        digest = None
        for a in reversed(args):
            s = string_literal(a)
            if s and norm_hash(s):
                digest = norm_hash(s)
                break
        js.add(m.start(), {"family": "PBKDF2", "hash": digest, "primitive": "kdf"}, "pbkdf2")
    for m in HKDF.finditer(t):
        js.add(m.start(), {"family": "HKDF", "hash": norm_hash(m.group(1)), "primitive": "kdf"}, "hkdf")
    for m in SCRYPT.finditer(t):
        js.add(m.start(), {"family": "scrypt", "primitive": "kdf"}, "scrypt")

    # Web Crypto: algorithm objects { name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256' } ...
    seen_objects: set[int] = set()
    for m in WEBCRYPTO_NAME.finditer(t):
        if m.group(1).startswith("SHA-") and re.search(r"hash\s*:\s*\{\s*$", t[max(0, m.start() - 40):m.start()]):
            continue  # the hash inside an algorithm object; recorded on that algorithm
        block = object_block(t, m.start())
        spec = dict(WEBCRYPTO[m.group(1)])
        _webcrypto_params(spec, block)
        js.add(m.start(), spec, f"{{name: '{m.group(1)}'}}")
        seen_objects.add(m.start())
    for m in SUBTLE_CALL.finditer(t):
        args = call_args(t, m.end() - 1) or []
        for a in args:
            s = string_literal(a)
            if s and s in WEBCRYPTO:
                js.add(m.start(), dict(WEBCRYPTO[s]), f"subtle.{m.group(1)}('{s}')")

    for m in TLS_VERSION.finditer(t):
        js.add(m.start(), parse_tls_version(m.group(2)), f"{m.group(1)}: '{m.group(2)}'", asset=PROTOCOL)
    for m in SECURE_PROTOCOL.finditer(t):
        js.add(m.start(), parse_tls_version(m.group(1)) or {"family": "TLS"}, f"secureProtocol: '{m.group(1)}'",
               asset=PROTOCOL)
    for m in ECDH_CURVE.finditer(t):
        for g in m.group(1).split(":"):
            pq = parse_pqc_name(g)
            if pq:
                js.add(m.start(), pq, f"ecdhCurve: '{g}'")
            elif g.lower() in ("x25519", "x448"):
                js.add(m.start(), {"family": g.upper().replace("X", "X", 1), "primitive": "key-agree"},
                       f"ecdhCurve: '{g}'")
            elif g.lower() != "auto":
                js.add(m.start(), {"family": "ECDH", "curve": norm_curve(g), "primitive": "key-agree"},
                       f"ecdhCurve: '{g}'")

    for m in JWT_ALG.finditer(t):
        js.add(m.start(), parse_jwt_alg(m.group(2)), f"{m.group(1)}: '{m.group(2)}'")
    for m in JWT_ALGS.finditer(t):
        for s in re.findall(r"['\"`]([\w+-]+)['\"`]", m.group(1)):
            js.add(m.start(), parse_jwt_alg(s), f"algorithms: ['{s}']")

    for m in FORGE_RSA.finditer(t):
        args = call_args(t, m.end() - 1) or []
        size = int_literal(args[0]) if args else None
        if size is None and args:
            bm = re.search(r"\bbits\s*:\s*(\d+)", args[0])
            size = int(bm.group(1)) if bm else None
        js.add(m.start(), {"family": "RSA", "key_size": size, "functions": ["keygen"]}, "forge.pki.rsa.generateKeyPair")
    for m in FORGE_MD.finditer(t):
        js.add(m.start(), _digest_spec(m.group(1)), f"forge.md.{m.group(1)}")
    for m in FORGE_CIPHER.finditer(t):
        fam, _, mode = m.group(1).upper().partition("-")
        family = {"AES": "AES", "3DES": "3DES", "DES": "DES", "RC2": "RC2"}.get(fam)
        spec = {"family": family, "mode": mode.lower() or None, "primitive": "block-cipher"} if family else None
        js.add(m.start(), spec or {"family": "Unknown"}, f"forge.cipher('{m.group(1)}')")

    for m in CRYPTOJS.finditer(t):
        name = m.group(1)
        if name.startswith("Hmac"):
            spec = {"family": "HMAC", "hash": norm_hash(name[4:]), "primitive": "mac"}
        elif name == "PBKDF2":
            region = t[m.end():m.end() + 300]
            hm = re.search(r"hasher\s*:\s*CryptoJS\s*\.\s*algo\s*\.\s*(\w+)", region)
            spec = {"family": "PBKDF2", "hash": norm_hash(hm.group(1)) if hm else None, "primitive": "kdf"}
            if not hm:
                spec["notes"] = ["No hasher option: crypto-js before 4.2.0 defaults to SHA-1 with 1 iteration "
                                 "(CVE-2023-46233); 4.2.0 and later default to SHA-256 with 250,000 iterations."]
                spec["details"] = {"force_unknown": "PBKDF2 hash depends on the crypto-js version."}
        elif name in ("AES", "DES", "TripleDES", "RC4", "RC4Drop", "Rabbit"):
            fam = {"TripleDES": "3DES", "RC4Drop": "RC4", "Rabbit": "Rabbit"}.get(name, name)
            if fam == "Rabbit":
                continue
            spec = {"family": fam, "primitive": "stream-cipher" if fam == "RC4" else "block-cipher"}
        else:
            spec = _digest_spec("SHA3-512" if name == "SHA3" else name)
        js.add(m.start(), spec, f"CryptoJS.{name}")
    for m in CRYPTOJS_ECB.finditer(t):
        js.add(m.start(), {"family": "BlockCipher", "mode": "ecb", "primitive": "block-cipher"}, "CryptoJS.mode.ECB")

    for m in NOBLE_IMPORT.finditer(t):
        module = m.group(1)
        if module.startswith("@noble/post-quantum"):
            continue
        key = module.split("/")[-1].removesuffix(".js")
        if key in NOBLE_CURVES:
            fam, curve = NOBLE_CURVES[key]
            js.add(m.start(), {"family": fam, "curve": curve,
                               "primitive": "key-agree" if fam.startswith("X") else "signature"}, module)
    if "@noble/post-quantum" in t:
        for m in NOBLE_PQ.finditer(t):
            name = m.group(1)
            spec = parse_pqc_name(name.replace("_", "-"))
            if spec:
                js.add(m.start(), spec, name)
    return js.findings


def _keypair_spec(kind: str, opts: str) -> dict | None:
    pq = parse_pqc_name(kind)
    if pq:
        return pq
    if kind in ("rsa", "rsa-pss"):
        m = re.search(r"\bmodulusLength\s*:\s*(\w+)", opts)
        spec = {"family": "RSA", "key_size": int_literal(m.group(1)) if m else None}
        if kind == "rsa-pss":
            spec.update(padding="pss", primitive="signature")
        return spec
    if kind == "dsa":
        m = re.search(r"\bmodulusLength\s*:\s*(\d+)", opts)
        return {"family": "DSA", "key_size": int(m.group(1)) if m else None, "primitive": "signature"}
    if kind == "ec":
        m = re.search(r"\bnamedCurve\s*:\s*['\"`]([\w-]+)['\"`]", opts)
        return {"family": "EC", "curve": norm_curve(m.group(1)) if m else None}
    if kind == "dh":
        m = re.search(r"\b(?:primeLength|prime)\s*:\s*(\d+)", opts)
        g = re.search(r"\bgroup\s*:\s*['\"`](\w+)['\"`]", opts)
        size = int(m.group(1)) if m else _DH_GROUPS.get(g.group(1).lower()) if g else None
        return {"family": "DH", "key_size": size, "primitive": "key-agree"}
    return parse_key_algorithm(kind)


def _webcrypto_params(spec: dict, block: str) -> None:
    m = re.search(r"\bmodulusLength\s*:\s*(\d+)", block)
    if m and spec["family"] == "RSA":
        spec["key_size"] = int(m.group(1))
    m = re.search(r"\bnamedCurve\s*:\s*['\"`]([\w-]+)['\"`]", block)
    if m:
        spec["curve"] = norm_curve(m.group(1))
    m = re.search(r"\blength\s*:\s*(128|192|256)\b", block)
    if m and spec["family"] == "AES":
        spec["key_size"] = int(m.group(1))
    m = re.search(r"\bhash\s*:\s*(?:\{\s*name\s*:\s*)?['\"`](SHA-\d+)['\"`]", block)
    if m and spec["family"] in ("RSA", "ECDSA", "HMAC", "PBKDF2", "HKDF"):
        spec["hash"] = norm_hash(m.group(1))
