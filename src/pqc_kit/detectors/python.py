"""Python detector. It reads the syntax tree (ast), so import aliases, keyword
arguments and module-level constants are resolved. Code is parsed, never run.

Libraries covered: hashlib, hmac, ssl, cryptography (pyca), PyCryptodome
(Crypto / Cryptodome), paramiko, PyJWT and python-jose, liboqs-python (oqs),
kyber-py and dilithium-py.
"""

from __future__ import annotations

import ast
import re

from pqc_kit.catalog import (
    apply, norm_curve, norm_hash, parse_jwt_alg, parse_pqc_name, parse_tls_version,
)
from pqc_kit.model import ALGORITHM, PROTOCOL, Finding

CRY = "cryptography.hazmat.primitives."
ASYM = CRY + "asymmetric."

_CRYPTO_HASH_MODULES = {
    "MD2": "MD2", "MD4": "MD4", "MD5": "MD5", "SHA1": "SHA-1", "SHA": "SHA-1", "SHA224": "SHA-224",
    "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA3_224": "SHA3-224", "SHA3_256": "SHA3-256",
    "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512", "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256",
    "BLAKE2b": "BLAKE2b", "BLAKE2s": "BLAKE2s", "RIPEMD160": "RIPEMD-160", "RIPEMD": "RIPEMD-160",
}
_PYCA_HASHES = {
    "MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384",
    "SHA512": "SHA-512", "SHA512_224": "SHA-512/224", "SHA512_256": "SHA-512/256", "SHA3_224": "SHA3-224",
    "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512", "SHAKE128": "SHAKE128",
    "SHAKE256": "SHAKE256", "BLAKE2b": "BLAKE2b", "BLAKE2s": "BLAKE2s", "SM3": "SM3",
}
_PYCA_CIPHERS = {
    "AES": ("AES", None), "AES128": ("AES", 128), "AES256": ("AES", 256), "TripleDES": ("3DES", None),
    "Blowfish": ("Blowfish", None), "ARC4": ("RC4", None), "CAST5": ("CAST5", None), "IDEA": ("IDEA", None),
    "SEED": ("SEED", 128), "Camellia": ("Camellia", None), "ChaCha20": ("ChaCha20", 256), "SM4": ("SM4", 128),
    "RC2": ("RC2", None),
}
_PYCA_AEAD = {"AESGCM": ("AES", "gcm"), "AESCCM": ("AES", "ccm"), "AESOCB3": ("AES", "ocb"),
              "AESSIV": ("AES", "siv"), "AESGCMSIV": ("AES", "gcm-siv"),
              "ChaCha20Poly1305": ("ChaCha20-Poly1305", None)}
_PYCRYPTODOME_CIPHERS = {"AES": "AES", "DES": "DES", "DES3": "3DES", "ARC2": "RC2", "ARC4": "RC4",
                         "Blowfish": "Blowfish", "CAST": "CAST5", "ChaCha20": "ChaCha20",
                         "ChaCha20_Poly1305": "ChaCha20-Poly1305", "Salsa20": "Salsa20"}
_CURVE_CLASSES = {"SECP192R1": "P-192", "SECP224R1": "P-224", "SECP256R1": "P-256", "SECP384R1": "P-384",
                  "SECP521R1": "P-521", "SECP256K1": "secp256k1", "BrainpoolP256R1": "brainpoolP256r1",
                  "BrainpoolP384R1": "brainpoolP384r1", "BrainpoolP512R1": "brainpoolP512r1",
                  "SECT163K1": "sect163k1", "SECT233K1": "sect233k1", "SECT283K1": "sect283k1",
                  "SECT409K1": "sect409k1", "SECT571K1": "sect571k1", "SECT163R2": "sect163r2",
                  "SECT233R1": "sect233r1", "SECT283R1": "sect283r1", "SECT409R1": "sect409r1",
                  "SECT571R1": "sect571r1"}
_SSL_ATTRS = {"PROTOCOL_SSLv2": "SSLv2", "PROTOCOL_SSLv3": "SSLv3", "PROTOCOL_TLSv1": "TLSv1",
              "PROTOCOL_TLSv1_1": "TLSv1.1", "PROTOCOL_TLSv1_2": "TLSv1.2", "TLSVersion.SSLv3": "SSLv3",
              "TLSVersion.TLSv1": "TLSv1", "TLSVersion.TLSv1_1": "TLSv1.1", "TLSVersion.TLSv1_2": "TLSv1.2",
              "TLSVersion.TLSv1_3": "TLSv1.3"}


def _normalise(q: str) -> str:
    if q.startswith("Cryptodome."):
        q = "Crypto." + q[len("Cryptodome."):]
    q = q.replace("cryptography.hazmat.decrepit.ciphers.", CRY + "ciphers.")
    return q


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: str, tree: ast.Module, in_tests: bool):
        self.path = path
        self.in_tests = in_tests
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}
        self.consts: dict[str, object] = {}
        self.consumed: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":
                        self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
                value = node.value
            else:
                continue
            name = node.targets[0].id if isinstance(node, ast.Assign) else node.target.id
            if isinstance(value, ast.Constant) and isinstance(value.value, (int, str)) and not isinstance(
                    value.value, bool):
                self.consts[name] = value.value

    # -- helpers ------------------------------------------------------------

    def qual(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            q = self.aliases.get(node.id)
            return _normalise(q) if q else None
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def add(self, node: ast.AST, family: str, symbol: str, asset: str = ALGORITHM, **fields) -> Finding:
        notes = fields.pop("notes", [])
        details = fields.pop("details", {})
        f = Finding(asset=asset, family=family, path=self.path, line=getattr(node, "lineno", None),
                    column=(getattr(node, "col_offset", 0) or 0) + 1, symbol=symbol, detector="python",
                    in_tests=self.in_tests, notes=list(notes), details=dict(details))
        for k, v in fields.items():
            if v is not None:
                setattr(f, k, v)
        self.findings.append(f)
        return f

    def add_spec(self, node: ast.AST, spec: dict | None, symbol: str, **extra) -> Finding | None:
        if not spec:
            return None
        f = Finding(asset=ALGORITHM, family="", path=self.path, line=getattr(node, "lineno", None),
                    column=(getattr(node, "col_offset", 0) or 0) + 1, symbol=symbol, detector="python",
                    in_tests=self.in_tests)
        if apply(f, spec) is None:
            return None
        for k, v in extra.items():
            if v is not None:
                setattr(f, k, v)
        self.findings.append(f)
        return f

    @staticmethod
    def arg(call: ast.Call, pos: int | None, *names: str) -> ast.AST | None:
        for kw in call.keywords:
            if kw.arg in names:
                return kw.value
        if pos is not None and len(call.args) > pos and not isinstance(call.args[pos], ast.Starred):
            return call.args[pos]
        return None

    def int_val(self, node: ast.AST | None) -> int | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name) and isinstance(self.consts.get(node.id), int):
            return self.consts[node.id]
        return None

    def str_val(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and isinstance(self.consts.get(node.id), str):
            return self.consts[node.id]
        return None

    def consume(self, node: ast.AST | None) -> None:
        if node is not None:
            for n in ast.walk(node):
                self.consumed.add(id(n))

    def hash_of(self, node: ast.AST | None) -> str | None:
        """Hash named by hashes.SHA256(), hashlib.sha256, SHA256 (PyCryptodome module) or 'sha256'."""
        if node is None:
            return None
        self.consume(node)
        s = self.str_val(node)
        if s:
            return norm_hash(s)
        target = node.func if isinstance(node, ast.Call) else node
        q = self.qual(target)
        if not q:
            return None
        last = q.split(".")[-1]
        if q.startswith(CRY + "hashes."):
            return _PYCA_HASHES.get(last)
        if q.startswith("Crypto.Hash."):
            mod = q.split(".")[2]
            return _CRYPTO_HASH_MODULES.get(mod)
        if q.startswith("hashlib."):
            return norm_hash(last)
        return None

    def curve_of(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        self.consume(node)
        s = self.str_val(node)
        if s:
            return norm_curve(s)
        target = node.func if isinstance(node, ast.Call) else node
        q = self.qual(target)
        if q and q.startswith(ASYM + "ec."):
            return _CURVE_CLASSES.get(q.split(".")[-1])
        return None

    # -- visitors -----------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        if id(node) not in self.consumed:
            q = self.qual(node.func)
            if q:
                self.handle_call(node, q)
        self._consume_chain(node.func)
        self.generic_visit(node)

    def _consume_chain(self, node: ast.AST) -> None:
        """Mark a.b.c (but not calls inside it) as explained by the call that uses it."""
        while isinstance(node, ast.Attribute):
            self.consumed.add(id(node))
            node = node.value
        if isinstance(node, ast.Name):
            self.consumed.add(id(node))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if id(node) not in self.consumed:
            q = self.qual(node)
            if q:
                self.handle_reference(node, q)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if id(node) not in self.consumed and node.id in self.aliases:
            q = self.qual(node)
            if q:
                self.handle_reference(node, q)

    # -- rules --------------------------------------------------------------

    def handle_reference(self, node: ast.AST, q: str) -> None:
        """Names used without a call: ssl constants, hash constructors passed as values, PQC classes."""
        if q.startswith("ssl."):
            key = q[4:]
            if key in _SSL_ATTRS:
                spec = parse_tls_version(_SSL_ATTRS[key])
                self.add_spec(node, spec, q, asset=PROTOCOL)
            return
        if q.startswith("hashlib.") and norm_hash(q.split(".")[-1]):
            self.add_spec(node, {"family": norm_hash(q.split(".")[-1]), "primitive": "hash"}, q)
            return
        m = re.match(r"(kyber_py\.ml_kem|dilithium_py\.ml_dsa|kyber_py\.kyber|dilithium_py\.dilithium)\.(\w+)$", q)
        if m:
            self.add_spec(node, parse_pqc_name(m.group(2)), q)
            return
        if q.startswith("Crypto.Cipher.") and q.endswith(".MODE_ECB"):
            self.add(node, "BlockCipher", q, mode="ecb", primitive="block-cipher")

    def handle_call(self, node: ast.Call, q: str) -> None:  # noqa: C901 - a flat rule table reads best
        last = q.split(".")[-1]
        short = ".".join(q.split(".")[-2:])

        # hashlib / hmac ------------------------------------------------------
        if q.startswith("hashlib."):
            if last == "new":
                name = self.str_val(self.arg(node, 0, "name"))
                h = norm_hash(name) if name else None
                if h:
                    self._hash(node, h, q)
                else:
                    self.add(node, "Unknown", q, primitive="hash", confidence="low",
                             notes=["Hash name chosen at run time."])
            elif last == "pbkdf2_hmac":
                h = norm_hash(self.str_val(self.arg(node, 0, "hash_name")))
                self.add(node, "PBKDF2", q, hash=h, primitive="kdf", functions=["keyderive"])
            elif last == "scrypt":
                self.add(node, "scrypt", q, primitive="kdf", functions=["keyderive"])
            elif last == "file_digest":
                h = self.hash_of(self.arg(node, 1, "digest"))
                if h:
                    self._hash(node, h, q)
            elif norm_hash(last):
                self._hash(node, norm_hash(last), q)
            return
        if q in ("hmac.new", "hmac.HMAC", "hmac.digest"):
            pos = 2
            h = self.hash_of(self.arg(node, pos, "digestmod", "digest"))
            self.add(node, "HMAC", q, hash=h, primitive="mac", functions=["tag"])
            return

        # cryptography (pyca) ------------------------------------------------
        if q.startswith(ASYM):
            self._pyca_asymmetric(node, q, last, short)
            return
        if q.startswith(CRY + "hashes."):
            if last in _PYCA_HASHES:
                self._hash(node, _PYCA_HASHES[last], short)
            return
        if q == CRY + "ciphers.Cipher":
            alg_node, mode_node = self.arg(node, 0, "algorithm"), self.arg(node, 1, "mode")
            fam, size = self._pyca_cipher(alg_node)
            mode = self._pyca_mode(mode_node)
            self.consume(alg_node)
            self.consume(mode_node)
            if fam:
                self.add(node, fam, "Cipher", key_size=size, mode=mode,
                         primitive="ae" if mode == "gcm" else "stream-cipher" if fam in ("RC4", "ChaCha20")
                         else "block-cipher", functions=["encrypt", "decrypt"])
            elif mode:
                self.add(node, "BlockCipher", "Cipher", mode=mode, primitive="block-cipher")
            return
        if q.startswith(CRY + "ciphers.algorithms."):
            fam, size = _PYCA_CIPHERS.get(last, (None, None))
            if fam:
                self.add(node, fam, short, key_size=size or self._key_len(self.arg(node, 0, "key")),
                         primitive="stream-cipher" if fam in ("RC4", "ChaCha20") else "block-cipher")
            return
        if q.startswith(CRY + "ciphers.modes."):
            if last == "ECB":
                self.add(node, "BlockCipher", short, mode="ecb", primitive="block-cipher")
            return
        if q.startswith(CRY + "ciphers.aead."):
            name = q.split(".")[-2] if last == "generate_key" else last
            if name in _PYCA_AEAD:
                fam, mode = _PYCA_AEAD[name]
                size = self.int_val(self.arg(node, 0, "bit_length")) if last == "generate_key" else None
                if name == "AESSIV" and size:
                    size //= 2
                self.add(node, fam, f"{name}.{last}" if last == "generate_key" else name,
                         key_size=size or (256 if fam == "ChaCha20-Poly1305" else None), mode=mode, primitive="ae",
                         functions=["keygen"] if last == "generate_key" else ["encrypt", "decrypt"])
            return
        if q.startswith(CRY + "kdf."):
            kdf = {"PBKDF2HMAC": "PBKDF2", "HKDF": "HKDF", "HKDFExpand": "HKDF", "Scrypt": "scrypt",
                   "ConcatKDFHash": "ConcatKDF", "ConcatKDFHMAC": "ConcatKDF", "X963KDF": "X963KDF",
                   "KBKDFHMAC": "KBKDF", "Argon2id": "Argon2"}.get(last)
            if kdf:
                h = self.hash_of(self.arg(node, 0, "algorithm")) if kdf not in ("scrypt", "Argon2") else None
                self.add(node, kdf, last, hash=h, primitive="kdf", functions=["keyderive"])
            return
        if q == CRY + "hmac.HMAC":
            self.add(node, "HMAC", "hmac.HMAC", hash=self.hash_of(self.arg(node, 1, "algorithm")), primitive="mac")
            return
        if q == CRY + "cmac.CMAC":
            self.consume(self.arg(node, 0, "algorithm"))
            self.add(node, "CMAC", "cmac.CMAC", primitive="mac")
            return
        if q == CRY + "poly1305.Poly1305":
            self.add(node, "Poly1305", "Poly1305", primitive="mac")
            return
        if q == "cryptography.fernet.Fernet" or q == "cryptography.fernet.MultiFernet":
            self.add(node, "AES", last, key_size=128, mode="cbc", primitive="block-cipher",
                     notes=["Fernet: AES-128-CBC with HMAC-SHA256."])
            return

        # PyCryptodome --------------------------------------------------------
        if q.startswith("Crypto."):
            self._pycryptodome(node, q, last)
            return

        # paramiko -------------------------------------------------------------
        if q.startswith("paramiko."):
            cls = next((p for p in q.split(".") if p.endswith("Key")), "")
            fam = {"RSAKey": "RSA", "DSSKey": "DSA", "ECDSAKey": "ECDSA", "Ed25519Key": "Ed25519"}.get(cls)
            if fam:
                size = self.int_val(self.arg(node, 0, "bits")) if last == "generate" else None
                curve = None
                if fam == "ECDSA" and last == "generate":
                    curve = {256: "P-256", 384: "P-384", 521: "P-521"}.get(size or 256)
                    size = None
                self.add(node, fam, f"paramiko.{cls}.{last}" if last != cls else f"paramiko.{cls}",
                         key_size=size, curve=curve, primitive="signature",
                         functions=["keygen"] if last == "generate" else [])
            return

        # JWT ------------------------------------------------------------------
        if re.match(r"(jwt|jose\.jwt|jose\.jws|jwt\.api_jwt|jwt\.api_jws)\.(encode|decode|sign|verify)$", q):
            algs: list[str] = []
            single = self.str_val(self.arg(node, None, "algorithm"))
            if single:
                algs.append(single)
            many = self.arg(node, None, "algorithms")
            if isinstance(many, (ast.List, ast.Tuple, ast.Set)):
                algs += [s for s in (self.str_val(e) for e in many.elts) if s]
            elif self.str_val(many):
                algs.append(self.str_val(many))
            for a in algs:
                self.add_spec(node, parse_jwt_alg(a), q)
            return

        # liboqs-python -------------------------------------------------------------
        if q in ("oqs.KeyEncapsulation", "oqs.Signature", "oqs.oqs.KeyEncapsulation", "oqs.oqs.Signature"):
            name = self.str_val(self.arg(node, 0, "alg_name"))
            spec = parse_pqc_name(name) if name else None
            if spec:
                self.add_spec(node, spec, q)
            else:
                self.add(node, "Unknown", q, confidence="low", notes=[f"liboqs algorithm {name or '(dynamic)'}"])
            return
        m = re.match(r"(kyber_py\.ml_kem|dilithium_py\.ml_dsa|kyber_py\.kyber|dilithium_py\.dilithium)\.(\w+)", q)
        if m:
            self.add_spec(node, parse_pqc_name(m.group(2)), q)

    def _hash(self, node: ast.Call, h: str, symbol: str) -> None:
        details = {}
        uf = self.arg(node, None, "usedforsecurity")
        if isinstance(uf, ast.Constant) and uf.value is False:
            details["non_security"] = True
        self.add(node, h, symbol, primitive="xof" if h.startswith("SHAKE") else "hash", functions=["digest"],
                 details=details)

    def _key_len(self, node: ast.AST | None) -> int | None:
        """AES(os.urandom(32)) or AES(b'...16 bytes...') -> key size in bits."""
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            return len(node.value) * 8 if len(node.value) in (16, 24, 32) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):  # b"k" * 16
            parts = [node.left, node.right]
            data = next((p.value for p in parts if isinstance(p, ast.Constant) and isinstance(p.value, bytes)), None)
            count = next((self.int_val(p) for p in parts if self.int_val(p) is not None), None)
            if data is not None and count is not None and len(data) * count in (16, 24, 32):
                return len(data) * count * 8
        if isinstance(node, ast.Call):
            q = self.qual(node.func) or ""
            if q in ("os.urandom", "secrets.token_bytes", "Crypto.Random.get_random_bytes"):
                n = self.int_val(node.args[0]) if node.args else None
                return n * 8 if n in (16, 24, 32) else None
        return None

    def _pyca_cipher(self, node: ast.AST | None) -> tuple[str | None, int | None]:
        if isinstance(node, ast.Call):
            q = self.qual(node.func) or ""
            if q.startswith(CRY + "ciphers.algorithms."):
                fam, size = _PYCA_CIPHERS.get(q.split(".")[-1], (None, None))
                return fam, size or self._key_len(node.args[0] if node.args else None)
        return None, None

    def _pyca_mode(self, node: ast.AST | None) -> str | None:
        target = node.func if isinstance(node, ast.Call) else node
        q = self.qual(target) if target is not None else None
        if q and q.startswith(CRY + "ciphers.modes."):
            return {"GCM": "gcm", "CBC": "cbc", "CTR": "ctr", "ECB": "ecb", "CFB": "cfb", "CFB8": "cfb",
                    "OFB": "ofb", "XTS": "xts"}.get(q.split(".")[-1])
        return None

    def _pyca_asymmetric(self, node: ast.Call, q: str, last: str, short: str) -> None:
        rest = q[len(ASYM):]
        mod = rest.split(".")[0]
        if rest == "rsa.generate_private_key":
            self.add(node, "RSA", short, key_size=self.int_val(self.arg(node, 1, "key_size")), functions=["keygen"])
        elif rest in ("dsa.generate_private_key", "dsa.generate_parameters"):
            self.add(node, "DSA", short, key_size=self.int_val(self.arg(node, 0, "key_size")),
                     primitive="signature", functions=["keygen"])
        elif rest == "dh.generate_parameters":
            self.add(node, "DH", short, key_size=self.int_val(self.arg(node, 1, "key_size")),
                     primitive="key-agree", functions=["keygen"])
        elif rest in ("ec.generate_private_key", "ec.derive_private_key"):
            curve = self.curve_of(self.arg(node, 0 if last == "generate_private_key" else 1, "curve"))
            self.add(node, "EC", short, curve=curve, functions=["keygen"])
        elif rest == "ec.ECDSA":
            self.add(node, "ECDSA", short, hash=self.hash_of(self.arg(node, 0, "algorithm")), primitive="signature",
                     functions=["sign", "verify"])
        elif rest == "ec.ECDH":
            self.add(node, "ECDH", short, primitive="key-agree", functions=["keyderive"])
        elif rest == "padding.OAEP":
            mgf, alg = self.arg(node, 0, "mgf"), self.arg(node, 1, "algorithm")
            h = self.hash_of(alg)
            self.consume(mgf)
            self.add(node, "RSA", short, padding="oaep", hash=h, primitive="pke", functions=["encrypt", "decrypt"])
        elif rest == "padding.PSS":
            self.consume(self.arg(node, 0, "mgf"))
            self.add(node, "RSA", short, padding="pss", primitive="signature", functions=["sign", "verify"])
        elif rest == "padding.PKCS1v15":
            self.add(node, "RSA", short, padding="pkcs1v15")
        elif mod == "ec" and last in _CURVE_CLASSES:
            self.add(node, "EC", short, curve=_CURVE_CLASSES[last])
        elif mod in ("ed25519", "ed448", "x25519", "x448"):
            fam = {"ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519", "x448": "X448"}[mod]
            self.add(node, fam, ".".join(rest.split(".")[-2:]), primitive="key-agree" if fam[0] == "X" else "signature",
                     functions=["keygen"] if last == "generate" else [])

    def _pycryptodome(self, node: ast.Call, q: str, last: str) -> None:
        parts = q.split(".")
        if len(parts) < 3:
            return
        pkg, mod = parts[1], parts[2]
        sym = ".".join(parts[2:])
        if pkg == "PublicKey":
            fam = {"RSA": "RSA", "DSA": "DSA", "ECC": "EC", "ElGamal": "ElGamal"}.get(mod)
            if not fam:
                return
            size = self.int_val(self.arg(node, 0, "bits")) if last == "generate" and fam != "EC" else None
            curve = self.curve_of(self.arg(node, None, "curve")) if fam == "EC" else None
            self.add(node, fam, sym, key_size=size, curve=curve, functions=["keygen"] if last == "generate" else [])
        elif pkg == "Cipher" and last == "new":
            if mod == "PKCS1_OAEP":
                self.add(node, "RSA", sym, padding="oaep", primitive="pke",
                         hash=self.hash_of(self.arg(node, 1, "hashAlgo")) or "SHA-1",
                         functions=["encrypt", "decrypt"])
                return
            if mod == "PKCS1_v1_5":
                self.add(node, "RSA", sym, padding="pkcs1v15", primitive="pke", functions=["encrypt", "decrypt"])
                return
            fam = _PYCRYPTODOME_CIPHERS.get(mod)
            if not fam:
                return
            mode_node = self.arg(node, 1, "mode")
            mode = None
            mq = self.qual(mode_node) if mode_node is not None else None
            if mq and ".MODE_" in mq:
                mode = mq.split(".MODE_")[-1].lower()
                mode = {"openpgp": "cfb", "siv": "siv", "eax": "eax"}.get(mode, mode)
                self.consume(mode_node)
            size = self._key_len(self.arg(node, 0, "key"))
            prim = "stream-cipher" if fam in ("RC4", "ChaCha20", "Salsa20") else (
                "ae" if mode in ("gcm", "ccm", "ocb", "siv", "eax") or fam == "ChaCha20-Poly1305" else "block-cipher")
            self.add(node, fam, sym, mode=mode, key_size=size, primitive=prim, functions=["encrypt", "decrypt"])
        elif pkg == "Signature" and last == "new":
            if mod in ("pkcs1_15", "PKCS1_v1_5"):
                self.add(node, "RSA", sym, padding="pkcs1v15", primitive="signature", functions=["sign", "verify"])
            elif mod in ("pss", "PKCS1_PSS"):
                self.add(node, "RSA", sym, padding="pss", primitive="signature", functions=["sign", "verify"])
            elif mod == "DSS":
                self.add(node, "ECDSA", sym, primitive="signature", confidence="low",
                         notes=["DSS signer: ECDSA or DSA depending on the key."], functions=["sign", "verify"])
            elif mod == "eddsa":
                self.add(node, "EdDSA", sym, primitive="signature", functions=["sign", "verify"])
        elif pkg == "Hash":
            if mod == "HMAC" and last == "new":
                dm = self.arg(node, 2, "digestmod")
                h = self.hash_of(dm) if dm is not None else "MD5"
                notes = [] if dm is not None else ["No digestmod given: PyCryptodome's HMAC defaults to MD5."]
                self.add(node, "HMAC", sym, hash=h, primitive="mac", functions=["tag"], notes=notes)
            elif mod in _CRYPTO_HASH_MODULES and last in ("new", mod):
                self._hash(node, _CRYPTO_HASH_MODULES[mod], sym)
        elif pkg == "Protocol" and mod == "KDF":
            if last == "PBKDF2":
                hm = self.arg(node, None, "hmac_hash_module")
                prf = self.arg(node, 4, "prf")
                h = self.hash_of(hm) if hm is not None else None
                notes = []
                if hm is None and prf is None:
                    h = "SHA-1"
                    notes.append("No hmac_hash_module or prf given: PyCryptodome's PBKDF2 defaults to HMAC-SHA1.")
                self.add(node, "PBKDF2", sym, hash=h, primitive="kdf", functions=["keyderive"], notes=notes)
            elif last == "HKDF":
                self.add(node, "HKDF", sym, hash=self.hash_of(self.arg(node, 3, "hashmod")), primitive="kdf")
            elif last in ("scrypt", "bcrypt"):
                self.add(node, last, sym, primitive="kdf", functions=["keyderive"])


# Only files that mention one of these are parsed; the rest cannot match any rule.
TRIGGERS = ("hashlib", "hmac", "ssl", "cryptography", "Crypto", "paramiko", "jwt", "jose", "oqs", "kyber_py",
            "dilithium_py")


def scan_python(path: str, source: str, in_tests: bool) -> tuple[list[Finding], str | None]:
    if not any(t in source for t in TRIGGERS):
        return [], None
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return [], f"{path}: could not parse as Python 3 ({type(exc).__name__})"
    scanner = _Scanner(path, tree, in_tests)
    try:
        scanner.visit(tree)
    except RecursionError:
        return scanner.findings, f"{path}: syntax tree too deep"
    return scanner.findings, None
