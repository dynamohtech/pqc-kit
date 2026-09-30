"""Source-code detectors: Python (AST), Java/Kotlin, Go and JavaScript/TypeScript."""

from __future__ import annotations

from conftest import by_name, detect, names

from pqc_kit.model import OK, RETIRING, SAFE, UNKNOWN, VULNERABLE, WEAK

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def test_python_resolves_aliases_constants_and_keywords():
    found = detect("python", """
import hashlib as hl
from cryptography.hazmat.primitives.asymmetric import rsa as R, ec
from cryptography.hazmat.primitives import hashes
BITS = 3072
k1 = R.generate_private_key(65537, BITS)
k2 = R.generate_private_key(public_exponent=65537, key_size=1024)
k3 = ec.generate_private_key(curve=ec.SECP521R1())
h = hl.sha1(b"x")
sig = ec.ECDSA(hashes.SHA384())
""")
    assert names(found) == ["RSA-3072", "RSA-1024", "EC P-521", "SHA-1", "ECDSA with SHA-384"]
    assert by_name(found, "RSA-1024").status == WEAK
    assert by_name(found, "RSA-3072").line == 6


def test_python_ignores_look_alike_names_that_are_not_imported():
    found = detect("python", """
import hashlib
def md5(x): return x
md5(b"not crypto")
class rsa:
    @staticmethod
    def generate_private_key(a, b): pass
rsa.generate_private_key(1, 512)
""")
    assert found == []


def test_python_hash_inside_oaep_is_not_counted_twice():
    found = detect("python", """
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
p = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
""")
    assert names(found) == ["RSA-OAEP with SHA-256"]
    assert found[0].role == "key-establishment"


def test_python_cipher_mode_and_key_length():
    found = detect("python", """
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
c1 = Cipher(algorithms.AES(os.urandom(16)), modes.GCM(os.urandom(12)))
c2 = Cipher(algorithms.AES(b"0123456789abcdef0123456789abcdef"), modes.ECB())
c3 = Cipher(TripleDES(os.urandom(24)), modes.CBC(os.urandom(8)))
""")
    assert names(found) == ["AES-128-GCM", "AES-256-ECB", "3DES-CBC"]
    assert [x.status for x in found] == [OK, WEAK, WEAK]


def test_python_usedforsecurity_false():
    found = detect("python", "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n")
    assert found[0].status == OK


def test_python_pycryptodome_defaults():
    found = detect("python", """
from Crypto.Hash import HMAC, SHA256
from Cryptodome.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, PKCS1_OAEP
m1 = HMAC.new(b"k", b"m")
m2 = HMAC.new(b"k", b"m", digestmod=SHA256)
k = PBKDF2("pw", b"salt", 32, count=100000)
c = AES.new(b"k" * 16, AES.MODE_ECB)
o = PKCS1_OAEP.new(key)
""")
    assert names(found) == ["HMAC-MD5", "HMAC-SHA-256", "PBKDF2-SHA-1", "AES-128-ECB", "RSA-OAEP with SHA-1"]
    assert [x.status for x in found] == [WEAK, OK, RETIRING, WEAK, VULNERABLE]


def test_python_jwt_ssl_paramiko_and_pqc():
    found = detect("python", """
import jwt, ssl, paramiko, oqs
from kyber_py.ml_kem import ML_KEM_1024
t = jwt.encode({}, key, algorithm="ES384")
jwt.decode(t, key, algorithms=["none"])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
k = paramiko.RSAKey.generate(bits=2048)
kem = oqs.KeyEncapsulation("ML-KEM-768")
pk, sk = ML_KEM_1024.keygen()
""")
    assert names(found) == ["ECDSA P-384 with SHA-384", "JWT alg=none", "TLS 1.1", "RSA-2048", "ML-KEM-768",
                            "ML-KEM-1024"]


def test_python_dynamic_hash_name_needs_review():
    found = detect("python", "import hashlib\ndef h(name):\n    return hashlib.new(name)\n")
    assert found[0].status == UNKNOWN
    assert found[0].name == "Hash chosen at run time"


def test_python_syntax_error_is_reported_not_raised():
    from pqc_kit.detectors.python import scan_python

    found, err = scan_python("old.py", "import hashlib\nprint 'python 2'\n", False)
    assert found == [] and "could not parse" in err


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


def test_java_key_sizes_curves_and_constants():
    found = detect("java", """
class K {
  static final String ALG = "RSA";
  private static final int BITS = 4096;
  void a() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALG);
    kpg.initialize(BITS);
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(128);
    // Cipher.getInstance("DES") in a comment is ignored
  }
}""")
    assert names(found) == ["RSA-4096", "EC P-256", "AES-128"]


def test_java_transformations_and_defaults():
    found = detect("java", """
Cipher a = Cipher.getInstance("AES");
Cipher b = Cipher.getInstance("AES/CBC/PKCS5Padding");
Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
Cipher d = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
Signature s = Signature.getInstance("SHA1withRSA");
MessageDigest m = MessageDigest.getInstance("SHA-512");
Mac h = Mac.getInstance("HmacSHA1");
SecretKeyFactory f = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
KeyAgreement ka = KeyAgreement.getInstance("X25519");
""")
    assert names(found) == ["AES-ECB", "AES-CBC", "3DES-ECB", "RSA-OAEP with SHA-256", "RSA PKCS#1 v1.5 with SHA-1",
                            "SHA-512", "HMAC-SHA-1", "DES", "X25519"]
    assert "defaults to ECB" in found[0].notes[0]
    assert by_name(found, "DES").hash == "MD5"


def test_java_pqc_bouncy_castle_and_jwt():
    found = detect("java", """
KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA");
g.initialize(NamedParameterSpec.ML_DSA_87);
KEM kem = KEM.getInstance("ML-KEM");
MLKEMKeyPairGenerator bc = new MLKEMKeyPairGenerator();
Digest d = new SHA1Digest();
HMac mac = new HMac(new SHA256Digest());
String t = Jwts.builder().signWith(key, SignatureAlgorithm.RS256).compact();
Algorithm a = Algorithm.ECDSA384(pub, priv);
SSLContext ctx = SSLContext.getInstance("TLSv1");
""")
    assert names(found) == ["ML-DSA-87", "ML-KEM", "ML-KEM", "SHA-1", "HMAC-SHA-256", "RSA PKCS#1 v1.5 with SHA-256",
                            "ECDSA P-384 with SHA-384", "TLS 1.0"]


def test_java_dynamic_algorithm_needs_review():
    found = detect("java", "Cipher c = Cipher.getInstance(config.get(\"alg\"));")
    assert found[0].status == UNKNOWN


def test_kotlin_uses_java_rules():
    from pqc_kit.detectors.java import scan_java
    from pqc_kit.scan import finalize

    found = scan_java("App.kt", 'val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }', False)
    finalize(found)
    assert names(found) == ["RSA-2048"]


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def test_go_imports_aliases_and_arguments():
    found = detect("go", """
package x
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/hmac"
    myrsa "crypto/rsa"
    "crypto/sha1"
    "crypto/sha512"
    "crypto"
    "golang.org/x/crypto/pbkdf2"
)
const bits = 2048
func f() {
    k, _ := myrsa.GenerateKey(rand.Reader, bits)
    e, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    m := hmac.New(sha1.New, key)
    s, _ := myrsa.SignPSS(rand.Reader, k, crypto.SHA384, d, nil)
    dk := pbkdf2.Key(pw, salt, 4096, 32, sha512.New)
    // md5.Sum(x) in a comment
}
""")
    assert names(found) == ["RSA-2048", "ECDSA P-384", "HMAC-SHA-1", "RSA-PSS with SHA-384", "PBKDF2-SHA-512"]
    assert by_name(found, "HMAC-SHA-1").status == RETIRING


def test_go_tls_x509_mlkem_circl_jwt():
    found = detect("go", """
package x
import (
    "crypto/mlkem"
    "crypto/tls"
    "crypto/x509"
    "github.com/cloudflare/circl/sign/mldsa/mldsa65"
    jwt "github.com/golang-jwt/jwt/v5"
)
var c = &tls.Config{MinVersion: tls.VersionTLS10, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
var s = []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
var a = x509.ECDSAWithSHA256
var k, _ = mlkem.GenerateKey1024()
var m = jwt.SigningMethodHS256
""")
    assert names(found) == ["ML-DSA-65", "TLS 1.0", "X25519MLKEM768", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "ECDSA with SHA-256", "ML-KEM-1024", "HMAC-SHA-256"]
    assert [x.status for x in found] == [SAFE, WEAK, SAFE, WEAK, VULNERABLE, SAFE, OK]


def test_go_without_crypto_imports_finds_nothing():
    assert detect("go", "package x\nfunc md5() {}\nvar rsa = 1\n") == []


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------


def test_js_node_crypto():
    found = detect("js", """
const crypto = require('crypto');
crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
crypto.generateKeyPairSync('ml-dsa-65');
crypto.createHash('md5');
crypto.createHmac('sha256', key);
crypto.createCipheriv('aes-128-cbc', key, iv);
crypto.createCipher('aes192', pw);
crypto.createECDH('prime256v1');
crypto.getDiffieHellman('modp2');
crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buf);
crypto.pbkdf2Sync(pw, salt, 1000, 32, 'sha1');
""")
    assert names(found) == ["RSA-3072", "EC secp256k1", "ML-DSA-65", "MD5", "HMAC-SHA-256", "AES-128-CBC",
                            "AES-192-CBC", "ECDH P-256", "DH-1024", "RSA PKCS#1 v1.5", "PBKDF2-SHA-1"]
    assert by_name(found, "AES-192-CBC").status == WEAK  # createCipher: MD5 key derivation
    assert by_name(found, "DH-1024").status == WEAK


def test_js_webcrypto_jwt_tls_libraries():
    found = detect("js", """
const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
const d = await crypto.subtle.digest('SHA-1', data);
const w = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
jwt.verify(token, key, { algorithms: ['RS256', 'HS512'] });
const opts = { secureProtocol: 'TLSv1_1_method' };
const h = CryptoJS.MD5(msg);
const e = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.ECB });
const kp = forge.pki.rsa.generateKeyPair({ bits: 1024 });
""")
    assert names(found) == ["ECDSA P-384", "SHA-1", "AES-256-GCM", "RSA PKCS#1 v1.5 with SHA-256", "HMAC-SHA-512",
                            "TLS 1.1", "MD5", "AES", "Block cipher in ECB mode", "RSA-1024"]


def test_js_comments_are_ignored():
    assert detect("js", "// crypto.createHash('md5')\n/* createCipheriv('des-cbc') */\n") == []


def test_js_forge_cipher_is_not_mistaken_for_node_createcipher():
    found = detect("js", "const c = forge.cipher.createCipher('AES-CBC', key);")
    assert names(found) == ["AES-CBC"]
    assert found[0].status == OK
