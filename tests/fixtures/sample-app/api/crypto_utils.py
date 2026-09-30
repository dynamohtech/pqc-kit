"""Sample service code for pqc-kit tests. Not meant to be run."""

import hashlib
import hmac as std_hmac
import ssl

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC as CryptoHMAC

KEY_BITS = 2048


def make_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def make_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign(key, data):
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def wrap_key(public_key, secret):
    return public_key.encrypt(
        secret, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def legacy_checksum(data):
    return hashlib.md5(data).hexdigest()


def cache_key(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def fingerprint(data):
    return hashlib.sha1(data).hexdigest()


def token_mac(key, msg):
    return std_hmac.new(key, msg, hashlib.sha256).hexdigest()


def old_mac(key, msg):
    return CryptoHMAC.new(key, msg).hexdigest()


def encrypt_record(key, iv, data):
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def encrypt_block(key, data):
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)


def encrypt_session(data):
    key = AESGCM.generate_key(bit_length=256)
    return AESGCM(key), key


def legacy_encrypt(key, data):
    return DES3.new(key, DES3.MODE_CBC).encrypt(data)


def derive(password, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=salt, iterations=600_000).derive(password)


def exchange():
    return x25519.X25519PrivateKey.generate()


def issue_token(payload, key):
    return jwt.encode(payload, key, algorithm="RS256")


def read_token(token, key):
    return jwt.decode(token, key, algorithms=["RS256", "HS256"])


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx
