# Cryptography inventory: `sample-app`

Scanned 10 files (5 certificate/key, 1 go, 1 java, 1 javascript, 2 python): 70 findings (19 weak today, 30 quantum-vulnerable, 2 retiring after 2030, 12 ok, 7 quantum-safe). 1 is in test code.

## Weak today (19)

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| MD5 | `api/crypto_utils.py:38` | `hashlib.md5` | MD5 collisions are practical; RFC 6151 says MD5 is no longer acceptable where collision resistance is required, such as digital signatures. It is not a NIST-approved hash. |
| SHA-1 | `api/crypto_utils.py:46` | `hashlib.sha1` | SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) and is retiring it in all uses by 31 December 2030. |
| HMAC-MD5 | `api/crypto_utils.py:54` | `HMAC.new` | HMAC built on MD5: MD5 is not a NIST-approved hash, and RFC 6151 says new protocols should not use HMAC-MD5. Use SHA-256 or stronger. No digestmod given: PyCryptodome's HMAC defaults to MD5. |
| AES-ECB | `api/crypto_utils.py:63` | `Cipher` | ECB mode reveals patterns in the plaintext; NIST SP 800-131A Rev. 3 (draft) proposes disallowing it for encryption. |
| 3DES-CBC | `api/crypto_utils.py:72` | `DES3.new` | NIST disallows Triple DES for encryption after 2023 (SP 800-131A Rev. 2); its 64-bit block is exposed to birthday attacks (Sweet32). |
| TLS 1.0 | `api/crypto_utils.py:93` | `ssl.TLSVersion.TLSv1` | TLS 1.0 and 1.1 are deprecated (RFC 8996). |
| DSA with SHA-1 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:46` | `Signature.getInstance("SHA1withDSA")` | SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) and is retiring it in all uses by 31 December 2030. |
| AES-ECB | `billing/src/main/java/com/example/billing/PaymentCrypto.java:52` | `Cipher.getInstance("AES")` | ECB mode reveals patterns in the plaintext; NIST SP 800-131A Rev. 3 (draft) proposes disallowing it for encryption. No mode given: the SunJCE provider defaults to ECB. |
| MD5 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:73` | `MessageDigest.getInstance("MD5")` | MD5 collisions are practical; RFC 6151 says MD5 is no longer acceptable where collision resistance is required, such as digital signatures. It is not a NIST-approved hash. |
| TLS 1.1 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:82` | `setEnabledProtocols` | TLS 1.0 and 1.1 are deprecated (RFC 8996). |
| RSA-1024 | `certs/legacy-partner.crt` | `X.509 certificate (DER)` | RSA-1024 gives under 112 bits of security; NIST SP 800-131A disallows it for protecting data. |
| RSA-1024 | `svc/keys.go:24` | `cryptorsa.GenerateKey` | RSA-1024 gives under 112 bits of security; NIST SP 800-131A disallows it for protecting data. |
| MD5 | `svc/keys.go:36` | `md5.Sum` | MD5 collisions are practical; RFC 6151 says MD5 is no longer acceptable where collision resistance is required, such as digital signatures. It is not a NIST-approved hash. |
| SHA-1 | `svc/keys.go:38` | `sha1.Sum` | SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) and is retiring it in all uses by 31 December 2030. |
| RSA PKCS#1 v1.5 with SHA-1 | `svc/keys.go:55` | `x509.SHA1WithRSA` | SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) and is retiring it in all uses by 31 December 2030. |
| MD5 | `test/test_crypto.py:5` (test) | `hashlib.md5` | MD5 collisions are practical; RFC 6151 says MD5 is no longer acceptable where collision resistance is required, such as digital signatures. It is not a NIST-approved hash. |
| SHA-1 | `web/src/auth.ts:18` | `createHash('sha1')` | SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) and is retiring it in all uses by 31 December 2030. |
| 3DES-CBC | `web/src/auth.ts:27` | `createCipheriv('des-ede3-cbc')` | NIST disallows Triple DES for encryption after 2023 (SP 800-131A Rev. 2); its 64-bit block is exposed to birthday attacks (Sweet32). |
| TLS 1.0 | `web/src/auth.ts:42` | `minVersion: 'TLSv1'` | TLS 1.0 and 1.1 are deprecated (RFC 8996). |

## Quantum-vulnerable (30)

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| RSA-2048 | `api/crypto_utils.py:20` | `rsa.generate_private_key` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| EC P-256 | `api/crypto_utils.py:24` | `ec.generate_private_key` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| ECDSA with SHA-256 | `api/crypto_utils.py:28` | `ec.ECDSA` | Signature algorithm that a large quantum computer can break (Shor's algorithm). |
| RSA-OAEP with SHA-256 | `api/crypto_utils.py:33` | `padding.OAEP` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. |
| X25519 | `api/crypto_utils.py:80` | `X25519PrivateKey.generate` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. |
| RSA PKCS#1 v1.5 with SHA-256 | `api/crypto_utils.py:84` | `jwt.encode` | Signature algorithm that a large quantum computer can break (Shor's algorithm). JWT/JOSE algorithm RS256. |
| RSA PKCS#1 v1.5 with SHA-256 | `api/crypto_utils.py:88` | `jwt.decode` | Signature algorithm that a large quantum computer can break (Shor's algorithm). JWT/JOSE algorithm RS256. |
| RSA-3072 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:22` | `KeyPairGenerator.getInstance("RSA")` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| EC P-384 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:28` | `KeyPairGenerator.getInstance("EC")` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| RSA PKCS#1 v1.5 with SHA-256 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:39` | `Signature.getInstance("SHA256withRSA")` | Signature algorithm that a large quantum computer can break (Shor's algorithm). |
| RSA PKCS#1 v1.5 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:64` | `Cipher.getInstance("RSA/ECB/PKCS1Padding")` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. PKCS#1 v1.5 encryption padding is prone to padding-oracle attacks (Bleichenbacher); prefer OAEP. |
| TLS 1.2 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:81` | `SSLContext.getInstance("TLSv1.2")` | TLS 1.2 has no standard post-quantum key exchange, so its handshake is quantum-vulnerable. |
| TLS 1.2 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:82` | `setEnabledProtocols` | TLS 1.2 has no standard post-quantum key exchange, so its handshake is quantum-vulnerable. |
| RSA-2048 | `certs/authorized_keys:1` | `SSH public key (ssh-rsa)` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| Ed25519 | `certs/authorized_keys:2` | `SSH public key (ssh-ed25519)` | Signature algorithm that a large quantum computer can break (Shor's algorithm). |
| EC P-256 | `certs/server-chain.pem:1` | `X.509 certificate (PEM)` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| RSA-2048 | `certs/server-chain.pem:16` | `X.509 certificate (PEM)` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). Valid until 2036-01-01, past the end of 2030 when NIST (draft IR 8547) deprecates 112-bit keys. |
| EC P-384 | `certs/webhook-signing.pub.pem:1` | `PEM PUBLIC KEY` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| ECDSA P-256 | `svc/keys.go:28` | `ecdsa.GenerateKey` | Signature algorithm that a large quantum computer can break (Shor's algorithm). |
| RSA PKCS#1 v1.5 with SHA-256 | `svc/keys.go:33` | `cryptorsa.SignPKCS1v15` | Signature algorithm that a large quantum computer can break (Shor's algorithm). |
| TLS 1.2 | `svc/keys.go:50` | `tls.VersionTLS12` | TLS 1.2 has no standard post-quantum key exchange, so its handshake is quantum-vulnerable. |
| X25519 | `svc/keys.go:51` | `tls.X25519` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. |
| ECDSA P-256 with SHA-256 | `svc/keys.go:57` | `jwt.SigningMethodES256` | Signature algorithm that a large quantum computer can break (Shor's algorithm). JWT/JOSE algorithm ES256. |
| ECDSA secp256k1 | `web/src/auth.ts:5` | `@noble/curves/secp256k1` | Signature algorithm that a large quantum computer can break (Shor's algorithm). |
| RSA-2048 | `web/src/auth.ts:8` | `generateKeyPair('rsa')` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| EC P-256 | `web/src/auth.ts:9` | `generateKeyPair('ec')` | Public-key algorithm that a large quantum computer can break (Shor's algorithm). |
| ECDSA P-256 with SHA-256 | `web/src/auth.ts:31` | `algorithm: 'ES256'` | Signature algorithm that a large quantum computer can break (Shor's algorithm). JWT/JOSE algorithm ES256. |
| RSA-4096-OAEP with SHA-256 | `web/src/auth.ts:36` | `{name: 'RSA-OAEP'}` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. |
| X25519 | `web/src/auth.ts:42` | `ecdhCurve: 'X25519'` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. |
| ECDH P-256 | `web/src/auth.ts:42` | `ecdhCurve: 'P-256'` | Key establishment that a large quantum computer can break (Shor's algorithm). Traffic recorded today can be decrypted later ('harvest now, decrypt later'), so migrate this first. |

## Retiring after 2030 (2)

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| PBKDF2-SHA-1 | `api/crypto_utils.py:76` | `PBKDF2HMAC` | PBKDF2 with SHA-1. NIST is retiring SHA-1 in all uses by 31 December 2030 (NIST announcement, December 2022). |
| PBKDF2-SHA-1 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:77` | `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")` | PBKDF2 with SHA-1. NIST is retiring SHA-1 in all uses by 31 December 2030 (NIST announcement, December 2022). |

## OK (12)

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| MD5 | `api/crypto_utils.py:42` | `hashlib.md5` | Declared as not used for security (usedforsecurity=False), so not counted as weak. |
| HMAC-SHA-256 | `api/crypto_utils.py:50` | `hmac.new` | Symmetric construction with adequate strength against quantum attacks. |
| AES-CBC | `api/crypto_utils.py:58` | `Cipher` | Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks. |
| AES-256-GCM | `api/crypto_utils.py:67` | `AESGCM.generate_key` | Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks. |
| AES-GCM | `api/crypto_utils.py:68` | `AESGCM` | Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks. |
| HMAC-SHA-256 | `api/crypto_utils.py:88` | `jwt.decode` | Symmetric construction with adequate strength against quantum attacks. JWT/JOSE algorithm HS256. |
| AES-GCM | `billing/src/main/java/com/example/billing/PaymentCrypto.java:57` | `Cipher.getInstance("AES/GCM/NoPadding")` | Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks. |
| AES-256 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:58` | `KeyGenerator.getInstance("AES")` | Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks. |
| HMAC-SHA-256 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:69` | `Mac.getInstance("HmacSHA256")` | Symmetric construction with adequate strength against quantum attacks. |
| HMAC-SHA-256 | `svc/keys.go:41` | `hmac.New` | Symmetric construction with adequate strength against quantum attacks. |
| PBKDF2-SHA-512 | `web/src/auth.ts:14` | `pbkdf2` | Symmetric construction with adequate strength against quantum attacks. |
| AES-256-GCM | `web/src/auth.ts:22` | `createCipheriv('aes-256-gcm')` | Symmetric cipher; NIST considers AES-128 and larger adequate against quantum attacks. |

## Quantum-safe (7)

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| ML-KEM-768 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:35` | `KeyPairGenerator.getInstance("ML-KEM-768")` | NIST FIPS 203 (2024) post-quantum key encapsulation. |
| ML-DSA-65 | `certs/pq-pilot-mldsa65.pem:2` | `X.509 certificate (PEM)` | NIST FIPS 204 (2024) post-quantum signature. |
| ML-KEM-768 | `svc/keys.go:46` | `mlkem.GenerateKey768` | NIST FIPS 203 (2024) post-quantum key encapsulation. |
| X25519MLKEM768 | `svc/keys.go:51` | `tls.X25519MLKEM768` | Hybrid key exchange that includes ML-KEM, so recorded traffic stays protected even against a future quantum computer. Hybrid TLS key exchange: ML-KEM-768 with X25519. |
| ML-KEM-768 | `web/src/auth.ts:4` | `ml_kem768` | NIST FIPS 203 (2024) post-quantum key encapsulation. |
| X25519MLKEM768 | `web/src/auth.ts:42` | `ecdhCurve: 'X25519MLKEM768'` | Hybrid key exchange that includes ML-KEM, so recorded traffic stays protected even against a future quantum computer. Hybrid key exchange: ML-KEM-768 combined with X25519. |
| ML-KEM-768 | `web/src/auth.ts:44` | `ml_kem768` | NIST FIPS 203 (2024) post-quantum key encapsulation. |

_Generated by pqc-kit 0.1.0._
