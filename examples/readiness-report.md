# Post-quantum readiness report: Example Payments Platform

Static scan of `sample-app` on 2026-09-30 by pqc-kit 0.1.0: 10 files scanned (5 certificate/key, 1 go, 1 java, 1 javascript, 2 python). Test code is counted separately.

> **Not legal advice.** This report maps what a static scan found to published government timelines. Several dates come from drafts and may change. Check the sources and your own obligations.

## Summary

- **34** uses of public-key cryptography that a quantum computer breaks: 10 for key establishment (exposed to 'harvest now, decrypt later'), 15 for signatures or certificates and 9 keys or key generation where the use is set elsewhere.
- **18** uses of cryptography that is weak or disallowed today; fix these first.
- **7** uses of post-quantum or hybrid algorithms already.

| Status | Product code | Test code | Meaning |
| --- | ---: | ---: | --- |
| Weak today | 18 | 1 | Broken or already disallowed. Fix now, whatever happens with quantum computers. |
| Quantum-vulnerable | 30 | 0 | Public-key cryptography a large quantum computer breaks. Plan the migration. |
| Retiring after 2030 | 2 | 0 | Acceptable today, but NIST plans to phase it out by the end of 2030 (SHA-1: announced; 224-bit hashes: draft). |
| Needs review | 0 | 0 | The algorithm or its parameters are set at run time or could not be read. Check by hand. |
| OK | 12 | 0 | Symmetric cryptography or a hash at a size that holds up against quantum attacks. |
| Quantum-safe | 7 | 0 | Post-quantum (NIST FIPS 203/204/205 or SP 800-208), or a hybrid that includes one. |

## Deadlines that apply

"Affected" counts the findings in product code that each milestone covers. "Time left" is from the report date.

### NIST post-quantum transition

**Applies to:** US federal systems. NIST's algorithm standards are also the common reference for other governments, vendors and auditors.  
**Status:** Initial public draft (NIST IR 8547, November 2024). The dates are proposals and may change.

| When | What | Affected | Time left |
| --- | --- | ---: | --- |
| Deprecated after 2030 | Quantum-vulnerable public-key algorithms at 112-bit security (e.g. RSA-2048, 2048-bit DH, ECDSA/ECDH on P-224). | 4 | about 4.3 years |
| By 31 Dec 2030 | SHA-1 phased out of all uses (NIST announcement, Dec 2022). SP 800-131A Rev. 3 (draft) also disallows 224-bit hash functions after 2030. | 8 | about 4.3 years |
| Disallowed after 2035 | All quantum-vulnerable public-key algorithms: RSA, ECDSA, EdDSA, DH, ECDH and MQV, at any key size (DSA is already not approved for signing). | 34 | about 9.3 years |

NIST says application-specific guidance (e.g. for TLS and IKE) may require or recommend quantum-resistant key establishment earlier, to counter 'harvest now, decrypt later' attacks.

Sources: [NIST IR 8547 (initial public draft): Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd); [NIST SP 800-131A Rev. 3 (initial public draft)](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd); [NIST retires SHA-1 (15 December 2022)](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm)

### US federal PQC migration (Executive Order 14412, OMB M-26-15)

**Applies to:** US federal agencies' high value assets and high impact systems (National Security Systems follow CNSA 2.0 instead), and, through a Federal Acquisition Regulation rule the order calls for, federal contractors.  
**Status:** Executive Order 14412 (22 June 2026) and OMB memorandum M-26-15 (24 June 2026). The contractor requirement depends on a FAR rule that the order gave the FAR Council 180 days to propose.

| When | What | Affected | Time left |
| --- | --- | ---: | --- |
| By 2 Jan 2030 | Agencies must support TLS 1.3 or later (M-26-15, Appendix A, citing Executive Order 14306). Affected counts code that names an older TLS or SSL version; check whether it caps the version or only sets a minimum. | 6 | about 3.3 years |
| By 31 Dec 2030 | High value assets and high impact systems use PQC for key establishment (EO 14412, sec. 4(b)(ii)). The order also asks for a FAR rule requiring covered contractors to comply with NIST's FIPS, including the post-quantum FIPS, by this date. Keys whose use can't be told from the code are counted here, under the earlier date. | 19 | about 4.3 years |
| By 31 Dec 2031 | High value assets and high impact systems use PQC for digital signatures (EO 14412, sec. 4(b)(iii)). | 15 | about 5.3 years |
| By 2035 | Remaining systems complete the migration (M-26-15, Phase 5). | 34 | about 9.3 years |

The order gives CISA, with NIST, 270 days (to about 19 March 2027) to publish the minimum elements for a cryptographic bill of materials. M-26-15 asks agencies to keep a central CBOM and to submit a PQC migration plan within 120 days (by about 22 October 2026).

M-26-15 (Appendix A, PQC algorithm selection) points agencies to ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).

Sources: [Executive Order 14412: Securing the Nation Against Advanced Cryptographic Attacks (22 June 2026)](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/); [OMB M-26-15: Execution of the Migration to Post-Quantum Cryptography (24 June 2026)](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf)

### NSA CNSA 2.0

**Applies to:** US National Security Systems, and vendors and contractors who supply them.  
**Status:** Policy: CNSSP 15, as summarised in the NSA CNSA 2.0 FAQ (Ver. 2.1, December 2024).

| When | What | Affected | Time left |
| --- | --- | ---: | --- |
| From 1 Jan 2027 | All new acquisitions for National Security Systems must be CNSA 2.0 compliant, unless otherwise noted. | 58 | about 3 months |
| By 31 Dec 2030 | Equipment and services that cannot support CNSA 2.0 must be phased out, unless otherwise noted. | 58 | about 4.3 years |
| By 31 Dec 2031 | CNSA 2.0 algorithms are mandated for use, unless otherwise noted. | 58 | about 5.3 years |
| By 2035 | All National Security Systems quantum-resistant (NSM-10 goal). | 34 | about 9.3 years |

CNSA 2.0 algorithms: ML-KEM-1024 (key establishment), ML-DSA-87 (signatures), LMS or XMSS (software and firmware signing; single-tree only), AES-256, SHA-384 or SHA-512. SLH-DSA is not approved for any use in National Security Systems. SHA3-384 and SHA3-512 are allowed only for internal hardware functions such as boot-up integrity checks.

CNSA 2.0 transition by product category (NSA CNSA 2.0 advisory, September 2022, reissued May 2025):

| Category | Support and prefer by | Use exclusively by |
| --- | --- | --- |
| Software and firmware signing | 2025 | 2030 |
| Web browsers, servers and cloud services | 2025 | 2033 |
| Traditional networking equipment (VPNs, routers) | 2026 | 2030 |
| Operating systems | 2027 | 2033 |
| Niche equipment (constrained devices, large PKI systems) | 2030 | 2033 |
| Custom applications and legacy equipment | - | 2033 (update or replace) |

In product code: 3 CNSA 2.0 algorithm uses, 58 not approved, 8 to check.

Sources: [NSA: The CNSA 2.0 and Quantum Computing FAQ (Ver. 2.1, Dec 2024)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF); [NSA: Announcing the Commercial National Security Algorithm Suite 2.0 (Sep 2022)](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

### UK NCSC migration timelines

**Applies to:** UK organisations; the NCSC's recommended timeline for planning and completing migration.  
**Status:** Guidance (published 20 March 2025).

| When | What | Affected | Time left |
| --- | --- | ---: | --- |
| By 2028 | Define migration goals, carry out a full discovery exercise (find your cryptography) and build an initial migration plan. | 69 | about 2.3 years |
| By 2031 | Carry out the early, highest-priority migration activities and refine the plan. | 34 | about 5.3 years |
| By 2035 | Complete migration to PQC of all systems, services and products. | 34 | about 9.3 years |

Sources: [NCSC: Timelines for migration to post-quantum cryptography](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines)

### EU coordinated PQC roadmap

**Applies to:** EU Member States: a recommended timeline agreed in the NIS Cooperation Group. It is addressed to Member States rather than directly to companies.  
**Status:** Non-binding roadmap agreed by Member States in the NIS Cooperation Group (Part 1, Version 1.1, 11 June 2025), following Commission Recommendation (EU) 2024/1101.

| When | What | Affected | Time left |
| --- | --- | ---: | --- |
| By 31 Dec 2026 | First steps done, national roadmaps set, and planning and pilots started for high- and medium-risk use cases. The roadmap calls cryptographic inventories a 'no-regret' first step. | 69 | about 3 months |
| By 31 Dec 2030 | High-risk use cases migrated: quantum-vulnerable public-key mechanisms no longer used on their own. Quantum-safe software and firmware upgrades enabled by default. | 34 | about 4.3 years |
| By 31 Dec 2035 | Medium-risk use cases migrated; low-risk use cases as far as feasible. | 34 | about 9.3 years |

The roadmap advises that data needing confidentiality for at least 10 years is protected against quantum attacks by the end of 2030 at the latest.

Sources: [European Commission: Coordinated Implementation Roadmap for the transition to PQC](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)

## 1. Fix first: weak today (18)

Broken or already disallowed. These are risks today, independent of quantum computers.

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
| SHA-1 | `web/src/auth.ts:18` | `createHash('sha1')` | SHA-1 collisions are practical. NIST disallows SHA-1 for signature generation (SP 800-131A Rev. 2) and is retiring it in all uses by 31 December 2030. |
| 3DES-CBC | `web/src/auth.ts:27` | `createCipheriv('des-ede3-cbc')` | NIST disallows Triple DES for encryption after 2023 (SP 800-131A Rev. 2); its 64-bit block is exposed to birthday attacks (Sweet32). |
| TLS 1.0 | `web/src/auth.ts:42` | `minVersion: 'TLSv1'` | TLS 1.0 and 1.1 are deprecated (RFC 8996). |

## 2. Key establishment: migrate first (10)

Anything encrypted with these today can be recorded now and decrypted once a large quantum computer exists, so they come before signatures.

**Replace with:** ML-KEM (FIPS 203). During the transition, combine it with the classical algorithm (for TLS 1.3, the X25519MLKEM768 hybrid group). CNSA 2.0 requires ML-KEM-1024.

| Algorithm | Where | Found by | Notes |
| --- | --- | --- | --- |
| RSA-OAEP with SHA-256 | `api/crypto_utils.py:33` | `padding.OAEP` |  |
| X25519 | `api/crypto_utils.py:80` | `X25519PrivateKey.generate` |  |
| RSA PKCS#1 v1.5 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:64` | `Cipher.getInstance("RSA/ECB/PKCS1Padding")` | PKCS#1 v1.5 encryption padding is prone to padding-oracle attacks (Bleichenbacher); prefer OAEP. |
| TLS 1.2 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:81` | `SSLContext.getInstance("TLSv1.2")` |  |
| TLS 1.2 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:82` | `setEnabledProtocols` |  |
| TLS 1.2 | `svc/keys.go:50` | `tls.VersionTLS12` |  |
| X25519 | `svc/keys.go:51` | `tls.X25519` |  |
| RSA-4096-OAEP with SHA-256 | `web/src/auth.ts:36` | `{name: 'RSA-OAEP'}` |  |
| X25519 | `web/src/auth.ts:42` | `ecdhCurve: 'X25519'` |  |
| ECDH P-256 | `web/src/auth.ts:42` | `ecdhCurve: 'P-256'` |  |

## 3. Signatures (10)

Forgery needs a quantum computer at the time of the attack, so these follow key establishment, but long-lived signatures (firmware, documents, roots of trust) need an early plan.

**Replace with:** ML-DSA (FIPS 204); SLH-DSA (FIPS 205) where a hash-based scheme is preferred; LMS or XMSS (SP 800-208) for firmware signing. CNSA 2.0 requires ML-DSA-87, or LMS/XMSS for firmware.

| Algorithm | Where | Found by | Notes |
| --- | --- | --- | --- |
| ECDSA with SHA-256 | `api/crypto_utils.py:28` | `ec.ECDSA` |  |
| RSA PKCS#1 v1.5 with SHA-256 | `api/crypto_utils.py:84` | `jwt.encode` | JWT/JOSE algorithm RS256. |
| RSA PKCS#1 v1.5 with SHA-256 | `api/crypto_utils.py:88` | `jwt.decode` | JWT/JOSE algorithm RS256. |
| RSA PKCS#1 v1.5 with SHA-256 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:39` | `Signature.getInstance("SHA256withRSA")` |  |
| Ed25519 | `certs/authorized_keys:2` | `SSH public key (ssh-ed25519)` |  |
| ECDSA P-256 | `svc/keys.go:28` | `ecdsa.GenerateKey` |  |
| RSA PKCS#1 v1.5 with SHA-256 | `svc/keys.go:33` | `cryptorsa.SignPKCS1v15` |  |
| ECDSA P-256 with SHA-256 | `svc/keys.go:57` | `jwt.SigningMethodES256` | JWT/JOSE algorithm ES256. |
| ECDSA secp256k1 | `web/src/auth.ts:5` | `@noble/curves/secp256k1` |  |
| ECDSA P-256 with SHA-256 | `web/src/auth.ts:31` | `algorithm: 'ES256'` | JWT/JOSE algorithm ES256. |

## 4. Other public-key use (8)

Keys and key generation where the use (encryption or signing) is decided elsewhere in the code.

**Replace with:** Depends on how the key is used: ML-KEM for key establishment, ML-DSA for signatures.

| Algorithm | Where | Found by | Notes |
| --- | --- | --- | --- |
| RSA-2048 | `api/crypto_utils.py:20` | `rsa.generate_private_key` |  |
| EC P-256 | `api/crypto_utils.py:24` | `ec.generate_private_key` |  |
| RSA-3072 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:22` | `KeyPairGenerator.getInstance("RSA")` |  |
| EC P-384 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:28` | `KeyPairGenerator.getInstance("EC")` |  |
| RSA-2048 | `certs/authorized_keys:1` | `SSH public key (ssh-rsa)` |  |
| EC P-384 | `certs/webhook-signing.pub.pem:1` | `PEM PUBLIC KEY` |  |
| RSA-2048 | `web/src/auth.ts:8` | `generateKeyPair('rsa')` |  |
| EC P-256 | `web/src/auth.ts:9` | `generateKeyPair('ec')` |  |

## 5. Certificates (4)

Plan re-issuance with ML-DSA keys before the deadlines above, and check your CA's roadmap. Where old and new clients must both be served, composite certificates (an IETF draft) are one option.

| Subject | Key | Signed with | Expires | Status | Where | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| legacy-partner.example-bank.test | RSA-1024 | RSA-1024 PKCS#1 v1.5 with SHA-1 | 2030-06-30 | Weak today | `certs/legacy-partner.crt` |  |
| api.example-bank.test | EC P-256 | RSA-2048 PKCS#1 v1.5 with SHA-256 | 2027-01-01 | Quantum-vulnerable | `certs/server-chain.pem:1` |  |
| Example Bank Root CA | RSA-2048 | RSA-2048 PKCS#1 v1.5 with SHA-256 | 2036-01-01 | Quantum-vulnerable | `certs/server-chain.pem:16` | Valid until 2036-01-01, past the end of 2030 when NIST (draft IR 8547) deprecates 112-bit keys. |
| pq-pilot.example-bank.test | ML-DSA-65 | ML-DSA-65 | 2045-12-31 | Quantum-safe | `certs/pq-pilot-mldsa65.pem:2` |  |

## 6. Retiring after 2030 (2)

Acceptable today; replace SHA-1 and 224-bit hashes with SHA-256 or stronger before the end of 2030.

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| PBKDF2-SHA-1 | `api/crypto_utils.py:76` | `PBKDF2HMAC` | PBKDF2 with SHA-1. NIST is retiring SHA-1 in all uses by 31 December 2030 (NIST announcement, December 2022). |
| PBKDF2-SHA-1 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:77` | `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")` | PBKDF2 with SHA-1. NIST is retiring SHA-1 in all uses by 31 December 2030 (NIST announcement, December 2022). |

## 8. Already quantum-safe (7)

| Algorithm | Where | Found by | Why |
| --- | --- | --- | --- |
| ML-KEM-768 | `billing/src/main/java/com/example/billing/PaymentCrypto.java:35` | `KeyPairGenerator.getInstance("ML-KEM-768")` | NIST FIPS 203 (2024) post-quantum key encapsulation. |
| ML-DSA-65 | `certs/pq-pilot-mldsa65.pem:2` | `X.509 certificate (PEM)` | NIST FIPS 204 (2024) post-quantum signature. |
| ML-KEM-768 | `svc/keys.go:46` | `mlkem.GenerateKey768` | NIST FIPS 203 (2024) post-quantum key encapsulation. |
| X25519MLKEM768 | `svc/keys.go:51` | `tls.X25519MLKEM768` | Hybrid key exchange that includes ML-KEM, so recorded traffic stays protected even against a future quantum computer. Hybrid TLS key exchange: ML-KEM-768 with X25519. |
| ML-KEM-768 | `web/src/auth.ts:4` | `ml_kem768` | NIST FIPS 203 (2024) post-quantum key encapsulation. |
| X25519MLKEM768 | `web/src/auth.ts:42` | `ecdhCurve: 'X25519MLKEM768'` | Hybrid key exchange that includes ML-KEM, so recorded traffic stays protected even against a future quantum computer. Hybrid key exchange: ML-KEM-768 combined with X25519. |
| ML-KEM-768 | `web/src/auth.ts:44` | `ml_kem768` | NIST FIPS 203 (2024) post-quantum key encapsulation. |

## What this report does not cover

- **Static scan only.** Algorithms chosen at run time, cryptography inside third-party libraries and binaries, network endpoints, hardware security modules and cloud key services are not visible to it.
- **Languages and formats.** v0.1 reads Python, Java/Kotlin, Go, JavaScript/TypeScript, PEM/DER certificates and keys, SSH public keys and keystore files. Other languages are not scanned yet.
- **Draft dates.** NIST IR 8547 and SP 800-131A Rev. 3 are drafts; the EU roadmap is a recommendation to Member States. Re-check the sources before you commit to dates in contracts.
- **Not legal advice.** Whether a framework applies to you depends on your customers and sector.

The pqc-kit enterprise edition adds network and TLS endpoint scanning, a risk-ranked migration plan based on data lifetime and exposure, auditor-ready reports, and a CI gate that blocks new weak or quantum-vulnerable cryptography against an approved baseline. Contact: dynamohtech24@gmail.com.
