# pqc-kit

**Find the cryptography that quantum computers will break.** pqc-kit scans your source code, certificates and keys,
writes a CycloneDX cryptography bill of materials (CBOM), and shows which post-quantum migration deadlines apply to
each finding: NIST, the US federal order, NSA CNSA 2.0, the UK NCSC and the EU roadmap.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)

> **Why now:** every migration plan starts with an inventory, and the dates are set.
>
> - **1 January 2027:** new acquisitions for US National Security Systems must be CNSA 2.0 compliant.
> - **2028:** the UK NCSC recommends completing a full discovery exercise and an initial migration plan.
> - **31 December 2030 / 2031:** Executive Order 14412 directs OMB to require US agencies to move high value
>   assets and high impact systems to post-quantum key establishment by 31 December 2030 and signatures by
>   31 December 2031. It also orders a proposed rule requiring federal contractors to comply with NIST's FIPS,
>   including the post-quantum FIPS, by 31 December 2030.
> - **After 2030 / 2035:** NIST's draft transition plan deprecates RSA-2048 and similar 112-bit algorithms after 2030
>   and disallows RSA, ECDSA, ECDH and the rest after 2035. The EU roadmap asks Member States to complete the
>   transition for high-risk use cases by the end of 2030.

```text
$ pqc-kit scan
Scanned 10 files (5 certificate/key, 1 go, 1 java, 1 javascript, 2 python): 70 findings (19 weak today,
30 quantum-vulnerable, 2 retiring after 2030, 12 ok, 7 quantum-safe). 1 is in test code.

STATUS               ALGORITHM                     WHERE                                FOUND BY
Weak today           DSA with SHA-1                billing/.../PaymentCrypto.java:46    Signature.getInstance("SHA1withDSA")
Weak today           AES-ECB                       billing/.../PaymentCrypto.java:52    Cipher.getInstance("AES")
Weak today           RSA-1024                      certs/legacy-partner.crt             X.509 certificate (DER)
Weak today           TLS 1.0                       web/src/auth.ts:42                   minVersion: 'TLSv1'
Quantum-vulnerable   RSA-2048                      api/crypto_utils.py:20               rsa.generate_private_key
Quantum-vulnerable   RSA-OAEP with SHA-256         api/crypto_utils.py:33               padding.OAEP
Quantum-vulnerable   X25519                        api/crypto_utils.py:80               X25519PrivateKey.generate
Quantum-safe         ML-KEM-768                    svc/keys.go:46                       mlkem.GenerateKey768
...

$ pqc-kit cbom
Wrote cbom.cdx.json: 49 cryptographic assets (35 algorithm, 4 certificate, 3 protocol, 7 keys) from 10 files.
```

<sub>Sample run on the test project in [`tests/fixtures/sample-app`](tests/fixtures/sample-app), shortened.</sub>

## What it does

| Command | What you get | Why it matters |
| --- | --- | --- |
| `pqc-kit scan` | Every use of cryptography in the project, with its status: weak today, quantum-vulnerable, retiring, needs review, OK or quantum-safe. Table, Markdown or JSON. `--fail-on` for CI. | The discovery step every timeline starts with (NCSC "by 2028", EU "no-regret first step", OMB M-26-15 Phase 1). |
| `pqc-kit cbom` | CycloneDX 1.6 CBOM: algorithms, protocols, certificates and keys as `cryptographic-asset` components, with where each was found and the first deadline that covers it. | EO 14412 asks CISA to publish the minimum elements for a CBOM by about March 2027; M-26-15 asks agencies to keep a central CBOM. |
| `pqc-kit assess` | A readiness report: counts per status, every milestone from the five frameworks with the number of findings it affects and the time left, then what to fix first and what to replace it with. | Turns the inventory into a plan you can put in front of a board, an auditor or a customer. |

See [`examples/`](examples/) for a full scan, CBOM and readiness report for a fictional payments platform.

## Install

Python 3.11 or newer. No runtime dependencies.

```bash
pipx install git+https://github.com/dynamohtech/pqc-kit
# or
pip install git+https://github.com/dynamohtech/pqc-kit
```

## Quickstart

Run these in your project's repository:

```bash
pqc-kit scan                                   # what is there, and how urgent
pqc-kit cbom -o cbom.cdx.json                  # CycloneDX 1.6 CBOM
pqc-kit assess -o pqc-readiness.md             # deadlines and migration priorities
pqc-kit assess --framework us --framework cnsa2  # only the frameworks that apply to you
```

Useful options: `--no-tests` skips test code (by default it is scanned but counted separately), `--exclude GLOB`
skips paths, and `--as-of YYYY-MM-DD` measures "time left" from another date. `pqc-kit assess --scan scan.json`
reuses the JSON from `pqc-kit scan --format json` instead of scanning again.

## What it finds

| Where | How | Covers |
| --- | --- | --- |
| Python | Syntax tree (never runs the code); follows import aliases, constants and keyword arguments | `hashlib`, `hmac`, `ssl`, pyca `cryptography`, PyCryptodome, paramiko, PyJWT, python-jose, liboqs, kyber-py, dilithium-py |
| Java, Kotlin, Scala, Groovy | Pattern matching with comments removed and same-file constants resolved | JCA/JCE (`Cipher`, `Signature`, `KeyPairGenerator`, `KeyAgreement`, `MessageDigest`, `Mac`, ...), `SSLContext`, Bouncy Castle including its post-quantum classes, jjwt, auth0 and Nimbus JWT |
| Go | Same approach, import-aware | Standard library `crypto/*` including `crypto/mlkem`, `crypto/tls` settings, `golang.org/x/crypto`, Cloudflare CIRCL, golang-jwt |
| JavaScript, TypeScript | Same approach | Node `crypto` and `tls`, Web Crypto, jsonwebtoken, jose, node-forge, crypto-js, @noble |
| Certificates and keys | A strict DER decoder written for pqc-kit (no OpenSSL) | X.509 certificates and CSRs, PKCS#1, PKCS#8 (including encrypted keys), SEC1, OpenSSH, SSH `authorized_keys`, DH and EC parameters, PEM pasted into source code, keystore files (`.jks`, `.p12`, `.pfx`, ...) by type |

Post-quantum algorithms are recognised by their NIST-registered identifiers (ML-KEM, ML-DSA, SLH-DSA and their
pre-hash forms), plus LMS/XMSS, and the IETF draft identifiers for composite (hybrid) certificates. The certificate
reader is checked against [pyca/cryptography](https://cryptography.io/) in the test suite and, weekly, against the
705 post-quantum certificates from 19 implementations (as of September 2026) published by the
[IETF Hackathon PQC certificates project](https://github.com/IETF-Hackathon/pqc-certificates).

**What each status means**

| Status | Meaning | Examples |
| --- | --- | --- |
| Weak today | Broken or already disallowed. Fix now, whatever happens with quantum computers. | MD5, SHA-1 signatures, DES/3DES, RC4, ECB mode, RSA-1024, TLS 1.0/1.1, JWT `alg: none` |
| Quantum-vulnerable | Public-key cryptography that a large quantum computer breaks. Plan the migration. | RSA, ECDSA, ECDH, EdDSA, X25519, DH, TLS 1.2 key exchange |
| Retiring after 2030 | Acceptable today, on NIST's retirement schedule for the end of 2030. | SHA-1 in HMAC or KDFs, SHA-224 |
| Needs review | The algorithm or its parameters are chosen at run time. | `hashlib.new(name)`, `Cipher.getInstance(config.alg)` |
| OK | Symmetric cryptography or a hash at a size that holds up. | AES-256-GCM, SHA-384, ChaCha20-Poly1305 |
| Quantum-safe | NIST post-quantum standard, or a hybrid that includes one. | ML-KEM, ML-DSA, SLH-DSA, LMS, X25519MLKEM768 |

Each finding also records its role (key establishment, signature, symmetric, hash, protocol), classical strength,
NIST post-quantum security category, and whether it is approved in CNSA 2.0.

## The deadlines it maps to

`pqc-kit assess` lists every milestone below, counts the findings each one affects, and shows the time left.
`pqc-kit cbom` records the first milestone that covers each asset as a `pqc-kit:deadline:<framework>` property.

| Framework | Applies to | Milestones | Status |
| --- | --- | --- | --- |
| NIST ([IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd), [SP 800-131A](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd)) | US federal systems; NIST's algorithm standards are the common reference elsewhere too | 112-bit public-key algorithms (RSA-2048, P-224, 2048-bit DH) deprecated after 2030; all quantum-vulnerable public-key algorithms disallowed after 2035; SHA-1 phased out of all uses by 31 Dec 2030 | IR 8547 and SP 800-131A Rev. 3 are drafts (Nov 2024 and Oct 2024); SHA-1 retirement announced Dec 2022 |
| [Executive Order 14412](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/) and [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) | US federal agencies' high value assets and high impact systems; federal contractors through a proposed FAR rule | TLS 1.3 supported by 2 Jan 2030; post-quantum key establishment by 31 Dec 2030; post-quantum signatures by 31 Dec 2031; remaining systems by 2035 | Order signed 22 Jun 2026; memo 24 Jun 2026 |
| [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) | US National Security Systems and their suppliers | New acquisitions compliant from 1 Jan 2027; non-compliant equipment phased out by 31 Dec 2030; CNSA 2.0 algorithms mandated by 31 Dec 2031; all systems quantum-resistant by 2035; per-category dates for firmware signing, networking, browsers and operating systems | Policy (CNSSP 15), FAQ v2.1 (Dec 2024) |
| [UK NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) | UK organisations | Discovery and initial plan by 2028; highest-priority migration by 2031; complete by 2035 | Guidance (Mar 2025) |
| [EU coordinated roadmap](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography) | EU Member States (addressed to governments, not directly to companies) | First steps and national plans by end of 2026; high-risk use cases by end of 2030; medium-risk by end of 2035 | Non-binding roadmap, v1.1 (Jun 2025), following Commission Recommendation (EU) 2024/1101 |

**What is at stake.** These timelines do not carry fines of their own. The pressure comes through contracts and
existing security law:

- **US government suppliers:** CNSA 2.0 applies to new National Security System acquisitions from 1 January 2027.
  EO 14412 directs the FAR Council to propose a rule requiring covered contractors to comply with NIST's FIPS,
  including the post-quantum standards, by 31 December 2030.
- **EU essential and important entities:** the NIS2 Directive requires "policies and procedures regarding the use of
  cryptography and, where appropriate, encryption" ([Article 21(2)(h)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)).
  Member States must allow maximum fines for breaching Article 21 of at least €10 million or 2% of total worldwide
  annual turnover, whichever is higher, for essential entities, and €7 million or 1.4% for important entities
  (Article 34(4) and (5)).
- **Harvest now, decrypt later:** data encrypted today with RSA or elliptic-curve key exchange can be recorded now
  and decrypted once a large quantum computer exists. That is why the US order sets key establishment a year
  before signatures (2030 against 2031), NIST expects TLS and similar guidance to move key establishment early, and
  the EU roadmap treats long-lived confidential data as high-risk. CNSA 2.0 is the exception: it puts software and
  firmware signing first.

## Use it in CI

Block new weak cryptography on every pull request:

```yaml
# .github/workflows/pqc.yml
name: Cryptography inventory
on: [push, pull_request]
jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/dynamohtech/pqc-kit
      - run: pqc-kit cbom -o cbom.cdx.json
      - run: pqc-kit assess -o pqc-readiness.md
      - run: pqc-kit scan --no-tests --format markdown -o pqc-scan.md --fail-on weak
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pqc-evidence
          path: |
            cbom.cdx.json
            pqc-readiness.md
            pqc-scan.md
```

`--fail-on` accepts `none` (default), `weak`, `vulnerable` (weak or quantum-vulnerable) and `not-cnsa2` (anything
CNSA 2.0 does not approve, for National Security System suppliers). Exit codes: `0` success, `1` findings matched
`--fail-on`, `2` error.

## The CBOM

The CBOM follows [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/), the first version with cryptographic
assets and the version CBOMkit produces. The test suite validates pqc-kit's output against the official schema.

- Each algorithm, protocol, certificate and key is a `cryptographic-asset` component with `cryptoProperties`
  (primitive, parameter set, curve, mode, padding, classical and NIST quantum security level, OID).
- `evidence.occurrences` lists every file and line where the asset was found.
- Certificates link to their public key and signature algorithm; keys link to their algorithm.
- pqc-kit's verdict travels in namespaced properties: `pqc-kit:status`, `pqc-kit:reason`, `pqc-kit:cnsa2`
  (approved, not approved or check) and `pqc-kit:deadline:<nist|us|cnsa2|ncsc|eu>`.
- Keys are identified by a SHA-256 fingerprint of the public key. Private key material is never written.

When CISA publishes its minimum elements for a CBOM (due about March 2027 under EO 14412), pqc-kit will follow them.

## How it works, and what leaves your machine

- **Nothing leaves your machine.** pqc-kit makes no network requests.
- **Reads files only.** It never runs, imports or builds your code, so it is safe on untrusted repositories.
  Symbolic links are never followed. Text files over 5 MB and binary files over 1 MB are skipped.
- **Private keys stay private.** A private key in the repository is reported (with its algorithm, size and whether
  it is encrypted) but its contents are never printed or written.
- **No runtime dependencies.** Standard library only, including the certificate and key parser, so adding pqc-kit
  does not grow your supply chain.
- **Cautious dates.** When the code does not say whether a key is used for encryption or signing, it is counted
  under the earlier key-establishment deadline.

## Limits

- pqc-kit is an inventory and a planning aid. **It is not legal advice.** Whether a framework applies to you depends
  on your customers, sector and contracts. NIST IR 8547 and SP 800-131A Rev. 3 are drafts, and the dates may change.
- **Static analysis without data flow.** It sees algorithms named in the code and resolves constants in the same
  file. An algorithm name read from configuration at run time is reported as "needs review". Tools with data-flow
  analysis, such as [CodeQL](https://codeql.github.com/), or the library-aware detection in
  [CBOMkit / sonar-cryptography](https://github.com/cbomkit/sonar-cryptography), can follow values further.
- **Your code, not your dependencies.** Cryptography inside third-party libraries, compiled binaries, container
  images, hardware security modules, cloud key services and live network endpoints is out of scope for the free core.
- **Languages.** C, C++, C#, Rust, PHP and Ruby are not scanned yet (see the roadmap).

## Free core and enterprise edition

| | Free (Apache-2.0) | Enterprise |
| --- | --- | --- |
| Source code, certificate and key scanning | Yes | Yes |
| CycloneDX 1.6 CBOM | Yes | Yes |
| Readiness report against NIST, US federal, CNSA 2.0, NCSC and EU deadlines | Yes | Yes |
| CI gate (`--fail-on`) | Yes | Yes, plus an approved baseline, so only new findings block |
| Network and TLS endpoint scanning | | Yes |
| Risk-ranked migration plan (data lifetime, exposure, dependencies) | | Yes |
| Auditor-ready reports and evidence packs | | Yes |
| Portfolio view across many repositories | | Yes |

Need help building your cryptographic inventory, planning the migration, or rolling pqc-kit out across a
portfolio? pqc-kit is built and maintained by [Emmanuel Adegbaju (Dynamoh Tech)](https://dynamotech.vercel.app/).
Email [dynamohtech24@gmail.com](mailto:dynamohtech24@gmail.com) about enterprise licences and implementation work.

## Roadmap

- More languages: C and C++ (OpenSSL), C# (.NET), Rust
- Configuration files: web server and OpenSSL settings, Java security properties, SSH configuration
- Keystore contents (PKCS#12, JKS)
- SARIF output for code-scanning dashboards
- CycloneDX 1.7 output, and alignment with CISA's CBOM minimum elements once published
- A ready-made GitHub Action

Issues and pull requests are welcome.

## License

[Apache License 2.0](LICENSE).
