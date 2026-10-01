# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-01

### Added

- `pqc-kit scan`: finds cryptography in Python (syntax tree), Java/Kotlin/Scala/Groovy, Go and
  JavaScript/TypeScript source, and in certificates, CSRs, keys, SSH keys, DH/EC parameters and keystore files.
  Each finding gets a status (weak today, quantum-vulnerable, retiring, needs review, OK, quantum-safe), a role,
  classical strength, NIST post-quantum security category and CNSA 2.0 approval. Table, Markdown and JSON output;
  `--fail-on none|weak|vulnerable|not-cnsa2` for CI; test code marked separately or skipped with `--no-tests`.
- A zero-dependency DER decoder for X.509 certificates and keys, recognising RSA, DSA, EC, EdDSA, X25519/X448,
  DH, ML-KEM, ML-DSA, SLH-DSA (including pre-hash variants), LMS/XMSS and IETF draft composite algorithms.
  Private key material is never output.
- `pqc-kit cbom`: CycloneDX 1.6 cryptography bill of materials with occurrences, certificate-to-key and
  key-to-algorithm links, and pqc-kit's status, CNSA 2.0 approval and first applicable deadline per framework.
- `pqc-kit assess`: readiness report (Markdown or JSON) mapping findings to NIST IR 8547 (draft), Executive Order
  14412 and OMB M-26-15, NSA CNSA 2.0, the UK NCSC migration timelines and the EU coordinated roadmap, with the
  number of findings each milestone affects, time left, and migration priorities.

[Unreleased]: https://github.com/dynamohtech/pqc-kit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dynamohtech/pqc-kit/releases/tag/v0.1.0
