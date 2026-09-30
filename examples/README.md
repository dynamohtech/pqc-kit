# Examples

Sample output for a fictional product, **Example Payments Platform**, built from the test project in
[`tests/fixtures/sample-app`](../tests/fixtures/sample-app). The project mixes Python, Java, Go and TypeScript code
with certificates and public keys, and deliberately includes weak, quantum-vulnerable and post-quantum cryptography
so every part of the output is shown. No private keys are included.

| File | What it is | Made with |
| --- | --- | --- |
| [`scan.md`](scan.md) | Cryptography inventory, grouped by status | `pqc-kit scan sample-app --format markdown` |
| [`cbom.cdx.json`](cbom.cdx.json) | CycloneDX 1.6 cryptography bill of materials | `pqc-kit cbom sample-app --name "Example Payments Platform" --product-version 1.0.0` |
| [`readiness-report.md`](readiness-report.md) | Post-quantum readiness report against the NIST, US federal, CNSA 2.0, NCSC and EU deadlines | `pqc-kit assess sample-app --as-of 2026-09-30` |
| [`generate.py`](generate.py) | Rebuilds these samples offline, with fixed dates | `python examples/generate.py` |
