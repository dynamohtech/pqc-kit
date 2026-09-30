# Security policy

pqc-kit reads other people's code, certificates and keys, so it is held to the same standard it checks for.

## Reporting a vulnerability

Please report security issues privately, in either of these ways:

- **GitHub (preferred):** **Security → Report a vulnerability** on this repository
  (<https://github.com/dynamohtech/pqc-kit/security/advisories/new>).
- **Email:** [dynamohtech24@gmail.com](mailto:dynamohtech24@gmail.com), with "pqc-kit security" in the subject.

Do not open a public issue for a security problem.

Please include the version (`pqc-kit --version`), what you ran, a sample file if the problem is in parsing, and what
an attacker could achieve.

## What to expect

- An acknowledgement within 5 working days.
- An assessment and a planned fix date as soon as the issue is confirmed.
- A GitHub security advisory and a CVE, where appropriate, when the fix is released. You are credited unless you
  ask not to be.

## Supported versions

Security fixes go into the latest release. pqc-kit is pre-1.0, so please upgrade to the latest version.

## Scope notes

These are vulnerabilities:

- A way to make pqc-kit execute, import or build scanned code, follow a symbolic link, or read or write outside the
  paths you give it.
- Private key material (or any part of it) appearing in any output: terminal, JSON, Markdown or CBOM.
- A crafted file that makes pqc-kit hang, use unbounded memory, or crash instead of reporting the file as unreadable.
- Any network request. pqc-kit is designed to work fully offline.

A wrong classification (for example an algorithm reported as quantum-safe that is not) is a serious bug but not
usually a vulnerability; please open a normal issue with the example, unless it could hide weak cryptography in a
way an attacker could exploit.
