"""Migration deadlines from the primary sources, and which findings each one affects.

Checked against the documents on 30 September 2026:

- NIST IR 8547 initial public draft (12 Nov 2024), Tables 2 and 4.
- NIST SP 800-131A Rev. 3 initial public draft (21 Oct 2024); NIST SHA-1 retirement news release (15 Dec 2022).
- Executive Order 14412 "Securing the Nation Against Advanced Cryptographic Attacks" (22 Jun 2026), sections 4-6;
  OMB memorandum M-26-15 "Execution of the Migration to Post-Quantum Cryptography" (24 Jun 2026).
- NSA "The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ", Ver. 2.1 (Dec 2024),
  which quotes CNSSP 15; the per-category timeline as in the NSA CNSA 2.0 advisory (Sep 2022, reissued May 2025)
  and FAQ Ver. 2.0 (Apr 2024).
- UK NCSC "Timelines for migration to post-quantum cryptography" (20 Mar 2025).
- EU "A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography", Part 1,
  Version 1.1 (11 Jun 2025), NIS Cooperation Group work stream on PQC.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pqc_kit.catalog import ASYMMETRIC, HASHES_224
from pqc_kit.model import CERTIFICATE, WEAK, VULNERABLE, Finding


@dataclass(frozen=True)
class Milestone:
    date: str  # ISO date used for "time left": the last day before the rule applies
    when: str  # how the source words it
    text: str
    selector: str


@dataclass(frozen=True)
class Framework:
    key: str
    name: str
    applies_to: str
    status: str
    milestones: list[Milestone]
    sources: list[tuple[str, str]]
    notes: list[str] = field(default_factory=list)


NIST = Framework(
    key="nist",
    name="NIST post-quantum transition",
    applies_to="US federal systems. NIST's algorithm standards are also the common reference for other "
               "governments, vendors and auditors.",
    status="Initial public draft (NIST IR 8547, November 2024). The dates are proposals and may change.",
    milestones=[
        Milestone("2030-12-31", "Deprecated after 2030",
                  "Quantum-vulnerable public-key algorithms at 112-bit security (e.g. RSA-2048, 2048-bit DH, "
                  "ECDSA/ECDH on P-224).", "vulnerable-112"),
        Milestone("2030-12-31", "By 31 Dec 2030",
                  "SHA-1 phased out of all uses (NIST announcement, Dec 2022). SP 800-131A Rev. 3 (draft) also disallows 224-bit hash "
                  "functions after 2030.", "sha1-224"),
        Milestone("2035-12-31", "Disallowed after 2035",
                  "All quantum-vulnerable public-key algorithms: RSA, ECDSA, EdDSA, DH, ECDH and MQV, at any key size "
                  "(DSA is already not approved for signing).",
                  "vulnerable"),
    ],
    sources=[
        ("NIST IR 8547 (initial public draft): Transition to Post-Quantum Cryptography Standards",
         "https://csrc.nist.gov/pubs/ir/8547/ipd"),
        ("NIST SP 800-131A Rev. 3 (initial public draft)", "https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd"),
        ("NIST retires SHA-1 (15 December 2022)",
         "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm"),
    ],
    notes=["NIST says application-specific guidance (e.g. for TLS and IKE) may require or recommend quantum-resistant "
           "key establishment earlier, to counter 'harvest now, decrypt later' attacks."],
)

US = Framework(
    key="us",
    name="US federal PQC migration (Executive Order 14412, OMB M-26-15)",
    applies_to="US federal agencies' high value assets and high impact systems (National Security Systems follow "
               "CNSA 2.0 instead), and, through a Federal Acquisition Regulation rule the order calls for, federal "
               "contractors.",
    status="Executive Order 14412 (22 June 2026) and OMB memorandum M-26-15 (24 June 2026). The contractor "
           "requirement depends on a FAR rule that the order gave the FAR Council 180 days to propose.",
    milestones=[
        Milestone("2030-01-02", "By 2 Jan 2030",
                  "Agencies must support TLS 1.3 or later (M-26-15, Appendix A, citing Executive Order 14306). "
                  "Affected counts code that names an older TLS or SSL version; check whether it caps the version "
                  "or only sets a minimum.", "tls-below-1.3"),
        Milestone("2030-12-31", "By 31 Dec 2030",
                  "High value assets and high impact systems use PQC for key establishment (EO 14412, sec. 4(b)(ii)). "
                  "The order also asks for a FAR rule requiring covered contractors to comply with NIST's FIPS, "
                  "including the post-quantum FIPS, by this date. Keys whose use can't be told from the code are "
                  "counted here, under the earlier date.", "vulnerable-kex"),
        Milestone("2031-12-31", "By 31 Dec 2031",
                  "High value assets and high impact systems use PQC for digital signatures (EO 14412, sec. 4(b)(iii)).",
                  "vulnerable-sig"),
        Milestone("2035-12-31", "By 2035",
                  "Remaining systems complete the migration (M-26-15, Phase 5).", "vulnerable"),
    ],
    sources=[
        ("Executive Order 14412: Securing the Nation Against Advanced Cryptographic Attacks (22 June 2026)",
         "https://www.whitehouse.gov/presidential-actions/2026/06/"
         "securing-the-nation-against-advanced-cryptographic-attacks/"),
        ("OMB M-26-15: Execution of the Migration to Post-Quantum Cryptography (24 June 2026)",
         "https://www.whitehouse.gov/wp-content/uploads/2026/06/"
         "M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf"),
    ],
    notes=["The order gives CISA, with NIST, 270 days (to about 19 March 2027) to publish the minimum elements "
           "for a cryptographic bill of materials. M-26-15 asks agencies to keep a central CBOM and to submit a "
           "PQC migration plan within 120 days (by about 22 October 2026).",
           "M-26-15 (Appendix A, PQC algorithm selection) points agencies to ML-KEM (FIPS 203), ML-DSA (FIPS 204) and "
           "SLH-DSA (FIPS 205)."],
)

CNSA2 = Framework(
    key="cnsa2",
    name="NSA CNSA 2.0",
    applies_to="US National Security Systems, and vendors and contractors who supply them.",
    status="Policy: CNSSP 15, as summarised in the NSA CNSA 2.0 FAQ (Ver. 2.1, December 2024).",
    milestones=[
        Milestone("2026-12-31", "From 1 Jan 2027",
                  "All new acquisitions for National Security Systems must be CNSA 2.0 compliant, unless otherwise "
                  "noted.", "not-cnsa2"),
        Milestone("2030-12-31", "By 31 Dec 2030",
                  "Equipment and services that cannot support CNSA 2.0 must be phased out, unless otherwise noted.",
                  "not-cnsa2"),
        Milestone("2031-12-31", "By 31 Dec 2031",
                  "CNSA 2.0 algorithms are mandated for use, unless otherwise noted.", "not-cnsa2"),
        Milestone("2035-12-31", "By 2035", "All National Security Systems quantum-resistant (NSM-10 goal).",
                  "vulnerable"),
    ],
    sources=[
        ("NSA: The CNSA 2.0 and Quantum Computing FAQ (Ver. 2.1, Dec 2024)",
         "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF"),
        ("NSA: Announcing the Commercial National Security Algorithm Suite 2.0 (Sep 2022)",
         "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"),
    ],
    notes=["CNSA 2.0 algorithms: ML-KEM-1024 (key establishment), ML-DSA-87 (signatures), LMS or XMSS "
           "(software and firmware signing; single-tree only), AES-256, SHA-384 or SHA-512. SLH-DSA is not "
           "approved for any use in National Security Systems. SHA3-384 and SHA3-512 are allowed only for internal hardware "
           "functions such as boot-up integrity checks."],
)

CNSA2_CATEGORIES = [
    ("Software and firmware signing", "2025", "2030"),
    ("Web browsers, servers and cloud services", "2025", "2033"),
    ("Traditional networking equipment (VPNs, routers)", "2026", "2030"),
    ("Operating systems", "2027", "2033"),
    ("Niche equipment (constrained devices, large PKI systems)", "2030", "2033"),
    ("Custom applications and legacy equipment", "-", "2033 (update or replace)"),
]

NCSC = Framework(
    key="ncsc",
    name="UK NCSC migration timelines",
    applies_to="UK organisations; the NCSC's recommended timeline for planning and completing migration.",
    status="Guidance (published 20 March 2025).",
    milestones=[
        Milestone("2028-12-31", "By 2028",
                  "Define migration goals, carry out a full discovery exercise (find your cryptography) and build an "
                  "initial migration plan.", "all"),
        Milestone("2031-12-31", "By 2031",
                  "Carry out the early, highest-priority migration activities and refine the plan.", "vulnerable"),
        Milestone("2035-12-31", "By 2035", "Complete migration to PQC of all systems, services and products.",
                  "vulnerable"),
    ],
    sources=[("NCSC: Timelines for migration to post-quantum cryptography",
              "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines")],
)

EU = Framework(
    key="eu",
    name="EU coordinated PQC roadmap",
    applies_to="EU Member States: a recommended timeline agreed in the NIS Cooperation Group. It is addressed to "
               "Member States rather than directly to companies.",
    status="Non-binding roadmap agreed by Member States in the NIS Cooperation Group (Part 1, Version 1.1, 11 June "
           "2025), following Commission Recommendation (EU) 2024/1101.",
    milestones=[
        Milestone("2026-12-31", "By 31 Dec 2026",
                  "First steps done, national roadmaps set, and planning and pilots started for high- and "
                  "medium-risk use cases. The roadmap calls cryptographic inventories a 'no-regret' first step.",
                  "all"),
        Milestone("2030-12-31", "By 31 Dec 2030",
                  "High-risk use cases migrated: quantum-vulnerable public-key mechanisms no longer used on their "
                  "own. Quantum-safe software and firmware upgrades enabled by default.", "vulnerable"),
        Milestone("2035-12-31", "By 31 Dec 2035",
                  "Medium-risk use cases migrated; low-risk use cases as far as feasible.", "vulnerable"),
    ],
    sources=[("European Commission: Coordinated Implementation Roadmap for the transition to PQC",
              "https://digital-strategy.ec.europa.eu/en/library/"
              "coordinated-implementation-roadmap-transition-post-quantum-cryptography")],
    notes=["The roadmap advises that data needing confidentiality for at least 10 years is protected against "
           "quantum attacks by the end of 2030 at the latest."],
)

FRAMEWORKS = [NIST, US, CNSA2, NCSC, EU]
BY_KEY = {f.key: f for f in FRAMEWORKS}


def is_quantum_vulnerable(f: Finding) -> bool:
    """Public-key cryptography a quantum computer would break (whatever its status today)."""
    if f.family in ASYMMETRIC and f.family != "Signature":
        return True
    if f.family in ("TLS", "DTLS") and f.status == VULNERABLE:
        return True
    if f.family == "TLS-CipherSuite" and f.details.get("suite_status") in (VULNERABLE,):
        return True
    return False


def is_vulnerable_key_establishment(f: Finding) -> bool:
    """Quantum-vulnerable key establishment, counting keys whose use is unknown (the cautious reading)."""
    return is_quantum_vulnerable(f) and f.role in ("key-establishment", "protocol", "other")


def is_vulnerable_signature(f: Finding) -> bool:
    return is_quantum_vulnerable(f) and f.role in ("signature", "certificate")


def is_tls_below_13(f: Finding) -> bool:
    if f.family == "SSL":
        return True
    if f.family in ("TLS", "DTLS") and f.version:
        try:
            major, minor = (int(x) for x in f.version.split(".")[:2])
        except ValueError:
            return False
        # DTLS 1.2 corresponds to TLS 1.2 and DTLS 1.3 to TLS 1.3.
        return (major, minor) < (1, 3)
    return False


def uses_sha1_or_224(f: Finding) -> bool:
    names = {"SHA-1"} | HASHES_224
    if f.family in names or f.hash in names:
        return not f.details.get("non_security")
    if f.asset == CERTIFICATE:
        sig = f.details.get("signature") or {}
        return sig.get("hash") in names and not (f.details.get("self_signed") and f.details.get("is_ca"))
    return False


def selects(selector: str, f: Finding) -> bool:
    if selector == "all":
        return True
    if selector == "vulnerable":
        return is_quantum_vulnerable(f)
    if selector == "vulnerable-kex":
        return is_vulnerable_key_establishment(f)
    if selector == "vulnerable-sig":
        return is_vulnerable_signature(f)
    if selector == "tls-below-1.3":
        return is_tls_below_13(f)
    if selector == "vulnerable-112":
        return is_quantum_vulnerable(f) and f.classical_bits == 112
    if selector == "sha1-224":
        return uses_sha1_or_224(f)
    if selector == "not-cnsa2":
        return f.cnsa2 is False
    if selector == "weak":
        return f.status == WEAK
    return False


def earliest_deadlines(f: Finding, frameworks: list[Framework] | None = None) -> dict[str, Milestone]:
    """For each framework, the first milestone that covers this finding.

    Milestones that cover every finding (such as "finish discovery by 2028") are left out: they are
    deadlines for the programme, not for a particular algorithm.
    """
    out: dict[str, Milestone] = {}
    for fw in frameworks or FRAMEWORKS:
        hits = [m for m in fw.milestones if m.selector != "all" and selects(m.selector, f)]
        if hits:
            out[fw.key] = min(hits, key=lambda m: m.date)
    return out
