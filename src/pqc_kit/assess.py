"""Post-quantum readiness report: what was found, which deadlines apply, and what to fix first."""

from __future__ import annotations

import json
from datetime import date, datetime

from pqc_kit import __version__
from pqc_kit.frameworks import CNSA2_CATEGORIES, FRAMEWORKS, Framework, is_quantum_vulnerable, selects
from pqc_kit.model import (
    CERTIFICATE, KEY, OK, RETIRING, SAFE, STATUS_ORDER, STATUS_TEXT, UNKNOWN, VULNERABLE, WEAK, Finding, ScanResult,
)

STATUS_MEANING = {
    WEAK: "Broken or already disallowed. Fix now, whatever happens with quantum computers.",
    VULNERABLE: "Public-key cryptography a large quantum computer breaks. Plan the migration.",
    RETIRING: ("Acceptable today, but NIST plans to phase it out by the end of 2030 (SHA-1: announced; 224-bit "
               "hashes: draft)."),
    UNKNOWN: "The algorithm or its parameters are set at run time or could not be read. Check by hand.",
    OK: "Symmetric cryptography or a hash at a size that holds up against quantum attacks.",
    SAFE: "Post-quantum (NIST FIPS 203/204/205 or SP 800-208), or a hybrid that includes one.",
}

REPLACEMENT = {
    "key-establishment": ("ML-KEM (FIPS 203). During the transition, combine it with the classical algorithm "
                          "(for TLS 1.3, the X25519MLKEM768 hybrid group). CNSA 2.0 requires ML-KEM-1024."),
    "signature": ("ML-DSA (FIPS 204); SLH-DSA (FIPS 205) where a hash-based scheme is preferred; LMS or XMSS "
                  "(SP 800-208) for firmware signing. CNSA 2.0 requires ML-DSA-87, or LMS/XMSS for firmware."),
    "certificate": ("Plan re-issuance with ML-DSA keys before the deadlines above, and check your CA's roadmap. "
                    "Where old and new clients must both be served, composite certificates (an IETF draft) are "
                    "one option."),
    "protocol": "TLS 1.3 with a hybrid post-quantum group such as X25519MLKEM768; disable TLS 1.0 and 1.1.",
    "other": "Depends on how the key is used: ML-KEM for key establishment, ML-DSA for signatures.",
}


def assess(result: ScanResult, name: str, include_tests: bool = False, as_of: date | None = None,
           frameworks: list[str] | None = None) -> dict:
    """Everything the report needs, as plain data (also the JSON output)."""
    as_of = as_of or date.today()
    selected = [f for f in FRAMEWORKS if not frameworks or f.key in frameworks]
    scope = [f for f in result.findings if include_tests or not f.in_tests]
    tests = [f for f in result.findings if f.in_tests]

    counts = {s: sum(1 for f in scope if f.status == s) for s in STATUS_ORDER}
    test_counts = {s: sum(1 for f in tests if f.status == s) for s in STATUS_ORDER}
    vulnerable = [f for f in scope if is_quantum_vulnerable(f)]

    deadline_rows = []
    for fw in selected:
        rows = []
        for m in fw.milestones:
            affected = [f for f in scope if selects(m.selector, f)]
            due = date.fromisoformat(m.date)
            rows.append({"when": m.when, "date": m.date, "days_left": (due - as_of).days, "text": m.text,
                         "affected": len(affected), "selector": m.selector})
        deadline_rows.append({"key": fw.key, "name": fw.name, "applies_to": fw.applies_to, "status": fw.status,
                              "milestones": rows, "notes": fw.notes,
                              "sources": [{"title": t, "url": u} for t, u in fw.sources]})

    def items(pred) -> list[dict]:
        return [_item(f) for f in scope if pred(f)]

    certs = [f for f in scope if f.asset == CERTIFICATE]
    private_keys = [f for f in result.findings if f.asset == KEY and f.details.get("kind") == "private"]
    cnsa_values = [f.cnsa2 for f in scope]

    return {
        "tool": {"name": "pqc-kit", "version": __version__},
        "project": name,
        "root": result.root,
        "as_of": as_of.isoformat(),
        "include_tests": include_tests,
        "files_scanned": result.files_scanned,
        "files_by_kind": result.files_by_kind,
        "counts": counts,
        "test_counts": test_counts,
        "headline": {
            "quantum_vulnerable": len(vulnerable),
            "key_establishment": sum(1 for f in vulnerable if f.role in ("key-establishment", "protocol")),
            "signatures": sum(1 for f in vulnerable if f.role in ("signature", "certificate")),
            "weak": counts[WEAK],
            "quantum_safe": counts[SAFE],
            "certificates": len(certs),
            "private_keys_in_repo": sum(1 for f in private_keys if not f.in_tests),
            "private_keys_in_tests": sum(1 for f in private_keys if f.in_tests),
        },
        "frameworks": deadline_rows,
        "cnsa2_categories": [{"category": c, "support_and_prefer": a, "exclusively_use": b}
                             for c, a, b in CNSA2_CATEGORIES] if any(f.key == "cnsa2" for f in selected) else [],
        "cnsa2": {"approved": cnsa_values.count(True), "not_approved": cnsa_values.count(False),
                  "check": cnsa_values.count(None)},
        "weak": items(lambda f: f.status == WEAK),
        "key_establishment": items(lambda f: f.status == VULNERABLE and f.role in ("key-establishment", "protocol")),
        "signatures": items(lambda f: f.status == VULNERABLE and f.role == "signature"),
        "other_public_key": items(lambda f: f.status == VULNERABLE and f.role in ("other",) and f.asset != CERTIFICATE),
        "certificates": [_item(f) for f in certs],
        "retiring": items(lambda f: f.status == RETIRING),
        "unknown": items(lambda f: f.status == UNKNOWN),
        "quantum_safe": items(lambda f: f.status == SAFE),
        "private_keys": [_item(f) for f in private_keys],
        "errors": result.errors,
    }


def _item(f: Finding) -> dict:
    d = {"algorithm": f.name, "status": f.status, "where": f.where, "found_by": f.symbol, "role": f.role,
         "reasons": f.reasons, "notes": f.notes, "in_tests": f.in_tests, "cnsa2": f.cnsa2}
    if f.asset == CERTIFICATE:
        sig = f.details.get("signature") or {}
        d.update(subject=f.details.get("common_name") or f.details.get("subject"),
                 not_after=f.details.get("not_after"), signature=sig.get("name"), is_ca=f.details.get("is_ca"))
    return d


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def to_markdown(a: dict, limit: int = 200) -> str:
    out: list[str] = []
    w = out.append
    h = a["headline"]
    w(f"# Post-quantum readiness report: {a['project']}")
    w("")
    kinds = ", ".join(f"{n} {k}" for k, n in a["files_by_kind"].items()) or "none with cryptography"
    w(f"Static scan of `{a['root']}` on {a['as_of']} by pqc-kit {a['tool']['version']}: "
      f"{a['files_scanned']} files scanned ({kinds}). "
      + ("Test code is included." if a["include_tests"] else "Test code is counted separately."))
    w("")
    w("> **Not legal advice.** This report maps what a static scan found to published government timelines. "
      "Several dates come from drafts and may change. Check the sources and your own obligations.")
    w("")
    w("## Summary")
    w("")
    lines = []
    if h["quantum_vulnerable"]:
        other = h["quantum_vulnerable"] - h["key_establishment"] - h["signatures"]
        split = [f"{h['key_establishment']} for key establishment (exposed to 'harvest now, decrypt later')",
                 f"{h['signatures']} for signatures or certificates"]
        if other:
            split.append(f"{other} keys or key generation where the use is set elsewhere")
        lines.append(f"**{h['quantum_vulnerable']}** uses of public-key cryptography that a quantum computer breaks: "
                     + ", ".join(split[:-1]) + " and " + split[-1] + ".")
    if h["weak"]:
        lines.append(f"**{h['weak']}** uses of cryptography that is weak or disallowed today; fix these first.")
    if h["quantum_safe"]:
        lines.append(f"**{h['quantum_safe']}** uses of post-quantum or hybrid algorithms already.")
    if h["private_keys_in_repo"]:
        lines.append(f"**{h['private_keys_in_repo']}** private key(s) stored in the repository outside test code.")
    if not lines:
        lines.append("No quantum-vulnerable or weak cryptography was found in the scanned files.")
    for line in lines:
        w(f"- {line}")
    w("")
    w("| Status | Product code | Test code | Meaning |")
    w("| --- | ---: | ---: | --- |")
    for s in STATUS_ORDER:
        w(f"| {STATUS_TEXT[s]} | {a['counts'][s]} | {a['test_counts'][s]} | {STATUS_MEANING[s]} |")
    w("")

    w("## Deadlines that apply")
    w("")
    w("\"Affected\" counts the findings in product code that each milestone covers. \"Time left\" is from the "
      "report date.")
    w("")
    for fw in a["frameworks"]:
        w(f"### {fw['name']}")
        w("")
        w(f"**Applies to:** {fw['applies_to']}  ")
        w(f"**Status:** {fw['status']}")
        w("")
        w("| When | What | Affected | Time left |")
        w("| --- | --- | ---: | --- |")
        for m in fw["milestones"]:
            w(f"| {m['when']} | {_md(m['text'])} | {m['affected']} | {_time_left(m['days_left'])} |")
        w("")
        for n in fw["notes"]:
            w(f"{n}")
            w("")
        if fw["key"] == "cnsa2" and a["cnsa2_categories"]:
            w("CNSA 2.0 transition by product category (NSA CNSA 2.0 advisory, September 2022, reissued May 2025):")
            w("")
            w("| Category | Support and prefer by | Use exclusively by |")
            w("| --- | --- | --- |")
            for c in a["cnsa2_categories"]:
                w(f"| {c['category']} | {c['support_and_prefer']} | {c['exclusively_use']} |")
            w("")
            c = a["cnsa2"]
            w(f"In product code: {c['approved']} CNSA 2.0 algorithm uses, {c['not_approved']} not approved, "
              f"{c['check']} to check.")
            w("")
        w("Sources: " + "; ".join(f"[{s['title']}]({s['url']})" for s in fw["sources"]))
        w("")

    _section(w, "1. Fix first: weak today", a["weak"], limit,
             "Broken or already disallowed. These are risks today, independent of quantum computers.",
             reason=True)
    _section(w, "2. Key establishment: migrate first", a["key_establishment"], limit,
             "Anything encrypted with these today can be recorded now and decrypted once a large quantum "
             "computer exists, so they come before signatures.", replacement="key-establishment", reason=False)
    _section(w, "3. Signatures", a["signatures"], limit,
             "Forgery needs a quantum computer at the time of the attack, so these follow key establishment, but "
             "long-lived signatures (firmware, documents, roots of trust) need an early plan.",
             replacement="signature", reason=False)
    _section(w, "4. Other public-key use", a["other_public_key"], limit,
             "Keys and key generation where the use (encryption or signing) is decided elsewhere in the code.",
             replacement="other", reason=False)
    if a["certificates"]:
        w(f"## 5. Certificates ({len(a['certificates'])})")
        w("")
        w(REPLACEMENT["certificate"])
        w("")
        w("| Subject | Key | Signed with | Expires | Status | Where | Notes |")
        w("| --- | --- | --- | --- | --- | --- | --- |")
        for c in a["certificates"][:limit]:
            w(f"| {_md(c.get('subject') or '')} | {_md(c['algorithm'])} | {_md(c.get('signature') or '')} | "
              f"{(c.get('not_after') or '')[:10]} | {STATUS_TEXT[c['status']]} | `{c['where']}` | "
              f"{_md(' '.join(c['notes']))} |")
        _more(w, a["certificates"], limit)
        w("")
    _section(w, "6. Retiring after 2030", a["retiring"], limit,
             "Acceptable today; replace SHA-1 and 224-bit hashes with SHA-256 or stronger before the end of 2030.",
             reason=True)
    _section(w, "7. Needs review", a["unknown"], limit,
             "The scan could not tell the algorithm or its parameters. Check these by hand.", reason=True)
    _section(w, "8. Already quantum-safe", a["quantum_safe"], limit, "", reason=True)
    keys = [k for k in a["private_keys"]]
    if keys:
        w(f"## Private keys found in the repository ({len(keys)})")
        w("")
        w("Private keys in source control can be copied by anyone with read access, now and from history. "
          "Move them to a secrets manager and rotate them; keep only test-only keys in test folders.")
        w("")
        w("| Key | Where | Test code |")
        w("| --- | --- | --- |")
        for k in keys[:limit]:
            w(f"| {_md(k['algorithm'])} | `{k['where']}` | {'yes' if k['in_tests'] else 'no'} |")
        _more(w, keys, limit)
        w("")
    w("## What this report does not cover")
    w("")
    w("- **Static scan only.** Algorithms chosen at run time, cryptography inside third-party libraries and "
      "binaries, network endpoints, hardware security modules and cloud key services are not visible to it.")
    w("- **Languages and formats.** v0.1 reads Python, Java/Kotlin, Go, JavaScript/TypeScript, PEM/DER "
      "certificates and keys, SSH public keys and keystore files. Other languages are not scanned yet.")
    w("- **Draft dates.** NIST IR 8547 and SP 800-131A Rev. 3 are drafts; the EU roadmap is a recommendation to "
      "Member States. Re-check the sources before you commit to dates in contracts.")
    w("- **Not legal advice.** Whether a framework applies to you depends on your customers and sector.")
    w("")
    w("The pqc-kit enterprise edition adds network and TLS endpoint scanning, a risk-ranked migration plan based "
      "on data lifetime and exposure, auditor-ready reports, and a CI gate that blocks new weak or "
      "quantum-vulnerable cryptography against an approved baseline. Contact: dynamohtech24@gmail.com.")
    if a["errors"]:
        w("")
        w("## Files that could not be fully read")
        w("")
        for e in a["errors"][:50]:
            w(f"- {_md(e)}")
    return "\n".join(out).rstrip() + "\n"


def _section(w, title: str, items: list[dict], limit: int, intro: str, replacement: str | None = None,
             reason: bool = True) -> None:
    if not items:
        return
    w(f"## {title} ({len(items)})")
    w("")
    if intro:
        w(intro)
        w("")
    if replacement:
        w(f"**Replace with:** {REPLACEMENT[replacement]}")
        w("")
    w("| Algorithm | Where | Found by | " + ("Why |" if reason else "Notes |"))
    w("| --- | --- | --- | --- |")
    for i in items[:limit]:
        text = " ".join(i["reasons"][:1] + i["notes"][:1]) if reason else " ".join(i["notes"][:2])
        w(f"| {_md(i['algorithm'])} | `{i['where']}` | `{_md(i['found_by'][:70])}` | {_md(text)} |")
    _more(w, items, limit)
    w("")


def _more(w, items: list, limit: int) -> None:
    if len(items) > limit:
        w(f"| ... and {len(items) - limit} more (use `--format json` for all) | | | |")


def _time_left(days: int) -> str:
    if days < 0:
        return "passed"
    if days < 60:
        return f"{days} days"
    months = round(days / 30.44)
    if months < 24:
        return f"about {months} months"
    return f"about {days / 365.25:.1f} years"


def _md(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_json(a: dict) -> str:
    return json.dumps(a, indent=2, ensure_ascii=False, default=_default) + "\n"


def _default(o):
    if isinstance(o, (date, datetime)):
        return o.isoformat()
    raise TypeError(type(o).__name__)
