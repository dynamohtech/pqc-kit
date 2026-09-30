"""Command-line interface: pqc-kit scan | cbom | assess."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from pqc_kit import __version__, assess as assess_mod, report
from pqc_kit.cbom import build_cbom, write_cbom
from pqc_kit.frameworks import BY_KEY
from pqc_kit.model import SAFE, STATUS_ORDER, WEAK, VULNERABLE, Finding, ScanResult
from pqc_kit.scan import finalize, scan_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
DEFAULT_CBOM = "cbom.cdx.json"
FAIL_ON = {
    "none": lambda f: False,
    "weak": lambda f: f.status == WEAK,
    "vulnerable": lambda f: f.status in (WEAK, VULNERABLE),
    "not-cnsa2": lambda f: f.cnsa2 is False,
}


class CliError(Exception):
    """A problem to report to the user without a traceback."""


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except BrokenPipeError:
        # Output was piped into a command that stopped reading (e.g. `| head`).
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        return EXIT_ERROR


def _run(argv: list[str] | None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # Keep going on consoles that cannot show every character (e.g. legacy Windows code pages).
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except (CliError, FileNotFoundError, ValueError) as exc:
        print(f"pqc-kit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-kit",
        description="Find the cryptography that quantum computers will break, export a CycloneDX CBOM, and map "
                    "it to the NIST, US federal, NSA CNSA 2.0, UK NCSC and EU migration deadlines. Not legal "
                    "advice.",
    )
    parser.add_argument("--version", action="version", version=f"pqc-kit {__version__}")
    sub = parser.add_subparsers(title="commands", metavar="COMMAND")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("path", nargs="?", default=".", help="project folder or single file (default: .)")
    common.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip matching files or folders (repeatable), e.g. --exclude 'docs/*'")
    common.add_argument("--no-default-excludes", action="store_true",
                        help="also scan node_modules, vendor, build, dist and similar folders")
    common.add_argument("--no-tests", action="store_true", help="skip test code and test fixtures entirely")

    p = sub.add_parser("scan", parents=[common], help="list the cryptography in a project")
    p.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    p.add_argument("-o", "--output", help="write the result to a file instead of the terminal")
    p.add_argument("--fail-on", choices=list(FAIL_ON), default="none",
                   help="exit with status 1 if any finding is weak; weak or quantum-vulnerable; or not approved "
                        "in CNSA 2.0 (default: none)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("cbom", parents=[common], help="write a CycloneDX 1.6 cryptography bill of materials")
    p.add_argument("-o", "--output", default=DEFAULT_CBOM, help=f"output file (default: {DEFAULT_CBOM})")
    p.add_argument("--name", help="product name (default: the folder name)")
    p.add_argument("--product-version", help="product version to record in the CBOM")
    p.set_defaults(func=cmd_cbom)

    p = sub.add_parser("assess", parents=[common], help="readiness report against the migration deadlines")
    p.add_argument("--scan", metavar="FILE", help="use the JSON output of `pqc-kit scan --format json` "
                                                  "instead of scanning again")
    p.add_argument("--framework", action="append", choices=list(BY_KEY), metavar="NAME",
                   help=f"limit the report to these frameworks: {', '.join(BY_KEY)} (repeatable; default: all)")
    p.add_argument("--include-tests", action="store_true", help="count test code with product code")
    p.add_argument("--as-of", metavar="YYYY-MM-DD", help="date to measure the time left from (default: today)")
    p.add_argument("--name", help="product name (default: the folder name)")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("-o", "--output", help="write the report to a file instead of the terminal")
    p.set_defaults(func=cmd_assess)
    return parser


def _scan(args: argparse.Namespace) -> ScanResult:
    return scan_path(args.path, excludes=args.exclude, include_tests=not args.no_tests,
                     use_default_excludes=not args.no_default_excludes)


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"Wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _project_name(path: str, name: str | None) -> str:
    if name:
        return name
    p = Path(path).resolve()
    return p.name if p.is_dir() else p.stem


def cmd_scan(args: argparse.Namespace) -> int:
    result = _scan(args)
    text = {"table": report.to_table, "markdown": report.to_markdown, "json": report.to_json}[args.format](result)
    _emit(text, args.output)
    if args.output:
        print(report.summary_line(result), file=sys.stderr)
    failing = [f for f in result.findings if FAIL_ON[args.fail_on](f)]
    if failing:
        print(f"pqc-kit: {len(failing)} finding(s) match --fail-on {args.fail_on}", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_cbom(args: argparse.Namespace) -> int:
    result = _scan(args)
    bom = build_cbom(result, _project_name(args.path, args.name), args.product_version)
    out = Path(args.output)
    write_cbom(bom, out)
    assets: dict[str, int] = {}
    for c in bom["components"]:
        t = c["cryptoProperties"]["assetType"]
        assets[t] = assets.get(t, 0) + 1
    parts = ", ".join(f"{n} {k.replace('related-crypto-material', 'keys')}" for k, n in sorted(assets.items()))
    print(f"Wrote {out}: {len(bom['components'])} cryptographic assets ({parts or 'none'}) "
          f"from {result.files_scanned} files.")
    return EXIT_OK


def cmd_assess(args: argparse.Namespace) -> int:
    as_of = date.fromisoformat(args.as_of) if args.as_of else None
    if args.scan:
        result = load_scan(Path(args.scan))
    else:
        result = _scan(args)
    data = assess_mod.assess(result, _project_name(args.path, args.name), include_tests=args.include_tests,
                             as_of=as_of, frameworks=args.framework)
    text = assess_mod.to_markdown(data) if args.format == "markdown" else assess_mod.to_json(data)
    _emit(text, args.output)
    return EXIT_OK


def load_scan(path: Path) -> ScanResult:
    """Rebuild a ScanResult from `pqc-kit scan --format json` output."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data:
        raise CliError(f"{path} is not the JSON output of `pqc-kit scan`")
    fields = set(Finding.__dataclass_fields__)
    findings = []
    for item in data["findings"]:
        kwargs = {k: v for k, v in item.items() if k in fields and k not in ("name", "status", "reasons", "role",
                                                                          "classical_bits", "quantum_category",
                                                                          "cnsa2")}
        findings.append(Finding(**kwargs))
    finalize(findings, now=datetime.now(timezone.utc))
    result = ScanResult(root=data.get("root", str(path)), findings=findings,
                        files_scanned=data.get("files_scanned", 0), files_by_kind=data.get("files_by_kind", {}),
                        errors=data.get("errors", []))
    return result


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
