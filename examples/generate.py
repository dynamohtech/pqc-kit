"""Rebuild the sample outputs in this folder from the sample project in tests/fixtures.

Run from the repository root:  python examples/generate.py
Works offline. Dates are fixed so the files only change when pqc-kit's output does.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pqc_kit import report  # noqa: E402
from pqc_kit.assess import assess, to_markdown  # noqa: E402
from pqc_kit.cbom import build_cbom, write_cbom  # noqa: E402
from pqc_kit.scan import scan_path  # noqa: E402

HERE = Path(__file__).resolve().parent
SAMPLE = ROOT / "tests" / "fixtures" / "sample-app"
NAME = "Example Payments Platform"
TODAY = date(2026, 9, 30)
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def main() -> None:
    result = scan_path(SAMPLE, now=NOW)
    result.root = "sample-app"
    (HERE / "scan.md").write_text(report.to_markdown(result), encoding="utf-8")
    bom = build_cbom(result, NAME, "1.0.0", timestamp=NOW, serial="urn:uuid:00000000-0000-4000-8000-000000000000")
    write_cbom(bom, HERE / "cbom.cdx.json")
    data = assess(result, NAME, as_of=TODAY)
    (HERE / "readiness-report.md").write_text(to_markdown(data), encoding="utf-8")
    print(report.summary_line(result))
    print("examples regenerated")


if __name__ == "__main__":
    main()
