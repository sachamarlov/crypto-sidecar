"""Per-package coverage gate checker.

Reads ``coverage.xml`` produced by ``pytest-cov`` and enforces a per-
package floor. Global floor is already handled by ``--cov-fail-under``
in ``pyproject.toml``; this script adds the ``core/`` and ``security/``
contracts stated in ``docs/CONVENTIONS.md`` section 13 (>= 95%).

Usage:
    uv run python scripts/check_coverage_gates.py
"""

from __future__ import annotations

import sys

# coverage.xml is produced by our own pytest-cov run in the previous CI
# step; it is never user-supplied. The bandit / ruff advisories about
# XML entity attacks do not apply to files the toolchain itself wrote
# seconds earlier. defusedxml would add a dependency for no benefit.
import xml.etree.ElementTree as ET  # nosec B405  # noqa: S405
from pathlib import Path

COVERAGE_XML = Path("coverage.xml")

#: Mapping from package path prefix (POSIX form) to minimum line coverage %.
GATES: dict[str, float] = {
    "src/guardiabox/core": 95.0,
    "src/guardiabox/security": 95.0,
}


def _normalise(filename: str) -> str:
    """Convert Windows backslashes to forward slashes for comparison."""
    return filename.replace("\\", "/")


def _compute_coverage(root: ET.Element, prefix: str) -> tuple[int, int]:
    """Aggregate line counters across every class file under ``prefix``."""
    total = covered = 0
    for cls in root.iter("class"):
        filename = _normalise(cls.get("filename", ""))
        if not filename.startswith(prefix):
            continue
        for line in cls.iter("line"):
            total += 1
            if int(line.get("hits", "0")) > 0:
                covered += 1
    return total, covered


def main() -> int:
    """Exit 0 if every package gate passes, 1 on failure, 2 on missing report."""
    if not COVERAGE_XML.exists():
        sys.stderr.write("coverage.xml not found -- run `uv run pytest` first so it is produced.\n")
        return 2

    tree = ET.parse(COVERAGE_XML)  # nosec B314  # noqa: S314
    root = tree.getroot()

    failed: list[str] = []
    for prefix, floor in GATES.items():
        total, covered = _compute_coverage(root, prefix)
        if total == 0:
            sys.stderr.write(f"[SKIP] {prefix}: no lines matched in coverage.xml\n")
            continue
        pct = 100.0 * covered / total
        status = "OK" if pct >= floor else "FAIL"
        sys.stdout.write(
            f"[{status}] {prefix}: {pct:.2f}% line coverage "
            f"({covered}/{total}) -- floor {floor:.1f}%\n"
        )
        if pct < floor:
            failed.append(prefix)

    if failed:
        sys.stderr.write(
            "\nCoverage gate failed on: " + ", ".join(failed) + "\n"
            "See docs/CONVENTIONS.md section 13 for the 95% target.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
