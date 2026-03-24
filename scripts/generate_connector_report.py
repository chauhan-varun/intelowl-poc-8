#!/usr/bin/env python3
"""Write connector_audit_report.md from full_scan()."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_connectors import (
    PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC,
    ScanResult,
    format_table_discarded,
    full_scan,
)


def _git_meta(intelowl_root: Path) -> tuple[str, str]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(intelowl_root),
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=str(intelowl_root),
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        return commit or "unknown", branch or "unknown"
    except OSError:
        return "unknown", "unknown"


def _read_health_snippet(intelowl_root: Path, max_lines: int = 45) -> str:
    path = intelowl_root / "api_app" / "classes.py"
    if not path.is_file():
        return "(api_app/classes.py not found)\n"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[str] = []
    in_fn = False
    indent = 0
    for i, line in enumerate(lines):
        if not in_fn and line.startswith("    def health_check("):
            in_fn = True
            indent = len(line) - len(line.lstrip())
            out.append(f"{i+1:4} | {line}")
            continue
        if in_fn:
            cur = len(line) - len(line.lstrip()) if line.strip() else indent + 4
            if line.strip() and cur <= indent and not line.strip().startswith("#"):
                break
            out.append(f"{i+1:4} | {line}")
            if len(out) >= max_lines:
                out.append("     | ... (truncated)")
                break
    if not out:
        return "(health_check not found)\n"
    return "\n".join(out) + "\n"


def generate_markdown(intelowl_root: Path, r: ScanResult) -> str:
    commit, branch = _git_meta(intelowl_root)
    w_lines: list[str] = []

    def w(s: str = "") -> None:
        w_lines.append(s)

    w("# Connectors — static dump")
    w()
    w(
        f"IntelOwl `{commit}` on `{branch}` · {datetime.now().strftime('%Y-%m-%d %H:%M')}. "
        "Scanned `connectors/`, requirement pins, connector tests."
    )
    w()
    w("## Summary")
    w()
    overrides = sum(1 for c in r.connector_classes if c.has_health_check_override)
    w(f"- {len(r.connector_classes)} connector classes under `connectors/`; {overrides} override `health_check`.")
    w(f"- {len(r.discarded_replaces)} bad `.replace()` (no assign) — MISP hash line if anything shows up below.")
    w(
        "- abuse_submitter pulls `AnalyzerRunException` from analyzers: "
        f"{'yes' if r.abuse_submitter_imports_analyzer_exception else 'no'}."
    )
    w(
        f"- pins: pymisp=={r.pymisp_pin or '?'}, pycti=={r.pycti_pin or '?'}"
    )
    w(
        f"- connector tests: {r.connector_test_py_files} files / ~{r.connector_test_total_lines} lines; "
        f"{len(r.tests_mentioning_connector_run)} test names contain `run`."
    )
    w(f"- OpenCTI client calls without `timeout`: {len(r.opencti_no_timeout)}")
    w(
        f"- PyMISP with timeout ≤{PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC}s: {len(r.pymisp_short_timeout)} "
        f"(threshold is `PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC` in scan_connectors.py)"
    )
    if r.emailsender_update_stub:
        w(
            f"- EmailSender.update is a stub: `{r.emailsender_update_stub.filepath}:{r.emailsender_update_stub.line}`"
        )
    w(f"- MockPyMISP.get_version: {'yes' if r.mockpymisp_has_get_version else 'no'}")
    w()
    w("## Connector classes")
    w()
    w("| Class | File | `health_check` override |")
    w("|-------|------|-------------------------|")
    for c in sorted(r.connector_classes, key=lambda x: x.name):
        hc = "yes" if c.has_health_check_override else "**no** (inherits generic `Plugin.health_check`)"
        w(f"| `{c.name}` | `{c.filepath}` | {hc} |")
    w()
    w("### Default health_check")
    w()
    w("Everyone inherits this unless overridden — `requests.head`, `verify=False`, some 4xx counted as fine. Snippet:")
    w()
    w("```text")
    w(_read_health_snippet(intelowl_root).rstrip())
    w("```")
    w()
    w("---")
    w()
    w("## Stray .replace()")
    w()
    w("Expr-statement `.replace()` without assignment — leaves e.g. `sha-256` as-is for MISP.")
    w()
    w(format_table_discarded(r.discarded_replaces))
    w()
    w("---")
    w()
    w("## Timeouts + test doubles")
    w()
    w("### OpenCTI client, no timeout kw")
    w()
    if r.opencti_no_timeout:
        w("| File | Line |")
        w("|------|------|")
        for x in r.opencti_no_timeout:
            w(f"| `{x.filepath}` | {x.line} |")
    else:
        w("(none)")
    w()
    w(f"### PyMISP timeout ≤{PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC}s")
    w()
    w(f"Arbitrary cutoff at {PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC}s — see constant in scan_connectors.py.")
    w()
    if r.pymisp_short_timeout:
        w("| File | Line | Seconds |")
        w("|------|------|---------|")
        for x in r.pymisp_short_timeout:
            w(f"| `{x.filepath}` | {x.line} | {x.seconds} |")
    else:
        w("(none)")
    w()
    w("### EmailSender.update")
    w()
    if r.emailsender_update_stub:
        w(
            f"`{r.emailsender_update_stub.filepath}:{r.emailsender_update_stub.line}` — `def update(self) -> bool: pass` "
            "returns `None`."
        )
    else:
        w("(not found)")
    w()
    w("### MockPyMISP.get_version")
    w()
    if r.mockpymisp_has_get_version:
        w("`get_version` is defined on `MockPyMISP`.")
    else:
        w("`MockPyMISP` has no `get_version`; add it if `health_check` starts calling the real API.")
    w()
    w("---")
    w()
    w("## AbuseSubmitter import")
    w()
    if r.abuse_submitter_imports_analyzer_exception:
        w(
            f"`{r.abuse_submitter_path}` imports `AnalyzerRunException` from analyzers. "
            "Probably should use `ConnectorRunException` like the rest of connectors."
        )
    else:
        w("No `AnalyzerRunException` import from analyzers.")
    w()
    w("---")
    w()
    w("## Yeti urls")
    w()
    w("Anything with `api/v2` in the connector vs analyzer files (#2309 context):")
    w()
    w("| File | Line | Fragment |")
    w("|------|------|----------|")
    for y in r.yeti_endpoints:
        w(f"| `{y.filepath}` | {y.line} | `{y.url_fragment}` |")
    if not r.yeti_endpoints:
        w("| (none) | | |")
    w()
    w("---")
    w()
    w('## Tests with "run" in the name')
    w()
    if r.tests_mentioning_connector_run:
        w("| File | Line | Line preview |")
        w("|------|------|--------------|")
        for filepath, line_no, preview in r.tests_mentioning_connector_run:
            w(f"| `{filepath}` | {line_no} | `{preview}` |")
    else:
        w("No `def test_...run...` patterns found under `tests/api_app/connectors_manager/`.")
    w()
    w("Just filename/grep style hits, not a real map of run() coverage.")
    w()
    w("## Random questions")
    w()
    w("Left the detailed list in maintainer_questions.md (pycti vs server, real health checks, how much CI time, etc.).")
    w()
    return "\n".join(w_lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate connector audit markdown")
    parser.add_argument("--intelowl-root", required=True, help="Path to IntelOwl repo root")
    parser.add_argument(
        "--output",
        default="reports/connector_audit_report.md",
        help="Output markdown path",
    )
    args = parser.parse_args()
    root = Path(args.intelowl_root)
    if not (root / "api_app").exists():
        print(f"Error: {root}/api_app does not exist.", file=sys.stderr)
        sys.exit(1)

    r = full_scan(root)
    md = generate_markdown(root, r)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
