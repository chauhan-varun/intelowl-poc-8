#!/usr/bin/env python3
"""AST scans for connector tree + related files. Stdlib only."""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiscardedReplace:
    filepath: str
    line: int
    snippet: str


@dataclass
class ConnectorClassInfo:
    filepath: str
    line: int
    name: str
    bases: list[str]
    has_health_check_override: bool


@dataclass
class YetiEndpointHit:
    filepath: str
    line: int
    url_fragment: str


@dataclass
class OpenCTINoTimeout:
    filepath: str
    line: int


@dataclass
class PyMISPTimeout:
    filepath: str
    line: int
    seconds: int


@dataclass
class EmailSenderUpdateStub:
    filepath: str
    line: int


@dataclass
class ScanResult:
    discarded_replaces: list[DiscardedReplace] = field(default_factory=list)
    abuse_submitter_imports_analyzer_exception: bool = False
    abuse_submitter_path: str | None = None
    connector_classes: list[ConnectorClassInfo] = field(default_factory=list)
    yeti_endpoints: list[YetiEndpointHit] = field(default_factory=list)
    pymisp_pin: str | None = None
    pycti_pin: str | None = None
    connector_test_py_files: int = 0
    connector_test_total_lines: int = 0
    tests_mentioning_connector_run: list[tuple[str, int, str]] = field(default_factory=list)
    opencti_no_timeout: list[OpenCTINoTimeout] = field(default_factory=list)
    pymisp_short_timeout: list[PyMISPTimeout] = field(default_factory=list)
    emailsender_update_stub: EmailSenderUpdateStub | None = None
    mockpymisp_has_get_version: bool = False


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def scan_discarded_replace(intelowl_root: Path) -> list[DiscardedReplace]:
    out: list[DiscardedReplace] = []
    connectors = intelowl_root / "api_app" / "connectors_manager" / "connectors"
    if not connectors.is_dir():
        return out

    for pyfile in sorted(connectors.glob("*.py")):
        src = _read(pyfile)
        if not src:
            continue
        try:
            tree = ast.parse(src, filename=str(pyfile))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Expr):
                continue
            v = node.value
            if not isinstance(v, ast.Call):
                continue
            func = v.func
            if not isinstance(func, ast.Attribute) or func.attr != "replace":
                continue
            line = getattr(node, "lineno", 0)
            line_text = src.splitlines()[line - 1] if 0 < line <= len(src.splitlines()) else ""
            out.append(
                DiscardedReplace(
                    filepath=str(pyfile.relative_to(intelowl_root)),
                    line=line,
                    snippet=line_text.strip(),
                )
            )
    return out


def _class_bases_names(bases: list[ast.expr]) -> list[str]:
    names = []
    for b in bases:
        if isinstance(b, ast.Name):
            names.append(b.id)
        elif isinstance(b, ast.Attribute):
            names.append(f"{ast.unparse(b)}")
        else:
            names.append(ast.unparse(b))
    return names


def _inherits_connector(bases: list[ast.expr]) -> bool:
    for b in bases:
        s = ast.unparse(b)
        if any(x in s for x in ("Connector", "EmailSender")):
            return True
    return False


def scan_connector_classes(intelowl_root: Path) -> list[ConnectorClassInfo]:
    out: list[ConnectorClassInfo] = []
    connectors = intelowl_root / "api_app" / "connectors_manager" / "connectors"
    if not connectors.is_dir():
        return out

    for pyfile in sorted(connectors.glob("*.py")):
        src = _read(pyfile)
        if not src:
            continue
        try:
            tree = ast.parse(src, filename=str(pyfile))
        except SyntaxError:
            continue

        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not _inherits_connector(node.bases):
                continue
            has_hc = any(
                isinstance(item, ast.FunctionDef) and item.name == "health_check"
                for item in node.body
            )
            rel = str(pyfile.relative_to(intelowl_root))
            out.append(
                ConnectorClassInfo(
                    filepath=rel,
                    line=node.lineno,
                    name=node.name,
                    bases=_class_bases_names(node.bases),
                    has_health_check_override=has_hc,
                )
            )
    return out


def scan_abuse_submitter(intelowl_root: Path) -> tuple[bool, str | None]:
    path = intelowl_root / "api_app" / "connectors_manager" / "connectors" / "abuse_submitter.py"
    if not path.is_file():
        return False, None
    src = _read(path)
    if not src:
        return False, str(path.relative_to(intelowl_root))
    bad = "from api_app.analyzers_manager.exceptions import AnalyzerRunException" in src
    return bad, str(path.relative_to(intelowl_root))


def scan_yeti_urls(intelowl_root: Path) -> list[YetiEndpointHit]:
    out: list[YetiEndpointHit] = []
    for rel in (
        "api_app/connectors_manager/connectors/yeti.py",
        "api_app/analyzers_manager/observable_analyzers/yeti.py",
    ):
        path = intelowl_root / rel
        if not path.is_file():
            continue
        src = _read(path)
        if not src:
            continue
        for i, line in enumerate(src.splitlines(), 1):
            if "/api/v2/" not in line:
                continue
            m = re.search(r"['\"]([^'\"]*api/v2[^'\"]*)['\"]", line)
            frag = m.group(1) if m else line.strip()[:120]
            out.append(YetiEndpointHit(filepath=rel, line=i, url_fragment=frag))
    return out


# Flag PyMISP(..., timeout=N) when N <= this (tight timeouts often lose on real instances).
PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC = 10

_PIN_RE = re.compile(r"^(pymisp|pycti)==([^\s#]+)")


def scan_requirement_pins(intelowl_root: Path) -> tuple[str | None, str | None]:
    pymisp, pycti = None, None
    for req_dir in (intelowl_root / "requirements",):
        if not req_dir.is_dir():
            continue
        for req_file in req_dir.glob("*.txt"):
            req_text = _read(req_file)
            for line in (req_text.splitlines() if req_text else []):
                m = _PIN_RE.match(line.strip())
                if not m:
                    continue
                if m.group(1) == "pymisp":
                    pymisp = m.group(2)
                elif m.group(1) == "pycti":
                    pycti = m.group(2)
    return pymisp, pycti


def _call_callee_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _kw_names(call: ast.Call) -> set[str]:
    return {k.arg for k in call.keywords if k.arg is not None}


def scan_opencti_client_no_timeout(intelowl_root: Path) -> list[OpenCTINoTimeout]:
    out: list[OpenCTINoTimeout] = []
    path = intelowl_root / "api_app" / "connectors_manager" / "connectors" / "opencti.py"
    if not path.is_file():
        return out
    src = _read(path)
    if not src:
        return out
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return out
    rel = str(path.relative_to(intelowl_root))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_callee_name(node) == "OpenCTIApiClient":
            if "timeout" not in _kw_names(node):
                out.append(OpenCTINoTimeout(filepath=rel, line=node.lineno))
    return out


def scan_pymisp_timeout(
    intelowl_root: Path,
    max_aggressive: int = PYMISP_AGGRESSIVE_TIMEOUT_MAX_SEC,
) -> list[PyMISPTimeout]:
    out: list[PyMISPTimeout] = []
    connectors = intelowl_root / "api_app" / "connectors_manager" / "connectors"
    if not connectors.is_dir():
        return out
    for pyfile in sorted(connectors.glob("*.py")):
        src = _read(pyfile)
        if not src:
            continue
        try:
            tree = ast.parse(src, filename=str(pyfile))
        except SyntaxError:
            continue
        rel = str(pyfile.relative_to(intelowl_root))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_callee_name(node) != "PyMISP":
                continue
            for kw in node.keywords:
                if kw.arg != "timeout":
                    continue
                if not isinstance(kw.value, ast.Constant):
                    continue
                raw = kw.value.value
                if type(raw) is bool:
                    continue
                if isinstance(raw, (int, float)) and raw <= max_aggressive:
                    sec = int(raw) if isinstance(raw, int) or raw == int(raw) else int(round(raw))
                    out.append(PyMISPTimeout(filepath=rel, line=node.lineno, seconds=sec))
    return out


def scan_emailsender_update_stub(intelowl_root: Path) -> EmailSenderUpdateStub | None:
    path = intelowl_root / "api_app" / "connectors_manager" / "connectors" / "email_sender.py"
    if not path.is_file():
        return None
    src = _read(path)
    if not src:
        return None
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return None
    rel = str(path.relative_to(intelowl_root))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "EmailSender":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef) or item.name != "update":
                continue
            if len(item.body) == 1 and isinstance(item.body[0], ast.Pass):
                return EmailSenderUpdateStub(filepath=rel, line=item.lineno)
    return None


def scan_mockpymisp_get_version(intelowl_root: Path) -> bool:
    path = intelowl_root / "api_app" / "connectors_manager" / "connectors" / "misp.py"
    if not path.is_file():
        return False
    src = _read(path)
    if not src:
        return False
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return False
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "MockPyMISP":
            continue
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "get_version":
                return True
            if isinstance(item, ast.AsyncFunctionDef) and item.name == "get_version":
                return True
    return False


def scan_connector_tests(intelowl_root: Path) -> tuple[int, int, list[tuple[str, int, str]]]:
    tests_root = intelowl_root / "tests" / "api_app" / "connectors_manager"
    if not tests_root.is_dir():
        return 0, 0, []

    py_files = [p for p in tests_root.rglob("*.py") if "__pycache__" not in p.parts]
    total_lines = 0
    for p in py_files:
        src = _read(p)
        if src:
            total_lines += len(src.splitlines())

    run_hits: list[tuple[str, int, str]] = []
    for p in py_files:
        src = _read(p)
        if not src:
            continue
        rel = str(p.relative_to(intelowl_root))
        for i, line in enumerate(src.splitlines(), 1):
            if "def test_" in line and "run" in line.lower():
                run_hits.append((rel, i, line.strip()[:100]))

    seen = set()
    deduped = []
    for item in run_hits:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    return len(py_files), total_lines, deduped[:30]


def full_scan(intelowl_root: Path) -> ScanResult:
    root = intelowl_root.resolve()
    r = ScanResult()
    r.discarded_replaces = scan_discarded_replace(root)
    r.connector_classes = scan_connector_classes(root)
    imp, path = scan_abuse_submitter(root)
    r.abuse_submitter_imports_analyzer_exception = imp
    r.abuse_submitter_path = path
    r.yeti_endpoints = scan_yeti_urls(root)
    r.pymisp_pin, r.pycti_pin = scan_requirement_pins(root)
    r.connector_test_py_files, r.connector_test_total_lines, r.tests_mentioning_connector_run = (
        scan_connector_tests(root)
    )
    r.opencti_no_timeout = scan_opencti_client_no_timeout(root)
    r.pymisp_short_timeout = scan_pymisp_timeout(root)
    r.emailsender_update_stub = scan_emailsender_update_stub(root)
    r.mockpymisp_has_get_version = scan_mockpymisp_get_version(root)
    return r


def format_table_discarded(items: list[DiscardedReplace]) -> str:
    if not items:
        return "| (none) |\n|--------|\n"
    lines = ["| File | Line | Snippet |", "|------|------|---------|"]
    for x in items:
        lines.append(f"| `{x.filepath}` | {x.line} | `{x.snippet[:80]}` |")
    return "\n".join(lines) + "\n"


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: scan_connectors.py /path/to/IntelOwl", file=sys.stderr)
        sys.exit(2)
    root = Path(sys.argv[1])
    r = full_scan(root)
    print("=== Discarded .replace() (connectors/) ===")
    for d in r.discarded_replaces:
        print(f"  {d.filepath}:{d.line}  {d.snippet}")
    print("\n=== Connector classes ===")
    for c in r.connector_classes:
        hc = "yes" if c.has_health_check_override else "no"
        print(f"  {c.name} @ {c.filepath}:{c.line}  health_check override: {hc}")
    print("\n=== Pins ===", r.pymisp_pin, r.pycti_pin)
    print("=== OpenCTI OpenCTIApiClient without timeout kw ===")
    for x in r.opencti_no_timeout:
        print(f"  {x.filepath}:{x.line}")
    print("=== PyMISP short timeout ===")
    for x in r.pymisp_short_timeout:
        print(f"  {x.filepath}:{x.line}  timeout={x.seconds}s")
    print("=== EmailSender.update stub ===")
    if r.emailsender_update_stub:
        print(f"  {r.emailsender_update_stub.filepath}:{r.emailsender_update_stub.line}")
    else:
        print("  (none)")
    print("=== MockPyMISP.get_version ===", "yes" if r.mockpymisp_has_get_version else "MISSING")
    print("=== Yeti URL fragments ===")
    for y in r.yeti_endpoints:
        print(f"  {y.filepath}:{y.line}  {y.url_fragment}")
    print(
        f"=== Connector tests: {r.connector_test_py_files} files, {r.connector_test_total_lines} lines ==="
    )


if __name__ == "__main__":
    main()
