#!/usr/bin/env python3
"""Optional live PyMISP.get_version check; skips if pymisp missing."""

from __future__ import annotations

import sys
from typing import Any


def misp_health_check_prototype(url: str, api_key: str, ssl_verify: bool = True) -> dict[str, Any]:
    try:
        from pymisp import PyMISP
    except ImportError:
        return {
            "status": "skipped",
            "detail": "Install pymisp in this venv to run a live check: uv pip install pymisp",
        }

    try:
        misp = PyMISP(url, api_key, ssl_verify, debug=False, timeout=10)
        version = misp.get_version()
        return {"status": "healthy", "version": version}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


def main() -> None:
    if len(sys.argv) >= 3:
        url, key = sys.argv[1], sys.argv[2]
        ssl = sys.argv[3].lower() in ("1", "true", "yes") if len(sys.argv) > 3 else True
        print(misp_health_check_prototype(url, key, ssl_verify=ssl))
    else:
        print("Usage (optional live test): health_check_prototype.py <misp_url> <api_key> [ssl_verify true|false]")
        print("Dry run (no pymisp required):")
        print(misp_health_check_prototype("https://example.invalid", "test-key"))


if __name__ == "__main__":
    main()
