#!/usr/bin/env python3
"""Toy OpenCTI error strings; not wired to IntelOwl."""

from __future__ import annotations


def generic_opencti_error() -> str:
    return "OpenCTI API is not reachable"


def improved_opencti_error(
    pycti_version: str,
    exc_message: str,
) -> str:
    if "Unknown type" in exc_message or "ThreatActorsFiltering" in exc_message:
        return (
            f"pycti {pycti_version} received an unexpected GraphQL type from your OpenCTI server. "
            "Your OpenCTI platform version may not match the bundled pycti — check compatibility "
            "between IntelOwl's pycti pin and the server version."
        )
    return f"OpenCTI request failed ({pycti_version}): {exc_message}"


def main() -> None:
    sample_exc = "Unknown type 'ThreatActorsFiltering'"
    print("Generic:")
    print(" ", generic_opencti_error())
    print()
    print("Improved (example):")
    print(" ", improved_opencti_error("6.8.8", sample_exc))


if __name__ == "__main__":
    main()
