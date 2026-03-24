#!/usr/bin/env bash
# Usage: scripts/smoke_test.sh /path/to/IntelOwl
set -euo pipefail

INTELOWL_ROOT="${1:?Usage: $0 /path/to/IntelOwl}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT="$PROJECT_DIR/reports/connector_audit_report.md"

if [ ! -d "$INTELOWL_ROOT/api_app" ]; then
  echo "missing $INTELOWL_ROOT/api_app" >&2
  exit 1
fi

uv run "$SCRIPT_DIR/scan_connectors.py" "$INTELOWL_ROOT" >/dev/null
uv run "$SCRIPT_DIR/generate_connector_report.py" --intelowl-root "$INTELOWL_ROOT" --output "$REPORT"
test -f "$REPORT"

uv run "$SCRIPT_DIR/health_check_prototype.py" >/dev/null
uv run "$SCRIPT_DIR/error_message_prototype.py" | grep -q Improved

grep -q "## Summary" "$REPORT" && grep -q "## Connector classes" "$REPORT" && grep -q "## Random questions" "$REPORT"
echo "ok"
