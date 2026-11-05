#!/bin/bash
set -u
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$PROJECT_DIR/.venv/bin/python"
LOCK_FILE="$PROJECT_DIR/unified_tip.lock"
if [ ! -x "$PYTHON" ]; then
  echo "ERROR: Project virtual environment not found at $PYTHON" >&2
  exit 2
fi
cd "$PROJECT_DIR" || exit 2
/usr/bin/flock -n "$LOCK_FILE" "$PYTHON" "$PROJECT_DIR/unified_ingest.py"
