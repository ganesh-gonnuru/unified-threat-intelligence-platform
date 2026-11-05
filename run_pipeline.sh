#!/bin/bash

PROJECT_DIR="$HOME/misp-aggregator"
LOCK_FILE="$PROJECT_DIR/pipeline.lock"

cd "$PROJECT_DIR" || exit 1

/usr/bin/flock -n "$LOCK_FILE" \
    "$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/main.py"

STATUS=$?

if [ "$STATUS" -ne 0 ]; then
    echo "Pipeline did not complete successfully. Exit code: $STATUS"
fi

exit "$STATUS"
