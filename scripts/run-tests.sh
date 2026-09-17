#!/usr/bin/env bash
# DevSentinel - run both test suites (macOS / Linux)
cd "$(dirname "$0")/.."

echo "=== 1/2  Python tests ==="
cd ai-engine
[ -d ".venv" ] && source .venv/bin/activate
DEVSENTINEL_SKIP_MODEL=1 python -m pytest tests/ -v
cd ..

echo
echo "=== 2/2  Java tests ==="
mvn clean test
