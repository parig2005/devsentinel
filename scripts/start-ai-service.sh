#!/usr/bin/env bash
# DevSentinel - start the Python AI service (macOS / Linux)
set -e
cd "$(dirname "$0")/../ai-engine"

if [ ! -d ".venv" ]; then
    echo "[setup] Creating virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    # CPU-only torch is a far smaller download than the default CUDA build
    pip install torch --index-url https://download.pytorch.org/whl/cpu
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

echo "[info] Starting on http://localhost:8000"
echo "[info] Set DEVSENTINEL_SKIP_MODEL=1 to skip the ~500 MB model download."
exec uvicorn main:app --host 127.0.0.1 --port 8000
