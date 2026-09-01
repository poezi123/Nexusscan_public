#!/usr/bin/env bash
# Launch the OSINT Dashboard.
#
# The dashboard runs in the SAME Python environment as NexusScan — its
# dependencies (osint_dashboard/requirements.txt) are installed by NexusScan's
# installer (python3 install.py). There is deliberately no private virtualenv
# here: a venv hardcodes absolute interpreter paths and breaks the moment the
# project folder is moved or renamed ("Defekter Interpreter" / bad interpreter).
#
# NexusScan passes its own interpreter via the PYTHON env var; standalone users
# fall back to the system python3.
set -e
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
PORT="${1:-8000}"

if ! "$PYTHON" -c "import uvicorn, fastapi" >/dev/null 2>&1; then
  echo "[!] OSINT dashboard dependencies are missing in this Python environment."
  echo "    Install them via NexusScan's installer:   python3 install.py"
  echo "    (or manually:   $PYTHON -m pip install -r requirements.txt)"
  exit 1
fi

echo "[*] OSINT Dashboard -> http://127.0.0.1:${PORT}"
exec "$PYTHON" -m uvicorn backend.app:app --host 0.0.0.0 --port "${PORT}"
