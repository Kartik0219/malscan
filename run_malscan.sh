#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  malscan launcher for macOS / Linux (runs from source -> no Gatekeeper block)
#  Usage:  ./run_malscan.sh
# ---------------------------------------------------------------------------
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

echo "Installing/refreshing dependencies..."
"$PY" -m pip install -r "$DIR/requirements.txt" flask waitress

echo
echo "Starting malscan dashboard at http://127.0.0.1:8080"
echo "Leave this window open while you use it; press Ctrl+C to quit."
echo
exec "$PY" "$DIR/serve.py"
