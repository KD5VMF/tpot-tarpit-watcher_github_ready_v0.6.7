#!/usr/bin/env bash
set -euo pipefail

# Launcher for TAR-PIT Watcher
# - Runs as root so conntrack reads work without prompts.
# - Sets TERM to a 256-color capable value (helps themes).
#
# Usage:
#   ~/Tar-Start.sh
#
export TERM="${TERM:-xterm-256color}"
export PYTHONWARNINGS="ignore::DeprecationWarning"

TPOT_DIR="${TPOT_DIR:-$HOME/tpotce}"
PY="$TPOT_DIR/tarpit_watch.py"

if [[ ! -f "$PY" ]]; then
  echo "ERROR: $PY not found."
  echo "Copy tarpit_watch.py into $TPOT_DIR first (or set TPOT_DIR)."
  exit 1
fi

exec sudo -E python3 "$PY"
