#!/usr/bin/env bash
set -euo pipefail

TPOT_DIR="${TPOT_DIR:-$HOME/tpotce}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_PY="$REPO_DIR/TarPit-Watcher/tarpit_watch.py"
SRC_START="$REPO_DIR/Tar-Start.sh"

usage() {
  cat <<'EOF'
TPOT TarPit Watcher installer

Usage:
  ./install.sh --deps        Install apt dependencies (conntrack, iproute2)
  ./install.sh --install     Copy watcher into ~/tpotce and create ~/Tar-Start.sh
  ./install.sh --run         Run watcher now
  ./install.sh --all         deps + install + run

Notes:
- Running the watcher requires sudo (conntrack + docker).
- You can override install target with TPOT_DIR=/path ./install.sh --install
EOF
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

install_deps() {
  echo "== Installing dependencies =="
  sudo apt-get update -y
  sudo apt-get install -y conntrack iproute2
  echo "OK"
}

do_install() {
  echo "== Installing TarPit Watcher =="
  mkdir -p "$TPOT_DIR"
  cp -f "$SRC_PY" "$TPOT_DIR/tarpit_watch.py"
  chmod +x "$TPOT_DIR/tarpit_watch.py"

  cp -f "$SRC_START" "$HOME/Tar-Start.sh"
  chmod +x "$HOME/Tar-Start.sh"

  echo "Installed:"
  echo "  $TPOT_DIR/tarpit_watch.py"
  echo "  $HOME/Tar-Start.sh"
  echo ""
  echo "Stats will be saved to:"
  echo "  $HOME/.tarpit_watch_stats.json"
  echo "  $HOME/.tarpit_watch_snapshot.txt"
}

do_run() {
  echo "== Running watcher =="
  "$HOME/Tar-Start.sh"
}

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

case "${1:-}" in
  --deps) install_deps ;;
  --install) do_install ;;
  --run) do_run ;;
  --all)
    install_deps
    do_install
    do_run
    ;;
  -h|--help) usage ;;
  *) usage; exit 2 ;;
esac
