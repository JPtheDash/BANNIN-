#!/usr/bin/env bash
# Builds BANNIN and its dashboard, then runs the whole tool as one
# process: `bannin serve` serves the built dashboard and the API on the
# same port, and this script opens it in your browser. Ctrl+C stops it.
#
# The dashboard is built once (static files) rather than run via a
# separate dev server, so Node is only needed at build time, there's a
# single origin/port, and nothing has to be wired between two servers.
# (For active frontend development with hot-reload, run `cd web && npm
# run dev` instead — that's the dev workflow, this is the run-it one.)
#
# Usage:
#   ./scripts/start-web.sh                       # uses ./bannin.yaml (created from the example if missing)
#   ./scripts/start-web.sh --config other.yaml    # use a specific config
#
# Requires Go 1.24+ and Node to already be installed (this script
# doesn't install them — see scripts/install-tools.sh for the scanner
# CLIs, and the README for Go/Node itself).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

log()  { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

CONFIG="bannin.yaml"
if [ "${1:-}" = "--config" ]; then
  [ $# -ge 2 ] || fail "--config requires a path"
  CONFIG="$2"
fi

command -v go   >/dev/null 2>&1 || fail "go not found on PATH — install Go 1.24+ (https://go.dev/dl/) first"
command -v node >/dev/null 2>&1 || fail "node not found on PATH — install Node (https://nodejs.org/) first"
command -v npm  >/dev/null 2>&1 || fail "npm not found on PATH — install Node (https://nodejs.org/) first"

if [ ! -f "$CONFIG" ]; then
  log "no $CONFIG found — creating one from configs/bannin.example.yaml"
  cp configs/bannin.example.yaml "$CONFIG"
  echo "  Edit $CONFIG to change the scan target or which plugins run."
fi

log "building bannin"
go build -o bin/bannin ./cmd/bannin

log "building the dashboard"
if [ ! -d web/node_modules ]; then
  echo "  installing frontend dependencies (first run only)"
  (cd web && npm install)
fi
(cd web && npm run build)

log "starting bannin (serves the dashboard + API on one port)"
./bin/bannin serve --config "$CONFIG" &
SERVE_PID=$!

cleanup() {
  log "stopping bannin (pid $SERVE_PID)"
  kill "$SERVE_PID" 2>/dev/null || true
  wait "$SERVE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

log "waiting for BANNIN to come up"
HOST="$(grep -A2 '^server:' "$CONFIG" | grep 'host:' | awk '{print $2}' | tr -d '"' || true)"
PORT="$(grep -A2 '^server:' "$CONFIG" | grep 'port:' | awk '{print $2}' || true)"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
URL="http://${HOST}:${PORT}"
for _ in $(seq 1 30); do
  if curl -sf "${URL}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
if ! curl -sf "${URL}/healthz" >/dev/null 2>&1; then
  fail "bannin didn't come up on ${URL} — check its output above"
fi

log "BANNIN is running — opening ${URL}"
echo "  Press Ctrl+C to stop."
case "$(uname -s)" in
  Darwin) open "$URL" 2>/dev/null || true ;;
  Linux)  command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 || true ;;
esac

# Keep the script in the foreground so Ctrl+C reaches the trap and the
# server keeps running until then.
wait "$SERVE_PID"
