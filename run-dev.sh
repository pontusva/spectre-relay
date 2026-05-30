#!/usr/bin/env bash
#
# run-dev.sh — start the Spectre relay in DEV mode (no TLS) for local
# two-device testing. See ../spectre/SEALED_SENDER_TEST.md for the full
# end-to-end checklist.
#
# DEV ONLY: SPECTRE_DEV=true disables the production TLS requirement. NEVER use
# this script for a deployed relay — see the production launch in
# SPECTRE_DEVLOG.md (real certs via SPECTRE_TLS_CERT / SPECTRE_TLS_KEY).
#
# Every setting below is overridable from the environment, e.g.:
#   SPECTRE_LISTEN_ADDR=":9000" ./run-dev.sh
#
set -euo pipefail

# Resolve paths relative to this script so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "error: Go toolchain not found on PATH. Install Go, then re-run." >&2
  exit 1
fi

# Dev data dir for the encrypted queue / prekey store / CA key. Gitignored.
DATA_DIR="${SPECTRE_DATA_DIR:-./data}"
mkdir -p "$DATA_DIR"

export SPECTRE_DEV="${SPECTRE_DEV:-true}"
export SPECTRE_LISTEN_ADDR="${SPECTRE_LISTEN_ADDR:-:8080}"
export SPECTRE_QUEUE_PATH="${SPECTRE_QUEUE_PATH:-$DATA_DIR/offline_queue.enc}"
export SPECTRE_PREKEY_PATH="${SPECTRE_PREKEY_PATH:-$DATA_DIR/prekeys.enc}"
export SPECTRE_SEALED_CA_PATH="${SPECTRE_SEALED_CA_PATH:-$DATA_DIR/sealed_ca.key}"

echo "Starting Spectre relay (DEV) on ${SPECTRE_LISTEN_ADDR}"
echo "  data dir:  ${DATA_DIR}"
echo "  ws url:    ws://localhost${SPECTRE_LISTEN_ADDR}/ws"
echo "  sealed-ca: http://localhost${SPECTRE_LISTEN_ADDR}/sealed-ca"
echo "Point the app at it with:"
echo "  flutter run -d linux --dart-define=SPECTRE_RELAY_URL=ws://localhost${SPECTRE_LISTEN_ADDR}/ws"
echo

# exec so signals (Ctrl-C / SIGTERM) reach the relay for its graceful drain.
exec go run .
