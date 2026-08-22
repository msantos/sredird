#!/usr/bin/env bash
#
# test_rfc2217.sh: End-to-end integration test for sredird using socat and picocom
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SREDIRD="${SREDIRD:-$ROOT_DIR/sredird}"
PICOCOM="${PICOCOM:-$(command -v picocom || echo "/usr/bin/picocom")}"
SOCAT="${SOCAT:-$(command -v socat || echo "socat")}"
ADDR="${ADDR:-127.0.11.11}"
PORT="${PORT:-10005}"
BAUD_LIST=("9600" "19200" "38400" "57600" "115200" "230400" "460800")

# Check prerequisites
if [[ ! -x "$SREDIRD" ]]; then
    echo "sredird not found at $SREDIRD. Attempting to build..."
    (cd "$ROOT_DIR" && make)
fi

if ! command -v "$SOCAT" >/dev/null 2>&1; then
    echo "ERROR: socat is required but not installed." >&2
    exit 1
fi

if ! command -v "$PICOCOM" >/dev/null 2>&1; then
    echo "ERROR: picocom is required but not installed." >&2
    exit 1
fi

# Verify picocom supports RFC 2217
if ! "$PICOCOM" --help 2>&1 | grep -qi "USE_RFC2217"; then
    echo "WARNING: picocom might not have RFC 2217 support compiled in." >&2
fi

TMPDIR="$(mktemp -d /tmp/sredird_test.XXXXXX)"
DEV="$TMPDIR/tty_dev"
PEER="$TMPDIR/tty_peer"
LOG_SREDIRD="$TMPDIR/sredird.log"
LOG_PICOCOM="$TMPDIR/picocom.log"
LOG_PEER="$TMPDIR/peer.log"

cleanup() {
    local exit_code=$?
    # Terminate background child jobs
    kill $(jobs -p) 2>/dev/null || true
    wait $(jobs -p) 2>/dev/null || true
    if [[ $exit_code -ne 0 ]]; then
        echo "=== FAILED: Logs ==="
        if [[ -f "$LOG_SREDIRD" ]]; then
            echo "--- sredird stderr ---"
            cat "$LOG_SREDIRD"
        fi
        if [[ -f "$LOG_PICOCOM" ]]; then
            echo "--- picocom output ---"
            cat "$LOG_PICOCOM"
        fi
    fi
    rm -rf "$TMPDIR"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo "=== SRedird RFC 2217 Integration Test ==="
echo "Platform : $(uname -m) / $(uname -s) $(uname -r)"
echo "Sredird  : $SREDIRD"
echo "Picocom  : $PICOCOM"
echo "Socat    : $SOCAT"
echo "Address  : $ADDR:$PORT"
echo ""

# Start PTY pair
"$SOCAT" -lf "$TMPDIR/socat_pty.log" pty,raw,echo=0,link="$DEV" pty,raw,echo=0,link="$PEER" &
SOCAT_PTY_PID=$!

# Wait for PTY symlinks to exist
for _ in {1..30}; do
    if [[ -e "$DEV" && -e "$PEER" ]]; then
        break
    fi
    sleep 0.1
done

if [[ ! -e "$DEV" ]]; then
    echo "ERROR: Timed out waiting for PTY pair creation." >&2
    exit 1
fi

# Start TCP listener wrapping sredird with poll interval 0
"$SOCAT" -lf "$LOG_SREDIRD" TCP-LISTEN:"$PORT",bind="$ADDR",reuseaddr,fork EXEC:"$SREDIRD 7 $DEV 0",stderr &
SOCAT_TCP_PID=$!
sleep 0.5

# Test 1: Bidirectional Data Transfer at 115200 baud
echo -n "Running Test 1: Bidirectional data transfer at 115200 baud... "

# Start logging data received on peer side
cat "$PEER" > "$LOG_PEER" 2>/dev/null &
CAT_PID=$!

TEST_STR="PING_FROM_PICOCOM_$$"

(
    sleep 0.3
    printf "%s\r\n" "$TEST_STR"
    sleep 0.3
    # Exit picocom with C-a C-x
    printf "\x01\x18"
) | "$PICOCOM" --telnet --baud 115200 "$ADDR,$PORT" > "$LOG_PICOCOM" 2>&1
PICO_STATUS=$?

sleep 0.3
kill "$CAT_PID" 2>/dev/null || true
wait "$CAT_PID" 2>/dev/null || true

if [[ $PICO_STATUS -ne 0 ]]; then
    echo "FAIL (picocom exit status: $PICO_STATUS)"
    exit 1
fi

if ! grep -q "$TEST_STR" "$LOG_PEER"; then
    echo "FAIL (data string '$TEST_STR' not received on serial peer)"
    exit 1
fi
echo "PASS"

# Test 2: Baud rate negotiation across standard baud rates
for BAUD in "${BAUD_LIST[@]}"; do
    echo -n "Running Test 2: RFC 2217 negotiation at $BAUD baud... "
    (
        sleep 0.2
        printf "\x01\x18"
    ) | "$PICOCOM" --telnet --baud "$BAUD" "$ADDR,$PORT" > "$LOG_PICOCOM" 2>&1
    STATUS=$?
    if [[ $STATUS -ne 0 ]]; then
        echo "FAIL (status $STATUS)"
        exit 1
    fi
    echo "PASS"
done

echo ""
echo "All RFC 2217 tests PASSED successfully."
