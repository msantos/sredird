#!/usr/bin/env bash
#
# test_rfc2217.sh: End-to-end integration test for sredird using socat and picocom
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SREDIRD="${SREDIRD:-$ROOT_DIR/sredird}"
PICOCOM="${PICOCOM:-}"
if [[ -z "$PICOCOM" ]]; then
	PICOCOM="$(command -v picocom || true)"
fi
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

install_picocom() {
	echo "picocom with RFC2217 support not found. Compiling, patching and installing..."
	local build_dir
	build_dir="$(mktemp -d /tmp/picocom_build.XXXXXX)"

	(
		set -euo pipefail
		trap 'rm -rf "$build_dir"' EXIT

		git clone -b rfc2217 https://github.com/npat-efault/picocom.git "$build_dir/picocom"

		cat <<'EOF' >"$build_dir/picocom.patch"
diff --git a/Makefile b/Makefile
index 75f3fdb..f3c344f 100644
--- a/Makefile
+++ b/Makefile
@@ -1,5 +1,5 @@
 
-VERSION = 4.0a
+VERSION = 4.0a+0.2.1
 
 #CC ?= gcc
 CPPFLAGS += -DVERSION_STR=\"$(VERSION)\"
@@ -46,9 +46,9 @@ linenoise-1.0/linenoise.o : linenoise-1.0/linenoise.c linenoise-1.0/linenoise.h
 #CPPFLAGS += -DNO_CUSTOM_BAUD
 
 ## Comment these in to enable RFC2217 support
-#CPPFLAGS += -DUSE_RFC2217
-#OBJS += tn2217.o
-#tn2217.o : tn2217.c tn2217.h tncomport.h fdio.h termint.h term.h
+CPPFLAGS += -DUSE_RFC2217
+OBJS += tn2217.o
+tn2217.o : tn2217.c tn2217.h tncomport.h fdio.h termint.h term.h
 
 ## Comment this IN to remove help strings (saves ~ 4-6 Kb).
 #CPPFLAGS += -DNO_HELP
diff --git a/tn2217.c b/tn2217.c
index d54676a..f02b836 100644
--- a/tn2217.c
+++ b/tn2217.c
@@ -129,7 +129,7 @@ struct tn2217_state {
     struct termios termios;     /* Predicted remote com port geometry */
     int modem;                  /* Predicted remote com port signals */
 
-    unsigned char cmdbuf[32];   /* IAC command accumulator */
+    unsigned char cmdbuf[255];  /* IAC command accumulator */
     unsigned char cmdbuflen;
     unsigned int cmdiac : 1;    /* 1 iff last cmdbuf ch is incomplete IAC */
EOF

		cd "$build_dir/picocom"
		patch -p1 <"../picocom.patch"
		make

		local install_dir=""
		if [[ -w "/usr/local/bin" ]]; then
			install_dir="/usr/local/bin"
		elif [[ -d "$HOME/.local/bin" && -w "$HOME/.local/bin" ]]; then
			install_dir="$HOME/.local/bin"
		elif mkdir -p "$HOME/.local/bin" 2>/dev/null && [[ -w "$HOME/.local/bin" ]]; then
			install_dir="$HOME/.local/bin"
		elif [[ -d "$HOME/bin" && -w "$HOME/bin" ]]; then
			install_dir="$HOME/bin"
		elif mkdir -p "$HOME/bin" 2>/dev/null && [[ -w "$HOME/bin" ]]; then
			install_dir="$HOME/bin"
		else
			install_dir="$ROOT_DIR"
		fi

		echo "Installing picocom to $install_dir..."
		cp picocom "$install_dir/picocom"
		chmod +x "$install_dir/picocom"
	)

	if [[ -x "/usr/local/bin/picocom" ]] && "/usr/local/bin/picocom" --help 2>&1 | grep -qi "USE_RFC2217"; then
		PICOCOM="/usr/local/bin/picocom"
	elif [[ -x "$HOME/.local/bin/picocom" ]] && "$HOME/.local/bin/picocom" --help 2>&1 | grep -qi "USE_RFC2217"; then
		PICOCOM="$HOME/.local/bin/picocom"
	elif [[ -x "$HOME/bin/picocom" ]] && "$HOME/bin/picocom" --help 2>&1 | grep -qi "USE_RFC2217"; then
		PICOCOM="$HOME/bin/picocom"
	elif [[ -x "$ROOT_DIR/picocom" ]] && "$ROOT_DIR/picocom" --help 2>&1 | grep -qi "USE_RFC2217"; then
		PICOCOM="$ROOT_DIR/picocom"
	else
		echo "ERROR: Failed to find or run installed picocom with RFC2217 support." >&2
		return 1
	fi
}

# Verify picocom is available and supports RFC 2217, if not compile and install it
if [[ -z "$PICOCOM" ]] || [[ ! -x "$PICOCOM" ]] || ! "$PICOCOM" --help 2>&1 | grep -qi "USE_RFC2217"; then
	install_picocom
fi

if [[ -z "$PICOCOM" ]] || [[ ! -x "$PICOCOM" ]]; then
	echo "ERROR: picocom is required but not installed." >&2
	exit 1
fi

if ! "$PICOCOM" --help 2>&1 | grep -qi "USE_RFC2217"; then
	echo "ERROR: picocom does not have RFC 2217 support." >&2
	exit 1
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
cat "$PEER" >"$LOG_PEER" 2>/dev/null &
CAT_PID=$!

TEST_STR="PING_FROM_PICOCOM_$$"

(
	sleep 0.3
	printf "%s\r\n" "$TEST_STR"
	sleep 0.3
	# Exit picocom with C-a C-x
	printf "\x01\x18"
) | "$PICOCOM" --telnet --baud 115200 "$ADDR,$PORT" >"$LOG_PICOCOM" 2>&1
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
	) | "$PICOCOM" --telnet --baud "$BAUD" "$ADDR,$PORT" >"$LOG_PICOCOM" 2>&1
	STATUS=$?
	if [[ $STATUS -ne 0 ]]; then
		echo "FAIL (status $STATUS)"
		exit 1
	fi
	echo "PASS"
done

echo ""
echo "All RFC 2217 tests PASSED successfully."
