#!/bin/sh
# Boot smoke test.
#
# Boots the kernel in QEMU and passes once the boot banner appears on COM1.
# A kernel ELF is loaded with QEMU's built-in Multiboot 1 loader (-kernel);
# a .img disk or .iso image boots through Limine. Because the banner is only
# printed after kmain() has validated the Multiboot magic, a pass proves:
#   - the loader accepted the kernel's Multiboot header,
#   - _start set up a stack and reached Rust,
#   - serial output works.
#
# Usage: scripts/test-boot.sh [kernel-elf | disk.img | cdrom.iso] [expected ...]
# Env:   QEMU (default qemu-system-i386), BOOT_TIMEOUT seconds (default 10)
#        BOOT_ORDERED=1     the expected strings must match on successive
#                           lines, in argument order (each on its own line)
#        BOOT_FORBID        newline-separated strings that fail the test as
#                           soon as any appears (e.g. "KERNEL PANIC")
#        BOOT_CONTIGUOUS    newline-separated strings that must match on
#                           consecutive lines, in order (an uninterrupted
#                           block), in addition to the expected strings
#
# Every argument after the image is an expected COM1 string (a substring of
# a line); the test passes only once all of them have appeared. With no extra
# arguments it checks the boot banner.

set -u

IMAGE="${1:-target/x86-f2k/debug/f2k-kernel}"
if [ "$#" -gt 0 ]; then shift; fi
if [ "$#" -eq 0 ]; then
    set -- "F2K Booted Successfully"
fi
QEMU="${QEMU:-qemu-system-i386}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-10}"

# The case block further down reuses "$@" for the QEMU arguments, so
# capture the expected strings first (newline-separated; the strings we
# pass contain no newlines).
EXPECTS=""
for expected in "$@"; do
    EXPECTS="$EXPECTS$expected
"
done
BOOT_ORDERED="${BOOT_ORDERED:-0}"
BOOT_FORBID="${BOOT_FORBID:-}"
BOOT_CONTIGUOUS="${BOOT_CONTIGUOUS:-}"

# One awk pass over the log answers every check. The lists travel as files
# (one string per line) so no string is reinterpreted by the shell or awk.
# Exit 0: everything matched; 1: not (yet); 2: a forbidden string appeared.
match_log() {
    awk -v ordered="$BOOT_ORDERED" \
        -v expects_file="$EXPECTS_FILE" \
        -v forbid_file="$FORBID_FILE" \
        -v block_file="$BLOCK_FILE" '
        function load(file, list,    line, n) {
            n = 0
            while ((getline line < file) > 0) if (line != "") list[n++] = line
            close(file)
            return n
        }
        BEGIN {
            ne = load(expects_file, e); nf = load(forbid_file, f); nb = load(block_file, b)
            next_e = 0; next_b = 0
            for (i = 0; i < ne; i++) seen[i] = 0
        }
        {
            for (i = 0; i < nf; i++) if (index($0, f[i]) > 0) { forbidden = f[i]; exit 2 }
            if (ordered) {
                if (next_e < ne && index($0, e[next_e]) > 0) next_e++
            } else {
                for (i = 0; i < ne; i++) if (!seen[i] && index($0, e[i]) > 0) seen[i] = 1
            }
            if (next_b < nb) {
                if (index($0, b[next_b]) > 0) next_b++
                else next_b = (index($0, b[0]) > 0) ? 1 : 0
            }
        }
        END {
            if (forbidden != "") { print "forbidden output: " forbidden > "/dev/stderr"; exit 2 }
            if (ordered) { if (next_e < ne) exit 1 }
            else for (i = 0; i < ne; i++) if (!seen[i]) exit 1
            if (next_b < nb) exit 1
            exit 0
        }' "$SERIAL_LOG"
}

if [ ! -f "$IMAGE" ]; then
    echo "FAIL: image not found: $IMAGE (run 'make kernel' or 'make disk' first)"
    exit 1
fi
if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "FAIL: $QEMU not found"
    exit 1
fi

SERIAL_LOG="$(mktemp)"
QEMU_LOG="$(mktemp)"
EXPECTS_FILE="$(mktemp)"
FORBID_FILE="$(mktemp)"
BLOCK_FILE="$(mktemp)"
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    rm -f "$SERIAL_LOG" "$QEMU_LOG" "$EXPECTS_FILE" "$FORBID_FILE" "$BLOCK_FILE"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
printf '%s' "$EXPECTS" >"$EXPECTS_FILE"
printf '%s\n' "$BOOT_FORBID" >"$FORBID_FILE"
printf '%s\n' "$BOOT_CONTIGUOUS" >"$BLOCK_FILE"

report_failure() {
    echo "$1"
    echo "--- serial output (COM1) ---"
    cat "$SERIAL_LOG"
    echo "--- QEMU output ---"
    cat "$QEMU_LOG"
    exit 1
}

case "$IMAGE" in
    *.img) set -- -drive "file=$IMAGE,format=raw,if=ide" ;;
    *.iso) set -- -cdrom "$IMAGE" -boot d ;;
    *)     set -- -kernel "$IMAGE" ;;
esac

# -no-reboot turns a triple fault into a QEMU exit, so crashes fail fast
"$QEMU" "$@" -m 64M -display none -monitor none -net none \
    -no-reboot -serial "file:$SERIAL_LOG" >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!

check() {
    match_log
    case $? in
        0)
            echo "PASS: expected output received on COM1"
            exit 0
            ;;
        2) report_failure "FAIL: forbidden output appeared on COM1" ;;
    esac
}

ticks=0
while [ "$ticks" -lt $((BOOT_TIMEOUT * 10)) ]; do
    check
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 0.1
    ticks=$((ticks + 1))
done

# One last look, in case QEMU wrote the output just before exiting
check

if kill -0 "$QEMU_PID" 2>/dev/null; then
    report_failure "FAIL: expected output not found within ${BOOT_TIMEOUT}s"
else
    report_failure "FAIL: QEMU exited before the expected output appeared"
fi
