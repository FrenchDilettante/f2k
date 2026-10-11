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
#
# Every argument after the image is an expected COM1 string; the test passes
# only once all of them have appeared. With no extra arguments it checks the
# boot banner.

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

all_expected_found() {
    printf '%s\n' "$EXPECTS" | while IFS= read -r expected; do
        [ -n "$expected" ] || continue
        grep -qF -- "$expected" "$SERIAL_LOG" || return 1
    done
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
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    rm -f "$SERIAL_LOG" "$QEMU_LOG"
}
trap cleanup EXIT INT TERM

case "$IMAGE" in
    *.img) set -- -drive "file=$IMAGE,format=raw,if=ide" ;;
    *.iso) set -- -cdrom "$IMAGE" -boot d ;;
    *)     set -- -kernel "$IMAGE" ;;
esac

# -no-reboot turns a triple fault into a QEMU exit, so crashes fail fast
"$QEMU" "$@" -m 64M -display none -monitor none -net none \
    -no-reboot -serial "file:$SERIAL_LOG" >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!

ticks=0
while [ "$ticks" -lt $((BOOT_TIMEOUT * 10)) ]; do
    if all_expected_found "$@"; then
        echo "PASS: expected output received on COM1"
        exit 0
    fi
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 0.1
    ticks=$((ticks + 1))
done

# One last look, in case QEMU wrote the output just before exiting
if all_expected_found "$@"; then
    echo "PASS: expected output received on COM1"
    exit 0
fi

if kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "FAIL: expected output not found within ${BOOT_TIMEOUT}s"
else
    echo "FAIL: QEMU exited before the expected output appeared"
fi
echo "--- serial output (COM1) ---"
cat "$SERIAL_LOG"
echo "--- QEMU output ---"
cat "$QEMU_LOG"
exit 1
