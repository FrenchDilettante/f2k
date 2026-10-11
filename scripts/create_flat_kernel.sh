#!/bin/sh
# Create a flat binary kernel with Limine header at the beginning
# This creates a raw binary that Limine can boot from ISO

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_ELF="$PROJECT_DIR/target/x86-f2k-limine/debug/f2k-kernel"
KERNEL_FLAT="$PROJECT_DIR/target/x86-f2k-limine/debug/f2k-kernel-flat.bin"
LIMINE_HEADER_BIN="$PROJECT_DIR/kernel/src/boot/limine_header.bin"

if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel ELF not found: $KERNEL_ELF"
    echo "Please run 'make kernel-limine' first"
    exit 1
fi

if [ ! -f "$LIMINE_HEADER_BIN" ]; then
    echo "ERROR: Limine header binary not found: $LIMINE_HEADER_BIN"
    exit 1
fi

echo "Creating flat kernel binary with Limine header..."

# Extract the text and data sections from the ELF (skip .limine_requests which is already in the header)
# We need to extract all the actual code and data, but skip the ELF headers
x86_64-elf-objcopy -O binary --only-section=.text --only-section=.rodata \
    --only-section=.data "$KERNEL_ELF" /tmp/kernel_code.bin

# Concatenate: Limine header + kernel code
cat "$LIMINE_HEADER_BIN" /tmp/kernel_code.bin > "$KERNEL_FLAT"

echo "Flat kernel created: $KERNEL_FLAT"
echo "Size: $(stat -f %z "$KERNEL_FLAT") bytes"

# Cleanup
rm -f /tmp/kernel_code.bin
