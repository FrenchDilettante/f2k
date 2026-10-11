#!/bin/sh
# Compile the limine header assembly file

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_FILE="$PROJECT_DIR/boot/limine/limine_header.o"
ASM_FILE="$PROJECT_DIR/kernel/src/boot/limine_header.asm"

# Create output directory
mkdir -p "$PROJECT_DIR/boot/limine"

# Compile with NASM
echo "Compiling limine header..."
if ! command -v nasm >/dev/null 2>&1; then
    echo "ERROR: NASM not found. Install with: brew install nasm"
    exit 1
fi

nasm -f elf32 "$ASM_FILE" -o "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Limine header compiled: $OUTPUT_FILE"
else
    echo "ERROR: Failed to compile limine header"
    exit 1
fi
