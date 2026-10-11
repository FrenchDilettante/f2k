#!/bin/bash
# Create a bootable disk image with limine bootloader

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

DISK_IMG="${PROJECT_DIR}/target/x86-f2k/debug/f2k-limine-disk.img"
DISK_SIZE=20480  # 10MB
LIMINE_DIR="${PROJECT_DIR}/boot/limine"
KERNEL_RAW="${PROJECT_DIR}/target/x86-f2k/debug/f2k-kernel.raw"
KERNEL_ELF="${PROJECT_DIR}/target/x86-f2k/debug/f2k-kernel"

# Check if we have the required files
echo "Checking for required files..."
for file in "${LIMINE_DIR}/limine" "${LIMINE_DIR}/limine-bios.sys" "${KERNEL_RAW}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing file: $file"
        exit 1
    fi
done

echo "Creating disk image..."
# Create empty disk image
rm -f "$DISK_IMG"
dd if=/dev/zero of="$DISK_IMG" bs=512 count=$DISK_SIZE

# Step 1: Save space for limine MBR (512 bytes)
# Step 2: Create FAT32 filesystem starting at byte 512
# But mkfs.fat wants to write to the entire device

# Instead, let's:
# 1. Install limine first (writes MBR and stage 2)
# 2. Create FAT32 filesystem (overwrites MBR, so we need to save and restore)

# Install limine first
echo "Installing limine BIOS bootloader..."
dd if=/dev/zero of="$DISK_IMG" bs=512 count=$DISK_SIZE
"${LIMINE_DIR}/limine" bios-install --force "$DISK_IMG"

# Save the first 8 sectors (4KB) which contains limine's MBR and stage 2
# Stage 2 is at offset 0x1000 = sector 8, so we need to save up to sector 7
dd if="$DISK_IMG" of=/tmp/limine_boot.bin bs=512 count=8

# Create FAT32 filesystem (this will overwrite the first sectors)
echo "Creating FAT32 filesystem..."
mkfs.fat -F 32 -n F2K "$DISK_IMG"

# Restore the first 8 sectors (limine MBR + stage 2)
echo "Restoring limine bootloader..."
dd if=/tmp/limine_boot.bin of="$DISK_IMG" conv=notrunc bs=512 count=8

# Create limine.conf
cat > /tmp/limine.conf << 'EOF'
:F2K - Fenêtre 2000
    PROTOCOL=boot
    PATH=/boot/limine/f2k-kernel
    CMDLINE=
    DRIVE=0x80
EOF

# Copy files using mtools
echo "Copying files to FAT32 partition..."

# Set up mtools config
MTOOLS_RC=$(mktemp)
cat > "$MTOOLS_RC" << EOF
drive a: file="$DISK_IMG"
EOF

export HOME=$(mktemp -d)
mkdir -p "$HOME"
cp "$MTOOLS_RC" "$HOME/.mtoolsrc"

# Create directories and copy files
mmd a:boot
mmd a:boot/limine
mcopy "${LIMINE_DIR}/limine-bios.sys" a:boot/limine/limine-bios.sys
mcopy "${KERNEL_RAW}" a:boot/limine/f2k-kernel
mcopy /tmp/limine.conf a:boot/limine/limine.conf

# Clean up
rm -f /tmp/limine_mbr.bin /tmp/limine.conf "$MTOOLS_RC"
rm -rf "$HOME"

echo ""
echo "Disk image created: $DISK_IMG"
echo ""
echo "To run in QEMU:"
echo "  qemu-system-i386 -m 256M -nographic -hda $DISK_IMG -boot a -net none"
