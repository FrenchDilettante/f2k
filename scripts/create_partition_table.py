#!/usr/bin/env python3
"""
Create a simple MBR partition table for a disk image.
Creates one active FAT32 (LBA) partition from start_sector to the end of the disk.

The default start of 2048 (1 MiB) leaves a gap after the MBR, which is where
`limine bios-install` puts Limine's stage 2.
"""
import sys
import struct

if len(sys.argv) not in (3, 4):
    print(f"Usage: {sys.argv[0]} <disk_image> <total_sectors> [start_sector=2048]")
    sys.exit(1)

image_path = sys.argv[1]
total_sectors = int(sys.argv[2])
partition_start_sector = int(sys.argv[3]) if len(sys.argv) == 4 else 2048
partition_num_sectors = total_sectors - partition_start_sector

if partition_num_sectors <= 0:
    print(f"ERROR: disk of {total_sectors} sectors is too small for a partition at {partition_start_sector}")
    sys.exit(1)


def lba_to_chs(lba):
    """Encode an LBA as MBR CHS bytes (255 heads, 63 sectors/track geometry).

    Addresses beyond CHS range use the conventional 1023/254/63 marker.
    """
    heads, sectors = 255, 63
    cylinder = lba // (heads * sectors)
    if cylinder > 1023:
        return bytes([0xFE, 0xFF, 0xFF])
    head = (lba // sectors) % heads
    sector = (lba % sectors) + 1
    return bytes([head, ((cylinder >> 2) & 0xC0) | sector, cylinder & 0xFF])


# Read the MBR (first 512 bytes)
with open(image_path, 'rb+') as f:
    mbr = f.read(512)

    # Partition entry format (16 bytes):
    # Byte 0: Boot flag (0x80 = bootable, 0x00 = not)
    # Bytes 1-3: CHS start
    # Byte 4: Partition type (0x0C = FAT32 LBA)
    # Bytes 5-7: CHS end
    # Bytes 8-11: LBA start (4 bytes, little-endian)
    # Bytes 12-15: Number of sectors (4 bytes, little-endian)
    boot_flag = 0x80  # Bootable
    partition_type = 0x0C  # FAT32 LBA

    partition_entry = struct.pack('<B3sB3sII',
                                  boot_flag,
                                  lba_to_chs(partition_start_sector),
                                  partition_type,
                                  lba_to_chs(total_sectors - 1),
                                  partition_start_sector,
                                  partition_num_sectors)

    # Replace partition table in MBR (offset 0x1BE), keep the boot code area
    new_mbr = mbr[:0x1BE] + partition_entry + bytes(48) + bytes([0x55, 0xAA])

    # Write back the new MBR
    f.seek(0)
    f.write(new_mbr)

    print(f"Created partition table in {image_path}")
    print(f"Partition 1: type=0x{partition_type:02X}, start={partition_start_sector}, sectors={partition_num_sectors}")
