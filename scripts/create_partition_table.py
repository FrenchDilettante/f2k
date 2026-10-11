#!/usr/bin/env python3
"""
Create a simple MBR partition table for a disk image.
Creates one partition spanning the entire disk (except MBR).
"""
import sys
import struct

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <disk_image> <total_sectors>")
    sys.exit(1)

image_path = sys.argv[1]
total_sectors = int(sys.argv[2])

# Read the MBR (first 512 bytes)
with open(image_path, 'rb+') as f:
    mbr = f.read(512)
    
    # Create a partition entry for partition 1
    # Bootable (0x80), starts at sector 1 (after MBR), spans total_sectors - 1
    # Partition type: 0x0C (FAT32 LBA) or 0x0B (FAT32 CHS) or 0x06 (FAT16)
    # We'll use 0x0C (FAT32 LBA)
    
    partition_start_sector = 1
    partition_num_sectors = total_sectors - 1
    
    # Partition entry format (16 bytes):
    # Byte 0: Boot flag (0x80 = bootable, 0x00 = not)
    # Bytes 1-3: CHS start (we'll use 0x00 0x01 0x00 for sector 1)
    # Byte 4: Partition type (0x0C for FAT32 LBA)
    # Bytes 5-7: CHS end (we'll use 0xFE 0xFF 0xFF for last sector)
    # Bytes 8-11: LBA start (4 bytes, little-endian)
    # Bytes 12-15: Number of sectors (4 bytes, little-endian)
    
    boot_flag = 0x80  # Bootable
    partition_type = 0x0C  # FAT32 LBA
    
    # CHS start for sector 1: cylinder 0, head 0, sector 1 = 0x00 0x01 0x00
    chs_start = struct.pack('<BBB', 0x00, 0x01, 0x00)
    
    # CHS end: we'll use the maximum (0xFE, 0xFF, 0xFF)
    chs_end = struct.pack('<BBB', 0xFE, 0xFF, 0xFF)
    
    # LBA start sector
    lba_start = struct.pack('<I', partition_start_sector)
    
    # Number of sectors
    num_sectors = struct.pack('<I', partition_num_sectors)
    
    # Build partition entry
    partition_entry = struct.pack('<B3sB3sII',
                                   boot_flag,
                                   chs_start,
                                   partition_type,
                                   chs_end,
                                   partition_start_sector,
                                   partition_num_sectors)
    
    # Replace partition table in MBR (offset 0x1BE)
    new_mbr = mbr[:0x1BE] + partition_entry + bytes(48) + bytes([0x55, 0xAA])
    
    # Write back the new MBR
    f.seek(0)
    f.write(new_mbr)
    
    print(f"Created partition table in {image_path}")
    print(f"Partition 1: type=0x{partition_type:02X}, start={partition_start_sector}, sectors={partition_num_sectors}")
