#!/usr/bin/env python3
"""
Create a minimal MBR (Master Boot Record) with partition table.
The MBR boots from the first partition.
"""
import sys

# MBR bootstrap code - jumps to partition boot record
# This is a minimal MBR that chains to the first partition
mbr_code = bytes.fromhex("""
FA 31 C0 8E D8 8E C0 8E D0 BC 00 7C B8 00 01 8E D8
66 8B 16 6C 07 66 81 E6 00 00 40 00 66 01 C0 66
01 E0 66 8B FC 66 81 C6 00 00 01 00 66 8B E5 66
8B D5 66 8B F0 B4 02 CD 13 72 2C B4 08 CD 15 73
1E EB 00 31 C0 8E D8 8E D0 BC 00 20 FB A0 6C 07
""")

# Partition entry for first partition (active, starts at sector 1, spans rest of disk)
# For a floppy, we use one partition
partition_entry = bytes.fromhex("""
80 01 01 00 02 00 00 00 00 00 00 00 00 00 00 00
""")

# Fill rest of partition table with zeros
partition_table = partition_entry + bytes(48)  # 4 partition entries * 16 bytes each

# MBR signature
signature = bytes.fromhex("55 AA")

# Pad to 440 bytes (MBR code + partition table)
padding = bytes(440 - len(mbr_code)) - bytes(66)  # Adjust based on actual mbr_code size

# Combine everything
mbr = mbr_code + padding + partition_table + signature

# Ensure it's exactly 512 bytes
if len(mbr) < 512:
    mbr += bytes(512 - len(mbr))
elif len(mbr) > 512:
    mbr = mbr[:512]

sys.stdout.buffer.write(mbr)
