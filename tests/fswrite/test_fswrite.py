"""fswrite - the write side of the file API (fswrite.c).

Create dispositions, writes and truncation, share modes, rename, copy and delete, directories, file
times, and CRT writes, in a scratch directory. Parked until F2K writes to a volume.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "fswrite",
    retake="captured on a VirtualBox shared folder: retake on a local FAT32 volume",
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_fswrite(captured, run_block):
    run_block(captured)
