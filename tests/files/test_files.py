"""files - the read side of the file API over files/DATA (files.c).

Path forms and errors, chunked and boundary reads, seeks, metadata, FindFirstFile listings, share
modes, CRT file I/O, read-only file mappings, and concurrent readers. Captured on a local FAT32
volume, as F2K's boot volume is.

Gating: F2K passes every block.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "files",
    gate=True,
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_files(captured, run_block):
    run_block(captured)
