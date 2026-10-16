"""files - the read side of the file API over files/DATA (files.c).

Path forms and errors, chunked and boundary reads, seeks, metadata, FindFirstFile listings, share
modes, CRT file I/O, read-only file mappings, and concurrent readers.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "files",
    retake="captured on a VirtualBox shared folder (no short names, no attribute bits, a "
    "remote drive) and without the .BIN data files: retake on a local FAT32 volume",
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_files(captured, run_block):
    run_block(captured)
