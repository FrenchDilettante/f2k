"""fswrite - the write side of the file API (fswrite.c).

Create dispositions, writes and truncation, share modes, rename, copy and delete, directories, file
times, and CRT writes, in a scratch directory.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks("fswrite", gate=True)


@pytest.mark.parametrize("captured", BLOCKS)
def test_fswrite(captured, run_block):
    run_block(captured)
