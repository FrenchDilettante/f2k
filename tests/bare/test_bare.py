"""bare - the image and process contract without a C runtime (bare.c).

The image as the loader maps it, the entry point's return value as the exit code, a full 32-bit
exit code, bad buffers to WriteFile, code run from .data, and fifteen faults each ending the
process with its exception code. Gating: F2K passes every block.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks("bare", gate=True)


@pytest.mark.parametrize("captured", BLOCKS)
def test_bare(captured, run_block):
    run_block(captured)
