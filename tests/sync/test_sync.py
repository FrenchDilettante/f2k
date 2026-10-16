"""sync - synchronization objects and waits (sync.c, /MT).

Events, semaphores, mutexes, multi-object waits, user APCs, critical sections, interlocked
operations, handle duplication and closing, and the original pingpong.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks("sync")


@pytest.mark.parametrize("captured", BLOCKS)
def test_sync(captured, run_block):
    run_block(captured)
