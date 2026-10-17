"""threads - thread lifecycle and per-thread state (threads.c, /MT).

Creation and exit codes, suspension, priorities, scale, TLS and __declspec(thread), per-thread
last error, errno, FPU and SEH, the CRT's thread starts, and the main thread's own exits.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "threads",
    gate=True,
    masks=(
        # The binary captured reads the parameter before waiting for the routine (argument
        # evaluation order): 9 or 0 by timing. The source waits first now; drop the mask once
        # threads.exe is rebuilt and recaptured.
        "its routine ran: WAIT_OBJECT_0, parameter *",
    ),
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_threads(captured, run_block):
    run_block(captured)
