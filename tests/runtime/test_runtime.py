"""runtime - the process environment a C program starts into (runtime.c).

argv, version, modules, the TEB and PEB, last-error semantics, the environment, code pages and
string conversion, CRT formatting, structured exception handling, and the CRT's exit path.

Gating: F2K passes every block (the hand-captured `console` block too: F2K's console is the
interactive one).

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "runtime",
    gate=True,
    masks=(
        # The breakpoint record's second parameter is a stack address.
        "int 3: handled yes code 0x80000003 flags 0 params 3 info 0 *",
    ),
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_runtime(captured, run_block):
    run_block(captured)
