"""memory - allocation, address space, and stacks (memory.c).

The C runtime heap the way programs use it, the Win32 heaps, Local/Global memory, the virtual
memory API and its protections, the image's own sections, paging-file mappings, and stacks.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "memory",
    gate=True,
    masks=(
        # Free regions run to the next allocation, wherever the system put it.
        "released: state 0x10000 protect 0x1 type 0x0 region * allocprotect 0x0",
        "past the image end: state 0x10000 protect 0x1 type 0x0 region * allocprotect 0x0",
    ),
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_memory(captured, run_block):
    run_block(captured)
