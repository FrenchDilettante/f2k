"""sched - time and scheduling, as verdicts (sched.c, /MT).

Sleeps and timed waits in bands, the clocks, waitable timers, round-robin, preemption, yielding, the
wake boost, suspension, and the starvation boost. The starvation section alone takes about six
seconds, hence the longer timeout.

Gating: F2K passes every block. The `yield` block's `Sleep(10) does: yes` is the real-hardware
answer: the VirtualBox capture VM, its CPU pegged by the guest, said `no`.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "sched",
    gate=True,
    timeout=30,
    masks=(
        # SwitchToThread hands the processor to any ready thread on it, another process's
        # included: whether ours ran first varies between runs on the real machine.
        "SwitchToThread: returned 1, the new thread had run *",
    ),
)


@pytest.mark.parametrize("captured", BLOCKS)
def test_sched(captured, run_block):
    run_block(captured)
