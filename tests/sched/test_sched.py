"""sched - time and scheduling, as verdicts (sched.c, /MT).

Sleeps and timed waits in bands, the clocks, waitable timers, round-robin, preemption, yielding, the
wake boost, suspension, and the starvation boost. The starvation section alone takes about six
seconds, hence the longer timeout.

Gating: F2K passes every block but `yield` (see its pending reason).

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks(
    "sched",
    gate=True,
    pending={
        # On an otherwise idle processor the BELOW_NORMAL thread runs while its NORMAL creator
        # sleeps, and F2K prints "yes". The capture's "no" matches the masked SwitchToThread line
        # just above it: the capture machine had another process's thread ready on the pinned
        # CPU, which outranks the BELOW_NORMAL one. Waiting on a recapture (or a mask) to settle
        # which the block should pin.
        "yield": "capture shows a busy capture CPU: 'Sleep(10) does: no' (F2K, idle: yes)",
    },
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
