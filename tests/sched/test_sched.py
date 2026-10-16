"""sched - time and scheduling, as verdicts (sched.c, /MT).

Sleeps and timed waits in bands, the clocks, waitable timers, round-robin, preemption, yielding, the
wake boost, suspension, and the starvation boost. The starvation section alone takes about six
seconds, hence the longer timeout.

One test per block of the real-machine capture, output.txt (see tests/README.md).
"""
import pytest

from f2kboot import blocks


BLOCKS = blocks("sched", timeout=30)


@pytest.mark.parametrize("captured", BLOCKS)
def test_sched(captured, run_block):
    run_block(captured)
