"""limine - corpus blocks booted through Limine: the disk itself, its loader handing the kernel the
block's command line (Limine's `cmdline`), instead of QEMU's Multiboot loader (`-kernel`,
`-append`), which every other corpus boot uses.

These are the sectioned successors of the single-path smokes' Limine (`-disk`) variants in
tests/kernel/test_kernel.py (pingpong, sleep, spin, suspend, respawn and fileio), which retired as these
passed, plus the command line's own path through a real loader (`runtime args`) and the loader's
memory map (`memory sysinfo`). Each block compares against the same capture, with the same declaration, as its Multiboot
run in tests/<fixture>/test_<fixture>.py.

    uv run pytest tests/test_limine.py
"""
from __future__ import annotations

import pytest

import f2kboot

# (fixture, section): the Limine runs, by the old smoke each replaces.
LIMINE_BLOCKS = (
    ("sync", "pingpong"),  # pingpong
    ("sched", "sleep"),  # sleep
    ("sched", "rr"),  # spin
    ("sched", "preempt"),  # spin
    ("threads", "suspend"),  # suspend
    ("threads", "scale"),  # respawn
    ("files", "read"),  # fileio
    ("runtime", "args"),  # the command line through a real loader
    ("memory", "sysinfo"),  # the loader's memory map
)


def limine_params() -> list:
    params = []
    for fixture, section in LIMINE_BLOCKS:
        # By the section's name, its arguments aside (runtime's args block carries some).
        found = [p for p in f2kboot.corpus_params(fixture)
                 if p.values[0].block.section.split(" ", 1)[0] == section]
        assert len(found) == 1, f"{fixture} has no single captured block {section!r}"
        param = found[0]
        params.append(pytest.param(*param.values, id=f"{fixture}-{section}",
                                   marks=list(param.marks) + [pytest.mark.disk]))
    return params


@pytest.mark.parametrize("captured", limine_params())
def test_limine(captured, run_block):
    """The block through the Limine boot path: the same output and exit code as its capture."""
    run_block(captured, image="disk")
