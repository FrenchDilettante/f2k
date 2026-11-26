"""nesting - window procedures nested deep inside the kernel, and another thread's message received
inside GetMessage: nestshow.exe (userland/nestshow), each through the kernel's user-mode callbacks.

nestshow's window's WM_CREATE makes a child window of the same class, whose WM_CREATE makes the
next, 20 levels deep: each level's messages reach the procedure by a callback from inside the
CreateWindowEx of the level above, so the GUI thread's kernel stack carries all twenty at once (its
large stack, grown as the callbacks need room: gui-D slice 6). Then a thread of nestshow's own sends
the window a message while the main thread waits in GetMessage, which delivers it by callback, and
posts the message that ends the loop. The disk the tests boot leaves nestshow.exe out, so the boot
attaches a copy of it with the program added (`f2kboot.disk_with_programs`); the kernel option
`redirected` puts its standard output on COM1, as a corpus program's.

    uv run pytest tests/core/test_nesting.py
"""
from __future__ import annotations

import pytest

import f2kboot

NESTSHOW = f2kboot.BUILT_PROGRAMS / "nestshow.exe"
COMMAND_LINE = r"WINNT\system32\nestshow.exe"
DEPTH = 20
# Each level starts, makes the one below it inside its WM_CREATE, and hears back once that one's
# creation (with everything under it) is done.
EXPECTED = [
    *(f"level {level}: WM_CREATE" for level in range(1, DEPTH + 1)),
    *(f"level {level}: child made yes" for level in range(DEPTH - 1, 0, -1)),
    f"top window made yes, {DEPTH} levels",
    "WM_USER+1 wParam=7 InSendMessage=1",
    "thread: SendMessage answered 42",
    "destroyed yes",
]
TIMEOUT = 30.0


@pytest.mark.kernel
def test_procedures_nest_and_receive_by_callback(builder, log_path, boot_timeout):
    """Twenty creations nest, each inside its parent's WM_CREATE, and another thread's send is
    delivered inside GetMessage; nestshow ends with 0."""
    build = builder([])
    assert NESTSHOW.exists(), f"{NESTSHOW} is missing: `make userland` builds and copies it"
    log, stopped = f2kboot.boot_with_programs(
        build, [NESTSHOW], log_path,
        cmdline=COMMAND_LINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    lines, code = f2kboot.program_output(log)
    assert lines == EXPECTED, f"nestshow's lines differ {context}"
    assert code == 0, f"nestshow's exit code {code} {context}"
