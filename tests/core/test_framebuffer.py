"""framebuffer - the VBE graphics screen, painted by FiSH's mode set: boot FiSH running a child that
works the kernel after the mode set (`fish.exe \\CORPUS\\pipe.exe create`, the kernel through QEMU's
Multiboot loader), and the screen is read back through QMP while QEMU still runs.

FiSH's first act is the graphics mode: user32's ChangeDisplaySettingsA reaches win32k's display
service, which sets the VBE mode through the kernel's real-mode trampoline, maps the linear
framebuffer, and clears it to the desktop color, Redmond blue 0x3A6EA5. Then the child runs: pipe's
create section makes pipes (nonpaged-pool allocations, which the frames the trampoline writes must
not hold), and its threads write into them and wait on timeouts (the clock, which a real-mode window
that swallowed a tick would have stopped). Its output goes to the console, whose text screen is no
longer drawn once the mode is set.

COM1 carries the mode line and the exit-code lines (pipe's 0, which FiSH ends with), and the
teardown's frame-database audit. The screen as QEMU displays it (`screendump`, PNG) must be 640x480
and every pixel Redmond blue: the framebuffer is observably painted, and nothing else drew on it.

    uv run pytest tests/core/test_framebuffer.py
"""
from __future__ import annotations

import pytest

import f2kboot

# FiSH running pipe's create section from the corpus directory.
CMDLINE = f"{f2kboot.FISH} \\CORPUS\\pipe.exe create"


@pytest.mark.kernel
def test_fish_paints_the_framebuffer(request, builder, log_path, boot_timeout, tmp_path):
    """The mode line and the clean exit codes on COM1, and the screen a solid desktop."""
    # The screen goes to pytest's own temporary directory, which pytest clears, not one of its
    # own that every run left behind.
    png = tmp_path / "screen.png"
    log, stopped = f2kboot.boot_painting(builder([]), CMDLINE, png, log_path=log_path,
                                         timeout=boot_timeout(60.0))
    f2kboot.check_painted(log, f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}", [
        ("child process", "pipe did not end with 0"),
        ("(PIPE) exited normally (exit code=0)", "pipe did not end with 0"),
        (f2kboot.FISH_ENDED, "FiSH did not end with the child's 0"),
    ], objects=False)

    bad = f2kboot.pixels_not(f2kboot.read_screen(png), f2kboot.DESKTOP)
    assert not bad, f"{len(bad)} pixels are not the desktop color, first {bad[:5]}"
