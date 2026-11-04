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

import tempfile
from pathlib import Path

import pytest

import f2kboot

# Redmond blue, Windows 2000's desktop color: 0x3A6EA5.
DESKTOP = b"\x3a\x6e\xa5"
# FiSH running pipe's create section from the corpus directory.
CMDLINE = "WINNT\\system32\\fish.exe \\CORPUS\\pipe.exe create"


@pytest.mark.kernel
def test_fish_paints_the_framebuffer(request, builder, log_path, boot_timeout):
    """The mode line and the clean exit codes on COM1, and the screen a solid desktop."""
    directory = Path(tempfile.mkdtemp(prefix="f2k-fb-"))
    png = directory / "screen.png"

    def observe(socket: Path) -> None:
        f2kboot.screendump(socket, png)

    log, stopped = f2kboot.boot(
        builder([]),
        image="kernel",
        cmdline=CMDLINE,
        log_path=log_path,
        timeout=boot_timeout(60.0),
        done=f2kboot.teardown_audited,
        observe=observe,
    )
    tail = f"log: {log_path} ({stopped})\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"
    assert "KERNEL PANIC" not in log, tail
    assert "F2K: vbe: 640x480x32" in log, f"no mode line\n{tail}"
    assert "child process" in log and "(PIPE) exited normally (exit code=0)" in log, (
        f"pipe did not end with 0\n{tail}"
    )
    assert "F2K: user process exited normally (exit code=0)" in log, f"FiSH did not end with the child's 0\n{tail}"
    assert "teardown audit: frame database ok" in log, f"teardown not clean\n{tail}"

    image = f2kboot.read_png(png)
    assert (image.width, image.height) == (640, 480), f"the screen is {image.width}x{image.height}"
    bad = [(x, y) for y, row in enumerate(image.rows) for x in range(image.width) if row[3 * x:3 * x + 3] != DESKTOP]
    assert not bad, f"{len(bad)} pixels are not the desktop color, first {bad[:5]}"
