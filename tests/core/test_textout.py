"""textout - text drawn on the VBE graphics screen through gdi32: boot FiSH running the gditext fixture
(`fish.exe \\CORPUS\\gditext.exe paint`, the kernel through QEMU's Multiboot loader), and read the
screen back through QMP while QEMU still runs.

FiSH sets the graphics mode first (user32's ChangeDisplaySettingsA, win32k's display service: the
screen cleared to the desktop color, Redmond blue 0x3A6EA5), then runs gditext's paint section:
gdi32's CreateDCA of the DISPLAY driver reaches win32k's NtGdiOpenDCW (a screen DC, an object in
the process's handle table), TextOutA and ExtTextOutA its NtGdiExtTextOutW, which draws the
built-in 8x16 font's glyphs into the framebuffer, and DeleteDC closes the DC's handle.

COM1 carries the mode line, the exit-code lines (gditext's 0, which FiSH ends with) and the
teardown's audits. The screen as QEMU displays it (`screendump`, PNG) must be 640x480 and no longer
all desktop: the text is there. The pixels are not compared (the screenshot comparison is a later
step); the PNG is kept as the run's artifact, target/qemu/screens/textout/paint.png.

gditext is declared ahead of its real-machine build: until tests/build.bat has built gditext.exe
and tests/capture.bat captured it, the test is skipped, as the fixture's own blocks are.

    uv run pytest tests/core/test_textout.py
"""
from __future__ import annotations

import pytest

import f2kboot

# Redmond blue, Windows 2000's desktop color: 0x3A6EA5.
DESKTOP = b"\x3a\x6e\xa5"
# The fixture whose program draws, and its section that does.
FIXTURE = "gditext"
CMDLINE = f"WINNT\\system32\\fish.exe \\CORPUS\\{FIXTURE}.exe paint"
# Where the screen is kept: the screenshots' directory, under this test's name.
SCREEN = f2kboot.SCREENS / "textout" / "paint.png"


@pytest.mark.kernel
def test_text_reaches_the_framebuffer(request, builder, log_path, boot_timeout):
    """The mode line and the clean exit codes on COM1, a clean teardown, and the screen holding
    more than the desktop."""
    if f2kboot.awaited(FIXTURE):
        pytest.skip(f"{FIXTURE} awaits its real-machine build and capture (tests/build.bat {FIXTURE})")
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)

    def observe(socket) -> None:
        f2kboot.screendump(socket, SCREEN)

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
    assert "(GDITEXT) exited normally (exit code=0)" in log, f"gditext did not end with 0\n{tail}"
    assert "F2K: user process exited normally (exit code=0)" in log, f"FiSH did not end with the child's 0\n{tail}"
    assert "teardown audit: frame database ok" in log, f"teardown not clean\n{tail}"
    assert "object audit FAILED" not in log, f"an object outlived its process\n{tail}"

    image = f2kboot.read_png(SCREEN)
    assert (image.width, image.height) == (640, 480), f"the screen is {image.width}x{image.height}"
    drawn = sum(1 for row in image.rows for x in range(image.width) if row[3 * x:3 * x + 3] != DESKTOP)
    assert drawn, f"the screen is all desktop: nothing was drawn (kept at {SCREEN})"
