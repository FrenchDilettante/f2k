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
all desktop: the text is there. The pixels are not compared with a baseline (only the dialogs,
nonclient and tahoma tests keep committed screens); the PNG is kept as the run's artifact,
target/qemu/screens/textout/paint.png.

gditext is declared ahead of its real-machine build: until tests/build.bat has built gditext.exe
and tests/capture.bat captured it, the test is skipped, as the fixture's own blocks are.

    uv run pytest tests/core/test_textout.py
"""
from __future__ import annotations

import pytest

import f2kboot

# The fixture whose program draws, and its section that does.
FIXTURE = "gditext"
CMDLINE = f"{f2kboot.FISH} \\CORPUS\\{FIXTURE}.exe paint"
# Where the screen is kept: the screenshots' directory, under this test's name.
SCREEN = f2kboot.SCREENS / "textout" / "paint.png"


@pytest.mark.kernel
def test_text_reaches_the_framebuffer(request, builder, log_path, boot_timeout):
    """The mode line and the clean exit codes on COM1, a clean teardown, and the screen holding
    more than the desktop."""
    if f2kboot.awaited(FIXTURE):
        pytest.skip(f"{FIXTURE} awaits its real-machine build and capture (tests/build.bat {FIXTURE})")
    log, stopped = f2kboot.boot_painting(builder([]), CMDLINE, SCREEN, log_path=log_path,
                                         timeout=boot_timeout(60.0))
    f2kboot.check_painted(log, f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}", [
        ("(GDITEXT) exited normally (exit code=0)", "gditext did not end with 0"),
        (f2kboot.FISH_ENDED, "FiSH did not end with the child's 0"),
    ])

    drawn = len(f2kboot.pixels_not(f2kboot.read_screen(SCREEN), f2kboot.DESKTOP))
    assert drawn, f"the screen is all desktop: nothing was drawn (kept at {SCREEN})"
