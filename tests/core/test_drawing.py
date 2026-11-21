"""drawing - user32's drawing calls in a window's DC: boot FiSH running drawdemo
(`fish.exe \\WINNT\\system32\\drawdemo.exe`, the kernel through QEMU's Multiboot loader), and read
the screen back through QMP while QEMU still runs.

drawdemo (userland/drawdemo) makes a borderless window at (20, 20) and paints a sample sheet in its
WM_PAINT through BeginPaint's DC: FillRect, FrameRect, InvertRect, DrawFocusRect, DrawEdge and
DrawText over gdi32's brushes and PatBlt, and one focus rectangle through GetDC's DC after the
paint. Each DC draws at the window's client origin, clipped to the client area.

COM1 carries the mode line, the exit-code lines (drawdemo's 0, which FiSH ends with) and the
teardown's audits. The screen as QEMU displays it (`screendump`, PNG) is kept as the run's
artifact, target/qemu/screens/drawing/sheet.png, for the owner to compare by eye with Windows 2000
drawing the same: no capture reads screen pixels machine-independently. A handful of pixels whose
place and color the sheet fixes are checked, so a DC that drew at the screen's origin, or not at
all, fails: the desktop outside the window, the face color inside it, the raised edge's inner
highlight one pixel in from its box's corner, a red fill, and the band inverted across it.

    uv run pytest tests/core/test_drawing.py
"""
from __future__ import annotations

import pytest

import f2kboot

CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\drawdemo.exe"
# Where the screen is kept: the screenshots' directory, under this test's name.
SCREEN = f2kboot.SCREENS / "drawing" / "sheet.png"
# The window's client origin on the screen (userland/drawdemo/src/lib.rs WINDOW).
ORIGIN = (20, 20)
# Pixels the sheet fixes, in client coordinates, as the framebuffer's RGB bytes.
FACE = f2kboot.FACE  # COLOR_3DFACE
HIGHLIGHT = b"\xff\xff\xff"  # COLOR_3DHILIGHT
RED = b"\xff\x00\x00"
CYAN = b"\x00\xff\xff"  # red, inverted
SAMPLES = [
    ((5, 60), FACE, "the client area's fill"),
    ((11, 11), HIGHLIGHT, "the raised edge's inner highlight"),
    ((12, 72), RED, "the red fill"),
    ((25, 95), CYAN, "the band inverted across the red fill"),
]


@pytest.mark.kernel
def test_the_drawing_calls_reach_the_window(request, builder, log_path, boot_timeout):
    """The clean exit codes on COM1, a clean teardown, the desktop around the window and the
    sheet's fixed pixels at the window's client origin."""
    log, stopped = f2kboot.boot_painting(builder([]), CMDLINE, SCREEN, log_path=log_path,
                                         timeout=boot_timeout(60.0))
    f2kboot.check_painted(log, f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}", [
        ("(drawdemo) exited normally (exit code=0)", "drawdemo did not end with 0"),
        (f2kboot.FISH_ENDED, "FiSH did not end with the child's 0"),
    ])

    image = f2kboot.read_screen(SCREEN)
    assert image.pixel(10, 10) == f2kboot.DESKTOP, f"the desktop outside the window (kept at {SCREEN})"
    for (x, y), color, what in SAMPLES:
        at = (ORIGIN[0] + x, ORIGIN[1] + y)
        assert image.pixel(*at) == color, f"{what} at {at}: {image.pixel(*at).hex()} (kept at {SCREEN})"
