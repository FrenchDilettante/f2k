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

CMDLINE = "WINNT\\system32\\fish.exe \\WINNT\\system32\\drawdemo.exe"
# Where the screen is kept: the screenshots' directory, under this test's name.
SCREEN = f2kboot.SCREENS / "drawing" / "sheet.png"
# The window's client origin on the screen (userland/drawdemo/src/lib.rs WINDOW).
ORIGIN = (20, 20)
# Pixels the sheet fixes, in client coordinates, as the framebuffer's RGB bytes.
DESKTOP = b"\x3a\x6e\xa5"
FACE = b"\xd4\xd0\xc8"  # COLOR_3DFACE
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
    assert "(drawdemo) exited normally (exit code=0)" in log, f"drawdemo did not end with 0\n{tail}"
    assert "F2K: user process exited normally (exit code=0)" in log, f"FiSH did not end with the child's 0\n{tail}"
    assert "teardown audit: frame database ok" in log, f"teardown not clean\n{tail}"
    assert "object audit FAILED" not in log, f"an object outlived its process\n{tail}"

    image = f2kboot.read_png(SCREEN)
    assert (image.width, image.height) == (640, 480), f"the screen is {image.width}x{image.height}"

    def pixel(x: int, y: int) -> bytes:
        return bytes(image.rows[y][3 * x:3 * x + 3])

    assert pixel(10, 10) == DESKTOP, f"the desktop outside the window (kept at {SCREEN})"
    for (x, y), color, what in SAMPLES:
        at = (ORIGIN[0] + x, ORIGIN[1] + y)
        assert pixel(*at) == color, f"{what} at {at}: {pixel(*at).hex()} (kept at {SCREEN})"
