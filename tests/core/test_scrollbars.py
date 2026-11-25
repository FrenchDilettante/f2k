"""scrollbars - scroll bars on the screen: scrollshow.exe (userland/scrollshow) run by FiSH, which
sets the graphics mode, on a copy of the disk with the system's fonts and scrollshow in
\\WINNT\\system32.

scrollshow makes a top-level window with both standard scroll bars and two ScrollBar controls in
its client area:
- the window's vertical bar: range 0-99, page 20, position 30;
- its horizontal bar: range 0-49, page 10, position 0, its left arrow disabled;
- a horizontal ScrollBar control: range 0-10, position 5, no page;
- a vertical ScrollBar control: range 0-4, both arrows disabled.

Once the window shows and scrollshow's queue is idle it prints `scrollshow: ready`; the screen is
dumped then, to target/qemu/screens/scrollbars/window.png, a few pixels checked, and last compared
with its committed baseline, tests/core/screens/scrollbars/window.png (`f2kboot.check_screens`: a
changed screen rewrites the baseline and fails, committing it accepts it). Alt+F4 then closes the
window, which ends scrollshow with 0.

    uv run pytest tests/core/test_scrollbars.py
"""
from __future__ import annotations

import pytest

import f2kboot

SCROLLSHOW = f2kboot.BUILT_PROGRAMS / "scrollshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\scrollshow.exe"
READY = "scrollshow: ready"
NAME = "scrollbars"
SCREEN = f2kboot.SCREENS / NAME / "window.png"
TIMEOUT = 60.0
# The window: a 260x200 client area in a 3-pixel fixed frame under a 19-pixel caption (266x225),
# centred on the 640x480 screen: (187, 127)-(453, 352). Its vertical bar runs down the client
# area's right 16 pixels (x 434-449), its horizontal bar along the bottom 16 (y 333-348); the
# ScrollBar controls sit at (20, 30) 160x17 and (200, 20) 17x120 in the client area (190, 149).
BLACK = b"\x00\x00\x00"
WHITE = b"\xff\xff\xff"
FACE = f2kboot.FACE
SHADOW = b"\x80\x80\x80"
DARK_SHADOW = b"\x40\x40\x40"
# Each point, what it shows, the colour expected.
POINTS = [
    ((442, 157), "the window's up arrow's glyph", BLACK),
    ((435, 220), "the window's vertical thumb's raised edge (position 30 of 0-99, page 20)", WHITE),
    ((435, 280), "the window's vertical track below the thumb", FACE),
    ((426, 341), "the window's right arrow's glyph", BLACK),
    ((197, 341), "the window's disabled left arrow's greyed glyph", SHADOW),
    ((441, 341), "the size box between the two bars", FACE),
    ((282, 187), "the horizontal control's thumb's left edge (position 5 of 0-10)", WHITE),
    ((297, 187), "the horizontal control's thumb's right edge", DARK_SHADOW),
    ((398, 178), "the disabled vertical control's greyed up arrow", SHADOW),
]


class ShotAndClose:
    """The boot's `during` step: once scrollshow's ready line is on COM1, the screen saved, then
    Alt+F4 typed."""

    def __init__(self) -> None:
        self.done = False

    def __call__(self, socket, log: str) -> None:
        if self.done or READY not in f2kboot.lines_of(log):
            return
        f2kboot.screendump(socket, SCREEN)
        f2kboot.press(socket, ["alt-f4"])
        self.done = True


@pytest.mark.kernel
def test_the_scroll_bars_on_the_screen(builder, log_path, boot_timeout):
    """The window shows with its two scroll bars and two ScrollBar controls drawn; Alt+F4 closes
    it and scrollshow ends with 0."""
    build = builder([])
    assert SCROLLSHOW.exists(), f"{SCROLLSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [SCROLLSHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"scrollshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"scrollshow's lines differ {context}"
    assert code == 0, f"scrollshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(*point)
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, [SCREEN.name])
