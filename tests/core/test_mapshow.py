"""mapping modes on the screen - drawing through a page transform: mapshow.exe (userland/mapshow) run
by FiSH, which sets the graphics mode, on a copy of the disk with the system's fonts and mapshow in
\\WINNT\\system32.

mapshow's WM_PAINT draws, each part between SaveDC and RestoreDC: a picture in a 10 by 10 logical
square at 8 pixels a unit (MM_ANISOTROPIC: Rectangle, Ellipse, RoundRect, a PatBlt mark, a line
clipped by IntersectClipRect's logical rectangle), the same flipped (y up), an 8 by 8 bitmap blitted
by BitBlt through a 4 times mapping upright and flipped, an MM_ISOTROPIC circle that stays round on
a 240 by -90 viewport, and, every state restored, a Rectangle in MM_TEXT.

Once the window shows and mapshow's queue is idle it prints `mapshow: ready`; the screen is
dumped then, to target/qemu/screens/mapping/window.png, a few pixels checked, and last compared with
its committed baseline, tests/core/screens/mapping/window.png (`f2kboot.check_screens`: a changed
screen rewrites the baseline and fails, committing it accepts it). Alt+F4 then closes the window,
which ends mapshow with 0.

    uv run pytest tests/core/test_mapshow.py
"""
from __future__ import annotations

import pytest

import f2kboot

MAPSHOW = f2kboot.BUILT_PROGRAMS / "mapshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\mapshow.exe"
READY = "mapshow: ready"
NAME = "mapping"
SCREEN = f2kboot.SCREENS / NAME / "window.png"
TIMEOUT = 60.0
# The window: a 260x200 client area in a 3-pixel fixed frame under a 19-pixel caption (266x225),
# centred on the 640x480 screen: its client area's top left at (190, 149).
BLACK = b"\x00\x00\x00"
WHITE = b"\xff\xff\xff"
RED = b"\xff\x00\x00"
GREEN = b"\x00\xff\x00"
BLUE = b"\x00\x00\xff"
YELLOW = b"\xff\xff\x00"
LEFT, TOP = 190, 149
# Each point (client coordinates), what it shows, the colour expected.
POINTS = [
    ((30, 30), "the red Rectangle, logical (1, 1, 5, 4) at 8 pixels a unit", RED),
    ((66, 34), "the blue Ellipse's middle", BLUE),
    ((50, 66), "the green RoundRect's interior", GREEN),
    ((14, 13), "the PatBlt mark at the logical origin", BLACK),
    ((86, 20), "the yellow square right of the Ellipse", YELLOW),
    ((95, 95), "the line past the square's corner, clipped away", WHITE),
    ((120, 70), "the flipped red Rectangle, y up from the viewport origin", RED),
    ((104, 86), "the flipped PatBlt mark, at the bottom", BLACK),
    ((104, 14), "the flipped square's top, yellow", YELLOW),
    ((205, 11), "the blitted bitmap's black top row, 4 pixels high", BLACK),
    ((212, 32), "the blitted bitmap's red pixel, 4 by 4", RED),
    ((205, 25), "the blitted bitmap's white", WHITE),
    ((205, 88), "the flipped blit's black top row, at the bottom", BLACK),
    ((212, 68), "the flipped blit's red pixel", RED),
    ((55, 145), "the MM_ISOTROPIC circle's middle", BLUE),
    ((95, 105), "outside the circle, at its box's corner: the viewport shrunk to 90 wide", WHITE),
    ((105, 145), "right of the circle, inside the 240-wide viewport asked for", WHITE),
    ((190, 150), "the MM_TEXT Rectangle after every RestoreDC", GREEN),
]


class ShotAndClose:
    """The boot's `during` step: once mapshow's ready line is on COM1, the screen saved, then
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
def test_the_mapping_on_the_screen(builder, log_path, boot_timeout):
    """The window shows with its parts drawn through their mappings; Alt+F4 closes it and mapshow ends with 0."""
    build = builder([])
    assert MAPSHOW.exists(), f"{MAPSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [MAPSHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
        needs=f2kboot.command_needs(CMDLINE, "keyboard"),
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"mapshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"mapshow's lines differ {context}"
    assert code == 0, f"mapshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(LEFT + point[0], TOP + point[1])
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, [SCREEN.name])
