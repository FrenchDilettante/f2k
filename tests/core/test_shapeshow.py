"""shapes on the screen - pens, lines and shapes: shapeshow.exe (userland/shapeshow) run by FiSH, which
sets the graphics mode, on a copy of the disk with the system's fonts and shapeshow in
\\WINNT\\system32.

shapeshow's WM_PAINT draws a Rectangle, an Ellipse and a RoundRect with solid brushes, a pentagram
Polygon under WINDING, a width-3 Polyline, a line in each cosmetic style, a width-9 corner under each
ExtCreatePen join, a width-5 PS_INSIDEFRAME Ellipse with the null brush, and an R2_NOT Rectangle
over a black bar.

Once the window shows and shapeshow's queue is idle it prints `shapeshow: ready`; the screen is
dumped then, to target/qemu/screens/shapes/window.png, a few pixels checked, and last compared with
its committed baseline, tests/core/screens/shapes/window.png (`f2kboot.check_screens`: a changed
screen rewrites the baseline and fails, committing it accepts it). Alt+F4 then closes the window,
which ends shapeshow with 0.

    uv run pytest tests/core/test_shapeshow.py
"""
from __future__ import annotations

import pytest

import f2kboot

SHAPESHOW = f2kboot.BUILT_PROGRAMS / "shapeshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\shapeshow.exe"
READY = "shapeshow: ready"
NAME = "shapes"
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
    ((10, 30), "the Rectangle's left edge", BLACK),
    ((40, 30), "the Rectangle's red interior", RED),
    ((135, 35), "the Ellipse's blue interior", BLUE),
    ((95, 10), "outside the Ellipse, at its box's corner", WHITE),
    ((220, 35), "the RoundRect's green interior", GREEN),
    ((40, 105), "the pentagram's middle, filled under WINDING", YELLOW),
    ((150, 88), "PS_DASH's first dash", BLACK),
    ((168, 88), "PS_DASH's first gap", WHITE),
    ((215, 150), "the R2_NOT outline over white: black", BLACK),
    ((215, 165), "the R2_NOT outline over the black bar: white", WHITE),
]


class ShotAndClose:
    """The boot's `during` step: once shapeshow's ready line is on COM1, the screen saved, then
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
def test_the_shapes_on_the_screen(builder, log_path, boot_timeout):
    """The window shows with its shapes drawn; Alt+F4 closes it and shapeshow ends with 0."""
    build = builder([])
    assert SHAPESHOW.exists(), f"{SHAPESHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [SHAPESHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
        needs=f2kboot.command_needs(CMDLINE, "keyboard"),
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"shapeshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"shapeshow's lines differ {context}"
    assert code == 0, f"shapeshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(LEFT + point[0], TOP + point[1])
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, [SCREEN.name])
