"""childpaint - children painted again after their parent: clipshow.exe (beside this test) run by
FiSH, which sets the graphics mode, on a copy of the disk with the system's fonts and clipshow in
\\WINNT\\system32.

clipshow makes a top-level window without WS_CLIPCHILDREN whose WM_PAINT fills its whole client
area in teal, over its children: a Static with WS_BORDER, an Edit with WS_EX_CLIENTEDGE and a
ListBox with WS_BORDER and a vertical scroll bar. As Windows 2000 does, the parent's DC is not cut
by its children, and its invalidation reaches them, their frames included: each child paints after
the parent (WM_NCPAINT, WM_ERASEBKGND, WM_PAINT), so its frame shows over the fill. The window
paints as it shows; once its queue is idle clipshow invalidates its whole client area again, and
once idle again prints `clipshow: ready`.

The screen is dumped then, to target/qemu/screens/childpaint/window.png, a few pixels checked (the
fill, the frames and the edges, never a glyph's), and last compared with its committed baseline,
tests/screens/clipshow/window.png (`f2kboot.check_screens`: a changed screen rewrites the
baseline and fails, committing it accepts it). Alt+F4 then closes the window, which ends clipshow
with 0.

    uv run pytest tests/screens/clipshow/test_childpaint.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

import f2kboot

CLIPSHOW = f2kboot.BUILT_PROGRAMS / "clipshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\clipshow.exe"
READY = "clipshow: ready"
NAME = "childpaint"
SCREEN = f2kboot.SCREENS / NAME / "window.png"
TIMEOUT = 60.0
# The window: a 300x200 client area in a 3-pixel fixed frame under a 19-pixel caption, centred on
# the 640x480 screen, its client area at (170, 149). The Static's window is at (180, 159), 120x40,
# its WS_BORDER one black pixel; the Edit's at (180, 219), 120x24, its sunken edge two pixels
# (shadow, then dark shadow); the ListBox's at (320, 159), 130x100, its WS_BORDER a sunken edge as
# the Edit's (a list box's WS_BORDER is drawn as WS_EX_CLIENTEDGE), its scroll bar down its right.
# Each point is the fill, a frame, an edge or a child's background: none is a glyph's.
BLACK = b"\x00\x00\x00"
WHITE = b"\xff\xff\xff"
SHADOW = b"\x80\x80\x80"
DARK_SHADOW = b"\x40\x40\x40"
TEAL = b"\x00\x80\x80"
# Each point, what it shows, the colour expected.
POINTS = [
    ((175, 154), "the parent's fill, above and left of its children", TEAL),
    ((460, 340), "the parent's fill, below and right of its children", TEAL),
    ((180, 190), "the Static's border, its left side", BLACK),
    ((250, 198), "the Static's border, its bottom", BLACK),
    ((299, 175), "the Static's border, its right side", BLACK),
    ((180, 232), "the Edit's sunken edge, its outer shadow", SHADOW),
    ((181, 232), "the Edit's sunken edge, its inner dark shadow", DARK_SHADOW),
    ((290, 232), "the Edit's background, past its text", WHITE),
    ((320, 200), "the ListBox's sunken edge, its outer shadow", SHADOW),
    ((321, 200), "the ListBox's sunken edge, its inner dark shadow", DARK_SHADOW),
    ((380, 159), "the ListBox's sunken edge, its top's outer shadow", SHADOW),
    ((380, 258), "the ListBox's sunken edge, its bottom's outer highlight", WHITE),
    ((420, 250), "the ListBox's background, past its items' text", WHITE),
]


class ShotAndClose:
    """The boot's `during` step: once clipshow's ready line is on COM1, the screen saved, then
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
def test_the_childrens_frames_survive_their_parents_painting(builder, log_path, boot_timeout):
    """The window's fill covers its children, which paint again after it, their frames included,
    after its first painting and after its invalidation; Alt+F4 closes it and clipshow ends
    with 0."""
    build = builder([])
    assert CLIPSHOW.exists(), f"{CLIPSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [CLIPSHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
        needs=f2kboot.command_needs(CMDLINE, "keyboard"),
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"clipshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"clipshow's lines differ {context}"
    assert code == 0, f"clipshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(*point)
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, Path(__file__).parent, [SCREEN.name])
