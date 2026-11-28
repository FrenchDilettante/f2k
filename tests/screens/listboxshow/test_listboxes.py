"""listboxes - list boxes on the screen: listboxshow.exe (beside this test) run by FiSH, which
sets the graphics mode, on a copy of the disk with the system's fonts and listboxshow in
\\WINNT\\system32.

listboxshow makes a top-level window with three ListBox controls in its client area:
- a list box with a border and a vertical scroll bar: fifteen items, the third selected and the
  focus on it;
- a multiple-selection list box with a border: five items, the first and the fourth selected;
- a disabled list box with a border: two items, greyed.

Once the window shows and listboxshow's queue is idle it prints `listboxshow: ready`; the screen is
dumped then, to target/qemu/screens/listboxes/window.png, a few pixels checked (the items'
backgrounds and the edges, never a glyph's), and last compared with its committed baseline,
tests/screens/listboxshow/window.png (`f2kboot.check_screens`: a changed screen rewrites the
baseline and fails, committing it accepts it). Alt+F4 then closes the window, which ends
listboxshow with 0.

    uv run pytest tests/screens/listboxshow/test_listboxes.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

import f2kboot

LISTBOXSHOW = f2kboot.BUILT_PROGRAMS / "listboxshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\listboxshow.exe"
READY = "listboxshow: ready"
NAME = "listboxes"
SCREEN = f2kboot.SCREENS / NAME / "window.png"
TIMEOUT = 60.0
# The window: a 300x200 client area in a 3-pixel fixed frame under a 19-pixel caption, centred on
# the 640x480 screen, its client area at (170, 149). The list boxes' sunken edges are two pixels
# (shadow, then dark shadow); the first list box's client area starts at (182, 161), its items 16
# pixels high (the System font), its scroll bar down its right (x 292-307); the second's client
# area at (332, 161). Each point is an item's background past its text, an edge or the scroll
# bar's own drawing: none is a glyph's.
BLACK = b"\x00\x00\x00"
WHITE = b"\xff\xff\xff"
SHADOW = b"\x80\x80\x80"
DARK_SHADOW = b"\x40\x40\x40"
HIGHLIGHT = b"\x0a\x24\x6a"
# Each point, what it shows, the colour expected.
POINTS = [
    ((180, 159), "the first list box's sunken edge, its outer shadow", SHADOW),
    ((181, 160), "the first list box's sunken edge, its inner dark shadow", DARK_SHADOW),
    ((288, 200), "the first list box's selected third item, past its text", HIGHLIGHT),
    ((288, 185), "the first list box's second item, past its text", WHITE),
    ((299, 168), "the first list box's scroll bar's up arrow's glyph", BLACK),
    ((299, 178), "the scroll bar's thumb's raised edge (11 of 15 items showing)", WHITE),
    ((450, 165), "the multiple-selection list box's first item, selected", HIGHLIGHT),
    ((450, 190), "the multiple-selection list box's second item, not selected", WHITE),
    ((450, 215), "the multiple-selection list box's fourth item, selected", HIGHLIGHT),
    ((450, 250), "the multiple-selection list box's client area below its items", WHITE),
    ((450, 330), "the disabled list box's background below its items", WHITE),
]


class ShotAndClose:
    """The boot's `during` step: once listboxshow's ready line is on COM1, the screen saved, then
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
def test_the_list_boxes_on_the_screen(builder, log_path, boot_timeout):
    """The window shows with its three list boxes drawn: the selections highlighted, the focus
    rectangle, the scroll bar, the disabled one greyed; Alt+F4 closes it and listboxshow ends
    with 0."""
    build = builder([])
    assert LISTBOXSHOW.exists(), f"{LISTBOXSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [LISTBOXSHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
        needs=f2kboot.command_needs(CMDLINE, "keyboard"),
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"listboxshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"listboxshow's lines differ {context}"
    assert code == 0, f"listboxshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(*point)
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, Path(__file__).parent, [SCREEN.name])
