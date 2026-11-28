"""comboboxes - combo boxes on the screen: comboboxshow.exe (beside this test) run by FiSH,
which sets the graphics mode, on a copy of the disk with the system's fonts and comboboxshow in
\\WINNT\\system32.

comboboxshow makes a top-level window with three ComboBox controls in its client area:
- a CBS_DROPDOWNLIST combo box: six items, the third selected, the focus on it, its list dropped
  down below it, cut to its six items;
- a CBS_DROPDOWN combo box: three items, its edit holding a text of its own;
- a CBS_SIMPLE combo box: its edit above its list of five items, the second selected.

Once the window shows and comboboxshow's queue is idle it prints `comboboxshow: ready`; the screen
is dumped then, to target/qemu/screens/comboboxes/window.png, a few pixels checked (the items'
backgrounds, the edges, the borders and the button's arrow, never a glyph's), and last compared
with its committed baseline, tests/screens/comboboxshow/window.png (`f2kboot.check_screens`: a
changed screen rewrites the baseline and fails, committing it accepts it). Alt+F4 then closes the
window, which ends comboboxshow with 0.

    uv run pytest tests/screens/comboboxshow/test_comboboxes.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

import f2kboot

COMBOBOXSHOW = f2kboot.BUILT_PROGRAMS / "comboboxshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\comboboxshow.exe"
READY = "comboboxshow: ready"
NAME = "comboboxes"
SCREEN = f2kboot.SCREENS / NAME / "window.png"
TIMEOUT = 60.0
# The window: a 300x200 client area in a 3-pixel fixed frame under a 19-pixel caption, centred on
# the 640x480 screen, its client area at (170, 149). The combo boxes' sunken edges are two pixels
# (shadow, then dark shadow); the first combo box is at (180, 159), 26 pixels high (the System
# font's 16 by 13/8), its button down its right (x 292-307); its dropped list below it, from
# y 185, a one-pixel black border round six 16-pixel items (x 180-309, y 185-282). The simple combo
# box is at (330, 199), its list from y 225 under a sunken edge, its items from y 227. Each point
# is an item's background past its text, an edge, a border or the button's arrow: none is a glyph's.
BLACK = b"\x00\x00\x00"
WHITE = b"\xff\xff\xff"
FACE = b"\xd4\xd0\xc8"
SHADOW = b"\x80\x80\x80"
DARK_SHADOW = b"\x40\x40\x40"
HIGHLIGHT = b"\x0a\x24\x6a"
# Each point, what it shows, the colour expected.
POINTS = [
    ((180, 159), "the first combo box's sunken edge, its outer shadow", SHADOW),
    ((181, 160), "the first combo box's sunken edge, its inner dark shadow", DARK_SHADOW),
    ((280, 170), "the first combo box's field past its text, not highlighted while dropped", WHITE),
    ((295, 165), "the first combo box's button's face", FACE),
    ((300, 172), "the first combo box's button's down arrow", BLACK),
    ((180, 200), "the dropped list's left border", BLACK),
    ((299, 282), "the dropped list's bottom border, cut to its six items", BLACK),
    ((299, 283), "the window's face below the dropped list", FACE),
    ((300, 210), "the dropped list's second item, past its text", WHITE),
    ((300, 225), "the dropped list's selected third item, past its text", HIGHLIGHT),
    ((420, 161), "the drop-down combo box's field above its edit", WHITE),
    ((330, 225), "the simple combo box's list's sunken edge, its outer shadow", SHADOW),
    ((450, 235), "the simple combo box's first item, past its text", WHITE),
    ((450, 250), "the simple combo box's selected second item, past its text", HIGHLIGHT),
]


class ShotAndClose:
    """The boot's `during` step: once comboboxshow's ready line is on COM1, the screen saved, then
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
def test_the_combo_boxes_on_the_screen(builder, log_path, boot_timeout):
    """The window shows with its three combo boxes drawn, the first one's list dropped down;
    Alt+F4 closes it and comboboxshow ends with 0."""
    build = builder([])
    assert COMBOBOXSHOW.exists(), f"{COMBOBOXSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [COMBOBOXSHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
        needs=f2kboot.command_needs(CMDLINE, "keyboard"),
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"comboboxshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"comboboxshow's lines differ {context}"
    assert code == 0, f"comboboxshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(*point)
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, Path(__file__).parent, [SCREEN.name])
