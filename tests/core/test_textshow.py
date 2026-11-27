"""text layout on the screen - textshow.exe (userland/textshow) run by FiSH, which sets the graphics
mode, on a copy of the disk with the system's fonts and textshow in \\WINNT\\system32.

textshow's WM_PAINT draws "Ab" under TA_LEFT|TA_TOP, TA_CENTER|TA_BASELINE and TA_RIGHT|TA_BOTTOM,
three strings from the current position under TA_UPDATECP, "Hello" with a character extra of 4,
"a b c" justified 40 pixels wider over its 2 breaks, two PolyTextOutW strings (the second over an
ETO_OPAQUE rectangle), and "Ab" under TA_RIGHT through a 2 times MM_ANISOTROPIC mapping, in the
System font on opaque yellow and cyan cells.

Once the window shows and textshow's queue is idle it prints `textshow: ready`; the screen is
dumped then, to target/qemu/screens/text/window.png, the cells' edges checked (their top rows, which
no glyph reaches), and last compared with its committed baseline, tests/core/screens/text/window.png
(`f2kboot.check_screens`: a changed screen rewrites the baseline and fails, committing it accepts
it). Alt+F4 then closes the window, which ends textshow with 0.

    uv run pytest tests/core/test_textshow.py
"""
from __future__ import annotations

import pytest

import f2kboot

TEXTSHOW = f2kboot.BUILT_PROGRAMS / "textshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\textshow.exe"
READY = "textshow: ready"
NAME = "text"
SCREEN = f2kboot.SCREENS / NAME / "window.png"
TIMEOUT = 60.0
# The window: a 260x200 client area in a 3-pixel fixed frame under a 19-pixel caption (266x225),
# centred on the 640x480 screen: its client area's top left at (190, 149).
WHITE = b"\xff\xff\xff"
RED = b"\xff\x00\x00"
YELLOW = b"\xff\xff\x00"
CYAN = b"\x00\xff\xff"
LEFT, TOP = 190, 149
# Each point (client coordinates), what it shows, the colour expected. The System font: "Ab" 16
# pixels wide, "Hello" 34, "a b c" 31 ('a' 8, the space 4), "abc" 23, 16 high, ascent 13.
POINTS = [
    ((10, 8), "TA_LEFT|TA_TOP's reference point mark", RED),
    ((11, 8), "TA_LEFT|TA_TOP's cells, from the reference point", YELLOW),
    ((25, 8), "TA_LEFT|TA_TOP's last column", YELLOW),
    ((26, 8), "right of TA_LEFT|TA_TOP's cells", WHITE),
    ((71, 8), "left of TA_CENTER|TA_BASELINE's cells (80 less 8)", WHITE),
    ((72, 8), "TA_CENTER|TA_BASELINE's cells' top, 13 above the baseline at 21", YELLOW),
    ((87, 8), "TA_CENTER|TA_BASELINE's last column", YELLOW),
    ((88, 8), "right of TA_CENTER|TA_BASELINE's cells", WHITE),
    ((80, 7), "above TA_CENTER|TA_BASELINE's cells", WHITE),
    ((133, 8), "left of TA_RIGHT|TA_BOTTOM's cells (150 less 16)", WHITE),
    ((134, 8), "TA_RIGHT|TA_BOTTOM's cells' top, 16 above the bottom at 24", YELLOW),
    ((149, 8), "TA_RIGHT|TA_BOTTOM's last column, left of the reference point", YELLOW),
    ((150, 8), "right of TA_RIGHT|TA_BOTTOM's cells", WHITE),
    ((150, 24), "TA_RIGHT|TA_BOTTOM's reference point mark", RED),
    ((25, 32), "TA_UPDATECP's first \"Ab\"", YELLOW),
    ((26, 32), "TA_UPDATECP's \"Hello\", from the position the first left", CYAN),
    ((59, 32), "\"Hello\"'s last column", CYAN),
    ((60, 32), "TA_UPDATECP's second \"Ab\"", YELLOW),
    ((75, 32), "the second \"Ab\"'s last column", YELLOW),
    ((76, 32), "right of the current position's run", WHITE),
    ((63, 56), "\"Hello\" with 4 extra a character: 54 wide", CYAN),
    ((64, 56), "right of the spaced \"Hello\"", WHITE),
    ((30, 85), "the first justified space, 24 wide, filled", YELLOW),
    ((80, 80), "the justified \"a b c\"'s last column: 71 wide", YELLOW),
    ((81, 80), "right of the justified line", WHITE),
    ((25, 104), "PolyTextOutW's first string", YELLOW),
    ((26, 104), "right of PolyTextOutW's first string", WHITE),
    ((119, 110), "left of the ETO_OPAQUE rectangle", WHITE),
    ((120, 110), "the ETO_OPAQUE rectangle's fill", YELLOW),
    ((249, 123), "the ETO_OPAQUE rectangle's far corner", YELLOW),
    ((250, 110), "right of the ETO_OPAQUE rectangle", WHITE),
    ((33, 140), "left of the mapped TA_RIGHT cells (logical 20 is 50)", WHITE),
    ((34, 140), "the mapped TA_RIGHT cells, 16 wide (the font not scaled)", YELLOW),
    ((49, 140), "the mapped cells' last column", YELLOW),
    ((50, 140), "right of the mapped cells", WHITE),
]


class ShotAndClose:
    """The boot's `during` step: once textshow's ready line is on COM1, the screen saved, then
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
def test_the_text_on_the_screen(builder, log_path, boot_timeout):
    """The window shows its text laid out; Alt+F4 closes it and textshow ends with 0."""
    build = builder([])
    assert TEXTSHOW.exists(), f"{TEXTSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    step = ShotAndClose()
    log, stopped = f2kboot.boot_with_programs(
        build, [TEXTSHOW], log_path, fonts=True,
        cmdline=CMDLINE,
        kernel_options=f2kboot.REDIRECTED_OPTION,
        timeout=boot_timeout(TIMEOUT),
        done=f2kboot.process_ended,
        during=step,
        needs=f2kboot.command_needs(CMDLINE, "keyboard"),
    )
    context = f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}"
    if not step.done:
        pytest.fail(f"textshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == [READY], f"textshow's lines differ {context}"
    assert code == 0, f"textshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    for point, what, colour in POINTS:
        pixel = image.pixel(LEFT + point[0], TOP + point[1])
        assert pixel == colour, f"{what} at {point} is {pixel.hex()}, not {colour.hex()} (kept at {SCREEN})"
    f2kboot.check_screens(NAME, [SCREEN.name])
