"""nonclient - the non-client area and the keyboard menu loop on the screen, driven by keys typed
through QEMU's monitor: menushow.exe (userland/menushow) run by FiSH, which sets the graphics mode,
on a copy of the disk with the system's fonts (so the caption is in Tahoma Bold, the menus in
Tahoma, the caption buttons' glyphs in Marlett) and menushow in \\WINNT\\system32.

menushow makes a top-level window of calc's styles (a caption with its system menu and minimize
box, a fixed frame) with calc's menu bar (Edit, View, Help), its size from AdjustWindowRectEx. The
screen is saved three times, for the owner to compare by eye with Windows 2000 drawing the same (no
capture reads screen pixels machine-independently; a few pixels are checked):
- once the window shows, painted (`window.png`);
- once Alt, V and Down have opened View's popup with Scientific selected and the loop is idle
  (`menu.png`);
- once Enter has chosen Scientific and the window is painted again, the popup gone (`after.png`).
Alt+F4 then closes the window (the default procedure's SC_CLOSE), which ends menushow with 0.

menushow prints the menu messages its procedure receives; the kernel option `redirected` puts its
lines on COM1, which are compared line for line, WM_ENTERIDLE's left out (how many come depends on
when each key's release arrives).

    uv run pytest tests/core/test_nonclient.py
"""
from __future__ import annotations

import pytest

import f2kboot

MENUSHOW = f2kboot.BUILT_PROGRAMS / "menushow.exe"
CMDLINE = "WINNT\\system32\\fish.exe \\WINNT\\system32\\menushow.exe"
READY = "menushow: ready"
# Each step: the lines it waits for, in order, after the step before's (a WM_ENTERIDLE among them is
# the loop gone idle: the popup painted), then the screen it saves (none: no screen) and the chord
# it types (none: no chord), pressed then released.
STEPS = [
    ([READY], "window.png", "alt"),
    (["WM_MENUSELECT 0 flags 0x0090 the bar"], None, "v"),
    (["WM_MENUSELECT 303 flags 0x0288 View"], None, "down"),
    (["WM_MENUSELECT 304 flags 0x0080 View", "WM_ENTERIDLE 2"], "menu.png", "ret"),
    (["menushow: settled"], "after.png", "alt-f4"),
]
EXPECTED = [
    READY,
    "WM_SYSCOMMAND 0xF100 lParam=0",
    "WM_ENTERMENULOOP 0",
    "WM_INITMENU the bar",
    "WM_MENUSELECT 0 flags 0x0090 the bar",
    "WM_MENUSELECT 1 flags 0x0090 the bar",
    "WM_INITMENUPOPUP View position 1 system 0",
    "WM_MENUSELECT 303 flags 0x0288 View",
    "WM_MENUSELECT 304 flags 0x0080 View",
    "WM_UNINITMENUPOPUP View",
    "WM_MENUSELECT 0 flags 0xFFFF NULL",
    "WM_EXITMENULOOP 0",
    "WM_COMMAND id=304 code=0",
    "menushow: settled",
    "WM_SYSCOMMAND 0xF060 lParam=0",
]
# Where the screens are kept: the screenshots' directory, under this test's name.
SCREENS = f2kboot.SCREENS / "nonclient"
TIMEOUT = 60.0
# The window: a 260x200 client area, a 3-pixel fixed frame, a 19-pixel caption and a 19-pixel menu
# bar (266x244), centred on the 640x480 screen: its rectangle (187, 118)-(453, 362).
WINDOW = (187, 118, 453, 362)
# COLOR_ACTIVECAPTION, the active caption's left end (its gradient starts there); COLOR_3DLIGHT, the
# frame's raised edge's top left; COLOR_3DDKSHADOW, its bottom right; COLOR_MENU, the menu bar.
ACTIVE_CAPTION = b"\x0a\x24\x6a"
LIGHT = b"\xd4\xd0\xc8"
DARK_SHADOW = b"\x40\x40\x40"
MENU = b"\xd4\xd0\xc8"
# COLOR_HIGHLIGHT behind Scientific, the second item of View's popup, which opens under View, the
# bar's second item: a point of its row, found on the screen F2K draws.
HIGHLIGHT = b"\x0a\x24\x6a"
SELECTED_ITEM = (300, 187)


def pixel(image, x: int, y: int) -> bytes:
    return image.rows[y][3 * x:3 * x + 3]


class ShotAndTypist:
    """The boot's `during` step: each of STEPS taken once its lines are on COM1, in order."""

    def __init__(self) -> None:
        self.next = 0
        self.seen = 0

    @property
    def done(self) -> bool:
        return self.next == len(STEPS)

    def __call__(self, socket, log: str) -> None:
        if self.done:
            return
        waits, screen, chord = STEPS[self.next]
        lines = f2kboot.lines_of(log)
        at = self.seen
        for wait in waits:
            try:
                at = lines.index(wait, at) + 1
            except ValueError:
                return
        self.seen = at
        if screen is not None:
            f2kboot.screendump(socket, SCREENS / screen)
        f2kboot.qmp_command(socket, [f2kboot.key_events(chord, True),
                                     f2kboot.key_events(chord, False)])
        self.next += 1


@pytest.mark.kernel
def test_the_menu_bar_by_keyboard(builder, log_path, boot_timeout):
    """The window shows with its caption, frame and menu bar; Alt, V and Down open View's popup
    and select Scientific; Enter chooses it (WM_COMMAND posted after the loop's end); Alt+F4 closes
    the window, and menushow ends with 0."""
    build = builder([])
    assert MENUSHOW.exists(), f"{MENUSHOW} is missing: `make userland` builds and copies it"
    SCREENS.mkdir(parents=True, exist_ok=True)
    for _, screen, _ in STEPS:
        if screen is not None:
            (SCREENS / screen).unlink(missing_ok=True)
    variant = f2kboot.disk_with_programs(build, [MENUSHOW],
                                         f2kboot.WORK / "variants" / f"{log_path.stem}.img",
                                         fonts=True)
    typist = ShotAndTypist()
    try:
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=CMDLINE,
            kernel_options=f2kboot.REDIRECTED_OPTION,
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(TIMEOUT),
            done=f2kboot.process_ended,
            during=typist,
        )
    finally:
        variant.unlink(missing_ok=True)
    context = f"(stopped: {stopped}, step {typist.next})\nlog: {log_path}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"
    if not typist.done:
        pytest.fail(f"menushow's steps did not all happen {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    lines = [line for line in lines if not line.startswith("WM_ENTERIDLE")]
    assert lines == EXPECTED, f"menushow's lines differ {context}"
    assert code == 0, f"menushow's exit code {code} {context}"
    left, top, right, bottom = WINDOW
    for name in ("window.png", "after.png"):
        image = f2kboot.read_png(SCREENS / name)
        assert pixel(image, left, top) == LIGHT, f"{name}: the frame's top left"
        assert pixel(image, right - 1, bottom - 1) == DARK_SHADOW, f"{name}: the frame's bottom right"
        assert pixel(image, left + 4, top + 5) == ACTIVE_CAPTION, f"{name}: the active caption's left end"
        assert pixel(image, right - 10, top + 3 + 19 + 9) == MENU, f"{name}: the menu bar"
        assert pixel(image, *SELECTED_ITEM) != HIGHLIGHT, f"{name}: no popup"
    menu = f2kboot.read_png(SCREENS / "menu.png")
    assert pixel(menu, *SELECTED_ITEM) == HIGHLIGHT, "Scientific selected in View's popup"
