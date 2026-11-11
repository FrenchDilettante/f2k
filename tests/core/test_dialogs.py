"""dialogs - user32's dialog manager and its Button and Static controls on the screen, driven by
keys typed through QEMU's monitor: dlgshow.exe (userland/dlgshow) run by FiSH, which sets the
graphics mode, on a copy of the disk with the system's fonts (so the dialog font is MS Sans Serif's
strike) and dlgshow in \\WINNT\\system32.

dlgshow makes a modeless dialog from a template in memory: static text, the default push button
OK, the push button Cancel, an auto check box, a group box around two auto radio buttons, and an
etched line. Its loop hands every message to IsDialogMessageW. Once the dialog shows, painted, with
the focus on OK, it prints `dlgshow: ready, focus 1`; the screen is saved then, at
target/qemu/screens/dialogs/dialog.png, for the owner to compare by eye with Windows 2000 drawing
the same (no capture reads screen pixels machine-independently; one pixel of the dialog's face is
checked). The keys typed next, all at once, back to back: Tab and Tab move the focus from OK to
Cancel to the check box, Space checks it (its release clicks it: BN_CLICKED), and Enter, with the
focus on a control that is no push button, presses the default button OK, which ends dlgshow with
0. Each key reaches the control the focus is on when dlgshow reads it, not when it was typed, as
type-ahead does on Windows. The kernel option `redirected` puts the program's lines on COM1, which
are compared line for line.

    uv run pytest tests/core/test_dialogs.py
"""
from __future__ import annotations

import pytest

import f2kboot

DLGSHOW = f2kboot.BUILT_PROGRAMS / "dlgshow.exe"
CMDLINE = "WINNT\\system32\\fish.exe \\WINNT\\system32\\dlgshow.exe"
READY = "dlgshow: ready, focus 1"
# The chords typed once dlgshow is ready, each pressed then released (QEMU's key names), all in one
# command, without waiting for dlgshow to act on any: a key goes to the control the focus is on
# when dlgshow reads it, so each reaches the control the keys before it moved the focus to.
CHORDS = ["tab", "tab", "spc", "ret"]
EXPECTED = [
    READY,
    "key 0x09: focus 2",
    "key 0x09: focus 101",
    "key 0x20: focus 101",
    "WM_COMMAND id=101 code=0",
    "WM_COMMAND id=1 code=0",
    "dlgshow: OK, keep 1, mode standard",
    "key 0x0D: focus 101",
]
# Where the screen is kept: the screenshots' directory, under this test's name.
SCREEN = f2kboot.SCREENS / "dialogs" / "dialog.png"
# COLOR_3DFACE, the dialog's face, between the group box and the buttons: (115, 80) in its dialog
# units of 6x13 pixels, in its client area (180x104 units, 270x169 pixels), which its modal frame
# (3 pixels) and caption (19) surround, the window (276x194) centred on the 640x480 screen.
FACE = b"\xd4\xd0\xc8"
FACE_POINT = (357, 295)
TIMEOUT = 60.0


class ShotAndTypist:
    """The boot's `during` step: once dlgshow's ready line is on COM1, the screen saved, then
    CHORDS typed back to back."""

    def __init__(self) -> None:
        self.typed = False

    def __call__(self, socket, log: str) -> None:
        if self.typed or READY not in f2kboot.lines_of(log):
            return
        f2kboot.screendump(socket, SCREEN)
        f2kboot.qmp_command(socket, [event for chord in CHORDS
                                     for event in (f2kboot.key_events(chord, True),
                                                   f2kboot.key_events(chord, False))])
        self.typed = True


@pytest.mark.kernel
def test_the_dialog_takes_typed_keys(builder, log_path, boot_timeout):
    """The dialog shows (its face where the template puts it), Tab moves the focus through the tab
    stops, Space checks the check box, Enter presses the default button, and dlgshow ends with 0."""
    build = builder([])
    assert DLGSHOW.exists(), f"{DLGSHOW} is missing: `make userland` builds and copies it"
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)
    variant = f2kboot.disk_with_programs(build, [DLGSHOW],
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
    context = f"(stopped: {stopped})\nlog: {log_path}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"
    if not typist.typed:
        pytest.fail(f"dlgshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == EXPECTED, f"dlgshow's lines differ {context}"
    assert code == 0, f"dlgshow's exit code {code} {context}"
    image = f2kboot.read_png(SCREEN)
    x, y = FACE_POINT
    pixel = image.rows[y][3 * x:3 * x + 3]
    assert pixel == FACE, f"the dialog's face at {FACE_POINT} is {pixel.hex()}, not the dialog's face (kept at {SCREEN})"
