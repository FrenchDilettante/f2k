"""guikeys - the PS/2 keyboard's keystrokes reaching a window: keyshow.exe (userland/keyshow) typed
into through QEMU's monitor, as a person types on the real machine.

keyshow makes a visible pop-up window, makes it the foreground and focus window, prints
`keyshow: ready`, and reads its queue (GetMessage, TranslateMessage, DispatchMessage), its
procedure printing each keyboard message it receives as `<message> wParam=0x.... lParam=0x........`,
until Escape's character destroys the window and ends it with 0. The disk the tests boot leaves
keyshow.exe out, so the boot attaches a copy of it with the built keyshow.exe added to
\\WINNT\\system32 (`f2kboot.disk_with_programs`, removed after the boot); the kernel option
`redirected` puts keyshow's standard output on COM1, as a corpus program's.

While a GUI program is in the foreground, the keyboard driver hands its bytes to win32k's raw input
thread instead of the console: each keystroke becomes a key message posted to the focus window, the
way SendInput's do (the user32 keyinput fixture's captures), and TranslateMessage makes its
character. Once `keyshow: ready` is on COM1 the keys are pressed through QMP's input-send-event:
Shift+A, 2, Ctrl+C (a key message like any other: the console never sees it), Alt+F (system keys,
Alt's release a WM_KEYUP since F went down meanwhile), then Escape. The messages are compared line
for line, with the lParams the keyinput capture shows for the same keys.

    uv run pytest tests/core/test_guikeys.py
"""
from __future__ import annotations

import pytest

import f2kboot

KEYSHOW = f2kboot.BUILT_PROGRAMS / "keyshow.exe"
COMMAND_LINE = r"WINNT\system32\keyshow.exe"
READY = "keyshow: ready"
# The chords typed once keyshow is ready, each pressed then released (QEMU's key names).
CHORDS = ["shift-a", "2", "ctrl-c", "alt-f", "esc"]
# What keyshow prints: its window's keyboard messages, as the keyinput capture prints the same
# keys' (wParam, lParam's repeat count, scan code, context, previous and transition bits).
EXPECTED = [
    READY,
    "WM_KEYDOWN wParam=0x0010 lParam=0x002A0001",
    "WM_KEYDOWN wParam=0x0041 lParam=0x001E0001",
    "WM_CHAR wParam=0x0041 lParam=0x001E0001",
    "WM_KEYUP wParam=0x0041 lParam=0xC01E0001",
    "WM_KEYUP wParam=0x0010 lParam=0xC02A0001",
    "WM_KEYDOWN wParam=0x0032 lParam=0x00030001",
    "WM_CHAR wParam=0x0032 lParam=0x00030001",
    "WM_KEYUP wParam=0x0032 lParam=0xC0030001",
    "WM_KEYDOWN wParam=0x0011 lParam=0x001D0001",
    "WM_KEYDOWN wParam=0x0043 lParam=0x002E0001",
    "WM_CHAR wParam=0x0003 lParam=0x002E0001",
    "WM_KEYUP wParam=0x0043 lParam=0xC02E0001",
    "WM_KEYUP wParam=0x0011 lParam=0xC01D0001",
    "WM_SYSKEYDOWN wParam=0x0012 lParam=0x20380001",
    "WM_SYSKEYDOWN wParam=0x0046 lParam=0x20210001",
    "WM_SYSCHAR wParam=0x0066 lParam=0x20210001",
    "WM_SYSKEYUP wParam=0x0046 lParam=0xE0210001",
    "WM_KEYUP wParam=0x0012 lParam=0xC0380001",
    "WM_KEYDOWN wParam=0x001B lParam=0x00010001",
    "WM_CHAR wParam=0x001B lParam=0x00010001",
]
# How long the boot may take to reach keyshow's window and its keys to arrive.
TIMEOUT = 30.0


class Typist:
    """The boot's `during` step: once keyshow's ready line is on COM1, CHORDS typed, once."""

    def __init__(self) -> None:
        self.typed = False

    def __call__(self, socket, log: str) -> None:
        if self.typed or READY not in f2kboot.lines_of(log):
            return
        for chord in CHORDS:
            f2kboot.qmp_command(socket, [f2kboot.key_events(chord, True),
                                         f2kboot.key_events(chord, False)])
        self.typed = True


@pytest.mark.kernel
def test_typed_keys_reach_the_window(builder, log_path, boot_timeout):
    """The keys typed reach keyshow's window as its key messages, their characters through
    TranslateMessage, and Escape ends it with 0."""
    build = builder([])
    assert KEYSHOW.exists(), f"{KEYSHOW} is missing: `make userland` builds and copies it"
    variant = f2kboot.disk_with_programs(build, [KEYSHOW],
                                         f2kboot.WORK / "variants" / f"{log_path.stem}.img")
    typist = Typist()
    try:
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=COMMAND_LINE,
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
        pytest.fail(f"keyshow never said it was ready {context}", pytrace=False)
    lines, code = f2kboot.program_output(log)
    assert lines == EXPECTED, f"keyshow's lines differ {context}"
    assert code == 0, f"keyshow's exit code {code} {context}"
