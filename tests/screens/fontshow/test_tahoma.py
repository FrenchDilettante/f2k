"""tahoma - the fonts the system loads at its start, drawn on the VBE graphics screen: boot a copy of
the disk the tests boot with Wine's five faces (fonts/*.ttf: Tahoma, Tahoma Bold, MS Sans Serif,
System and Marlett) in \\WINNT\\Fonts and F2K's fontshow.exe (beside this test) beside the system's
programs, FiSH running fontshow, and read the screen back through QMP while QEMU still runs.

win32k loads each face once the volume is mounted (its built-in list standing in for the registry's
Fonts key), and says so on COM1. fontshow draws lines of text through gdi32's TextOutW: the stock
SYSTEM_FONT and DEFAULT_GUI_FONT, Tahoma at lfHeight -11, -13, -16 and -24, Tahoma Bold, the dialog
faces "MS Shell Dlg 2" and "MS Shell Dlg", MS Sans Serif at its three sizes, System at its two,
and a line of Marlett's caption-button and scroll-arrow glyphs, reporting each font's face and
kind; it ends with 0 when every face asked for by name was that face. The disk the tests boot
carries neither the fonts nor the program: this boot's copy is its own, removed after it.

The screen is dumped to target/qemu/screens/tahoma/fontshow.png and last compared with its
committed baseline, tests/screens/fontshow/fontshow.png (`f2kboot.check_screens`: a changed
screen rewrites the baseline and fails, committing it accepts it). The baseline is F2K's own, for
the eye; the Tahoma -11 and -24 rows match Windows 2000's for the fixtures' copy of the font in the
host tests of kernel/src/win32k/fonts, but for two pixels at -24.

    uv run pytest tests/screens/fontshow/test_tahoma.py
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import f2kboot

PROGRAM = f2kboot.BUILT_PROGRAMS / "fontshow.exe"
CMDLINE = f"{f2kboot.FISH} \\WINNT\\system32\\fontshow.exe"
# Where the screen is dumped (the scratch screens, under this test's name) and its baseline's name.
NAME = "tahoma"
SCREEN = f2kboot.SCREENS / NAME / "fontshow.png"
DISK = f2kboot.WORK / "disks" / "tahoma.img"


def add_fonts_and_program(disk) -> None:
    """The system's fonts into \\WINNT\\Fonts and fontshow.exe into \\WINNT\\system32, on the copy."""
    f2kboot.add_system_fonts(disk)
    subprocess.run(
        ["mcopy", "-i", f"{disk}{f2kboot.PARTITION}", str(PROGRAM), "::/WINNT/system32/FONTSHOW.EXE"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


@pytest.mark.kernel
def test_tahoma_reaches_the_framebuffer(request, builder, log_path, boot_timeout):
    """The boot's font lines, fontshow's 0 (every face asked for by name that face), a clean
    teardown, and the screen holding more than the desktop."""
    if not PROGRAM.exists():
        pytest.fail(f"{PROGRAM} missing: `make userland` builds it")
    build = builder([])
    with f2kboot.kept_disk(build, DISK) as disk:
        add_fonts_and_program(disk)
        log, stopped = f2kboot.boot_painting(build, CMDLINE, SCREEN, log_path=log_path,
                                             timeout=boot_timeout(90.0), kept=disk)
    f2kboot.check_painted(log, f"(stopped: {stopped})\n{f2kboot.failure_context(log_path, log)}", [
        *((f"F2K: win32k: font loaded: \\WINNT\\Fonts\\{font.name}", f"no font line for {font.name}")
          for font in f2kboot.system_font_files()),
        ("(FONTSHOW) exited normally (exit code=0)", "fontshow did not end with 0"),
    ])

    drawn = len(f2kboot.pixels_not(f2kboot.read_screen(SCREEN), f2kboot.DESKTOP))
    assert drawn, f"the screen is all desktop: nothing was drawn (kept at {SCREEN})"
    f2kboot.check_screens(NAME, Path(__file__).parent, [SCREEN.name])
