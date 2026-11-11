"""tahoma - the fonts the system loads at its start, drawn on the VBE graphics screen: boot a copy of
the disk the tests boot with Wine's five faces (fonts/*.ttf: Tahoma, Tahoma Bold, MS Sans Serif,
System and Marlett) in \\WINNT\\Fonts and F2K's fontshow.exe (userland/fontshow) beside the system's
programs, FiSH running fontshow, and read the screen back through QMP while QEMU still runs.

win32k loads each face once the volume is mounted (its built-in list standing in for the registry's
Fonts key), and says so on COM1. fontshow draws lines of text through gdi32's TextOutW: the stock
SYSTEM_FONT and DEFAULT_GUI_FONT, Tahoma at lfHeight -11, -13, -16 and -24, Tahoma Bold, the dialog
faces "MS Shell Dlg 2" and "MS Shell Dlg", MS Sans Serif at its three sizes, System at its two,
and a line of Marlett's caption-button and scroll-arrow glyphs, reporting each font's face and
kind; it ends with 0 when every face asked for by name was that face. The disk the tests boot
carries neither the fonts nor the program: this boot's copy is its own, removed after it.

The pixels are not compared: the screen is kept for the eye, at target/qemu/screens/tahoma/
fontshow.png (the Tahoma -11 and -24 rows match Windows 2000's for the fixtures' copy of the font in
the host tests of kernel/src/win32k/fonts, but for two pixels at -24).

    uv run pytest tests/core/test_tahoma.py
"""
from __future__ import annotations

import subprocess

import pytest

import f2kboot

# Redmond blue, Windows 2000's desktop color: 0x3A6EA5.
DESKTOP = b"\x3a\x6e\xa5"
PROGRAM = f2kboot.BUILT_PROGRAMS / "fontshow.exe"
CMDLINE = "WINNT\\system32\\fish.exe \\WINNT\\system32\\fontshow.exe"
# Where the screen is kept: the screenshots' directory, under this test's name.
SCREEN = f2kboot.SCREENS / "tahoma" / "fontshow.png"
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
    SCREEN.parent.mkdir(parents=True, exist_ok=True)
    SCREEN.unlink(missing_ok=True)

    def observe(socket) -> None:
        f2kboot.screendump(socket, SCREEN)

    with f2kboot.kept_disk(build, DISK) as disk:
        add_fonts_and_program(disk)
        log, stopped = f2kboot.boot(
            build,
            image="kernel",
            cmdline=CMDLINE,
            log_path=log_path,
            timeout=boot_timeout(90.0),
            done=f2kboot.teardown_audited,
            observe=observe,
            kept=disk,
        )
    tail = f"log: {log_path} ({stopped})\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"
    assert "KERNEL PANIC" not in log, tail
    for font in f2kboot.system_font_files():
        line = f"F2K: win32k: font loaded: \\WINNT\\Fonts\\{font.name}"
        assert line in log, f"no font line for {font.name}\n{tail}"
    assert "F2K: vbe: 640x480x32" in log, f"no mode line\n{tail}"
    assert "(FONTSHOW) exited normally (exit code=0)" in log, f"fontshow did not end with 0\n{tail}"
    assert "teardown audit: frame database ok" in log, f"teardown not clean\n{tail}"
    assert "object audit FAILED" not in log, f"an object outlived its process\n{tail}"

    image = f2kboot.read_png(SCREEN)
    assert (image.width, image.height) == (640, 480), f"the screen is {image.width}x{image.height}"
    drawn = sum(1 for row in image.rows for x in range(image.width) if row[3 * x:3 * x + 3] != DESKTOP)
    assert drawn, f"the screen is all desktop: nothing was drawn (kept at {SCREEN})"
