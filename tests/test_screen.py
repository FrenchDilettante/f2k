"""screen - the console's VGA text screen, read back from the machine: hello's "Hello, world!"
lands on the text page as the console's renderer draws it, and looks as recorded.

The boot is hello's program smoke (the kernel through QEMU's Multiboot loader, `hello.exe` from the
volume's root), with a QMP socket beside it. hello has no sectioned capture: its line is its
fixture's — hello.c's printf, which the real-machine trace (tests/hello/trace.txt) shows as one
15-byte WriteFile, the C runtime's "Hello, world!\\r\\n". The serial log must carry it as the
program's output, the process ending with 0 and a clean teardown. Once it has, the machine is read
through QMP while QEMU still runs:

- the text page (`xp` on guest-physical 0xB8000): the line on row 0, in the default attribute
  (0x07, light grey on black), the next row blank. The fresh console's screen starts blank and
  nothing else draws on it, so the program's first line is row 0;
- the screen as QEMU displays it (`screendump`, PNGs), until two dumps differ: the hardware cursor
  blinks, so the one cell where they differ is where the CRT controller's cursor is, which must be
  the console's cursor. Every other pixel must match the recorded reference, tests/screens/<name>.png
  (`--update-screens` records it from the run, the cursor drawn; a QEMU whose font or palette
  changed shows as a mismatch, to look at and record again).

Each run's screen is kept beside its COM1 log (target/qemu/logs/<test id>.png).

    uv run pytest tests/test_screen.py
    uv run pytest tests/test_screen.py --update-screens
"""
from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path

import pytest

import f2kboot

# hello's run, as its fixture pins it: the one line, then a clean exit.
HELLO = f2kboot.Block("hello.exe", ["Hello, world!"], exit_code=0)
DEFAULT_ATTRIBUTE = 0x07
REFERENCE = f2kboot.REPO_ROOT / "tests" / "screens" / "hello.png"
# How long the dumps may take to catch both of the cursor's blink phases.
BLINK_TIMEOUT = 3.0


def dumps_across_a_blink(socket: Path, directory: Path) -> list[Path]:
    """Screen dumps until one differs from the first (the cursor's other phase), at most
    BLINK_TIMEOUT seconds of them: the first and the differing one, or the first alone."""
    first = directory / "dump-0.png"
    f2kboot.screendump(socket, first)
    image = f2kboot.read_png(first)
    deadline = time.monotonic() + BLINK_TIMEOUT
    count = 1
    while time.monotonic() < deadline:
        time.sleep(0.1)
        dump = directory / f"dump-{count}.png"
        f2kboot.screendump(socket, dump)
        count += 1
        if f2kboot.read_png(dump).rows != image.rows:
            return [first, dump]
    return [first]


@pytest.mark.kernel
def test_hello_reaches_the_text_screen(request, builder, log_path, boot_timeout):
    """hello's "Hello, world!" on row 0 of the text page, in the default attribute, the rest of the
    row blank; the hardware cursor on the row after it; the screen as recorded."""
    block = HELLO
    assert 0 < len(block.lines) < f2kboot.ROWS, "the block fits the screen without scrolling"
    assert all(len(line) < f2kboot.COLUMNS for line in block.lines), "and without wrapping"
    # hello's output ends with a line break: the cursor waits at the next row's start.
    cursor = (len(block.lines), 0)
    screens: list[f2kboot.TextScreen] = []
    directory = Path(tempfile.mkdtemp(prefix="f2k-screen-"))
    dumps: list[Path] = []

    def observe(socket: Path) -> None:
        screens.append(f2kboot.read_text_screen(socket, (len(block.lines) + 1) * f2kboot.COLUMNS))
        dumps.extend(dumps_across_a_blink(socket, directory))

    try:
        log, stopped = f2kboot.boot(
            builder([]),
            image="kernel",
            cmdline=block.command,
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(f2kboot.CORPUS_TIMEOUT),
            done=f2kboot.teardown_audited,
            observe=observe,
        )
        if not screens:
            pytest.fail(f"the boot never reached its teardown (stopped: {stopped})\nlog: {log_path}\n"
                        f"--- COM1 (tail) ---\n{f2kboot.tail(log)}", pytrace=False)
        mismatch = f2kboot.compare_block(block, log, [])
        assert mismatch is None, f"the serial log does not carry the block: {mismatch}\nlog: {log_path}"

        (screen,) = screens
        for row, line in enumerate(block.lines):
            assert screen.text(row) == line.ljust(f2kboot.COLUMNS), f"row {row}"
            attributes = {attribute for _, attribute in screen.row(row)}
            assert attributes == {DEFAULT_ATTRIBUTE}, f"row {row}: attributes {sorted(attributes)}"
        after = len(block.lines)
        assert screen.text(after) == " " * f2kboot.COLUMNS, f"row {after}: nothing after the output"

        images = [f2kboot.read_png(dump) for dump in dumps]
        # The phase with the cursor drawn is the one kept and recorded.
        shown = max(range(len(images)), key=lambda index: f2kboot.lit_pixels(images[index], cursor))
        shutil.copyfile(dumps[shown], log_path.with_suffix(".png"))
        assert len(images) == 2, f"the cursor never blinked within {BLINK_TIMEOUT} s"
        blinking = f2kboot.differing_cells(*images)
        assert blinking == {cursor}, f"the hardware cursor blinks at {sorted(blinking)}, not {cursor}"

        if request.config.getoption("--update-screens"):
            REFERENCE.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(dumps[shown], REFERENCE)
            return
        assert REFERENCE.exists(), (f"no reference screen {REFERENCE.relative_to(f2kboot.REPO_ROOT)}:"
                                    " record it with --update-screens")
        reference = f2kboot.read_png(REFERENCE)
        changed = f2kboot.differing_cells(reference, images[shown]) - {cursor}
        assert not changed, (f"the screen differs from {REFERENCE.relative_to(f2kboot.REPO_ROOT)} in "
                             f"cells {sorted(changed)[:10]} (this run's: {log_path.with_suffix('.png')})")
    finally:
        shutil.rmtree(directory, ignore_errors=True)
