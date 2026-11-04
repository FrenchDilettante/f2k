"""cmd - the file, console and clock built-ins, booted: `md`, `copy`, `ren`, `move`, `del`, `rd`,
`pushd` and `popd` in a batch file, and `color`, `del`'s question, `$+` and `pause` typed at the
prompt.

The first boot runs `cmd.exe /c f2kfiles.cmd` (as tests/core/test_cmd.py's `/c` boots do, with
the kernel option `redirected`, so that its output and error reach COM1). The batch file and a
one-line data file, f2kdata.txt, are added beside cmd.exe in \\WINNT\\system32, the current
directory. The script builds a tree under F2KDIR, copies, joins, renames and moves files in it,
looks at them with `type`, goes in and out of a directory with `pushd` and `popd`, then deletes
it all; `echo %errorlevel%` shows what each built-in left:

- `md` makes the directories along a path; a second `md` of one prints that it exists, and sets
  ERRORLEVEL to 1;
- `copy` to a directory prints `1 file(s) copied.` right-aligned; `copy /b a+a b` prints each
  source and writes them one after the other; a wildcard copy prints each file's name;
- `ren` with wildcards gives each file the new extension; `move` renames a file into another
  directory;
- `pushd` alone lists the saved directory; `cd` shows where `pushd` went and `popd` came back;
- `del` of a name matching nothing prints `Could Not Find` and the full path, and leaves the
  ERRORLEVEL 0; `rd` of a directory holding files prints that it is not empty; `rd /s /q`
  removes it all.

The second boot types at the prompt (as tests/core/test_cmd.py's do): `color 1e` colours every
cell of the screen; `del` of a directory asks `Are you sure (Y/N)?` and Y deletes its files;
`prompt $+$p$g` shows a `+` once `pushd` saved a directory; `pause` waits for a key.

    uv run pytest tests/core/test_cmd_files.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

import f2kboot
from test_cmd import (
    BANNER,
    COMMAND_LINE,
    PROMPT,
    TIMEOUT,
    Typist,
    disk_with_cmd,
    rows_of,
    run_with_c,
    shown,
)

SCRIPT = [
    "@echo off",
    "md f2kdir\\sub",
    "echo md %errorlevel%",
    "md f2kdir",
    "echo md again %errorlevel%",
    "copy f2kdata.txt f2kdir",
    "copy /b f2kdata.txt+f2kdata.txt f2kdir\\two.txt",
    "type f2kdir\\two.txt",
    "copy f2kdir\\*.txt f2kdir\\sub",
    "ren f2kdir\\sub\\*.txt *.bak",
    "move f2kdir\\sub\\two.bak f2kdir\\moved.txt",
    "type f2kdir\\moved.txt",
    "title F2K files",
    "pushd f2kdir\\sub",
    "pushd",
    "cd",
    "type f2kdata.bak",
    "popd",
    "cd",
    "del f2kdir\\none.txt",
    "echo del none %errorlevel%",
    "rd f2kdir",
    "echo rd %errorlevel%",
    "del f2kdir\\*.txt",
    "rd /s /q f2kdir",
    "type f2kdir\\moved.txt",
    "echo done",
]

EXPECTED = [
    "md 0",
    "A subdirectory or file f2kdir already exists.",
    "md again 1",
    "        1 file(s) copied.",
    "f2kdata.txt",
    "f2kdata.txt",
    "        1 file(s) copied.",
    "one",
    "one",
    "f2kdir\\f2kdata.txt",
    "f2kdir\\two.txt",
    "        2 file(s) copied.",
    "one",
    "one",
    "C:\\WINNT\\system32",
    "C:\\WINNT\\system32\\f2kdir\\sub",
    "one",
    "C:\\WINNT\\system32",
    "Could Not Find C:\\WINNT\\system32\\f2kdir\\none.txt",
    "del none 0",
    "The directory is not empty.",
    "rd 1",
    "The system cannot find the path specified.",
    "done",
]


def files(directory: Path) -> list[Path]:
    """The script and its data file written into `directory`, their lines ended by CR LF."""
    script = directory / "f2kfiles.cmd"
    script.write_bytes("".join(f"{line}\r\n" for line in SCRIPT).encode("ascii"))
    data = directory / "f2kdata.txt"
    data.write_bytes(b"one\r\n")
    return [script, data]


@pytest.mark.kernel
def test_files_in_a_batch_file(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c` of the script: each built-in's output and ERRORLEVEL, and the exit code 0."""
    output, code = run_with_c(builder, log_path, boot_timeout, "f2kfiles", files(tmp_path))
    assert (output, code) == (EXPECTED, 0)


# QMP's key codes for the characters the typed lines hold that are not lowercase letters or digits.
QCODES = {
    " ": "spc",
    "$": "shift-4",
    "+": "shift-equal",
    "\\": "backslash",
    ".": "dot",
}


def line_of(text: str) -> list[str]:
    """The chords that type `text`, then Return."""
    return [QCODES.get(character, character) for character in text] + ["ret"]


@pytest.mark.kernel
def test_console_built_ins_at_the_prompt(builder, log_path, boot_timeout):
    """`color`, `del`'s question, `$+` after `pushd`, and `pause`, typed at the prompt: the screen
    they leave, every cell of it in `color`'s colours."""
    question = "C:\\WINNT\\system32\\f2kq\\*, Are you sure (Y/N)?"
    steps = [
        (PROMPT, line_of("color 1e")),
        (PROMPT, line_of("md f2kq")),
        (PROMPT, line_of("copy cmd.exe f2kq")),
        (PROMPT, line_of("del f2kq")),
        (question, line_of("y")),
        (PROMPT, line_of("rd f2kq")),
        (PROMPT, line_of("prompt $+$p$g")),
        (PROMPT, line_of("pushd \\")),
        ("+C:\\>", line_of("popd")),
        (PROMPT, line_of("pause")),
        ("Press any key to continue . . .", ["x"]),
    ]
    expected = [
        BANNER,
        "",
        PROMPT + "color 1e",
        "",
        PROMPT + "md f2kq",
        "",
        PROMPT + "copy cmd.exe f2kq",
        "        1 file(s) copied.",
        "",
        PROMPT + "del f2kq",
        question + " y",
        "",
        PROMPT + "rd f2kq",
        "",
        PROMPT + "prompt $+$p$g",
        "",
        PROMPT + "pushd \\",
        "",
        "+C:\\>popd",
        "",
        PROMPT + "pause",
        "Press any key to continue . . .",
        "",
        PROMPT,
    ]
    build, variant = disk_with_cmd(builder, log_path, [])
    typist = Typist(steps)
    try:
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=COMMAND_LINE,
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(TIMEOUT),
            done=lambda log: typist.screen is not None or f2kboot.process_ended(log),
            during=typist,
        )
    finally:
        variant.unlink(missing_ok=True)
    context = (f"\n--- the screen ---\n{shown(typist.screen or typist.last)}\nlog: {log_path}\n"
               f"--- COM1 (tail) ---\n{f2kboot.tail(log)}")
    if typist.taken < len(steps):
        pytest.fail(f"step {typist.taken + 1}'s screen never showed: its last line "
                    f"{steps[typist.taken][0]!r} (stopped: {stopped}){context}", pytrace=False)
    if typist.screen is None:
        pytest.fail(f"the prompt never came back after the last step (stopped: {stopped}){context}",
                    pytrace=False)
    rows = rows_of(typist.screen)
    assert rows == expected + [""] * (f2kboot.ROWS - len(expected)), f"the screen differs{context}"
    colours = {attribute for _, attribute in typist.screen.cells}
    assert colours == {0x1E}, f"the screen's attributes: {sorted(colours)}{context}"
