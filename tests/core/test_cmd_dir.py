"""cmd - `dir` and `start`, booted: one `cmd.exe /c f2kdir.cmd` (as tests/core/test_cmd.py's `/c`
boots run, with the kernel option `redirected`, so that its output and error reach COM1), the
batch file and the spawn fixture's companion, spawnkid.exe, beside cmd.exe in \\WINNT\\system32,
the current directory.

The script makes a directory, f2kd, with three files of known sizes (`echo` into one, `copy /b`
joining another into the others) and a subdirectory holding a fourth, then lists them:

- `dir /o:n` in the long format: the volume's heading, the directory's, each entry's date, time,
  `<DIR>` or size (with its thousands separator) and name, then the totals and the bytes free;
- `/b` with `/o:-s` and `/a:-d`: the files' names alone, largest first; `/s /b`: full paths,
  through the subdirectory; `/w`: the names side by side, directories in brackets; `/s` in the long
  format: each directory under its own heading, then the totals of both;
- the DIRCMD variable's switches, which the command line overrides (`/-b`);
- `/x /l /t:c` on a file with a long name: its short name before it, both in lowercase, and its
  creation time;
- a file that does not exist: `File Not Found`, and ERRORLEVEL 1.

Then `start /wait /b spawnkid exit 4` waits for the program and takes its exit code;
`start /b /low spawnkid exit 7` does not wait, and leaves ERRORLEVEL 0.

The dates, times, serial number and free bytes vary from boot to boot: their lines are matched by
patterns.

    uv run pytest tests/core/test_cmd_dir.py
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_cmd import SPAWNKID, run_with_c

# 58 letters and CR LF: 60 bytes; the script joins two into b.txt (120), ten of those into c.dat.
LINE = "abcdefghijklmnopqrstuvwxyz" * 2 + "abcdef"

SCRIPT = [
    "@echo off",
    "md f2kd\\sub",
    "echo alpha> f2kd\\a.txt",
    f"echo {LINE}> f2kd\\t.tmp",
    "copy /b f2kd\\t.tmp+f2kd\\t.tmp f2kd\\b.txt > nul",
    "copy /b " + "+".join(["f2kd\\b.txt"] * 10) + " f2kd\\c.dat > nul",
    "del f2kd\\t.tmp",
    "echo four> f2kd\\sub\\d.txt",
    "dir f2kd /o:n",
    "dir /b /o:-s /a:-d f2kd",
    "dir /s /b /o:n f2kd",
    "dir /w /o:n f2kd",
    "dir /s /o:n f2kd\\*.txt",
    "set DIRCMD=/b /o:n",
    "dir f2kd",
    "dir /-b /a:d f2kd",
    "set DIRCMD=",
    "md f2kx",
    "echo x> \"f2kx\\Long Name.txt\"",
    "dir /x /l /t:c /a:-d f2kx",
    "rd /s /q f2kx",
    "dir f2kd\\none.txt",
    "echo dir none %errorlevel%",
    "start /wait /b spawnkid exit 4",
    "echo start wait %errorlevel%",
    "start /b /low spawnkid exit 7",
    "echo start %errorlevel%",
    "rd /s /q f2kd",
]

# Each expected line: text to match exactly, or a compiled pattern for one that varies.
STAMP = r"\d\d/\d\d/\d{4}  \d\d:\d\d[ap]"
HEADING = [
    " Volume in drive C is F2K",
    re.compile(r" Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}"),
]


def entry(text: str) -> re.Pattern[str]:
    """A long-format line, its date and time varying: `text` is what follows them."""
    return re.compile(STAMP + re.escape(text))


def directories(count: int) -> re.Pattern[str]:
    """The line of directories and bytes free, `count` directories."""
    return re.compile(rf" {{15}}{count} Dir\(s\) +[\d,]+ bytes free")


EXPECTED = [
    *HEADING,
    "",
    " Directory of C:\\WINNT\\system32\\f2kd",
    "",
    entry("      <DIR>          ."),
    entry("      <DIR>          .."),
    entry("                   7 a.txt"),
    entry("                 120 b.txt"),
    entry("               1,200 c.dat"),
    entry("      <DIR>          sub"),
    "               3 File(s)          1,327 bytes",
    directories(3),
    "c.dat",
    "b.txt",
    "a.txt",
    "C:\\WINNT\\system32\\f2kd\\a.txt",
    "C:\\WINNT\\system32\\f2kd\\b.txt",
    "C:\\WINNT\\system32\\f2kd\\c.dat",
    "C:\\WINNT\\system32\\f2kd\\sub",
    "C:\\WINNT\\system32\\f2kd\\sub\\d.txt",
    *HEADING,
    "",
    " Directory of C:\\WINNT\\system32\\f2kd",
    "",
    "[.]            [..]           a.txt          b.txt          c.dat",
    "[sub]",
    "               3 File(s)          1,327 bytes",
    directories(3),
    *HEADING,
    "",
    " Directory of C:\\WINNT\\system32\\f2kd",
    "",
    entry("                   7 a.txt"),
    entry("                 120 b.txt"),
    "               2 File(s)            127 bytes",
    "",
    " Directory of C:\\WINNT\\system32\\f2kd\\sub",
    "",
    entry("                   6 d.txt"),
    "               1 File(s)              6 bytes",
    "",
    "     Total Files Listed:",
    "               3 File(s)            133 bytes",
    directories(0),
    "a.txt",
    "b.txt",
    "c.dat",
    "sub",
    *HEADING,
    "",
    " Directory of C:\\WINNT\\system32\\f2kd",
    "",
    entry("      <DIR>          ."),
    entry("      <DIR>          .."),
    entry("      <DIR>          sub"),
    "               0 File(s)              0 bytes",
    directories(3),
    *HEADING,
    "",
    " Directory of C:\\WINNT\\system32\\f2kx",
    "",
    entry("                   3 longna~1.txt long name.txt"),
    "               1 File(s)              3 bytes",
    directories(0),
    *HEADING,
    "",
    " Directory of C:\\WINNT\\system32\\f2kd",
    "",
    "File Not Found",
    "dir none 1",
    "start wait 4",
    "start 0",
]


def files(directory: Path) -> list[Path]:
    """The script written into `directory`, its lines ended by CR LF."""
    script = directory / "f2kdir.cmd"
    script.write_bytes("".join(f"{line}\r\n" for line in SCRIPT).encode("ascii"))
    return [script, SPAWNKID]


def matches(expected: str | re.Pattern[str], line: str) -> bool:
    if isinstance(expected, str):
        return line == expected
    return expected.fullmatch(line) is not None


@pytest.mark.kernel
def test_dir_and_start(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c` of the script: each listing, each ERRORLEVEL, and the exit code 0."""
    output, code = run_with_c(builder, log_path, boot_timeout, "f2kdir", files(tmp_path))
    differing = [
        (number, expected, line)
        for number, (expected, line) in enumerate(zip(EXPECTED, output), start=1)
        if not matches(expected, line)
    ]
    assert (differing, len(output), code) == ([], len(EXPECTED), 0), "\n".join(output)
