"""cmd - `cmd /u`'s Unicode output, and the `%~s` and `%~t` modifiers, booted.

One boot runs `cmd.exe /c f2kuni` (as tests/core/test_cmd.py's `/c` boots do, with the kernel
option `redirected`, so that its output reaches COM1). The script and its helpers are added beside
cmd.exe in \\WINNT\\system32, the current directory, with spawnkid.exe (the spawn fixture's
companion) and a data file, f2kansi.txt, holding `caf` and the OEM code page's e acute, then CR LF.
The script runs shells of its own, each writing into f2kuni.bin, and `call f2ksize f2kuni.bin`
shows the bytes written (`%~z1`):

- `cmd /u /c echo one`: `one` CR LF as UTF-16LE without a byte-order mark, 10 bytes (as
  tests/cmd/batstd's capture shows); typed back, its bytes reach COM1 as they are, between the
  `[` and `]` the script echoes around them;
- `/a` writes the 5 bytes of `one` CR LF, and the last of `/u` and `/a` counts;
- `set`'s listing (`F2KU=x` CR LF) is 16 bytes, `type` of the 6-byte OEM file 12 bytes (each byte
  read in the OEM code page), and `type`'s message on the standard error for a missing file
  (`The system cannot find the file specified.` CR LF) 88 bytes;
- a program a `cmd /u` runs writes its own way: spawnkid's line, `kid: to the standard output` CR
  LF, is 29 bytes.

Then `echo x> "f2k long name.txt"` makes a file with a long name, and `call f2kmod` shows its
`%~s1` (its full path with each long name replaced by the 8.3 name the volume gave it), `%~snx1`,
`%~nx1` and `%~t1`, the time it was written (`11/05/2026 06:31 PM`, matched as a pattern).

    uv run pytest tests/core/test_cmd_unicode.py
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_cmd import SPAWNKID, run_with_c

SCRIPT = [
    "@echo off",
    "set F2KU=x",
    "cmd /u /c echo one> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "echo [",
    "type f2kuni.bin",
    "echo ]",
    "cmd /a /c echo one> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "cmd /u /a /c echo one> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "cmd /a /u /c echo one> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "cmd /u /c set F2KU> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "cmd /u /c type f2kansi.txt> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "cmd /u /c type f2knone.txt 2> f2kuni.bin",
    "call f2ksize f2kuni.bin",
    "cmd /u /c spawnkid out> f2kuni.bin 2> nul",
    "call f2ksize f2kuni.bin",
    'echo x> "f2k long name.txt"',
    'call f2kmod "f2k long name.txt"',
    "del f2kuni.bin",
    'del "f2k long name.txt"',
]

HELPERS = {
    "f2ksize.cmd": ["@echo %~nx1 %~z1"],
    "f2kmod.cmd": ["@echo %~s1", "@echo %~snx1", "@echo %~nx1", "@echo %~t1"],
}

# What COM1 shows. The UTF-16LE bytes typed back split into lines at their CR and LF, each NUL
# after them starting the next line.
EXPECTED = [
    "f2kuni.bin 10",
    "[",
    "o\0n\0e\0",
    "\0",
    "\0]",
    "f2kuni.bin 5",
    "f2kuni.bin 5",
    "f2kuni.bin 10",
    "f2kuni.bin 16",
    "f2kuni.bin 12",
    "f2kuni.bin 88",
    "f2kuni.bin 29",
    "C:\\WINNT\\system32\\F2KLON~1.TXT",
    "F2KLON~1.TXT",
    "f2k long name.txt",
]

# `%~t1`: the US date, then the time on a 12-hour clock without seconds.
WRITTEN = re.compile(r"^\d\d/\d\d/\d{4} \d\d:\d\d [AP]M$")


def files(directory: Path) -> list[Path]:
    """The script, its helpers and its data file written into `directory`, lines ended by CR LF."""
    paths = []
    for name, lines in {"f2kuni.cmd": SCRIPT, **HELPERS}.items():
        path = directory / name
        path.write_bytes("".join(f"{line}\r\n" for line in lines).encode("ascii"))
        paths.append(path)
    data = directory / "f2kansi.txt"
    data.write_bytes(b"caf\x82\r\n")
    return [*paths, data]


@pytest.mark.kernel
def test_unicode_output_and_the_short_name_and_time(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c` of the script: the bytes each shell wrote, the long name's short forms and its
    time, and the exit code 0."""
    output, code = run_with_c(builder, log_path, boot_timeout, "f2kuni",
                              [*files(tmp_path), SPAWNKID])
    assert (output[:-1], code) == (EXPECTED, 0), "\n".join(map(repr, output))
    assert WRITTEN.match(output[-1]), repr(output[-1])
