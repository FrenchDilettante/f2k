"""cmd - `set /a` and `set /p`, booted.

One boot runs `cmd.exe /c f2kseta.cmd & echo Carol| f2kpipe.cmd & set /a 6*7 & echo.` (as
tests/core/test_cmd.py's `/c` boots do, with the kernel option `redirected`, so that its output
and error reach COM1). The batch files and two data files are added beside cmd.exe in
\\WINNT\\system32, the current directory.

f2kseta.cmd evaluates expressions, which print nothing in a batch file, and shows the variables
they assigned with `echo`:

- several assignments a comma separates, a variable read by its name, hexadecimal and octal
  numbers;
- `%%` for the remainder in a batch file, the shift in quotes, and the precedence `set /?` lists;
- 2147483647 + 1 wrapping to -2147483648;
- each error's message (on the standard error) and the ERRORLEVEL it leaves;
- `set /p` with its input from a file (the prompt printed without a line break, the line's CR LF
  dropped, and the ERRORLEVEL 0, as a `set` that succeeds leaves it in a `.cmd` file), then from
  an empty file, which leaves the variable as it was and the ERRORLEVEL 1.

`echo Carol| f2kpipe.cmd` runs f2kpipe.cmd in a shell of its own, its standard input the pipe:
its `set /p` reads `Carol`. Last, `set /a 6*7` outside a batch file prints 42, without a line
break (`echo.` ends its line), and the exit code is the last command's return code, 0.

    uv run pytest tests/core/test_cmd_seta.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

from test_cmd import run_with_c

SETA = [
    "@echo off",
    "set /a F2KA=6*7, F2KB=F2KA+0x10-010",
    "echo a=%F2KA% b=%F2KB%",
    'set /a "F2KC=(1+2)*3 %% 4 << 2 | 1"',
    "echo c=%F2KC%",
    "set /a F2KD=2147483647+1",
    "echo d=%F2KD%",
    "set /a F2KE=-F2KB / 4, F2KE*=~0",
    "echo e=%F2KE%",
    "set /a 1/0",
    "echo divide %errorlevel%",
    "set /a 08",
    "echo invalid %errorlevel%",
    "set /a (1",
    "echo unbalanced %errorlevel%",
    "set /a 1 2",
    "echo operator %errorlevel%",
    "set /a 1+",
    "echo operand %errorlevel%",
    "set /p F2KP=Name? < f2kin.txt",
    "echo [%F2KP%] %errorlevel%",
    "set /p F2KP=Again? < f2kempty.txt",
    "echo [%F2KP%] %errorlevel%",
]

PIPE = [
    "@echo off",
    "set /p F2KQ=Who? ",
    "echo [%F2KQ%]",
]

EXPECTED = [
    "a=42 b=50",
    "c=5",
    "d=-2147483648",
    "e=12",
    "Divide by zero error.",
    "divide 1073750993",
    "Invalid number.  Numeric constants are either decimal (17), hexadecimal (0x11), or octal "
    "(021).",
    "invalid 1073750991",
    "Unbalanced parenthesis.",
    "unbalanced 1073750988",
    "Missing operator.",
    "operator 1073750990",
    "Missing operand.",
    "operand 1073750989",
    "Name? [Bob] 0",
    "Again? [Bob] 1",
    "Who? [Carol]",
    "42",
]


def files(directory: Path) -> list[Path]:
    """The batch files and their data files written into `directory`, lines ended by CR LF."""
    written = []
    for name, lines in [("f2kseta.cmd", SETA), ("f2kpipe.cmd", PIPE)]:
        path = directory / name
        path.write_bytes("".join(f"{line}\r\n" for line in lines).encode("ascii"))
        written.append(path)
    data = directory / "f2kin.txt"
    data.write_bytes(b"Bob\r\nnever read\r\n")
    empty = directory / "f2kempty.txt"
    empty.write_bytes(b"")
    return [*written, data, empty]


@pytest.mark.kernel
def test_set_a_and_set_p(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c` of the script, a pipe into the second, and `set /a` at the end: what they print,
    and the exit code 0."""
    output, code = run_with_c(builder, log_path, boot_timeout,
                              "f2kseta.cmd & echo Carol| f2kpipe.cmd & set /a 6*7 & echo.",
                              files(tmp_path))
    assert (output, code) == (EXPECTED, 0)
