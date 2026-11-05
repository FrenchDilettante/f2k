"""cmd - the batch language's control flow in F2K's command interpreter: `goto` and its labels,
`call :label`, `if` and `else`, blocks over several lines, `for` in its forms, and a batch file
run without `call` taking the place of the one that ran it.

Two `/c` boots, as tests/core/test_cmd.py runs them (its helpers, imported): the kernel option
`redirected` sends cmd.exe's output to COM1.

`cmd.exe /c f2kflow` runs F2KFLOW.CMD (FLOW below, beside cmd.exe in \\WINNT\\system32). It goes
to a label ahead of it; loops back to a label behind it until a variable holds three `x`s;
calls a label of its own with arguments, which shifts them and returns with `exit /b 4`; calls it
from a `for` loop; counts with `for /l`; cuts a string into tokens with `for /f`; reads a file's
name and extension through `%%~nx` and `%%~x`; tests `if exist` with `else`, `if not exist` with
a block over several lines, a nested `if /i` and a number compared with GTR, `if defined`, `if
errorlevel` and `if cmdextversion`; reads a command's output with `for /f`; then runs
F2KCHAIN.CMD without `call`. F2KCHAIN.CMD runs itself without `call` 40 times, an `x` more on its
argument each time: each run takes the place of the last, so no nesting limit is reached (the
shell nests 32 batch files), and the line after the chain in F2KFLOW.CMD never runs.

`cmd.exe /c for %a in (1 2) do @echo %a & echo end` runs `for` at the prompt's rules: `%a`, and
the `&` part of the loop's command, so `end` follows each number.

    uv run pytest tests/core/test_cmd_flow.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

from test_cmd import run_with_c

FORTY = "x" * 40
# The batch files the batch test adds beside cmd.exe, by name, their lines ended by CR LF.
FLOW = {
    "f2kflow.cmd": [
        "@echo off",
        "set F2KN=",
        "goto :start",
        "echo never",
        ":again",
        "set F2KN=%F2KN%x",
        'if not "%F2KN%"=="xxx" goto again',
        "echo looped %F2KN%",
        "goto :tests",
        ":start",
        "echo started",
        "goto again",
        ":tests",
        'call :sub one "two three"',
        "echo back %errorlevel%",
        "for %%a in (a b) do call :sub %%a",
        "for /l %%i in (1,2,5) do echo l%%i",
        'for /f "tokens=1,3* delims=," %%a in ("x,y,z,w,v") do echo f [%%a] [%%b] [%%c]',
        "for %%f in (f2kflow.cmd) do echo %%~nxf %%~xf",
        "if exist f2kflow.cmd (echo exists) else echo missing",
        "if not exist f2knope.cmd (",
        "  echo not there",
        "",
        "  echo two lines",
        ") else (",
        "  echo never",
        ")",
        "if /i ABC==abc if 10 GTR 9 echo nested",
        "if defined F2KN (echo defined) else echo undefined",
        "if errorlevel 4 echo four or more",
        "if cmdextversion 2 echo extensions",
        "for /f %%v in ('echo piped out') do echo command [%%v]",
        "f2kchain x",
        "echo never after the chain",
        ":sub",
        "echo sub [%0] [%1] [%~2]",
        "shift",
        "echo shifted [%1]",
        "exit /b 4",
    ],
    "f2kchain.cmd": [
        "@echo off",
        f'if "%1"=="{FORTY}" goto done',
        "f2kchain %1x",
        ":done",
        "echo chained %1",
    ],
}


def flow_files(directory: Path) -> list[Path]:
    """FLOW written into `directory`, their lines ended by CR LF."""
    paths = []
    for name, lines in FLOW.items():
        path = directory / name
        path.write_bytes("".join(f"{line}\r\n" for line in lines).encode("ascii"))
        paths.append(path)
    return paths


@pytest.mark.kernel
def test_a_batch_file_s_control_flow(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c f2kflow`: labels, `call :label`, `if`, blocks, `for`, and a chain of 40 batch files
    each taking the place of the last; the exit code is the last echo's 0."""
    output, code = run_with_c(builder, log_path, boot_timeout, "f2kflow", flow_files(tmp_path))
    assert (output, code) == ([
        "started",
        "looped xxx",
        'sub [:sub] [one] [two three]',
        'shifted ["two three"]',
        "back 4",
        "sub [:sub] [a] []",
        "shifted []",
        "sub [:sub] [b] []",
        "shifted []",
        "l1",
        "l3",
        "l5",
        "f [x] [z] [w,v]",
        "f2kflow.cmd .cmd",
        "exists",
        "not there",
        "two lines",
        "nested",
        "defined",
        "four or more",
        "extensions",
        "command [piped]",
        f"chained {FORTY}",
    ], 0), "\n".join(output)


@pytest.mark.kernel
def test_for_at_the_prompt_s_rules(builder, log_path, boot_timeout):
    """`cmd /c for %a in (1 2) do @echo %a & echo end`: the loop's command holds the `&` after it,
    `@` hides each pass's echo, and the exit code is 0."""
    output, code = run_with_c(builder, log_path, boot_timeout,
                              "for %a in (1 2) do @echo %a & echo end", [])
    assert (output, code) == (["1 ", "end", "2 ", "end"], 0), "\n".join(output)
