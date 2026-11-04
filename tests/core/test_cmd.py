"""cmd - F2K's command interpreter, driven from the keyboard: lines typed at its prompt, and the
screen read as Windows 2000's cmd would leave it.

Each boot is the kernel through QEMU's Multiboot loader, its command line running
`WINNT\\system32\\cmd.exe`, with a QMP socket beside it. The disk the tests boot leaves cmd.exe
out, so each boot attaches a copy of it with the built cmd.exe added to \\WINNT\\system32
(`f2kboot.disk_with_programs`, removed after the boot). No `redirected` kernel option: the console
draws on the VGA text screen, which is read through QMP while QEMU runs.

The prompt is `C:\\WINNT\\system32>` (the first process's current directory is its image's, in the
case the command line gives it). A boot types its lines step by step, each step's keys pressed
once (through QMP) when the screen's last line reads what the step waits for, on a row or with a
text the step before did not see; the boot stops once a prompt shows below the last step's, and
the text screen must then read, row by row, its trailing blanks dropped, as each test says, the
rest of it blank.

`pwd` Return: the console echoes the line, cmd starts pwd.exe from the system directory, pwd
prints the current directory, and cmd prompts again after an empty line:

    F2K [Version 5.00.2195]

    C:\\WINNT\\system32>pwd
    C:\\WINNT\\system32

    C:\\WINNT\\system32>

The built-ins: `set F2KX=hello` sets a variable; `echo %F2KX% %NOPE%` prints its value, the
undefined `%NOPE%` kept as it is typed; `ab` then Ctrl+C abandons the line, which the console
leaves as it echoed it, and cmd prompts on the row below it, with no empty line between; `ver`
prints an empty line, then the version:

    F2K [Version 5.00.2195]

    C:\\WINNT\\system32>set F2KX=hello

    C:\\WINNT\\system32>echo %F2KX% %NOPE%
    hello %NOPE%

    C:\\WINNT\\system32>ab
    C:\\WINNT\\system32>ver

    F2K [Version 5.00.2195]

    C:\\WINNT\\system32>

A batch file typed at the prompt: `f2kbat x` runs F2KBAT.CMD (BATCHES below, added to
\\WINNT\\system32 beside cmd.exe), found in the current directory with PATHEXT's `.CMD`. Its
`@echo off` hides its lines, `call` runs F2KSUB.CMD and comes back, and `exit /b 4` ends it; the
prompt comes back as it was before the batch turned echo off, and `%errorlevel%` is 4:

    F2K [Version 5.00.2195]

    C:\\WINNT\\system32>f2kbat x
    first x
    all x
    in f2ksub.cmd sub
    back 2

    C:\\WINNT\\system32>echo %errorlevel%
    4

    C:\\WINNT\\system32>

Two boots run cmd.exe with `/c` and the kernel option `redirected`, so that its output reaches
COM1 as a corpus program's does: `cmd.exe /c echo hi` prints `hi` and ends with 0;
`cmd.exe /c f2kbat one "two three"` prints the batch's lines and ends with 0: `/c` ends with the
last command's return code, and `exit /b 4` sets the ERRORLEVEL to 4 but returns 0 (as
tests/cmd/batexit's capture shows).

Four more `/c` boots run lines of commands, with the spawn fixture's companion (spawnkid.exe)
beside cmd.exe: `echo` redirected into a file and appended to it, then `type` of it back, a
program's standard error into a file and its output into nul; a built-in piped into a program (the
built-in in a `cmd /c` of its own) and a program's `2>&1` down a pipe; `&&` and `||` deciding by
the return code, and `^&`; and `echo ver| cmd`, a shell reading its commands from a pipe.

    uv run pytest tests/core/test_cmd.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

import f2kboot

COMMAND_LINE = r"WINNT\system32\cmd.exe"
# The batch files the batch tests add beside cmd.exe, by name, their lines ended by CR LF.
BATCHES = {
    "f2kbat.cmd": [
        "@echo off",
        "rem the batch file cmd's tests run",
        "echo first %1",
        "echo all %*",
        "call f2ksub.cmd sub",
        "echo back %errorlevel%",
        "exit /b 4",
        "echo never",
    ],
    "f2ksub.cmd": [
        "echo in %0 %~1",
        "exit /b 2",
    ],
}
CMD = f2kboot.BUILT_PROGRAMS / "cmd.exe"
PROMPT = "C:\\WINNT\\system32>"
BANNER = "F2K [Version 5.00.2195]"
# How long the boot may take to reach the first prompt and its lines to run.
TIMEOUT = 30.0
# QMP's key codes for the characters typed that are not lowercase letters or digits.
QCODES = {" ": "spc", "=": "equal", "%": "shift-5"}


def keys_of(text: str) -> list[str]:
    """The chords that type `text` on a US keyboard."""
    keys = []
    for character in text:
        if character in QCODES:
            keys.append(QCODES[character])
        elif character.isupper():
            keys.append(f"shift-{character.lower()}")
        else:
            keys.append(character)
    return keys


def line_of(text: str) -> list[str]:
    """The chords that type `text`, then Return."""
    return keys_of(text) + ["ret"]


def rows_of(screen: f2kboot.TextScreen) -> list[str]:
    """The text screen's rows, their trailing blanks dropped."""
    return [screen.text(row).rstrip(" \0") for row in range(f2kboot.ROWS)]


def last_row(rows: list[str]) -> int | None:
    """The index of the last row holding anything, None for a blank screen."""
    return next((index for index in reversed(range(len(rows))) if rows[index]), None)


class Typist:
    """The boot's `during` step: `steps`, each the screen's last line to wait for and the chords
    then pressed and released in turn, taken one after another; a step's wait is met only by a
    last line on another row or with another text than the step before met. Once the steps are
    done, a prompt on a row below the last step's ends the boot, its screen kept (`screen`)."""

    def __init__(self, steps: list[tuple[str, list[str]]]) -> None:
        self.steps = steps
        self.taken = 0
        self.met: tuple[int, str] | None = None
        self.screen: f2kboot.TextScreen | None = None
        self.last: f2kboot.TextScreen | None = None

    def __call__(self, socket: Path, log: str) -> None:
        if self.screen is not None:
            return
        screen = f2kboot.read_text_screen(socket)
        self.last = screen
        rows = rows_of(screen)
        row = last_row(rows)
        if row is None:
            return
        line = (row, rows[row])
        if self.taken == len(self.steps):
            if rows[row] == PROMPT and self.met is not None and row > self.met[0]:
                self.screen = screen
            return
        wait, keys = self.steps[self.taken]
        if rows[row] != wait or line == self.met:
            return
        for key in keys:
            f2kboot.qmp_command(socket, [f2kboot.key_events(key, True),
                                         f2kboot.key_events(key, False)])
        self.taken += 1
        self.met = line


def shown(screen: f2kboot.TextScreen | None) -> str:
    if screen is None:
        return "(never read)"
    rows = rows_of(screen)
    end = last_row(rows)
    return "\n".join(rows[:(end or 0) + 1])


def batch_files(directory: Path) -> list[Path]:
    """BATCHES written into `directory`, their lines ended by CR LF."""
    paths = []
    for name, lines in BATCHES.items():
        path = directory / name
        path.write_bytes("".join(f"{line}\r\n" for line in lines).encode("ascii"))
        paths.append(path)
    return paths


def disk_with_cmd(builder, log_path, extra: list[Path]) -> tuple[f2kboot.Build, Path]:
    """The build, and a copy of its disk with cmd.exe and `extra` in \\WINNT\\system32."""
    build = builder([])
    assert CMD.exists(), f"{CMD} is missing: `make disk` builds and copies it"
    variant = f2kboot.disk_with_programs(build, [CMD, *extra],
                                         f2kboot.WORK / "variants" / f"{log_path.stem}.img")
    return build, variant


def run_with_c(builder, log_path, boot_timeout, string: str,
               extra: list[Path]) -> tuple[list[str], int | None]:
    """Boot `cmd.exe /c <string>` with the kernel option `redirected` (its output on COM1, as a
    corpus program's): its output lines and exit code."""
    build, variant = disk_with_cmd(builder, log_path, extra)
    try:
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=f"{COMMAND_LINE} /c {string}",
            kernel_options=f2kboot.REDIRECTED_OPTION,
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(TIMEOUT),
            done=f2kboot.process_ended,
        )
    finally:
        variant.unlink(missing_ok=True)
    if not f2kboot.process_ended(log):
        pytest.fail(f"cmd.exe never ended (stopped: {stopped})\nlog: {log_path}\n"
                    f"--- COM1 (tail) ---\n{f2kboot.tail(log)}", pytrace=False)
    return f2kboot.program_output(log)


def type_at_the_prompt(builder, log_path, boot_timeout, steps: list[tuple[str, list[str]]],
                       screen: list[str], extra: list[Path] | None = None) -> None:
    """Boot into cmd.exe (`extra` files beside it), take `steps`, and check the screen the last
    prompt shows on."""
    build, variant = disk_with_cmd(builder, log_path, extra or [])
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
    if typist.taken == 0:
        pytest.fail(f"the first prompt never showed (stopped: {stopped}){context}", pytrace=False)
    if typist.taken < len(steps):
        pytest.fail(f"step {typist.taken + 1}'s screen never showed: its last line "
                    f"{steps[typist.taken][0]!r} (stopped: {stopped}){context}", pytrace=False)
    if typist.screen is None:
        pytest.fail(f"the prompt never came back after the last step (stopped: {stopped}){context}",
                    pytrace=False)
    rows = rows_of(typist.screen)
    expected = screen + [""] * (f2kboot.ROWS - len(screen))
    assert rows == expected, f"the screen differs{context}"


@pytest.mark.kernel
def test_pwd_at_the_prompt(builder, log_path, boot_timeout):
    """`pwd` Return at cmd's prompt: the banner, the line typed, pwd's output, and the next prompt,
    the rest of the screen blank."""
    type_at_the_prompt(builder, log_path, boot_timeout, [(PROMPT, line_of("pwd"))], [
        BANNER,
        "",
        PROMPT + "pwd",
        "C:\\WINNT\\system32",
        "",
        PROMPT,
    ])


@pytest.mark.kernel
def test_built_ins_and_ctrl_c(builder, log_path, boot_timeout):
    """`set`, `echo` with a variable and an undefined one, a line Ctrl+C abandons, then `ver`."""
    type_at_the_prompt(builder, log_path, boot_timeout, [
        (PROMPT, line_of("set F2KX=hello")),
        (PROMPT, line_of("echo %F2KX% %NOPE%")),
        (PROMPT, keys_of("ab")),
        (PROMPT + "ab", ["ctrl-c"]),
        (PROMPT, line_of("ver")),
    ], [
        BANNER,
        "",
        PROMPT + "set F2KX=hello",
        "",
        PROMPT + "echo %F2KX% %NOPE%",
        "hello %NOPE%",
        "",
        PROMPT + "ab",
        PROMPT + "ver",
        "",
        BANNER,
        "",
        PROMPT,
    ])


@pytest.mark.kernel
def test_a_batch_file_at_the_prompt(builder, log_path, boot_timeout, tmp_path):
    """A batch file's name typed at the prompt: its output, the prompt back as it was, and the
    ERRORLEVEL its `exit /b` left."""
    type_at_the_prompt(builder, log_path, boot_timeout, [
        (PROMPT, line_of("f2kbat x")),
        (PROMPT, line_of("echo %errorlevel%")),
    ], [
        BANNER,
        "",
        PROMPT + "f2kbat x",
        "first x",
        "all x",
        "in f2ksub.cmd sub",
        "back 2",
        "",
        PROMPT + "echo %errorlevel%",
        "4",
        "",
        PROMPT,
    ], extra=batch_files(tmp_path))


@pytest.mark.kernel
def test_c_runs_a_command(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c echo hi`: no banner, `hi`, and the exit code 0."""
    output, code = run_with_c(builder, log_path, boot_timeout, "echo hi", [])
    assert (output, code) == (["hi"], 0)


@pytest.mark.kernel
def test_c_runs_a_batch_file(builder, log_path, boot_timeout, tmp_path):
    """`cmd /c` of a batch file: its arguments, `call` of another, and the exit code 0, `exit /b
    4`'s return code (its 4 is the ERRORLEVEL's, not the return code's)."""
    output, code = run_with_c(builder, log_path, boot_timeout, 'f2kbat one "two three"',
                              batch_files(tmp_path))
    assert (output, code) == ([
        "first one",
        'all one "two three"',
        "in f2ksub.cmd sub",
        "back 2",
    ], 0)


# The spawn fixture's companion, which the redirection boots add beside cmd.exe: `spawnkid out`
# writes a line to its standard output, then one to its standard error; `spawnkid read` reads its
# standard input once and prints what it read.
SPAWNKID = f2kboot.REPO_ROOT / "tests" / "kernel32" / "spawn" / "spawnkid.exe"


@pytest.mark.kernel
def test_c_redirects_and_types_back(builder, log_path, boot_timeout):
    """`cmd /c` of a line of commands `&` joins, redirected: `echo` into a new file, then appended
    to it, `type` of it back (the blank before `&` is echo's text, as on Windows); a program's
    standard error into a file of its own and its standard output into nul; a command not
    recognized, its message into nul; and the exit code 0."""
    string = ("echo one> f2kred.txt & echo two>>f2kred.txt & type f2kred.txt"
              " & spawnkid out 2> f2kerr.txt > nul & type f2kerr.txt"
              " & f2knope 2> nul || echo f2knope failed")
    output, code = run_with_c(builder, log_path, boot_timeout, string, [SPAWNKID])
    assert (output, code) == ([
        "one ",
        "two ",
        "kid: to the standard error",
        "f2knope failed",
    ], 0)


@pytest.mark.kernel
def test_c_pipes_into_a_program(builder, log_path, boot_timeout):
    """`cmd /c echo piped line| spawnkid read`: echo, a built-in, runs in a `cmd /c` of its own,
    its output through a pipe into spawnkid's one read; the pipeline ends with spawnkid's code,
    and `2>&1` sends the program's standard error down the pipe after its output."""
    output, code = run_with_c(builder, log_path, boot_timeout,
                              "echo piped line| spawnkid read & spawnkid out 2>&1 | spawnkid read",
                              [SPAWNKID])
    assert (output, code) == ([
        "kid: read: ret=1 err=- [piped line]",
        "kid: read: ret=1 err=- [kid: to the standard output]",
    ], 0)


@pytest.mark.kernel
def test_c_runs_on_success_or_failure(builder, log_path, boot_timeout):
    """`&&` runs its second command when the first succeeds, `||` when it fails; a `^` makes `&`
    text; and `/c` ends with the last command's return code: a `type` of a missing file fails with
    1, `||` runs the echo, which returns 0."""
    string = ("ver > nul && echo and ran || echo or skipped & type f2knone.txt 2> nul"
              " && echo and skipped || echo or ran & echo a ^& b")
    output, code = run_with_c(builder, log_path, boot_timeout, string, [])
    assert (output, code) == (["and ran ", "or ran ", "a & b"], 0)



@pytest.mark.kernel
def test_commands_from_a_pipe(builder, log_path, boot_timeout):
    """`echo ver| cmd`: a cmd.exe whose standard input is a pipe reads its commands from it, each
    line echoed after the prompt as the console would have echoed it, and ends at the input's end,
    after its last prompt, with 0."""
    output, code = run_with_c(builder, log_path, boot_timeout, "echo ver| cmd", [])
    # The last prompt ends no line: COM1's next line (the kernel's, of the child's end) follows it.
    assert (output[:6], code) == ([BANNER, "", PROMPT + "ver", "", BANNER, ""], 0), \
        "\n".join(output)
    assert len(output) == 7 and output[6].startswith(PROMPT), "\n".join(output)
