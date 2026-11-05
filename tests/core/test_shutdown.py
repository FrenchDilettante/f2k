"""shutdown - the machine shut down, or restarted, from cmd.exe's prompt, and booted again from the
disk the first boot wrote to.

Each test boots cmd.exe, as tests/core/test_cmd.py's prompt tests do (the kernel through QEMU's
Multiboot loader, a copy of the disk with cmd.exe added to \\WINNT\\system32, no `redirected`
option, keys typed through QMP once the screen's last line reads what each step waits for). The
copy is kept between two boots (`f2kboot.boot`'s `kept`: attached without QEMU's snapshot), and
removed after the test.

The first boot types `echo kept> C:\\KEPT.TXT`, then a `shutdown` command (userland/shutdown, on
the base disk). shutdown.exe enables SeShutdownPrivilege and calls ExitWindowsEx; the console
server stand-in then ends the session: cmd.exe, which has no handler for CTRL_SHUTDOWN_EVENT (its
Ctrl+C handler answers FALSE for any other event), is ended by kernel32's default handler with
STATUS_CONTROL_C_EXIT (3221225786), without the 20 s wait; shutdown.exe, the caller, last (it may
have ended by itself first, with 0). Then NtShutdownSystem's steps on COM1: the volume flushed and
marked clean, the registry's empty flush, and either "It is now safe to turn off your computer.",
alone and centered on the text screen, or the restart, which QEMU's -no-reboot turns into its exit
(the boot's end "reset").

Between the boots the host reads the kept image (`f2kboot.read_volume`): FAT[1]'s clean-shutdown
bit set, FSInfo's free count the FAT's own (and the one COM1 reported), its next-free hint a free
cluster. The second boot types `type C:\\KEPT.TXT` and finds `kept`.

A third test counts down: `shutdown /l /t:2 "Bye now" /y` shows the message and the countdown line
for 2, then 1 second (on COM1, where the console's output is copied, each rewrite after a carriage
return), then shuts down. A fourth stays at the prompt: a no to shutdown's question, and Ctrl+C
during a countdown, each print `Shutdown cancelled.` and leave ERRORLEVEL 1, and the machine keeps
running.

    uv run pytest tests/core/test_shutdown.py
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

import pytest

import f2kboot
from test_cmd import BANNER, CMD, COMMAND_LINE, PROMPT, TIMEOUT, Typist, last_row, rows_of, shown

SAFE_TO_TURN_OFF = "It is now safe to turn off your computer."
# QMP's key codes for the characters the typed lines hold that are not lowercase letters or
# digits (an uppercase letter is typed with Shift).
QCODES = {
    " ": "spc",
    ">": "shift-dot",
    ":": "shift-semicolon",
    "\\": "backslash",
    "/": "slash",
    ".": "dot",
    '"': "shift-apostrophe",
    "%": "shift-5",
}
WRITE = "echo kept> C:\\KEPT.TXT"
FORBIDS = ["KERNEL PANIC", "F2K: object audit FAILED", "CPU EXCEPTION",
           # cmd.exe ends on the event: the session's end never waits it out.
           "F2K: session: process"]
# The session's end: cmd.exe, the boot's program, ended by its default handler. Its teardown audit
# and shutdown.exe's end race the shutdown's steps (the session's end waits for a process's end,
# not its teardown, and passes over a process already leaving its console), so they are not
# ordered against them.
SESSION_END = "F2K: user process exited normally (exit code=3221225786)"
# shutdown.exe's own end, when COM1 shows it: by itself (0), or by the session's end (3221225786)
# if it had not ended by then.
SHUTDOWN_EXE_END = re.compile(r"^F2K: child process \d+ \(shutdown\) exited normally \(exit code=(\d+)\)$",
                              re.IGNORECASE)


def keys_of(text: str) -> list[str]:
    """The chords that type `text` on a US keyboard, then Return."""
    keys = []
    for character in text:
        if character in QCODES:
            keys.append(QCODES[character])
        elif character.isupper():
            keys.append(f"shift-{character.lower()}")
        else:
            keys.append(character)
    return keys + ["ret"]


def machine_end(action: str) -> list[str]:
    """NtShutdownSystem's steps for `action`, in order, up to its end."""
    return [
        f"F2K: shutdown: {action}",
        r"re:^F2K: shutdown: volume flushed \(\d+ clusters free, next free \d+\), marked clean$",
        "F2K: shutdown: registry flushed (no hive on disk)",
        "F2K: shutdown complete",
    ]


class Keys:
    """The boot's `during` step: `steps`, each a wait on the screen's last line (its text, or a
    test of it) and the chords then pressed in turn, taken one after another; a wait is met only by
    a last line on another row or with another text than the step before met. `screens` keeps the
    last screen read."""

    def __init__(self, steps: list[tuple[str | Callable[[str], bool], list[str]]]) -> None:
        self.steps = steps
        self.taken = 0
        self.met: tuple[int, str] | None = None
        self.last: f2kboot.TextScreen | None = None

    def __call__(self, socket: Path, log: str) -> None:
        if self.taken == len(self.steps):
            return
        screen = f2kboot.read_text_screen(socket)
        self.last = screen
        rows = rows_of(screen)
        row = last_row(rows)
        if row is None:
            return
        wait, keys = self.steps[self.taken]
        line = (row, rows[row])
        met = wait(rows[row]) if callable(wait) else rows[row] == wait
        if not met or line == self.met:
            return
        for key in keys:
            f2kboot.qmp_command(socket, [f2kboot.key_events(key, True), f2kboot.key_events(key, False)])
        self.taken += 1
        self.met = line

    def done(self) -> bool:
        return self.taken == len(self.steps)


def failure(what: str, log_path: Path, log: str, keys: Keys | None = None) -> str:
    screen = f"\n--- the screen ---\n{shown(keys.last)}" if keys is not None else ""
    return f"{what}{screen}\nlog: {log_path}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"


def boot_cmd(build: f2kboot.Build, kept: Path, log_path: Path, timeout: float, keys: Keys | Typist,
             done: Callable[[str], bool],
             observe: Callable[[Path], None] | None = None) -> tuple[str, str]:
    """Boot cmd.exe on the kept disk `kept`, typing `keys`, until `done(log)` holds or QEMU exits."""
    return f2kboot.boot(
        f2kboot.Build(build.kernel, kept),
        image="kernel",
        cmdline=COMMAND_LINE,
        memory="256M",
        kept=kept,
        log_path=log_path,
        timeout=timeout,
        done=done,
        during=keys,
        observe=observe,
    )


def flushed_count(log: str) -> int:
    """The free-cluster count the flush's line reports."""
    line = next(line for line in f2kboot.lines_of(log) if line.startswith("F2K: shutdown: volume flushed"))
    return int(line.split("(")[1].split()[0])


def assert_flushed(kept: Path, log: str) -> None:
    """The kept image as the shutdown left it: marked clean, FSInfo's count the FAT's own (and the
    one COM1 reported), its hint a free cluster."""
    volume = f2kboot.read_volume(kept)
    assert volume.clean, f"FAT[1]'s clean-shutdown bit is clear: {volume}"
    assert volume.fsinfo_free == volume.free, f"FSInfo's count is not the FAT's: {volume}"
    assert volume.fsinfo_free == flushed_count(log), f"COM1 reported another count: {volume}"
    assert volume.hint_is_free, f"FSInfo's next-free hint names no free cluster: {volume}"


def assert_file_kept(build: f2kboot.Build, kept: Path, log_path: Path, timeout: float) -> None:
    """The kept disk's next boot: `type C:\\KEPT.TXT` shows what the first boot wrote."""
    second_log = log_path.with_name(f"{log_path.stem}-again.log")
    typist = Typist([(PROMPT, keys_of("type C:\\KEPT.TXT"))])
    log, stopped = boot_cmd(build, kept, second_log, timeout, typist,
                            done=lambda log: typist.screen is not None)
    if typist.screen is None:
        pytest.fail(f"the second boot's prompt never came back (stopped: {stopped})\n--- the screen ---\n"
                    f"{shown(typist.last)}\nlog: {second_log}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}",
                    pytrace=False)
    expected = [BANNER, "", PROMPT + "type C:\\KEPT.TXT", "kept", "", PROMPT]
    assert rows_of(typist.screen) == expected + [""] * (f2kboot.ROWS - len(expected))
    status, detail = f2kboot.Expectation(expects=[], forbids=FORBIDS).check(log)
    assert status == "pass", failure(f"the second boot: {detail}", second_log, log)


@pytest.fixture
def kept(builder, log_path):
    """The build, and a private copy of its disk with cmd.exe added, kept across the test's boots
    and removed after it."""
    build = builder([])
    assert CMD.exists(), f"{CMD} is missing: `make disk` builds and copies it"
    path = f2kboot.disk_with_programs(build, [CMD], f2kboot.WORK / "variants" / f"{log_path.stem}-kept.img")
    try:
        yield build, path
    finally:
        path.unlink(missing_ok=True)


def shut_down(build: f2kboot.Build, disk: Path, log_path: Path, timeout: float, command: str,
              expects: list[str], *, restart: bool) -> tuple[str, list[f2kboot.TextScreen]]:
    """The first boot: the file written, then `command`; its COM1 log once `expects` (in order) and
    shutdown.exe's end have shown, and the screen read then (none for a restart)."""
    keys = Keys([(PROMPT, keys_of(WRITE)), (PROMPT, keys_of(command))])
    expectation = f2kboot.Expectation(expects=expects, ordered=True, forbids=FORBIDS)
    screens: list[f2kboot.TextScreen] = []
    log, stopped = boot_cmd(
        build, disk, log_path, timeout, keys,
        done=(lambda log: False) if restart else (lambda log: expectation.check(log)[0] != "pending"),
        observe=None if restart else (lambda socket: screens.append(f2kboot.read_text_screen(socket))),
    )
    if not keys.done():
        pytest.fail(failure(f"the prompt never took the lines (stopped: {stopped})", log_path, log, keys),
                    pytrace=False)
    status, detail = expectation.check(log)
    if status != "pass" or (restart and stopped != "reset"):
        pytest.fail(failure(f"the shutdown's lines: {status} {detail} (stopped: {stopped})", log_path, log),
                    pytrace=False)
    for line in f2kboot.lines_of(log):
        if (end := SHUTDOWN_EXE_END.match(line)) is not None:
            assert end.group(1) in ("0", "3221225786"), failure(f"shutdown.exe's end: {line}", log_path, log)
    return log, screens


def assert_safe_screen(screens: list[f2kboot.TextScreen]) -> None:
    """The text screen after the halt: the closing line alone, centered on the middle row."""
    (screen,) = screens
    middle = f2kboot.ROWS // 2
    assert screen.text(middle).strip() == SAFE_TO_TURN_OFF
    assert screen.text(middle).index(SAFE_TO_TURN_OFF) == (f2kboot.COLUMNS - len(SAFE_TO_TURN_OFF)) // 2
    assert all(not screen.text(row).strip(" \0") for row in range(f2kboot.ROWS) if row != middle)


@pytest.mark.kernel
def test_a_shutdown_keeps_the_file_on_a_clean_volume(kept, log_path, boot_timeout):
    """`shutdown /l /t:0 /y` after a file is written: the session's end, the shutdown's steps and
    the closing line on COM1 and the screen; the volume clean and its FSInfo the FAT's; the next
    boot finds the file."""
    build, disk = kept
    expects = [*f2kboot.BOOT_CHECKS, "Shutting down QEMU.", SESSION_END, *machine_end("ShutdownNoReboot"),
               SAFE_TO_TURN_OFF]
    log, screens = shut_down(build, disk, log_path, boot_timeout(TIMEOUT), "shutdown /l /t:0 /y", expects,
                             restart=False)
    assert f2kboot.lines_of(log)[-1] == SAFE_TO_TURN_OFF, "the closing line is COM1's last"
    assert_safe_screen(screens)
    assert_flushed(disk, log)
    assert_file_kept(build, disk, log_path, boot_timeout(TIMEOUT))


@pytest.mark.kernel
def test_a_restart_keeps_the_file_and_boots_again(kept, log_path, boot_timeout):
    """`shutdown /l /r /t:0 /y` after a file is written: the session's end, the shutdown's steps,
    the restart line last and QEMU's exit on the reset; the volume clean; the next boot works and
    finds the file."""
    build, disk = kept
    expects = [*f2kboot.BOOT_CHECKS, "Restarting QEMU.", SESSION_END, *machine_end("ShutdownReboot"),
               f2kboot.RESTARTING]
    log, _ = shut_down(build, disk, log_path, boot_timeout(TIMEOUT), "shutdown /l /r /t:0 /y", expects,
                       restart=True)
    assert SAFE_TO_TURN_OFF not in log
    assert_flushed(disk, log)
    assert_file_kept(build, disk, log_path, boot_timeout(TIMEOUT))


@pytest.mark.kernel
def test_a_countdown_shows_the_message_then_shuts_down(kept, log_path, boot_timeout):
    """`shutdown /l /t:2 "Bye now" /y`: the message, the countdown line for 2 seconds then 1, then
    the shutdown, as without a delay."""
    build, disk = kept
    expects = [*f2kboot.BOOT_CHECKS, "re:^Bye now$",
               "Shutting down QEMU in 2 seconds (Ctrl+C cancels)",
               "Shutting down QEMU in 1 second (Ctrl+C cancels)",
               "Shutting down QEMU.", SESSION_END, *machine_end("ShutdownNoReboot"), SAFE_TO_TURN_OFF]
    log, screens = shut_down(build, disk, log_path, boot_timeout(TIMEOUT), 'shutdown /l /t:2 "Bye now" /y',
                             expects, restart=False)
    assert_safe_screen(screens)
    assert_flushed(disk, log)


COUNTING = re.compile(r"^Shutting down QEMU in \d+ seconds \(Ctrl\+C cancels\)$")


@pytest.mark.kernel
def test_no_and_ctrl_c_cancel_the_shutdown(kept, log_path, boot_timeout):
    """A no to the question, then Ctrl+C during the countdown: each prints `Shutdown cancelled.`,
    returns to the prompt with ERRORLEVEL 1, and the machine runs on."""
    build, disk = kept
    question = "Shut down QEMU (Y/N)?"
    keys = Keys([
        (PROMPT, keys_of("shutdown /l /t:0")),
        (question, keys_of("n")),
        (PROMPT, keys_of("echo %errorlevel%")),
        (PROMPT, keys_of("shutdown /l /t:30 /y")),
        (lambda line: COUNTING.match(line) is not None, ["ctrl-c"]),
        (PROMPT, keys_of("echo %errorlevel%")),
        (PROMPT, []),
    ])
    log, stopped = boot_cmd(build, disk, log_path, boot_timeout(TIMEOUT + 20), keys,
                            done=lambda log: keys.done())
    if not keys.done():
        pytest.fail(failure(f"step {keys.taken + 1}'s screen never showed (stopped: {stopped})", log_path, log,
                            keys), pytrace=False)
    rows = rows_of(keys.last)
    expected = [
        BANNER,
        "",
        PROMPT + "shutdown /l /t:0",
        question + " n",
        "Shutdown cancelled.",
        "",
        PROMPT + "echo %errorlevel%",
        "1",
        "",
        PROMPT + "shutdown /l /t:30 /y",
        COUNTING,
        "Shutdown cancelled.",
        "",
        PROMPT + "echo %errorlevel%",
        "1",
        "",
        PROMPT,
    ]
    expected += [""] * (f2kboot.ROWS - len(expected))
    differ = [index for index, (want, row) in enumerate(zip(expected, rows))
              if not (want.match(row) if isinstance(want, re.Pattern) else want == row)]
    assert not differ, failure(f"the screen differs at rows {differ}", log_path, log, keys)
    status, detail = f2kboot.Expectation(expects=[], forbids=[*FORBIDS, "F2K: shutdown", "F2K: user process"]).check(log)
    assert status == "pass", failure(f"the machine did not run on: {detail}", log_path, log)
