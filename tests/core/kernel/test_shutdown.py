"""shutdown - the kernel's shutdown on the machine: NtShutdownSystem's own path, run by the kernel
options `shutdown` (ShutdownNoReboot) and `reboot` (ShutdownReboot) once the boot's program has
ended, on a kept copy of the disk the program wrote to.

The program is fswrite's write section, which creates, writes, truncates and grows files: its first
change marks the volume dirty and makes FSInfo's hints unknown. The shutdown then closes the volume
to changes, counts its free clusters, writes them and the next-free hint to FSInfo, marks the
volume clean, and either halts on "It is now safe to turn off your computer." (on the text screen,
centered, and on COM1) or restarts the machine through the keyboard controller, which QEMU's
-no-reboot turns into its exit. The host then reads the kept image: FAT[1]'s clean bit set, FSInfo's
count the FAT's own and its hint a free cluster. After the restart, the same disk boots again.

    uv run pytest tests/core/kernel/test_shutdown.py
"""
from __future__ import annotations

import pytest

import f2kboot

PROGRAM = "CORPUS\\fswrite.exe write"
TIMEOUT = 60.0
FORBIDS = ["KERNEL PANIC", "F2K: object audit FAILED", "CPU EXCEPTION"]


def shutdown(action: str) -> list[str]:
    """The program's run, then the shutdown's steps for `action` up to its end, in order."""
    return [
        "F2K Booted Successfully",
        "F2K: frame database audit: ok",
        "F2K: entering ring 3",
        "fswrite: done",
        "F2K: user process exited normally (exit code=0)",
        "F2K: teardown audit: frame database ok",
        f"F2K: shutdown: {action}",
        r"re:^F2K: shutdown: volume flushed \(\d+ clusters free, next free \d+\), marked clean$",
        "F2K: shutdown: registry flushed (no hive on disk)",
        "F2K: shutdown complete",
    ]


SAFE_TO_TURN_OFF = "It is now safe to turn off your computer."


def kept_path(log_path):
    """The kept disk's path: among the disk variants, which the next run prunes if a killed test
    left it."""
    return f2kboot.WORK / "variants" / f"{log_path.stem}-kept.img"


def flushed_count(log: str) -> int:
    """The free-cluster count the flush's line reports."""
    line = next(line for line in f2kboot.lines_of(log) if line.startswith("F2K: shutdown: volume flushed"))
    return int(line.split("(")[1].split()[0])


def assert_flushed(kept, log: str) -> None:
    """The kept image as the flush left it: marked clean, FSInfo's count the FAT's own (and the
    one COM1 reported), its hint a free cluster."""
    volume = f2kboot.read_volume(kept)
    assert volume.clean, f"FAT[1]'s clean-shutdown bit is clear: {volume}"
    assert volume.fsinfo_free == volume.free, f"FSInfo's count is not the FAT's: {volume}"
    assert volume.fsinfo_free == flushed_count(log), f"COM1 reported another count: {volume}"
    assert volume.hint_is_free, f"FSInfo's next-free hint names no free cluster: {volume}"


def failure(what: str, why: str, log_path, log: str) -> str:
    return f"{what}\n{why}\nlog: {log_path}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"


def test_a_shutdown_flushes_the_volume_and_halts(builder, log_path, boot_timeout):
    """ShutdownNoReboot after a program wrote to the volume: the steps on COM1, the closing line
    centered on the text screen and last on COM1, then the processor halts; the kept image is clean
    and its FSInfo matches its FAT."""
    build = builder([])
    expectation = f2kboot.Expectation(expects=[*shutdown("ShutdownNoReboot"), SAFE_TO_TURN_OFF], ordered=True,
                                      forbids=FORBIDS)
    screens = []
    with f2kboot.kept_disk(build, kept_path(log_path)) as kept:
        log, stopped = f2kboot.boot(
            build, image="kernel", cmdline=PROGRAM, kernel_options="shutdown", kept=kept,
            log_path=log_path, timeout=boot_timeout(TIMEOUT),
            done=lambda log: expectation.check(log)[0] != "pending",
            observe=lambda socket: screens.append(f2kboot.read_text_screen(socket)),
        )
        status, detail = expectation.check(log)
        if status != "pass":
            pytest.fail(failure("the shutdown's lines", f"{status} ({stopped}): {detail}", log_path, log),
                        pytrace=False)
        assert f2kboot.lines_of(log)[-1] == SAFE_TO_TURN_OFF, "the closing line is COM1's last"
        (screen,) = screens
        middle = f2kboot.ROWS // 2
        assert screen.text(middle).strip() == SAFE_TO_TURN_OFF
        assert screen.text(middle).index(SAFE_TO_TURN_OFF) == (f2kboot.COLUMNS - len(SAFE_TO_TURN_OFF)) // 2
        assert all(not screen.text(row).strip() for row in range(f2kboot.ROWS) if row != middle)
        assert_flushed(kept, log)


def test_a_restart_flushes_the_volume_and_ends_qemu(builder, log_path, boot_timeout):
    """ShutdownReboot after a program wrote to the volume: the same steps, then the restart line
    last, and QEMU exits on the reset (its -no-reboot); the kept image is clean and its FSInfo
    matches its FAT, and the disk boots again."""
    build = builder([])
    expectation = f2kboot.Expectation(expects=[*shutdown("ShutdownReboot"), f2kboot.RESTARTING], ordered=True,
                                      forbids=[*FORBIDS, SAFE_TO_TURN_OFF])
    with f2kboot.kept_disk(build, kept_path(log_path)) as kept:
        log, stopped = f2kboot.boot(
            build, image="kernel", cmdline=PROGRAM, kernel_options="reboot", kept=kept,
            log_path=log_path, timeout=boot_timeout(TIMEOUT), done=lambda log: False,
        )
        status, detail = expectation.check(log)
        if stopped != "reset" or status != "pass":
            pytest.fail(failure("the restart's lines, then QEMU's exit",
                                f"stopped: {stopped}; lines: {status} {detail}", log_path, log),
                        pytrace=False)
        assert_flushed(kept, log)

        again = f2kboot.Expectation(
            expects=["F2K Booted Successfully", "F2K: user process exited normally (exit code=0)"],
            ordered=True, forbids=FORBIDS)
        second_log = log_path.with_name(f"{log_path.stem}-again.log")
        log, stopped = f2kboot.boot(build, image="kernel", kept=kept, log_path=second_log,
                                    timeout=boot_timeout(TIMEOUT),
                                    done=lambda log: again.check(log)[0] != "pending")
        status, detail = again.check(log)
        if status != "pass":
            pytest.fail(failure("the kept disk's second boot", f"{status} ({stopped}): {detail}",
                                second_log, log), pytrace=False)
