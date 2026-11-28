"""Checks on the harness's own judgements: the logs, the build stamps, the boots' QEMU and where
they read their disk, the kept disks and the host's read of their volume."""
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import zlib
from types import SimpleNamespace
from typing import Callable

import pytest

import f2kboot

ENDED = [
    "F2K: entering ring 3",
    "hello",
    "F2K: user process exited normally (exit code=0)",
]
CLEAN = "F2K: teardown audit: frame database ok"
LEAKED = "F2K: teardown audit FAILED: 1234 frames available, 1240 before the process (frame database ok)"


def test_a_clean_teardown_passes():
    assert f2kboot.teardown_problem(ENDED + [CLEAN]) is None
    assert f2kboot.teardown_audited("\n".join(ENDED + [CLEAN]))


def test_a_failed_teardown_audit_is_the_failure():
    assert f2kboot.teardown_problem(ENDED + [LEAKED]) == LEAKED


def test_an_object_leak_is_the_failure():
    leak = "F2K: object audit FAILED: 1 objects or file records outlived their process"
    assert f2kboot.teardown_problem(ENDED + [leak, CLEAN]) == leak


def test_a_missing_teardown_audit_fails():
    assert f2kboot.teardown_problem(ENDED) == "the process ended, but its teardown audit never arrived"
    assert not f2kboot.teardown_audited("\n".join(ENDED))


def test_a_fault_during_teardown_is_named():
    lines = ENDED + ["CPU EXCEPTION: page fault (vector 14)"]
    assert f2kboot.teardown_problem(lines) == "the teardown faulted: CPU EXCEPTION: page fault (vector 14)"


def test_a_suite_legs_audit_line_counts():
    assert f2kboot.teardown_audited("F2K: process 3 teardown audit: frame database ok")


# --- Batches: a fixture's blocks in one boot, each judged on its own part of the log -------------

BATCH_BOOT = [*f2kboot.BOOT_CHECKS, "F2K: command line: CORPUS\\t.exe a ;; CORPUS\\t.exe b ;; CORPUS\\t.exe c"]


def leg(index: int, command: str, output: str, code: int = 0) -> list[str]:
    return [f"F2K: process {index} of 3: CORPUS\\{command}", "F2K: entering ring 3", output,
            f"F2K: process {index} (t) exited normally (exit code={code})",
            f"F2K: process {index} teardown audit: frame database ok"]


def batch_of(lines: list[str], stopped: str = "done") -> f2kboot.Batch:
    log = "\n".join(lines) + "\n"
    return f2kboot.Batch(["t.exe a", "t.exe b", "t.exe c"], log, f2kboot.WORK / "logs" / "t.log", stopped,
                         *f2kboot.split_programs(log))


def test_each_block_is_judged_on_its_own_part_of_the_batch():
    batch = batch_of(BATCH_BOOT + leg(1, "t.exe a", "A") + leg(2, "t.exe b", "B", code=3) + leg(3, "t.exe c", "C")
                     + ["F2K: process suite complete: 3 run, 0 faulted, 0 leaks"])
    assert [command for command, _ in batch.programs] == ["CORPUS\\t.exe a", "CORPUS\\t.exe b", "CORPUS\\t.exe c"]
    assert batch.verdict(0, [], f2kboot.Block("t.exe a", ["A"], 0)) is None
    assert batch.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 3)) is None
    assert batch.verdict(2, [], f2kboot.Block("t.exe c", ["B"], 0)) == "line 1: [C], expected [B]"
    # A block whose part is another's (the order went wrong) is not compared at all.
    assert "where [CORPUS\\t.exe c] was expected" in batch.verdict(1, [], f2kboot.Block("t.exe c", ["C"], 0))


def test_a_boot_that_stops_fails_its_block_and_leaves_the_rest_not_run():
    batch = batch_of(BATCH_BOOT + leg(1, "t.exe a", "A")
                     + ["F2K: process 2 of 3: CORPUS\\t.exe b", "KERNEL PANIC: at kernel/src/x.rs"])
    assert batch.verdict(0, [], f2kboot.Block("t.exe a", ["A"], 0)) is None
    assert batch.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 0)).startswith("KERNEL PANIC")
    assert batch.stopped_in() == "t.exe b"
    assert batch.verdict(2, [], f2kboot.Block("t.exe c", ["C"], 0)) == "not run: the boot stopped in t.exe b (done)"
    # A boot that never reached its first program fails that one on the boot's own lines.
    early = batch_of(["F2K Booted Successfully"], stopped="timeout")
    assert early.verdict(0, [], f2kboot.Block("t.exe a", ["A"], 0)) == (
        "the boot did not report [F2K: frame database audit: ok]")
    assert early.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 0)) == "not run: the boot stopped in t.exe a (timeout)"


# --- Children: a process another started ends with its own line, inside its parent's part ------

# Today's end lines, every form the kernel prints (kernel/src/process/exit.rs, EndReport).
TODAYS_ENDS = [
    "F2K: user process exited normally (exit code=0)",
    "F2K: user process ended by fault (bad user argument pointer, exit code=3221225477); halting",
    "F2K: user process ended by fault (raised exception, exit code=3221225477); halting",
    "F2K: user process ended by fault (vector 14, exit code=3221225477); halting",
    "F2K: process 3 (bare) exited normally (exit code=0)",
    "F2K: process 3 (bare) ended by fault (vector 14, exit code=3221225477)",
]
CHILD_EXITED = "F2K: child process 136 (child) exited normally (exit code=7)"
CHILD_FAULTED = "F2K: child process 140 (child) ended by fault (vector 14, exit code=3221225477)"
# A parent's run with two children: their output interleaved with its own, one child's fault dump.
WITH_CHILDREN = [
    "F2K: entering ring 3",
    "parent: starting the children",
    "child: hello",
    "parent: waiting",
    CHILD_EXITED,
    "parent: first child's exit code 7",
    "CPU EXCEPTION: vector 14",
    "  error code 0x00000006",
    CHILD_FAULTED,
    "parent: second child's exit code 0xc0000005",
]
PARENT_OUTPUT = [
    "parent: starting the children",
    "child: hello",
    "parent: waiting",
    "parent: first child's exit code 7",
    "parent: second child's exit code 0xc0000005",
]


def test_a_childs_end_line_has_its_own_form():
    for line in TODAYS_ENDS:
        assert f2kboot.END.match(line) and not f2kboot.CHILD_END.match(line), line
    for line, pid, verdict in ((CHILD_EXITED, "136", "exited normally"), (CHILD_FAULTED, "140", "ended by fault")):
        match = f2kboot.CHILD_END.match(line)
        assert match and match.groups() == (pid, "child", verdict)
        for pattern in (f2kboot.END, f2kboot.TEARDOWN, f2kboot.OBJECT_LEAK, f2kboot.START):
            assert not pattern.match(line), (pattern.pattern, line)


def test_a_childs_end_does_not_end_its_parent():
    log = "\n".join(WITH_CHILDREN)
    assert not f2kboot.process_ended(log)
    assert not f2kboot.teardown_audited(log)
    assert f2kboot.program_output(log) == (PARENT_OUTPUT, None)
    # A kernel case's expectation of the parent's end is not met by a child's.
    expectation = f2kboot.Expectation(expects=["F2K: user process exited normally (exit code=0)"])
    assert expectation.check(log)[0] == "pending"


def test_a_childs_output_is_its_parents():
    lines = WITH_CHILDREN + [ENDED[-1], CLEAN]
    assert f2kboot.program_output("\n".join(lines)) == (PARENT_OUTPUT, 0)
    assert f2kboot.teardown_problem(lines) is None
    assert f2kboot.teardown_problem(WITH_CHILDREN + [ENDED[-1]]) == (
        "the process ended, but its teardown audit never arrived")
    log = "\n".join([*f2kboot.BOOT_CHECKS, *lines])
    assert f2kboot.compare_block(f2kboot.Block("parent", PARENT_OUTPUT, 0), log, []) is None


def test_a_batch_keeps_a_childs_lines_in_its_parents_part():
    first = leg(1, "t.exe a", "A")
    first[3:3] = WITH_CHILDREN[1:]
    lines = BATCH_BOOT + first + leg(2, "t.exe b", "B") + leg(3, "t.exe c", "C")
    batch = batch_of(lines + ["F2K: process suite complete: 3 run, 0 faulted, 0 leaks"])
    assert [command for command, _ in batch.programs] == ["CORPUS\\t.exe a", "CORPUS\\t.exe b", "CORPUS\\t.exe c"]
    assert CHILD_EXITED in batch.programs[0][1] and CHILD_FAULTED in batch.programs[0][1]
    assert batch.verdict(0, [], f2kboot.Block("t.exe a", ["A", *PARENT_OUTPUT], 0)) is None
    assert batch.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 0)) is None
    # The batch's stop check counts the legs' audits alone: a child's end is none.
    watch = f2kboot.BatchWatch([60.0] * 3)
    assert not watch("\n".join(BATCH_BOOT + first[:-2]))
    assert not watch("\n".join(lines))
    assert watch("\n".join(lines + ["F2K: process suite complete: 3 run, 0 faulted, 0 leaks"]))
    alone = f2kboot.BatchWatch([60.0])
    assert not alone("\n".join(WITH_CHILDREN))
    assert alone("\n".join(WITH_CHILDREN + [ENDED[-1], CLEAN]))


class SetClock:
    """A boot clock the test sets."""

    def __init__(self):
        self.now = 0.0

    def elapsed(self) -> float:
        return self.now


def test_a_batch_counts_each_programs_timeout_on_the_boots_clock():
    clock = SetClock()
    watch = f2kboot.BatchWatch([5.0, 8.0, 5.0], clock)
    # The boot's start counts against the first program.
    clock.now = 4.9
    assert not watch("\n".join(BATCH_BOOT))
    clock.now = 4.95
    first = BATCH_BOOT + leg(1, "t.exe a", "A")
    assert not watch("\n".join(first + leg(2, "t.exe b", "B")[:2]))
    # The second runs from its start, 4.95, against its own 8 seconds.
    clock.now = 12.9
    assert not watch("\n".join(first + leg(2, "t.exe b", "B")[:2]))
    assert watch.overran is None
    clock.now = 13.0
    assert watch("\n".join(first + leg(2, "t.exe b", "B")[:2]))
    assert watch.overran == 1


def test_a_boots_clock_leaves_out_what_the_load_took():
    # Unattached, it is the wall clock.
    clock = f2kboot.BootClock()
    before = clock.elapsed()
    time.sleep(0.05)
    assert clock.elapsed() >= before + 0.05
    # Attached to a busy process (this one), it runs no faster than the wall clock, nor backwards.
    clock = f2kboot.BootClock()
    clock.attach(os.getpid())
    started = time.monotonic()
    readings = []
    while time.monotonic() - started < 0.3:
        readings.append(clock.elapsed())
    assert readings == sorted(readings)
    assert 0.0 <= readings[-1] <= time.monotonic() - clock.started
    if sys.platform == "darwin" or sys.platform.startswith("linux"):
        assert f2kboot.time_lost(os.getpid()) >= 0.0
        # A process that is gone tells nothing.
        gone = subprocess.Popen(["true"])
        gone.wait()
        assert f2kboot.time_lost(gone.pid) is None


# A parent replaced by its child (_P_OVERLAY): the parent ends first, its child prints after it.
OVERLAID = [
    "F2K: entering ring 3",
    "parent: the program ends, its replacement prints next",
    "F2K: user process exited normally (exit code=0)",
    "kid: replacing it",
    "F2K: child process 16 (kid) exited normally (exit code=3)",
    CLEAN,
]


def test_a_block_ends_when_its_process_tree_has_ended():
    log = "\n".join([*f2kboot.BOOT_CHECKS, *OVERLAID])
    expected = ["parent: the program ends, its replacement prints next", "kid: replacing it"]
    # The child's lines after its parent's end are the block's; the exit code is the parent's.
    assert f2kboot.program_output(log) == (expected, 0)
    assert f2kboot.compare_block(f2kboot.Block("parent", expected, 0), log, []) is None
    assert f2kboot.compare_block(f2kboot.Block("parent", expected[:1], 0), log, []) == (
        "line 2: extra [kid: replacing it]")
    # Nothing past the teardown audit line, printed once the tree has ended, is the block's.
    assert f2kboot.program_output(log + "\nstray\n") == (expected, 0)
    # A tree still running at the log's end: what it printed so far, the parent's exit code.
    assert f2kboot.program_output("\n".join(OVERLAID[:4])) == (expected, 0)


def test_a_batch_leg_ends_when_its_process_tree_has_ended():
    first = [
        "F2K: process 1 of 3: CORPUS\\t.exe a",
        *OVERLAID[:-1],
        "F2K: process 1 teardown audit: frame database ok",
    ]
    first[3] = "F2K: process 1 (t) exited normally (exit code=0)"
    lines = BATCH_BOOT + first + leg(2, "t.exe b", "B") + leg(3, "t.exe c", "C")
    batch = batch_of(lines + ["F2K: process suite complete: 3 run, 0 faulted, 0 leaks"])
    expected = ["parent: the program ends, its replacement prints next", "kid: replacing it"]
    assert batch.verdict(0, [], f2kboot.Block("t.exe a", expected, 0)) is None
    assert batch.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 0)) is None
    assert batch.verdict(2, [], f2kboot.Block("t.exe c", ["C"], 0)) is None


# --- --no-build: the build on disk must be the one the test needs------------------------------


def built(tmp_path, kernel_features: str | None, disk_features: str | None) -> f2kboot.Build:
    """A kernel and disk in `tmp_path` with the build stamps the Makefile writes (None: no stamp)."""
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    for path, features in ((build.kernel, kernel_features), (build.disk, disk_features)):
        path.write_bytes(b"")
        if features is not None:
            f2kboot.stamp_path(path).write_text(f"features={features}\nprofile=dev\n")
    return build


def test_a_build_with_the_features_asked_for_is_taken(tmp_path):
    assert f2kboot.build_mismatch(built(tmp_path, "", ""), [], profile="dev") is None
    build = built(tmp_path, "run-ret0,disk-smoke", "run-ret0,disk-smoke")
    assert f2kboot.build_mismatch(build, ["disk-smoke", "run-ret0"], profile="dev") is None


def test_a_feature_build_is_refused_for_another_feature_set(tmp_path):
    why = f2kboot.build_mismatch(built(tmp_path, "fault-test-ud", "fault-test-ud"), [], profile="dev")
    assert why is not None
    assert "fault-test-ud" in why and "(default)" in why


def test_a_kernel_rebuilt_after_its_disk_is_refused(tmp_path):
    # `make kernel CARGO_FEATURES=...` after `make disk`: the ELF no longer matches the disk.
    why = f2kboot.build_mismatch(built(tmp_path, "irq-smoke", ""), [], profile="dev")
    assert why is not None and "irq-smoke" in why


def test_a_build_without_stamps_is_refused(tmp_path):
    why = f2kboot.build_mismatch(built(tmp_path, None, None), [], profile="dev")
    assert why is not None and "make disk" in why


# --- A boot's QEMU dies with the process that started it----------------------------------------

BOOT_AND_HANG = """
import sys
from pathlib import Path
sys.path.insert(0, {tests!r})
import f2kboot
work = Path({work!r})
disk = work / "blank.img"
disk.write_bytes(bytes(512 * 64))
f2kboot.FULL_SYSTEM = True  # no subsys=, which a Limine boot writes into its (blank) disk
f2kboot.boot(f2kboot.Build(work / "none", disk), image="disk", log_path=work / "com1.log",
             timeout=120, done=lambda log: False)
"""


@pytest.mark.skipif(shutil.which(f2kboot.QEMU) is None, reason="needs QEMU")
@pytest.mark.parametrize("signal_number", [signal.SIGKILL, signal.SIGTERM], ids=["SIGKILL", "SIGTERM"])
def test_qemu_does_not_outlive_its_test_process(tmp_path, signal_number):
    """A worker killed mid-boot (a crashed xdist worker, an interrupted run) takes its QEMU with it:
    nothing is left running against the build or holding the log."""
    script = BOOT_AND_HANG.format(tests=str(f2kboot.REPO_ROOT / "tests"), work=str(tmp_path))
    worker = subprocess.Popen([sys.executable, "-c", script])
    try:
        qemu = None
        deadline = time.monotonic() + 10
        while qemu is None and time.monotonic() < deadline:
            time.sleep(0.2)
            qemu = qemu_child_of(worker.pid)
        assert qemu is not None, "the boot never started QEMU"
        os.kill(worker.pid, signal_number)
        worker.wait(timeout=10)
        deadline = time.monotonic() + 10
        while alive(qemu) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not alive(qemu), f"QEMU (pid {qemu}) outlived its test process"
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait()
        if qemu is not None and alive(qemu):
            os.kill(qemu, signal.SIGKILL)


def qemu_child_of(pid: int) -> int | None:
    """The pid of a QEMU whose parent is `pid`, if there is one."""
    listing = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,comm="], capture_output=True, text=True).stdout
    for line in listing.splitlines():
        child, parent, command = line.split(None, 2)
        if int(parent) == pid and "qemu" in command:
            return int(child)
    return None


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie (not yet reaped by launchd/init) is gone for our purposes.
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
    return bool(state.strip()) and not state.strip().startswith("Z")


# --- Kept disks: a boot's writes kept for the host and a later boot ---------------------------


def test_a_kept_disk_is_a_private_copy_removed_after(tmp_path):
    disk = tmp_path / "f2k-disk.img"
    disk.write_bytes(b"built" * 100)
    build = f2kboot.Build(tmp_path / "f2k-kernel", disk)
    with f2kboot.kept_disk(build, tmp_path / "kept" / "boot.img") as kept:
        assert kept.read_bytes() == disk.read_bytes()
        kept.write_bytes(b"written by a boot")
        assert disk.read_bytes() == b"built" * 100, "the build's disk is never written"
    assert not kept.exists()
    with pytest.raises(RuntimeError), f2kboot.kept_disk(build, tmp_path / "failed.img") as kept:
        raise RuntimeError("a failed check")
    assert not kept.exists(), "removed after a failure too"


def test_a_kept_disk_is_attached_without_a_snapshot(tmp_path):
    disk = tmp_path / "disk.img"
    assert f2kboot.drive(disk) == f"file={disk},format=raw,if=ide,snapshot=on"
    assert f2kboot.drive(disk, kept=True) == f"file={disk},format=raw,if=ide"


def test_a_reset_after_the_restart_line_ends_the_boot():
    restarted = "\n".join([*f2kboot.BOOT_CHECKS, "F2K: shutdown complete", f2kboot.RESTARTING, ""])
    assert f2kboot.ended_by_reset(restarted)
    assert f2kboot.ended_by_reset(f"{restarted}\n{f2kboot.QEMU_STDERR}\nqemu: a warning\n")
    crashed = f"{restarted}CPU EXCEPTION: general protection fault (vector 13)\n"
    assert not f2kboot.ended_by_reset(crashed), "a fault after the line is a crash"
    assert not f2kboot.ended_by_reset("F2K Booted Successfully\n")
    assert not f2kboot.ended_by_reset("")


FAKE_QEMU = """#!{python}
import json, sys
arguments = sys.argv[1:]
with open({record!r}, "w") as record:
    json.dump(arguments, record)
serial = arguments[arguments.index("-serial") + 1].removeprefix("file:")
with open(serial, "w") as com1:
    com1.write({output!r})
"""


@pytest.mark.parametrize("output, reason", [
    ("F2K Booted Successfully\nF2K: shutdown complete\nF2K: shutdown: restarting\n", "reset"),
    ("F2K Booted Successfully\nCPU EXCEPTION: double fault (vector 8)\n", "exited"),
], ids=["restart", "crash"])
def test_a_kept_boot_attaches_its_disk_and_a_restart_ends_it(tmp_path, monkeypatch, output, reason):
    """A boot on a kept disk attaches that disk without a snapshot, and QEMU's exit after the
    kernel's restart line (its -no-reboot exit) is the boot's end, "reset"; any other exit stays
    "exited". A stand-in QEMU records its arguments and writes COM1, then exits."""
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", True)  # the options compared below are the caller's
    record = tmp_path / "arguments.json"
    qemu = tmp_path / "qemu"
    qemu.write_text(FAKE_QEMU.format(python=sys.executable, record=str(record), output=output))
    qemu.chmod(0o755)
    monkeypatch.setattr(f2kboot, "QEMU", str(qemu))
    monkeypatch.setattr(f2kboot, "exit_with_parent", lambda: [])
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    kept = tmp_path / "kept.img"
    log, stopped = f2kboot.boot(build, image="kernel", log_path=tmp_path / "com1.log", timeout=20,
                                done=lambda log: False, kernel_options="redirected", kept=kept)
    assert stopped == reason, log
    arguments = json.loads(record.read_text())
    assert arguments[arguments.index("-drive") + 1] == f"file={kept},format=raw,if=ide"
    assert "-no-reboot" in arguments
    assert arguments[arguments.index("-append") + 1] == "redirected --"


SLOW_QEMU = """#!{python}
import sys, time
arguments = sys.argv[1:]
serial = arguments[arguments.index("-serial") + 1].removeprefix("file:")
with open(serial, "w") as com1:
    for part in {parts!r}:
        com1.write(part)
        com1.flush()
        time.sleep(0.5)
    time.sleep(60)
"""


def test_a_boot_reads_only_the_lines_the_guest_finished(tmp_path, monkeypatch):
    """QEMU writes COM1 a byte at a time as the guest sends it, so a look at the log can land
    inside a line. A process's end line seen up to "exited normally" is not its end yet (its exit
    code is still to come), and a line the guest had begun when the boot was stopped is none of
    the program's. A stand-in QEMU writes its lines in pieces, pausing between them, and runs
    on."""
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", True)
    parts = ["F2K: entering ring 3\nhello\nF2K: user process exited normally (exit c",
             "ode=0)\nF2"]
    qemu = tmp_path / "qemu"
    qemu.write_text(SLOW_QEMU.format(python=sys.executable, parts=parts))
    qemu.chmod(0o755)
    monkeypatch.setattr(f2kboot, "QEMU", str(qemu))
    monkeypatch.setattr(f2kboot, "exit_with_parent", lambda: [])
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    log, stopped = f2kboot.boot(build, image="kernel", log_path=tmp_path / "com1.log", timeout=20,
                                done=f2kboot.process_ended)
    assert stopped == "done", log
    assert f2kboot.program_output(log) == (["hello"], 0), log
    assert log.endswith("(exit code=0)\n"), log
    # A teardown audit line begun is not yet its verdict: a painting boot's `done` waits for it.
    begun = "\n".join(ENDED) + "\nF2K: teardown audit: frame databas"
    assert f2kboot.teardown_audited(begun) and not f2kboot.teardown_audited(f2kboot.complete_lines(begun))


# --- Storage: the disk in memory, or on the IDE controller ------------------------------------


def stand_in_qemu(tmp_path, monkeypatch) -> Callable[[], list[str]]:
    """A stand-in QEMU that records its arguments and writes a line on COM1, then exits; returns
    the reader of the last boot's arguments."""
    record = tmp_path / "arguments.json"
    qemu = tmp_path / "qemu"
    qemu.write_text(FAKE_QEMU.format(python=sys.executable, record=str(record), output="F2K Booted Successfully\n"))
    qemu.chmod(0o755)
    monkeypatch.setattr(f2kboot, "QEMU", str(qemu))
    monkeypatch.setattr(f2kboot, "exit_with_parent", lambda: [])
    return lambda: json.loads(record.read_text())


def storage_of(arguments: list[str]) -> tuple[str, str, str]:
    """A boot's storage as its QEMU arguments give it: "ram" with the module's value or "ide" with
    the drive's, and the guest memory."""
    memory = arguments[arguments.index("-m") + 1]
    assert ("-initrd" in arguments) != ("-drive" in arguments), "one disk, one way"
    if "-initrd" in arguments:
        return "ram", arguments[arguments.index("-initrd") + 1], memory
    return "ide", arguments[arguments.index("-drive") + 1], memory


@pytest.mark.parametrize("run, declared, expected", [
    (None, None, "ram"),
    ("ram", None, "ram"),
    ("ide", None, "ide"),
    (None, "ide", "ide"),
    ("ram", "ide", "ide"),
    ("ide", "ram", "ram"),
], ids=["default", "run-ram", "run-ide", "declared-ide", "declared-ide-over-run", "declared-ram-over-run"])
def test_a_kernel_boot_reads_its_disk_by_its_storage(tmp_path, monkeypatch, run, declared, expected):
    """A kernel boot reads its disk from memory, the image as the f2k-disk Multiboot module with
    256M of guest memory and no drive, unless its test declares the IDE disk or the run asks for it
    (F2K_STORAGE=ide): then the image is a snapshot drive, at the memory the caller asked for. A
    test's declaration wins over the run's."""
    arguments = stand_in_qemu(tmp_path, monkeypatch)
    if run is None:
        monkeypatch.delenv("F2K_STORAGE", raising=False)
    else:
        monkeypatch.setenv("F2K_STORAGE", run)
    disk = tmp_path / "f2k-disk.img"
    build = f2kboot.Build(tmp_path / "f2k-kernel", disk)
    f2kboot.boot(build, image="kernel", log_path=tmp_path / "com1.log", timeout=20,
                 done=lambda log: False, storage=declared)
    if expected == "ram":
        assert storage_of(arguments()) == ("ram", f"{disk} f2k-disk", "256M")
    else:
        assert storage_of(arguments()) == ("ide", f2kboot.drive(disk), "64M")


def test_a_limine_or_kept_boot_reads_the_ide_disk(tmp_path, monkeypatch):
    """Limine reads the disk through the BIOS, and a kept disk's writes must reach the image: both
    attach the IDE disk whatever the run or the test asks for."""
    arguments = stand_in_qemu(tmp_path, monkeypatch)
    monkeypatch.setenv("F2K_STORAGE", "ram")
    # No subsys=, which a Limine boot writes into its disk (here a stand-in).
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", True)
    disk = tmp_path / "f2k-disk.img"
    build = f2kboot.Build(tmp_path / "f2k-kernel", disk)
    f2kboot.boot(build, image="disk", log_path=tmp_path / "com1.log", timeout=20,
                 done=lambda log: False, storage="ram", memory="256M")
    assert storage_of(arguments()) == ("ide", f2kboot.drive(disk), "256M")
    kept = tmp_path / "kept.img"
    f2kboot.boot(build, image="kernel", log_path=tmp_path / "com1.log", timeout=20,
                 done=lambda log: False, storage="ram", kept=kept)
    assert storage_of(arguments()) == ("ide", f2kboot.drive(kept, kept=True), "64M")


def test_a_storage_that_cannot_be_is_refused(tmp_path, monkeypatch):
    """F2K_STORAGE and a test's storage are "ram" or "ide"; a module path QEMU would split at a
    space or a comma is refused rather than misread."""
    monkeypatch.setenv("F2K_STORAGE", "floppy")
    with pytest.raises(ValueError, match="F2K_STORAGE"):
        f2kboot.run_storage()
    with pytest.raises(ValueError, match="storage"):
        f2kboot.storage_args(tmp_path / "disk.img", "floppy", "64M")
    for path in ("with space/disk.img", "with,comma.img"):
        with pytest.raises(ValueError, match="splits"):
            f2kboot.storage_args(tmp_path / path, "ram", "64M")
    with pytest.raises(ValueError, match="kept"):
        f2kboot.storage_args(tmp_path / "disk.img", "ram", "64M", kept=True)


def test_a_fixture_declares_its_storage(tmp_path, monkeypatch):
    """A fixture's `storage` is "ide" or "ram" (none by default: the run's); anything else is
    refused."""
    directory = tmp_path / "kernel32" / "secfake"
    directory.mkdir(parents=True)
    declared = directory / "fixture.toml"
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})
    declared.write_text('kind = "sectioned"\n')
    assert f2kboot.fixture_storage("secfake") is None
    for storage in f2kboot.STORAGES:
        declared.write_text(f'kind = "sectioned"\nstorage = "{storage}"\n')
        assert f2kboot.fixture_storage("secfake") == storage
    for wrong in ('"floppy"', '["ide"]', "1"):
        declared.write_text(f'kind = "sectioned"\nstorage = {wrong}\n')
        with pytest.raises(ValueError, match="storage"):
            f2kboot.fixture_storage("secfake")


# --- Subsystems: each boot starts the ones its programs need -----------------------------------

SUBSYS_RS = f2kboot.REPO_ROOT / "kernel" / "src" / "boot" / "subsys.rs"


def test_the_optional_subsystems_are_the_kernel_tables():
    """The rows a boot can leave out are the kernel table's System, Auto and Demand rows, and the
    alias is the kernel's (kernel/src/boot/subsys.rs)."""
    source = SUBSYS_RS.read_text()
    rows = re.findall(r'subsystem\(\s*S::\w+,\s*"(\w+)",\s*T::(\w+),', source)
    assert len(rows) == 20
    assert tuple(name for name, start in rows if start != "Boot") == f2kboot.OPTIONAL_SUBSYSTEMS
    assert re.search(r'ALIASES[^=]*= \[\("gui", Subsystem::WinSta\.bit\(\) \| Subsystem::Fonts\.bit\(\)\)\]',
                     source)
    assert f2kboot.SUBSYSTEM_ALIASES == {"gui": ("winsta", "fonts")}


def test_needs_are_subsystem_names():
    assert f2kboot.subsystem_names(["gui", "ide"], "t") == {"winsta", "fonts", "ide"}
    assert f2kboot.subsystem_names([], "t") == frozenset()
    for wrong in (["memory"], ["GUI"], "gui", [1]):
        with pytest.raises(ValueError, match="needs"):
            f2kboot.subsystem_names(wrong, "t")


def test_the_subsys_option_names_the_needs_win32ks_as_gui():
    assert f2kboot.subsys_value(frozenset()) == "subsys="
    assert f2kboot.subsys_value(frozenset({"keyboard", "ide"})) == "subsys=ide,keyboard"
    assert f2kboot.subsys_value(frozenset({"winsta", "fonts", "pci"})) == "subsys=gui,pci"
    assert f2kboot.subsys_value(frozenset({"fonts"})) == "subsys=fonts"


def test_a_programs_needs_follow_its_imports():
    """A console program needs nothing beyond the base profile; one importing user32 or gdi32 (or a
    DLL that does) needs win32k's two, `gui`; a program the harness cannot find, everything."""
    hello = f2kboot.TESTS / "core" / "hello" / "hello.exe"
    hellogui = f2kboot.fixture_directory("hellogui") / "hellogui.exe"
    assert f2kboot.program_needs(hello) == frozenset()
    assert f2kboot.program_needs(hellogui) == {"winsta", "fonts"}
    assert f2kboot.command_needs(None) == frozenset()
    assert f2kboot.command_needs("hello.exe ;; exit0") == frozenset()
    assert f2kboot.command_needs("CORPUS\\hellogui.exe ;; hello.exe") == {"winsta", "fonts"}
    assert f2kboot.command_needs("hello.exe", "keyboard") == {"keyboard"}
    assert f2kboot.command_needs("CORPUS\\nosuch.exe") == f2kboot.EVERY_SUBSYSTEM


def needs_fixture(tmp_path, monkeypatch, declaration: str, programs=("hello.exe",)) -> None:
    """A sectioned fixture, secfake, with `programs` (copies of the corpus's) and `declaration`."""
    directory = tmp_path / "kernel32" / "secfake"
    directory.mkdir(parents=True, exist_ok=True)
    for program in programs:
        source = f2kboot.program_path(program)
        shutil.copyfile(source, directory / ("secfake.exe" if program == programs[0] else program))
    (directory / "fixture.toml").write_text('kind = "sectioned"\n' + declaration)
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})


def test_a_fixtures_needs_default_to_its_programs_imports(tmp_path, monkeypatch):
    needs_fixture(tmp_path, monkeypatch, "")
    assert f2kboot.fixture_needs("secfake") == frozenset()
    # A companion program (a child it starts) counts too.
    needs_fixture(tmp_path, monkeypatch, "", programs=("hello.exe", "hellogui.exe"))
    assert f2kboot.fixture_needs("secfake") == {"winsta", "fonts"}


def test_a_fixtures_declared_needs_replace_its_imports(tmp_path, monkeypatch):
    needs_fixture(tmp_path, monkeypatch, 'needs = ["pci"]\n', programs=("hellogui.exe",))
    assert f2kboot.fixture_needs("secfake") == {"pci"}
    needs_fixture(tmp_path, monkeypatch, 'needs = []\n', programs=("hellogui.exe",))
    assert f2kboot.fixture_needs("secfake") == frozenset()
    needs_fixture(tmp_path, monkeypatch, 'needs = ["memory"]\n')
    with pytest.raises(ValueError, match="needs"):
        f2kboot.fixture_needs("secfake")


def test_a_fixtures_keys_and_fonts_bring_their_subsystems(tmp_path, monkeypatch):
    needs_fixture(tmp_path, monkeypatch, 'needs = []\nsystem_fonts = true\n')
    assert f2kboot.fixture_needs("secfake") == {"fonts"}
    needs_fixture(tmp_path, monkeypatch, '[keys]\nread = [{ press = ["a"] }]\n')
    assert f2kboot.fixture_needs("secfake") == {"keyboard"}


def kernel_options_of(arguments: list[str]) -> str:
    """The kernel's own options a kernel boot's QEMU arguments carry (before -append's "--")."""
    return arguments[arguments.index("-append") + 1].split("--")[0].strip()


@pytest.mark.parametrize("storage, cmdline, needs, options, expected", [
    ("ram", "hello.exe", None, "", "subsys="),
    ("ram", "CORPUS\\hellogui.exe", None, "redirected", "redirected subsys=gui"),
    ("ide", "hello.exe", None, "", "subsys=ide"),
    ("ram", "hello.exe", ["keyboard"], "", "subsys=keyboard"),
    ("ram", "hello.exe", ["pci"], "subsys=gui", "subsys=gui"),
], ids=["console", "gui", "ide-disk", "declared", "own-option"])
def test_a_boot_starts_the_subsystems_it_needs(tmp_path, monkeypatch, storage, cmdline, needs, options, expected):
    """A boot names its subsystems in a `subsys=` kernel option: its `needs`, else its command
    line's programs' imports, and `ide` on the IDE disk; kernel options choosing their own keep
    them."""
    arguments = stand_in_qemu(tmp_path, monkeypatch)
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", False)
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    f2kboot.boot(build, image="kernel", log_path=tmp_path / "com1.log", timeout=20, done=lambda log: False,
                 storage=storage, cmdline=cmdline, needs=needs, kernel_options=options)
    assert kernel_options_of(arguments()) == expected


def test_the_full_system_boots_every_subsystem(tmp_path, monkeypatch):
    """`--full-system` (FULL_SYSTEM): no subsys=, so the kernel starts every subsystem."""
    arguments = stand_in_qemu(tmp_path, monkeypatch)
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", True)
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    f2kboot.boot(build, image="kernel", log_path=tmp_path / "com1.log", timeout=20, done=lambda log: False,
                 storage="ide", cmdline="hello.exe", needs=[], kernel_options="redirected")
    assert kernel_options_of(arguments()) == "redirected"


REFUSAL = ("F2K: win32k service 0x119f refused: subsystem winsta,fonts not started (subsys=),"
           " STATUS_INVALID_SYSTEM_SERVICE")
NOT_STARTED = ("KERNEL PANIC: SUBSYSTEM_NOT_STARTED: pci::devices needs subsystem pci, which this boot's"
               " subsys= left out")


def test_a_reach_into_a_left_out_subsystem_names_it():
    assert f2kboot.undeclared_subsystem("F2K: entering ring 3\nhello\n") is None
    refused = f2kboot.undeclared_subsystem(f"F2K: entering ring 3\n{REFUSAL}\n")
    assert refused is not None and 'needs = ["gui"]' in refused and "0x119f" in refused
    panic = f2kboot.undeclared_subsystem(f"{NOT_STARTED}\n")
    assert panic is not None and 'needs = ["pci"]' in panic and "pci::devices" in panic


def test_a_boot_that_reached_a_left_out_subsystem_fails(tmp_path, monkeypatch):
    """A boot that chose its subsystems fails its test on a reach into one it left out, naming it;
    the full system's boot, and one whose kernel options chose, are left to their own checks."""
    record, qemu = tmp_path / "arguments.json", tmp_path / "qemu"
    qemu.write_text(FAKE_QEMU.format(python=sys.executable, record=str(record),
                                     output=f"F2K Booted Successfully\n{REFUSAL}\n"))
    qemu.chmod(0o755)
    monkeypatch.setattr(f2kboot, "QEMU", str(qemu))
    monkeypatch.setattr(f2kboot, "exit_with_parent", lambda: [])
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", False)
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    boot = dict(image="kernel", log_path=tmp_path / "com1.log", timeout=20, done=lambda log: False,
                storage="ram", cmdline="hello.exe")
    with pytest.raises(pytest.fail.Exception, match=r"used subsystem gui"):
        f2kboot.boot(build, **boot)
    f2kboot.boot(build, **boot, kernel_options="subsys=")
    f2kboot.boot(build, **boot, check_needs=False)
    monkeypatch.setattr(f2kboot, "FULL_SYSTEM", True)
    f2kboot.boot(build, **boot)


def test_a_batch_fails_the_block_that_reached_a_left_out_subsystem():
    lines = (BATCH_BOOT + leg(1, "t.exe a", "A") + leg(2, "t.exe b", "B")[:2] + [REFUSAL]
             + leg(2, "t.exe b", "B")[2:] + leg(3, "t.exe c", "C"))
    batch = batch_of(lines)
    batch.narrowed = True
    assert batch.verdict(0, [], f2kboot.Block("t.exe a", ["A"], 0)) is None
    assert "used subsystem gui" in batch.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 0))
    assert batch.verdict(2, [], f2kboot.Block("t.exe c", ["C"], 0)) is None
    # A later block that differs is told of the earlier reach (the refusal is reported once a boot).
    assert "used subsystem gui" in batch.verdict(2, [], f2kboot.Block("t.exe c", ["D"], 0))
    batch.narrowed = False
    assert batch.verdict(1, [], f2kboot.Block("t.exe b", ["B"], 0)) is None


def test_a_batch_starts_the_union_of_its_fixtures_needs(tmp_path, monkeypatch):
    directories = {}
    for name, declaration in (("one", 'needs = ["keyboard"]\n'), ("two", 'needs = ["gui"]\n')):
        directory = tmp_path / "kernel32" / name
        directory.mkdir(parents=True)
        (directory / "fixture.toml").write_text('kind = "sectioned"\n' + declaration)
        directories[name] = directory
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: directories)
    captured = [f2kboot.Captured(name, f2kboot.Block("t.exe"), (), 1.0) for name in ("one", "two", "one")]
    assert f2kboot.batch_needs(captured) == {"keyboard", "winsta", "fonts"}


def test_a_fixture_declares_its_memory(tmp_path, monkeypatch):
    """A fixture's `memory` is a guest size QEMU's -m takes ("32M"; none by default: the run's
    RAM_MEMORY); it needs `storage = "ide"`, the RAM-disk boot loading the whole disk image."""
    directory = tmp_path / "kernel32" / "secfake"
    directory.mkdir(parents=True)
    declared = directory / "fixture.toml"
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})
    declared.write_text('kind = "sectioned"\nstorage = "ide"\n')
    assert f2kboot.fixture_memory("secfake") is None
    for memory in ("32M", "64M", "256M", "512"):
        declared.write_text(f'kind = "sectioned"\nstorage = "ide"\nmemory = "{memory}"\n')
        assert f2kboot.fixture_memory("secfake") == memory
    for wrong in ('"32 M"', '["32M"]', "1", '"ide"'):
        declared.write_text(f'kind = "sectioned"\nstorage = "ide"\nmemory = {wrong}\n')
        with pytest.raises(ValueError, match="memory"):
            f2kboot.fixture_memory("secfake")
    declared.write_text('kind = "sectioned"\nmemory = "32M"\n')
    with pytest.raises(ValueError, match="storage"):
        f2kboot.fixture_memory("secfake")


def test_a_separate_section_declares_its_own_memory(tmp_path, monkeypatch):
    """`[section_memory]` gives a `separate` section's boot its own guest size; the fixture's other
    blocks keep its `memory`, and a section it names must be separate."""
    directory = tmp_path / "kernel32" / "secfake"
    directory.mkdir(parents=True)
    declared = directory / "fixture.toml"
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})
    base = 'kind = "sectioned"\nstorage = "ide"\nmemory = "32M"\nseparate = ["big"]\n'
    declared.write_text(base + '[section_memory]\nbig = "128M"\n')
    assert f2kboot.fixture_memory("secfake") == "32M"
    assert f2kboot.fixture_memory("secfake", "small") == "32M"
    assert f2kboot.fixture_memory("secfake", "big") == "128M"
    declared.write_text(base + '[section_memory]\nother = "128M"\n')
    with pytest.raises(ValueError, match="not separate"):
        f2kboot.fixture_memory("secfake")
    declared.write_text(base + '[section_memory]\nbig = "128 M"\n')
    with pytest.raises(ValueError, match="section_memory.big"):
        f2kboot.fixture_memory("secfake")
    declared.write_text('kind = "sectioned"\nseparate = ["big"]\n[section_memory]\nbig = "128M"\n')
    with pytest.raises(ValueError, match="storage"):
        f2kboot.fixture_memory("secfake", "big")


def volume_image(path, *, fat1=0x0FFF_FFFF, free_count=0xFFFF_FFFF, next_free=0xFFFF_FFFF,
                 used=(), fsinfo=True):
    """A small FAT32-shaped volume at the partition's offset in a disk image: 8 reserved sectors
    (FSInfo at 1), two one-sector FATs, 100 one-sector clusters; the root (cluster 2) and `used`
    taken, the rest free."""
    clusters = 100
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    struct.pack_into("<HBHB", boot, 11, 512, 1, 8, 2)
    struct.pack_into("<II", boot, 32, 8 + 2 + clusters, 1)
    struct.pack_into("<H", boot, 48, 1)
    boot[510:512] = b"\x55\xaa"
    info = bytearray(512)
    if fsinfo:
        for at, value in f2kboot.FSINFO_SIGNATURES:
            struct.pack_into("<I", info, at, value)
    struct.pack_into("<II", info, 488, free_count, next_free)
    fat = bytearray(512)
    struct.pack_into("<III", fat, 0, 0x0FFF_FFF8, fat1, 0x0FFF_FFFF)
    for cluster in used:
        struct.pack_into("<I", fat, cluster * 4, 0x0FFF_FFFF)
    image = bytearray(f2kboot.PARTITION_OFFSET + (8 + 2 + clusters) * 512)
    at = f2kboot.PARTITION_OFFSET
    image[at:at + 512] = boot
    image[at + 512:at + 1024] = info
    image[at + 8 * 512:at + 9 * 512] = fat
    image[at + 9 * 512:at + 10 * 512] = fat
    path.write_bytes(bytes(image))
    return path


def test_a_volume_image_reads_its_clean_bit_fsinfo_and_free_clusters(tmp_path):
    flushed = f2kboot.read_volume(volume_image(tmp_path / "clean.img", free_count=96, next_free=6,
                                               used=(3, 4, 5)))
    assert flushed == f2kboot.VolumeState(clean=True, fsinfo_free=96, fsinfo_next_free=6, free=96,
                                          clusters=100, hint_is_free=True)
    dirty = f2kboot.read_volume(volume_image(tmp_path / "dirty.img", fat1=0x07FF_FFFF, used=(3,)))
    assert not dirty.clean
    assert (dirty.fsinfo_free, dirty.fsinfo_next_free, dirty.free) == (0xFFFF_FFFF, 0xFFFF_FFFF, 98)
    assert not dirty.hint_is_free, "an unknown hint names no cluster"
    taken = f2kboot.read_volume(volume_image(tmp_path / "taken.img", free_count=97, next_free=3,
                                             used=(3, 4)))
    assert not taken.hint_is_free and taken.free == 97


def test_a_volume_without_fsinfo_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not an FSInfo sector"):
        f2kboot.read_volume(volume_image(tmp_path / "plain.img", fsinfo=False))
    with pytest.raises(ValueError, match="no FAT32 boot sector"):
        f2kboot.read_volume(volume_image(tmp_path / "shifted.img"), offset=0)


# --- Masks: one value each, in their own section-----------------------------------------------


def test_a_mask_star_stands_for_one_value():
    mask = f2kboot.mask_pattern("region * allocprotect 0x0")
    assert mask.fullmatch("region 0x77B50000 allocprotect 0x0")
    assert not mask.fullmatch("region  allocprotect 0x0"), "an empty value"
    assert not mask.fullmatch("region 0x1 allocprotect 0x4 region 0x2 allocprotect 0x0"), "a run of fields"


def test_a_mask_double_star_stands_for_any_text():
    mask = f2kboot.mask_pattern("  the standard output handle after _popen: **")
    assert mask.fullmatch("  the standard output handle after _popen: another value")
    assert mask.fullmatch("  the standard output handle after _popen: the same value")
    assert not mask.fullmatch("  the standard output handle after _popen: "), "no text"
    both = f2kboot.mask_pattern("a ** then * end")
    assert both.fullmatch("a one two then 3 end")
    assert not both.fullmatch("a one two then 3 4 end"), "a star is still one value"

def test_masks_and_pending_blocks_apply_to_their_own_section():
    params = {p.id: p for p in f2kboot.blocks(
        "memory", gate=True,
        masks={"virtual": ("released: state 0x10000 protect 0x1 type 0x0 region * allocprotect 0x0",)},
        pending={"stack": "GAP-X: y"},
    )}
    assert params["virtual"].values[0].masks
    assert not params["image"].values[0].masks, "a mask reached another section"
    assert [m.name for m in params["stack"].marks].count("xfail") == 1
    assert not [m for m in params["heap"].marks if m.name == "xfail"]


def test_a_mask_or_pending_block_naming_no_section_is_refused():
    with pytest.raises(ValueError, match="nosuch"):
        f2kboot.blocks("memory", gate=True, masks={"nosuch": ("x *",)})
    with pytest.raises(ValueError, match="nosuch"):
        f2kboot.blocks("memory", gate=True, pending={"nosuch": "GAP-X: y"})


SECTIONED_CAPTURE = """# F2K capture of fakesec (tests\\capture.bat)
>>> fakesec.exe a
A
<<< exit code=0
>>> fakesec.exe down
down: ret=0 err=1314
<<< exit code=0
>>> fakesec.exe c
C
<<< exit code=0
"""


def batch_item(param, function, name: str) -> SimpleNamespace:
    """A stand-in for a block's collected test, as conftest's `batch_name` and `batch_items` read it."""
    marks = [decorator.mark for decorator in param.marks]
    return SimpleNamespace(function=function, originalname=name,
                           callspec=SimpleNamespace(params={"captured": param.values[0]}),
                           get_closest_marker=lambda mark: next((m for m in marks if m.name == mark), None))


def test_a_skipped_block_is_neither_booted_nor_compared(tmp_path, monkeypatch):
    """A `skip` section's block is skipped with its reason, never an expected failure: the batch
    leaves it out of its boot (conftest's `batch_items`), so the boot's command line lists the
    other blocks alone, and each of them is judged on its own part of the log."""
    import conftest

    directory = tmp_path / "user32" / "fakesec"
    directory.mkdir(parents=True)
    (directory / "fakesec.exe").write_bytes(b"MZ")
    (directory / "output.txt").write_text(SECTIONED_CAPTURE)
    (directory / "fixture.toml").write_text(
        'kind = "sectioned"\ngate = true\n\n[skip]\ndown = "the call would shut the test boot down"\n')
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"fakesec": directory})
    params = {param.id: param for param in f2kboot.corpus_params("fakesec")}
    [skip] = [mark for mark in params["down"].marks if mark.name == "skip"]
    assert skip.kwargs["reason"] == "never run on F2K: the call would shut the test boot down"
    assert not [mark for mark in params["down"].marks if mark.name == "xfail"]
    assert not [mark for param in (params["a"], params["c"]) for mark in param.marks if mark.name == "skip"]

    def test():
        pass

    items = [batch_item(param, test, "test_fakesec") for param in params.values()]
    selected = conftest.batch_items(SimpleNamespace(items=items), items[0])
    blocks = [each.callspec.params["captured"].block for each in selected]
    assert f2kboot.batch_command_line([block.command for block in blocks]) == (
        "CORPUS\\fakesec.exe a ;; CORPUS\\fakesec.exe c")
    log = "\n".join(BATCH_BOOT + [line.replace("t.exe", "fakesec.exe").replace(" of 3", " of 2")
                                  for line in leg(1, "t.exe a", "A") + leg(2, "t.exe c", "C")]
                    + ["F2K: process suite complete: 2 run, 0 faulted, 0 leaks"]) + "\n"
    batch = f2kboot.Batch([block.command for block in blocks], log, tmp_path / "fakesec.log", "done",
                          *f2kboot.split_programs(log))
    assert [batch.verdict(index, [], block) for index, block in enumerate(blocks)] == [None, None]


def test_a_separate_section_boots_on_its_own(tmp_path, monkeypatch):
    """A `separate` section's block is a batch of its own, `<fixture>-<section>` (its boot's log
    and profile named so), and the fixture's other blocks keep theirs, `<fixture>`; a block of the
    same section run in another suite's batch (the Limine boot's) stays in that one."""
    import conftest

    directory = tmp_path / "user32" / "fakesplit"
    directory.mkdir(parents=True)
    (directory / "fakesplit.exe").write_bytes(b"MZ")
    (directory / "output.txt").write_text(SECTIONED_CAPTURE.replace("fakesec", "fakesplit"))
    (directory / "fixture.toml").write_text('kind = "sectioned"\ngate = true\nseparate = ["down"]\n')
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"fakesplit": directory})
    params = f2kboot.corpus_params("fakesplit")

    def test():
        pass

    items = [batch_item(param, test, "test_fakesplit") for param in params]
    assert [conftest.batch_name(item) for item in items] == ["fakesplit", "fakesplit-down", "fakesplit"]
    session = SimpleNamespace(items=items)
    assert conftest.batch_items(session, items[2]) == [items[0], items[2]]
    assert conftest.batch_items(session, items[1]) == [items[1]]
    assert conftest.batch_name(batch_item(params[1], test, "test_limine")) == "limine"
    with pytest.raises(ValueError, match="nosuch"):
        f2kboot.blocks("fakesplit", gate=True, separate=["nosuch"])


def test_a_section_both_pending_and_skipped_is_refused():
    with pytest.raises(ValueError, match="both pending and skipped"):
        f2kboot.blocks("memory", gate=True, pending={"heap": "GAP-X: y"}, skip={"heap": "never"})
    with pytest.raises(ValueError, match="nosuch"):
        f2kboot.blocks("memory", gate=True, skip={"nosuch": "never"})
    with pytest.raises(ValueError, match="no reason"):
        f2kboot.blocks("memory", gate=True, skip={"heap": " "})


def test_pins_name_sections_and_exports():
    """A fixture's pins are keyed by section name ("*" for every block) and name dll.Export."""
    assert f2kboot.blocks("memory", gate=True, pins={"*": ["kernel32.HeapAlloc"], "heap": ["ntdll.RtlSizeHeap"]})
    with pytest.raises(ValueError, match="nosuch"):
        f2kboot.blocks("memory", gate=True, pins={"nosuch": ["kernel32.HeapAlloc"]})
    with pytest.raises(ValueError, match="not dll.Export"):
        f2kboot.blocks("memory", gate=True, pins={"heap": ["HeapAlloc"]})


# --- Script fixtures: one block, its script run by cmd /c ----------------------------------------

SCRIPT_CAPTURE = """# F2K capture of batfake (tests\\capture.bat)
>>> cmd /c batfake.cmd
one
C:\\some\\where>echo two
<<< exit code=0
"""


def script_fixture(tmp_path, monkeypatch, declaration: str, capture: str | None) -> str:
    """A script fixture, batfake, under `tmp_path` (tests/cmd/batfake/), the declaration and capture
    given (none: awaited), with the harness's fixture lookup pointed at it."""
    directory = tmp_path / "cmd" / "batfake"
    directory.mkdir(parents=True)
    (directory / "batfake.cmd").write_bytes(b"@echo off\r\necho one\r\n")
    (directory / "fixture.toml").write_text(declaration)
    if capture is not None:
        (directory / "output.txt").write_text(capture)
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"batfake": directory})
    return "batfake"


def test_an_awaited_script_fixture_is_one_skipped_test(tmp_path, monkeypatch):
    """A script fixture without its capture is awaited (it has no program to wait for): one skipped
    test, so no boot."""
    fixture = script_fixture(tmp_path, monkeypatch, 'kind = "script"\n', None)
    assert f2kboot.awaited(fixture)
    [param] = f2kboot.corpus_params(fixture)
    assert param.id == "awaited"
    skip = next(mark for mark in param.marks if mark.name == "skip")
    assert "output.txt" in skip.kwargs["reason"] and ".exe" not in skip.kwargs["reason"]


def test_a_script_fixtures_capture_is_one_block_its_masks_apply_to(tmp_path, monkeypatch):
    """A captured script fixture is one test, its block the script run by `cmd /c`, its masks (a
    list) that block's; ungated, it runs as an expected failure. On F2K the block runs the cmd.exe
    in the corpus's directory, so the script's current directory is the corpus's."""
    declaration = 'kind = "script"\nmasks = ["**>echo two"]\n'
    fixture = script_fixture(tmp_path, monkeypatch, declaration, SCRIPT_CAPTURE)
    assert not f2kboot.awaited(fixture)
    [param] = f2kboot.corpus_params(fixture)
    captured = param.values[0]
    assert captured.block.command == "cmd /c batfake.cmd"
    assert captured.block.lines == ["one", "C:\\some\\where>echo two"]
    assert any(mask.fullmatch("C:\\CORPUS>echo two") for mask in captured.masks)
    assert [mark.name for mark in param.marks].count("xfail") == 1
    assert f2kboot.batch_command_line([captured.block.command]) == "CORPUS\\cmd /c batfake.cmd"


def test_a_script_capture_of_another_command_or_masks_by_section_is_refused(tmp_path, monkeypatch):
    fixture = script_fixture(tmp_path, monkeypatch, 'kind = "script"\n',
                             SCRIPT_CAPTURE.replace("batfake.cmd", "other.cmd"))
    with pytest.raises(ValueError, match="one block"):
        f2kboot.corpus_params(fixture)
    blocks = f2kboot.parse_capture(tmp_path / "cmd" / "batfake" / "output.txt")
    with pytest.raises(ValueError, match="a list"):
        f2kboot.script_masks("batfake", {"masks": {"/c batfake.cmd": ["x"]}},
                             [f2kboot.Block("cmd /c batfake.cmd", blocks[0].lines, 0)])


def test_a_pending_script_gives_its_block_s_reason(tmp_path, monkeypatch):
    """A gated script's `pending`, a string, is its one block's reason: the block runs as a strict
    expected failure with it. Anything but a string is refused."""
    declaration = 'kind = "script"\ngate = true\npending = "redirection not implemented"\n'
    fixture = script_fixture(tmp_path, monkeypatch, declaration, SCRIPT_CAPTURE)
    [param] = f2kboot.corpus_params(fixture)
    [xfail] = [mark for mark in param.marks if mark.name == "xfail"]
    assert xfail.kwargs == {"reason": "redirection not implemented", "strict": True}
    declared = tmp_path / "cmd" / "batfake" / "fixture.toml"
    declared.write_text('kind = "script"\ngate = true\n')
    [param] = f2kboot.corpus_params(fixture)
    assert not [mark for mark in param.marks if mark.name == "xfail"]
    declared.write_text('kind = "script"\ngate = true\npending = {a = "b"}\n')
    with pytest.raises(ValueError, match="a string"):
        f2kboot.corpus_params(fixture)


def test_system_programs_give_a_sectioned_fixture_a_disk_of_its_own(tmp_path, monkeypatch):
    """A sectioned fixture declaring `system_programs` boots a copy of the disk with those built
    programs added to \\WINNT\\system32; one declaring none boots the disk the tests boot. A
    program not built, and anything but a list of distinct names, are refused."""
    directory = tmp_path / "kernel32" / "secfake"
    directory.mkdir(parents=True)
    declared = directory / "fixture.toml"
    built = tmp_path / "built"
    built.mkdir()
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})
    monkeypatch.setattr(f2kboot, "BUILT_PROGRAMS", built)
    copies = []
    monkeypatch.setattr(f2kboot, "disk_with_programs",
                        lambda build, programs, path, **rest: copies.append((programs, path, rest)) or path)
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    variant = tmp_path / "variant.img"

    declared.write_text('kind = "sectioned"\n')
    assert f2kboot.corpus_disk(build, "secfake", variant) is None
    declared.write_text('kind = "sectioned"\nsystem_programs = ["cmd"]\n')
    with pytest.raises(RuntimeError, match="cmd.exe missing"):
        f2kboot.corpus_disk(build, "secfake", variant)
    (built / "cmd.exe").write_bytes(b"MZ")
    assert f2kboot.corpus_disk(build, "secfake", variant) == variant
    assert copies == [([built / "cmd.exe"], variant, {"corpus": [], "fonts": False})]
    for wrong in ('"cmd"', '[1]', '[""]', '["cmd", "cmd"]'):
        declared.write_text(f'kind = "sectioned"\nsystem_programs = {wrong}\n')
        with pytest.raises(ValueError, match="system_programs"):
            f2kboot.system_programs("secfake")


def test_data_files_give_a_sectioned_fixture_a_disk_of_its_own(tmp_path, monkeypatch):
    """A sectioned fixture declaring `data_files` boots a copy of the disk with those files of its
    directory added to \\CORPUS, and no program added; anything but a list of distinct names is
    refused."""
    directory = tmp_path / "gdi32" / "secfake"
    directory.mkdir(parents=True)
    declared = directory / "fixture.toml"
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})
    copies = []
    monkeypatch.setattr(f2kboot, "disk_with_programs",
                        lambda build, programs, path, **rest: copies.append((programs, path, rest)) or path)
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    variant = tmp_path / "variant.img"

    declared.write_text('kind = "sectioned"\ndata_files = ["f2ktahom.ttf"]\n')
    assert f2kboot.corpus_disk(build, "secfake", variant) == variant
    assert copies == [([], variant, {"corpus": [directory / "f2ktahom.ttf"], "fonts": False})]
    for wrong in ('"f2ktahom.ttf"', '[1]', '[""]', '["a.ttf", "a.ttf"]'):
        declared.write_text(f'kind = "sectioned"\ndata_files = {wrong}\n')
        with pytest.raises(ValueError, match="data_files"):
            f2kboot.data_files("secfake")


def test_system_fonts_give_a_sectioned_fixture_a_disk_of_its_own(tmp_path, monkeypatch):
    """A sectioned fixture declaring `system_fonts = true` boots a copy of the disk with the
    system's fonts added, and no program or file; `false` boots the disk the tests boot, and
    anything but true or false is refused."""
    directory = tmp_path / "gdi32" / "secfake"
    directory.mkdir(parents=True)
    declared = directory / "fixture.toml"
    monkeypatch.setattr(f2kboot, "fixture_directories", lambda: {"secfake": directory})
    copies = []
    monkeypatch.setattr(f2kboot, "disk_with_programs",
                        lambda build, programs, path, **rest: copies.append((programs, path, rest)) or path)
    build = f2kboot.Build(tmp_path / "f2k-kernel", tmp_path / "f2k-disk.img")
    variant = tmp_path / "variant.img"

    declared.write_text('kind = "sectioned"\nsystem_fonts = false\n')
    assert f2kboot.corpus_disk(build, "secfake", variant) is None
    declared.write_text('kind = "sectioned"\nsystem_fonts = true\n')
    assert f2kboot.corpus_disk(build, "secfake", variant) == variant
    assert copies == [([], variant, {"corpus": [], "fonts": True})]
    for wrong in ('"yes"', '1', '["tahoma.ttf"]'):
        declared.write_text(f'kind = "sectioned"\nsystem_fonts = {wrong}\n')
        with pytest.raises(ValueError, match="system_fonts"):
            f2kboot.system_fonts("secfake")


def test_the_system_fonts_are_the_boot_list_s(tmp_path, monkeypatch):
    """The system's fonts are fonts/*.ttf, the five files win32k's boot list loads from
    \\WINNT\\Fonts; `add_system_fonts` puts them there by their own names."""
    source = (f2kboot.REPO_ROOT / "kernel" / "src" / "win32k" / "fonts" / "mod.rs").read_text()
    boot_list = source[source.index("pub const BOOT_FONTS"):]
    boot_list = boot_list[:boot_list.index("];")]
    loaded = re.findall(r'"WINNT\\\\Fonts\\\\([^"]+)"', boot_list)
    assert sorted(loaded) == [path.name for path in f2kboot.system_font_files()]
    assert len(loaded) == 5

    calls = []
    monkeypatch.setattr(f2kboot.subprocess, "run", lambda command, **_: calls.append(command))
    f2kboot.add_system_fonts(tmp_path / "disk.img")
    image = f"{tmp_path / 'disk.img'}{f2kboot.PARTITION}"
    assert calls == [
        ["mmd", "-i", image, "::/WINNT/Fonts"],
        ["mcopy", "-i", image, *map(str, f2kboot.system_font_files()), "::/WINNT/Fonts/"],
    ]


# --- Stale build directories and logs are pruned-----------------------------------------------


def test_stale_builds_logs_and_variants_are_pruned(tmp_path):
    hours = 3600
    now = time.time()

    def made(relative: str, age: float, directory: bool = False, finished: bool = True):
        path = tmp_path / relative
        if directory:
            path.mkdir(parents=True)
            if finished:
                (path / "run-id").write_text("an earlier run")
                os.utime(path / "run-id", (now - age, now - age))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        os.utime(path, (now - age, now - age))
        return path

    unused = made("builds/fault-test-user", 8 * 24 * hours, directory=True)
    last_week = made("builds/fault-test-ud", 5 * 24 * hours, directory=True)  # still cached
    unfinished = made("builds/nest-smoke", 5 * hours, directory=True, finished=False)
    old_failure = made("builds/irq-smoke.failed", 5 * hours)
    old_run = made("builds/run.sources", 5 * hours)
    running = made("builds/default", 0.1 * hours, directory=True)  # another run's, in flight
    lock = made("build.lock", 50 * hours)
    old_log = made("logs/test_kernel_crash.log", 72 * hours)
    fresh_log = made("logs/test_sync_event.log", 1 * hours)
    old_variant = made("variants/test_limine_sync-pingpong.img", 5 * hours)

    f2kboot.prune(tmp_path, now=now)

    assert not unused.exists() and not unfinished.exists() and not old_failure.exists()
    assert not old_run.exists() and not old_variant.exists() and not old_log.exists()
    assert last_week.exists() and running.exists() and fresh_log.exists() and lock.exists()


# --- Builds are reused while their sources are unchanged ---------------------------------------


def git(root, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def checkout(tmp_path):
    """A git checkout with a few committed files."""
    root = tmp_path / "checkout"
    for relative, text in (("Makefile", "TARGET ?= x86-f2k\n"), ("kernel/src/lib.rs", "fn a() {}\n"),
                           ("README.md", "# F2K\n"), ("tests/core/test_a.py", "x = 1\n"),
                           ("tests/core/a/output.txt", "A\n")):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text)
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "files")
    return root


def test_the_fingerprint_follows_every_build_input(checkout, monkeypatch):
    fingerprint = f2kboot.source_fingerprint(checkout)
    assert fingerprint is not None and fingerprint == f2kboot.source_fingerprint(checkout)
    seen = {fingerprint}

    def changed() -> bool:
        now = f2kboot.source_fingerprint(checkout)
        new = now not in seen
        seen.add(now)
        return new

    (checkout / "kernel/src/lib.rs").write_text("fn a() { b() }\n")  # modified
    assert changed()
    git(checkout, "add", "kernel/src/lib.rs")  # the same content, staged
    assert not changed()
    (checkout / "kernel/src/lib.rs").write_text("fn a() {}\n")  # back to the committed content
    assert changed()  # (the worktree's content counts, not the index's)
    (checkout / "kernel/src/new.rs").write_text("")  # untracked
    assert changed()
    (checkout / "tests/core/a/output.txt").unlink()  # deleted (a .txt under tests/ may be read)
    assert changed()
    (checkout / "Cargo.lock").write_text("lock")  # ignored by git, read by cargo
    assert changed()
    monkeypatch.setenv("RUSTFLAGS", "-C force-frame-pointers=yes")
    assert changed()
    monkeypatch.setenv("TARGET", "other")  # a Makefile variable
    assert changed()


def test_the_fingerprint_ignores_files_no_build_reads(checkout):
    fingerprint = f2kboot.source_fingerprint(checkout)
    (checkout / "README.md").write_text("# F2K, changed\n")
    (checkout / "tests/core/test_a.py").write_text("x = 2\n")
    (checkout / "tests/core/test_b.py").write_text("")
    (checkout / ".scratch").mkdir()
    (checkout / ".scratch/notes").write_text("")
    assert f2kboot.source_fingerprint(checkout) == fingerprint


def test_no_fingerprint_outside_a_checkout(tmp_path):
    assert f2kboot.source_fingerprint(tmp_path) is None


@pytest.fixture
def fake_make(tmp_path, monkeypatch):
    """f2kboot.build with its make replaced: each call records its features and writes a kernel and
    disk with their stamps, as `make disk` does; `sources` is what source_fingerprint returns
    (None: git cannot tell), `fail` makes the next make fail."""
    work, built_dir = tmp_path / "qemu", tmp_path / "built"
    built_dir.mkdir()
    monkeypatch.setattr(f2kboot, "WORK", work)
    monkeypatch.setattr(f2kboot, "BUILT_KERNEL", built_dir / "f2k-kernel")
    monkeypatch.setattr(f2kboot, "BUILT_DISK", built_dir / "f2k-disk.img")
    state = SimpleNamespace(makes=[], sources="sources-1", fail=False)
    monkeypatch.setattr(f2kboot, "source_fingerprint", lambda root=None: state.sources)
    real_run = subprocess.run

    def run(arguments, **kwargs):
        if arguments[:2] != ["make", "disk"]:
            return real_run(arguments, **kwargs)
        features = arguments[2].split("=", 1)[1]
        state.makes.append(features)
        if state.fail:
            state.fail = False
            return SimpleNamespace(returncode=2, stdout="error: the kernel did not build\n")
        stamp = f"features={features}\nprofile={f2kboot.PROFILE}\n"
        for path in (f2kboot.BUILT_KERNEL, f2kboot.BUILT_DISK):
            path.unlink(missing_ok=True)
            path.write_text(f"{features} from {state.sources}")
            f2kboot.stamp_path(path).write_text(stamp)
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(f2kboot.subprocess, "run", run)
    return state


def test_a_build_is_reused_across_runs_while_its_sources_are_unchanged(fake_make):
    first = f2kboot.build(["irq-smoke"], "run-1")
    assert f2kboot.build(["irq-smoke"], "run-1") == first
    assert first.kernel.read_text() == "irq-smoke from sources-1"
    assert fake_make.makes == ["irq-smoke"]
    # A later run, nothing changed: no make.
    assert f2kboot.build(["irq-smoke"], "run-2") == first
    assert fake_make.makes == ["irq-smoke"]
    # The sources changed: built again, then reused within that run.
    fake_make.sources = "sources-2"
    assert f2kboot.build(["irq-smoke"], "run-3").kernel.read_text() == "irq-smoke from sources-2"
    f2kboot.build(["irq-smoke"], "run-3")
    assert fake_make.makes == ["irq-smoke", "irq-smoke"]
    # Each feature set is a build of its own.
    f2kboot.build([], "run-3")
    assert fake_make.makes == ["irq-smoke", "irq-smoke", ""]


def test_a_build_made_while_its_sources_changed_serves_its_run_alone(fake_make, monkeypatch):
    fingerprints = iter(["sources-1", "sources-1", "sources-2"])  # the run's, before, after make
    monkeypatch.setattr(f2kboot, "source_fingerprint", lambda root=None: next(fingerprints))
    f2kboot.build(["irq-smoke"], "run-1")
    f2kboot.build(["irq-smoke"], "run-1")
    assert fake_make.makes == ["irq-smoke"]
    fingerprints = iter(["sources-1", "sources-1", "sources-1"])
    f2kboot.build(["irq-smoke"], "run-2")
    assert fake_make.makes == ["irq-smoke", "irq-smoke"]


def test_nothing_is_reused_when_git_cannot_tell(fake_make):
    fake_make.sources = None
    f2kboot.build([], "run-1")
    f2kboot.build([], "run-1")
    f2kboot.build([], "run-2")
    assert fake_make.makes == ["", ""]


def test_a_failed_build_fails_the_rest_of_its_run_and_is_retried_by_the_next(fake_make):
    fake_make.fail = True
    for _ in range(2):
        with pytest.raises(f2kboot.BuildError, match="the kernel did not build"):
            f2kboot.build(["nest-smoke"], "run-1")
    assert fake_make.makes == ["nest-smoke"]
    f2kboot.build(["nest-smoke"], "run-2")
    assert fake_make.makes == ["nest-smoke", "nest-smoke"]


def test_a_build_of_another_profile_is_refused(tmp_path):
    build = built(tmp_path, "", "")
    for path in (build.kernel, build.disk):
        f2kboot.stamp_path(path).write_text("features=\nprofile=dev-opt\n")
    assert f2kboot.build_mismatch(build, [], profile="dev-opt") is None
    why = f2kboot.build_mismatch(build, [], profile="dev")
    assert why is not None and "dev-opt" in why


# --- The text screen's read ---------------------------------------------------------------------

XP_DUMP = """00000000000b8000: 0x48 0x07 0x69 0x07 0x20 0x1e 0x00 0x00
00000000000b8008: 0xdb 0x70
"""


def test_an_xp_dump_drops_its_addresses_and_decodes_the_bytes():
    assert f2kboot.parse_xp(XP_DUMP) == bytes([0x48, 0x07, 0x69, 0x07, 0x20, 0x1E, 0, 0, 0xDB, 0x70])
    with pytest.raises(ValueError):
        f2kboot.parse_xp("0x48 0x07\n")


def test_a_text_page_dump_is_characters_then_attributes():
    screen = f2kboot.text_screen_of(f2kboot.parse_xp(XP_DUMP))
    assert screen.cells == [(0x48, 0x07), (0x69, 0x07), (0x20, 0x1E), (0, 0), (0xDB, 0x70)]
    assert screen.text(0) == "Hi \x00\xdb"
    with pytest.raises(ValueError):
        f2kboot.text_screen_of(b"\x48")


def png_of(rows: list[bytes], filters: list[int], path) -> None:
    """Write 8-bit RGB `rows` as a PNG, each row under its filter (0-4)."""
    import struct
    import zlib

    width = len(rows[0]) // 3

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    raw, previous = bytearray(), bytes(len(rows[0]))
    for row, kind in zip(rows, filters):
        encoded = bytearray()
        for x, value in enumerate(row):
            left = row[x - 3] if x >= 3 else 0
            up = previous[x]
            corner = previous[x - 3] if x >= 3 else 0
            guess = left + up - corner
            paeth = min((abs(guess - left), 0, left), (abs(guess - up), 1, up),
                        (abs(guess - corner), 2, corner))[2]
            predicted = (0, left, up, (left + up) // 2, paeth)[kind]
            encoded.append((value - predicted) & 0xFF)
        raw += bytes([kind]) + encoded
        previous = row
    header = struct.pack(">IIBBBBB", width, len(rows), 8, 2, 0, 0, 0)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                     + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b""))


def test_a_png_decodes_under_every_row_filter(tmp_path):
    rows = [bytes((x * 37 + y * 11 + (x * y) % 7) & 0xFF for x in range(3 * 20)) for y in range(5)]
    path = tmp_path / "filters.png"
    png_of(rows, [0, 1, 2, 3, 4], path)
    image = f2kboot.read_png(path)
    assert (image.width, image.height, image.rows) == (20, 5, rows)


def test_differing_cells_name_the_text_cells_a_change_touches(tmp_path):
    width, height = 2 * f2kboot.CELL_WIDTH, 2 * f2kboot.CELL_HEIGHT
    blank = [bytes(3 * width) for _ in range(height)]
    marked = [bytearray(row) for row in blank]
    # One pixel in cell (1, 0), one in cell (0, 1).
    marked[f2kboot.CELL_HEIGHT + 3][3 * 2] = 0xA8
    marked[5][3 * (f2kboot.CELL_WIDTH + 8) + 1] = 0xA8
    paths = tmp_path / "blank.png", tmp_path / "marked.png"
    png_of(blank, [0] * height, paths[0])
    png_of([bytes(row) for row in marked], [4] * height, paths[1])
    a, b = (f2kboot.read_png(path) for path in paths)
    assert f2kboot.differing_cells(a, a) == set()
    assert f2kboot.differing_cells(a, b) == {(1, 0), (0, 1)}
    assert f2kboot.lit_pixels(b, (1, 0)) == 1 and f2kboot.lit_pixels(a, (1, 0)) == 0


# --- The screen baselines ------------------------------------------------------------------------


def image_of(width: int, height: int, seed: int = 0) -> f2kboot.Image:
    """A synthetic image, every pixel its own colour."""
    return f2kboot.Image(width, height, [bytes((x * 37 + y * 11 + seed + c * 5) & 0xFF
                                               for x in range(width) for c in range(3))
                                         for y in range(height)])


def with_pixel(image: f2kboot.Image, x: int, y: int, pixel: bytes) -> f2kboot.Image:
    rows = list(image.rows)
    row = bytearray(rows[y])
    row[3 * x:3 * x + 3] = pixel
    rows[y] = bytes(row)
    return f2kboot.Image(image.width, image.height, rows)


def test_the_canonical_encoding_round_trips_through_read_png(tmp_path):
    image = image_of(23, 7)
    path = tmp_path / "a.png"
    f2kboot.write_png(path, image)
    assert f2kboot.read_png(path) == image
    assert f2kboot.is_canonical(path)


def test_the_canonical_encoding_is_deterministic_and_only_ihdr_idat_iend(tmp_path):
    image = image_of(16, 9)
    data = f2kboot.encode_png(image)
    assert data == f2kboot.encode_png(f2kboot.Image(16, 9, [bytes(row) for row in image.rows]))
    at, kinds = 8, []
    while at < len(data):
        length, kind = struct.unpack(">I4s", data[at:at + 8])
        kinds.append(kind)
        at += 12 + length
    assert kinds == [b"IHDR", b"IDAT", b"IEND"]


def test_a_png_in_another_encoding_is_not_canonical(tmp_path):
    rows = image_of(20, 5).rows
    path = tmp_path / "filters.png"
    png_of(rows, [0, 1, 2, 3, 4], path)
    assert not f2kboot.is_canonical(path)
    f2kboot.write_png(path, f2kboot.read_png(path))
    assert f2kboot.is_canonical(path) and f2kboot.read_png(path).rows == rows


def test_compare_images_counts_and_boxes_the_differing_pixels():
    a = image_of(30, 20)
    b = with_pixel(with_pixel(a, 4, 3, b"\x01\x02\x03"), 17, 11, b"\x09\x09\x09")
    assert f2kboot.compare_images(a, a) == f2kboot.PixelDiff(0, None)
    assert f2kboot.compare_images(a, b) == f2kboot.PixelDiff(2, (4, 3, 18, 12))
    # A mask over one of them leaves the other.
    assert f2kboot.compare_images(a, b, ((15, 10, 20, 15),)) == f2kboot.PixelDiff(1, (4, 3, 5, 4))
    with pytest.raises(ValueError):
        f2kboot.compare_images(a, image_of(30, 21))


def test_the_diff_image_marks_the_differing_and_masked_pixels():
    a = image_of(10, 6)
    b = with_pixel(a, 2, 1, b"\x00\x00\x00")
    diff = f2kboot.diff_image(a, b, ((8, 0, 10, 1),))
    assert diff.pixel(2, 1) == f2kboot.DIFF_PIXEL
    assert diff.pixel(9, 0) == f2kboot.MASKED_PIXEL
    grey = diff.pixel(5, 5)
    assert grey[0] == grey[1] == grey[2] and grey != f2kboot.DIFF_PIXEL


def screen_and_baseline(tmp_path, screen: f2kboot.Image, baseline: f2kboot.Image | None):
    dump, kept = tmp_path / "scratch" / "s.png", tmp_path / "baselines" / "s.png"
    dump.parent.mkdir()
    png_of(screen.rows, [4] * screen.height, dump)  # a dump in QEMU's kind of encoding, not canonical
    if baseline is not None:
        f2kboot.write_png(kept, baseline)
    return dump, kept


def test_identical_pixels_leave_the_baseline_untouched(tmp_path):
    image = image_of(12, 8)
    dump, kept = screen_and_baseline(tmp_path, image, image)
    before = kept.stat().st_mtime_ns, kept.read_bytes()
    assert dump.read_bytes() != kept.read_bytes()  # other bytes, the same pixels
    assert f2kboot.check_screen(dump, kept) is None
    assert (kept.stat().st_mtime_ns, kept.read_bytes()) == before
    assert not dump.with_name("s.diff.png").exists()


def test_changed_pixels_rewrite_the_baseline_and_write_a_diff(tmp_path):
    old = image_of(12, 8)
    new = with_pixel(old, 3, 5, b"\xff\xff\xff")
    dump, kept = screen_and_baseline(tmp_path, new, old)
    problem = f2kboot.check_screen(dump, kept)
    assert problem is not None and "1 pixels differ, within (3, 5, 4, 6)" in problem and "commit it" in problem
    assert f2kboot.read_png(kept) == new and f2kboot.is_canonical(kept)
    diff = f2kboot.read_png(dump.with_name("s.diff.png"))
    assert diff.pixel(3, 5) == f2kboot.DIFF_PIXEL
    # Accepted (the rewritten file committed): the rerun passes, its stale diff gone.
    assert f2kboot.check_screen(dump, kept) is None
    assert not dump.with_name("s.diff.png").exists()


def test_masked_pixels_do_not_count(tmp_path):
    old = image_of(12, 8)
    dump, kept = screen_and_baseline(tmp_path, with_pixel(old, 3, 5, b"\xff\xff\xff"), old)
    before = kept.read_bytes()
    assert f2kboot.check_screen(dump, kept, ((0, 4, 12, 6),)) is None
    assert kept.read_bytes() == before


def test_a_missing_baseline_is_written_and_fails(tmp_path):
    image = image_of(12, 8)
    dump, kept = screen_and_baseline(tmp_path, image, None)
    problem = f2kboot.check_screen(dump, kept)
    assert problem is not None and "new baseline written, commit it to accept" in problem
    assert f2kboot.read_png(kept) == image and f2kboot.is_canonical(kept)


def test_a_resized_screen_rewrites_the_baseline(tmp_path):
    dump, kept = screen_and_baseline(tmp_path, image_of(12, 8), image_of(10, 8))
    problem = f2kboot.check_screen(dump, kept)
    assert problem is not None and "12x8" in problem and "10x8" in problem
    assert (f2kboot.read_png(kept).width, f2kboot.read_png(kept).height) == (12, 8)


BASELINE_FILES = sorted(f2kboot.BASELINES.glob("*/*.png"))


def test_the_baselines_exist():
    names = {path.relative_to(f2kboot.BASELINES).as_posix() for path in BASELINE_FILES}
    assert {"dialogs/dialog.png", "nonclient/window.png", "nonclient/menu.png", "nonclient/after.png",
            "tahoma/fontshow.png"} <= names


@pytest.mark.parametrize("path", BASELINE_FILES, ids=lambda path: path.relative_to(f2kboot.BASELINES).as_posix())
def test_a_committed_baseline_is_canonical(path):
    """Decoded then re-encoded, a baseline gives back its own bytes: written by the canonical
    encoder (`f2kboot.check_screen`), not copied from a dump or another tool."""
    assert f2kboot.is_canonical(path), (f"{path.relative_to(f2kboot.REPO_ROOT)} is not in the canonical"
                                        f" encoding (zlib {zlib.ZLIB_RUNTIME_VERSION}): rewrite it with"
                                        " f2kboot.write_png(path, f2kboot.read_png(path))")
