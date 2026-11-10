"""Checks on the harness's own judgements: the logs, the build stamps, the boots' QEMU, the kept
disks and the host's read of their volume."""
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

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
        for pattern in (f2kboot.END, f2kboot.TEARDOWN, f2kboot.OBJECT_LEAK, f2kboot.START, f2kboot.SCREEN_PAUSE):
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


def test_a_childs_end_takes_no_screenshot(tmp_path):
    # No pause announced: the taker reaches for no monitor (there is none at this socket's path).
    taker = f2kboot.ScreenTaker([f2kboot.Block("t.exe a")], tmp_path)
    taker(tmp_path / "no.sock", "\n".join(WITH_CHILDREN))
    assert taker.taken == 0


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

    def item(param):
        marks = [decorator.mark for decorator in param.marks]
        return SimpleNamespace(function=test, callspec=SimpleNamespace(params={"captured": param.values[0]}),
                               get_closest_marker=lambda name: next((m for m in marks if m.name == name), None))

    selected = conftest.batch_items(SimpleNamespace(items=[item(param) for param in params.values()]), test)
    blocks = [each.callspec.params["captured"].block for each in selected]
    assert f2kboot.batch_command_line([block.command for block in blocks]) == (
        "CORPUS\\fakesec.exe a ;; CORPUS\\fakesec.exe c")
    log = "\n".join(BATCH_BOOT + [line.replace("t.exe", "fakesec.exe").replace(" of 3", " of 2")
                                  for line in leg(1, "t.exe a", "A") + leg(2, "t.exe c", "C")]
                    + ["F2K: process suite complete: 2 run, 0 faulted, 0 leaks"]) + "\n"
    batch = f2kboot.Batch([block.command for block in blocks], log, tmp_path / "fakesec.log", "done",
                          *f2kboot.split_programs(log))
    assert [batch.verdict(index, [], block) for index, block in enumerate(blocks)] == [None, None]


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
    assert copies == [([built / "cmd.exe"], variant, {"corpus": []})]
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
    assert copies == [([], variant, {"corpus": [directory / "f2ktahom.ttf"]})]
    for wrong in ('"f2ktahom.ttf"', '[1]', '[""]', '["a.ttf", "a.ttf"]'):
        declared.write_text(f'kind = "sectioned"\ndata_files = {wrong}\n')
        with pytest.raises(ValueError, match="data_files"):
            f2kboot.data_files("secfake")


# --- Stale build directories and logs are pruned-----------------------------------------------


def test_stale_builds_logs_and_variants_are_pruned(tmp_path):
    hours = 3600
    now = time.time()

    def made(relative: str, age: float, directory: bool = False):
        path = tmp_path / relative
        if directory:
            path.mkdir(parents=True)
            (path / "run-id").write_text("an earlier run")
            os.utime(path / "run-id", (now - age, now - age))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        os.utime(path, (now - age, now - age))
        return path

    old_build = made("builds/fault-test-user", 5 * hours, directory=True)
    old_failure = made("builds/irq-smoke.failed", 5 * hours)
    running = made("builds/default", 0.1 * hours, directory=True)  # another run's, in flight
    lock = made("build.lock", 50 * hours)
    old_log = made("logs/test_kernel_crash.log", 72 * hours)
    fresh_log = made("logs/test_sync_event.log", 1 * hours)
    old_variant = made("variants/test_limine_sync-pingpong.img", 5 * hours)

    f2kboot.prune(tmp_path, now=now)

    assert not old_build.exists() and not old_failure.exists() and not old_variant.exists()
    assert not old_log.exists()
    assert running.exists() and fresh_log.exists() and lock.exists()


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
