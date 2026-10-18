"""Checks on the harness's own judgements: the logs, the build stamps, the boots' QEMU."""
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

import f2kboot

ENDED = [
    "F2K: entering ring 3",
    "hello",
    "F2K: user process exited normally (exit code=0)",
]
CLEAN = "F2K: teardown audit: frame database ok, kernel heap ok"
LEAKED = "F2K: teardown audit FAILED: 1234 frames available, 1240 before the process (frame database ok, kernel heap ok)"


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
    assert f2kboot.teardown_audited("F2K: process 3 teardown audit: frame database ok, kernel heap ok")


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


# --- Masks: one value each, in their own section-----------------------------------------------


def test_a_mask_star_stands_for_one_value():
    mask = f2kboot.mask_pattern("region * allocprotect 0x0")
    assert mask.fullmatch("region 0x77B50000 allocprotect 0x0")
    assert not mask.fullmatch("region  allocprotect 0x0"), "an empty value"
    assert not mask.fullmatch("region 0x1 allocprotect 0x4 region 0x2 allocprotect 0x0"), "a run of fields"


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
