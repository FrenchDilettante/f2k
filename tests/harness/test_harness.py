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


# --- Batches: a fixture's blocks in one boot, each judged on its own part of the log -------------

BATCH_BOOT = [*f2kboot.BOOT_CHECKS, "F2K: command line: CORPUS\\t.exe a ;; CORPUS\\t.exe b ;; CORPUS\\t.exe c"]


def leg(index: int, command: str, output: str, code: int = 0) -> list[str]:
    return [f"F2K: process {index} of 3: CORPUS\\{command}", "F2K: entering ring 3", output,
            f"F2K: process {index} (t) exited normally (exit code={code})",
            f"F2K: process {index} teardown audit: frame database ok, kernel heap ok"]


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


def test_pins_name_sections_and_exports():
    """A fixture's pins are keyed by section name ("*" for every block) and name dll.Export."""
    assert f2kboot.blocks("memory", gate=True, pins={"*": ["kernel32.HeapAlloc"], "heap": ["ntdll.RtlSizeHeap"]})
    with pytest.raises(ValueError, match="nosuch"):
        f2kboot.blocks("memory", gate=True, pins={"nosuch": ["kernel32.HeapAlloc"]})
    with pytest.raises(ValueError, match="not dll.Export"):
        f2kboot.blocks("memory", gate=True, pins={"heap": ["HeapAlloc"]})


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
