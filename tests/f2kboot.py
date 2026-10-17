"""Boot F2K in QEMU for the test suites.

Three pieces the test modules share:

- builds: `make disk` with a set of cargo features, kept per feature set under target/qemu/builds
  and reused for the rest of the test run (the builds serialize across pytest-xdist workers on a
  file lock: they share cargo's target directory);
- boots: QEMU with COM1 logged to a file, the disk attached as a snapshot (so boots run side by
  side), stopped as soon as the caller's check has its answer;
- checks: the kernel cases' expected-string rules (`Expectation`), and the corpus's capture blocks
  compared against the program output a boot carries (`Block`, `blocks`).
"""
from __future__ import annotations

import fcntl
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
QEMU = os.environ.get("QEMU", "qemu-system-i386")
WORK = REPO_ROOT / "target" / "qemu"
BUILT_KERNEL = REPO_ROOT / "target" / "x86-f2k" / "debug" / "f2k-kernel"
BUILT_DISK = REPO_ROOT / "target" / "x86-f2k" / "debug" / "f2k-disk.img"


# --- Builds -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Build:
    """A built kernel ELF and the disk image built with it."""

    kernel: Path
    disk: Path


class BuildError(Exception):
    """`make disk` failed; the message carries the output's tail."""


def build(features: list[str], run_id: str) -> Build:
    """The kernel and disk built with `features`: built once per test run (`run_id`), then
    reused."""
    key = "+".join(features) or "default"
    out = WORK / "builds" / key
    WORK.mkdir(parents=True, exist_ok=True)
    with open(WORK / "build.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = out / "run-id"
        if marker.exists() and marker.read_text() == run_id:
            return Build(out / "f2k-kernel", out / "f2k-disk.img")
        made = subprocess.run(
            ["make", "disk", f"CARGO_FEATURES={','.join(features)}"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if made.returncode != 0:
            tail = "\n".join(made.stdout.splitlines()[-40:])
            raise BuildError(f"make disk CARGO_FEATURES={','.join(features)} failed:\n{tail}")
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        shutil.copy2(BUILT_KERNEL, out / "f2k-kernel")
        # The disk build deletes and recreates its image, so a hard link keeps this one intact
        # through later builds (and costs no copy of the 64 MiB).
        try:
            os.link(BUILT_DISK, out / "f2k-disk.img")
        except OSError:
            shutil.copy2(BUILT_DISK, out / "f2k-disk.img")
        marker.write_text(run_id)
    return Build(out / "f2k-kernel", out / "f2k-disk.img")


def last_build() -> Build:
    """The kernel and disk the last `make disk` left (whatever its features)."""
    return Build(BUILT_KERNEL, BUILT_DISK)


# --- Boots ------------------------------------------------------------------------------------


def boot(
    build: Build,
    *,
    image: str,
    log_path: Path,
    timeout: float,
    done: Callable[[str], bool],
    cmdline: str | None = None,
    memory: str = "64M",
) -> tuple[str, str]:
    """Boot `build` (`image` "kernel": the ELF through QEMU's Multiboot loader, the disk attached;
    "disk": the disk itself through Limine) and log COM1 to `log_path` until `done(log)` holds, QEMU
    exits, or `timeout` seconds pass. `cmdline` is the user program's command line (kernel boots
    only), passed after the kernel command line's "--". Returns the log and why the boot stopped
    ("done", "exited", "timeout")."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.unlink(missing_ok=True)
    args = [QEMU]
    if image == "kernel":
        args += ["-kernel", str(build.kernel)]
        if cmdline:
            args += ["-append", f"-- {cmdline}"]
    elif cmdline:
        raise ValueError("a command line needs a kernel boot (QEMU -append)")
    args += [
        "-drive", f"file={build.disk},format=raw,if=ide,snapshot=on",
        "-m", memory, "-display", "none", "-monitor", "none", "-net", "none",
        # -no-reboot turns a triple fault into a QEMU exit, so crashes fail fast.
        "-no-reboot", "-serial", f"file:{log_path}",
    ]
    qemu = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + timeout
    reason = "timeout"
    try:
        while time.monotonic() < deadline:
            if done(read_log(log_path)):
                reason = "done"
                break
            if qemu.poll() is not None:
                reason = "exited"
                break
            time.sleep(0.1)
    finally:
        qemu.kill()
        _, stderr = qemu.communicate()
    log = read_log(log_path)
    if reason != "done" and done(log):
        reason = "done"  # QEMU wrote the answer just before it stopped
    if reason == "exited" and stderr:
        log += f"\n--- QEMU stderr ---\n{stderr.decode(errors='replace')}"
    return log, reason


def read_log(path: Path) -> str:
    try:
        return path.read_text(encoding="latin-1")
    except FileNotFoundError:
        return ""


def lines_of(log: str) -> list[str]:
    return [line.rstrip("\r") for line in log.splitlines()]


def tail(log: str, count: int = 40) -> str:
    return "\n".join(lines_of(log)[-count:])


# --- The kernel cases' expected-string rules ---------------------------------------------------


def matches(expected: str, line: str) -> bool:
    """Whether a line satisfies an `expects` string: a substring, or a `re:` regular expression."""
    if expected.startswith("re:"):
        return re.search(expected[3:], line) is not None
    return expected in line


@dataclass
class Expectation:
    """A kernel case's COM1 rules: every `expects` string appears on some line (in order, each on a
    later line, when `ordered`); the `contiguous` strings match consecutive lines, in order; no
    `forbids` string appears. An `expects` string written `re:<pattern>` is a regular expression
    searched in the line instead of a substring."""

    expects: list[str]
    ordered: bool = False
    contiguous: list[str] = field(default_factory=list)
    forbids: list[str] = field(default_factory=list)

    def check(self, log: str) -> tuple[str, str]:
        """("pass", ""), ("forbidden", the string), or ("pending", what is still missing)."""
        seen = [False] * len(self.expects)
        next_expect = 0
        next_block = 0
        for line in lines_of(log):
            for forbidden in self.forbids:
                if forbidden in line:
                    return "forbidden", forbidden
            if self.ordered:
                if next_expect < len(self.expects) and matches(self.expects[next_expect], line):
                    next_expect += 1
            else:
                for index, expected in enumerate(self.expects):
                    if not seen[index] and matches(expected, line):
                        seen[index] = True
            if next_block < len(self.contiguous):
                if self.contiguous[next_block] in line:
                    next_block += 1
                else:
                    next_block = 1 if self.contiguous[0] in line else 0
        if self.ordered and next_expect < len(self.expects):
            return "pending", f"in order, next: {self.expects[next_expect]!r}"
        missing = [e for e, ok in zip(self.expects, seen) if not ok] if not self.ordered else []
        if missing:
            return "pending", "missing: " + ", ".join(repr(m) for m in missing)
        if next_block < len(self.contiguous):
            return "pending", f"contiguous block broken before {self.contiguous[next_block]!r}"
        return "pass", ""


# --- The corpus's capture blocks ------------------------------------------------------------------

ENTER = "F2K: entering ring 3"
# The boot's own checks, reported before any program runs: every block's boot must pass them.
BOOT_CHECKS = ("F2K Booted Successfully", "F2K: frame database audit: ok", "F2K: kernel heap: alloc/free ok")
END = re.compile(r"^F2K: user process (exited normally|ended by fault)")
EXIT_CODE = re.compile(r"exit code=(\d+)")
# Kernel output inside the program's span: its own report lines and the fault dump.
KERNEL_PREFIXES = ("F2K:", "CPU EXCEPTION:")
DUMP_PREFIXES = ("  error code ", "  EAX ", "  ESI ", "  DS ", "  raised from ring 3", "  CR2 ")


@dataclass
class Block:
    """One captured run: its command line, the program's output, and the exit code (None when the
    capture did not record one)."""

    command: str
    lines: list[str] = field(default_factory=list)
    exit_code: int | None = None

    @property
    def section(self) -> str:
        return self.command.split(" ", 1)[1] if " " in self.command else "(default)"


def parse_capture(path: Path) -> list[Block]:
    """A capture's blocks (tests/capture.bat's ">>> command / output / <<< exit code=N")."""
    blocks: list[Block] = []
    for line in lines_of(path.read_text(encoding="latin-1")):
        if line.startswith(">>> "):
            blocks.append(Block(line[4:]))
        elif not blocks:
            continue  # a header before the first block
        elif line.startswith("<<< exit code="):
            blocks[-1].exit_code = int(line[len("<<< exit code="):]) & 0xFFFFFFFF
        else:
            blocks[-1].lines.append(line)
    for block in blocks:
        while block.lines and not block.lines[-1].strip():
            block.lines.pop()
    return blocks


def mask_pattern(mask: str) -> re.Pattern[str]:
    """A capture mask: "*" stands for any run of characters, the rest is literal."""
    return re.compile(".*".join(re.escape(part) for part in mask.split("*")))


def process_ended(log: str) -> bool:
    return any(END.match(line) for line in lines_of(log)) or "KERNEL PANIC" in log


def program_output(log: str) -> tuple[list[str], int | None]:
    """The program's lines in a boot's log and its exit code (None when it did not end)."""
    lines = lines_of(log)
    start = next((i + 1 for i, line in enumerate(lines) if line.startswith(ENTER)), None)
    if start is None:
        return [], None
    output = []
    for line in lines[start:]:
        if END.match(line):
            match = EXIT_CODE.search(line)
            return output, int(match.group(1)) if match else None
        if line.startswith(KERNEL_PREFIXES) or line.startswith(DUMP_PREFIXES):
            continue
        output.append(line)
    return output, None


def compare_block(block: Block, log: str, masks: list[re.Pattern[str]]) -> str | None:
    """None when the boot reproduced the block; otherwise why not, in one line."""
    lines = lines_of(log)
    if "KERNEL PANIC" in log:
        at = next(i for i, line in enumerate(lines) if "KERNEL PANIC" in line)
        message = " ".join(line.strip() for line in lines[at:at + 3] if line.strip())
        return message
    # The boot's own checks hold under every program: the kernel reports them and carries on.
    failed = next((line.strip() for line in lines if "audit FAILED" in line or "audit: FAILED" in line), None)
    if failed is not None:
        return failed
    for check in BOOT_CHECKS:
        if not any(line.startswith(check) for line in lines):
            return f"the boot did not report [{check}]"
    if not any(line.startswith(ENTER) for line in lines):
        refusal = next(
            (line.strip() for line in lines
             if "not loaded" in line or "refused" in line or "names no file" in line),
            "the program never entered ring 3",
        )
        return refusal
    actual, exit_code = program_output(log)

    def same(expected: str, got: str) -> bool:
        return expected == got or any(m.fullmatch(expected) and m.fullmatch(got) for m in masks)

    for number, expected in enumerate(block.lines, start=1):
        if number > len(actual):
            return f"line {number}: missing, expected [{expected}]"
        if not same(expected, actual[number - 1]):
            return f"line {number}: [{actual[number - 1]}], expected [{expected}]"
    if len(actual) > len(block.lines):
        return f"line {len(block.lines) + 1}: extra [{actual[len(block.lines)]}]"
    if exit_code is None:
        return "the process did not end"
    if block.exit_code is not None and exit_code != block.exit_code:
        return f"exit code {exit_code:#010x}, expected {block.exit_code:#010x}"
    return None


# --- The sectioned corpus ------------------------------------------------------------------------
#
# Each sectioned fixture's real-machine capture, tests/<name>/output.txt (tests/capture.bat), is its
# expectation, and tests/<name>/test_<name>.py runs it: one test per captured block, through
# `blocks` and the `run_block` fixture (tests/conftest.py).

# The fixtures' directory on the boot volume (the Makefile's CORPUS_FIXTURES go to \CORPUS): each
# block's program runs from there, as each runs from its own directory on the real machine.
CORPUS_DIRECTORY = "CORPUS"
CORPUS_TIMEOUT = 20.0


@dataclass(frozen=True)
class Captured:
    """One captured block of a fixture, with what its comparison allows."""

    fixture: str
    block: Block
    masks: tuple[re.Pattern[str], ...]
    timeout: float


def blocks(
    fixture: str,
    *,
    gate: bool = False,
    pending: dict[str, str] | None = None,
    masks: tuple[str, ...] = (),
    timeout: float = CORPUS_TIMEOUT,
    retake: str | None = None,
) -> list:
    """A fixture's captured blocks as pytest parameters, one per block, its section the id.

    - `gate`: the blocks must pass. Without it the fixture is on the work list: its blocks run as
      expected failures (one that starts passing shows as XPASS; `--runxfail` shows why the others
      fail).
    - `pending`: in a gated fixture, the sections still on the work list, each with what it waits
      for: those blocks run as expected failures.
    - `masks`: capture lines that carry machine-specific values F2K cannot reproduce (an address,
      the size of a free region the real machine's other allocations bound). A capture line matching
      a mask matches any line that matches the same mask; "*" stands for any run of characters.
    - `timeout`: seconds per boot.
    - `retake`: the capture must be retaken before it counts (the reason): the blocks are skipped.
    """
    import pytest

    marks = [pytest.mark.corpus]
    if retake is not None:
        marks.append(pytest.mark.skip(reason=f"capture to retake: {retake}"))
    elif not gate:
        marks.append(pytest.mark.xfail(reason=f"{fixture} is not served yet", strict=False))
    patterns = tuple(mask_pattern(mask) for mask in masks)
    params = []
    seen: dict[str, int] = {}
    for block in parse_capture(REPO_ROOT / "tests" / fixture / "output.txt"):
        seen[block.section] = seen.get(block.section, 0) + 1
        case_id = block.section if seen[block.section] == 1 else f"{block.section}#{seen[block.section]}"
        block_marks = marks
        if gate and pending and block.section in pending:
            block_marks = marks + [pytest.mark.xfail(reason=pending[block.section], strict=False)]
        params.append(pytest.param(Captured(fixture, block, patterns, timeout), id=case_id, marks=block_marks))
    return params


def log_path_for(nodeid: str) -> Path:
    """Where a test's COM1 log goes: target/qemu/logs/<test id>.log."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", nodeid.split("::", 1)[-1]).strip("_")
    return WORK / "logs" / f"{safe}.log"
