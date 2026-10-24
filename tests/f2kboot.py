"""Boot F2K in QEMU for the test suites.

Three pieces the test modules share:

- builds: `make disk` with a set of cargo features, kept per feature set under target/qemu/builds
  and reused for the rest of the test run (the builds serialize across pytest-xdist workers on a
  file lock: they share cargo's target directory);
- boots: QEMU with COM1 logged to a file, the disk attached as a snapshot (so boots run side by
  side), stopped as soon as the caller's check has its answer;
- checks: the kernel cases' expected-string rules (`Expectation`), and the corpus's capture blocks
  compared against the program output a boot carries (`Block`, `blocks`); a sectioned fixture's
  tests come from its declaration, tests/<dll>/<fixture>/fixture.toml (`corpus_test`); a
  fixture's blocks run in one boot, each its own process, and each is compared on its own part of
  the log (`boot_batch`, `Batch`);
- the text screen: a boot that asks for it carries a QMP socket, and the machine's VGA text page is
  read through it while QEMU still runs (`read_text_screen`, `TextScreen`), or drawn as QEMU shows
  it (`screendump`, a PNG; `read_png`, `differing_cells`).
"""
from __future__ import annotations

import fcntl
import functools
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import tomllib
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS = REPO_ROOT / "tests"
QEMU = os.environ.get("QEMU", "qemu-system-i386")
WORK = REPO_ROOT / "target" / "qemu"
# The kernel's cargo profile (the Makefile's KERNEL_PROFILE, which `make test` passes on): dev, the
# unoptimized default, or dev-opt, optimized with the debug checks kept. Each builds in its own
# directory.
PROFILE = os.environ.get("F2K_KERNEL_PROFILE") or "dev"
BUILT = REPO_ROOT / "target" / "x86-f2k" / ("debug" if PROFILE == "dev" else PROFILE)
BUILT_KERNEL = BUILT / "f2k-kernel"
BUILT_DISK = BUILT / "f2k-disk.img"


# --- Builds -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Build:
    """A built kernel ELF and the disk image built with it."""

    kernel: Path
    disk: Path


class BuildError(Exception):
    """`make disk` failed; the message carries the output's tail."""


def read_text(path: Path) -> str | None:
    """A small state file's contents, or None when there is none."""
    try:
        return path.read_text()
    except FileNotFoundError:
        return None


# How long one `make disk` may take before the build counts as failed (a cargo blocked on another
# holder of its own lock, for instance, would otherwise hang every worker). Seconds; overridable.
BUILD_TIMEOUT = float(os.environ.get("F2K_BUILD_TIMEOUT", "1200"))


def build(features: list[str], run_id: str) -> Build:
    """The kernel and disk built with `features`: built once per test run (`run_id`), then
    reused. A build that failed in this run fails every later request at once, with its output."""
    key = "+".join(features) or "default"
    if PROFILE != "dev":
        key = f"{PROFILE}-{key}"
    out = WORK / "builds" / key
    marker = out / "run-id"
    failed = WORK / "builds" / f"{key}.failed"
    # Already built in this run: the marker is written only once the build's files are in place,
    # and nothing rewrites them within a run, so this check needs no lock (and does not wait behind
    # another worker's build of a different feature set).
    if read_text(marker) == run_id:
        return Build(out / "f2k-kernel", out / "f2k-disk.img")
    WORK.mkdir(parents=True, exist_ok=True)
    with open(WORK / "build.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if read_text(marker) == run_id:
            return Build(out / "f2k-kernel", out / "f2k-disk.img")
        recorded = read_text(failed)
        if recorded is not None and recorded.startswith(run_id + "\n"):
            raise BuildError(recorded.split("\n", 1)[1])
        command = f"make disk CARGO_FEATURES={','.join(features)} KERNEL_PROFILE={PROFILE}"
        try:
            made = subprocess.run(
                ["make", "disk", f"CARGO_FEATURES={','.join(features)}", f"KERNEL_PROFILE={PROFILE}"],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=BUILD_TIMEOUT,
            )
            error = None
            if made.returncode != 0:
                tail = "\n".join(made.stdout.splitlines()[-40:])
                error = f"{command} failed:\n{tail}"
        except subprocess.TimeoutExpired:
            error = f"{command} did not finish within {BUILD_TIMEOUT:.0f} s (F2K_BUILD_TIMEOUT)"
        if error is not None:
            failed.parent.mkdir(parents=True, exist_ok=True)
            failed.write_text(f"{run_id}\n{error}")
            raise BuildError(error)
        # The stamps say what the make built: a concurrent `make disk` in the same tree would show.
        mismatch = build_mismatch(last_build(), features)
        if mismatch is not None:
            error = f"{command} left another build: {mismatch}"
            failed.parent.mkdir(parents=True, exist_ok=True)
            failed.write_text(f"{run_id}\n{error}")
            raise BuildError(error)
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        shutil.copy2(BUILT_KERNEL, out / "f2k-kernel")
        shutil.copy2(stamp_path(BUILT_KERNEL), stamp_path(out / "f2k-kernel"))
        shutil.copy2(stamp_path(BUILT_DISK), stamp_path(out / "f2k-disk.img"))
        # The disk build deletes and recreates its image, so a hard link keeps this one intact
        # through later builds (and costs no copy of the 64 MiB).
        try:
            os.link(BUILT_DISK, out / "f2k-disk.img")
        except OSError:
            shutil.copy2(BUILT_DISK, out / "f2k-disk.img")
        marker.write_text(run_id)
    return Build(out / "f2k-kernel", out / "f2k-disk.img")


# How long a test run's leftovers are kept: a build directory serves only the run that made it (the
# cache is keyed on the run id), so one an hour old belongs to no run still going; a log is kept
# for two days for inspection (each test rewrites its own, so only removed or renamed tests' logs
# grow old); a disk variant outlives its boot only when the boot's process died.
BUILD_AGE = 3600.0
LOG_AGE = 2 * 86400.0


def prune(work: Path = WORK, now: float | None = None) -> None:
    """Remove the earlier runs' leftovers under `work`: their builds and recorded build failures,
    stale logs, and stray disk variants. Called once per test session, before anything builds."""
    now = time.time() if now is None else now

    def older(path: Path, age: float) -> bool:
        try:
            return now - path.stat().st_mtime > age
        except FileNotFoundError:
            return False

    builds = work / "builds"
    for entry in builds.iterdir() if builds.is_dir() else ():
        if entry.is_dir():
            # A build's age is its marker's (written last); one without a marker never finished.
            marker = entry / "run-id"
            if older(marker if marker.exists() else entry, BUILD_AGE):
                shutil.rmtree(entry, ignore_errors=True)
        elif older(entry, BUILD_AGE):
            entry.unlink(missing_ok=True)
    for directory, age in (
        (work / "logs", LOG_AGE),
        (work / "profiles", LOG_AGE),
        (work / "variants", BUILD_AGE),
    ):
        for entry in directory.iterdir() if directory.is_dir() else ():
            if entry.is_file() and older(entry, age):
                entry.unlink(missing_ok=True)


def last_build() -> Build:
    """The kernel and disk the last `make disk` left (whatever its features: see `build_mismatch`)."""
    return Build(BUILT_KERNEL, BUILT_DISK)


# --- Build stamps -------------------------------------------------------------------------------
#
# The Makefile writes what each build was made with beside it: the kernel target beside the ELF,
# the disk target beside the image (`<file>.build`, `key=value` lines; removed before a build,
# written once it succeeded). A boot of a build on disk (`--no-build`) checks them against what the
# test needs, so a feature build left by the last `make disk` is never mistaken for the plain one.


def stamp_path(path: Path) -> Path:
    """Where the Makefile records what `path` (the kernel ELF, the disk image) was built with."""
    return path.with_name(path.name + ".build")


def read_stamp(path: Path) -> dict[str, str] | None:
    """The build stamp of `path`, None when it has none."""
    text = read_text(stamp_path(path))
    if text is None:
        return None
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def feature_set(features) -> tuple[str, ...]:
    """A feature list in one canonical form (sorted, no blanks)."""
    if isinstance(features, str):
        features = features.split(",")
    return tuple(sorted({feature.strip() for feature in features if feature.strip()}))


def describe_features(features) -> str:
    return ",".join(feature_set(features)) or "(default)"


def unstamped(build: Build) -> str | None:
    """Why `build` cannot be told apart from any other (a file without its stamp), or None."""
    for path in (build.kernel, build.disk):
        if read_stamp(path) is None:
            return (f"{path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path} "
                    "has no build stamp: run `make disk` (with the features the tests need)")
    return None


def build_mismatch(build: Build, features: list[str], profile: str | None = None) -> str | None:
    """Why `build` is not the kernel and disk built with `features` (and the cargo `profile`, by
    default this run's); None when it is."""
    missing = unstamped(build)
    if missing is not None:
        return missing
    profile = profile or PROFILE
    for path in (build.kernel, build.disk):
        built_profile = read_stamp(path).get("profile", "dev")
        if built_profile != profile:
            return (f"{path.name} was built with the {built_profile} profile; this run boots {profile} "
                    f"(KERNEL_PROFILE, F2K_KERNEL_PROFILE)")
    want = feature_set(features)
    kernel = feature_set(read_stamp(build.kernel).get("features", ""))
    disk = feature_set(read_stamp(build.disk).get("features", ""))
    if kernel == want and disk == want:
        return None
    if kernel == disk:
        built = f"features {describe_features(kernel)}"
    else:
        built = f"a kernel with features {describe_features(kernel)} and a disk with {describe_features(disk)}"
    make = f"make disk CARGO_FEATURES={','.join(want)}" if want else "make disk"
    if profile != "dev":
        make += f" KERNEL_PROFILE={profile}"
    return (f"the build on disk has {built}; this test needs {describe_features(want)} "
            f"(`{make}`, or run without --no-build)")


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
    observe: Callable[[Path], None] | None = None,
) -> tuple[str, str]:
    """Boot `build` (`image` "kernel": the ELF through QEMU's Multiboot loader, the disk attached;
    "disk": the disk itself through Limine) and log COM1 to `log_path` until `done(log)` holds, QEMU
    exits, or `timeout` seconds pass. `cmdline` is the user program's command line, passed after
    the kernel command line's "--": by QEMU's -append on a kernel boot, by the Limine entry's
    `cmdline` on a disk boot (a copy of the disk with its configuration rewritten, removed after the
    boot). With `observe`, QEMU also carries a QMP socket, and once `done(log)` holds `observe` is
    called with the socket's path while QEMU still runs (the machine's state, read before it is
    stopped). Returns the log and why the boot stopped ("done", "exited", "timeout")."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.unlink(missing_ok=True)
    disk = build.disk
    variant = None
    args = [QEMU]
    if image == "kernel":
        args += ["-kernel", str(build.kernel)]
        if cmdline:
            args += ["-append", f"-- {cmdline}"]
    elif cmdline:
        variant = disk = limine_disk(build, cmdline, WORK / "variants" / f"{log_path.stem}.img")
    args += [
        "-drive", f"file={disk},format=raw,if=ide,snapshot=on",
        "-m", memory, "-display", "none", "-monitor", "none", "-net", "none",
        # -no-reboot turns a triple fault into a QEMU exit, so crashes fail fast.
        "-no-reboot", "-serial", f"file:{log_path}",
    ]
    # A unix socket's path is short (104 bytes on macOS): the socket lives in its own temporary
    # directory rather than beside the log.
    qmp_directory = Path(tempfile.mkdtemp(prefix="f2k-qmp-")) if observe is not None else None
    if qmp_directory is not None:
        args += ["-qmp", f"unix:{qmp_directory / 'qmp.sock'},server,nowait"]
    args += exit_with_parent()
    qemu = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + timeout
    reason = "timeout"
    try:
        while time.monotonic() < deadline:
            if done(read_log(log_path)):
                reason = "done"
                if observe is not None:
                    observe(qmp_directory / "qmp.sock")
                break
            if qemu.poll() is not None:
                reason = "exited"
                break
            time.sleep(0.1)
    finally:
        qemu.kill()
        _, stderr = qemu.communicate()
        if variant is not None:
            variant.unlink(missing_ok=True)
        if qmp_directory is not None:
            shutil.rmtree(qmp_directory, ignore_errors=True)
    log = read_log(log_path)
    if reason != "done" and done(log):
        reason = "done"  # QEMU wrote the answer just before it stopped
    if stderr:
        # QEMU's own complaints (an image it could not open, an option it refused) go into the log
        # file too, after COM1's lines, so a failure read from the file shows them.
        section = f"\n{QEMU_STDERR}\n{stderr.decode(errors='replace')}"
        log += section
        with open(log_path, "a", encoding="latin-1", errors="replace") as file:
            file.write(section)
    return log, reason


@functools.cache
def exit_with_parent() -> list[str]:
    """QEMU's options to end with the process that started it, when this QEMU has them:
    a test process that dies mid-boot (killed, a crashed xdist worker, an interrupted run) takes
    its QEMU with it instead of leaving it running."""
    try:
        listing = subprocess.run([QEMU, "-run-with", "help"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return ["-run-with", "exit-with-parent=on"] if "exit-with-parent" in listing.stdout + listing.stderr else []


# --- The text screen ---------------------------------------------------------------------------
#
# Mode 3's text page: COLUMNS x ROWS cells from physical 0xB8000, each a character byte then an
# attribute byte (the kernel's hw::vga). QEMU's monitor reads guest-physical memory with `xp`; the
# hardware cursor lives in the CRT controller's registers, which this read cannot reach.

TEXT_SCREEN = 0xB8000
COLUMNS = 80
ROWS = 25


@dataclass(frozen=True)
class TextScreen:
    """Cells read from the text page, from its first: each a (character, attribute) pair."""

    cells: list[tuple[int, int]]

    def row(self, row: int) -> list[tuple[int, int]]:
        return self.cells[row * COLUMNS:(row + 1) * COLUMNS]

    def text(self, row: int) -> str:
        """A row's characters, as code page 437's bytes read as Latin-1."""
        return bytes(character for character, _ in self.row(row)).decode("latin-1")


def parse_xp(output: str) -> bytes:
    """The bytes an `xp /<n>bx` dump shows: each line's leading address token (ending with ":")
    dropped, every value after it hex-decoded."""
    data = bytearray()
    for line in output.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if not tokens[0].endswith(":"):
            raise ValueError(f"an xp line without its address: {line!r}")
        data.extend(int(token, 16) for token in tokens[1:])
    return bytes(data)


def text_screen_of(data: bytes) -> TextScreen:
    """The cells a dump of the text page holds: even offsets characters, odd ones attributes."""
    if len(data) % 2:
        raise ValueError("a text page dump is whole cells")
    return TextScreen([(data[i], data[i + 1]) for i in range(0, len(data), 2)])


class QmpError(Exception):
    """QEMU's QMP answered with an error, or not at all."""


def qmp_command(path: Path, commands: list[dict], timeout: float = 10.0) -> list:
    """Connect to QEMU's QMP socket at `path`, leave capabilities negotiation, run `commands` in
    order, and return each one's "return" value (events in between are skipped)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(timeout)
            connection.connect(str(path))
            break
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            if time.monotonic() > deadline:
                raise QmpError(f"no QMP socket at {path}") from None
            time.sleep(0.05)
    with connection, connection.makefile("rwb") as stream:

        def receive() -> dict:
            while True:
                line = stream.readline()
                if not line:
                    raise QmpError("QMP closed the connection")
                message = json.loads(line)
                if "event" not in message:
                    return message

        def execute(command: dict):
            stream.write(json.dumps(command).encode() + b"\n")
            stream.flush()
            answer = receive()
            if "error" in answer:
                raise QmpError(f"{command['execute']}: {answer['error']}")
            return answer["return"]

        if "QMP" not in receive():
            raise QmpError("no QMP greeting")
        execute({"execute": "qmp_capabilities"})
        return [execute(command) for command in commands]


def read_text_screen(path: Path, cells: int = COLUMNS * ROWS) -> TextScreen:
    """The text page's first `cells` cells, read through the QMP socket at `path`."""
    command = f"xp /{2 * cells}bx {TEXT_SCREEN:#x}"
    (output,) = qmp_command(path, [{"execute": "human-monitor-command",
                                    "arguments": {"command-line": command}}])
    data = parse_xp(output)
    if len(data) != 2 * cells:
        raise QmpError(f"{command}: {len(data)} bytes, expected {2 * cells}")
    return text_screen_of(data)


# QEMU draws mode 3 as 720 x 400 pixels: each cell 9 pixels wide and 16 high (the ninth column the
# character generator's gap). The hardware cursor blinks: a dump draws it or not by when it lands.
CELL_WIDTH = 9
CELL_HEIGHT = 16


def screendump(path: Path, png: Path) -> None:
    """The screen as QEMU displays it, written as a PNG to `png`, through the QMP socket at
    `path`."""
    qmp_command(path, [{"execute": "screendump",
                        "arguments": {"filename": str(png), "format": "png"}}])


@dataclass(frozen=True)
class Image:
    """A decoded image: its rows of RGB pixels, three bytes each."""

    width: int
    height: int
    rows: list[bytes]

    def pixel(self, x: int, y: int) -> bytes:
        return self.rows[y][3 * x:3 * x + 3]


def read_png(path: Path) -> Image:
    """A PNG as QEMU's screendump writes it (8-bit RGB, not interlaced), decoded: its chunks
    read, its image data inflated and each row's filter undone."""
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path}: not a PNG")
    at, compressed, header = 8, bytearray(), None
    while at < len(data):
        length, kind = struct.unpack(">I4s", data[at:at + 8])
        body = data[at + 8:at + 8 + length]
        at += 12 + length
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            compressed += body
    if header is None:
        raise ValueError(f"{path}: no header")
    width, height, depth, colour, _, _, interlace = header
    if (depth, colour, interlace) != (8, 2, 0):
        raise ValueError(f"{path}: not 8-bit RGB without interlacing: {header}")
    raw = zlib.decompress(bytes(compressed))
    stride = 3 * width
    rows, previous = [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, row = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for x in range(stride):
            left = row[x - 3] if x >= 3 else 0
            up = previous[x]
            corner = previous[x - 3] if x >= 3 else 0
            if kind == 1:
                row[x] = (row[x] + left) & 0xFF
            elif kind == 2:
                row[x] = (row[x] + up) & 0xFF
            elif kind == 3:
                row[x] = (row[x] + (left + up) // 2) & 0xFF
            elif kind == 4:
                guess = left + up - corner
                near = min((abs(guess - left), 0, left), (abs(guess - up), 1, up),
                           (abs(guess - corner), 2, corner))
                row[x] = (row[x] + near[2]) & 0xFF
            elif kind != 0:
                raise ValueError(f"{path}: row {y}: filter {kind}")
        rows.append(bytes(row))
        previous = row
    return Image(width, height, rows)


def differing_cells(a: Image, b: Image) -> set[tuple[int, int]]:
    """The text cells (row, column) holding a pixel that differs between two dumps of the text
    screen."""
    if (a.width, a.height) != (b.width, b.height):
        raise ValueError(f"dumps of different sizes: {a.width}x{a.height}, {b.width}x{b.height}")
    cells = set()
    for y, (first, second) in enumerate(zip(a.rows, b.rows)):
        if first == second:
            continue
        for x in range(a.width):
            if first[3 * x:3 * x + 3] != second[3 * x:3 * x + 3]:
                cells.add((y // CELL_HEIGHT, x // CELL_WIDTH))
    return cells


def lit_pixels(image: Image, cell: tuple[int, int]) -> int:
    """How many of a cell's pixels are not black."""
    row, column = cell
    return sum(image.pixel(x, y) != b"\0\0\0"
               for y in range(row * CELL_HEIGHT, (row + 1) * CELL_HEIGHT)
               for x in range(column * CELL_WIDTH, (column + 1) * CELL_WIDTH))


# The disk's FAT32 partition, as mtools addresses it (the Makefile's disk target puts it at 1 MiB).
PARTITION = "@@1M"
LIMINE_CONF = REPO_ROOT / "boot" / "limine.conf"


def limine_disk(build: Build, cmdline: str, path: Path) -> Path:
    """A copy of `build`'s disk at `path` whose Limine entry hands the kernel `cmdline` as the user
    program's command line (after the kernel command line's "--")."""
    if "\n" in cmdline:
        raise ValueError("a Limine command line is one line")
    entry = LIMINE_CONF.read_text()
    marker = "    path: boot():/f2k-kernel\n"
    if marker not in entry:
        raise ValueError(f"{LIMINE_CONF} has no kernel path line to add the command line after")
    path.parent.mkdir(parents=True, exist_ok=True)
    conf = path.with_suffix(".conf")
    conf.write_text(entry.replace(marker, f"{marker}    cmdline: -- {cmdline}\n"))
    shutil.copyfile(build.disk, path)
    try:
        subprocess.run(
            ["mcopy", "-o", "-i", f"{path}{PARTITION}", str(conf), "::/boot/limine/limine.conf"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except subprocess.CalledProcessError as error:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"rewriting the Limine configuration failed:\n{error.stdout}") from None
    finally:
        conf.unlink(missing_ok=True)
    return path


# The marker before QEMU's stderr in a boot's log.
QEMU_STDERR = "--- QEMU stderr ---"


def qemu_complaint(log: str) -> str | None:
    """The first line QEMU wrote on its stderr during the boot, if any."""
    _, marker, rest = log.partition(QEMU_STDERR)
    if not marker:
        return None
    return next((line.strip() for line in rest.splitlines() if line.strip()), None)


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
# A process's end: a one-process boot's form, or a batch's, which names the process's index and
# name ("F2K: process 3 (bare) exited normally ...").
END = re.compile(r"^F2K: (?:user process|process \d+ \(.*\)) (exited normally|ended by fault)")
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

    @property
    def name(self) -> str:
        """The section's name: its first argument (a fixture's `[pins]` key)."""
        return self.section.split(" ", 1)[0]


class CaptureError(Exception):
    """A capture file that is not a well-formed sequence of blocks."""


def parse_capture(path: Path) -> list[Block]:
    """A capture's blocks (tests/capture.bat's ">>> command / output / <<< exit code=N"), exactly:
    lines before the first block are its header (provenance), blank lines may separate blocks, and
    anything else outside a block, or a block without its exit code line, is an error."""
    blocks: list[Block] = []
    closed = True
    for number, line in enumerate(lines_of(path.read_text(encoding="latin-1")), start=1):
        if line.startswith(">>> "):
            if not closed:
                raise CaptureError(f"{path}:{number}: a block starts before the last one's exit code")
            blocks.append(Block(line[4:]))
            closed = False
        elif not blocks:
            continue  # the header, before the first block
        elif line.startswith("<<< exit code="):
            if closed:
                raise CaptureError(f"{path}:{number}: an exit code line outside a block")
            blocks[-1].exit_code = int(line[len("<<< exit code="):]) & 0xFFFFFFFF
            closed = True
        elif closed:
            if line.strip():
                raise CaptureError(f"{path}:{number}: a line between blocks: {line!r}")
        else:
            blocks[-1].lines.append(line)
    if not closed:
        raise CaptureError(f"{path}: its last block has no exit code line")
    return blocks


def read_capture(fixture: str) -> list[Block]:
    """A fixture's blocks: its capture (output.txt), with the blocks of its overrides.txt (those the
    capture script cannot take: an interactive console, a real-hardware answer) merged over it. An
    override replaces the captured block with the same command line, in place, or comes after them
    all."""
    directory = fixture_directory(fixture)
    blocks = parse_capture(directory / "output.txt")
    overrides = directory / "overrides.txt"
    if overrides.is_file():
        for override in parse_capture(overrides):
            at = next((i for i, block in enumerate(blocks) if block.command == override.command), None)
            if at is None:
                blocks.append(override)
            else:
                blocks[at] = override
    return blocks


def mask_pattern(mask: str) -> re.Pattern[str]:
    """A capture mask: each "*" stands for one value (a run of non-blank characters), the rest is
    literal."""
    return re.compile(r"\S+".join(re.escape(part) for part in mask.split("*")))


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
        if line == QEMU_STDERR:
            break  # COM1 ends here; what follows is QEMU's own
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
    # The boot's own checks hold under every program: the kernel reports them and carries on. (The
    # teardown's audit, after the program, is judged last: a program mismatch says more.)
    failed = next(
        (line.strip() for line in lines
         if ("audit FAILED" in line or "audit: FAILED" in line) and not TEARDOWN.match(line)),
        None,
    )
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
    if exit_code is None:
        # A kernel fault outside any user attribution halts with its diagnostic and no end line:
        # name it rather than the program lines it cut short (its dump lines are filtered out of
        # the program's output as kernel lines).
        at = next((i for i, line in enumerate(lines) if line.startswith("CPU EXCEPTION:")), None)
        if at is not None:
            dump = [line.strip() for line in lines[at:at + 4] if line.strip()]
            return "kernel fault, the process never ended: " + " | ".join(dump)

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
    return teardown_problem(lines)


# The teardown audit line that follows every process's end: the allocators back at the post-boot
# baseline ("... teardown audit: frame database ok, kernel heap ok"), or what is off ("... teardown
# audit FAILED: ..."). A suite leg's line names the leg ("F2K: process 3 teardown audit ...").
TEARDOWN = re.compile(r"^F2K: (?:process \d+ )?teardown audit")

# The object audit's line, printed only when objects outlived their process (a reference leak),
# before the teardown audit line.
OBJECT_LEAK = re.compile(r"^F2K: object audit FAILED")


def teardown_audited(log: str) -> bool:
    """Whether the boot has gone as far as a corpus block needs: the process ended and was torn
    down (its audit line printed), or the kernel panicked."""
    return any(TEARDOWN.match(line) for line in lines_of(log)) or "KERNEL PANIC" in log


def teardown_problem(lines: list[str]) -> str | None:
    """Why the ended process's teardown failed its audit or never reported one; None when its
    audit is clean."""
    audit = next((line.strip() for line in lines if TEARDOWN.match(line)), None)
    if audit is None:
        end = next((i for i, line in enumerate(lines) if END.match(line)), len(lines))
        fault = next((line.strip() for line in lines[end:] if line.startswith("CPU EXCEPTION:")), None)
        if fault is not None:
            return f"the teardown faulted: {fault}"
        return "the process ended, but its teardown audit never arrived"
    if "FAILED" in audit:
        return audit
    leak = next((line.strip() for line in lines if OBJECT_LEAK.match(line)), None)
    if leak is not None:
        return leak
    return None


# --- The sectioned corpus ------------------------------------------------------------------------
#
# Each sectioned fixture's real-machine capture, tests/<dll>/<name>/output.txt (tests/capture.bat),
# with the blocks of its overrides.txt merged over it, is its expectation; its declaration,
# tests/<dll>/<name>/fixture.toml, says how the comparison goes, and
# tests/<dll>/<name>/test_<name>.py binds `corpus_test(<name>)`: one test per captured block, through
# `blocks` and the `run_block` fixture (tests/conftest.py).

# The fixtures' directory on the boot volume (the Makefile's CORPUS_FIXTURES go to \CORPUS): each
# block's program runs from there, as each runs from its own directory on the real machine.
CORPUS_DIRECTORY = "CORPUS"
CORPUS_TIMEOUT = 20.0

# A pinned export, as a fixture's `[pins]` names it: `dll.Export` (kernel32.CreateFileA).
PIN = re.compile(r"[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_]*")


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
    masks: dict[str, tuple[str, ...]] | None = None,
    pins: dict[str, list[str]] | None = None,
    timeout: float = CORPUS_TIMEOUT,
    retake: str | None = None,
) -> list:
    """A fixture's captured blocks as pytest parameters, one per block, its section the id.

    - `gate`: the blocks must pass. Without it the fixture is on the work list: its blocks run as
      expected failures (one that starts passing shows as XPASS; `--runxfail` shows why the others
      fail).
    - `pending`: in a gated fixture, the sections still on the work list, each with what it waits
      for: those blocks run as expected failures.
    - `masks`: per section, the capture lines that carry machine-specific values F2K cannot
      reproduce (an address, the size of a free region the real machine's other allocations bound).
      In that section's block, a capture line matching a mask matches any line that matches the
      same mask; each "*" stands for one value (a run of non-blank characters).

    A `pending` or `masks` section the capture has no block for is an error.
    - `pins`: per section name (a block's first argument), the exports its block pins, as
      `dll.Export`; `"*"` for every block. scripts/compat.py reads them (and checks that each names
      an export); a section the capture has no block for is an error here.
    - `timeout`: seconds per boot.
    - `retake`: the capture must be retaken before it counts (the reason): the blocks are skipped.
    """
    import pytest

    marks = [pytest.mark.corpus]
    if retake is not None:
        marks.append(pytest.mark.skip(reason=f"capture to retake: {retake}"))
    elif not gate:
        marks.append(pytest.mark.xfail(reason=f"{fixture} is not served yet", strict=True))
    captured = read_capture(fixture)
    sections = {block.section for block in captured}
    for field_name, keyed in (("pending", pending or {}), ("masks", masks or {})):
        unknown = sorted(set(keyed) - sections)
        if unknown:
            raise ValueError(f"{fixture}: {field_name} names sections with no captured block: {unknown}")
    unknown = sorted(set(pins or {}) - {block.name for block in captured} - {"*"})
    if unknown:
        raise ValueError(f"{fixture}: pins names sections with no captured block: {unknown}")
    for section, exports in (pins or {}).items():
        malformed = [pin for pin in exports if not PIN.fullmatch(pin)]
        if malformed:
            raise ValueError(f"{fixture}: pins {section!r}: not dll.Export: {malformed}")
    patterns = {section: tuple(mask_pattern(mask) for mask in section_masks)
                for section, section_masks in (masks or {}).items()}
    params = []
    seen: dict[str, int] = {}
    for block in captured:
        seen[block.section] = seen.get(block.section, 0) + 1
        case_id = block.section if seen[block.section] == 1 else f"{block.section}#{seen[block.section]}"
        block_marks = marks
        if gate and pending and block.section in pending:
            block_marks = marks + [pytest.mark.xfail(reason=pending[block.section], strict=True)]
        captured_block = Captured(fixture, block, patterns.get(block.section, ()), timeout)
        params.append(pytest.param(captured_block, id=case_id, marks=block_marks))
    return params


@functools.cache
def fixture_directories() -> dict[str, Path]:
    """Every declared fixture's directory, by name: tests/<dll>/<name>/, the one holding its
    fixture.toml. The fixtures are grouped by the DLL they exercise, but the disk carries them all
    in one directory (and the pins and results key on the bare name): a name two groups declare is
    an error."""
    directories: dict[str, Path] = {}
    for path in sorted(TESTS.glob("*/*/fixture.toml")):
        name = path.parent.name
        if name in directories:
            first, second = (where.relative_to(REPO_ROOT) for where in (directories[name], path.parent))
            raise ValueError(f"fixture {name!r} is declared twice, in {first} and {second}: the names must be"
                             " unique across the groups")
        directories[name] = path.parent
    return directories


def fixture_directory(fixture: str) -> Path:
    """A declared fixture's directory, tests/<dll>/<fixture>/."""
    try:
        return fixture_directories()[fixture]
    except KeyError:
        raise ValueError(f"no fixture {fixture!r} is declared (tests/*/{fixture}/fixture.toml)") from None


def declaration(fixture: str) -> dict:
    """A fixture's declaration, tests/<dll>/<fixture>/fixture.toml (tests/README.md documents its
    fields)."""
    with open(fixture_directory(fixture) / "fixture.toml", "rb") as file:
        return tomllib.load(file)


# A sectioned fixture's real-machine files: its program and its capture. A fixture declared before
# they are checked in has neither: it is awaited (its source may lead them, written here and built
# and captured on the real machine).
REAL_MACHINE_FILES = ("{name}.exe", "output.txt")


def real_machine_files(fixture: str) -> list[Path]:
    """A sectioned fixture's real-machine files (REAL_MACHINE_FILES), by path."""
    directory = fixture_directory(fixture)
    return [directory / name.format(name=fixture) for name in REAL_MACHINE_FILES]


def awaited(fixture: str) -> bool:
    """Whether a fixture is declared ahead of its real-machine files: none of them is checked in
    (tests/harness/test_repository.py refuses a fixture holding only some)."""
    return not any(path.exists() for path in real_machine_files(fixture))


def corpus_params(fixture: str) -> list:
    """A sectioned fixture's blocks as pytest parameters, as its declaration says to compare them;
    one skipped parameter for a fixture still awaiting its real-machine files."""
    import pytest

    declared = declaration(fixture)
    if declared.get("kind") != "sectioned":
        raise ValueError(f"{fixture_directory(fixture).relative_to(REPO_ROOT)}/fixture.toml does not declare"
                         " a sectioned fixture")
    if awaited(fixture):
        reason = (f"{fixture} awaits its real-machine build and capture "
                  f"({', '.join(path.name for path in real_machine_files(fixture))})")
        return [pytest.param(None, id="awaited", marks=[pytest.mark.corpus, pytest.mark.skip(reason=reason)])]
    return blocks(
        fixture,
        gate=declared.get("gate", False),
        pending=declared.get("pending"),
        masks={section: tuple(lines) for section, lines in declared.get("masks", {}).items()},
        pins=declared.get("pins"),
        timeout=float(declared.get("timeout", CORPUS_TIMEOUT)),
        retake=declared.get("retake"),
    )


def corpus_test(fixture: str) -> Callable:
    """A sectioned fixture's test function, from its declaration: one test per captured block, run
    through the `run_block` fixture (tests/conftest.py), which runs the fixture's selected blocks
    in one boot. A fixture's module binds it to test_<fixture>, the name the test ids carry and its
    batch is named after."""
    import pytest

    declared = declaration(fixture)
    params = corpus_params(fixture)

    @pytest.mark.parametrize("captured", params)
    def test(captured, run_block):
        run_block(captured)

    test.__doc__ = declared.get("description")
    return test


# --- Batches: a fixture's blocks in one boot -----------------------------------------------------
#
# A fixture's blocks run in one boot, in the capture's order: the kernel command line lists their
# command lines (` ;; ` between two), and the kernel runs each as its own process, announcing each
# one's start on COM1 before it. The log splits at those lines, and each block is compared on the
# boot's own lines (before the first program) followed by its own part.

# A program's start: its index in the list, the list's length, and its command line.
START = re.compile(r"^F2K: process (\d+) of (\d+): (.*)$")
# The line a boot of several programs ends with, once the last is torn down.
SUMMARY = "F2K: process suite complete:"
# The longest kernel command line the kernel keeps, its terminator included (kernel/src/boot/
# cmdline.rs, MAX_LEN).
KERNEL_COMMAND_LINE = 4096


def batch_command_line(commands: list[str]) -> str:
    """The user command line that runs `commands` (blocks' command lines) from the corpus's
    directory, one after another."""
    return " ;; ".join(f"{CORPUS_DIRECTORY}\\{command}" for command in commands)


def split_programs(log: str) -> tuple[str, list[tuple[str, str]]]:
    """A boot's log at its programs' start lines: the boot's own part (before the first program),
    and each program that started, as its command line and its part of the log (from its start line
    to the next one's, the last to the end)."""
    prefix: list[str] = []
    programs: list[tuple[str, list[str]]] = []
    for line in log.splitlines(keepends=True):
        start = START.match(line.rstrip("\r\n"))
        if start is not None:
            programs.append((start.group(3), [line]))
        elif programs:
            programs[-1][1].append(line)
        else:
            prefix.append(line)
    return "".join(prefix), [(command, "".join(lines)) for command, lines in programs]


class BatchWatch:
    """A batch boot's stop check: true once the last program is torn down (with several, once the
    summary follows), the kernel panicked, or the running program overran its own timeout (the
    boot's start counts against the first). `overran` then names that program's index."""

    def __init__(self, timeouts: list[float]):
        self.timeouts = timeouts
        self.started = 0
        self.since = time.monotonic()
        self.overran: int | None = None

    def __call__(self, log: str) -> bool:
        if "KERNEL PANIC" in log:
            return True
        lines = lines_of(log)
        finished = sum(1 for line in lines if TEARDOWN.match(line))
        if finished >= len(self.timeouts) and (len(self.timeouts) == 1 or SUMMARY in log):
            return True
        started = sum(1 for line in lines if START.match(line))
        if started != self.started:
            self.started, self.since = started, time.monotonic()
        running = max(started, 1) - 1
        if time.monotonic() - self.since > self.timeouts[min(running, len(self.timeouts) - 1)]:
            self.overran = running
            return True
        return False


@dataclass
class Batch:
    """A batch boot's outcome: the blocks' command lines it ran, in order; its log (at `log_path`)
    and why it stopped ("done", "exited", "timeout"); the log split at the programs' starts."""

    commands: list[str]
    log: str
    log_path: Path
    stopped: str
    prefix: str
    programs: list[tuple[str, str]]

    def stopped_in(self) -> str:
        """The block's command line the boot stopped in: the last to start (the first when none
        did)."""
        return self.commands[max(len(self.programs), 1) - 1]

    def verdict(self, index: int, masks: list[re.Pattern[str]], block: Block) -> str | None:
        """None when block `index` (its capture `block`) was reproduced in its own part of the log;
        otherwise why not, in one line."""
        if index >= len(self.programs) and index > 0:
            return f"not run: the boot stopped in {self.stopped_in()} ({self.stopped})"
        if index < len(self.programs):
            ran = self.programs[index][0]
            expected = f"{CORPUS_DIRECTORY}\\{block.command}"
            if ran != expected:
                return f"the boot ran [{ran}] where [{expected}] was expected"
            part = self.programs[index][1]
        else:
            part = ""  # the boot stopped before the first program: its own lines say why
        return compare_block(block, self.prefix + part, masks)


def boot_batch(build: Build, blocks: list[Block], *, image: str, log_path: Path,
               timeouts: list[float]) -> Batch:
    """Run `blocks` in one boot of `build` (`image` as `boot` takes it), each its own process, in
    order; `timeouts` are each block's seconds (the boot's start counts against the first)."""
    watch = BatchWatch(timeouts)
    commands = [block.command for block in blocks]
    cmdline = batch_command_line(commands)
    # The kernel keeps the first KERNEL_COMMAND_LINE bytes; QEMU's loader puts the kernel's path
    # first.
    if len(str(build.kernel)) + len(cmdline) + 4 >= KERNEL_COMMAND_LINE:
        raise ValueError(f"the batch's command line is {len(cmdline)} bytes, more than the kernel keeps"
                         f" ({KERNEL_COMMAND_LINE}, kernel/src/boot/cmdline.rs MAX_LEN)")
    log, stopped = boot(
        build,
        image=image,
        cmdline=cmdline,
        memory="256M",
        log_path=log_path,
        timeout=sum(timeouts),
        done=watch,
    )
    if watch.overran is not None:
        stopped = "timeout"
    prefix, programs = split_programs(log)
    return Batch(commands, log, log_path, stopped, prefix, programs)


def log_path_for(nodeid: str) -> Path:
    """Where a test's COM1 log goes: target/qemu/logs/<test id>.log."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", nodeid.split("::", 1)[-1]).strip("_")
    return WORK / "logs" / f"{safe}.log"


def profile_path_for(nodeid: str) -> Path:
    """Where a test's performance profile goes (the suite's `--perf-trace`): target/qemu/profiles/
    <test id>.json, beside the boot's COM1 log, loadable at profiler.firefox.com."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", nodeid.split("::", 1)[-1]).strip("_")
    return WORK / "profiles" / f"{safe}.json"
