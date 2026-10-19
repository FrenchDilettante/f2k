"""kernel - the kernel's own boots: fault stubs, the Limine disk path, the program smokes, the
multi-process suite, and the interrupt and IDE diagnostics.

These boots carry no sectioned capture to compare against: each case builds the kernel and disk
with its cargo features (once per feature set per test run), boots the kernel ELF through QEMU's
Multiboot loader with the disk attached (`image="kernel"`) or the disk itself through Limine
(`image="disk"`), and passes once its expected strings have appeared on COM1 by its rules (see
`f2kboot.Expectation`): each a substring of some line, in any order, or in order with `ordered`;
`contiguous` strings must match consecutive lines, `forbids` strings fail the case on sight, and
"KERNEL PANIC" fails every case. `cmdline` is the user program's command line: QEMU's `-append`
on a kernel boot, the Limine entry's `cmdline` on a disk boot; without one the kernel runs exit0.

The program smokes (pingpong, sleep, spin, suspend, respawn, fileio) run the root directory's
single-path fixtures, selected by the command line, until the sectioned blocks that succeed them
replace them (tests/test_limine.py names each successor).

    uv run pytest tests/kernel                 # every case
    uv run pytest tests/kernel -m kernel       # the Multiboot cases (-m disk: the Limine ones)
    uv run pytest tests/kernel -k fault-ud     # one case
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

import f2kboot

# Output no case may produce: a kernel panic is never an expected outcome, nor an object that
# outlived its process (the object audit, in every teardown).
DEFAULT_FORBIDS = ("KERNEL PANIC", "F2K: object audit FAILED")
DEFAULT_TIMEOUT = 10.0

# Every full boot's own checks, before any program runs.
BOOTED = (
    "F2K Booted Successfully",
    "F2K: frame database audit: ok",
    "F2K: kernel heap: alloc/free ok",
)

# The irq-smoke boot's lines, in order (both boot paths). The PIT runs in mode 2, the rate generator.
IRQ_SMOKE = (
    *BOOTED,
    "F2K: irq-smoke: PIC remapped (master 0x30, slave 0x38, IRQ0 unmasked)",
    "F2K: irq-smoke: PIC line masks: master 0xfe, slave 0xff",
    "F2K: irq-smoke: PIT programmed (mode 2, divisor 11949, 10.0144 ms tick)",
    "F2K: irq-smoke: PIT channel 0 read-back: mode 2, lobyte/hibyte, binary",
    "F2K: irq-smoke: timer live (>= 5 ticks observed)",
    "F2K: irq-smoke: clock DPC fired",
    "F2K: irq-smoke: interrupt audit: ok",
    "F2K: image loaded",
    "F2K: entering ring 3",
    "F2K: user process exited normally (exit code=0)",
)

# The multi-process suite's lines: exit0, ret0, bsscheck, bsscheck, bare null-write, exit0 in one
# boot, each process torn down to the post-boot baseline before the next starts. COM1 protocol (the
# sequence runner implements it; the shapes parallel the single-process lines with the per-process
# index and name added):
#   normal exit: F2K: process <i> (<name>) exited normally (exit code=N)
#   fault:       F2K: process <i> (<name>) ended by fault (vector N, exit code=X)
#   teardown:    F2K: process <i> teardown audit: frame database ok, kernel heap ok
#   summary:     F2K: process suite complete: 6 run, 0 faulted, 0 leaks
# The teardown line prints after every process (all six), so every index is asserted
# independently. bare null-write writes through the unmapped NULL page, which raises #PF (vector
# 14): the access violation reaches kernel32's BaseProcessStart frame, whose
# UnhandledExceptionFilter verdict calls ExitProcess with STATUS_ACCESS_VIOLATION — an exit, not a
# kernel-ended fault (F2K's own expectation, as Windows 2000 builds the start frame; the fixture's
# exit code is the same either way). bare's default run takes bsscheck's legs once the stack grows.
PROCESS_SUITE = (
    *BOOTED,
    "F2K: process 1 (exit0) exited normally (exit code=0)",
    "F2K: process 1 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 2 (ret0) exited normally (exit code=0)",
    "F2K: process 2 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 3 (bsscheck) exited normally (exit code=0)",
    "F2K: process 3 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 4 (bsscheck) exited normally (exit code=0)",
    "F2K: process 4 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 5 (bare) exited normally (exit code=3221225477)",
    "F2K: process 5 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 6 (exit0) exited normally (exit code=0)",
    "F2K: process 6 teardown audit: frame database ok, kernel heap ok",
    "F2K: process suite complete: 6 run, 0 faulted, 0 leaks",
)

# What a one-process boot reports once its program has run and its process is gone.
EXITED_CLEAN = (
    "F2K: user process exited normally (exit code=0)",
    "F2K: teardown audit: frame database ok, kernel heap ok",
)


@dataclass(frozen=True)
class Case:
    name: str
    description: str
    image: str
    expects: tuple[str, ...]
    features: tuple[str, ...] = ()
    cmdline: str | None = None
    ordered: bool = False
    contiguous: tuple[str, ...] = ()
    forbids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        assert self.image in ("kernel", "disk"), f"{self.name}: image is kernel or disk"
        assert self.expects and all(self.expects), f"{self.name}: expects is non-empty"


def both_paths(name: str, description: str, **fields) -> tuple[Case, Case]:
    """A case on the kernel path (QEMU's Multiboot loader) and its `-disk` twin (Limine)."""
    return (
        Case(name=name, description=f"{description} (kernel path)", image="kernel", **fields),
        Case(name=f"{name}-disk", description=f"{description} (Limine disk path)", image="disk",
             **fields),
    )


def program_smoke(program: str, description: str, expects: tuple[str, ...], **fields) -> tuple[Case, Case]:
    """A root-directory program run by its command line, on both boot paths: the boot's checks,
    the command line the kernel took, the program's own lines, its clean exit and teardown."""
    return both_paths(
        f"{program}-smoke",
        description,
        cmdline=f"{program}.exe",
        expects=(
            # The command line is reported first thing, before the boot's own checks.
            "F2K Booted Successfully",
            f"F2K: command line: {program}.exe",
            *BOOTED[1:],
            "F2K: image loaded",
            "F2K: entering ring 3",
            *expects,
            *EXITED_CLEAN,
        ),
        **fields,
    )


# The preemption smoke's raised thread runs its block uninterrupted: its progress lines and
# completion appear on consecutive lines, no A/B line between.
SPIN_C_BLOCK = tuple(f"C {n * 5_000_000}" for n in range(1, 11)) + ("C done, checksum 1283106752",)

CASES = (
    Case(
        name="fault-ud",
        description="#UD right after init: exception dump without a CPU error code",
        image="kernel",
        features=("fault-test-ud",),
        expects=(
            "F2K: GDT after load: 0x00cf9b000000ffff 0x00cf93000000ffff",
            "CPU EXCEPTION: vector 6",
            "error code 0x00000000",
        ),
    ),
    Case(
        name="fault-gp",
        description="#GP right after init: exception dump with the CPU error code",
        image="kernel",
        features=("fault-test-gp",),
        expects=(
            "CPU EXCEPTION: vector 13",
            "error code 0x00000038",
        ),
    ),
    Case(
        name="fault-badargs",
        description="a bad user argument pointer ends the process inside the kernel's argument copy, with the access violation as its exit code",
        image="kernel",
        features=("fault-test-badargs",),
        expects=(
            "F2K: entering ring 3",
            "CPU EXCEPTION: vector 14",
            "F2K: user process ended by fault (bad user argument pointer, exit code=3221225477); halting",
        ),
    ),
    Case(
        name="fault-segments",
        description="ring 3 loads the TEB selector into DS/ES and keeps running across ticks and a syscall; the kernel's entry stubs load their own data segments",
        image="kernel",
        features=("fault-test-segments",),
        expects=(
            "F2K: entering ring 3",
            "F2K: user process exited normally (exit code=7)",
        ),
    ),
    Case(
        name="nt-close",
        description="NtClose by Windows 2000's service number (0x18) on a handle naming nothing answers STATUS_INVALID_HANDLE through the NT service table",
        image="kernel",
        features=("fault-test-ntclose",),
        expects=(
            "F2K: entering ring 3",
            "F2K: user process exited normally (exit code=3221225480)",
        ),
    ),
    Case(
        name="fault-threadexit",
        description="the internal thread-exit service on a boot without user threads is refused (STATUS_INVALID_SYSTEM_SERVICE), not a kernel panic",
        image="kernel",
        features=("fault-test-threadexit",),
        expects=(
            "F2K: entering ring 3",
            "F2K: user process exited normally (exit code=3221225500)",
        ),
    ),
    # Exit during a disk read: a stub process opens HELLO.EXE and starts a time-critical child that
    # seeks and reads a sector in a loop; the main thread runs again only while the child waits on
    # the drive, and calls ExitProcess there. The child must finish its read — releasing the volume
    # and the drive — before it ends, so the process's end is reported by the child, and the idle
    # thread's lookup after the teardown finds the volume usable.
    Case(
        name="fault-exitio",
        description="ExitProcess while another thread is blocked inside a disk read leaves the volume usable after the teardown",
        image="kernel",
        features=("fault-test-exitio",),
        ordered=True,
        expects=(
            "F2K: entering ring 3",
            "F2K: user process exited normally (exit code=0)",
            "F2K: exit-during-read: volume usable after teardown (HELLO.EXE, 28672 bytes)",
        ),
    ),
    # No command line on either path: the kernel runs exit0.
    *both_paths(
        "boot-smoke",
        "full boot through the first PE image (exit0) to its exit syscall, no command line",
        expects=(*BOOTED, "F2K: image loaded", "F2K: entering ring 3", *EXITED_CLEAN),
        forbids=("F2K: command line:",),
    ),
    *program_smoke(
        "ret0",
        "the CRT startup fixture runs to main and exits 0 through the 35-import surface",
        expects=(),
    ),
    # The console-observable corpus: hello runs the ret0 CRT startup, printf writes "Hello, world!"
    # to stdout through WriteFile, then it exits 0 — the program's own output on COM1 (no F2K:
    # prefix), before the exit line.
    *program_smoke(
        "hello",
        "the console fixture prints \"Hello, world!\" as its own COM1 output and exits 0",
        expects=("Hello, world!",),
        ordered=True,
    ),
    # The blocking-wait smoke: the strict alternation is the point, the turns must appear in order.
    *program_smoke(
        "pingpong",
        "the blocking-wait smoke runs its captured five-turn alternation through two auto-reset events and a child thread, the child-handle wait returns 0, and the process exits cleanly",
        expects=(
            *(line for turn in range(5) for line in (f"pong {turn}", f"ping {turn}")),
            "child handle wait returned 0",
            "pingpong: ok",
        ),
        ordered=True,
    ),
    # Timer smoke: the main thread parks in the timer table through Sleep(200) (the idle thread
    # owns the processor while it sleeps), yields through Sleep(0), and times out a wait on a
    # never-signaled event after 100 ms. Both spans read whole ticks: the GetTickCount reads and the
    # sleeps' due times derive from the same tick-quantized accumulator, so the captured cadence
    # (exactly 200 and exactly 100) is pinned verbatim.
    *program_smoke(
        "sleep",
        "the timer smoke parks the main thread in the timer table for a 200 ms sleep, yields through Sleep(0), and times out a 100 ms wait, reporting both spans at the captured cadence",
        expects=(
            "sleep 200ms spanned 200 ticks",
            "sleep 0 returned",
            "timed wait: timeout after 100 ticks",
            "sleep: ok",
        ),
    ),
    # Preemption smoke: two same-priority spinners alternate at quantum ends (round-robin delivered
    # from the tick — a quantum spans exactly two ticks), and a third thread raised above them
    # through SetThreadPriority runs its whole block uninterrupted (the service-boundary delivery),
    # before the pair resumes and finishes. The per-run A/B progress line counts are
    # timing-dependent, so the case pins the invariants: the C block's ten progress lines and
    # completion as one uninterrupted block (`contiguous`), the A/B/C completions with their
    # checksums, and the summary.
    *program_smoke(
        "spin",
        "the preemption smoke interleaves two same-priority spinners at quantum ends and runs a raised thread's block uninterrupted, with all three checksums reported",
        expects=(
            "main: spinners started",
            "main: starting high-priority thread",
            "C done, checksum 1283106752",
            "A done, checksum 1283106752",
            "B done, checksum 1283106752",
            "main: all threads finished",
            "spin: ok",
        ),
        contiguous=SPIN_C_BLOCK,
    ),
    # Suspend/resume smoke: the main thread suspends a spinning worker through its builtin suspend
    # APC, sleeps long enough that a runnable worker would have finished (the frozen check), then
    # resumes it to completion. The suspend and resume calls return the documented previous counts
    # (0 then 1).
    *program_smoke(
        "suspend",
        "the suspend/resume smoke freezes a worker through its suspend APC across a sleep and resumes it, with the previous-count returns pinned",
        expects=(
            "suspend returned 0",
            "worker frozen: yes",
            "resume returned 1",
            "suspend: ok",
        ),
    ),
    # Thread-slot reuse smoke: three rounds of create, wait for, close, one child alive at a time,
    # so every child after the first reuses the gate-stack resources the previous one released at
    # its exit. The child/main alternation is deterministic, so the case pins the output in order.
    *program_smoke(
        "respawn",
        "the slot-reuse smoke runs three create/wait/close rounds, each child after the first reusing the previous one's released gate-stack resources, and exits cleanly",
        expects=(
            "child 1: running",
            "main: round 1: child finished",
            "child 2: running",
            "main: round 2: child finished",
            "child 3: running",
            "main: round 3: child finished",
            "respawn: ok",
        ),
        ordered=True,
    ),
    # File smoke: the fileio fixture opens its own image on the boot volume — CreateFileA on the
    # path GetModuleFileNameA reports, the volume path the loader read it from — reads the MZ
    # signature, seeks to e_lfanew and reads the PE signature, seeks back and reads the MZ again.
    # Every line derives from the file's own bytes, so tests/fileio/output.txt (the real machine's
    # capture) is pinned verbatim, in order.
    *program_smoke(
        "fileio",
        "the file smoke opens its own image by its module path, reads the MZ and PE signatures across seeks, and prints the captured lines",
        expects=("MZ ok", "PE ok", "MZ again ok", "fileio: ok"),
        ordered=True,
    ),
    *both_paths(
        "process-suite",
        "sequential multi-process run (exit0, ret0, bsscheck x2, bare null-write, exit0) with per-process teardown audits and a zero-leak summary",
        features=("run-process-suite",),
        expects=PROCESS_SUITE,
    ),
    # Interrupt/timer core: the irq-smoke diagnostic boot proves the hardware layer and the
    # interrupt core are live, then the normal boot proceeds to the default image's exit (the tick
    # and the process machinery coexist, not just the diagnostic). Read from the hardware where it
    # can be: the PIC's line masks (IRQ0 the one line open before the disk connects IRQ14), the
    # PIT's read-back status for channel 0 (mode 2, both bytes, binary) beside the corpus-captured
    # divisor (11949 = 10.0144 ms); the tick counter crossing 5 (IRQ0 arrives on 0x30: on the
    # BIOS's 0x08 it would be a double fault), the clock DPC's timer expiry, and the interrupt
    # audit. The diagnostic is a feature; the tick is default-on kernel machinery.
    *both_paths(
        "irq-smoke",
        "the interrupt diagnostic boot reports the PIC remap and masks, the PIT's programming, the live tick, the clock DPC, and the audit, then the default image exits 0",
        features=("irq-smoke",),
        ordered=True,
        expects=IRQ_SMOKE,
    ),
    # IDE driver: the disk-smoke diagnostic boot drives the IRQ14 PIO read path end to end —
    # IDENTIFY, the MBR, the volume boot sector, and the first fixture's sector — then the default
    # image exits 0: coexistence, not just the diagnostic. The disk build copies
    # tests/hello/hello.exe into the volume first, so the fixture's bytes land on cluster 3 (LBA
    # 4067; see the disk target in the Makefile); the expected checksums are the offline CRC-32s of
    # its first 512 and 4096 bytes, and one IRQ14 per sector is expected, none unsolicited. The
    # reads go through the block layer: the disk and the one partition the boot-time scan
    # registers from its MBR, the volume read as that partition's own sectors. The boot also mounts
    # that partition as a FAT32 volume; the diagnostic reports the mount state (in disk LBAs) and
    # two FAT entries from one FAT sector — the second lookup is a cache hit. Fifteen interrupts:
    # IDENTIFY, the scan's MBR read, the mount's boot-sector read, the smoke's MBR and VBR reads,
    # the FAT sector, the single-sector file read, and the 8-sector run (1 + 1 + 1 + 1 + 1 + 1 + 1
    # + 8). The diagnostic then finds HELLO.EXE by name in the root directory and reads it through
    # its cluster chain; the CRC-32 pinned for it is the offline checksum of tests/hello/hello.exe
    # whole. 72 = those 15 + the root directory's 1 sector + HELLO.EXE's 56 clusters (its FAT
    # sector is already cached).
    Case(
        name="disk-smoke",
        description="the IDE diagnostic boot reads the MBR, the volume boot sector, and the first fixture's sectors through the block layer and IRQ14, then the default image exits 0 (Limine disk path)",
        image="disk",
        features=("disk-smoke",),
        ordered=True,
        expects=(
            "F2K Booted Successfully",
            "F2K: ide: primary master: LBA28, 131072 sectors",
            "F2K: disk-smoke: drive detected (LBA supported, 131072 sectors)",
            "F2K: disk-smoke: block devices: 0 = ATA disk (131072 sectors of 512 bytes), 1 = partition 0 of device 0 (129024 sectors)",
            "F2K: disk-smoke: MBR ok (signature 0xAA55, partition 0 type 0x0C at LBA 2048, 129024 sectors)",
            "F2K: disk-smoke: volume boot sector ok (signature 0xAA55, 512 bytes/sector, 1 sector/cluster, 32 reserved, 2 FATs, 993 sectors/FAT, root cluster 2, data region at LBA 4066)",
            "F2K: disk-smoke: mount ok (127006 clusters, FAT at LBA 2080, data at LBA 4066, root cluster 2)",
            "F2K: disk-smoke: FAT cluster 3 -> 4",
            "F2K: disk-smoke: FAT cluster 2 -> end of chain",
            "F2K: disk-smoke: HELLO.EXE: 28672 bytes, first cluster 3",
            "F2K: disk-smoke: HELLO.EXE via chain: CRC-32 0x89BBE49C",
            "F2K: disk-smoke: LBA 4067 CRC-32 0x659C3505",
            "F2K: disk-smoke: LBA 4067+8 CRC-32 0x15FB0DC0",
            "F2K: disk-smoke: IRQ14 serviced 72 interrupts (0 unsolicited), interrupt audit: ok",
            "F2K: image loaded",
            "F2K: entering ring 3",
            "F2K: user process exited normally (exit code=0)",
        ),
    ),
)

assert len({case.name for case in CASES}) == len(CASES), "case names are unique"


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case.name, marks=getattr(pytest.mark, case.image)) for case in CASES],
)
def test_kernel(case, builder, log_path, boot_timeout, write_profile):
    """The case's description, as the case states it."""
    build = builder(list(case.features))
    expectation = f2kboot.Expectation(
        expects=list(case.expects),
        ordered=case.ordered,
        contiguous=list(case.contiguous),
        forbids=list(DEFAULT_FORBIDS + case.forbids),
    )
    log, stopped = f2kboot.boot(
        build,
        image=case.image,
        cmdline=case.cmdline,
        log_path=log_path,
        timeout=boot_timeout(DEFAULT_TIMEOUT),
        done=lambda log: expectation.check(log)[0] != "pending",
    )
    write_profile(log, build)
    status, detail = expectation.check(log)
    if status == "pass":
        return
    if status == "forbidden":
        why = f"forbidden output appeared on COM1: {detail!r}"
    elif stopped == "exited":
        why = f"QEMU exited before the expected output appeared ({detail})"
    else:
        why = f"expected output not found within the timeout ({detail})"
    pytest.fail(f"{case.description}\n{why}\nlog: {log_path}\n--- COM1 (tail) ---\n"
                f"{f2kboot.tail(log)}", pytrace=False)
