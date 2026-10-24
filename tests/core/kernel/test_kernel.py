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

The program smokes (ret0, hello) run the root directory's single-path fixtures, selected by the
command line (tests/core/test_limine.py names the sectioned blocks that succeeded the retired ones).

    uv run pytest tests/core/kernel              # every case
    uv run pytest tests/core/kernel -m kernel    # the Multiboot cases (-m disk: the Limine ones)
    uv run pytest tests/core/kernel -k fault-ud  # one case
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

# The multi-process suite's lines: exit0, ret0, bare, bare, bare null-write, exit0 in one
# boot (the command line lists them, ` ;; ` between two), each process torn down to the post-boot
# baseline before the next starts. COM1 protocol (the kernel's runner implements it; the shapes
# parallel the single-process lines with the per-process index and name added):
#   start:       F2K: process <i> of <n>: <its command line>
#   normal exit: F2K: process <i> (<name>) exited normally (exit code=N)
#   fault:       F2K: process <i> (<name>) ended by fault (vector N, exit code=X)
#   teardown:    F2K: process <i> teardown audit: frame database ok, kernel heap ok
#   summary:     F2K: process suite complete: 6 run, 0 faulted, 0 leaks
# The teardown line prints after every process (all six), so every index is asserted
# independently. bare null-write writes through the unmapped NULL page, which raises #PF (vector
# 14): the access violation reaches kernel32's BaseProcessStart frame, whose
# UnhandledExceptionFilter verdict calls ExitProcess with STATUS_ACCESS_VIOLATION — an exit, not a
# kernel-ended fault (F2K's own expectation, as Windows 2000 builds the start frame; the fixture's
# exit code is the same either way). bare's default run (its image checks, 256 KiB of stack grown
# on demand) is legs 3 and 4.
PROCESS_SUITE_PROGRAMS = (
    "exit0", "ret0", "CORPUS\\bare.exe", "CORPUS\\bare.exe", "CORPUS\\bare.exe null-write", "exit0",
)
PROCESS_SUITE = (
    *BOOTED,
    *(f"F2K: process {index} of 6: {program}" for index, program in enumerate(PROCESS_SUITE_PROGRAMS, start=1)),
    "F2K: process 1 (exit0) exited normally (exit code=0)",
    "F2K: process 1 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 2 (ret0) exited normally (exit code=0)",
    "F2K: process 2 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 3 (bare) exited normally (exit code=0)",
    "F2K: process 3 teardown audit: frame database ok, kernel heap ok",
    "F2K: process 4 (bare) exited normally (exit code=0)",
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
        description="NtTerminateThread on the main thread ends it, and with it the process, with the thread's status (as returning from the entry point does)",
        image="kernel",
        features=("fault-test-threadexit",),
        expects=(
            "F2K: entering ring 3",
            "F2K: user process exited normally (exit code=0)",
        ),
    ),
    # Exit during a disk read: a stub process opens HELLO.EXE and starts a time-critical child that
    # seeks and reads a sector in a loop (NtCreateThread on a stack it allocated, raised through
    # NtSetInformationThread); the main thread runs again only while the child waits on the drive,
    # and calls NtTerminateProcess there. The child must finish its read — releasing the volume
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
    *both_paths(
        "process-suite",
        "sequential multi-process run (exit0, ret0, bare x2, bare null-write, exit0) with per-process teardown audits and a zero-leak summary",
        cmdline=" ;; ".join(PROCESS_SUITE_PROGRAMS),
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
    # tests/core/hello/hello.exe into the volume first, so the fixture's bytes land on cluster 3 (LBA
    # 4067; see the disk target in the Makefile); the expected checksums are the offline CRC-32s of
    # its first 512 and 4096 bytes, and one IRQ14 per sector is expected, none unsolicited. The
    # reads go through the block layer: the disk and the one partition the boot-time scan
    # registers from its MBR, the volume read as that partition's own sectors. The boot also mounts
    # that partition as a FAT32 volume; the diagnostic reports the mount state (in disk LBAs) and
    # two FAT entries from one FAT sector — the second lookup is a cache hit. Fifteen interrupts:
    # IDENTIFY, the scan's MBR read, the mount's boot-sector read, the smoke's MBR and VBR reads,
    # the FAT sector, the single-sector file read, and the 8-sector run (1 + 1 + 1 + 1 + 1 + 1 + 1
    # + 8). The diagnostic then finds HELLO.EXE by name in the root directory and reads it through
    # its cluster chain; the CRC-32 pinned for it is the offline checksum of tests/core/hello/hello.exe
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
            "F2K: disk-smoke: HELLO.EXE via chain: CRC-32 0xA9C8002E",
            "F2K: disk-smoke: LBA 4067 CRC-32 0x05100D7E",
            "F2K: disk-smoke: LBA 4067+8 CRC-32 0x859CE3F0",
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
