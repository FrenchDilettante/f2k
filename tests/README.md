# F2K Test Corpus

C programs compiled on a real Windows 2000 machine with the era's
toolchain. They are the compatibility baseline: every test is a real
PE32 executable whose imports and behavior are dictated by that
environment, not by what F2K happens to implement.

## Layout

One directory per test, named after the test:

```
tests/<name>/
├── <name>.c        # the source, built on the real Windows 2000 machine
├── <name>.exe      # the compiled fixture (committed; it is the point)
├── output.txt      # the real-machine capture, where there is one
├── test_<name>.py  # sectioned fixtures: the pytest file running the capture on F2K
├── imports.txt     # verified facts from the binary, where relevant
└── <name>.rs       # planned: the same test for F2K's own Rust toolchain
```

The Rust counterpart exists so the same test can be built and run by
our own toolchain as well as the reference one; it lands when the
toolchain can build it. Build intermediates (`.obj` etc.) are ignored,
not committed.

Shared pieces sit beside the tests: `common/f2kt.h` (the reporting and
section helpers the sectioned fixtures include), `build.bat`,
`capture.bat` (the real-machine capture of the sectioned fixtures), and
the pytest side: `conftest.py` and `f2kboot.py` (building, booting,
comparing), and `test_suite.py`, which runs the legacy fixtures and the
kernel's own diagnostic boots from `scripts/qemu-tests.yaml`.

## Sectioned fixtures

The sectioned fixtures cover the public API by area rather than one
smoke path each. Each is a list of named sections:
`<fixture> <section>` runs one section, and the suite runs every
section as its own process; with no argument a fixture runs all its
sections except the named-only ones (those that end the process, or
whose output depends on an interactive console).

They follow one set of conventions, from `common/f2kt.h`:

- **Observe, don't assert.** A line prints what a call returned
  (`ret=0 err=288`); the real-machine capture is the expectation, and
  where F2K disagrees, F2K is wrong. Nothing machine-specific is
  printed: no addresses, handle values, thread ids, absolute paths or
  raw timings (timing-shaped facts print as a verdict against a band).
- **The last error is armed with a sentinel** before the call under
  observation and printed as `-` when the call left it untouched, so
  the captures pin which calls set, clear or keep it.
- **One line, one `WriteFile`.** Output never interleaves across
  threads and does not depend on CRT stdio buffering, so a redirected
  capture matches the console.
- **Critical paths are covered even where F2K has nothing yet**
  (structured exception handling, thread-local storage, growable
  heaps, waitable timers, file writes...): a fixture importing an
  export F2K lacks fails to load until the export lands, which is the
  point - the fixtures lead the kernel.

The fixtures:

- `bare` - no C runtime. With no argument: `.bss` zeroing (run twice
  in the multi-process boot, to catch frames reused unzeroed), `.data` and `.rdata` contents, linker
  pointer tables, entry stack alignment, a stack that grows to 256 KiB;
  the exit code is a mask of failed checks. With a mode: the entry
  point's return value as the exit code, a full 32-bit exit code,
  bad buffer pointers to `WriteFile`, code run from `.data`, and
  fifteen faults (NULL, `.rdata`, code, kernel addresses, divide by
  zero, `ud2`, `int3`, `hlt`, `cli`, `in`, `into`, stack overflow),
  each ending the process with its NTSTATUS. Replaced `bsscheck` and
  `crash` (removed: the multi-process suite runs `bare` in their
  place).
- `runtime` - the process environment: argv, version, modules and
  `GetProcAddress`/`LoadLibraryA`, the TEB/PEB fields compilers and
  runtimes read, last-error semantics and `FormatMessageA`, the
  environment, code pages and string conversion, CRT formatting and
  parsing, structured exception handling (faults, `RaiseException`,
  filters, `__finally`, unwinding), plus named-only `console`,
  `unhandled` and `exit`. Replaces `ret0` and `hello` as coverage
  (`hello` stays as the CRT smoke and the disk-smoke file).
- `memory` - `malloc`/`calloc`/`realloc`/`free` the way programs use
  them (thousands of small blocks, past 1 MiB of them, 4/16/32 MiB,
  realloc doubling to 4 MiB), the Win32 heap with private and capped
  heaps, `LocalAlloc`/`GlobalAlloc`, `VirtualAlloc`/`VirtualFree`/
  `VirtualQuery`/`VirtualProtect` and guard pages, the image's section
  protections, paging-file mappings, stack growth and thread stack
  sizes.
- `threads` - creation, exit codes, `ExitThread`/`TerminateThread`,
  suspend counts and suspension during waits, priorities and classes,
  scale (32 sequential, 20 concurrent, 100 fire-and-forget threads,
  hundreds of handles), TLS slots and `__declspec(thread)`, per-thread
  last error/errno/FPU/SEH, `_beginthreadex`, and named-only
  `mainexit`/`procexit`. Built with `/MT`. Replaces `thread` and
  `respawn`.
- `sync` - events (`PulseEvent`, named objects), semaphores, mutexes
  and abandonment, `WaitForMultipleObjects`, user APCs, critical
  sections, interlocked operations, handle duplication and closing,
  and `pingpong` kept as a section (plus a `SignalObjectAndWait`
  variant). Built with `/MT`. Replaces `pingpong`.
- `sched` - sleeps and timed waits in bands, the clocks, waitable
  timers, round-robin, preemption, yielding, the wake boost,
  suspension, and the starvation boost; pinned to one CPU. Built with
  `/MT`. Replaces `sleep`, `spin` and `suspend`.
- `files` - the read side of the file API over `files/DATA` (generated
  by `scripts/gen-files-data.py`; every byte is formula-defined): path
  forms and errors, chunked and boundary reads, seeks, metadata,
  `FindFirstFile` listings, share modes, CRT file I/O, read-only file
  mappings, concurrent readers. Run `files/setup.bat` once on the real
  machine (attributes git cannot carry). Replaces `fileio`.
- `fswrite` - the write side (create dispositions, writes, truncation,
  share modes, rename/copy/delete, directories, file times, CRT
  writes) in a scratch directory. Parked until F2K writes to disk.

Capture `files` and `fswrite` from a local FAT32 volume: F2K's boot
volume is FAT32, and file-system details differ elsewhere — NTFS has
its own names and timestamps, and a VirtualBox shared folder has no
short names, no attribute bits and reports a remote drive.

### Capturing

After `build.bat`, run `capture.bat` on the real machine: it runs every
section as its own process and writes each fixture's `output.txt` as
blocks of `>>> <command line>`, the output, and `<<< exit code=N`
(ERRORLEVEL, signed). `runtime console` needs an interactive console
and is captured by hand.

### Running against F2K

Each sectioned fixture's `test_<name>.py` runs its capture on the
kernel, one pytest test per block (`make corpus` runs them all, the
`corpus` marker): one boot per block, the block's command line passed
on the kernel command line, the program's output compared line for line
and its exit code checked. The
disk build puts the sectioned fixtures in `\CORPUS` (the files
fixture's data tree beside them), the way each runs from its own
directory on the real machine. The file states what its comparison
allows (`f2kboot.blocks`): `gate=True` once F2K passes every block
(the others run as expected failures, a progress report: a block that
starts passing shows as XPASS, and `--runxfail` shows each failure's
first differing line), `masks` for the few capture lines that carry
machine-specific values, a `timeout`, and `retake` for a capture to be
retaken (its blocks skipped). Every boot's COM1 log stays under
`target/qemu/logs/`.

## Legacy fixtures

The single-path smokes below predate the sectioned fixtures. Each one's
scenario reappears in a sectioned fixture (named above); they retire
once the suite runs the sectioned fixture in their place. `exit0`
(the one-import boot smoke) and `hello` (the CRT smoke, the pinned
import trace, and the disk-smoke checksum file) stay.

- `exit0` - no C runtime: the entry point calls `ExitProcess(0)`; a
  single import, so it exercises process creation, image mapping and
  the exit path and nothing else.
- `ret0` - the default MSVC 6 `/ML` CRT startup around
  `int main() { return 0; }`; exercises the full CRT initialization
  surface (35 KERNEL32.dll imports; see `ret0/imports.txt`).
- `hello` - the console rung: the same CRT startup, then `printf`
  writes "Hello, world!" to stdout and exits 0; the first test with
  observable output. Also carries `trace.txt`, the real-machine
  import trace (21 of the watched imports called on the happy path,
  one WriteFile, exit 0 — the real-machine baseline for the
  console-observable corpus).
- `hellogui` - the GUI rung: registers a window class, shows a
  window, paints "Hello, world!" once with `TextOut`, then closes
  itself and exits 0; the first test to import user32.dll and
  gdi32.dll.
- `thread` - scheduler smoke: the main thread creates one child
  that prints from its own stack and exits; completion is observed
  through a shared flag (no wait APIs), so a single CPU must take
  the CPU away from the spinning main thread for the child to run.
- `pingpong` - scheduler smoke: two threads alternate strictly for
  five turns through two auto-reset events, so each blocking wait
  must actually block; the final wait on the child's thread handle
  captures the thread-exit signaling contract.
- `sleep` - scheduler smoke: `Sleep(200)` measured in tick counts
  with `GetTickCount`, a pure-yield `Sleep(0)`, and a timed wait on
  a never-signaled event reporting timeout - the timer machinery
  behind all of them.
- `spin` - scheduler smoke: three equal-work spinner threads, two
  at normal priority interleaving by quantum-end round-robin, a
  third raised above normal preempting them until it finishes.
- `suspend` - scheduler smoke: a worker frozen across a long sleep
  while suspended, then resumed and completed, with the documented
  suspend-count returns (0 then 1).
- `respawn` - scheduler smoke: three rounds of create a child,
  wait for it, close it - one child alive at a time, so every
  child after the first reuses the kernel resources (gate-stack
  slot) the previous one released at its exit. The binary is
  built, its imports verified, and its output confirmed against
  the real-machine capture.
- `fileio` - disk smoke: opens the program's own image from the
  filesystem, reads the MZ and PE signatures, seeks back, and reads
  the MZ again - the file API over the boot volume, the measuring
  stick for the disk workstream. The output is derived only from
  the file's own bytes, so it is identical wherever the same
  executable runs. Built on the real Windows 2000 machine
  (`fileio.exe`, 42 KERNEL32.dll imports - hello's 40 plus
  `CreateFileA` and `ReadFile`; see `imports.txt`); the
  real-machine captured output lands as `output.txt`.

## Building

Run `build.bat` from a command prompt that has the MSVC 6 compiler on
PATH (the VS command prompt sets this up, e.g. via `vcvars32.bat`).
The exact per-test command lines live in `build.bat`; expected exit
code 0 means pass.

## How F2K consumes these

F2K loads every fixture from its boot disk: the disk build copies
the fixtures the suite runs into the FAT32 volume's root directory
by their 8.3 names (`EXIT0.EXE`, `RET0.EXE`, ...; see `DISK_FIXTURES`
in the Makefile), and the kernel reads the selected program off the
volume by path before loading it. The suite attaches that disk to
every case, kernel-path cases included. The default kernel runs
`exit0`, the `run-ret0` feature selects `ret0`, and the `run-hello`
feature selects `hello` (whose WriteFile output appears on COM1 as
the program's own). The `run-pingpong` feature (the blocking-wait
smoke) selects `pingpong` with the thread-ified boot: the main thread
enters ring 3 through the scheduler's first switch, and its thread
and wait calls run against the landed scheduler machinery. The
`run-process-suite` feature (the multi-process case) runs the
sequence `exit0`, `ret0`, `bare`, `bare`, `bare null-write`, `exit0`
in one boot (`bare` from `\CORPUS`): the second `bare` catches frames
reused without re-zeroing, `bare null-write` a fault the kernel must
contain before the last `exit0` runs. The `run-fileio` feature selects `fileio`, which opens its
own image on the volume through the module path the loader staged.
A boot can also choose its program by command line, with no feature:
the text after `--` on the kernel command line is the program's own
command line, `<program> [arguments]` (QEMU's `-append "-- SYNC.EXE
event"`, the suite's per-case `cmdline` key). The program's
GetCommandLineA reports that text verbatim and its GetModuleFileNameA
the drive-qualified image path (`C:\SYNC.EXE`). This is how the
sectioned fixtures run: one section per boot, `<fixture> <section>`.
Each boot prints the observed process exit code on COM1, which the
suite cases assert. Host unit tests still read the checked-in `.exe`
files directly (`include_bytes!`, test builds only).

The scheduler smoke tests (`thread`, `pingpong`, `sleep`, `spin`,
`respawn`, `suspend`) join the corpus one per scheduler
stage, in dependency order, as the scheduler grows; each asserts
the real-machine captured output of its stage. The
`run-respawn` feature selects `respawn` on the thread-ified boot,
the same entry `run-pingpong` uses.
