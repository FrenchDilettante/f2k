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
├── *.dll           # companion DLLs the program loads, if any (committed, built beside it
│                   # from their checked-in source and .def)
├── fixture.toml    # the declaration: its kind, and how its capture compares (served fixtures)
├── output.txt      # the real-machine capture, where there is one
├── overrides.txt   # blocks the capture script cannot take (an interactive console...), if any
├── test_<name>.py  # sectioned fixtures: binds the fixture's tests (f2kboot.corpus_test)
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
comparing), `kernel/test_kernel.py`, the kernel's own boots (the
fault stubs, the Limine disk path, the multi-process suite, the
interrupt and IDE diagnostics, and the single-path program smokes
below), which have no sectioned capture to compare against, and `test_limine.py`, a few corpus blocks booted
through Limine instead of QEMU's Multiboot loader.

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
  each ending the process with its NTSTATUS. Replaces `crash` and
  `bsscheck` (the multi-process suite runs `bare` and `bare null-write`
  in their place).
- `runtime` - the process environment: argv, version, modules and
  `GetProcAddress`/`LoadLibraryA`, the TEB/PEB fields compilers and
  runtimes read, last-error semantics and `FormatMessageA`, the
  environment, code pages and string conversion, CRT formatting and
  parsing, structured exception handling (faults, `RaiseException`,
  filters, `__finally`, unwinding), plus named-only `console`,
  `unhandled` and `exit`. Replaces `ret0` and `hello` as coverage
  (`hello` stays as the CRT smoke and the disk-smoke file). Gated; its
  `console` block was captured by hand in an interactive console (it
  lives in `runtime/overrides.txt`).
- `memory` - `malloc`/`calloc`/`realloc`/`free` the way programs use
  them (thousands of small blocks, past 1 MiB of them, 4/16/32 MiB,
  realloc doubling to 4 MiB), the Win32 heap with private and capped
  heaps, `LocalAlloc`/`GlobalAlloc`, `VirtualAlloc`/`VirtualFree`/
  `VirtualQuery`/`VirtualProtect` and guard pages, the image's section
  protections, paging-file mappings, stack growth and thread stack
  sizes. Gated; two free-region sizes are masked (the real machine's
  other allocations bound them).
- `threads` - creation, exit codes, `ExitThread`/`TerminateThread`,
  suspend counts and suspension during waits, priorities and classes,
  scale (32 sequential, 20 concurrent, 100 fire-and-forget threads,
  hundreds of handles), TLS slots and `__declspec(thread)`, per-thread
  last error/errno/FPU/SEH, `_beginthreadex`, and named-only
  `mainexit`/`procexit`. Built with `/MT`. Replaced the `thread`,
  `respawn` and `suspend` smokes.
- `sync` - events (`PulseEvent`, named objects), semaphores, mutexes
  and abandonment, `WaitForMultipleObjects`, user APCs, critical
  sections, interlocked operations, handle duplication and closing,
  and `pingpong` kept as a section (plus a `SignalObjectAndWait`
  variant). Built with `/MT`. Replaced the `pingpong` smoke.
- `sched` - sleeps and timed waits in bands, the clocks, waitable
  timers, round-robin, preemption, yielding, the wake boost,
  suspension, and the starvation boost; pinned to one CPU. Built with
  `/MT`. Replaced the `sleep` and `spin` smokes. Gated. Its `yield` capture line `Sleep(10)
  does: yes` comes from real hardware: the VirtualBox capture VM runs
  at 100% CPU (a normal-priority thread yielding with `Sleep(0)`), so
  below-normal threads there run only at the balance-set boost, 300
  ticks in, and it answered `no`.
- `files` - the read side of the file API over `files/DATA` (generated
  by `scripts/gen-files-data.py`; every byte is formula-defined): path
  forms and errors, chunked and boundary reads, seeks, metadata,
  `FindFirstFile` listings, share modes, CRT file I/O, read-only file
  mappings, concurrent readers. Captured on a local FAT32 volume, as
  F2K's boot volume is (run `files/setup.bat` once on the real machine:
  attributes git cannot carry). Gated.
  Replaced the `fileio` smoke.
- `dll` - a program and its companion DLL (`f2kcom.dll`, built
  beside it from `f2kcom.c` and `f2kcom.def`, with no C runtime and
  no entry point: a loaded DLL's entry point is never called, so
  nothing is observed from load time): the program-driven dynamic
  linking - LoadLibraryA from the program's directory, the load
  reference count, GetProcAddress by name and by ordinal (its .def
  pins them), a call into the DLL, the counter reset by the unload
  and reload, FreeLibrary down to the unload. Gated.
- `fswrite` - the write side (create dispositions, writes, truncation,
  share modes, rename/copy/delete, directories, file times, CRT
  writes) in a scratch directory, captured on a local FAT32 volume.
  Gated (the test disk boots as a QEMU snapshot, so its writes never
  reach the image).

Capture `files` and `fswrite` from a local FAT32 volume: F2K's boot
volume is FAT32, and file-system details differ elsewhere — NTFS has
its own names and timestamps, and a VirtualBox shared folder has no
short names, no attribute bits and reports a remote drive.

### Capturing

After `build.bat`, run `capture.bat` on the real machine: it runs every
section as its own process and writes each fixture's `output.txt` as
blocks of `>>> <command line>`, the output, and `<<< exit code=N`
(ERRORLEVEL, signed), after a provenance header (the OS build, the
machine, the date, and the binary's source stamp). The fixtures built on
`common/f2kt.h` list their own sections (`<fixture>.exe --list`), so
the script captures whatever the binary declares; `bare`'s modes are
listed in the script. Both scripts take a fixture's name
(`build.bat dll`, `capture.bat dll`) to rebuild or recapture only that
one.

`build.bat` stamps each of those binaries with the CRC-32 of its source
and `f2kt.h` (`common/srcsum.c` computes it; `<fixture>.exe --source`
prints it), and `test_repository.py` checks the stamp against the
checked-in source, so a stale binary shows. Binaries built before the
stamp existed skip that check; once `build.bat` has rebuilt them all, set
`REQUIRE_SOURCE_STAMPS = True` in `test_repository.py`.

A block the script cannot take goes in the fixture's `overrides.txt`
(same format, its reasons in the header): `runtime console` needs an
interactive console, and `sched yield`'s `Sleep(10) does: yes` is the
real-hardware answer the VirtualBox capture VM cannot give. The suite
merges it over `output.txt` (a block replaces the captured block with
the same command line, or comes after them), so a recapture never drops
it.

### Running against F2K

Each sectioned fixture's capture runs on the
kernel, one pytest test per block (`make test` runs them with
everything else; `-m corpus` selects them alone): one boot per block, the block's command line passed
on the kernel command line, the program's output compared line for line
and its exit code checked. The
disk build puts the sectioned fixtures in `\CORPUS` (the files
fixture's data tree beside them), the way each runs from its own
directory on the real machine. The fixture's declaration,
`fixture.toml`, states what its comparison allows: `gate = true` once
F2K passes every block, `[pending]` for the blocks still on the work
list (each with the increment that enables it: `yield =
"B7: threads and scheduling"`), both run as
strict expected failures (a block that starts passing fails the run, so
the marker goes with the fix; `--runxfail` shows each failure's first
differing line), `[masks]` for the few capture lines that carry
machine-specific values (per section, `"virtual" = ["... region *
..."]`: each `*` one value, a run of non-blank characters, and only in
that section's block), a `timeout`, and `retake` for a capture to be
retaken (its blocks skipped). A `[pending]` or `[masks]` section with
no captured block is an error, as is a mask that matches none of its
block's lines. The fixture's `test_<name>.py` only binds
`f2kboot.corpus_test("<name>")`. A sectioned fixture may be declared
ahead of its real-machine files (`<name>.exe`, `<name>.c` and
`output.txt`, all absent): it is then one skipped test, and the disk
build leaves it out; `test_repository.py` refuses a fixture holding
only some of them. A fixture's companion DLLs (`tests/<name>/*.dll`)
go into `\CORPUS` beside its program, by their uppercase names (keep
them 8.3), as they sit beside it on the real machine. Every corpus boot goes through QEMU's
Multiboot loader (`-kernel`, the command line by `-append`), except
`test_limine.py`'s: a few blocks (the scenarios the retired smokes ran
on both paths, the command line, the memory map) booted from the disk
through Limine, on a copy of the disk whose Limine entry carries the
block's command line (`cmdline:`), compared against the same capture
with the same declaration. The Makefile's corpus derives from the
declarations too: a new fixture is its directory and its
`fixture.toml`. Every boot's COM1 log stays under
`target/qemu/logs/`.

### Tracing a slow block

`--perf-trace` builds the kernel with its `perf-trace` cargo feature and,
once each boot is done, turns its COM1 log into a performance profile
beside it: `target/qemu/profiles/<test id>.json`, one file per boot,
loadable at profiler.firefox.com (Load profile from file). The kernel's
interval clock then samples the interrupted context and its call stack on
every tick and dumps the samples before the line the harness stops the
boot on; nothing of the trace compiles without the feature. The stack walk
follows the frame-pointer chain, which the perf build forces (the
Makefile passes the flag; the first perf build rebuilds core and alloc),
and every step of a user stack is validated against the process's own
regions before it is read. The converter, scripts/perf_profile.py —
runnable by hand on any kept log — writes the profile: the kernel's
samples one thread, the ring-3 samples another, the flame graph a call
tree over real stacks.

The sampling rate is `SAMPLES_PER_TICK` in kernel/src/perf.rs
(samples per platform tick, 1, 2, 4, 8, or 16). Above 1 the
interrupt source runs faster, which can quantize a timed wait one
tick longer, so the tick-exact pins (the sleep smoke's) hold only at
the default 1 — a profiling build is for inspection, not
verification. A boot longer than the buffer's 1024 samples keeps its
most recent ones, up to 24 frames deep. Every booting suite gets its
profile — the corpus blocks, the Limine blocks, and the kernel cases
alike; a boot that halts before its teardown (a fault case's kernel
halt) has no dump to take, and a case whose last expectation passes
before the teardown may cut the dump short.

## Legacy fixtures

The single-path smokes below predate the sectioned fixtures. Each one's
scenario reappears in a sectioned fixture (named above); they retire
once the suite passes the sectioned fixture's blocks in their place
(`tests/test_limine.py` names each successor). `exit0` (the one-import
boot smoke) and `hello` (the CRT smoke, the pinned import trace, and
the disk-smoke checksum file) stay. Their checks are the kernel cases
in `kernel/test_kernel.py`; `exit0`, `ret0` and `hello` carry a
`fixture.toml` of kind `smoke` (no capture).

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

## Building

Run `build.bat` from a command prompt that has the MSVC 6 compiler on
PATH (the VS command prompt sets this up, e.g. via `vcvars32.bat`).
The exact per-test command lines live in `build.bat`; expected exit
code 0 means pass.

## How F2K consumes these

F2K loads every fixture from its boot disk: the disk build copies
the single-path fixtures into the FAT32 volume's root directory by
their 8.3 names (`EXIT0.EXE`, `RET0.EXE`, ...; see `DISK_FIXTURES` in
the Makefile; the root's one cluster is full) and the sectioned
fixtures into `\CORPUS`, and the kernel reads the selected program off
the volume by path before loading it. The suite attaches that disk to
every case, kernel-path cases included.

A boot chooses its program by command line: the text after `--` on
the kernel command line is the program's own command line,
`<program> [arguments]` (QEMU's `-append "-- CORPUS\sync.exe event"`,
the Limine entry's `cmdline:`, a kernel case's `cmdline`). Its first
token is the image's root-relative volume path (`.exe` added when it
has no extension); the program's GetCommandLineA reports the whole
text verbatim and its GetModuleFileNameA the volume path. Without a
command line the kernel runs `exit0`. The `run-process-suite` feature
(the multi-process case) runs the sequence `exit0`, `ret0`,
`bare`, `bare`, `bare null-write`, `exit0` in one boot: the second
`bare` catches frames reused without re-zeroing, `bare
null-write` a fault that must end its process (through kernel32's
start frame, with the access violation's code) before the last `exit0`
runs. Each boot
prints the observed process exit code on COM1 and then the teardown
audit (`F2K: teardown audit: frame database ok, kernel heap ok`), which
the corpus comparison waits for. Host unit tests still read the
checked-in `.exe` files directly (`include_bytes!`, test builds
only).

