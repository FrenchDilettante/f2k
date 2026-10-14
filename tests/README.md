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
├── imports.txt     # verified facts from the binary, where relevant
└── <name>.rs       # planned: the same test for F2K's own Rust toolchain
```

The Rust counterpart exists so the same test can be built and run by
our own toolchain as well as the reference one; it lands when the
toolchain can build it. Build intermediates (`.obj` etc.) are ignored,
not committed.

## Tests

- `exit0` - no C runtime: the entry point calls `ExitProcess(0)`; a
  single import, so it exercises process creation, image mapping and
  the exit path and nothing else.
- `bsscheck` - no C runtime: the entry point checks that its `.bss`
  (uninitialized data) is all zero, scribbles a pattern over it, and
  exits 0 only if the check passed. The suite runs it twice in one
  boot: the second run catches teardown that reuses frames without
  re-zeroing them.
- `crash` - no C runtime, no imports: the entry point writes through
  the unmapped NULL page as its first act and must fault. The suite
  asserts the kernel contains the fault and keeps running.
- `ret0` - the default MSVC 6 `/ML` CRT startup around
  `int main() { return 0; }`; exercises the full CRT initialization
  surface (35 KERNEL32.dll imports; see `ret0/imports.txt`).
- `hello` - the console rung: the same CRT startup, then `printf`
  writes "Hello, world!" to stdout and exits 0; the first test with
  observable output. Also carries `trace.txt`, the real-machine
  import trace (21 of the watched imports called on the happy path,
  one WriteFile, exit 0 — the oracle for the console-observable
  workstream).
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

## Building

Run `build.bat` from a command prompt that has the MSVC 6 compiler on
PATH (the VS command prompt sets this up, e.g. via `vcvars32.bat`).
The exact per-test command lines live in `build.bat`; expected exit
code 0 means pass.

## How F2K consumes these

Until F2K can read from its FAT32 disk partition, the on-target QEMU
suite embeds fixtures directly in the kernel image
(`include_bytes!`): the default kernel runs `exit0`, the `run-ret0`
feature selects `ret0`, and the `run-hello` feature selects `hello`
(whose WriteFile output appears on COM1 as the program's own). The
`run-pingpong` feature (the blocking-wait smoke) selects `pingpong`
with the thread-ified boot: the main thread enters ring 3 through
the scheduler's first switch, and its thread and wait calls run
against the landed scheduler machinery. The
`run-process-suite` feature (the multi-process case) embeds
`bsscheck` and `crash` as well and
runs the sequence `exit0`, `ret0`, `bsscheck`, `bsscheck`, `crash`,
`exit0` in one boot. Each boot prints the observed process exit code
on COM1, which the suite cases assert. Once disk I/O exists,
fixtures load from the disk image instead and the embedding goes
away.

The scheduler smoke tests (`thread`, `pingpong`, `sleep`, `spin`,
`suspend`) join the same embedding one per workstream slice, in
dependency order, as the scheduler grows; each asserts the
real-machine captured output of its stage.
