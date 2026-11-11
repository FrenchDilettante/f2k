# Work order — kernel consolidation C5: retire COM1 as the observation channel (COM stays a feature)

For one implementation agent, working only from this order and the repository it
lives in. Everything the task needs is stated here or already in the tree;
nothing else is assumed. This file lives in `.scratch/`; it is a work order,
not product documentation, and it is deleted when the work lands.

**Sequencing:** C4 is in flight on `wip/kernel-c4` (five new fixtures whose
blocks are verified on the COM1 observation). This branch is created off
master: do not touch `tests/kernel32/{threx,vmedge,startup,lcid,ntquery}/` or
their pins, and do not change any behavior those fixtures pin. Rebase onto
master again when C4 lands; the observation flip is the last thing to land
of the two.

## Standing rules

- This repository is a no_std i686 kernel plus its user-mode DLLs. Match the
  existing style of the file you touch. Comments describe what and why, never
  how, and never cite other operating systems or codebases. Documented public
  names (VGA text-mode cell format, the 16550 UART's register names, QMP
  command names, PE/COFF fields, `Nt*` spellings) are required naming where
  they appear.
- Never commit. Leave the work in the working tree and report.
- The behaviors this order states are the contract. Hardware facts (VGA text
  mode, the 16550, QEMU's QMP) are public; do not consult or derive from any
  other implementation's source.
- The gates: `make check`, `make run-tests`, `uv run pytest tests/harness`,
  `uv run scripts/compat.py --check`, and `make test` (the on-target QEMU
  suite) green when you report; the owner re-runs the full suite. Do not
  weaken an existing test to make it pass; report instead.
- Do not touch anything outside the scope fence at the end of this order.

## Where things stand (the file map)

- The observation channel today is COM1: QEMU boots log the serial line to a
  file (`tests/f2kboot.py`: `-serial file:{log_path}`, the `done(log)`
  predicates, the kernel cases' `expects` rules, the batch's split at the
  program-start lines, `SCREEN_PAUSE` matched from the log, the log paths
  under `target/qemu/logs/`), and `scripts/perf_profile.py` parses those logs.
  The screen side already exists beside it: `read_text_screen`/`TextScreen`
  and `screendump`/`read_png` in `tests/f2kboot.py`, used for the
  `screenshots` fixtures and `tests/core/test_textscreen.py`.
- The kernel's serial output: `kernel/src/hw/serial.rs` (the 16550 driver,
  host-tested against a simulated register file) and the `serial_print!` /
  `serial_println!` macros it defines. `kernel/src/boot/mod.rs` prints the
  boot diagnostics through them; `kernel/src/dbgprint.rs` is `DbgPrint`;
  `kernel/src/csr.rs` tees every client write to the serial line beside the
  screen buffer's renderer (its module doc describes the two places, and the
  `redirected` kernel option that sends the standard handles' writes to the
  serial line alone; after each call the window's changed rows are copied to
  the VGA text screen). The console's screen buffer is
  `rtl::console::screen::ScreenBuffer`; the VGA text screen is
  `kernel/src/hw/vga.rs`'s `TextScreen`/`CellMemory`.
- The screens-pause protocol today: the kernel option `screens` makes
  `kernel/src/process/runner.rs` announce each process's end (the line
  `F2K: screen: process N ended`), hold the boot, and wait on the CMOS
  mailbox (`kernel/src/hw/rtc.rs` `SCREEN_MAILBOX`, `await_mailbox`); the
  harness's `ScreenTaker` matches the announcement in the COM1 log, takes the
  QMP `screendump`, then writes the mailbox through the monitor.
- Kernel cargo features live in `kernel/Cargo.toml` `[features]` (the
  fault-injection ones are the pattern: test-only, off by default).

## The task (C5, in this order)

1. **C5.1 — the kernel console-writer.** Early boot and the panic path write
   the VGA text screen directly (the text page is mapped from the boot
   directory; lock-free at that point). Once the console subsystem is up,
   diagnostics go through the console's screen buffer, the way client writes
   render.
2. **C5.2 — the serial tee comes out of `csr.rs`.** Client writes render to
   the screen only, as on a real machine under redirection. Keep the
   `redirected` option's contract consistent with however C5.3 reads block
   output (the capture's redirected output never reaches the screen); record
   the choice in your report.
3. **C5.3 — the harness observation flips, once.** From the COM1 log to the
   QMP text-screen read: the kernel cases' `expects` strings become expected
   screen lines; the batch's block splitting and start announcements read the
   screen; the screens-pause protocol moves off COM1 (announcement on the
   screen, detection by reading the screen, release through the CMOS mailbox
   as today); `scripts/perf_profile.py` reads the new channel. The suite is
   green reading the screen on both boot paths (`-kernel` and Limine).
4. **C5.4 — COM stays a feature.** `kernel/src/hw/serial.rs` remains as a
   serial device (host tests unchanged). COM1 logging becomes an opt-in cargo
   feature in `kernel/Cargo.toml` (default off) — the channel a future kernel
   debugger binds to, and the basis for a user-mode COM1 device object.
   `DbgPrint` with no debugger attached then goes nowhere unless the feature
   is on. No `serial_println!` remains outside the feature: a repository
   check pins that.

## Scope fence

Within scope: `kernel/src/**` (boot, csr and csr/, hw/serial.rs, hw/vga.rs,
hw/rtc.rs, dbgprint.rs, process/runner.rs, mem/ as needed), `kernel/Cargo.toml`
(features), `tests/f2kboot.py`, `tests/conftest.py`, `tests/core/**`,
`tests/harness/**`, `tests/README.md`, `scripts/perf_profile.py`, the
`Makefile` if a build option is needed. Do NOT touch: `userland/`,
`kernel/src/win32k/**`, `kernel/exports.toml`, `kernel/loader/`, the linker
scripts, `scripts/loader.x86`, C4's five fixtures
(`tests/kernel32/{threx,vmedge,startup,lcid,ntquery}/`), any DLL spec, or any
other slice's files.

## Done means

- The full suite green reading the screen on both boot paths (`make test`),
  with the `screenshots` fixtures' PNGs still recorded.
- A boot with the COM1 feature on logs to COM1; a boot with it off writes
  nothing to COM1 (repository check); no `serial_println!` outside the
  feature.
- `make check`, `make run-tests`, `uv run pytest tests/harness`,
  `uv run scripts/compat.py --check` green.
- A report: the console-writer's shape, the redirected-output contract you
  chose in C5.2, the observation flip's mechanics, the feature's name, and
  any deviation from this order with its reason.
