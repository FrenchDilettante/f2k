# F2K - Fenêtre 2000

A Windows 2000-compatible operating system written in Rust.

F2K boots on a PC (QEMU or VirtualBox) and runs programs built for Windows 2000, unmodified.
Its behaviour is checked against the real thing: every test program is also run on Windows 2000, and F2K must give the same output.

## What runs today

- **Console programs**, including Windows 2000's own `cmd.exe`, with its built-in commands, batch files, redirection, and the programs it starts.
- **Simple GUI programs**, such as Windows 2000's Calculator: windows, menus driven by the keyboard, dialogs, buttons and edit boxes, drawn in the classic look.
- **Processes and threads**: up to 64 processes at once, child processes, consoles of their own or shared, and synchronization between them.
- **Files** on a FAT32 disk, the registry (kept in memory), the clipboard, TrueType fonts and bitmaps.
- **Legacy drivers**: a `.sys` file can be loaded and talked to, as on Windows 2000.

F2K provides its own versions of seven of Windows 2000's system DLLs: ntdll, kernel32, msvcrt, advapi32, user32, gdi32 and shell32.
None of them is complete yet: a function F2K doesn't have is either absent or a stub that logs its call, and the [compatibility report](#the-compatibility-report) shows which.
The mouse, networking, sound, printing and multiple processors are not there yet.

F2K also has a few programs of its own, under `userland/`: [`cmd.exe`](userland/cmd/README.md), [`pwd`](userland/pwd/README.md), [`ps`](userland/ps/README.md), [`shutdown`](userland/shutdown/README.md), `fish` (which switches to graphics mode and starts a GUI program), and small demos and test programs.

## Getting started

### Prerequisites

Rust must come from [rustup](https://rustup.rs): the `rust-toolchain` file pins the nightly this project needs, with its `rust-src`, `clippy` and `rustfmt` components.
A distribution `rustc`/`cargo` (Homebrew's `rust`, apt's `rustc cargo`) ignores that file and cannot build the kernel.

On macOS (ARM64 or x86_64):

```bash
brew install rustup x86_64-elf-binutils mtools qemu uv
rustup-init
uv sync          # the Python tooling (pytest), in a repository-local .venv
```

On Linux (x86_64):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install binutils mtools qemu-system-x86
curl -LsSf https://astral.sh/uv/install.sh | sh && uv sync
```

### Building

```bash
make userland    # the system DLLs only
make kernel      # the kernel (the system DLLs first)
make disk        # the disk image the tests boot
make clean
```

The system DLLs build first, because the kernel embeds ntdll.
The kernel builds with cargo's `release` profile; `KERNEL_PROFILE=checked` turns the debug assertions and overflow checks on (what `make test` boots, `TEST_PROFILE`), and `KERNEL_PROFILE=dev` builds it unoptimized.
So a bare `cargo check` in `kernel/` (and rust-analyzer) fails until `make userland` has run once.

### Running

```bash
make run                                   # boot into F2K's cmd.exe in a QEMU window
make run CMDLINE='CORPUS\sync.exe event'   # boot into another program
```

The QEMU window shows the screen and takes the keyboard; the kernel's log (COM1) goes to the terminal.
A GUI program runs under `fish`: type `fish <program>` at the prompt, or `make run CMDLINE='WINNT\system32\fish.exe \WINNT\system32\drawdemo.exe'`.
`shutdown /l /y` ends the session cleanly.

To run F2K in VirtualBox, `make vbox-image` writes the same disk as `target/f2k.vdi`, with any files under `vbox-image/` (not committed) laid over it.
F2K's disk driver is IDE, so attach the disk to an IDE controller:

```bash
VBoxManage createvm --name F2K --ostype Other --register
VBoxManage storagectl F2K --name IDE --add ide --controller PIIX4 --bootable on
VBoxManage storageattach F2K --storagectl IDE --port 0 --device 0 --type hdd --medium target/f2k.vdi
VBoxManage modifyvm F2K --memory 256
VBoxManage startvm F2K
```

The VDI keeps its UUID across rebuilds, so the VM keeps it attached; rebuild with the VM powered off.

## Testing

```bash
make run-tests   # host unit tests
make test        # on-target tests: F2K booted in QEMU
make compat      # export pins, host scenarios, and the compatibility report
make check-all   # all three, fastest first, stopping at the first failure
make check       # cargo check and clippy
```

### The corpus

Most of F2K's behaviour is pinned by the corpus under `tests/`: small C programs built and run on a real Windows 2000 machine, their output captured, and the same programs run on F2K and compared block by block.
[`tests/README.md`](tests/README.md) explains how fixtures are written, built, captured and compared.

The on-target tests are ordinary pytest tests, so an IDE lists and runs them one by one:

```bash
uv run pytest tests/kernel32/runtime -k crt         # one block of one fixture
uv run pytest tests/kernel32 -n 4                   # one DLL's fixtures
uv run pytest tests/kernel32/runtime --runxfail     # see why pending blocks fail
uv run pytest --collect-only -q                     # list every test
```

Besides the corpus, `tests/core/` holds the kernel's own boots, the shutdown tests, and three screen tests that compare the screen with committed PNG baselines.
A screen that changes fails its test and rewrites its baseline; committing the new baseline accepts it.

### The compatibility report

Each system DLL's exports are declared once, in `userland/<dll>/exports.toml`, which lists every export of Windows 2000's own DLL and marks each as implemented, a stub, or not there yet.
`tools/exportgen` generates the system-call tables and stubs from these specs; the system calls use Windows 2000's own numbers.

`make compat` draws `target/compat/report.html`: one square per export, coloured by whether the tests that pin it pass, plus a card per real Windows program showing which of its imports F2K has.
`uv run scripts/compat.py --check` checks the pins and the import tables; `--depth` lists exports tested by a single block.

### Formatting

```bash
make fmt         # format everything
make fmt-check   # fail if anything is unformatted
```

Rust follows `rustfmt.toml` (100 columns; wrap new comments yourself, rustfmt never joins lines).
Markdown follows rumdl (`pyproject.toml`): one sentence per line.

## Repository layout

```text
f2k/
├── kernel/       # The kernel, ntoskrnl.exe: memory, processes, the scheduler, the object manager,
│                 # FAT32, the registry, the I/O manager and drivers, and win32k (windows and GDI)
├── userland/     # The system DLLs (rtl, ntdll, kernel32, msvcrt, advapi32, user32, gdi32,
│                 # shell32) and F2K's own programs; its own Cargo workspace
├── tests/        # The Windows 2000 corpus and the pytest suite (see tests/README.md)
├── tools/        # exportgen: the export specs' reader and generator
├── scripts/      # Build and test scripts: linker scripts, compat.py, the export dumps
├── fonts/        # The TrueType fonts the run disk carries
├── boot/         # The Limine configuration (Limine itself is a submodule)
└── vbox-image/   # Files added to the VirtualBox disk (not committed)
```

## Make targets

| Target            | Description                                                                      |
| ----------------- | -------------------------------------------------------------------------------- |
| `make userland`   | Build the system DLLs (`target/userland/`)                                       |
| `make kernel`     | Build the kernel, its image `ntoskrnl.exe` and the boot loader, the DLLs first   |
| `make disk`       | Create the Limine-bootable disk image the tests boot                             |
| `make cmd-disk`   | The disk with `cmd.exe` and the fonts added, booting `CMDLINE` (default cmd.exe) |
| `make run`        | Boot the cmd disk in a QEMU window                                               |
| `make vbox-image` | The cmd disk as a VirtualBox disk (`target/f2k.vdi`)                             |
| `make run-tests`  | Run the host unit tests                                                          |
| `make test`       | Run every on-target QEMU test                                                    |
| `make compat`     | Check the tests' pins, run the host scenarios, write the compatibility report    |
| `make check-all`  | `run-tests`, `compat` and `test`, in that order                                  |
| `make check`      | `cargo check` and clippy                                                         |
| `make fmt`        | Format the Rust sources and the Markdown files                                   |
| `make fmt-check`  | Fail if a Rust source or a Markdown file is unformatted                          |
| `make limine`     | Download the Limine bootloader                                                   |
| `make clean`      | Clean build artifacts                                                            |
| `make clobber`    | Remove all build artifacts                                                       |
