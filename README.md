# F2K - Fenêtre 2000

A Windows 2000-compatible operating system written in Rust.

## What runs today

F2K boots on a PC (QEMU or VirtualBox) from a FAT32 disk and runs Win32 console programs built for Windows 2000, unmodified.
Five of Windows 2000's system DLLs are F2K's own code:

- **ntdll**: the system calls into the kernel, the program loader, and the runtime library the other DLLs build on.
- **kernel32**: processes and threads, synchronization, memory, files, the console, the environment, code pages and locale, messages.
- **msvcrt**: the C runtime for programs built against msvcrt.dll: start-up and exit, exception handling and `setjmp`, files and stdio, `printf` and `scanf`, wide strings, the allocator.
- **advapi32**: the registry calls, over a registry the kernel keeps in memory.
- **user32**: window stations, desktops and `MessageBeep`; no windows yet.

Windows 2000's own `cmd.exe` starts and runs its built-in commands (`dir`, `copy`, `set`, `type`, `md`...); it cannot start other programs yet, since F2K runs one process at a time.
Functions F2K does not have yet are either absent or stubs that log their call (see the compatibility report below).

## Prerequisites

This project uses Nightly Rust via the `rust-toolchain` file, which also pulls in the `rust-src`, `clippy` and `rustfmt` components.
Your default toolchain remains unaffected.

Rust must come from [rustup](https://rustup.rs): it is what reads the `rust-toolchain` file and installs the pinned nightly.
A distribution `rustc`/`cargo` (Homebrew's `rust`, apt's `rustc cargo`) ignores the file and cannot build the kernel (`-Z build-std`, JSON target specs).

### macOS (ARM64 or x86_64)

```bash
brew install rustup x86_64-elf-binutils xorriso mtools qemu uv
rustup-init
# The Python tooling (pytest for the on-target tests) in a
# repository-local .venv, from pyproject.toml
uv sync
```

### Linux (x86_64)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install binutils xorriso mtools qemu-system-x86
curl -LsSf https://astral.sh/uv/install.sh | sh && uv sync
```

## Building

The system DLLs (`userland/`) are real PE32 DLLs, built at Windows 2000's base addresses.
They build first, into `target/userland/`: the kernel embeds ntdll, and the disk image carries all five in its system directory, `\WINNT\system32`, where ntdll loads the others from when a program starts, as on Windows 2000.
`userland/` is its own Cargo workspace with its own target (`userland/i686-f2k-pe.json`).
The kernel's build reads the built DLLs, so a bare `cargo check` or `cargo build` in `kernel/` (and rust-analyzer) fails until `make userland` has run once.

```bash
# Build the system DLLs only
make userland

# Build the kernel (the system DLLs first)
make kernel

# Build bootable ISO with Limine (boots the kernel via Multiboot 1)
make iso

# Clean build artifacts
make clean
```

## Running

A boot runs the program its kernel command line names (`-- <program> [arguments]`; `exit0` without one).
Every process starts in its program's directory with the same environment (`kernel/src/user/params.rs`): `COMPUTERNAME=QEMU`, `ComSpec=C:\WINNT\system32\cmd.exe`, `PATH=C:\WINNT\system32;C:\WINNT`, `PATHEXT=.COM;.EXE;.BAT;.CMD`, `SystemRoot=C:\WINNT`, `USERNAME=jeb` and `windir=C:\WINNT`.

### QEMU (ISO with Limine)

```bash
make iso          # Create ISO first
make qemu_iso    # Boot ISO in QEMU
```

### QEMU (Direct kernel)

The kernel is a Multiboot 1 ELF, so QEMU can load it without a bootloader (the disk image is still attached: the kernel loads its programs from the disk's volume):

```bash
make qemu        # Exit with Ctrl-A X
```

### Disk image (Limine on an MBR/FAT32 hard disk)

```bash
make run         # Builds target/x86-f2k/debug/f2k-disk.img and boots it in QEMU
```

### VirtualBox

`make vbox-image` writes the disk as a VirtualBox disk, `target/f2k.vdi` (with `qemu-img`).
Every file under `vbox-image/` is added to the volume at the same path, directories merged with the disk's own (`vbox-image/WINNT/system32/cmd.exe` lands beside the system DLLs); nothing there is committed.
`CMDLINE` sets what the boot runs, the program's path on the volume and its arguments; without it the boot runs `exit0`:

```bash
make vbox-image CMDLINE='WINNT\system32\cmd.exe'
```

The VDI keeps the same UUID across rebuilds, so a VM keeps it attached: rebuild with the VM powered off.
F2K's disk driver is IDE, so the VM's disk goes on an IDE controller:

```bash
VBoxManage createvm --name F2K --ostype Other --register
VBoxManage storagectl F2K --name IDE --add ide --controller PIIX4 --bootable on
VBoxManage storageattach F2K --storagectl IDE --port 0 --device 0 --type hdd --medium target/f2k.vdi
VBoxManage modifyvm F2K --memory 256
VBoxManage startvm F2K
```

## Testing

### Host unit tests

```bash
make run-tests
```

### The export specs and the compatibility report

Each system DLL's exports are declared once, in `userland/<dll>/exports.toml` (the file's header documents its records): name, API group, prototype and implementation.
`tools/exportgen` reads the specs and generates what derives from them: the kernel's system-call tables, the `.def` files, and the system-call stubs.

As on Windows 2000, only three DLLs call into the kernel: ntdll for the NT system calls, and user32 and gdi32 for the window manager's (gdi32 has none yet).
Both tables use Windows 2000's own call numbers (`userland/ntdll/w2k-services.txt`, `userland/user32/w2k-services.txt`).
Every other DLL is user-mode code on top of them, and the kernel has no Win32 layer.

A stub (`impl = { stub = "<reason>" }` in the spec) is an export that exists but does nothing yet: when called, it writes a line to COM1 with its arguments and the reason, then fails the way the real function fails (one that returns nothing just returns).
Code that reaches a case it doesn't handle yet can do the same, through `stub::stubbed`.
Stubs log through ntdll's `DbgPrint`, which Windows 2000's msvcrt and user32 do not import: the import check allows that one import (`STUB_LOG_IMPORT` in `scripts/compat.py`).

The host scenarios (`userland/kernel32/src/scenarios/`, all `#[cfg(test)]`) call kernel32's exports as a program does, against stand-ins for ntdll.
A known gap is an expected-failure test: a scenario marked `#[ignore = "<gap id>: <why>"]`, or a pending block in its fixture's `fixture.toml`.

The tests declare which exports they pin, as `dll.Export`: a corpus fixture in its `fixture.toml`'s `[pins]` (per section; `"*"` for every block), a host scenario in its doc comment's `/// Pins:` lines.
`scripts/compat.py` derives each export's status from its pinning tests' last results:

- grey: not implemented; darker grey, marked !: a stub;
- green: implemented, and a test passed;
- red, marked ×: implemented, and a test failed;
- yellow: implemented, with no test that passed or failed.

A border marks an export a pending or skipped corpus test pins: work in progress.
Every `make test` keeps its results (`target/test-results/pytest.json`); `make compat-report` runs the host scenarios and draws the report from both, `target/compat/report.html`, a treemap of every DLL with one square per export.
`--check` checks the pins against the specs and the captures, and that each DLL F2K builds imports only what Windows 2000's imports; `--run` runs every scenario, ignored ones included, and fails once a gap's test passes (the marker goes with the fix).

```bash
uv run scripts/compat.py --check
uv run scripts/compat.py --run
make compat          # both
make compat-report   # the report, after a `make test`
```

Each spec lists every export of Windows 2000's own DLL (SP4's: ntdll, kernel32, advapi32, user32, gdi32, msvcrt, ole32, oleaut32, rpcrt4, psapi and version): an export F2K doesn't implement yet is a catalogued record (its name and ordinal only), and every implemented export keeps its Windows 2000 ordinal.
`scripts/dump_exports.py` reads a real DLL's export and import tables into `userland/<dll>/exports-<version>.txt` and `imports-<version>.txt`; `scripts/catalogue_exports.py` folds the export dump into the spec, after which the dump goes.
The import tables stay, for the import check.
The real DLLs never enter the repository.

### Everything

`make check-all` runs the test systems in turn, fastest first, stopping at the first failure: the host unit tests (`make run-tests`), the pins and the host scenarios (`make compat`) and the on-target suite (`make test`; `PYTEST_FLAGS` passes through).

```bash
make check-all PYTEST_FLAGS="-n 2"
```

### On-target QEMU tests

The on-target tests run through pytest, so an IDE lists and runs them one by one:

- **The corpus.**
  Each fixture's `tests/<dll>/<name>/test_<name>.py` compares F2K with the fixture's real-machine capture (see `tests/README.md`): one test per captured block, the fixture's `fixture.toml` stating what the comparison allows and which blocks are still pending.
  A fixture's blocks share one boot, each block's program its own process, and each test compares its own part of the boot's COM1 log (`target/qemu/logs/<fixture>.log`).
  Selecting one block (`-k crt`) boots that block alone; if the boot stops early, the block it stopped in fails with the reason and the later ones fail as not run.
  Fixtures that draw on the screen can save a screenshot per block (`target/qemu/screens/`), not compared yet.
- **The kernel's own boots** (the fault stubs, the Limine disk path, the program smokes, the multi-process suite, the interrupt and IDE diagnostics) are cases in `tests/core/kernel/test_kernel.py`: the kernel features to build with, the image to boot, the program's command line, the COM1 strings expected (anywhere, in order, as one block of lines) or forbidden.
  A kernel panic fails every case.

Each test builds the kernel and disk for its feature set (once per run, cached under `target/qemu/builds/`); each run removes earlier runs' builds and logs older than two days.
Boots attach the disk as a snapshot, so tests run in parallel (`-n 4` by default in `make test`; `--dist loadgroup`, set in `pyproject.toml`, keeps a fixture's tests on one worker).

```bash
make test        # every on-target test: the kernel boots and the corpus
uv run pytest --collect-only -q                     # list every test
uv run pytest tests/core/kernel -k fault-ud         # one kernel case
uv run pytest tests/core/bare                       # one fixture's blocks, one boot
uv run pytest tests/kernel32/runtime -k crt         # one block
uv run pytest tests/kernel32 -n 4                   # one DLL's fixtures
uv run pytest tests/kernel32/runtime --runxfail     # see why the work list fails
uv run pytest --no-build ...                        # reuse the last make disk (its features only)
make test KERNEL_PROFILE=dev-opt                    # the kernel's dependencies optimized
```

`KERNEL_PROFILE` picks the kernel's cargo profile (`make kernel`, `disk`, `qemu`, `test`...; the suite reads it as `F2K_KERNEL_PROFILE`): `dev`, the default, or `dev-opt` (Cargo.toml), which optimizes the kernel's dependencies (core, alloc, memcpy and memset) and keeps the debug assertions and overflow checks.
The kernel crate itself stays unoptimized: an optimized kernel hangs (see the profile's comment).

### Check code

```bash
make check
```

### Formatting

Rust sources are formatted with rustfmt (settings in `rustfmt.toml`): 100 columns for code and comments, imports grouped (std/core, external, crate) and sorted.
It splits overlong comment lines but never joins short ones, so wrap new comments at 100 yourself.
Hand-laid tables opt out with `#[rustfmt::skip]`.
Markdown files are formatted with rumdl (settings in `pyproject.toml`): one sentence per line, the editor wraps, and tables aligned.

```bash
make fmt         # format everything
make fmt-check   # fail if anything is unformatted
```

## Project Structure

```text
f2k/
├── rust-toolchain    # Nightly Rust for this project
├── rustfmt.toml      # rustfmt settings (make fmt)
├── Cargo.toml        # Workspace manifest
├── Makefile          # Build system
├── x86-f2k.json      # Rust target: 32-bit x86 bare metal
│
├── boot/             # Bootloader files
│   ├── *.asm, *.S        # Early custom boot sector experiments (unused)
│   ├── limine.conf       # Limine config (ISO and disk image)
│   └── limine/           # Limine bootloader (git submodule)
│
├── scripts/          # Build and test scripts
│   ├── x86-elf-ld         # Linker wrapper
│   ├── linker.x86         # Custom linker script
│   ├── create_partition_table.py  # MBR partition table for the disk image
│   ├── gen-files-data.py  # The files fixture's data tree (tests/kernel32/files/DATA)
│   ├── gen-nt-tables.py   # Windows 2000's service numbers and the status table, regenerated
│   ├── compat.py          # The DLL compatibility: the pins checked, the scenarios run, the report
│   ├── dump_exports.py    # A real DLL's export and import tables, dumped
│   ├── catalogue_exports.py  # A dumped export table folded into its DLL's spec
│   └── vbox_image.py      # The boot disk as a VirtualBox disk (make vbox-image)
│
├── pyproject.toml    # The Python tooling (uv): pytest for the on-target tests
├── tests/            # Windows 2000 test corpus and the pytest suite (see tests/README.md)
│   ├── core/             # The kernel's own boots and the smoke fixtures
│   ├── kernel32/         # The kernel32 fixtures
│   ├── user32/           # The user32 fixtures (hellogui, winsta)
│   ├── advapi32/         # The advapi32 fixture (registry)
│   ├── crt/              # The msvcrt fixtures, built against msvcrt.dll (/MD)
│   ├── harness/          # Checks of the tests and the repository (no QEMU)
│   └── common/           # The fixtures' shared header (f2kt.h) and stamp tool
│
├── tools/exportgen/  # The export specs' reader and generator (a host crate, outside the workspace)
├── userland/         # The system DLLs (own workspace and target): rtl (the shared runtime),
│                     # ntdll, kernel32, msvcrt, advapi32, user32; each DLL's export spec in
│                     # userland/<dll>/exports.toml, the DLLs F2K doesn't build their spec alone
├── vbox-image/       # Files make vbox-image adds to the VirtualBox disk (not committed)
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    ├── build.rs          # The service tables from the export specs; the embedded ntdll
    └── src/
        ├── block/        # Block devices, partitions, and the device registry
        ├── boot/         # Boot-related code
        ├── cm/           # The configuration manager: the registry, in kernel memory
        ├── cpu/          # The CPU tables
        ├── exec/         # Executable loading, and ntdll, the DLL every process maps
        ├── fs/           # FAT32 over the block devices, and the open files
        ├── hw/           # The hardware layer: devices the kernel drives directly
        ├── interrupt/    # The interrupt core (hardware-neutral, host-testable)
        ├── mem/          # Memory management
        ├── nt/           # The NT system services, by Windows 2000's numbers
        ├── ob/           # The object manager: handles and the objects they name
        ├── process/      # Process lifetime
        ├── sched/        # The scheduler
        ├── user/         # Ring 3: the user-mode boundary
        ├── win32k/       # Window stations and desktops: win32k's services, user32's calls
        ├── c_lib.rs      # C library stubs (linker support)
        ├── lib.rs        # Kernel library: kmain and all modules (unit-testable)
        └── main.rs       # Kernel binary: links the ELF; panic handler
```

## Targets

| Target               | Description                                                                      |
| -------------------- | -------------------------------------------------------------------------------- |
| `make userland`      | Build the system DLLs (`target/userland/`)                                       |
| `make kernel`        | Build the kernel (ELF), the system DLLs first                                    |
| `make qemu`          | Build the disk and boot the kernel directly in QEMU, the disk attached           |
| `make test`          | Run every on-target QEMU test (pytest: the kernel boots and the corpus)          |
| `make run-tests`     | Run host unit tests                                                              |
| `make compat`        | Check the tests' pins and run the host scenarios                                 |
| `make compat-report` | The DLL compatibility report (`target/compat/report.html`) from the last results |
| `make check-all`     | `run-tests`, `compat` and `test`, in that order                                  |
| `make check`         | `cargo check` + clippy (the kernel and the userland crates)                      |
| `make fmt`           | Format the Rust sources and the Markdown files                                   |
| `make fmt-check`     | Fail if a Rust source or a Markdown file is unformatted                          |
| `make limine`        | Download Limine bootloader                                                       |
| `make iso`           | Create bootable ISO with Limine                                                  |
| `make qemu_iso`      | Build ISO and run in QEMU                                                        |
| `make disk`          | Create Limine-bootable disk image                                                |
| `make run`           | Build disk and run in QEMU                                                       |
| `make vbox-image`    | The disk as a VirtualBox disk (`target/f2k.vdi`), with `vbox-image/` added       |
| `make clean`         | Clean build artifacts                                                            |
| `make clobber`       | Remove all build artifacts                                                       |
