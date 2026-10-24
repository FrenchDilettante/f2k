# F2K - Fenêtre 2000

A Windows 2000-compatible operating system written in Rust.

## Prerequisites

This project uses Nightly Rust via the `rust-toolchain` file, which also pulls in the `rust-src`, `clippy` and `rustfmt` components. Your default toolchain remains unaffected.

Rust must come from [rustup](https://rustup.rs): it is what reads the
`rust-toolchain` file and installs the pinned nightly. A distribution
`rustc`/`cargo` (Homebrew's `rust`, apt's `rustc cargo`) ignores the file
and cannot build the kernel (`-Z build-std`, JSON target specs).

### macOS (ARM64 or x86_64):
```bash
brew install rustup x86_64-elf-binutils xorriso mtools qemu uv
rustup-init
# The Python tooling (pytest for the on-target tests) in a
# repository-local .venv, from pyproject.toml
uv sync
```

### Linux (x86_64):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install binutils xorriso mtools qemu-system-x86
curl -LsSf https://astral.sh/uv/install.sh | sh && uv sync
```

## Building

The system DLLs (`userland/`: `ntdll.dll` and `kernel32.dll`, real PE32 images) build first: the
kernel embeds ntdll and maps it into every process, and the disk image carries both in its system
directory, `\WINNT\system32`. As on Windows 2000, the kernel maps only a program and ntdll; ntdll's
process start loads every other DLL from the volume, kernel32 included, snaps their imports and
calls their entry points (the kernel reads kernel32's start thunk, where every program's main
thread starts, from the same file at boot). `userland/` is its own Cargo workspace with
its own target (`userland/i686-f2k-pe.json`, linked by the toolchain's `rust-lld` in its MSVC
mode); `make kernel` builds it first, and the DLLs land in `target/userland/`. The kernel's build
script reads them, so a bare `cargo check` or `cargo build` in `kernel/` (and rust-analyzer) fails
until `make userland` has run once.

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

### QEMU (ISO with Limine)
```bash
make iso          # Create ISO first
make qemu_iso    # Boot ISO in QEMU
```

### QEMU (Direct kernel)
The kernel is a Multiboot 1 ELF, so QEMU can load it without a bootloader (the disk image is
still attached: the kernel loads its programs from the disk's volume):
```bash
make qemu        # Exit with Ctrl-A X
```

### Disk image (Limine on an MBR/FAT32 hard disk)
```bash
make run         # Builds target/x86-f2k/debug/f2k-disk.img and boots it in QEMU
```

To run the same image in VirtualBox:
```bash
VBoxManage createvm --name F2K --ostype Linux24 --register
VBoxManage storagectl F2K --name 'SATA' --add sata --bootable on
VBoxManage storageattach F2K --storagectl SATA --port 0 --device 0 --type hdd --medium target/x86-f2k/debug/f2k-disk.img
VBoxManage modifyvm F2K --memory 256
VBoxManage startvm F2K
```

## Testing

### Host unit tests
```bash
make run-tests
```

### The export specs and the compatibility report
Each system DLL's exports are declared once, in `userland/<dll>/exports.toml` (the file's header
documents its records): name, API group, prototype and implementation. `tools/exportgen` reads the
specs and generates what derives from them: the kernel's NT service table (ntdll's `Nt*` system
services, by Windows 2000's own numbers, `userland/ntdll/w2k-services.txt`) and the tables its
tests check the built DLLs against (through the kernel's build script), and, for the DLL builds,
the `.def` file and ntdll's `Nt*`/`Zw*` stubs (`userland/build-support/stubs.rs`).

Only ntdll's system services enter the kernel, as on Windows 2000: an `impl = { syscall = "..." }`
export's stub raises the gate on Windows 2000's own service number, and the kernel's typed handler
(`kernel/src/nt/`) takes its arguments by the kinds the spec gives them (`handle`, `ptr`,
`ptr<u32>`..., see the spec's header) and answers an NTSTATUS. Every kernel32 export is kernel32's
own user-mode code over ntdll (`impl = { native = "..." }`, or a forwarder into ntdll), which sets
the last error from the NTSTATUS through `RtlNtStatusToDosError`. The kernel has no Win32 layer.

The host scenarios (`userland/kernel32/src/scenarios/`, all `#[cfg(test)]`) call kernel32's
exports as a program does, against host stand-ins for ntdll. A known gap is an expected-failure
test: a scenario marked `#[ignore = "<gap id>: <why>"]`, or a strict pending block in its
fixture's `fixture.toml`.

The tests declare which exports they pin, as `dll.Export`: a corpus fixture in its
`fixture.toml`'s `[pins]` (per section; `"*"` for every block), a host scenario in its doc
comment's `/// Pins:` lines. `scripts/compat.py` derives each export's status from its pinning
tests' last results: unimplemented (grey), implemented and passing (green), implemented with a
failing test (red), implemented with no passing test (yellow: none pins it, or every test that
does is pending, skipped or did not run), or stubbed (grey with a teal tint). Every
`make test` keeps its results
(`target/test-results/pytest.json`); `make compat-report` runs the host scenarios and draws the
report from both, `target/compat/report.html`: a treemap of every DLL, one square per export. `--check` checks the
pins against the specs and the captures; `--run` runs every scenario, ignored ones included, and
fails once a gap's test passes (the marker goes with the fix).

A stub (`impl = { stub = "<reason>" }` in the spec) is an export that exists but does nothing
yet: when called, it writes a line to COM1 with its arguments and the reason, then fails the way
the real function fails. Code that hits a case it doesn't handle yet can do the same, through
`stub::stubbed`.
```bash
uv run scripts/compat.py --check
uv run scripts/compat.py --run
make compat          # both
make compat-report   # the report, after a `make test`
```

Each spec lists every export of Windows 2000's own DLL (SP4's: ntdll, kernel32, advapi32, user32,
gdi32, msvcrt, ole32, oleaut32, rpcrt4, psapi and version): an export F2K does not implement yet is a catalogued record (its name and
ordinal, no implementation; nothing is generated for it), and every implemented export carries
its Windows 2000 ordinal. `scripts/dump_exports.py` reads a real DLL's export table (ordinals,
names, forwarders, data exports) into `userland/<dll>/exports-<file version>.txt`, and its import
table (each module it imports from, delay-loaded ones marked) into
`userland/<dll>/imports-<file version>.txt`; `scripts/catalogue_exports.py` folds the export dump
into the spec (checking the spec's exports and forwarders against it first); the export dumps go
once folded, and the DLLs themselves never enter the repository. The import tables stay:
`compat.py --check` fails if one of our DLLs imports something the real one doesn't.

### Everything
`make check-all` runs the test systems in turn, fastest first,
stopping at the first failure: the host unit tests (`make run-tests`),
the pins and the host scenarios (`make compat`) and the on-target suite (`make test`;
`PYTEST_FLAGS` passes through).
```bash
make check-all PYTEST_FLAGS="-n 2"
```

### On-target QEMU tests
The on-target tests run through pytest (each sectioned fixture's
`tests/<dll>/<name>/test_<name>.py`, under the DLL it exercises; the
kernel's own boots in `tests/core/kernel/test_kernel.py`; helpers in
`tests/f2kboot.py` and `tests/conftest.py`), so an IDE lists and runs
them one by one. The
kernel boots (the fault stubs, the Limine disk path, the program
smokes, the multi-process suite, the interrupt and IDE diagnostics) are
cases in `test_kernel.py`: kernel features to build with, image to
boot, the program's command line, expected COM1 strings, one test per
case. Expected strings match anywhere in the COM1 log by default; a
case can require them in order (`ordered`), as an uninterrupted block of
lines (`contiguous`), or forbid strings (`forbids`). A kernel panic
fails every case. The sectioned fixtures' tests are their real-machine
captures (see `tests/README.md`): one test per captured block, each
fixture's `fixture.toml` stating what its comparison allows and which
blocks are still pending. A fixture's blocks share one boot: the first
of its tests to run boots the kernel once with every block the run
selected, in the capture's order, each block's program its own process
one after another, and each test compares its own block's part of that
boot's COM1 log (`target/qemu/logs/<fixture>.log`). Selecting one block
(`-k crt`) boots that block alone; if the boot stops early, the block
it stopped in fails with the reason and the later ones fail as not run.

Each test builds the kernel and disk for its feature set (once per
run, cached under `target/qemu/builds/`) and keeps its COM1 log under
`target/qemu/logs/` (a fixture's, one per fixture); each run starts by
removing the builds of earlier runs and logs older than two days. Boots
attach the disk as a snapshot, so tests run in parallel (`-n 4` by
default in `make test`, pytest-xdist; `--dist loadgroup`, set in
`pyproject.toml`, keeps a fixture's tests on one worker).
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

`KERNEL_PROFILE` picks the kernel's cargo profile (`make kernel`,
`disk`, `qemu`, `test`...; the suite reads it as `F2K_KERNEL_PROFILE`):
`dev`, the default, or `dev-opt` (Cargo.toml), which builds in its own
directory and optimizes everything under the kernel crate (core, alloc,
compiler_builtins' memcpy and memset) with the debug assertions and
overflow checks kept. The kernel crate itself stays unoptimized there:
an optimized kernel hangs (see the profile's comment).

### Check code
```bash
make check
```

### Formatting
Sources are formatted with rustfmt (settings in `rustfmt.toml`): 100
columns for code and comments, imports grouped (std/core, external,
crate) and sorted. rustfmt splits overlong comment lines and reflows
list items, but never joins short prose lines, so wrap new comments at
100 yourself. Hand-laid tables opt out with `#[rustfmt::skip]`.
```bash
make fmt         # format everything
make fmt-check   # fail if anything is unformatted
```

## Project Structure

```
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
│   └── catalogue_exports.py  # A dumped export table folded into its DLL's spec
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
├── userland/         # The system DLLs (own workspace and target): rtl, ntdll, kernel32, each
│                     # DLL's export spec in userland/<dll>/exports.toml (the DLLs F2K
│                     # does not build yet: their specs alone, catalogued)
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    ├── build.rs          # The NT service table from the export specs; the embedded ntdll
    └── src/
        ├── block/        # Block devices, partitions, and the device registry
        ├── boot/         # Boot-related code
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
        ├── c_lib.rs      # C library stubs (linker support)
        ├── lib.rs        # Kernel library: kmain and all modules (unit-testable)
        └── main.rs       # Kernel binary: links the ELF; panic handler
```

## Targets

| Target | Description |
|--------|-------------|
| `make userland` | Build the system DLLs (`target/userland/`) |
| `make kernel` | Build the kernel (ELF), the system DLLs first |
| `make qemu` | Build the disk and boot the kernel directly in QEMU, the disk attached |
| `make test` | Run every on-target QEMU test (pytest: the kernel boots and the corpus) |
| `make run-tests` | Run host unit tests |
| `make compat` | Check the tests' pins and run the host scenarios |
| `make compat-report` | The DLL compatibility report (`target/compat/report.html`) from the last results |
| `make check-all` | `run-tests`, `compat` and `test`, in that order |
| `make check` | `cargo check` + clippy (the kernel and the userland crates) |
| `make fmt` | Format all Rust sources |
| `make fmt-check` | Fail if any Rust source is unformatted |
| `make limine` | Download Limine bootloader |
| `make iso` | Create bootable ISO with Limine |
| `make qemu_iso` | Build ISO and run in QEMU |
| `make disk` | Create Limine-bootable disk image |
| `make run` | Build disk and run in QEMU |
| `make clean` | Clean build artifacts |
| `make clobber` | Remove all build artifacts |
