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

```bash
# Build kernel only
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

### The kernel32 contract harness
The compatibility surface's behavior is pinned host-side by the
contract harness (`kernel/src/compat/harness/`, all `#[cfg(test)]`):
each export's scenarios live under its API group, disabled by
default (`#[ignore]`) and switched on as implementations migrate.
The ledger (`scripts/kernel32-ledger.yaml`) maps every export to
its group, contract status, and scenarios; the report script prints
the per-group progress (`--check` verifies the ledger against the
scenario sources, `--run` fills the passing column).
```bash
uv run --with pyyaml scripts/kernel32-ledger.py --check
```

### Everything
`make check-all` runs the test systems in turn, fastest first,
stopping at the first failure: the host unit tests (`make run-tests`)
and the on-target suite (`make test`; `PYTEST_FLAGS` passes through).
```bash
make check-all PYTEST_FLAGS="-n 2"
```

### On-target QEMU tests
The on-target tests run through pytest (each sectioned fixture's
`tests/<name>/test_<name>.py`, the kernel's own boots in
`tests/kernel/test_kernel.py`, helpers in `tests/f2kboot.py` and
`tests/conftest.py`), so an IDE lists and runs them one by one. The
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
blocks are still pending.

Each test builds the kernel and disk for its feature set (once per
run, cached under `target/qemu/builds/`) and keeps its COM1 log under
`target/qemu/logs/`; each run starts by removing the builds of earlier
runs and logs older than two days. Boots attach the disk as a snapshot,
so tests run in parallel (`-n 4` by default in `make test`,
pytest-xdist).
```bash
make test        # every on-target test: the kernel boots and the corpus
uv run pytest --collect-only -q                     # list every test
uv run pytest tests/kernel -k fault-ud              # one kernel case
uv run pytest tests/bare -n 4                       # one fixture's blocks
uv run pytest tests/runtime --runxfail              # see why the work list fails
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
│   ├── gen-files-data.py  # The files fixture's data tree (tests/files/DATA)
│   ├── kernel32-ledger.py   # kernel32 contract ledger report (host-side)
│   └── kernel32-ledger.yaml  # The contract ledger (data, not Makefile targets)
│
├── pyproject.toml    # The Python tooling (uv): pytest for the on-target tests
├── tests/            # Windows 2000 test corpus and the pytest suite (see tests/README.md)
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    └── src/
        ├── boot/         # Boot-related code
        ├── compat/       # The Windows compatibility layer
        ├── cpu/          # The CPU tables
        ├── exec/         # Executable loading
        ├── hw/           # The hardware layer: devices the kernel drives directly
        ├── interrupt/    # The interrupt core (hardware-neutral, host-testable)
        ├── mem/          # Memory management
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
| `make kernel` | Build the kernel (ELF) |
| `make qemu` | Build the disk and boot the kernel directly in QEMU, the disk attached |
| `make test` | Run every on-target QEMU test (pytest: the kernel boots and the corpus) |
| `make run-tests` | Run host unit tests |
| `make check-all` | `run-tests`, then `test` |
| `make check` | `cargo check` + clippy |
| `make fmt` | Format all Rust sources |
| `make fmt-check` | Fail if any Rust source is unformatted |
| `make limine` | Download Limine bootloader |
| `make iso` | Create bootable ISO with Limine |
| `make qemu_iso` | Build ISO and run in QEMU |
| `make disk` | Create Limine-bootable disk image |
| `make run` | Build disk and run in QEMU |
| `make clean` | Clean build artifacts |
| `make clobber` | Remove all build artifacts |
