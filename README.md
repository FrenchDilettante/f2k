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
brew install rustup x86_64-elf-binutils xorriso mtools qemu
rustup-init
# PyYAML for the on-target suite, in a repository-local venv (`make test`
# uses .venv/bin/python when it exists)
python3 -m venv .venv && .venv/bin/pip install pyyaml
```

### Linux (x86_64):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install binutils xorriso mtools qemu-system-x86 python3-yaml
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
The kernel is a Multiboot 1 ELF, so QEMU can load it without a bootloader:
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

### On-target QEMU suite
The cases (kernel features to build with, image to boot, expected
COM1 strings) are data in `scripts/qemu-tests.yaml`;
`scripts/run-qemu-tests.py` builds and runs them. Adding a case does
not add a Makefile target. Expected strings match anywhere in the
COM1 log by default; a case can require them in order (`ordered`),
as an uninterrupted block of lines (`contiguous`), or forbid strings
(`forbids`). A kernel panic fails every case.
```bash
make test        # all kernel-path cases (QEMU -kernel)
make test-disk   # all disk-path cases (Limine disk image)
.venv/bin/python scripts/run-qemu-tests.py scripts/qemu-tests.yaml --list   # list cases
.venv/bin/python scripts/run-qemu-tests.py scripts/qemu-tests.yaml --only fault-ud
```

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
│   ├── test-boot.sh       # Boot one image in QEMU and assert COM1 strings
│   ├── run-qemu-tests.py  # On-target suite runner: builds and boots per case
│   └── qemu-tests.yaml    # On-target test cases (data, not Makefile targets)
│
├── tests/            # Windows 2000 test corpus (see tests/README.md)
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
| `make qemu` | Build the kernel and boot it directly in QEMU |
| `make test` | Run the on-target QEMU suite (kernel path) |
| `make test-disk` | Run the on-target QEMU suite (Limine disk path) |
| `make run-tests` | Run host unit tests |
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
