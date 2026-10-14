# F2K - Fenêtre 2000

A Windows 2000-compatible operating system written in Rust.

## Prerequisites

This project uses Nightly Rust via the `rust-toolchain` file. Your default toolchain remains unaffected.

### macOS (ARM64 or x86_64):
```bash
brew install rust FiloSottile/tap/x86_64-elf-binutils nasm xorriso mtools
```

### Linux (x86_64):
```bash
sudo apt install rustc cargo binutils nasm xorriso mtools qemu-system-x86
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
not add a Makefile target.
```bash
make test        # all kernel-path cases (QEMU -kernel)
make test-disk   # all disk-path cases (Limine disk image)
scripts/run-qemu-tests.py scripts/qemu-tests.yaml --list   # list cases
scripts/run-qemu-tests.py scripts/qemu-tests.yaml --only fault-ud
```

### Check code
```bash
make check
```

## Project Structure

```
f2k/
├── rust-toolchain    # Nightly Rust for this project
├── Cargo.toml        # Workspace manifest
├── Makefile          # Build system
├── x86-f2k.json      # Rust target: 32-bit x86 bare metal
│
├── boot/             # Bootloader files
│   ├── boot_final.asm    # Custom boot sector source (unused)
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
│   ├── README.md         # Test conventions and one-line summaries
│   ├── build.bat         # Rebuilds every fixture on the Windows 2000 machine
│   ├── exit0/
│   │   ├── exit0.c       # Baseline: no CRT, entry calls ExitProcess(0)
│   │   ├── exit0.exe      # Fixture compiled on a real Windows 2000 machine
│   │   └── imports.txt    # Verified import surface of the fixture
│   ├── ret0/             # Baseline: CRT startup, main returns 0
│   │   ├── ret0.c
│   │   ├── ret0.exe       # Fixture compiled on a real Windows 2000 machine
│   │   └── imports.txt    # Verified import surface of the fixture
│   ├── hello/
│   │   ├── hello.c        # Console rung: CRT + printf "Hello, world!"
│   │   ├── hello.exe      # Fixture compiled on a real Windows 2000 machine
│   │   └── imports.txt    # Verified import surface of the fixture
│   └── hellogui/
│       ├── hellogui.c     # GUI rung: window + TextOut, self-terminating
│       ├── hellogui.exe   # Fixture compiled on a real Windows 2000 machine
│       └── imports.txt    # Verified import surface of the fixture
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    └── src/
        ├── main.rs       # Kernel binary: links the ELF; panic handler
        ├── lib.rs        # Kernel library: kmain and all modules (unit-testable)
        ├── boot/         # Boot-related code
        │   └── mod.rs    # Multiboot header and _start stub
        ├── gdt.rs        # GDT: flat kernel + user segments, TEB segment, TSS (ring-0 stack for gate entries)
        ├── idt.rs        # IDT: CPU exception dump on COM1; registers the syscall gate; faults classified by origin
        ├── mem/          # Memory management
        │   ├── mod.rs        # Module root
        │   ├── frame.rs      # Physical frame allocator: state-keyed FIFO lists, per-color chains
        │   ├── multiboot.rs  # Multiboot 1 memory map parsing (host-testable)
        │   ├── paging.rs     # Boot page tables; runtime table access (self-map, scratch); per-process directories and user/kernel page mapping
        │   ├── heap.rs       # Kernel heap: fixed-pool free-list allocator (host-testable)
        │   └── bootmem.rs    # Boot-time initialization: frame database and heap from the memory map
        ├── syscall.rs    # Syscall gate (int 0x2E, DPL 3): service dispatch, argument probe/copy, user-memory transfers
        ├── pe.rs         # PE32 image parsing, mapping plan and IAT snap (host-testable)
        ├── loader.rs     # Kernel-side image loader: staging, section mapping, entry into ring 3
        ├── kernel32.rs   # Kernel-synthesized kernel32: 40-export service registry, thunk stubs, replayed startup values, console output
        ├── cp1252.rs     # Codepage 1252 replay data: MB/WC tables, ctype flags, case mapping (host-testable)
        ├── userheap.rs   # User-mode heap: first-fit allocator with coalescing; the CRT's VirtualAlloc region
        ├── user.rs       # Ring 3: iret entry (TEB segment in FS), trap frame shape, fault-test stubs, process end
        ├── process.rs    # The process object: per-process directory, ring-0 gate stack, user-heap state; the teardown walk
        ├── runner.rs     # Sequential multi-process suite runner (run-process-suite feature): context switch, audits, summary
        ├── serial.rs     # Serial port output
        └── c_lib.rs      # C library stubs
```

## Targets

| Target | Description |
|--------|-------------|
| `make kernel` | Build the kernel (ELF) |
| `make qemu` | Build the kernel and boot it directly in QEMU |
| `make test` | Run the boot smoke test |
| `make test-disk` | Run the boot smoke test on the disk image |
| `make run-tests` | Run host unit tests |
| `make test-fault` | On-target exception dump tests (#UD and #GP) |
| `make limine` | Download Limine bootloader |
| `make iso` | Create bootable ISO with Limine |
| `make qemu_iso` | Build ISO and run in QEMU |
| `make disk` | Create Limine-bootable disk image |
| `make run` | Build disk and run in QEMU |
| `make clean` | Clean build artifacts |
| `make clobber` | Remove all build artifacts |
