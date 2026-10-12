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

### Boot smoke test
Boots the kernel in QEMU and checks for the boot banner on COM1:
```bash
make test        # Kernel loaded directly by QEMU
make test-disk   # Disk image booted through Limine
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
├── scripts/          # Build scripts
│   ├── x86-elf-ld         # Linker wrapper
│   ├── linker.x86         # Custom linker script
│   └── test-boot.sh       # Boot smoke test
│
├── tests/            # Windows 2000 test corpus (see tests/README.md)
│   ├── README.md         # Test conventions and inventory
│   ├── exit0/
│   │   └── exit0.c       # Baseline: no CRT, entry calls ExitProcess(0)
│   └── ret0/             # Baseline: CRT startup, main returns 0
│       ├── ret0.c
│       └── ret0.exe       # Fixture compiled on a real Windows 2000 machine
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    └── src/
        ├── main.rs       # Kernel binary: links the ELF; panic handler
        ├── lib.rs        # Kernel library: kmain and all modules (unit-testable)
        ├── boot/         # Boot-related code
        │   └── mod.rs    # Multiboot header and _start stub
        ├── gdt.rs        # GDT: flat 32-bit kernel segments
        ├── idt.rs        # IDT: CPU exception handlers with register dump on COM1
        ├── mem/          # Memory management
        │   ├── mod.rs        # Module root
        │   ├── frame.rs      # Physical frame allocator: state-keyed FIFO lists, per-color chains
        │   ├── multiboot.rs  # Multiboot 1 memory map parsing (host-testable)
        │   ├── paging.rs     # Boot page tables: kernel window at 0x80000000+, temporary low identity
        │   ├── heap.rs       # Kernel heap: fixed-pool free-list allocator (host-testable)
        │   └── bootmem.rs    # Boot-time initialization: frame database and heap from the memory map
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
