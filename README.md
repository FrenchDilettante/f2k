# F2K - Fenêtre 2000

A Windows 2000-compatible operating system written in Rust.

## Prerequisites

This project uses Nightly Rust via the `rust-toolchain` file. Your default toolchain remains unaffected.

### macOS (ARM64 or x86_64):
```bash
brew install rust FiloSottile/tap/x86_64-elf-binutils nasm xorriso
```

### Linux (x86_64):
```bash
sudo apt install rustc cargo binutils nasm xorriso qemu-system-x86
```

## Building

```bash
# Build kernel only
make kernel

# Build kernel with Limine support
make kernel-limine

# Build bootable ISO with Limine
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
```bash
make kernel
qemu-system-i386 -kernel target/x86-f2k/debug/f2k-kernel -m 256M -nographic -net none
```

### Disk image
```bash
make disk
qemu-system-i386 -m 256M -nographic -hda target/x86-f2k/debug/f2k-disk.img -boot a -net none
```

## Testing

### Unit tests (host)
```bash
cd kernel && cargo test
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
├── x86-f2k-limine.json  # Rust target with Limine support
│
├── boot/             # Bootloader files
│   ├── boot_final.asm    # Boot sector source
│   └── limine/           # Limine bootloader (git submodule)
│
├── scripts/          # Build scripts
│   ├── x86-elf-ld         # Linker wrapper
│   ├── x86-elf-ld-limine  # Linker wrapper for Limine
│   └── linker.x86        # Custom linker script
│
└── kernel/           # F2K Kernel
    ├── Cargo.toml        # Kernel package
    └── src/
        ├── main.rs       # Kernel entry point (_start)
        ├── boot/         # Boot-related code
        │   └── mod.rs    # Limine header
        ├── serial.rs     # Serial port output
        └── c_lib.rs      # C library stubs
```

## Targets

| Target | Description |
|--------|-------------|
| `make kernel` | Build the kernel (ELF) |
| `make kernel-limine` | Build kernel with Limine header |
| `make limine` | Download Limine bootloader |
| `make iso` | Create bootable ISO with Limine |
| `make qemu_iso` | Build ISO and run in QEMU |
| `make disk` | Create bootable disk image |
| `make run` | Build disk and run in QEMU |
| `make run-limine` | Build Limine disk and run |
| `make clean` | Clean build artifacts |
| `make clobber` | Remove all build artifacts |

## License

MIT or Apache-2.0, at your option.
