# Bootloader and QEMU Issues Documentation

## Overview

This document summarizes the issues encountered while attempting to boot the F2K kernel using various methods: custom boot sector, QEMU direct loading, and Limine bootloader.

---

## 1. QEMU Direct Kernel Loading

### Issue: QEMU 11.x on macOS with Raw Disk Images

**Problem:** QEMU 11.x on macOS has issues booting raw disk images via SeaBIOS.

**Symptoms:**
- SeaBIOS loads but fails to boot from the disk
- Error: "Boot failed: could not read the boot disk"
- Works with VirtualBox but not QEMU

**Root Cause:** File locking restrictions in QEMU 11.x when using raw disk images.

**Workarounds Attempted:**
1. Using `-drive file=...,format=raw,if=floppy,file.locking=off`
2. Using older QEMU versions (< 8.0)
3. Using VirtualBox instead

**Current Status:** Not resolved for QEMU 11.x with raw disk images. VirtualBox works.

---

## 2. Custom Boot Sector

### Issue: Entry Point Address Mismatch

**Problem:** The custom boot sector loads the kernel at address 0x7E00 (right after the boot sector at 0x7C00), but this creates constraints for modern bootloaders like Limine.

**Symptoms:**
- Kernel builds successfully with entry point at 0x7E00
- Boot sector correctly loads kernel and jumps to 0x7E00
- Works in some environments but incompatible with Limine's expectations

**Root Cause:** Legacy design decision for traditional BIOS boot.

**Solution:** Changed kernel entry point to 0x100000 (1MB) which is:
- Standard for 32-bit protected mode kernels
- Compatible with Limine boot protocol
- Avoids low memory (first 640KB)

**Status:** Resolved by updating linker script to place kernel at 0x100000

### Issue: Memory Layout Gaps

**Problem:** With Limine header at address 0x100000 and kernel code at 0x7E00, there were gaps in memory layout.

**Solution:** Updated linker script to place .text section immediately after .limine_requests.

**Current Linker Layout:**
- 0x100000: .limine_requests (136 bytes)
- 0x100088: .text (kernel code)

**Status:** Resolved

---

## 3. Limine Bootloader

### Issue: "Default entry is not valid, booting to menu"

**Problem:** Limine loads from ISO but displays error instead of booting kernel.

**Root Cause:** Incorrect configuration file format.

**Incorrect format:**
```
:F2K
    PROTOCOL=limine
    KERNEL_PATH=/f2k-kernel
```

**Correct format (Limine uses key: value syntax):**
```
/F2K - Fenêtre 2000
    protocol: limine
    path: /f2k-kernel
    drive: 0x80
    stack_size: 16384
```

**Status:** Resolved

### Issue: Limine Header Not Found

**Problem:** Limine was not finding the boot protocol header.

**Solution:** 
- Added .limine_requests section via Rust static variable
- Made section writable using `static mut`
- Embedded pre-compiled limine_header.bin

**Status:** Resolved

### Issue: ISO Boot Configuration

**Problem:** Limine requires specific files in specific locations.

**Current ISO Structure:**
```
/root
├── limine-bios-cd.bin    (El Torito boot image)
├── limine-bios.sys       (required)
├── limine.cfg            (configuration)
├── limine.conf           (alternative config)
└── f2k-kernel            (ELF kernel)
```

**Status:** Resolved

### Issue: Kernel Not Executing

**Problem:** After fixing config and Limine header, kernel still doesn't produce output.

**Symptoms:**
- Limine loads successfully (no "Default entry" error)
- SeaBIOS shows "Booting from DVD/CD..."
- No serial output from kernel

**Possible Causes:**
1. Serial port initialization failing
2. Entry point not being jumped to by Limine
3. CPU in wrong mode
4. Kernel crashing before serial output

**Current Status:** Partially resolved - Limine loads but kernel execution unclear.

---

## 4. Cross-Compilation Toolchain

### Issue: Rust Target Specification

**Problem:** Custom targets need to be accessible to Rust.

**Solution:** Created target JSON files and copied to rustup toolchain directory.

**Note:** Custom targets require `-Zunstable-options` flag.

**Status:** Resolved

---

## Summary

### Resolved:
- Entry point changed from 0x7E00 to 0x100000
- Limine header embedded in kernel
- Configuration file syntax corrected
- ISO structure with all required files
- Cross-compilation toolchain setup

### Partially Resolved:
- Kernel not producing serial output in QEMU/ISO

### Unresolved:
- QEMU 11.x raw disk image boot issues

### Next Steps:
1. Verify kernel execution by Limine
2. Debug serial port output
3. Test with different QEMU versions
