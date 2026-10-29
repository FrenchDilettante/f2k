//! The diagnostic boots: each runs at its place in the boot sequence when its feature selects it,
//! and is nothing otherwise. The fault tests never return (their faults halt); the smoke runs fall
//! through to the normal boot, proving it coexists with what they exercised.

/// Test-only fault injection, right after the CPU tables: raise an exception to exercise the stubs
/// and the COM1 dump on target. The diagnostics prove the CPU did not write to the GDT and pin the
/// pre-fault ESP.
#[cfg(target_arch = "x86")]
pub fn cpu_faults() {
    #[cfg(any(feature = "fault-test-ud", feature = "fault-test-gp"))]
    {
        use core::arch::asm;

        crate::serial_println!(
            "F2K: GDT after load: {:#018x} {:#018x}",
            crate::cpu::gdt::debug_descriptor(1),
            crate::cpu::gdt::debug_descriptor(2)
        );
        let esp: u32;
        // SAFETY: copying ESP into a register reads no memory and changes no state.
        unsafe { asm!("mov {}, esp", out(reg) esp, options(nomem, nostack)) };
        crate::serial_println!("F2K: ESP before fault: {:#010x}", esp);
    }
    #[cfg(feature = "fault-test-ud")]
    {
        crate::serial_println!("F2K: fault test: forcing #UD (no error code)");
        // SAFETY: a deliberate fault in a test-only build: `ud2` raises #UD, whose handler dumps
        // the frame and halts, so execution never continues past it.
        unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
    }
    #[cfg(feature = "fault-test-gp")]
    {
        // Selector 0x38 lies one past the seven-entry GDT limit (0x37): #GP with the CPU-pushed
        // error code 0x38 — the EXC_STUB_ERR path. Segment registers can only be loaded from a
        // general-purpose register.
        crate::serial_println!("F2K: fault test: forcing #GP (error code path)");
        // SAFETY: a deliberate fault in a test-only build: loading the out-of-limit selector
        // raises #GP before DS changes, and its handler dumps the frame and halts, so execution
        // never continues past it.
        unsafe {
            core::arch::asm!(
                "mov ax, 0x38",
                "mov ds, ax",
                out("ax") _,
                options(nomem, nostack)
            );
        };
    }
}

/// The interrupt/timer diagnostic boot, once the interrupt core and the idle thread are up: report
/// the hardware state, wait for the live tick and the clock's deferred work, and audit the whole
/// subsystem.
#[cfg(target_arch = "x86")]
pub fn interrupts() {
    #[cfg(feature = "irq-smoke")]
    crate::interrupt::smoke();
}

/// The device diagnostic boots, once the boot volume is mounted: the disk's (read the drive's
/// identity, the MBR, the volume boot sector, and the first file's sectors through the
/// interrupt-driven path), then the interrupt nesting's (a disk interrupt held behind the
/// keyboard's, both let in at once).
#[cfg(target_arch = "x86")]
pub fn devices() {
    #[cfg(feature = "disk-smoke")]
    crate::hw::ide::smoke::run();

    #[cfg(feature = "nest-smoke")]
    crate::interrupt::nest_smoke();
}
