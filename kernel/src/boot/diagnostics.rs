//! The diagnostic boots: each runs at its place in the boot sequence when its feature selects it,
//! and is nothing otherwise. The fault tests never return (their faults halt); the smoke runs fall
//! through to the normal boot, proving it coexists with what they exercised.

use super::subsys::Subsystem;

/// The subsystems the build's diagnostic boots need, beside the base profile: a boot that selects
/// its subsystems (`subsys=`) starts these too, so a diagnostic never runs against a subsystem the
/// selection left out (none in a build without a diagnostic feature).
pub const NEEDS: u32 = {
    let mut set = 0;
    // The IDE disk's diagnostic, and the exit during one of its reads.
    if cfg!(any(feature = "disk-smoke", feature = "fault-test-exitio")) {
        set |= Subsystem::Ide.bit();
    }
    // A disk interrupt held behind the keyboard's.
    if cfg!(feature = "nest-smoke") {
        set |= Subsystem::Ide.bit() | Subsystem::Keyboard.bit();
    }
    if cfg!(feature = "kbd-smoke") {
        set |= Subsystem::Keyboard.bit();
    }
    // The callbacks run from winsta's first win32k service.
    if cfg!(feature = "callback-smoke") {
        set |= Subsystem::WinSta.bit() | Subsystem::Fonts.bit();
    }
    set
};

/// The diagnostic boot at the end of the boot's `phase`, once its subsystems are started: the CPU
/// faults' after the processor's, the interrupts' after the interrupts' and the scheduler's, the
/// devices' after the devices'.
#[cfg(target_arch = "x86")]
pub fn after(phase: super::subsys::Phase) {
    use super::subsys::Phase;
    match phase {
        Phase::Processor => cpu_faults(),
        Phase::Interrupts => interrupts(),
        Phase::Devices => devices(),
        Phase::Late => late(),
        Phase::Memory | Phase::Executive => {}
    }
}

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

/// The diagnostic boots once every subsystem is up, before the first process: the nonpaged pool's
/// growth past its old region, with directories made before and after it, then the kernel stack
/// region's.
#[cfg(target_arch = "x86")]
pub fn late() {
    #[cfg(feature = "pool-smoke")]
    {
        crate::mem::pool::smoke();
        crate::mem::kstacks::smoke();
    }
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
