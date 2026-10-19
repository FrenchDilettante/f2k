//! The floating-point unit's setup at boot: `fxsave`/`fxrstor` and the SSE state enabled.
//!
//! User code is compiled for SSE2 (the system DLLs among it), so the context switch saves each
//! thread's whole floating-point state with `fxsave`, which needs CR4.OSFXSR; CR4.OSXMMEXCPT makes
//! an unmasked SIMD floating-point exception raise #XM (STATUS_FLOAT_MULTIPLE_TRAPS) rather than
//! #UD. A processor without FXSR cannot hold a thread's SSE state at all: the kernel refuses to
//! boot on one rather than switch threads with part of their state lost. The boot context then
//! starts from a fresh thread's image (`sched::thread::FpuState::initial`).

/// CPUID leaf 1's EDX feature bits the setup reads: FXSAVE/FXRSTOR, and SSE.
pub const CPUID_FXSR: u32 = 1 << 24;
pub const CPUID_SSE: u32 = 1 << 25;

/// CR0's floating-point bits: monitor coprocessor (`wait` honours TS), emulation (every FPU
/// instruction faults), and native error reporting (#MF rather than the external IRQ 13).
pub const CR0_MP: u32 = 1 << 1;
pub const CR0_EM: u32 = 1 << 2;
pub const CR0_NE: u32 = 1 << 5;

/// CR4's bits: the OS saves the state with `fxsave` (SSE instructions enabled), and handles #XM.
pub const CR4_OSFXSR: u32 = 1 << 9;
pub const CR4_OSXMMEXCPT: u32 = 1 << 10;

/// The control registers' values for a processor whose CPUID leaf 1 reports `features` in EDX,
/// from their current values: `None` when it has no FXSR (the kernel cannot boot on it).
pub fn control_registers(features: u32, cr0: u32, cr4: u32) -> Option<(u32, u32)> {
    if features & CPUID_FXSR == 0 {
        return None;
    }
    let cr0 = (cr0 & !CR0_EM) | CR0_MP | CR0_NE;
    let mut cr4 = cr4 | CR4_OSFXSR;
    if features & CPUID_SSE != 0 {
        cr4 |= CR4_OSXMMEXCPT;
    }
    Some((cr0, cr4))
}

/// Enable `fxsave`/`fxrstor` and the SSE state, and load a fresh thread's image: once, on the boot
/// CPU, before the first context switch. Halts, after the report, on a processor without FXSR.
///
/// # Safety
///
/// Ring 0, boot, before any thread's floating-point state is saved or restored.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    use core::arch::asm;

    // CPUID leaf 1 (every processor the kernel runs on has CPUID). EBX is reserved by LLVM, so the
    // instruction runs between a save and a restore of it.
    let features: u32;
    // SAFETY: CPUID reads identification only.
    unsafe {
        asm!("push ebx", "cpuid", "pop ebx", inout("eax") 1u32 => _, out("ecx") _,
             out("edx") features, options(preserves_flags));
    }
    let (cr0, cr4): (u32, u32);
    // SAFETY: reading the control registers at ring 0.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    let Some((cr0, cr4)) = control_registers(features, cr0, cr4) else {
        crate::serial_println!(
            "F2K: the processor has no FXSAVE/FXRSTOR (CPUID.1:EDX {:#010x}): a thread's SSE state \
             cannot be saved, not booting",
            features
        );
        crate::halt()
    };
    /// A fresh thread's image, as the boot context's first state.
    static INITIAL: crate::sched::thread::FpuState = crate::sched::thread::FpuState::initial();
    // SAFETY: the caller's contract; the image is 16-byte aligned (its type's alignment).
    unsafe {
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        asm!("fninit", "fxrstor [{}]", in(reg) core::ptr::addr_of!(INITIAL),
             options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With FXSR and SSE: OSFXSR and OSXMMEXCPT set, emulation off, MP and NE on, every other bit
    /// as it was.
    #[test]
    fn fxsr_and_sse_enable_both_cr4_bits() {
        let cr0 = 0x8001_0011 | CR0_EM;
        let (new_cr0, new_cr4) = control_registers(CPUID_FXSR | CPUID_SSE, cr0, 0x10).unwrap();
        assert_eq!(new_cr0, 0x8001_0011 | CR0_MP | CR0_NE);
        assert_eq!(new_cr4, 0x10 | CR4_OSFXSR | CR4_OSXMMEXCPT);
        assert_eq!((CR4_OSFXSR, CR4_OSXMMEXCPT), (0x200, 0x400));
    }

    /// FXSR without SSE: `fxsave` serves the x87 state, and no #XM can arise.
    #[test]
    fn fxsr_alone_enables_fxsave_only() {
        let (_, cr4) = control_registers(CPUID_FXSR, 0x11, 0).unwrap();
        assert_eq!(cr4, CR4_OSFXSR);
    }

    /// No FXSR: the kernel does not boot, whatever else the processor has.
    #[test]
    fn no_fxsr_refuses() {
        assert_eq!(control_registers(CPUID_SSE, 0x11, 0), None);
        assert_eq!(control_registers(0, 0x11, 0), None);
    }
}
