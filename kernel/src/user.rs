//! Ring 3: entering user mode and the end of the user process.
//!
//! M2 proved the privilege switch end to end ([`enter_ring3`]); M3
//! wired the return path through the syscall gate (see `syscall.rs`);
//! M4 made the default user process a real PE image (see `loader.rs`):
//! the kernel maps the image and a stack, enters ring 3 with an iret,
//! and the image ends the process through the exit service.
//!
//! The fault-test features substitute a hand-assembled stub for the
//! image (see [`RING3_STUB`]), so the user-fault paths can be verified
//! on target without a PE fixture in the loop.
//!
//! Single tasking, run to completion: the kernel "calls" the user
//! process, the exit syscall is the return path, and faults raised by
//! user code end the process rather than the kernel (see `idt.rs`).

#[cfg(target_arch = "x86")]
use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// The fault-test stub's code page (the PE image base, which the
/// fault-test builds never map).
#[cfg(any(feature = "fault-test-user", feature = "fault-test-badargs", test))]
pub const USER_CODE_PAGE: u32 = 0x0040_0000;
/// The user stack page, in its own 4 MiB window — window 0, which
/// held the boot identity mapping until it was removed. Shared by
/// the PE image runs and the fault-test stubs.
pub const USER_STACK_PAGE: u32 = 0x0030_0000;
/// Initial user ESP: one past the stack page's top byte.
pub const USER_STACK_TOP: u32 = USER_STACK_PAGE + 4096;

/// A kernel address the fault-test stub reads from ring 3: the kernel
/// window is supervisor-only, so the read must fault.
#[cfg(any(feature = "fault-test-user", test))]
pub const KERNEL_WINDOW_PROBE: u32 = 0x8010_1000;

/// An unmapped user address the bad-args stub passes as the syscall
/// argument pointer: below the user probe limit (the range probe
/// passes) but backed by no page, so the kernel's argument copy
/// faults on the user process's behalf.
#[cfg(any(feature = "fault-test-badargs", test))]
pub const BAD_ARGS_PTR: u32 = 0x0050_0000;

/// The ring-3 fault-test stub, in bytes: a body that must end the
/// process through a fault (see the variants below) followed by a
/// spin as the safety net.
///
/// Assembled by hand so it can live in a kernel constant and be copied
/// into the user page: kernel code itself is unreachable from ring 3,
/// because the kernel window is supervisor-only. Never combine the
/// features.
///
/// `fault-test-user` reads the supervisor-only kernel window, and
/// `fault-test-badargs` passes an unmapped user address as the syscall
/// argument pointer — both must end the process, not the kernel
/// (`make test-fault-*`).
#[cfg(feature = "fault-test-user")]
pub const RING3_STUB: [u8; 7] = [
    0xA1, 0x00, 0x10, 0x10, 0x80, // mov eax, dword ptr [KERNEL_WINDOW_PROBE]
    0xEB, 0xFE, // jmp $ (the read must fault before this)
];

#[cfg(all(feature = "fault-test-badargs", not(feature = "fault-test-user")))]
pub const RING3_STUB: [u8; 14] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_EXIT (service 1)
    0xBA, 0x00, 0x00, 0x50, 0x00, // mov edx, BAD_ARGS_PTR
    0xCD, 0x2E, // int 0x2E (syscall gate)
    0xEB, 0xFE, // jmp $
];

/// Trap frame the gate stubs build on the ring-0 stack.
///
/// The CPU pushes the tail (raised from ring 3: EIP, CS, EFLAGS, user
/// ESP, user SS, onto the TSS stack); the stub pushes the rest in the
/// same order as the exception stubs, so every frame in this kernel —
/// exception or syscall — shares one shape.
#[allow(dead_code)]
#[repr(C)]
pub struct TrapFrame {
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub vector: u32,
    pub error_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    /// Present only because the gate was raised from ring 3.
    pub user_esp: u32,
    pub user_ss: u32,
}

// Entry into ring 3: load the user data segments, build the iret
// frame and switch. Never returns.
//
// The pushed EFLAGS is a fixed value: bit 1 (reserved, always 1) only.
// Interrupts stay disabled — the kernel runs its single user process
// with `cli` set — and IOPL is 0, so port I/O stays privileged.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    pub fn enter_ring3(eip: u32, esp: u32) -> !;
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.enter_ring3, \"ax\"",
    ".global enter_ring3",
    "enter_ring3:",
    // Arguments: [esp+4] = user EIP, [esp+8] = user ESP. Load the
    // user data segments for DS/ES/FS/GS; SS comes from the iret frame.
    "    mov ax, {user_data}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov edx, [esp + 4]",
    "    mov ecx, [esp + 8]",
    // iret frame: SS:ESP, EFLAGS, CS with RPL 3, EIP. The 32-bit form
    // is spelled `iretd`: under the toolchain's integrated assembler
    // for 32-bit x86 the bare `iret` assembles as the 16-bit form.
    "    push {user_data}",
    "    push ecx",
    "    push {user_eflags}",
    "    push {user_code}",
    "    push edx",
    // iret loads only EIP, CS, EFLAGS, ESP and SS: every other
    // register passes through to user code. Zero the general-purpose
    // registers so kernel pointers (multiboot state, serial buffers)
    // do not leak into user mode. Once real PE images run, the initial
    // register state must match the reference OS instead.
    "    xor eax, eax",
    "    xor ebx, ebx",
    "    xor ecx, ecx",
    "    xor edx, edx",
    "    xor esi, esi",
    "    xor edi, edi",
    "    xor ebp, ebp",
    "    iretd",
    user_data = const USER_DATA_SELECTOR | 3,
    user_code = const USER_CODE_SELECTOR | 3,
    user_eflags = const 0x0000_0002u32,
);

/// End of the user process: the exit service's landing point.
///
/// Single tasking, run to completion: there is no next process, so the
/// kernel's process-end policy is to report and halt. The exit code is
/// the process's only observable (the current fixtures have no console
/// backend), so the report is the smoke's completion line. A real
/// process object moves this to the future process module.
pub fn process_exited(code: u32) -> ! {
    #[cfg(target_arch = "x86")]
    {
        crate::serial_println!("F2K: user process exited normally (exit code={})", code);
        crate::halt()
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds compile the dispatch tables but never run them:
        // there is no serial port and no process to end.
        let _ = code;
        unimplemented!("process exit is a kernel-runtime operation")
    }
}

/// Launch the first user process. The default path loads the first
/// corpus fixture through the PE loader ([`crate::loader`]); the
/// fault-test features substitute their stub for the image (never
/// combine them). Never returns.
#[cfg(target_arch = "x86")]
pub fn run_user_process() -> ! {
    #[cfg(not(any(feature = "fault-test-user", feature = "fault-test-badargs")))]
    {
        crate::loader::run_image(crate::loader::EXIT0)
    }
    #[cfg(any(feature = "fault-test-user", feature = "fault-test-badargs"))]
    {
        run_fault_stub()
    }
}

/// Map the fault-test stub's user pages and enter ring 3.
///
/// The code page is written through the scratch alias before it is
/// mapped read-only; the stack page is zeroed and writable. Both are
/// user-accessible; each allocation takes one frame, and the two
/// pages sit in different 4 MiB windows, so two page tables are
/// created on demand. Never returns.
#[cfg(target_arch = "x86")]
#[cfg(any(feature = "fault-test-user", feature = "fault-test-badargs"))]
pub fn run_fault_stub() -> ! {
    use crate::mem::paging;

    let code_frame = paging::allocate_frame_phys();
    paging::init_frame(code_frame, 0, &RING3_STUB);
    paging::map_user_page(USER_CODE_PAGE, code_frame, false);

    let stack_frame = paging::allocate_frame_phys();
    paging::init_frame(stack_frame, 0, &[]);
    paging::map_user_page(USER_STACK_PAGE, stack_frame, true);

    crate::serial_println!(
        "F2K: entering ring 3 (code {:#010x}, stack {:#010x})",
        USER_CODE_PAGE,
        USER_STACK_TOP
    );
    // SAFETY: the code page is mapped readable (user), the stack page
    // writable (user), the TSS carries the ring-0 stack, and the
    // syscall gate is installed at DPL 3.
    unsafe { enter_ring3(USER_CODE_PAGE, USER_STACK_TOP) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use crate::syscall::SYSCALL_VECTOR;
    use core::mem::size_of;
    use core::ptr::addr_of;

    /// The fault-test stub reads the supervisor-only kernel window and
    /// spins: A1+moffs32 (mov eax, [moffs]) then jmp $.
    #[cfg(feature = "fault-test-user")]
    #[test]
    fn fault_stub_bytes_match_their_encoding() {
        let mut expected = [0u8; 7];
        expected[0] = 0xA1;
        expected[1..5].copy_from_slice(&KERNEL_WINDOW_PROBE.to_le_bytes());
        expected[5] = 0xEB;
        expected[6] = 0xFE;
        assert_eq!(RING3_STUB, expected);
    }

    /// The bad-args stub requests the exit service with an unmapped
    /// argument pointer: BA+imm32 (mov edx, imm32), int, jmp $.
    #[cfg(all(feature = "fault-test-badargs", not(feature = "fault-test-user")))]
    #[test]
    fn badargs_stub_bytes_match_their_encoding() {
        let mut expected = [0u8; 14];
        expected[0] = 0xB8;
        expected[1..5].copy_from_slice(&crate::syscall::SYS_EXIT.to_le_bytes());
        expected[5] = 0xBA;
        expected[6..10].copy_from_slice(&BAD_ARGS_PTR.to_le_bytes());
        expected[10] = 0xCD;
        expected[11] = SYSCALL_VECTOR as u8;
        expected[12] = 0xEB;
        expected[13] = 0xFE;
        assert_eq!(RING3_STUB, expected);
    }

    /// The fault-test addresses: the kernel-window probe lies inside
    /// the kernel window (supervisor-only), the bad-args pointer below
    /// the user probe limit (so the range probe passes) but away from
    /// the two mapped smoke pages.
    #[test]
    fn fault_probe_layout_is_consistent() {
        assert!(KERNEL_WINDOW_PROBE >= KERNEL_BASE);
        assert!(BAD_ARGS_PTR < KERNEL_BASE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_CODE_PAGE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_STACK_PAGE);
    }

    /// The trap frame is 15 u32s; the CPU-pushed tail keeps the iret
    /// order (EIP, CS, EFLAGS, then the ring-3 ESP/SS pair), following
    /// the exception-stub prefix.
    #[test]
    fn trap_frame_layout() {
        assert_eq!(size_of::<TrapFrame>(), 15 * 4);
        let frame = TrapFrame {
            edi: 0, esi: 0, ebp: 0, esp: 0, ebx: 0, edx: 0, ecx: 0, eax: 0,
            vector: 0, error_code: 0, eip: 0, cs: 0, eflags: 0,
            user_esp: 0, user_ss: 0,
        };
        let base = addr_of!(frame) as usize;
        assert_eq!(addr_of!(frame.eax) as usize - base, 7 * 4);
        assert_eq!(addr_of!(frame.vector) as usize - base, 8 * 4);
        assert_eq!(addr_of!(frame.error_code) as usize - base, 9 * 4);
        assert_eq!(addr_of!(frame.eip) as usize - base, 10 * 4);
        assert_eq!(addr_of!(frame.cs) as usize - base, 11 * 4);
        assert_eq!(addr_of!(frame.eflags) as usize - base, 12 * 4);
        assert_eq!(addr_of!(frame.user_esp) as usize - base, 13 * 4);
        assert_eq!(addr_of!(frame.user_ss) as usize - base, 14 * 4);
    }

    /// The user layout: both fault-test pages below the kernel
    /// window, page-aligned, in different 4 MiB windows; the stack
    /// top one past the stack page.
    #[test]
    fn user_layout_is_consistent() {
        for page in [USER_CODE_PAGE, USER_STACK_PAGE] {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
        assert_ne!(USER_CODE_PAGE >> 22, USER_STACK_PAGE >> 22);
        assert_eq!(USER_STACK_TOP, USER_STACK_PAGE + 4096);
    }
}
