//! Ring 3: entering user mode and the M2 round-trip smoke.
//!
//! M2 proves the privilege switch end to end: the kernel maps two user
//! pages (a code page carrying a hand-assembled stub, a stack page),
//! enters ring 3 with an iret, the stub writes a marker into user
//! memory and raises the temporary round-trip gate, and the kernel
//! confirms the marker on COM1. The gate is deliberately simple: M3
//! replaces it with the syscall gate at vector 0x2E, keeping the trap
//! frame shape defined here.

#[cfg(target_arch = "x86")]
use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// Temporary round-trip gate vector (M2 only); the M3 syscall gate
/// replaces it at 0x2E.
pub const RING3_GATE_VECTOR: usize = 0x60;

/// The smoke's user code page (the future PE image base).
pub const USER_CODE_PAGE: u32 = 0x0040_0000;
/// The smoke's user stack page, in its own 4 MiB window — window 0,
/// which held the boot identity mapping until it was removed.
pub const USER_STACK_PAGE: u32 = 0x0030_0000;
/// Initial user ESP: one past the stack page's top byte.
pub const USER_STACK_TOP: u32 = USER_STACK_PAGE + 4096;
/// Where the ring-3 stub writes its marker: inside the stack page,
/// below the initial ESP.
pub const MARKER_VA: u32 = USER_STACK_PAGE + 4096 - 16;

/// Marker value the ring-3 stub writes ("R3OK").
pub const RING3_MARKER: u32 = 0x4B4F_3352;

/// The ring-3 stub, in bytes:
/// 1. load the marker,
/// 2. store it into user memory,
/// 3. raise the round-trip gate,
/// 4. spin (the gate ends the process; this is the safety net).
///
/// Assembled by hand so it can live in a kernel constant and be copied
/// into the user page: kernel code itself is unreachable from ring 3,
/// because the kernel window is supervisor-only.
pub const RING3_STUB: [u8; 14] = [
    0xB8, 0x52, 0x33, 0x4F, 0x4B, // mov eax, RING3_MARKER
    0xA3, 0xF0, 0x0F, 0x30, 0x00, // mov dword ptr [MARKER_VA], eax
    0xCD, 0x60, // int RING3_GATE_VECTOR
    0xEB, 0xFE, // jmp $
];

/// Trap frame the round-trip gate stub builds on the ring-0 stack.
///
/// The CPU pushes the tail (raised from ring 3: EIP, CS, EFLAGS,
/// user ESP, user SS, onto the TSS stack); the stub pushes the rest in
/// the same order as the exception stubs, so the frame prefix layout
/// is shared and the M3 syscall gate keeps this shape.
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
    /// Present only because this gate is raised from ring 3.
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
    fn enter_ring3(eip: u32, esp: u32) -> !;
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
    "    iretd",
    user_data = const USER_DATA_SELECTOR | 3,
    user_code = const USER_CODE_SELECTOR | 3,
    user_eflags = const 0x0000_0002u32,
);

// Stub for the round-trip gate (vector 0x60, DPL 3).
//
// Entered from ring 3: the CPU has already switched to the TSS ring-0
// stack and pushed EIP, CS, EFLAGS, user ESP, user SS. The stub saves
// the rest in the exception-stub push order and calls the handler.
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.ring3_gate_stub, \"ax\"",
    ".global ring3_gate_stub",
    "ring3_gate_stub:",
    "    push 0", // error-code slot (no CPU error code for this gate)
    "    push {vector}",
    "    pushad",
    "    cld",
    "    push esp", // frame pointer: ring3_gate_handler(frame)
    "    call {handler}",
    "1:  cli",
    "    hlt",
    "    jmp 1b",
    vector = const RING3_GATE_VECTOR as u32,
    handler = sym ring3_gate_handler,
);

/// Round-trip gate handler: confirm the ring-3 stub ran and wrote its
/// marker, report on COM1, and end the smoke.
///
/// Single tasking, run to completion: the kernel "called" the user
/// code and this gate is the return path, so halting here is the
/// intended end of the M2 smoke.
#[cfg(target_arch = "x86")]
extern "C" fn ring3_gate_handler(frame: &TrapFrame) -> ! {
    // Contract: the gate is raised from ring 3 only.
    assert_eq!(frame.cs & 3, 3, "round-trip gate raised from ring 0");
    // SAFETY: MARKER_VA is a mapped, user-writable page; the stub had
    // ring-3 write access to it.
    let marker = unsafe { core::ptr::read_volatile(MARKER_VA as *const u32) };
    assert_eq!(marker, RING3_MARKER, "the ring-3 stub did not write its marker");
    crate::serial_println!(
        "F2K: ring-3 round trip ok (marker {:#010x}, cs {:#04x}, esp {:#010x})",
        marker,
        frame.cs,
        frame.user_esp
    );
    crate::halt();
}

/// Map the smoke's user pages and enter ring 3.
///
/// The code page is written through the scratch alias before it is
/// mapped read-only; the stack page is zeroed and writable. Both are
/// user-accessible; each allocation takes one frame, and the two pages
/// sit in different 4 MiB windows, so two page tables are created on
/// demand. Never returns.
#[cfg(target_arch = "x86")]
pub fn ring3_smoke() -> ! {
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
    // round-trip gate is installed at DPL 3.
    unsafe { enter_ring3(USER_CODE_PAGE, USER_STACK_TOP) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use core::mem::size_of;
    use core::ptr::addr_of;

    /// The stub bytes are exactly the documented encoding: B8+imm32
    /// (mov eax), A3+moffs32 (store), CD+ib (int), EB FE (jmp $).
    #[test]
    fn stub_bytes_match_their_encoding() {
        let mut expected = [0u8; 14];
        expected[0] = 0xB8;
        expected[1..5].copy_from_slice(&RING3_MARKER.to_le_bytes());
        expected[5] = 0xA3;
        expected[6..10].copy_from_slice(&MARKER_VA.to_le_bytes());
        expected[10] = 0xCD;
        expected[11] = RING3_GATE_VECTOR as u8;
        expected[12] = 0xEB;
        expected[13] = 0xFE;
        assert_eq!(RING3_STUB, expected);
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

    /// The smoke's address layout: both pages below the kernel window,
    /// page-aligned, in different 4 MiB windows; the marker inside the
    /// stack page but below the initial ESP; the gate vector outside
    /// the exception range and away from the future syscall vector.
    #[test]
    fn smoke_layout_is_consistent() {
        for page in [USER_CODE_PAGE, USER_STACK_PAGE] {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
        assert_ne!(USER_CODE_PAGE >> 22, USER_STACK_PAGE >> 22);
        assert!(MARKER_VA >= USER_STACK_PAGE && MARKER_VA + 4 <= USER_STACK_TOP);
        assert_eq!(USER_STACK_TOP, USER_STACK_PAGE + 4096);
        assert!(RING3_GATE_VECTOR > 31 && RING3_GATE_VECTOR < 256);
        assert_ne!(RING3_GATE_VECTOR, 0x2E);
    }
}
