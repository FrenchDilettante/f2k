//! Ring 3: entering user mode and the end of the user process.
//!
//! The kernel maps the image, stack, TEB and parameters pages, enters
//! ring 3 with an iret ([`enter_ring3`]), and the image ends the
//! process through the exit service. The fault-test features
//! substitute a hand-assembled stub ([`RING3_STUB`]) so the
//! user-fault paths can be verified without a PE fixture.
//!
//! Single tasking, run to completion: the exit syscall is the return
//! path; faults raised by user code end the process, not the kernel.

pub mod syscall;
pub mod userheap;

#[cfg(target_arch = "x86")]
use crate::cpu::gdt::{TEB_SELECTOR, USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// The fault-test stub's code page (the PE image base, which the
/// fault-test builds never map).
#[cfg(any(feature = "fault-test-user", feature = "fault-test-badargs", test))]
pub const USER_CODE_PAGE: u32 = 0x0040_0000;
/// The user stack's top page, in its own 4 MiB window (window 0,
/// whose boot identity mapping was removed). The stack spans two
/// pages growing down — the CRT's startup passes need the room.
pub const USER_STACK_PAGE: u32 = 0x0030_0000;
/// The stack's second page, one below the top.
pub const USER_STACK_LOW_PAGE: u32 = USER_STACK_PAGE - 4096;
/// Initial user ESP: one past the stack's top page.
pub const USER_STACK_TOP: u32 = USER_STACK_PAGE + 4096;
/// The thread block page, reached through the FS-based TEB segment
/// (the CRT installs its exception frames at fs:[0] first thing);
/// mapped zeroed and writable by the loader.
pub const TEB_PAGE: u32 = 0x0031_0000;
/// The EFLAGS every planted user context carries: bit 1
/// (architecturally one) plus the interrupt flag — user code runs
/// enabled, IOPL 0 (port I/O stays privileged).
pub const USER_EFLAGS: u32 = 0x0000_0202;

/// The process parameters page: the staged command line,
/// environment and module-name replays (see `kernel32`).
pub const PARAMS_PAGE: u32 = 0x0032_0000;

/// The region per-thread TEB pages allocate from (user window 2,
/// mapped by no run path today). A process's first thread keeps the
/// fixed TEB page below; later threads take one page from here.
pub const THREAD_TEB_REGION: u32 = 0x0080_0000;

/// Thread `index`'s TEB page.
pub const fn thread_teb_va(index: u32) -> u32 {
    if index == 0 {
        TEB_PAGE
    } else {
        THREAD_TEB_REGION + (index - 1) * 4096
    }
}

/// The region per-thread user stacks allocate from (user window 3),
/// recorded for the thread-creation surface: thread `index` ≥ 1 gets
/// the two pages ending at `THREAD_STACK_REGION + index * 0x2000`,
/// growing down like the main thread's. Nothing consumes it yet.
pub const THREAD_STACK_REGION: u32 = 0x00C0_0000;

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

/// The ring-3 fault-test stub, in bytes: a faulting body plus a spin
/// as the safety net. Hand-assembled so it can be copied into the
/// user page (kernel code is unreachable from ring 3). Never combine
/// the features: `fault-test-user` reads the supervisor-only kernel
/// window; `fault-test-badargs` passes an unmapped user address as
/// the syscall argument pointer.
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

/// Trap frame the gate stubs build on the ring-0 stack, in the shape
/// shared with the exception stubs (the CPU pushes the ring-3 tail;
/// the stub pushes the rest in the same order).
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

// Entry into ring 3: load the segments, build the iret frame, switch.
// Never returns. FS takes the TEB segment and GS null (the captured
// entry state); the pushed EFLAGS is bit 1 plus the interrupt flag —
// user code runs with interrupts enabled. IOPL is 0, so port I/O
// stays privileged and the serial backend stays kernel-only.
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
    // user data segments for DS/ES, the TEB segment for FS, and null
    // for GS; SS comes from the iret frame.
    "    mov ax, {user_data}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ax, {teb}",
    "    mov fs, ax",
    "    xor eax, eax",
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
    // iret loads only EIP, CS, EFLAGS, ESP and SS: zero the rest so
    // kernel pointers do not leak into user mode. (Entry register
    // fidelity for real images is a recorded open item.)
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
    teb = const TEB_SELECTOR | 3,
    user_eflags = const USER_EFLAGS,
);

/// End of the user process: the exit service's landing point. The
/// exit code is the only observable, making this line the suite's
/// check. Single-process runs report and halt on the boot address
/// space; the multi-process suite hands the chain to the next
/// process (its runner tears this one down).
pub fn process_exited(code: u32) -> ! {
    #[cfg(all(target_arch = "x86", feature = "run-pingpong"))]
    {
        // The thread-ified boot: the process's exit is its last
        // thread's exit (the report and the last-thread route are
        // the exit path's own).
        crate::process::threads::exit_thread(code as i32)
    }
    #[cfg(all(target_arch = "x86", not(feature = "run-pingpong")))]
    {
        #[cfg(feature = "run-process-suite")]
        {
            crate::process::runner::process_exited(code)
        }
        #[cfg(not(feature = "run-process-suite"))]
        {
            crate::serial_println!("F2K: user process exited normally (exit code={})", code);
            // Back to the boot directory before anything else runs on
            // the process's tables.
            crate::mem::paging::activate_address_space(
                crate::mem::paging::boot_directory_phys(),
            );
            crate::idle()
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds compile the dispatch tables but never run them:
        // there is no serial port and no process to end.
        let _ = code;
        unimplemented!("process exit is a kernel-runtime operation")
    }
}

/// Launch the first user process: exit0 through the PE loader by
/// default, ret0 with the `run-ret0` feature, hello with the
/// `run-hello` feature, a fault-test stub, or the full multi-process
/// suite with `run-process-suite`. Never returns.
#[cfg(target_arch = "x86")]
pub fn run_user_process() -> ! {
    #[cfg(feature = "run-process-suite")]
    {
        crate::process::runner::run_suite()
    }
    #[cfg(not(feature = "run-process-suite"))]
    {
        #[cfg(not(any(feature = "fault-test-user", feature = "fault-test-badargs")))]
        {
            #[cfg(feature = "run-pingpong")]
            {
                crate::exec::loader::run_image(crate::exec::loader::PINGPONG, "pingpong")
            }
            #[cfg(all(not(feature = "run-pingpong"), feature = "run-hello"))]
            {
                crate::exec::loader::run_image(crate::exec::loader::HELLO, "hello")
            }
            #[cfg(all(
                not(feature = "run-pingpong"),
                not(feature = "run-hello"),
                not(feature = "run-ret0")
            ))]
            {
                crate::exec::loader::run_image(crate::exec::loader::EXIT0, "exit0")
            }
            #[cfg(all(
                not(feature = "run-pingpong"),
                not(feature = "run-hello"),
                feature = "run-ret0"
            ))]
            {
                crate::exec::loader::run_image(crate::exec::loader::RET0, "ret0")
            }
        }
        #[cfg(any(feature = "fault-test-user", feature = "fault-test-badargs"))]
        {
            run_fault_stub()
        }
    }
}

/// Map the fault-test stub's pages and enter ring 3. Never returns.
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
    let stack_low = paging::allocate_frame_phys();
    paging::init_frame(stack_low, 0, &[]);
    paging::map_user_page(USER_STACK_LOW_PAGE, stack_low, true);

    // The stubs enter ring 3 on the boot address space, so their gate
    // entries need a ring-0 stack mapped there: every run path
    // installs its own (image runs get one per process inside the
    // process object; the retired static stack used to serve this).
    let _gate_stack_frames = paging::map_gate_stack();
    crate::cpu::gdt::set_gate_stack_top(paging::GATE_STACK_TOP);

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
    use crate::user::syscall::SYSCALL_VECTOR;
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
        expected[1..5].copy_from_slice(&crate::user::syscall::SYS_EXIT.to_le_bytes());
        expected[5] = 0xBA;
        expected[6..10].copy_from_slice(&BAD_ARGS_PTR.to_le_bytes());
        expected[10] = 0xCD;
        expected[11] = SYSCALL_VECTOR as u8;
        expected[12] = 0xEB;
        expected[13] = 0xFE;
        assert_eq!(RING3_STUB, expected);
    }

    /// The fault-test addresses: the kernel-window probe inside the
    /// supervisor-only window; the bad-args pointer below the probe
    /// limit but on no mapped page.
    #[test]
    fn fault_probe_layout_is_consistent() {
        assert!(KERNEL_WINDOW_PROBE >= KERNEL_BASE);
        assert!(BAD_ARGS_PTR < KERNEL_BASE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_CODE_PAGE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_STACK_PAGE);
    }

    /// 15 u32s; the CPU-pushed tail keeps the iret order after the
    /// exception-stub prefix.
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

/// Per-thread TEB pages: the first thread keeps the loader's fixed
/// page; later threads take their own page from the region, so
/// threads of one process never share a TEB.
    #[test]
    fn per_thread_teb_pages_are_distinct() {
        assert_eq!(thread_teb_va(0), TEB_PAGE);
        let pages = [thread_teb_va(0), thread_teb_va(1), thread_teb_va(2)];
        assert_eq!(pages[1], THREAD_TEB_REGION);
        assert_eq!(pages[2], THREAD_TEB_REGION + 4096);
        for index in 1..pages.len() {
            for other in 0..index {
                assert_ne!(pages[index], pages[other]);
            }
            assert!(pages[index] > PARAMS_PAGE);
            // 0x0200_0000: the heap region's base, the next mapped
            // user window above the TEB region.
            assert!(pages[index] < 0x0200_0000);
        }
        for &page in &pages {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
    }

    /// The user pages: below the kernel window, page-aligned, the
    /// stack top one past its top page, the image window clear of
    /// window 0.
    #[test]
    fn user_layout_is_consistent() {
        for page in [
            USER_CODE_PAGE,
            USER_STACK_PAGE,
            USER_STACK_LOW_PAGE,
            TEB_PAGE,
            PARAMS_PAGE,
        ] {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
        assert_ne!(USER_CODE_PAGE >> 22, USER_STACK_PAGE >> 22);
        assert_eq!(USER_STACK_LOW_PAGE, USER_STACK_PAGE - 4096);
        assert_eq!(USER_STACK_TOP, USER_STACK_PAGE + 4096);
        assert!(TEB_PAGE > USER_STACK_TOP);
        assert!(PARAMS_PAGE > TEB_PAGE);
        assert!(PARAMS_PAGE + 4096 < crate::exec::pe::IMAGE_BASE);
    }
}
