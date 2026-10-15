//! Ring 3: the user layout, the boot's choice of what runs, and the end of the user process.
//!
//! The kernel maps the image, stack, TEB and parameters pages and enters the process as its main
//! thread: the scheduler's first switch into the thread leaves its startup ladder for ring 3. The
//! image ends the process through the exit service. The fault-test features substitute a
//! hand-assembled stub ([`RING3_STUB`]) so the user-fault paths can be verified without a PE
//! fixture.
//!
//! Every user context is a thread: a thread's return ends the thread (the last thread's end is the
//! process's), the exit service ends the process and all its threads, and faults raised by user
//! code end the process, not the kernel.

pub mod syscall;
pub mod userheap;

/// The fault-test stub's code page (the PE image base, which the fault-test builds never map).
#[cfg(any(
    feature = "fault-test-user",
    feature = "fault-test-badargs",
    feature = "fault-test-segments",
    feature = "fault-test-threadexit",
    test
))]
pub const USER_CODE_PAGE: u32 = 0x0040_0000;
/// The user stack's top page, in its own 4 MiB window (window 0, whose boot identity mapping was
/// removed). The stack spans two pages growing down — the CRT's startup passes need the room.
pub const USER_STACK_PAGE: u32 = 0x0030_0000;
/// The stack's second page, one below the top.
pub const USER_STACK_LOW_PAGE: u32 = USER_STACK_PAGE - 4096;
/// Initial user ESP: one past the stack's top page.
pub const USER_STACK_TOP: u32 = USER_STACK_PAGE + 4096;
/// The thread block page, reached through the FS-based TEB segment (the CRT installs its exception
/// frames at fs:[0] first thing); mapped zeroed and writable by the loader.
pub const TEB_PAGE: u32 = 0x0031_0000;
/// The EFLAGS every planted user context carries: bit 1 (architecturally one) plus the interrupt
/// flag — user code runs enabled, IOPL 0 (port I/O stays privileged).
pub const USER_EFLAGS: u32 = 0x0000_0202;

/// The process parameters page: the staged command line, environment and module-name replays (see
/// `kernel32`).
pub const PARAMS_PAGE: u32 = 0x0032_0000;

/// The region per-thread TEB pages allocate from (user window 2, mapped by no run path today). A
/// process's first thread keeps the fixed TEB page below; later threads take one page from here.
pub const THREAD_TEB_REGION: u32 = 0x0080_0000;

/// Thread `index`'s TEB page.
pub const fn thread_teb_va(index: u32) -> u32 {
    if index == 0 {
        TEB_PAGE
    } else {
        THREAD_TEB_REGION + (index - 1) * 4096
    }
}

/// The region per-thread user stacks allocate from (user window 3), recorded for the
/// thread-creation surface: thread `index` ≥ 1 gets the two pages ending at
/// `THREAD_STACK_REGION + index * 0x2000`, growing down like the main thread's. Nothing consumes it
/// yet.
pub const THREAD_STACK_REGION: u32 = 0x00C0_0000;

/// A kernel address the fault-test stub reads from ring 3: the kernel window is supervisor-only, so
/// the read must fault.
#[cfg(any(feature = "fault-test-user", test))]
pub const KERNEL_WINDOW_PROBE: u32 = 0x8010_1000;

/// An unmapped user address the bad-args stub passes as the syscall argument pointer: below the
/// user probe limit (the range probe passes) but backed by no page, so the kernel's argument copy
/// faults on the user process's behalf.
#[cfg(any(feature = "fault-test-badargs", test))]
pub const BAD_ARGS_PTR: u32 = 0x0050_0000;

/// The ring-3 fault-test stub, in bytes: a faulting body plus a spin as the safety net.
/// Hand-assembled so it can be copied into the user page (kernel code is unreachable from ring 3).
/// Never combine the features: `fault-test-user` reads the supervisor-only kernel window;
/// `fault-test-badargs` passes an unmapped user address as the syscall argument pointer.
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

/// DS/ES loaded with the TEB selector (base TEB_PAGE, limit 0xFFF: legal at CPL 3), then a spin
/// long enough that the clock preempts it many times over, then the exit service with code 7 (the
/// argument block sits on the stack, which SS still reaches). The TEB segment rather than a null
/// selector: real hardware faults on both once the kernel runs on them, but QEMU's TCG skips the
/// null-selector check on flat data accesses, so only the based selector exposes the bug under
/// emulation.
#[cfg(all(
    feature = "fault-test-segments",
    not(feature = "fault-test-user"),
    not(feature = "fault-test-badargs")
))]
#[rustfmt::skip]
pub const RING3_STUB: [u8; 29] = [
    0x66, 0xB8, 0x33, 0x00, // mov ax, TEB_SELECTOR | 3
    0x8E, 0xD8, // mov ds, ax
    0x8E, 0xC0, // mov es, ax
    0xB9, 0x00, 0x00, 0x00, 0x08, // mov ecx, 0x08000000
    0x49, // dec ecx
    0x75, 0xFD, // jnz (back to dec ecx)
    0x6A, 0x07, // push 7
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_EXIT (service 1)
    0xCD, 0x2E, // int 0x2E
    0xEB, 0xFE, // jmp $
];

/// Raise the internal thread-exit service with no user thread running, then exit with the status
/// the gate returned in EAX.
#[cfg(all(
    feature = "fault-test-threadexit",
    not(feature = "fault-test-user"),
    not(feature = "fault-test-badargs"),
    not(feature = "fault-test-segments")
))]
#[rustfmt::skip]
pub const RING3_STUB: [u8; 22] = [
    0xB8, 0x00, 0x00, 0x00, 0x80, // mov eax, SYS_THREAD_EXIT
    0x31, 0xD2, // xor edx, edx
    0xCD, 0x2E, // int 0x2E
    0x50, // push eax
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_EXIT (service 1)
    0xCD, 0x2E, // int 0x2E
    0xEB, 0xFE, // jmp $
    0x90, // pad
];

/// Trap frame the gate stubs build on the ring-0 stack, in the shape shared with the exception
/// stubs (the CPU pushes the ring-3 tail; the stub pushes the rest in the same order).
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

/// The exit service's landing point: the process ends with `code` — its other threads are
/// terminated, then the calling thread — and the exit code is reported (the line every boot's
/// check reads). Never returns.
pub fn process_exited(code: u32) -> ! {
    #[cfg(target_arch = "x86")]
    {
        crate::process::threads::exit_process(code)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds compile the dispatch tables but never run them: there is no serial port and
        // no process to end.
        let _ = code;
        unimplemented!("process exit is a kernel-runtime operation")
    }
}

/// Launch the boot's user code: the multi-process suite with `run-process-suite`, a fault-test
/// stub with a `fault-test-*` feature, or one image through the PE loader (see [`boot_image`]).
/// Every path enters its process as a main thread through the idle loop. Never returns.
#[cfg(target_arch = "x86")]
pub fn run_user_process() -> ! {
    #[cfg(feature = "run-process-suite")]
    {
        crate::process::runner::run_suite()
    }
    #[cfg(all(
        not(feature = "run-process-suite"),
        any(
            feature = "fault-test-user",
            feature = "fault-test-badargs",
            feature = "fault-test-segments",
            feature = "fault-test-threadexit"
        )
    ))]
    {
        run_fault_stub()
    }
    #[cfg(all(
        not(feature = "run-process-suite"),
        not(any(
            feature = "fault-test-user",
            feature = "fault-test-badargs",
            feature = "fault-test-segments",
            feature = "fault-test-threadexit"
        ))
    ))]
    {
        let (image, name) = boot_image();
        let entry = crate::exec::loader::load_image(image, name);
        crate::process::threads::enter_as_main_thread(entry, USER_STACK_TOP)
    }
}

/// The one image a one-process boot runs: the first fixture feature in this order — the
/// blocking-wait, timer, preemption, slot-reuse, or suspend smoke
/// (`run-pingpong`/`run-sleep`/`run-spin`/`run-respawn`/`run-suspend`), hello (`run-hello`),
/// ret0 (`run-ret0`) — else exit0.
#[cfg(all(
    target_arch = "x86",
    not(feature = "run-process-suite"),
    not(any(
        feature = "fault-test-user",
        feature = "fault-test-badargs",
        feature = "fault-test-segments",
        feature = "fault-test-threadexit"
    ))
))]
#[allow(unreachable_code)]
fn boot_image() -> (&'static [u8], &'static str) {
    #[cfg(feature = "run-pingpong")]
    return (crate::exec::loader::PINGPONG, "pingpong");
    #[cfg(feature = "run-sleep")]
    return (crate::exec::loader::SLEEP, "sleep");
    #[cfg(feature = "run-spin")]
    return (crate::exec::loader::SPIN, "spin");
    #[cfg(feature = "run-respawn")]
    return (crate::exec::loader::RESPAWN, "respawn");
    #[cfg(feature = "run-suspend")]
    return (crate::exec::loader::SUSPEND, "suspend");
    #[cfg(feature = "run-hello")]
    return (crate::exec::loader::HELLO, "hello");
    #[cfg(feature = "run-ret0")]
    return (crate::exec::loader::RET0, "ret0");
    (crate::exec::loader::EXIT0, "exit0")
}

/// Create the fault-test stub's process — its code and stack pages mapped in the process's own
/// address space — and enter it as its main thread. Never returns.
#[cfg(target_arch = "x86")]
#[cfg(any(
    feature = "fault-test-user",
    feature = "fault-test-badargs",
    feature = "fault-test-segments",
    feature = "fault-test-threadexit"
))]
pub fn run_fault_stub() -> ! {
    use crate::mem::paging;

    crate::process::Process::start("stub");

    let code_frame = paging::allocate_frame_phys();
    paging::init_frame(code_frame, 0, &RING3_STUB);
    paging::map_user_page(USER_CODE_PAGE, code_frame, false);

    let stack_frame = paging::allocate_frame_phys();
    paging::init_frame(stack_frame, 0, &[]);
    paging::map_user_page(USER_STACK_PAGE, stack_frame, true);
    let stack_low = paging::allocate_frame_phys();
    paging::init_frame(stack_low, 0, &[]);
    paging::map_user_page(USER_STACK_LOW_PAGE, stack_low, true);

    crate::serial_println!(
        "F2K: entering ring 3 (code {:#010x}, stack {:#010x})",
        USER_CODE_PAGE,
        USER_STACK_TOP
    );
    crate::process::threads::enter_as_main_thread(USER_CODE_PAGE, USER_STACK_TOP)
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr::addr_of;

    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use crate::user::syscall::SYSCALL_VECTOR;

    /// The fault-test stub reads the supervisor-only kernel window and spins: A1+moffs32 (mov eax,
    /// [moffs]) then jmp $.
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

    /// The bad-args stub requests the exit service with an unmapped argument pointer: BA+imm32 (mov
    /// edx, imm32), int, jmp $.
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

    /// The fault-test addresses: the kernel-window probe inside the supervisor-only window; the
    /// bad-args pointer below the probe limit but on no mapped page.
    #[test]
    fn fault_probe_layout_is_consistent() {
        assert!(KERNEL_WINDOW_PROBE >= KERNEL_BASE);
        assert!(BAD_ARGS_PTR < KERNEL_BASE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_CODE_PAGE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_STACK_PAGE);
    }

    /// 15 u32s; the CPU-pushed tail keeps the iret order after the exception-stub prefix.
    #[test]
    fn trap_frame_layout() {
        assert_eq!(size_of::<TrapFrame>(), 15 * 4);
        let frame = TrapFrame {
            edi: 0,
            esi: 0,
            ebp: 0,
            esp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            vector: 0,
            error_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
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

    /// Per-thread TEB pages: the first thread keeps the loader's fixed page; later threads take
    /// their own page from the region, so threads of one process never share a TEB.
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
            // 0x0200_0000: the heap region's base, the next mapped user window above the TEB
            // region.
            assert!(pages[index] < 0x0200_0000);
        }
        for &page in &pages {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
    }

    /// The user pages: below the kernel window, page-aligned, the stack top one past its top page,
    /// the image window clear of window 0.
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
