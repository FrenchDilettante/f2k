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

pub mod stack;
pub mod apc;
pub mod syscall;
pub mod teb;
pub mod tls;
pub mod userheap;

/// The fault-test stub's code page (the corpus programs' preferred base, which the fault-test builds
/// never map).
#[cfg(any(
    feature = "fault-test-badargs",
    feature = "fault-test-segments",
    feature = "fault-test-threadexit",
    feature = "fault-test-exitio",
    test
))]
pub const USER_CODE_PAGE: u32 = 0x0040_0000;
/// The user stack's top page, in its own 4 MiB window (window 0, whose boot identity mapping was
/// removed). The stack spans two pages growing down — the CRT's startup passes need the room.
pub const USER_STACK_PAGE: u32 = 0x0030_0000;
/// The stack's second page, one below the top.
pub const USER_STACK_LOW_PAGE: u32 = USER_STACK_PAGE - 4096;
/// One past the stack's top page.
pub const USER_STACK_TOP: u32 = USER_STACK_PAGE + 4096;
/// The main thread's stack reservation: 1 MiB, the MSVC linker's default, of which the two pages
/// above are committed at start and the rest on demand (see [`stack`]).
pub const USER_STACK_RESERVE: u32 = 0x10_0000;
/// The reservation's lowest address.
pub const USER_STACK_BASE: u32 = USER_STACK_TOP - USER_STACK_RESERVE;
/// The main thread's entry ESP: one dword below the top, where the entry point's return address
/// sits — the thread-exit trampoline, so returning from the entry point ends the thread with the
/// returned value, as Windows' process start routine does.
pub const USER_ENTRY_ESP: u32 = USER_STACK_TOP - 4;
/// The thread block page, reached through the FS-based TEB segment (the CRT installs its exception
/// frames at fs:[0] first thing); mapped zeroed and writable by the loader.
pub const TEB_PAGE: u32 = 0x0031_0000;
/// The EFLAGS every planted user context carries: bit 1 (architecturally one) plus the interrupt
/// flag — user code runs enabled, IOPL 0 (port I/O stays privileged).
pub const USER_EFLAGS: u32 = 0x0000_0202;

/// The process parameters page: the staged command line, environment and module-name replays (see
/// `kernel32`).
pub const PARAMS_PAGE: u32 = 0x0032_0000;

/// The process environment block's page (see [`teb`]): every thread's TEB points here.
pub const PEB_PAGE: u32 = 0x0033_0000;

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

/// The number of pages a per-thread user stack spans (the same two pages the main thread's stack
/// has).
pub const THREAD_STACK_PAGES: u32 = 2;

/// An unmapped user address the bad-args stub passes as the syscall argument pointer: below the
/// user probe limit (the range probe passes) but backed by no page, so the kernel's argument copy
/// faults on the user process's behalf.
#[cfg(any(feature = "fault-test-badargs", test))]
pub const BAD_ARGS_PTR: u32 = 0x0050_0000;

/// The ring-3 fault-test stub, in bytes: a faulting body plus a spin as the safety net.
/// Hand-assembled so it can be copied into the user page (kernel code is unreachable from ring 3).
/// Never combine the features: `fault-test-badargs` passes an unmapped user address as the syscall
/// argument pointer.
#[cfg(feature = "fault-test-badargs")]
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

/// Raise the internal thread-exit service on the main thread with status 0: the main thread ends,
/// and with it the process (exit code 0). Were the service refused, the exit service below would
/// report the status the gate returned in EAX instead.
#[cfg(all(
    feature = "fault-test-threadexit",
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

/// The exit-during-read stub, before its service numbers are patched in: the main thread opens
/// HELLO.EXE and creates a child, raised time-critical, that seeks to the start and reads a sector
/// forever; main runs again only while the child waits on the disk, and ends the process there. The
/// zeroed immediates are the service numbers ([`EXIT_DURING_READ_SERVICES`]).
#[cfg(any(feature = "fault-test-exitio", test))]
#[rustfmt::skip]
const EXIT_DURING_READ_TEMPLATE: [u8; 156] = [
    // main:
    0x6A, 0x00, // push 0 (hTemplateFile)
    0x6A, 0x00, // push 0 (dwFlagsAndAttributes)
    0x6A, 0x03, // push OPEN_EXISTING
    0x6A, 0x00, // push 0 (lpSecurityAttributes)
    0x6A, 0x01, // push FILE_SHARE_READ
    0x68, 0x00, 0x00, 0x00, 0x80, // push GENERIC_READ
    0xB8, 0x92, 0x00, 0x40, 0x00, // mov eax, path (0x00400092)
    0x50, // push eax (lpFileName)
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x17: mov eax, CreateFileA
    0xCD, 0x2E, // int 0x2E
    0x83, 0xC4, 0x1C, // add esp, 28
    0x89, 0xC3, // mov ebx, eax (the file handle)
    0x6A, 0x00, // push 0 (lpThreadId)
    0x6A, 0x00, // push 0 (dwCreationFlags)
    0x53, // push ebx (lpParameter: the file handle)
    0xB8, 0x5A, 0x00, 0x40, 0x00, // mov eax, child (0x0040005A)
    0x50, // push eax (lpStartAddress)
    0x6A, 0x00, // push 0 (dwStackSize)
    0x6A, 0x00, // push 0 (lpThreadAttributes)
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x34: mov eax, CreateThread
    0xCD, 0x2E, // int 0x2E
    0x83, 0xC4, 0x18, // add esp, 24
    0x6A, 0x0F, // push THREAD_PRIORITY_TIME_CRITICAL
    0x50, // push eax (the child's handle)
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x43: mov eax, SetThreadPriority (the child preempts here)
    0xCD, 0x2E, // int 0x2E
    0x83, 0xC4, 0x08, // add esp, 8
    0x6A, 0x00, // push 0 (uExitCode)
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x51: mov eax, ExitProcess (the child is inside a read)
    0xCD, 0x2E, // int 0x2E
    0xEB, 0xFE, // 0x58: jmp $
    // child (0x5A):
    0x8B, 0x5C, 0x24, 0x04, // mov ebx, [esp+4] (the file handle)
    0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, // sub esp, 0x200
    0x89, 0xE7, // mov edi, esp (the buffer)
    // child_loop (0x66):
    0x6A, 0x00, // push FILE_BEGIN
    0x6A, 0x00, // push 0 (lpDistanceToMoveHigh)
    0x6A, 0x00, // push 0 (lDistanceToMove)
    0x53, // push ebx
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x6F: mov eax, SetFilePointer
    0xCD, 0x2E, // int 0x2E
    0x83, 0xC4, 0x10, // add esp, 16
    0x6A, 0x00, // push 0 (lpOverlapped)
    0x6A, 0x00, // push 0 (lpNumberOfBytesRead)
    0x68, 0x00, 0x02, 0x00, 0x00, // push 512
    0x57, // push edi
    0x53, // push ebx
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x86: mov eax, ReadFile
    0xCD, 0x2E, // int 0x2E
    0x83, 0xC4, 0x14, // add esp, 20
    0xEB, 0xD4, // jmp child_loop
    // path (0x92):
    b'h', b'e', b'l', b'l', b'o', b'.', b'e', b'x', b'e', 0,
];

/// Where the template's service-number immediates sit (each one byte past its `mov eax` opcode),
/// and the export each names.
#[cfg(any(feature = "fault-test-exitio", test))]
const EXIT_DURING_READ_SERVICES: [(usize, &str); 6] = [
    (0x18, "CreateFileA"),
    (0x35, "CreateThread"),
    (0x44, "SetThreadPriority"),
    (0x52, "ExitProcess"),
    (0x70, "SetFilePointer"),
    (0x87, "ReadFile"),
];

/// The exit-during-read stub: the template with the registry's service numbers patched in at build
/// time, so a registry change cannot leave it calling the wrong services.
#[cfg(any(feature = "fault-test-exitio", test))]
pub const EXIT_DURING_READ_STUB: [u8; 156] = {
    let mut stub = EXIT_DURING_READ_TEMPLATE;
    let mut index = 0;
    while index < EXIT_DURING_READ_SERVICES.len() {
        let (offset, name) = EXIT_DURING_READ_SERVICES[index];
        let number = crate::compat::kernel32::service_number(name).to_le_bytes();
        stub[offset] = number[0];
        stub[offset + 1] = number[1];
        stub[offset + 2] = number[2];
        stub[offset + 3] = number[3];
        index += 1;
    }
    stub
};

#[cfg(all(
    feature = "fault-test-exitio",
    not(feature = "fault-test-badargs"),
    not(feature = "fault-test-segments"),
    not(feature = "fault-test-threadexit")
))]
pub const RING3_STUB: [u8; 156] = EXIT_DURING_READ_STUB;

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
/// stub with a `fault-test-*` feature, or one image from the boot volume through the PE loader
/// (see [`boot_image`]).
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
            feature = "fault-test-badargs",
            feature = "fault-test-segments",
            feature = "fault-test-threadexit",
            feature = "fault-test-exitio"
        )
    ))]
    {
        run_fault_stub()
    }
    #[cfg(all(
        not(feature = "run-process-suite"),
        not(any(
            feature = "fault-test-badargs",
            feature = "fault-test-segments",
            feature = "fault-test-threadexit",
            feature = "fault-test-exitio"
        ))
    ))]
    {
        let (path, name, command_line) = command_line_image().unwrap_or_else(|| {
            let (path, name) = boot_image();
            (path, name, name.as_bytes())
        });
        let entry = crate::exec::loader::load_path(path, name, command_line);
        crate::process::threads::enter_as_main_thread(entry, USER_ENTRY_ESP)
    }
}

/// The program the boot's user command line names (see [`crate::boot::cmdline`]), as its volume
/// path, its process name (the file name's stem) and the command line itself; none without a user
/// command line. A program token without an extension gets `.exe`, as CreateProcess gives it; one
/// that names no volume path is reported and halts, like an image that does not load.
#[cfg(target_arch = "x86")]
fn command_line_image() -> Option<(&'static [u8], &'static str, &'static [u8])> {
    use crate::boot::cmdline::{kernel_command_line, program_token, user_command_line};
    use crate::compat::path::{resolve, MAX_PATH};

    /// The program's volume path: built once, here, at boot.
    static mut PROGRAM: ([u8; MAX_PATH], usize) = ([0; MAX_PATH], 0);

    let line = user_command_line(kernel_command_line())?;
    let token = program_token(line);
    let resolved = match resolve(token, b"") {
        Ok(resolved) if !resolved.is_root() => resolved,
        other => {
            crate::serial_println!(
                "F2K: command line program {} names no file (error {})",
                core::str::from_utf8(token).unwrap_or("(not ASCII)"),
                other
                    .err()
                    .unwrap_or(crate::compat::error::ERROR_PATH_NOT_FOUND)
            );
            crate::halt()
        }
    };
    // SAFETY: single-threaded boot; the buffer is written once, here, and only read afterwards.
    let (buffer, length) = unsafe { &mut *core::ptr::addr_of_mut!(PROGRAM) };
    let path = resolved.as_bytes();
    buffer[..path.len()].copy_from_slice(path);
    *length = path.len();
    if !resolved.file_name().contains(&b'.') && *length + 4 < MAX_PATH {
        buffer[*length..*length + 4].copy_from_slice(b".exe");
        *length += 4;
    }
    let path: &'static [u8] = &buffer[..*length];
    let file_name = &path[path
        .iter()
        .rposition(|&byte| byte == b'\\')
        .map_or(0, |i| i + 1)..];
    let stem = &file_name[..file_name
        .iter()
        .position(|&byte| byte == b'.')
        .unwrap_or(file_name.len())];
    Some((path, core::str::from_utf8(stem).unwrap_or("program"), line))
}

/// The one image a one-process boot runs, as its path on the boot volume and its process name: the
/// first fixture feature in this order — the file smoke (`run-fileio`), hello (`run-hello`), ret0
/// (`run-ret0`) — else exit0. The paths are
/// root-relative; the lookup folds case, so the lowercase spelling finds the stored uppercase name.
#[cfg(all(
    target_arch = "x86",
    not(feature = "run-process-suite"),
    not(any(
        feature = "fault-test-badargs",
        feature = "fault-test-segments",
        feature = "fault-test-threadexit",
        feature = "fault-test-exitio"
    ))
))]
#[allow(unreachable_code)]
fn boot_image() -> (&'static [u8], &'static str) {
    #[cfg(feature = "run-fileio")]
    return (b"fileio.exe", "fileio");
    #[cfg(feature = "run-hello")]
    return (b"hello.exe", "hello");
    #[cfg(feature = "run-ret0")]
    return (b"ret0.exe", "ret0");
    (b"exit0.exe", "exit0")
}

/// Create the fault-test stub's process — its code and stack pages mapped in the process's own
/// address space — and enter it as its main thread. Never returns.
#[cfg(target_arch = "x86")]
#[cfg(any(
    feature = "fault-test-badargs",
    feature = "fault-test-segments",
    feature = "fault-test-threadexit",
    feature = "fault-test-exitio"
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

/// The exit-during-read boot's check, on the idle thread after the process's teardown: the volume
/// must be usable again — its lock free, the drive between commands — so a lookup succeeds.
#[cfg(all(target_arch = "x86", feature = "fault-test-exitio"))]
pub fn check_volume_after_teardown() {
    let found = crate::fs::fat32::volume::with_boot_volume(|volume| {
        crate::fs::fat32::lookup::lookup(volume, b"hello.exe")
    });
    match found {
        Some(Ok(file)) => {
            crate::serial_println!(
                "F2K: exit-during-read: volume usable after teardown (HELLO.EXE, {} bytes)",
                file.size
            );
        }
        other => {
            crate::serial_println!(
                "F2K: exit-during-read: volume unusable after teardown ({:?})",
                other
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr::addr_of;

    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use crate::user::syscall::SYSCALL_VECTOR;

    /// The bad-args stub requests the exit service with an unmapped argument pointer: BA+imm32 (mov
    /// edx, imm32), int, jmp $.
    #[cfg(feature = "fault-test-badargs")]
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

    /// The exit-during-read stub: each patch site is a `mov eax, imm32` raising the gate right
    /// after, carrying its export's service number; the two absolute addresses name the child
    /// entry and the path string inside the code page.
    #[test]
    fn exit_during_read_stub_patches_its_service_numbers() {
        for (offset, name) in EXIT_DURING_READ_SERVICES {
            assert_eq!(EXIT_DURING_READ_STUB[offset - 1], 0xB8, "{name}: mov eax");
            assert_eq!(
                &EXIT_DURING_READ_STUB[offset + 4..offset + 6],
                &[0xCD, SYSCALL_VECTOR as u8],
                "{name}: int"
            );
            let number = u32::from_le_bytes(
                EXIT_DURING_READ_STUB[offset..offset + 4]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(
                crate::compat::kernel32::resolve(name),
                Some(crate::compat::kernel32::THUNK_PAGE + (number - 1) * 16),
                "{name}"
            );
        }
        assert_eq!(
            u32::from_le_bytes(EXIT_DURING_READ_STUB[0x52..0x56].try_into().unwrap()),
            crate::user::syscall::SYS_EXIT
        );
        let child = USER_CODE_PAGE + 0x5A;
        let path = USER_CODE_PAGE + 0x92;
        assert_eq!(&EXIT_DURING_READ_STUB[0x29..0x2D], &child.to_le_bytes());
        assert_eq!(&EXIT_DURING_READ_STUB[0x10..0x14], &path.to_le_bytes());
        assert_eq!(
            &EXIT_DURING_READ_STUB[0x5A..0x5E],
            &[0x8B, 0x5C, 0x24, 0x04]
        );
        assert_eq!(&EXIT_DURING_READ_STUB[0x92..], b"hello.exe\0");
        // The loop's back jump lands on its first instruction.
        assert_eq!(0x92 + (EXIT_DURING_READ_STUB[0x91] as i8 as i32), 0x66);
    }

    /// The bad-args pointer: below the probe limit but on no mapped page.
    #[test]
    fn fault_probe_layout_is_consistent() {
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
            PEB_PAGE,
        ] {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
        assert_ne!(USER_CODE_PAGE >> 22, USER_STACK_PAGE >> 22);
        assert_eq!(USER_STACK_LOW_PAGE, USER_STACK_PAGE - 4096);
        assert_eq!(USER_STACK_TOP, USER_STACK_PAGE + 4096);
        assert!(TEB_PAGE > USER_STACK_TOP);
        assert!(PARAMS_PAGE > TEB_PAGE);
        assert!(PEB_PAGE >= PARAMS_PAGE + 4096);
        assert!(PEB_PAGE + 4096 <= USER_CODE_PAGE);
    }
}
